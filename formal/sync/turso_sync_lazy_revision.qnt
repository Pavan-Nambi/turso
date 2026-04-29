module turso_sync_lazy_revision {
  pure val NO_REV: int = -1
  pure val R0: int = 0
  pure val R1: int = 1
  pure val R2: int = 2
  pure val REVS: Set[int] = Set(NO_REV, R0, R1, R2)
  pure val PAGES: Set[int] = Set(1, 2, 3)

  var bootstrapped: bool
  var remoteRev: int
  var durableBootstrapRev: int
  var durableSyncedRev: int
  var storageRev: int

  // Base bytes are the sparse main DB file managed by LazyDatabaseStorage.
  var basePresent: Set[int]
  var baseOriginRev: int -> int

  // Pull/apply writes remote changes as a WAL overlay. This is separate from
  // the sparse base file; a normal pull is not a full base materialization.
  var walPresent: Set[int]
  var walOriginRev: int -> int

  // Remote pages changed since the latest successful pull.
  var pendingRemoteChanged: Set[int]

  // Event log for the core safety property: the revision used for each lazy
  // load request, independent of whether later WAL/pull activity overwrites
  // the visible page contents.
  var lastLazyRequestRev: int -> int

  pure val noRevByPage: int -> int =
    PAGES.mapBy(_ => NO_REV)

  action init = all {
    bootstrapped' = false,
    remoteRev' = NO_REV,
    durableBootstrapRev' = NO_REV,
    durableSyncedRev' = NO_REV,
    storageRev' = NO_REV,
    basePresent' = Set(),
    baseOriginRev' = noRevByPage,
    walPresent' = Set(),
    walOriginRev' = noRevByPage,
    pendingRemoteChanged' = Set(),
    lastLazyRequestRev' = noRevByPage,
  }

  action keepRevisionState = all {
    bootstrapped' = bootstrapped,
    remoteRev' = remoteRev,
    durableBootstrapRev' = durableBootstrapRev,
    durableSyncedRev' = durableSyncedRev,
    storageRev' = storageRev,
  }

  action keepPages = all {
    basePresent' = basePresent,
    baseOriginRev' = baseOriginRev,
    walPresent' = walPresent,
    walOriginRev' = walOriginRev,
    pendingRemoteChanged' = pendingRemoteChanged,
    lastLazyRequestRev' = lastLazyRequestRev,
  }

  action partialBootstrap = {
    nondet selected = PAGES.powerset().oneOf()
    partialBootstrapWith(selected)
  }

  action partialBootstrapWith(selected: Set[int]): bool = all {
    not(bootstrapped),
    selected.subseteq(PAGES),
    bootstrapped' = true,
    remoteRev' = R0,
    durableBootstrapRev' = R0,
    durableSyncedRev' = R0,
    storageRev' = R0,
    basePresent' = selected,
    baseOriginRev' = PAGES.mapBy(p => if (p.in(selected)) { R0 } else { NO_REV }),
    walPresent' = Set(),
    walOriginRev' = noRevByPage,
    pendingRemoteChanged' = Set(),
    lastLazyRequestRev' = noRevByPage,
  }

  action remoteAdvance = {
    nondet p = PAGES.oneOf()
    remoteAdvanceChanging(p)
  }

  action remoteAdvanceChanging(p: int): bool = all {
    bootstrapped,
    p.in(PAGES),
    remoteRev < R2,
    bootstrapped' = bootstrapped,
    remoteRev' = remoteRev + 1,
    durableBootstrapRev' = durableBootstrapRev,
    durableSyncedRev' = durableSyncedRev,
    storageRev' = storageRev,
    basePresent' = basePresent,
    baseOriginRev' = baseOriginRev,
    walPresent' = walPresent,
    walOriginRev' = walOriginRev,
    pendingRemoteChanged' = pendingRemoteChanged.union(Set(p)),
    lastLazyRequestRev' = lastLazyRequestRev,
  }

  action pullRemote = all {
    bootstrapped,
    pendingRemoteChanged.size() > 0,
    bootstrapped' = bootstrapped,
    remoteRev' = remoteRev,
    durableBootstrapRev' = durableBootstrapRev,
    durableSyncedRev' = remoteRev,
    storageRev' = storageRev,
    basePresent' = basePresent,
    baseOriginRev' = baseOriginRev,
    walPresent' = walPresent.union(pendingRemoteChanged),
    walOriginRev' = PAGES.mapBy(p =>
      if (p.in(pendingRemoteChanged)) { remoteRev } else { walOriginRev.get(p) }
    ),
    pendingRemoteChanged' = Set(),
    lastLazyRequestRev' = lastLazyRequestRev,
  }

  action pullNoChanges = all {
    bootstrapped,
    pendingRemoteChanged.size() == 0,
    keepRevisionState,
    keepPages,
  }

  action lazyLoad = {
    nondet p = PAGES.oneOf()
    lazyLoadPage(p)
  }

  action lazyLoadPage(p: int): bool = all {
    bootstrapped,
    p.in(PAGES),
    not(p.in(basePresent)),
    not(p.in(walPresent)),
    bootstrapped' = bootstrapped,
    remoteRev' = remoteRev,
    durableBootstrapRev' = durableBootstrapRev,
    durableSyncedRev' = durableSyncedRev,
    storageRev' = storageRev,
    basePresent' = basePresent.union(Set(p)),
    baseOriginRev' = baseOriginRev.set(p, storageRev),
    walPresent' = walPresent,
    walOriginRev' = walOriginRev,
    pendingRemoteChanged' = pendingRemoteChanged,
    lastLazyRequestRev' = lastLazyRequestRev.set(p, storageRev),
  }

  action reopen = all {
    bootstrapped,
    bootstrapped' = bootstrapped,
    remoteRev' = remoteRev,
    durableBootstrapRev' = durableBootstrapRev,
    durableSyncedRev' = durableSyncedRev,
    storageRev' = durableBootstrapRev,
    keepPages,
  }

  action buggyReopenUsesSyncedRevForStorage = all {
    bootstrapped,
    bootstrapped' = bootstrapped,
    remoteRev' = remoteRev,
    durableBootstrapRev' = durableBootstrapRev,
    durableSyncedRev' = durableSyncedRev,
    storageRev' = durableSyncedRev,
    keepPages,
  }

  run reproSyncedAdvancesButLazyLoadUsesBootstrapRev =
    init
      .then(partialBootstrapWith(Set(1)))
      .then(remoteAdvanceChanging(3))
      .then(pullRemote)
      .expect(durableSyncedRev == R1)
      .expect(storageRev == durableBootstrapRev)
      .then(lazyLoadPage(2))
      .expect(lastLazyRequestRev.get(2) == R0)
      .expect(baseOriginRev.get(2) == R0)
      .expect(CurrentImplementationCoherence)
      .expect(LazyLoadsPinnedToBootstrap)

  run reproReopenKeepsStoragePinnedToBootstrap =
    init
      .then(partialBootstrapWith(Set(1)))
      .then(remoteAdvanceChanging(3))
      .then(pullRemote)
      .then(reopen)
      .expect(durableSyncedRev == R1)
      .expect(storageRev == durableBootstrapRev)
      .then(lazyLoadPage(2))
      .expect(lastLazyRequestRev.get(2) == R0)
      .expect(LazyLoadsPinnedToBootstrap)

  run reproBuggyReopenMixesLazyBaseRevision =
    init
      .then(partialBootstrapWith(Set(1)))
      .then(remoteAdvanceChanging(3))
      .then(pullRemote)
      .then(buggyReopenUsesSyncedRevForStorage)
      .expect(storageRev == durableSyncedRev)
      .expect(storageRev != durableBootstrapRev)
      .then(lazyLoadPage(2))
      .expect(lastLazyRequestRev.get(2) == R1)
      .expect(not(CurrentImplementationCoherence))
      .expect(not(LazyLoadsPinnedToBootstrap))

  run reproPullNoChangesDoesNotAdvanceSyncedRev =
    init
      .then(partialBootstrapWith(Set(1)))
      .then(pullNoChanges)
      .expect(durableSyncedRev == R0)
      .expect(storageRev == durableBootstrapRev)

  action step = any {
    partialBootstrap,
    remoteAdvance,
    pullRemote,
    pullNoChanges,
    lazyLoad,
    reopen,
  }

  pure def TypeOK: bool =
    and {
      remoteRev.in(REVS),
      durableBootstrapRev.in(REVS),
      durableSyncedRev.in(REVS),
      storageRev.in(REVS),
      basePresent.subseteq(PAGES),
      walPresent.subseteq(PAGES),
      pendingRemoteChanged.subseteq(PAGES),
      baseOriginRev.keys() == PAGES,
      walOriginRev.keys() == PAGES,
      lastLazyRequestRev.keys() == PAGES,
      PAGES.forall(p =>
        and {
          baseOriginRev.get(p).in(REVS),
          walOriginRev.get(p).in(REVS),
          lastLazyRequestRev.get(p).in(REVS),
          p.in(basePresent) or baseOriginRev.get(p) == NO_REV,
          p.in(walPresent) or walOriginRev.get(p) == NO_REV,
        }
      ),
      not(bootstrapped) implies and {
        remoteRev == NO_REV,
        durableBootstrapRev == NO_REV,
        durableSyncedRev == NO_REV,
        storageRev == NO_REV,
      },
      bootstrapped implies and {
        durableBootstrapRev == R0,
        durableSyncedRev >= durableBootstrapRev,
        remoteRev >= durableSyncedRev,
      },
    }

  pure def CurrentImplementationCoherence: bool =
    not(bootstrapped) or storageRev == durableBootstrapRev

  pure def LazyLoadsPinnedToBootstrap: bool =
    not(bootstrapped) or
      PAGES.forall(p =>
        lastLazyRequestRev.get(p) == NO_REV or
          lastLazyRequestRev.get(p) == durableBootstrapRev
      )

  pure def BaseOriginPinnedToBootstrap: bool =
    not(bootstrapped) or
      basePresent.forall(p => baseOriginRev.get(p) == durableBootstrapRev)

  temporal spec = init.and(always(step.orKeep(
    (
      bootstrapped,
      remoteRev,
      durableBootstrapRev,
      durableSyncedRev,
      storageRev,
      basePresent,
      baseOriginRev,
      walPresent,
      walOriginRev,
      pendingRemoteChanged,
      lastLazyRequestRev
    )
  )))
}
