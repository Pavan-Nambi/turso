module turso_sync_dirty_clean {
  pure val OLD: int = 0
  pure val NEW1: int = 1
  pure val NEW2: int = 2
  pure val NO_VALUE: int = -1
  pure val VALUES: Set[int] = Set(OLD, NEW1, NEW2, NO_VALUE)

  pure val NONE: int = 0
  pure val CLEAN: int = 1
  pure val REMOTE: int = 2
  pure val READ_SOURCES: Set[int] = Set(NONE, CLEAN, REMOTE)

  pure val NO_PAGE: int = 0
  pure val PAGES: Set[int] = Set(1, 2)

  // Backend/configuration knobs:
  //
  // - hasDirty=false matches the current DatabaseSyncEngine construction, which
  //   passes dirty_file: None.
  // - hasDirty=true models the TODO future path where a dirty shadow file is
  //   allocated for the clean database file.
  // - asyncBackend=true models the File trait generally: pwrite/pwritev may
  //   return before the clean write completion fires.
  var hasDirty: bool
  var asyncBackend: bool

  // Clean file contents and dirty shadow contents. A dirty hole means the
  // clean page is trusted; a present dirty page is a validation shadow.
  var cleanHole: int -> bool
  var dirtyHole: int -> bool
  var cleanValue: int -> int
  var dirtyValue: int -> int

  // Last completed clean-file value. This is not fsync durability; it only
  // records whether the clean write completion has run.
  var completedCleanValue: int -> int

  // In-flight clean pwrite/pwritev completion. This is per page so write_pages
  // can complete one page while another remains pending.
  var pendingCleanWrite: int -> bool
  var pendingValue: int -> int

  // PageStates-style write guard. Current write_page releases the guard when
  // pwrite returns; current write_pages does not acquire a guard.
  var writeGuardHeld: int -> bool

  var lastReadPage: int
  var lastReadSource: int
  var lastReadValue: int
  var allReadDecisionsMatched: bool

  pure val oldByPage: int -> int =
    PAGES.mapBy(_ => OLD)

  pure val noPendingValueByPage: int -> int =
    PAGES.mapBy(_ => NO_VALUE)

  pure val falseByPage: int -> bool =
    PAGES.mapBy(_ => false)

  action initNoDirtySync = initWith(false, false)
  action initDirtySync = initWith(true, false)
  action initDirtyAsync = initWith(true, true)
  action initNoDirtyAsync = initWith(false, true)

  action initWith(configHasDirty: bool, configAsync: bool): bool = all {
    hasDirty' = configHasDirty,
    asyncBackend' = configAsync,
    cleanHole' = PAGES.mapBy(_ => false),
    dirtyHole' = PAGES.mapBy(_ => false),
    cleanValue' = oldByPage,
    dirtyValue' = oldByPage,
    completedCleanValue' = oldByPage,
    pendingCleanWrite' = falseByPage,
    pendingValue' = noPendingValueByPage,
    writeGuardHeld' = falseByPage,
    lastReadPage' = NO_PAGE,
    lastReadSource' = NONE,
    lastReadValue' = NO_VALUE,
    allReadDecisionsMatched' = true,
  }

  action init = any {
    initNoDirtySync,
    initDirtySync,
    initDirtyAsync,
    initNoDirtyAsync,
  }

  action keepConfig = all {
    hasDirty' = hasDirty,
    asyncBackend' = asyncBackend,
  }

  action keepFiles = all {
    cleanHole' = cleanHole,
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    completedCleanValue' = completedCleanValue,
  }

  action keepPending = all {
    pendingCleanWrite' = pendingCleanWrite,
    pendingValue' = pendingValue,
    writeGuardHeld' = writeGuardHeld,
  }

  action keepLastRead = all {
    lastReadPage' = lastReadPage,
    lastReadSource' = lastReadSource,
    lastReadValue' = lastReadValue,
    allReadDecisionsMatched' = allReadDecisionsMatched,
  }

  action recordRead(p: int, source: int, value: int): bool = all {
    lastReadPage' = p,
    lastReadSource' = source,
    lastReadValue' = value,
    allReadDecisionsMatched' = allReadDecisionsMatched,
  }

  action readPage = {
    nondet p = PAGES.oneOf()
    readPageAt(p)
  }

  action readPageAt(p: int): bool = all {
    p.in(PAGES),
    keepConfig,
    keepFiles,
    keepPending,
    if (cleanHole.get(p)) {
      recordRead(p, REMOTE, NEW2)
    } else if (not(hasDirty)) {
      recordRead(p, CLEAN, cleanValue.get(p))
    } else if (dirtyHole.get(p)) {
      recordRead(p, CLEAN, cleanValue.get(p))
    } else if (dirtyValue.get(p) == cleanValue.get(p)) {
      recordRead(p, CLEAN, cleanValue.get(p))
    } else {
      recordRead(p, REMOTE, NEW2)
    },
  }

  action writePageStartCurrent = {
    nondet p = PAGES.oneOf()
    nondet v = Set(NEW1, NEW2).oneOf()
    writePageStartCurrentAt(p, v)
  }

  action writePageStartCurrentAt(p: int, v: int): bool = all {
    p.in(PAGES),
    v.in(Set(NEW1, NEW2)),
    not(pendingCleanWrite.get(p)),
    not(writeGuardHeld.get(p)),
    keepConfig,
    cleanHole' = cleanHole,
    dirtyHole' = if (hasDirty) { dirtyHole.set(p, true) } else { dirtyHole },
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    completedCleanValue' = completedCleanValue,
    pendingCleanWrite' = if (asyncBackend) {
      pendingCleanWrite.set(p, true)
    } else {
      pendingCleanWrite
    },
    pendingValue' = if (asyncBackend) {
      pendingValue.set(p, v)
    } else {
      pendingValue
    },
    // This models current write_page: the guard is local to write_page and is
    // dropped when pwrite returns, even if the completion is still pending.
    writeGuardHeld' = writeGuardHeld.set(p, false),
    lastReadPage' = lastReadPage,
    lastReadSource' = lastReadSource,
    lastReadValue' = lastReadValue,
    allReadDecisionsMatched' = allReadDecisionsMatched,
  }

  action writePageSync = {
    nondet p = PAGES.oneOf()
    nondet v = Set(NEW1, NEW2).oneOf()
    writePageSyncAt(p, v)
  }

  action writePageSyncAt(p: int, v: int): bool = all {
    p.in(PAGES),
    v.in(Set(NEW1, NEW2)),
    not(asyncBackend),
    not(pendingCleanWrite.get(p)),
    keepConfig,
    cleanHole' = cleanHole.set(p, false),
    dirtyHole' = if (hasDirty) { dirtyHole.set(p, true) } else { dirtyHole },
    cleanValue' = cleanValue.set(p, v),
    dirtyValue' = dirtyValue,
    completedCleanValue' = completedCleanValue.set(p, v),
    keepPending,
    keepLastRead,
  }

  action writePagesStartCurrent(v1: int, v2: int): bool = all {
    v1.in(Set(NEW1, NEW2)),
    v2.in(Set(NEW1, NEW2)),
    asyncBackend,
    not(pendingCleanWrite.get(1)),
    not(pendingCleanWrite.get(2)),
    keepConfig,
    cleanHole' = cleanHole,
    dirtyHole' = if (hasDirty) {
      dirtyHole.set(1, true).set(2, true)
    } else {
      dirtyHole
    },
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue,
    completedCleanValue' = completedCleanValue,
    pendingCleanWrite' = pendingCleanWrite.set(1, true).set(2, true),
    pendingValue' = pendingValue.set(1, v1).set(2, v2),
    // Current write_pages does not acquire PageStatesGuard for the range.
    writeGuardHeld' = writeGuardHeld,
    keepLastRead,
  }

  action writePagesStart = {
    nondet v1 = Set(NEW1, NEW2).oneOf()
    nondet v2 = Set(NEW1, NEW2).oneOf()
    writePagesStartCurrent(v1, v2)
  }

  action cleanWriteComplete = {
    nondet p = PAGES.oneOf()
    cleanWriteCompleteAt(p)
  }

  action cleanWriteCompleteAt(p: int): bool = all {
    p.in(PAGES),
    pendingCleanWrite.get(p),
    keepConfig,
    cleanHole' = cleanHole.set(p, false),
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue.set(p, pendingValue.get(p)),
    dirtyValue' = dirtyValue,
    completedCleanValue' = completedCleanValue.set(p, pendingValue.get(p)),
    pendingCleanWrite' = pendingCleanWrite.set(p, false),
    pendingValue' = pendingValue.set(p, NO_VALUE),
    writeGuardHeld' = writeGuardHeld,
    keepLastRead,
  }

  action dirtyMismatch = {
    nondet p = PAGES.oneOf()
    dirtyMismatchAt(p)
  }

  action dirtyMismatchAt(p: int): bool = all {
    p.in(PAGES),
    hasDirty,
    not(dirtyHole.get(p)),
    cleanValue.get(p) == OLD,
    keepConfig,
    cleanHole' = cleanHole,
    dirtyHole' = dirtyHole,
    cleanValue' = cleanValue,
    dirtyValue' = dirtyValue.set(p, NEW1),
    completedCleanValue' = completedCleanValue,
    keepPending,
    keepLastRead,
  }

  run reproDirtyHoleBeforeCleanWriteAllowsFastStaleRead =
    initDirtyAsync
      .then(writePageStartCurrentAt(1, NEW1))
      .expect(dirtyHole.get(1))
      .expect(pendingCleanWrite.get(1))
      .expect(not(DirtyHoleMeansCleanCompleted))
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)
      .expect(not(NoSamePageFastReadWhileCleanWritePending))

  run reproWritePagesPartialCompletionLeavesSecondPageTrustedTooEarly =
    initDirtyAsync
      .then(writePagesStartCurrent(NEW1, NEW2))
      .then(cleanWriteCompleteAt(1))
      .expect(not(pendingCleanWrite.get(1)))
      .expect(pendingCleanWrite.get(2))
      .expect(dirtyHole.get(2))
      .then(readPageAt(2))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == OLD)
      .expect(not(NoSamePageFastReadWhileCleanWritePending))

  run reproDirtyMismatchFetchesRemoteInsteadOfTrustingClean =
    initDirtySync
      .then(dirtyMismatchAt(1))
      .then(readPageAt(1))
      .expect(lastReadSource == REMOTE)
      .expect(ReadDecisionMatchesImplementation)

  run reproCompletedSyncWriteMakesDirtyHoleTrusted =
    initDirtySync
      .then(writePageSyncAt(1, NEW1))
      .expect(dirtyHole.get(1))
      .expect(cleanValue.get(1) == NEW1)
      .expect(DirtyHoleMeansCleanCompleted)
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == NEW1)

  run reproCurrentNoDirtyFileDoesNotExerciseDirtyShadow =
    initNoDirtySync
      .then(writePageSyncAt(1, NEW1))
      .expect(not(hasDirty))
      .expect(CurrentNoDirtyFileDoesNotExerciseDirtyShadow)
      .then(readPageAt(1))
      .expect(lastReadSource == CLEAN)
      .expect(lastReadValue == NEW1)

  action step = any {
    readPage,
    writePageStartCurrent,
    writePageSync,
    writePagesStart,
    cleanWriteComplete,
    dirtyMismatch,
  }

  pure def TypeOK: bool =
    and {
      cleanHole.keys() == PAGES,
      dirtyHole.keys() == PAGES,
      cleanValue.keys() == PAGES,
      dirtyValue.keys() == PAGES,
      completedCleanValue.keys() == PAGES,
      pendingCleanWrite.keys() == PAGES,
      pendingValue.keys() == PAGES,
      writeGuardHeld.keys() == PAGES,
      PAGES.forall(p =>
        and {
          cleanValue.get(p).in(VALUES),
          dirtyValue.get(p).in(VALUES),
          completedCleanValue.get(p).in(VALUES),
          pendingValue.get(p).in(VALUES),
          pendingCleanWrite.get(p) or pendingValue.get(p) == NO_VALUE,
          not(cleanHole.get(p)) or cleanValue.get(p) == completedCleanValue.get(p),
        }
      ),
      lastReadPage.in(PAGES.union(Set(NO_PAGE))),
      lastReadSource.in(READ_SOURCES),
      lastReadValue.in(VALUES),
      allReadDecisionsMatched,
    }

  pure def CurrentNoDirtyFileDoesNotExerciseDirtyShadow: bool =
    not(hasDirty) implies PAGES.forall(p => not(dirtyHole.get(p)))

  pure def DirtyHoleMeansCleanCompleted: bool =
    PAGES.forall(p =>
      not(hasDirty) or
        cleanHole.get(p) or
        not(dirtyHole.get(p)) or
        and {
          not(pendingCleanWrite.get(p)),
          cleanValue.get(p) == completedCleanValue.get(p),
        }
    )

  pure def NoSamePageFastReadWhileCleanWritePending: bool =
    lastReadSource != CLEAN or
      lastReadPage == NO_PAGE or
      not(pendingCleanWrite.get(lastReadPage))

  pure def ReadDecisionMatchesImplementation: bool =
    allReadDecisionsMatched

  pure def PendingWritesHaveNoPageStateProtection: bool =
    PAGES.forall(p =>
      not(pendingCleanWrite.get(p)) or not(writeGuardHeld.get(p))
    )

  temporal spec = init.and(always(step.orKeep(
    (
      hasDirty,
      asyncBackend,
      cleanHole,
      dirtyHole,
      cleanValue,
      dirtyValue,
      completedCleanValue,
      pendingCleanWrite,
      pendingValue,
      writeGuardHeld,
      lastReadPage,
      lastReadSource,
      lastReadValue,
      allReadDecisionsMatched
    )
  )))
}
