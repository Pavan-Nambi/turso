module turso_sync {
  // Small finite model. Increase these only after the base model verifies.
  pure val CLIENTS: Set[str] = Set("c1", "c2")
  pure val NO_CLIENT: str = "none"
  pure val NO_PULL: int = -1
  pure val MAX_CHANGE: int = 4
  pure val MAX_REV: int = 5
  pure val CHANGE_IDS: Set[int] = 1.to(MAX_CHANGE)
  pure val REVS: Set[int] = 0.to(MAX_REV)

  // Remote state.
  var serverRev: int
  var serverRows: Set[int]
  var serverRowsAtRev: int -> Set[int]

  // Remote turso_sync_last_change_id snapshots.
  var remotePullGen: str -> int
  var remoteChangeId: str -> int
  var remotePullGenAtRev: int -> (str -> int)
  var remoteChangeIdAtRev: int -> (str -> int)

  // Local durable/visible client state.
  var clientRows: str -> Set[int]
  var localCdc: str -> Set[int]
  var syncedRevision: str -> int
  var localPullGen: str -> int
  var syncedBaseRows: str -> Set[int]
  var revertBaseRows: str -> Set[int]
  var lastPushedHint: str -> int

  // Volatile wait_changes buffer.
  var changesFileRev: str -> int
  var changesFileRows: str -> Set[int]
  var changesFilePullGen: str -> int
  var changesFileChangeId: str -> int

  // Change-id allocation and ownership.
  var generated: Set[int]
  var changeOwner: int -> str
  var nextChangeId: int

  pure val emptyClientRows: str -> Set[int] =
    CLIENTS.mapBy(_ => Set())

  pure val zeroClientInts: str -> int =
    CLIENTS.mapBy(_ => 0)

  pure val noPullClientInts: str -> int =
    CLIENTS.mapBy(_ => NO_PULL)

  pure val emptyRowsByRev: int -> Set[int] =
    REVS.mapBy(_ => Set())

  pure val zeroCursorsByRev: int -> (str -> int) =
    REVS.mapBy(_ => zeroClientInts)

  def ownedBy(c: str): Set[int] =
    generated.filter(x => changeOwner.get(x) == c)

  def localReplaySuffix(c: str, pullGen: int, changeId: int): Set[int] =
    if (pullGen == localPullGen.get(c)) {
      localCdc.get(c).filter(x => x > changeId)
    } else {
      localCdc.get(c)
    }

  def clientView(c: str): Set[int] =
    syncedBaseRows.get(c).union(localCdc.get(c))

  action init = all {
    serverRev' = 0,
    serverRows' = Set(),
    serverRowsAtRev' = emptyRowsByRev,
    remotePullGen' = zeroClientInts,
    remoteChangeId' = zeroClientInts,
    remotePullGenAtRev' = zeroCursorsByRev,
    remoteChangeIdAtRev' = zeroCursorsByRev,
    clientRows' = emptyClientRows,
    localCdc' = emptyClientRows,
    syncedRevision' = zeroClientInts,
    localPullGen' = zeroClientInts,
    syncedBaseRows' = emptyClientRows,
    revertBaseRows' = emptyClientRows,
    lastPushedHint' = zeroClientInts,
    changesFileRev' = noPullClientInts,
    changesFileRows' = emptyClientRows,
    changesFilePullGen' = zeroClientInts,
    changesFileChangeId' = zeroClientInts,
    generated' = Set(),
    changeOwner' = CHANGE_IDS.mapBy(_ => NO_CLIENT),
    nextChangeId' = 1,
  }

  action keepServer = all {
    serverRev' = serverRev,
    serverRows' = serverRows,
    serverRowsAtRev' = serverRowsAtRev,
    remotePullGen' = remotePullGen,
    remoteChangeId' = remoteChangeId,
    remotePullGenAtRev' = remotePullGenAtRev,
    remoteChangeIdAtRev' = remoteChangeIdAtRev,
  }

  action keepLocal = all {
    clientRows' = clientRows,
    localCdc' = localCdc,
    syncedRevision' = syncedRevision,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    revertBaseRows' = revertBaseRows,
    lastPushedHint' = lastPushedHint,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  // A user transaction captured by CDC. Change ids are ordered and unique.
  action localWrite = {
    nondet c = CLIENTS.oneOf()
    all {
      nextChangeId <= MAX_CHANGE,
      keepServer,
      clientRows' = clientRows.set(c, clientRows.get(c).union(Set(nextChangeId))),
      localCdc' = localCdc.set(c, localCdc.get(c).union(Set(nextChangeId))),
      syncedRevision' = syncedRevision,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      revertBaseRows' = revertBaseRows,
      lastPushedHint' = lastPushedHint,
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      generated' = generated.union(Set(nextChangeId)),
      changeOwner' = changeOwner.set(nextChangeId, c),
      nextChangeId' = nextChangeId + 1,
    }
  }

  // Remote SQL batch committed, and the client observed success.
  action pushObserved = push(true)

  // Remote SQL batch committed, but the client lost the response before it could
  // update its local last_pushed hint. A retry should be harmless because push
  // fetches the remote cursor first.
  action pushLostResponse = push(false)

  action push(observed: bool): bool = {
    nondet c = CLIENTS.oneOf()
    nondet upTo = localCdc.get(c).oneOf()
    val pushed = localCdc.get(c).filter(x => x <= upTo)
    val newRows = serverRows.union(pushed)
    val newRev = serverRev + 1
    val newRemotePullGen = remotePullGen.set(c, localPullGen.get(c))
    val newRemoteChangeId = remoteChangeId.set(
      c,
      if (upTo > remoteChangeId.get(c)) upTo else remoteChangeId.get(c)
    )
    all {
      serverRev < MAX_REV,
      pushed.size() > 0,
      serverRev' = newRev,
      serverRows' = newRows,
      serverRowsAtRev' = serverRowsAtRev.set(newRev, newRows),
      remotePullGen' = newRemotePullGen,
      remoteChangeId' = newRemoteChangeId,
      remotePullGenAtRev' = remotePullGenAtRev.set(newRev, newRemotePullGen),
      remoteChangeIdAtRev' = remoteChangeIdAtRev.set(newRev, newRemoteChangeId),
      clientRows' = clientRows,
      localCdc' = localCdc,
      syncedRevision' = syncedRevision,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      revertBaseRows' = revertBaseRows,
      lastPushedHint' = if (observed) {
        lastPushedHint.set(c, newRemoteChangeId.get(c))
      } else {
        lastPushedHint
      },
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  // wait_changes_from_remote stores a historical remote snapshot. The current
  // server can move forward before apply_changes_from_remote consumes it.
  action waitChanges = {
    nondet c = CLIENTS.oneOf()
    all {
      keepServer,
      clientRows' = clientRows,
      localCdc' = localCdc,
      syncedRevision' = syncedRevision,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      revertBaseRows' = revertBaseRows,
      lastPushedHint' = lastPushedHint,
      changesFileRev' = changesFileRev.set(c, serverRev),
      changesFileRows' = changesFileRows.set(c, serverRowsAtRev.get(serverRev)),
      changesFilePullGen' = changesFilePullGen.set(c, remotePullGenAtRev.get(serverRev).get(c)),
      changesFileChangeId' = changesFileChangeId.set(c, remoteChangeIdAtRev.get(serverRev).get(c)),
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  // apply_changes_from_remote rolls back to the synced base, applies the pulled
  // remote snapshot, and replays the local CDC suffix not acknowledged by that
  // pulled snapshot's remote cursor.
  action applyChanges = {
    nondet c = CLIENTS.oneOf()
    val pulledRev = changesFileRev.get(c)
    val pulledRows = changesFileRows.get(c)
    val pulledGen = changesFilePullGen.get(c)
    val pulledChangeId = changesFileChangeId.get(c)
    val suffix = localReplaySuffix(c, pulledGen, pulledChangeId)
    val newPullGen = if (suffix.size() > 0) {
      localPullGen.get(c) + 1
    } else {
      localPullGen.get(c)
    }
    all {
      pulledRev != NO_PULL,
      pulledGen <= localPullGen.get(c),
      keepServer,
      clientRows' = clientRows.set(c, pulledRows.union(suffix)),
      localCdc' = localCdc,
      syncedRevision' = syncedRevision.set(c, pulledRev),
      localPullGen' = localPullGen.set(c, newPullGen),
      syncedBaseRows' = syncedBaseRows.set(c, pulledRows),
      revertBaseRows' = revertBaseRows.set(c, pulledRows),
      lastPushedHint' = lastPushedHint,
      changesFileRev' = changesFileRev.set(c, NO_PULL),
      changesFileRows' = changesFileRows.set(c, Set()),
      changesFilePullGen' = changesFilePullGen.set(c, 0),
      changesFileChangeId' = changesFileChangeId.set(c, 0),
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  // Checkpoint is observationally transparent for this abstraction. It refreshes
  // the modeled rollback baseline to the synced base, not to the current local
  // view with pending local CDC changes.
  action checkpoint = {
    nondet c = CLIENTS.oneOf()
    all {
      keepServer,
      clientRows' = clientRows,
      localCdc' = localCdc,
      syncedRevision' = syncedRevision,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      revertBaseRows' = revertBaseRows.set(c, syncedBaseRows.get(c)),
      lastPushedHint' = lastPushedHint,
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  // Operation-boundary crash/restart: drop the volatile fetched changes file.
  // In-operation crash cut points are listed in README.md as the next extension.
  action crashRestart = {
    nondet c = CLIENTS.oneOf()
    all {
      keepServer,
      clientRows' = clientRows,
      localCdc' = localCdc,
      syncedRevision' = syncedRevision,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      revertBaseRows' = revertBaseRows,
      lastPushedHint' = lastPushedHint,
      changesFileRev' = changesFileRev.set(c, NO_PULL),
      changesFileRows' = changesFileRows.set(c, Set()),
      changesFilePullGen' = changesFilePullGen.set(c, 0),
      changesFileChangeId' = changesFileChangeId.set(c, 0),
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  action step = any {
    localWrite,
    pushObserved,
    pushLostResponse,
    waitChanges,
    applyChanges,
    checkpoint,
    crashRestart,
  }

  pure def TypeOK: bool =
    and {
      serverRev.in(REVS),
      serverRows.subseteq(generated),
      serverRowsAtRev.keys() == REVS,
      remotePullGen.keys() == CLIENTS,
      remoteChangeId.keys() == CLIENTS,
      remotePullGenAtRev.keys() == REVS,
      remoteChangeIdAtRev.keys() == REVS,
      clientRows.keys() == CLIENTS,
      localCdc.keys() == CLIENTS,
      syncedRevision.keys() == CLIENTS,
      localPullGen.keys() == CLIENTS,
      syncedBaseRows.keys() == CLIENTS,
      revertBaseRows.keys() == CLIENTS,
      lastPushedHint.keys() == CLIENTS,
      changesFileRev.keys() == CLIENTS,
      changesFileRows.keys() == CLIENTS,
      changesFilePullGen.keys() == CLIENTS,
      changesFileChangeId.keys() == CLIENTS,
      generated.subseteq(CHANGE_IDS),
      changeOwner.keys() == CHANGE_IDS,
      nextChangeId >= 1,
      nextChangeId <= MAX_CHANGE + 1,
      CHANGE_IDS.forall(x => changeOwner.get(x).in(CLIENTS.union(Set(NO_CLIENT)))),
      generated.forall(x => changeOwner.get(x) != NO_CLIENT),
      CLIENTS.forall(c =>
        and {
          clientRows.get(c).subseteq(generated),
          localCdc.get(c).subseteq(ownedBy(c)),
          syncedRevision.get(c).in(REVS),
          localPullGen.get(c) >= 0,
          syncedBaseRows.get(c).subseteq(generated),
          revertBaseRows.get(c).subseteq(generated),
          lastPushedHint.get(c) >= 0,
          changesFileRev.get(c) == NO_PULL or changesFileRev.get(c).in(REVS),
          changesFileRows.get(c).subseteq(generated),
          changesFilePullGen.get(c) >= 0,
          changesFileChangeId.get(c) >= 0,
        }
      ),
    }

  // A client view is exactly its installed remote base plus all locally generated
  // CDC changes. Insert-only semantics make this a set union.
  pure def ClientViewExact: bool =
    CLIENTS.forall(c => clientRows.get(c) == clientView(c))

  // If a remote revision acknowledges c's changes up to change_id, those changes
  // must be present in that same revision's rows. This is the key cursor
  // soundness condition used by applyChanges when replaying only a suffix.
  pure def RemoteCursorSound: bool =
    REVS.forall(r =>
      CLIENTS.forall(c =>
        localCdc.get(c)
          .filter(x => x <= remoteChangeIdAtRev.get(r).get(c))
          .subseteq(serverRowsAtRev.get(r))
      )
    )

  // A fetched changes file is an exact historical snapshot, including the
  // remote cursor observed at that revision.
  pure def PullBufferSound: bool =
    CLIENTS.forall(c =>
      changesFileRev.get(c) == NO_PULL or
        and {
          changesFileRows.get(c) == serverRowsAtRev.get(changesFileRev.get(c)),
          changesFilePullGen.get(c) == remotePullGenAtRev.get(changesFileRev.get(c)).get(c),
          changesFileChangeId.get(c) == remoteChangeIdAtRev.get(changesFileRev.get(c)).get(c),
        }
    )

  pure def RemoteCursorNotAhead: bool =
    CLIENTS.forall(c => remotePullGen.get(c) <= localPullGen.get(c))

  pure def RevertBaselineSound: bool =
    CLIENTS.forall(c => revertBaseRows.get(c).subseteq(clientRows.get(c)))

  temporal spec = init.and(always(step.orKeep(
    (
      serverRev,
      serverRows,
      serverRowsAtRev,
      remotePullGen,
      remoteChangeId,
      remotePullGenAtRev,
      remoteChangeIdAtRev,
      clientRows,
      localCdc,
      syncedRevision,
      localPullGen,
      syncedBaseRows,
      revertBaseRows,
      lastPushedHint,
      changesFileRev,
      changesFileRows,
      changesFilePullGen,
      changesFileChangeId,
      generated,
      changeOwner,
      nextChangeId
    )
  )))
}
