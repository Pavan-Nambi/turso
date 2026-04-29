module turso_sync_crash {
  pure val CLIENTS: Set[str] = Set("c1", "c2")
  pure val NO_CLIENT: str = "none"
  pure val NO_PULL: int = -1
  pure val MAX_CHANGE: int = 4
  pure val MAX_REV: int = 5
  pure val CHANGE_IDS: Set[int] = 1.to(MAX_CHANGE)
  pure val REVS: Set[int] = 0.to(MAX_REV)
  pure val PHASES: Set[str] = Set(
    "idle",
    "apply_main_committed",
    "apply_revert_reset",
    "apply_meta_file_written",
    "checkpoint_revert_written",
    "checkpoint_meta_file_written"
  )

  // Remote state and historical snapshots.
  var serverRev: int
  var serverRows: Set[int]
  var serverRowsAtRev: int -> Set[int]
  var remotePullGen: str -> int
  var remoteChangeId: str -> int
  var remotePullGenAtRev: int -> (str -> int)
  var remoteChangeIdAtRev: int -> (str -> int)

  // Local database state. localPullGen is stored in the main DB sync table, not
  // in the metadata file.
  var clientRows: str -> Set[int]
  var localCdc: str -> Set[int]
  var localPullGen: str -> int
  var syncedBaseRows: str -> Set[int]

  // Metadata file fields and in-memory metadata copy. update_meta writes the
  // file before replacing in-memory metadata.
  var durableSyncedRevision: str -> int
  var memSyncedRevision: str -> int

  // Revert WAL state. recoveryBaseRows is the base that a future apply can
  // recover by using durable metadata plus revert WAL.
  var revertBaseRows: str -> Set[int]
  var recoveryBaseRows: str -> Set[int]

  // Volatile wait_changes result. It is a WAL delta from changesFileFromRev to
  // changesFileRev, represented abstractly by the target snapshot.
  var changesFileFromRev: str -> int
  var changesFileRev: str -> int
  var changesFileRows: str -> Set[int]
  var changesFilePullGen: str -> int
  var changesFileChangeId: str -> int

  // Apply/checkpoint phase state.
  var phase: str -> str
  var pendingRev: str -> int
  var pendingBaseRows: str -> Set[int]
  var pendingResultRows: str -> Set[int]
  var pendingNewPullGen: str -> int

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
    localPullGen' = zeroClientInts,
    syncedBaseRows' = emptyClientRows,
    durableSyncedRevision' = zeroClientInts,
    memSyncedRevision' = zeroClientInts,
    revertBaseRows' = emptyClientRows,
    recoveryBaseRows' = emptyClientRows,
    changesFileFromRev' = noPullClientInts,
    changesFileRev' = noPullClientInts,
    changesFileRows' = emptyClientRows,
    changesFilePullGen' = zeroClientInts,
    changesFileChangeId' = zeroClientInts,
    phase' = CLIENTS.mapBy(_ => "idle"),
    pendingRev' = noPullClientInts,
    pendingBaseRows' = emptyClientRows,
    pendingResultRows' = emptyClientRows,
    pendingNewPullGen' = zeroClientInts,
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

  action keepLocalCore = all {
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision,
    revertBaseRows' = revertBaseRows,
    recoveryBaseRows' = recoveryBaseRows,
    changesFileFromRev' = changesFileFromRev,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    phase' = phase,
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  action localWrite = {
    nondet c = CLIENTS.oneOf()
    localWriteFor(c)
  }

  action localWriteFor(c: str): bool = all {
    c.in(CLIENTS),
    phase.get(c) == "idle",
    nextChangeId <= MAX_CHANGE,
    keepServer,
    clientRows' = clientRows.set(c, clientRows.get(c).union(Set(nextChangeId))),
    localCdc' = localCdc.set(c, localCdc.get(c).union(Set(nextChangeId))),
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision,
    revertBaseRows' = revertBaseRows,
    recoveryBaseRows' = recoveryBaseRows,
    changesFileFromRev' = changesFileFromRev,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    phase' = phase,
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated.union(Set(nextChangeId)),
    changeOwner' = changeOwner.set(nextChangeId, c),
    nextChangeId' = nextChangeId + 1,
  }

  action pushObserved = push(true)
  action pushLostResponse = push(false)

  action push(observed: bool): bool = {
    nondet c = CLIENTS.oneOf()
    nondet upTo = localCdc.get(c).oneOf()
    pushFor(c, upTo)
  }

  action pushFor(c: str, upTo: int): bool = {
    val pushed = localCdc.get(c).filter(x => x <= upTo)
    val newRows = serverRows.union(pushed)
    val newRev = serverRev + 1
    val newRemotePullGen = remotePullGen.set(c, localPullGen.get(c))
    val newRemoteChangeId = remoteChangeId.set(
      c,
      if (upTo > remoteChangeId.get(c)) upTo else remoteChangeId.get(c)
    )
    all {
      c.in(CLIENTS),
      phase.get(c) == "idle",
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
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      durableSyncedRevision' = durableSyncedRevision,
      memSyncedRevision' = memSyncedRevision,
      revertBaseRows' = revertBaseRows,
      recoveryBaseRows' = recoveryBaseRows,
      changesFileFromRev' = changesFileFromRev,
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      phase' = phase,
      pendingRev' = pendingRev,
      pendingBaseRows' = pendingBaseRows,
      pendingResultRows' = pendingResultRows,
      pendingNewPullGen' = pendingNewPullGen,
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  action waitChanges = {
    nondet c = CLIENTS.oneOf()
    waitChangesFor(c)
  }

  action waitChangesFor(c: str): bool = all {
    c.in(CLIENTS),
    phase.get(c) == "idle",
    keepServer,
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision,
    revertBaseRows' = revertBaseRows,
    recoveryBaseRows' = recoveryBaseRows,
    changesFileFromRev' = changesFileFromRev.set(c, memSyncedRevision.get(c)),
    changesFileRev' = changesFileRev.set(c, serverRev),
    changesFileRows' = changesFileRows.set(c, serverRowsAtRev.get(serverRev)),
    changesFilePullGen' = changesFilePullGen.set(c, remotePullGenAtRev.get(serverRev).get(c)),
    changesFileChangeId' = changesFileChangeId.set(c, remoteChangeIdAtRev.get(serverRev).get(c)),
    phase' = phase,
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  // Main DB commit cut. This abstracts wal_session.end(true): the remote WAL
  // delta has become durable in the main DB, and the sync-table pull_gen written
  // by local replay is durable too. The metadata file is still old.
  action beginApply = {
    nondet c = CLIENTS.oneOf()
    beginApplyFor(c)
  }

  action beginApplyFor(c: str): bool = {
    val fromRev = changesFileFromRev.get(c)
    val toRev = changesFileRev.get(c)
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
      c.in(CLIENTS),
      phase.get(c) == "idle",
      fromRev != NO_PULL,
      toRev != NO_PULL,
      fromRev == memSyncedRevision.get(c),
      recoveryBaseRows.get(c) == serverRowsAtRev.get(fromRev),
      pulledRows == serverRowsAtRev.get(toRev),
      pulledGen <= localPullGen.get(c),
      keepServer,
      clientRows' = clientRows.set(c, pulledRows.union(suffix)),
      localCdc' = localCdc,
      localPullGen' = localPullGen.set(c, newPullGen),
      syncedBaseRows' = syncedBaseRows.set(c, pulledRows),
      durableSyncedRevision' = durableSyncedRevision,
      memSyncedRevision' = memSyncedRevision,
      revertBaseRows' = revertBaseRows,
      recoveryBaseRows' = recoveryBaseRows,
      changesFileFromRev' = changesFileFromRev,
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      phase' = phase.set(c, "apply_main_committed"),
      pendingRev' = pendingRev.set(c, toRev),
      pendingBaseRows' = pendingBaseRows.set(c, pulledRows),
      pendingResultRows' = pendingResultRows.set(c, pulledRows.union(suffix)),
      pendingNewPullGen' = pendingNewPullGen.set(c, newPullGen),
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  // reset_wal_file(revert) cut. This is the dangerous window: old metadata may
  // still name the old revision, but the old revert material is gone.
  action resetRevertAfterApply = {
    nondet c = CLIENTS.oneOf()
    resetRevertAfterApplyFor(c)
  }

  action resetRevertAfterApplyFor(c: str): bool = all {
    c.in(CLIENTS),
    phase.get(c) == "apply_main_committed",
    keepServer,
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision,
    revertBaseRows' = revertBaseRows.set(c, pendingBaseRows.get(c)),
    recoveryBaseRows' = recoveryBaseRows.set(c, pendingBaseRows.get(c)),
    changesFileFromRev' = changesFileFromRev,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    phase' = phase.set(c, "apply_revert_reset"),
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  // Metadata file write cut inside update_meta.
  action writeMetaAfterApply = {
    nondet c = CLIENTS.oneOf()
    all {
      phase.get(c) == "apply_revert_reset",
      keepServer,
      clientRows' = clientRows,
      localCdc' = localCdc,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      durableSyncedRevision' = durableSyncedRevision.set(c, pendingRev.get(c)),
      memSyncedRevision' = memSyncedRevision,
      revertBaseRows' = revertBaseRows,
      recoveryBaseRows' = recoveryBaseRows,
      changesFileFromRev' = changesFileFromRev,
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      phase' = phase.set(c, "apply_meta_file_written"),
      pendingRev' = pendingRev,
      pendingBaseRows' = pendingBaseRows,
      pendingResultRows' = pendingResultRows,
      pendingNewPullGen' = pendingNewPullGen,
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  // In-memory metadata update and operation completion.
  action finishApply = {
    nondet c = CLIENTS.oneOf()
    all {
      phase.get(c) == "apply_meta_file_written",
      keepServer,
      clientRows' = clientRows,
      localCdc' = localCdc,
      localPullGen' = localPullGen,
      syncedBaseRows' = syncedBaseRows,
      durableSyncedRevision' = durableSyncedRevision,
      memSyncedRevision' = memSyncedRevision.set(c, durableSyncedRevision.get(c)),
      revertBaseRows' = revertBaseRows,
      recoveryBaseRows' = recoveryBaseRows,
      changesFileFromRev' = changesFileFromRev.set(c, NO_PULL),
      changesFileRev' = changesFileRev.set(c, NO_PULL),
      changesFileRows' = changesFileRows.set(c, Set()),
      changesFilePullGen' = changesFilePullGen.set(c, 0),
      changesFileChangeId' = changesFileChangeId.set(c, 0),
      phase' = phase.set(c, "idle"),
      pendingRev' = pendingRev.set(c, NO_PULL),
      pendingBaseRows' = pendingBaseRows.set(c, Set()),
      pendingResultRows' = pendingResultRows.set(c, Set()),
      pendingNewPullGen' = pendingNewPullGen.set(c, 0),
      generated' = generated,
      changeOwner' = changeOwner,
      nextChangeId' = nextChangeId,
    }
  }

  action checkpointWriteRevert = {
    nondet c = CLIENTS.oneOf()
    checkpointWriteRevertFor(c)
  }

  action checkpointWriteRevertFor(c: str): bool = all {
    c.in(CLIENTS),
    phase.get(c) == "idle",
    keepServer,
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision,
    revertBaseRows' = revertBaseRows.set(c, syncedBaseRows.get(c)),
    recoveryBaseRows' = recoveryBaseRows.set(c, syncedBaseRows.get(c)),
    changesFileFromRev' = changesFileFromRev,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    phase' = phase.set(c, "checkpoint_revert_written"),
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  action checkpointWriteMeta = {
    nondet c = CLIENTS.oneOf()
    checkpointWriteMetaFor(c)
  }

  action checkpointWriteMetaFor(c: str): bool = all {
    c.in(CLIENTS),
    phase.get(c) == "checkpoint_revert_written",
    keepServer,
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision,
    revertBaseRows' = revertBaseRows,
    recoveryBaseRows' = recoveryBaseRows,
    changesFileFromRev' = changesFileFromRev,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    phase' = phase.set(c, "checkpoint_meta_file_written"),
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  action finishCheckpoint = {
    nondet c = CLIENTS.oneOf()
    finishCheckpointFor(c)
  }

  action finishCheckpointFor(c: str): bool = all {
    c.in(CLIENTS),
    phase.get(c) == "checkpoint_meta_file_written",
    keepServer,
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision.set(c, durableSyncedRevision.get(c)),
    revertBaseRows' = revertBaseRows,
    recoveryBaseRows' = recoveryBaseRows,
    changesFileFromRev' = changesFileFromRev,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    phase' = phase.set(c, "idle"),
    pendingRev' = pendingRev,
    pendingBaseRows' = pendingBaseRows,
    pendingResultRows' = pendingResultRows,
    pendingNewPullGen' = pendingNewPullGen,
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  // Crash/restart reloads in-memory metadata from the metadata file and loses
  // the volatile changes status. It does not invent a recovery procedure.
  action crashRestart = {
    nondet c = CLIENTS.oneOf()
    crashRestartFor(c)
  }

  action crashRestartFor(c: str): bool = all {
    c.in(CLIENTS),
    keepServer,
    clientRows' = clientRows,
    localCdc' = localCdc,
    localPullGen' = localPullGen,
    syncedBaseRows' = syncedBaseRows,
    durableSyncedRevision' = durableSyncedRevision,
    memSyncedRevision' = memSyncedRevision.set(c, durableSyncedRevision.get(c)),
    revertBaseRows' = revertBaseRows,
    recoveryBaseRows' = recoveryBaseRows,
    changesFileFromRev' = changesFileFromRev.set(c, NO_PULL),
    changesFileRev' = changesFileRev.set(c, NO_PULL),
    changesFileRows' = changesFileRows.set(c, Set()),
    changesFilePullGen' = changesFilePullGen.set(c, 0),
    changesFileChangeId' = changesFileChangeId.set(c, 0),
    phase' = phase.set(c, "idle"),
    pendingRev' = pendingRev.set(c, NO_PULL),
    pendingBaseRows' = pendingBaseRows.set(c, Set()),
    pendingResultRows' = pendingResultRows.set(c, Set()),
    pendingNewPullGen' = pendingNewPullGen.set(c, 0),
    generated' = generated,
    changeOwner' = changeOwner,
    nextChangeId' = nextChangeId,
  }

  run reproApplyCrashLosesModeledRecoveryBasis =
    init
      .then(localWriteFor("c1"))
      .then(pushFor("c1", 1))
      .then(waitChangesFor("c2"))
      .then(beginApplyFor("c2"))
      .then(resetRevertAfterApplyFor("c2"))
      .then(crashRestartFor("c2"))
      .expect(not(IdlePullBasisRecoverable))

  run reproApplyCrashKeepsVisibleRows =
    init
      .then(localWriteFor("c1"))
      .then(pushFor("c1", 1))
      .then(waitChangesFor("c2"))
      .then(beginApplyFor("c2"))
      .then(resetRevertAfterApplyFor("c2"))
      .then(crashRestartFor("c2"))
      .expect(IdleOwnedChangesVisible and IdleClientViewExact)

  run reproCheckpointMetaAfterApplyCrashLosesModeledRecoveryBasis =
    init
      .then(localWriteFor("c1"))
      .then(pushFor("c1", 1))
      .then(waitChangesFor("c2"))
      .then(beginApplyFor("c2"))
      .then(resetRevertAfterApplyFor("c2"))
      .then(crashRestartFor("c2"))
      .then(checkpointWriteRevertFor("c2"))
      .then(checkpointWriteMetaFor("c2"))
      .then(crashRestartFor("c2"))
      .expect(not(IdlePullBasisRecoverable))

  action step = any {
    localWrite,
    pushObserved,
    pushLostResponse,
    waitChanges,
    beginApply,
    resetRevertAfterApply,
    writeMetaAfterApply,
    finishApply,
    checkpointWriteRevert,
    checkpointWriteMeta,
    finishCheckpoint,
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
      localPullGen.keys() == CLIENTS,
      syncedBaseRows.keys() == CLIENTS,
      durableSyncedRevision.keys() == CLIENTS,
      memSyncedRevision.keys() == CLIENTS,
      revertBaseRows.keys() == CLIENTS,
      recoveryBaseRows.keys() == CLIENTS,
      changesFileFromRev.keys() == CLIENTS,
      changesFileRev.keys() == CLIENTS,
      changesFileRows.keys() == CLIENTS,
      changesFilePullGen.keys() == CLIENTS,
      changesFileChangeId.keys() == CLIENTS,
      phase.keys() == CLIENTS,
      pendingRev.keys() == CLIENTS,
      pendingBaseRows.keys() == CLIENTS,
      pendingResultRows.keys() == CLIENTS,
      pendingNewPullGen.keys() == CLIENTS,
      generated.subseteq(CHANGE_IDS),
      changeOwner.keys() == CHANGE_IDS,
      nextChangeId >= 1,
      nextChangeId <= MAX_CHANGE + 1,
      CHANGE_IDS.forall(x => changeOwner.get(x).in(CLIENTS.union(Set(NO_CLIENT)))),
      generated.forall(x => changeOwner.get(x) != NO_CLIENT),
      CLIENTS.forall(c =>
        and {
          phase.get(c).in(PHASES),
          clientRows.get(c).subseteq(generated),
          localCdc.get(c).subseteq(ownedBy(c)),
          durableSyncedRevision.get(c).in(REVS),
          memSyncedRevision.get(c).in(REVS),
          localPullGen.get(c) >= 0,
          syncedBaseRows.get(c).subseteq(generated),
          revertBaseRows.get(c).subseteq(generated),
          recoveryBaseRows.get(c).subseteq(generated),
          changesFileFromRev.get(c) == NO_PULL or changesFileFromRev.get(c).in(REVS),
          changesFileRev.get(c) == NO_PULL or changesFileRev.get(c).in(REVS),
          changesFileRows.get(c).subseteq(generated),
          changesFilePullGen.get(c) >= 0,
          changesFileChangeId.get(c) >= 0,
          pendingRev.get(c) == NO_PULL or pendingRev.get(c).in(REVS),
          pendingBaseRows.get(c).subseteq(generated),
          pendingResultRows.get(c).subseteq(generated),
          pendingNewPullGen.get(c) >= 0,
        }
      ),
    }

  pure def IdleClientViewExact: bool =
    CLIENTS.forall(c =>
      phase.get(c) != "idle" or clientRows.get(c) == clientView(c)
    )

  pure def IdlePullBasisRecoverable: bool =
    CLIENTS.forall(c =>
      phase.get(c) != "idle" or
        recoveryBaseRows.get(c) == serverRowsAtRev.get(durableSyncedRevision.get(c))
    )

  pure def IdleOwnedChangesVisible: bool =
    CLIENTS.forall(c =>
      phase.get(c) != "idle" or ownedBy(c).subseteq(clientRows.get(c))
    )

  pure def RemoteCursorSound: bool =
    REVS.forall(r =>
      CLIENTS.forall(c =>
        localCdc.get(c)
          .filter(x => x <= remoteChangeIdAtRev.get(r).get(c))
          .subseteq(serverRowsAtRev.get(r))
      )
    )

  pure def PullBufferSound: bool =
    CLIENTS.forall(c =>
      changesFileRev.get(c) == NO_PULL or
        and {
          changesFileFromRev.get(c).in(REVS),
          changesFileRows.get(c) == serverRowsAtRev.get(changesFileRev.get(c)),
          changesFilePullGen.get(c) == remotePullGenAtRev.get(changesFileRev.get(c)).get(c),
          changesFileChangeId.get(c) == remoteChangeIdAtRev.get(changesFileRev.get(c)).get(c),
        }
    )

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
      localPullGen,
      syncedBaseRows,
      durableSyncedRevision,
      memSyncedRevision,
      revertBaseRows,
      recoveryBaseRows,
      changesFileFromRev,
      changesFileRev,
      changesFileRows,
      changesFilePullGen,
      changesFileChangeId,
      phase,
      pendingRev,
      pendingBaseRows,
      pendingResultRows,
      pendingNewPullGen,
      generated,
      changeOwner,
      nextChangeId
    )
  )))
}
