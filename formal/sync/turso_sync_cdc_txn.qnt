module turso_sync_cdc_txn {
  pure val CLIENTS: Set[str] = Set("c1", "c2")
  pure val NO_CLIENT: str = "none"
  pure val NO_PULL: int = -1
  pure val DELETED: int = 0
  pure val MAX_TXN: int = 3
  pure val MAX_CHANGE: int = 6
  pure val MAX_REV: int = 5
  pure val TXNS: Set[int] = 1.to(MAX_TXN)
  pure val CHANGE_IDS: Set[int] = 1.to(MAX_CHANGE)
  pure val REVS: Set[int] = 0.to(MAX_REV)
  pure val KEYS: Set[int] = Set(1, 2)
  pure val VALUES: Set[int] = Set(DELETED, 1, 2)

  // Remote source of truth and historical snapshots.
  var serverRev: int
  var serverRows: int -> int
  var serverRowsAtRev: int -> (int -> int)
  var serverHistory: Set[int]
  var serverHistoryAtRev: int -> Set[int]

  // Remote turso_sync_last_change_id snapshots. The cursor is row-level
  // change_id, not change_txn_id.
  var remotePullGen: str -> int
  var remoteChangeId: str -> int
  // Witness txns for the current row-level cursor generation. This is not the
  // cumulative remote history; serverHistory tracks all txns ever applied.
  var remoteAcked: str -> Set[int]
  var remotePullGenAtRev: int -> (str -> int)
  var remoteChangeIdAtRev: int -> (str -> int)
  var remoteAckedAtRev: int -> (str -> Set[int])

  // Local visible state and current-generation CDC logical txns.
  var clientRows: str -> (int -> int)
  var syncedBaseRows: str -> (int -> int)
  var localTxns: str -> Set[int]
  var localPullGen: str -> int
  var lastPushedHint: str -> int

  // Volatile wait_changes result.
  var changesFileRev: str -> int
  var changesFileRows: str -> (int -> int)
  var changesFilePullGen: str -> int
  var changesFileChangeId: str -> int

  // Stable logical transaction metadata. Each transaction has two ordered row
  // changes, enough to expose partial-transaction cursor mistakes.
  var txnOwner: int -> str
  var txnGen: int -> int
  var txnFirstChange: int -> int
  var txnLastChange: int -> int
  var txnKey1: int -> int
  var txnVal1: int -> int
  var txnKey2: int -> int
  var txnVal2: int -> int
  var nextTxn: int
  var nextChange: int

  pure val emptyRows: int -> int =
    KEYS.mapBy(_ => DELETED)

  pure val emptyRowsByClient: str -> (int -> int) =
    CLIENTS.mapBy(_ => emptyRows)

  pure val emptyTxnSetByClient: str -> Set[int] =
    CLIENTS.mapBy(_ => Set())

  pure val zeroClientInts: str -> int =
    CLIENTS.mapBy(_ => 0)

  pure val noPullClientInts: str -> int =
    CLIENTS.mapBy(_ => NO_PULL)

  pure val emptyRowsByRev: int -> (int -> int) =
    REVS.mapBy(_ => emptyRows)

  pure val emptyHistoryByRev: int -> Set[int] =
    REVS.mapBy(_ => Set())

  pure val zeroCursorsByRev: int -> (str -> int) =
    REVS.mapBy(_ => zeroClientInts)

  pure val emptyAckedByRev: int -> (str -> Set[int]) =
    REVS.mapBy(_ => emptyTxnSetByClient)

  def applyTxnToRows(rows: int -> int, t: int): int -> int =
    rows
      .set(txnKey1.get(t), txnVal1.get(t))
      .set(txnKey2.get(t), txnVal2.get(t))

  def applyTxnSet(rows: int -> int, txns: Set[int]): int -> int = {
    val after1 = if (1.in(txns)) { applyTxnToRows(rows, 1) } else { rows }
    val after2 = if (2.in(txns)) { applyTxnToRows(after1, 2) } else { after1 }
    if (3.in(txns)) { applyTxnToRows(after2, 3) } else { after2 }
  }

  def currentCursorBase(c: str): int =
    if (remotePullGen.get(c) == localPullGen.get(c)) {
      remoteChangeId.get(c)
    } else {
      0
    }

  def txnsAfterCursor(c: str, pullGen: int, changeId: int): Set[int] =
    if (pullGen == localPullGen.get(c)) {
      localTxns.get(c).filter(t => txnLastChange.get(t) > changeId)
    } else {
      localTxns.get(c)
    }

  def pushedTxns(c: str, upTo: int): Set[int] =
    localTxns.get(c).filter(t =>
      and {
        txnGen.get(t) == localPullGen.get(c),
        txnLastChange.get(t) > currentCursorBase(c),
        txnLastChange.get(t) <= upTo,
      }
    )

  def isTxnBoundaryFor(c: str, changeId: int): bool =
    localTxns.get(c)
      .filter(t => txnLastChange.get(t) == changeId)
      .size() > 0

  action init = all {
    serverRev' = 0,
    serverRows' = emptyRows,
    serverRowsAtRev' = emptyRowsByRev,
    serverHistory' = Set(),
    serverHistoryAtRev' = emptyHistoryByRev,
    remotePullGen' = zeroClientInts,
    remoteChangeId' = zeroClientInts,
    remoteAcked' = emptyTxnSetByClient,
    remotePullGenAtRev' = zeroCursorsByRev,
    remoteChangeIdAtRev' = zeroCursorsByRev,
    remoteAckedAtRev' = emptyAckedByRev,
    clientRows' = emptyRowsByClient,
    syncedBaseRows' = emptyRowsByClient,
    localTxns' = emptyTxnSetByClient,
    localPullGen' = zeroClientInts,
    lastPushedHint' = zeroClientInts,
    changesFileRev' = noPullClientInts,
    changesFileRows' = emptyRowsByClient,
    changesFilePullGen' = zeroClientInts,
    changesFileChangeId' = zeroClientInts,
    txnOwner' = TXNS.mapBy(_ => NO_CLIENT),
    txnGen' = TXNS.mapBy(_ => 0),
    txnFirstChange' = TXNS.mapBy(_ => 0),
    txnLastChange' = TXNS.mapBy(_ => 0),
    txnKey1' = TXNS.mapBy(_ => 1),
    txnVal1' = TXNS.mapBy(_ => DELETED),
    txnKey2' = TXNS.mapBy(_ => 1),
    txnVal2' = TXNS.mapBy(_ => DELETED),
    nextTxn' = 1,
    nextChange' = 1,
  }

  action keepServer = all {
    serverRev' = serverRev,
    serverRows' = serverRows,
    serverRowsAtRev' = serverRowsAtRev,
    serverHistory' = serverHistory,
    serverHistoryAtRev' = serverHistoryAtRev,
    remotePullGen' = remotePullGen,
    remoteChangeId' = remoteChangeId,
    remoteAcked' = remoteAcked,
    remotePullGenAtRev' = remotePullGenAtRev,
    remoteChangeIdAtRev' = remoteChangeIdAtRev,
    remoteAckedAtRev' = remoteAckedAtRev,
  }

  action keepLocal = all {
    clientRows' = clientRows,
    syncedBaseRows' = syncedBaseRows,
    localTxns' = localTxns,
    localPullGen' = localPullGen,
    lastPushedHint' = lastPushedHint,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    txnOwner' = txnOwner,
    txnGen' = txnGen,
    txnFirstChange' = txnFirstChange,
    txnLastChange' = txnLastChange,
    txnKey1' = txnKey1,
    txnVal1' = txnVal1,
    txnKey2' = txnKey2,
    txnVal2' = txnVal2,
    nextTxn' = nextTxn,
    nextChange' = nextChange,
  }

  action localTxn = {
    nondet c = CLIENTS.oneOf()
    nondet k1 = KEYS.oneOf()
    nondet v1 = VALUES.oneOf()
    nondet k2 = KEYS.oneOf()
    nondet v2 = VALUES.oneOf()
    localTxnFor(c, k1, v1, k2, v2)
  }

  action localTxnFor(c: str, k1: int, v1: int, k2: int, v2: int): bool = all {
    c.in(CLIENTS),
    k1.in(KEYS),
    k2.in(KEYS),
    v1.in(VALUES),
    v2.in(VALUES),
    nextTxn <= MAX_TXN,
    nextChange + 1 <= MAX_CHANGE,
    keepServer,
    clientRows' = clientRows.set(c, clientRows.get(c).set(k1, v1).set(k2, v2)),
    syncedBaseRows' = syncedBaseRows,
    localTxns' = localTxns.set(c, localTxns.get(c).union(Set(nextTxn))),
    localPullGen' = localPullGen,
    lastPushedHint' = lastPushedHint,
    changesFileRev' = changesFileRev,
    changesFileRows' = changesFileRows,
    changesFilePullGen' = changesFilePullGen,
    changesFileChangeId' = changesFileChangeId,
    txnOwner' = txnOwner.set(nextTxn, c),
    txnGen' = txnGen.set(nextTxn, localPullGen.get(c)),
    txnFirstChange' = txnFirstChange.set(nextTxn, nextChange),
    txnLastChange' = txnLastChange.set(nextTxn, nextChange + 1),
    txnKey1' = txnKey1.set(nextTxn, k1),
    txnVal1' = txnVal1.set(nextTxn, v1),
    txnKey2' = txnKey2.set(nextTxn, k2),
    txnVal2' = txnVal2.set(nextTxn, v2),
    nextTxn' = nextTxn + 1,
    nextChange' = nextChange + 2,
  }

  action pushObserved = push(true)
  action pushLostResponse = push(false)

  action push(observed: bool): bool = {
    nondet c = CLIENTS.oneOf()
    nondet upTo = CHANGE_IDS.oneOf()
    pushFor(c, upTo, observed)
  }

  action pushFor(c: str, upTo: int, observed: bool): bool = {
    val sent = pushedTxns(c, upTo)
    val newRows = applyTxnSet(serverRows, sent)
    val newRev = serverRev + 1
    val newRemotePullGen = remotePullGen.set(c, localPullGen.get(c))
    val newRemoteChangeId = remoteChangeId.set(c, upTo)
    val newRemoteAcked = remoteAcked.set(c, sent)
    all {
      c.in(CLIENTS),
      serverRev < MAX_REV,
      upTo.in(CHANGE_IDS),
      isTxnBoundaryFor(c, upTo),
      sent.size() > 0,
      serverRev' = newRev,
      serverRows' = newRows,
      serverRowsAtRev' = serverRowsAtRev.set(newRev, newRows),
      serverHistory' = serverHistory.union(sent),
      serverHistoryAtRev' = serverHistoryAtRev.set(newRev, serverHistory.union(sent)),
      remotePullGen' = newRemotePullGen,
      remoteChangeId' = newRemoteChangeId,
      remoteAcked' = newRemoteAcked,
      remotePullGenAtRev' = remotePullGenAtRev.set(newRev, newRemotePullGen),
      remoteChangeIdAtRev' = remoteChangeIdAtRev.set(newRev, newRemoteChangeId),
      remoteAckedAtRev' = remoteAckedAtRev.set(newRev, newRemoteAcked),
      clientRows' = clientRows,
      syncedBaseRows' = syncedBaseRows,
      localTxns' = localTxns,
      localPullGen' = localPullGen,
      lastPushedHint' = if (observed) { lastPushedHint.set(c, upTo) } else { lastPushedHint },
      changesFileRev' = changesFileRev,
      changesFileRows' = changesFileRows,
      changesFilePullGen' = changesFilePullGen,
      changesFileChangeId' = changesFileChangeId,
      txnOwner' = txnOwner,
      txnGen' = txnGen,
      txnFirstChange' = txnFirstChange,
      txnLastChange' = txnLastChange,
      txnKey1' = txnKey1,
      txnVal1' = txnVal1,
      txnKey2' = txnKey2,
      txnVal2' = txnVal2,
      nextTxn' = nextTxn,
      nextChange' = nextChange,
    }
  }

  action waitChanges = {
    nondet c = CLIENTS.oneOf()
    waitChangesFor(c)
  }

  action waitChangesFor(c: str): bool = all {
    c.in(CLIENTS),
    keepServer,
    clientRows' = clientRows,
    syncedBaseRows' = syncedBaseRows,
    localTxns' = localTxns,
    localPullGen' = localPullGen,
    lastPushedHint' = lastPushedHint,
    changesFileRev' = changesFileRev.set(c, serverRev),
    changesFileRows' = changesFileRows.set(c, serverRowsAtRev.get(serverRev)),
    changesFilePullGen' = changesFilePullGen.set(c, remotePullGenAtRev.get(serverRev).get(c)),
    changesFileChangeId' = changesFileChangeId.set(c, remoteChangeIdAtRev.get(serverRev).get(c)),
    txnOwner' = txnOwner,
    txnGen' = txnGen,
    txnFirstChange' = txnFirstChange,
    txnLastChange' = txnLastChange,
    txnKey1' = txnKey1,
    txnVal1' = txnVal1,
    txnKey2' = txnKey2,
    txnVal2' = txnVal2,
    nextTxn' = nextTxn,
    nextChange' = nextChange,
  }

  action applyPull = {
    nondet c = CLIENTS.oneOf()
    applyPullFor(c)
  }

  action applyPullFor(c: str): bool = {
    val pulledRev = changesFileRev.get(c)
    val pulledRows = changesFileRows.get(c)
    val pulledGen = changesFilePullGen.get(c)
    val pulledChangeId = changesFileChangeId.get(c)
    val suffix = txnsAfterCursor(c, pulledGen, pulledChangeId)
    val newPullGen = if (suffix.size() > 0) { localPullGen.get(c) + 1 } else { localPullGen.get(c) }
    all {
      c.in(CLIENTS),
      pulledRev != NO_PULL,
      pulledGen <= localPullGen.get(c),
      keepServer,
      clientRows' = clientRows.set(c, applyTxnSet(pulledRows, suffix)),
      syncedBaseRows' = syncedBaseRows.set(c, pulledRows),
      localTxns' = localTxns.set(c, suffix),
      localPullGen' = localPullGen.set(c, newPullGen),
      lastPushedHint' = lastPushedHint.set(c, 0),
      changesFileRev' = changesFileRev.set(c, NO_PULL),
      changesFileRows' = changesFileRows.set(c, emptyRows),
      changesFilePullGen' = changesFilePullGen.set(c, 0),
      changesFileChangeId' = changesFileChangeId.set(c, 0),
      txnOwner' = txnOwner,
      txnGen' = TXNS.mapBy(t => if (t.in(suffix)) { newPullGen } else { txnGen.get(t) }),
      txnFirstChange' = txnFirstChange,
      txnLastChange' = txnLastChange,
      txnKey1' = txnKey1,
      txnVal1' = txnVal1,
      txnKey2' = txnKey2,
      txnVal2' = txnVal2,
      nextTxn' = nextTxn,
      nextChange' = nextChange,
    }
  }

  run reproStalePullReplaysLocalSuffix =
    init
      .then(localTxnFor("c1", 1, 1, 2, 1))
      .then(pushFor("c1", 2, true))
      .then(waitChangesFor("c2"))
      .then(localTxnFor("c2", 1, 2, 2, 2))
      .then(applyPullFor("c2"))
      .expect(clientRows.get("c2").get(1) == 2)
      .expect(clientRows.get("c2").get(2) == 2)

  run reproLostPushResponseThenPullDoesNotReplayAckedTxn =
    init
      .then(localTxnFor("c1", 1, 1, 2, 1))
      .then(pushFor("c1", 2, false))
      .then(waitChangesFor("c1"))
      .then(applyPullFor("c1"))
      .expect(lastPushedHint.get("c1") == 0)
      .expect(localTxns.get("c1").size() == 0)
      .expect(clientRows.get("c1") == serverRows)

  run reproDeleteThenUpdateLastPushWins =
    init
      .then(localTxnFor("c1", 1, 1, 1, 1))
      .then(pushFor("c1", 2, true))
      .then(waitChangesFor("c2"))
      .then(applyPullFor("c2"))
      .then(localTxnFor("c1", 1, DELETED, 1, DELETED))
      .then(pushFor("c1", 4, true))
      .then(localTxnFor("c2", 1, 2, 1, 2))
      .then(pushFor("c2", 6, true))
      .expect(serverRows.get(1) == 2)

  action step = any {
    localTxn,
    pushObserved,
    pushLostResponse,
    waitChanges,
    applyPull,
  }

  pure def TypeOK: bool =
    and {
      serverRev.in(REVS),
      serverRows.keys() == KEYS,
      serverRowsAtRev.keys() == REVS,
      serverHistory.subseteq(TXNS),
      serverHistoryAtRev.keys() == REVS,
      remotePullGen.keys() == CLIENTS,
      remoteChangeId.keys() == CLIENTS,
      remoteAcked.keys() == CLIENTS,
      remotePullGenAtRev.keys() == REVS,
      remoteChangeIdAtRev.keys() == REVS,
      remoteAckedAtRev.keys() == REVS,
      clientRows.keys() == CLIENTS,
      syncedBaseRows.keys() == CLIENTS,
      localTxns.keys() == CLIENTS,
      localPullGen.keys() == CLIENTS,
      lastPushedHint.keys() == CLIENTS,
      changesFileRev.keys() == CLIENTS,
      changesFileRows.keys() == CLIENTS,
      changesFilePullGen.keys() == CLIENTS,
      changesFileChangeId.keys() == CLIENTS,
      txnOwner.keys() == TXNS,
      txnGen.keys() == TXNS,
      txnFirstChange.keys() == TXNS,
      txnLastChange.keys() == TXNS,
      txnKey1.keys() == TXNS,
      txnVal1.keys() == TXNS,
      txnKey2.keys() == TXNS,
      txnVal2.keys() == TXNS,
      nextTxn >= 1,
      nextTxn <= MAX_TXN + 1,
      nextChange >= 1,
      nextChange <= MAX_CHANGE + 1,
      CLIENTS.forall(c =>
        and {
          localTxns.get(c).subseteq(TXNS),
          localTxns.get(c).forall(t => txnOwner.get(t) == c),
          remoteAcked.get(c).subseteq(TXNS),
          remoteAcked.get(c).forall(t => txnOwner.get(t) == c),
          localPullGen.get(c) >= 0,
          lastPushedHint.get(c) >= 0,
          changesFileRev.get(c) == NO_PULL or changesFileRev.get(c).in(REVS),
          changesFilePullGen.get(c) >= 0,
          changesFileChangeId.get(c) >= 0,
        }
      ),
      TXNS.forall(t =>
        and {
          txnOwner.get(t).in(CLIENTS.union(Set(NO_CLIENT))),
          txnGen.get(t) >= 0,
          txnFirstChange.get(t) == 0 or txnFirstChange.get(t).in(CHANGE_IDS),
          txnLastChange.get(t) == 0 or txnLastChange.get(t).in(CHANGE_IDS),
          txnFirstChange.get(t) == 0 or txnLastChange.get(t) == txnFirstChange.get(t) + 1,
          txnKey1.get(t).in(KEYS),
          txnKey2.get(t).in(KEYS),
          txnVal1.get(t).in(VALUES),
          txnVal2.get(t).in(VALUES),
        }
      ),
      REVS.forall(r =>
        and {
          serverRowsAtRev.get(r).keys() == KEYS,
          serverHistoryAtRev.get(r).subseteq(TXNS),
          remotePullGenAtRev.get(r).keys() == CLIENTS,
          remoteChangeIdAtRev.get(r).keys() == CLIENTS,
          remoteAckedAtRev.get(r).keys() == CLIENTS,
          CLIENTS.forall(c => remoteAckedAtRev.get(r).get(c).subseteq(TXNS)),
        }
      ),
    }

  pure def ClientViewExact: bool =
    CLIENTS.forall(c => clientRows.get(c) == applyTxnSet(syncedBaseRows.get(c), localTxns.get(c)))

  pure def CursorAtTxnBoundary: bool =
    CLIENTS.forall(c =>
      remoteChangeId.get(c) == 0 or
        remoteAcked.get(c).filter(t => txnLastChange.get(t) == remoteChangeId.get(c)).size() > 0
    )

  pure def RemoteCursorHistorySound: bool =
    REVS.forall(r =>
      CLIENTS.forall(c =>
        remoteAckedAtRev.get(r).get(c).forall(t =>
          and {
            t.in(serverHistoryAtRev.get(r)),
            txnLastChange.get(t) <= remoteChangeIdAtRev.get(r).get(c),
          }
        )
      )
    )

  pure def PullBufferSound: bool =
    CLIENTS.forall(c =>
      changesFileRev.get(c) == NO_PULL or
        and {
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
      serverHistory,
      serverHistoryAtRev,
      remotePullGen,
      remoteChangeId,
      remoteAcked,
      remotePullGenAtRev,
      remoteChangeIdAtRev,
      remoteAckedAtRev,
      clientRows,
      syncedBaseRows,
      localTxns,
      localPullGen,
      lastPushedHint,
      changesFileRev,
      changesFileRows,
      changesFilePullGen,
      changesFileChangeId,
      txnOwner,
      txnGen,
      txnFirstChange,
      txnLastChange,
      txnKey1,
      txnVal1,
      txnKey2,
      txnVal2,
      nextTxn,
      nextChange
    )
  )))
}
