module turso_sync_push_batching {
  pure val CLIENT: str = "c1"
  pure val NO_OUTCOME: str = "none"
  pure val FETCH_FAIL: str = "fetch_fail"
  pure val SUCCESS_OBSERVED: str = "success_observed"
  pure val SUCCESS_LOST: str = "success_lost"
  pure val FAIL_BEFORE_COMMIT: str = "fail_before_commit"

  pure val MAX_TXN: int = 4
  pure val MAX_CHANGE: int = 16
  pure val TXNS: Set[int] = 1.to(MAX_TXN)
  pure val CHANGE_IDS: Set[int] = 1.to(MAX_CHANGE)
  pure val SIZES: Set[int] = 1.to(3)
  pure val THRESHOLDS: Set[int] = 0.to(3)
  pure val OUTCOMES: Set[str] =
    Set(NO_OUTCOME, FETCH_FAIL, SUCCESS_OBSERVED, SUCCESS_LOST, FAIL_BEFORE_COMMIT)

  // One client, one pull generation, no transform, no ignored tables. This
  // isolates the pushOperationsThreshold batching/retry contract.
  var threshold: int
  var localPullGen: int
  var remotePullGen: int
  // Row-level cursor from turso_sync_last_change_id. This intentionally points
  // at the last row change, not the following CDC commit marker.
  var remoteCursor: int
  var remoteAppliedTxns: Set[int]
  var remoteRows: Set[int]

  var localTxns: Set[int]
  var txnSize: int -> int
  var txnFirstRow: int -> int
  var txnLastRow: int -> int
  var txnCommitId: int -> int
  var nextTxn: int
  var nextChange: int

  // Volatile state for one push() call after fetch_last_change_id succeeds.
  var pushActive: bool
  var attemptCursor: int
  var lastFetchCursor: int
  var lastFetchSawCommitGap: bool

  // Ghost trace of the most recently attempted HTTP push batch.
  var lastBatchStartCursor: int
  var lastBatchTxns: Set[int]
  var lastBatchRows: Set[int]
  var lastBatchFinal: bool
  var lastOutcome: str

  pure val zeroByTxn: int -> int =
    TXNS.mapBy(_ => 0)

  def trustedRemoteCursor: int =
    if (remotePullGen == localPullGen) { remoteCursor } else { 0 }

  def pendingTxnsAfter(cursor: int): Set[int] =
    localTxns.filter(t => txnLastRow.get(t) > cursor)

  def prefixTo(cursor: int, t: int): Set[int] =
    pendingTxnsAfter(cursor).filter(x => x <= t)

  def rowCount(txns: Set[int]): int =
    (if (1.in(txns)) { txnSize.get(1) } else { 0 }) +
    (if (2.in(txns)) { txnSize.get(2) } else { 0 }) +
    (if (3.in(txns)) { txnSize.get(3) } else { 0 }) +
    (if (4.in(txns)) { txnSize.get(4) } else { 0 })

  def maxTxnIn(txns: Set[int]): int =
    if (4.in(txns)) {
      4
    } else if (3.in(txns)) {
      3
    } else if (2.in(txns)) {
      2
    } else if (1.in(txns)) {
      1
    } else {
      0
    }

  def maxLastRow(txns: Set[int]): int =
    if (4.in(txns)) {
      txnLastRow.get(4)
    } else if (3.in(txns)) {
      txnLastRow.get(3)
    } else if (2.in(txns)) {
      txnLastRow.get(2)
    } else if (1.in(txns)) {
      txnLastRow.get(1)
    } else {
      0
    }

  def hasPendingAfterTxn(cursor: int, t: int): bool =
    pendingTxnsAfter(cursor).filter(x => x > t).size() > 0

  def isBatchEnd(cursor: int, t: int): bool =
    and {
      t.in(pendingTxnsAfter(cursor)),
      if (threshold == 0) {
        not(hasPendingAfterTxn(cursor, t))
      } else {
        rowCount(prefixTo(cursor, t)) >= threshold or
        not(hasPendingAfterTxn(cursor, t))
      },
    }

  // Rust-like deterministic batching: the next batch ends at the first commit
  // boundary whose accumulated row count reaches the threshold, except that the
  // final suffix is always flushed. threshold=0 disables splitting.
  def nextBatchEnd(cursor: int): int =
    if (isBatchEnd(cursor, 1)) {
      1
    } else if (isBatchEnd(cursor, 2)) {
      2
    } else if (isBatchEnd(cursor, 3)) {
      3
    } else if (isBatchEnd(cursor, 4)) {
      4
    } else {
      0
    }

  def nextBatch(cursor: int): Set[int] = {
    val end = nextBatchEnd(cursor)
    if (end == 0) { Set() } else { prefixTo(cursor, end) }
  }

  def isFinalBatchAt(cursor: int, txns: Set[int]): bool =
    TXNS.forall(t =>
      not(t.in(pendingTxnsAfter(cursor))) or
      t <= maxTxnIn(txns)
    )

  def priorPrefixesBelowThreshold(cursor: int, txns: Set[int]): bool =
    threshold == 0 or
    TXNS.forall(t =>
      not(t.in(pendingTxnsAfter(cursor))) or
      t >= maxTxnIn(txns) or
      rowCount(prefixTo(cursor, t)) < threshold
    )

  def txnRows(t: int): Set[int] =
    if (txnSize.get(t) == 1) {
      Set(txnFirstRow.get(t))
    } else if (txnSize.get(t) == 2) {
      Set(txnFirstRow.get(t), txnFirstRow.get(t) + 1)
    } else {
      Set(txnFirstRow.get(t), txnFirstRow.get(t) + 1, txnFirstRow.get(t) + 2)
    }

  def rowsOfTxns(txns: Set[int]): Set[int] =
    (if (1.in(txns)) { txnRows(1) } else { Set() })
      .union(if (2.in(txns)) { txnRows(2) } else { Set() })
      .union(if (3.in(txns)) { txnRows(3) } else { Set() })
      .union(if (4.in(txns)) { txnRows(4) } else { Set() })

  def sawCommitGapAfter(cursor: int): bool =
    localTxns.exists(t => txnCommitId.get(t) == cursor + 1)

  action init = {
    nondet t = THRESHOLDS.oneOf()
    initWith(t)
  }

  action initWith(t: int): bool = all {
    t.in(THRESHOLDS),
    threshold' = t,
    localPullGen' = 0,
    remotePullGen' = 0,
    remoteCursor' = 0,
    remoteAppliedTxns' = Set(),
    remoteRows' = Set(),
    localTxns' = Set(),
    txnSize' = zeroByTxn,
    txnFirstRow' = zeroByTxn,
    txnLastRow' = zeroByTxn,
    txnCommitId' = zeroByTxn,
    nextTxn' = 1,
    nextChange' = 1,
    pushActive' = false,
    attemptCursor' = 0,
    lastFetchCursor' = 0,
    lastFetchSawCommitGap' = false,
    lastBatchStartCursor' = 0,
    lastBatchTxns' = Set(),
    lastBatchRows' = Set(),
    lastBatchFinal' = true,
    lastOutcome' = NO_OUTCOME,
  }

  action keepConfig = all {
    threshold' = threshold,
    localPullGen' = localPullGen,
  }

  action keepRemote = all {
    remotePullGen' = remotePullGen,
    remoteCursor' = remoteCursor,
    remoteAppliedTxns' = remoteAppliedTxns,
    remoteRows' = remoteRows,
  }

  action keepLocal = all {
    localTxns' = localTxns,
    txnSize' = txnSize,
    txnFirstRow' = txnFirstRow,
    txnLastRow' = txnLastRow,
    txnCommitId' = txnCommitId,
    nextTxn' = nextTxn,
    nextChange' = nextChange,
  }

  action clearAttempt = all {
    pushActive' = false,
    attemptCursor' = attemptCursor,
    lastFetchCursor' = lastFetchCursor,
    lastFetchSawCommitGap' = lastFetchSawCommitGap,
  }

  action keepAttempt = all {
    pushActive' = pushActive,
    attemptCursor' = attemptCursor,
    lastFetchCursor' = lastFetchCursor,
    lastFetchSawCommitGap' = lastFetchSawCommitGap,
  }

  action recordNoBatch(outcome: str): bool = all {
    lastBatchStartCursor' = attemptCursor,
    lastBatchTxns' = Set(),
    lastBatchRows' = Set(),
    lastBatchFinal' = true,
    lastOutcome' = outcome,
  }

  action recordBatch(cursor: int, txns: Set[int], outcome: str): bool = all {
    lastBatchStartCursor' = cursor,
    lastBatchTxns' = txns,
    lastBatchRows' = rowsOfTxns(txns),
    lastBatchFinal' = isFinalBatchAt(cursor, txns),
    lastOutcome' = outcome,
  }

  action localTxn = {
    nondet txnLen = SIZES.oneOf()
    localTxnFor(txnLen)
  }

  action localTxnFor(txnLen: int): bool = all {
    txnLen.in(SIZES),
    not(pushActive),
    nextTxn <= MAX_TXN,
    nextChange + txnLen <= MAX_CHANGE,
    keepConfig,
    keepRemote,
    localTxns' = localTxns.union(Set(nextTxn)),
    txnSize' = txnSize.set(nextTxn, txnLen),
    txnFirstRow' = txnFirstRow.set(nextTxn, nextChange),
    txnLastRow' = txnLastRow.set(nextTxn, nextChange + txnLen - 1),
    txnCommitId' = txnCommitId.set(nextTxn, nextChange + txnLen),
    nextTxn' = nextTxn + 1,
    nextChange' = nextChange + txnLen + 1,
    keepAttempt,
    recordNoBatch(NO_OUTCOME),
  }

  action startPushFetchOk = all {
    not(pushActive),
    keepConfig,
    keepRemote,
    keepLocal,
    pushActive' = true,
    attemptCursor' = trustedRemoteCursor,
    lastFetchCursor' = trustedRemoteCursor,
    lastFetchSawCommitGap' = sawCommitGapAfter(trustedRemoteCursor),
    recordNoBatch(NO_OUTCOME),
  }

  action startPushFetchFail = all {
    not(pushActive),
    keepConfig,
    keepRemote,
    keepLocal,
    pushActive' = false,
    attemptCursor' = attemptCursor,
    lastFetchCursor' = lastFetchCursor,
    lastFetchSawCommitGap' = lastFetchSawCommitGap,
    recordNoBatch(FETCH_FAIL),
  }

  action finishNoopPush = all {
    pushActive,
    nextBatch(attemptCursor).size() == 0,
    keepConfig,
    keepRemote,
    keepLocal,
    clearAttempt,
    recordNoBatch(SUCCESS_OBSERVED),
  }

  action sendBatchSuccessObserved = {
    val batch = nextBatch(attemptCursor)
    val nextCursor = maxLastRow(batch)
    all {
      pushActive,
      batch.size() > 0,
      keepConfig,
      remotePullGen' = localPullGen,
      remoteCursor' = nextCursor,
      remoteAppliedTxns' = remoteAppliedTxns.union(batch),
      remoteRows' = remoteRows.union(rowsOfTxns(batch)),
      keepLocal,
      pushActive' = pendingTxnsAfter(nextCursor).size() > 0,
      attemptCursor' = nextCursor,
      lastFetchCursor' = lastFetchCursor,
      lastFetchSawCommitGap' = lastFetchSawCommitGap,
      recordBatch(attemptCursor, batch, SUCCESS_OBSERVED),
    }
  }

  action sendBatchSuccessLostResponse = {
    val batch = nextBatch(attemptCursor)
    val nextCursor = maxLastRow(batch)
    all {
      pushActive,
      batch.size() > 0,
      keepConfig,
      remotePullGen' = localPullGen,
      remoteCursor' = nextCursor,
      remoteAppliedTxns' = remoteAppliedTxns.union(batch),
      remoteRows' = remoteRows.union(rowsOfTxns(batch)),
      keepLocal,
      // The HTTP response is lost after the remote commit. The push() call
      // aborts; the next push must fetch the durable remote cursor again.
      clearAttempt,
      recordBatch(attemptCursor, batch, SUCCESS_LOST),
    }
  }

  action sendBatchFailBeforeCommit = {
    val batch = nextBatch(attemptCursor)
    all {
      pushActive,
      batch.size() > 0,
      keepConfig,
      keepRemote,
      keepLocal,
      clearAttempt,
      recordBatch(attemptCursor, batch, FAIL_BEFORE_COMMIT),
    }
  }

  run reproLargeTxnNotSplitByThreshold =
    initWith(2)
      .then(localTxnFor(3))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(1))
      .expect(rowCount(lastBatchTxns) == 3)
      .expect(remoteAppliedTxns == Set(1))
      .expect(RemoteHasNoPartialTxn)

  run reproMultipleSmallTxnsAccumulate =
    initWith(3)
      .then(localTxnFor(1))
      .then(localTxnFor(1))
      .then(localTxnFor(1))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(1, 2, 3))
      .expect(rowCount(lastBatchTxns) == 3)
      .expect(not(pushActive))

  run reproFinalUnderThresholdSuffixFlushes =
    initWith(2)
      .then(localTxnFor(1))
      .then(localTxnFor(1))
      .then(localTxnFor(1))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(1, 2))
      .expect(pushActive)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(3))
      .expect(rowCount(lastBatchTxns) == 1)
      .expect(lastBatchFinal)
      .expect(not(pushActive))

  run reproFailSecondBatchLeavesFirstOnly =
    initWith(2)
      .then(localTxnFor(2))
      .then(localTxnFor(2))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .then(sendBatchFailBeforeCommit)
      .expect(remoteAppliedTxns == Set(1))
      .expect(remoteCursor == txnLastRow.get(1))
      .expect(PendingSuffixExact)

  run reproRetryAfterPrefixFailureSendsSuffixOnly =
    initWith(2)
      .then(localTxnFor(2))
      .then(localTxnFor(2))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .then(sendBatchFailBeforeCommit)
      .then(startPushFetchOk)
      .expect(lastFetchCursor == txnLastRow.get(1))
      .expect(lastFetchSawCommitGap)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(2))
      .expect(remoteAppliedTxns == Set(1, 2))
      .expect(not(pushActive))

  run reproLostResponseThenRetrySkipsCommittedPrefix =
    initWith(2)
      .then(localTxnFor(2))
      .then(localTxnFor(2))
      .then(startPushFetchOk)
      .then(sendBatchSuccessLostResponse)
      .expect(remoteAppliedTxns == Set(1))
      .then(startPushFetchOk)
      .expect(lastFetchCursor == txnLastRow.get(1))
      .expect(lastFetchSawCommitGap)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(2))
      .expect(remoteAppliedTxns == Set(1, 2))

  run reproDisabledThresholdSendsWholeSuffix =
    initWith(0)
      .then(localTxnFor(1))
      .then(localTxnFor(1))
      .then(localTxnFor(1))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchTxns == Set(1, 2, 3))
      .expect(lastBatchFinal)
      .expect(not(pushActive))

  action step = any {
    localTxn,
    startPushFetchOk,
    startPushFetchFail,
    finishNoopPush,
    sendBatchSuccessObserved,
    sendBatchSuccessLostResponse,
    sendBatchFailBeforeCommit,
  }

  pure def TypeOK: bool =
    and {
      threshold.in(THRESHOLDS),
      localPullGen >= 0,
      remotePullGen >= 0,
      remoteCursor >= 0,
      remoteCursor <= MAX_CHANGE,
      remoteAppliedTxns.subseteq(localTxns),
      remoteRows.subseteq(CHANGE_IDS),
      localTxns.subseteq(TXNS),
      txnSize.keys() == TXNS,
      txnFirstRow.keys() == TXNS,
      txnLastRow.keys() == TXNS,
      txnCommitId.keys() == TXNS,
      nextTxn >= 1,
      nextTxn <= MAX_TXN + 1,
      nextChange >= 1,
      nextChange <= MAX_CHANGE + 1,
      attemptCursor >= 0,
      attemptCursor <= MAX_CHANGE,
      lastFetchCursor >= 0,
      lastFetchCursor <= MAX_CHANGE,
      lastBatchStartCursor >= 0,
      lastBatchStartCursor <= MAX_CHANGE,
      lastBatchTxns.subseteq(TXNS),
      lastBatchRows.subseteq(CHANGE_IDS),
      lastOutcome.in(OUTCOMES),
      TXNS.forall(t =>
        and {
          txnSize.get(t) == 0 or txnSize.get(t).in(SIZES),
          txnFirstRow.get(t) >= 0,
          txnFirstRow.get(t) <= MAX_CHANGE,
          txnLastRow.get(t) >= 0,
          txnLastRow.get(t) <= MAX_CHANGE,
          txnCommitId.get(t) >= 0,
          txnCommitId.get(t) <= MAX_CHANGE,
          not(t.in(localTxns)) or
            and {
              txnSize.get(t).in(SIZES),
              txnLastRow.get(t) == txnFirstRow.get(t) + txnSize.get(t) - 1,
              txnCommitId.get(t) == txnLastRow.get(t) + 1,
              t == 1 or not(t.in(localTxns)) or txnCommitId.get(t - 1) < txnFirstRow.get(t),
            },
        }
      ),
    }

  pure def DeterministicBatchShape: bool =
    lastBatchTxns.size() == 0 or
      and {
        lastBatchTxns == nextBatch(lastBatchStartCursor),
        priorPrefixesBelowThreshold(lastBatchStartCursor, lastBatchTxns),
        if (threshold == 0) {
          lastBatchFinal
        } else if (lastBatchFinal) {
          true
        } else {
          rowCount(lastBatchTxns) >= threshold
        },
      }

  pure def FailedBatchDoesNotAdvanceRemote: bool =
    lastOutcome != FAIL_BEFORE_COMMIT or
      and {
        lastBatchTxns.size() > 0,
        lastBatchTxns.intersect(remoteAppliedTxns).size() == 0,
        remoteCursor == lastBatchStartCursor,
      }

  pure def RemoteCursorMatchesAppliedPrefix: bool =
    remotePullGen != localPullGen or remoteCursor == maxLastRow(remoteAppliedTxns)

  pure def CursorNeverAcknowledgesMissingRows: bool =
    remotePullGen != localPullGen or
      localTxns.forall(t =>
        txnLastRow.get(t) > remoteCursor or t.in(remoteAppliedTxns)
      )

  pure def PendingSuffixExact: bool =
    pendingTxnsAfter(trustedRemoteCursor) == localTxns.exclude(remoteAppliedTxns)

  pure def RemoteHasNoPartialTxn: bool =
    localTxns.forall(t =>
      rowsOfTxns(Set(t)).subseteq(remoteRows) or
      rowsOfTxns(Set(t)).intersect(remoteRows).size() == 0
    )

  pure def CommitGapDoesNotRepushPreviousTxn: bool =
    not(lastFetchSawCommitGap) or
      localTxns.forall(t =>
        txnCommitId.get(t) != lastFetchCursor + 1 or not(t.in(nextBatch(lastFetchCursor)))
      )

  temporal spec = init.and(always(step.orKeep(
    (
      threshold,
      localPullGen,
      remotePullGen,
      remoteCursor,
      remoteAppliedTxns,
      remoteRows,
      localTxns,
      txnSize,
      txnFirstRow,
      txnLastRow,
      txnCommitId,
      nextTxn,
      nextChange,
      pushActive,
      attemptCursor,
      lastFetchCursor,
      lastFetchSawCommitGap,
      lastBatchStartCursor,
      lastBatchTxns,
      lastBatchRows,
      lastBatchFinal,
      lastOutcome
    )
  )))
}
