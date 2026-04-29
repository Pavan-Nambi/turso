module turso_sync_transform_batching {
  pure val KEEP: str = "keep"
  pure val SKIP: str = "skip"
  pure val REWRITE: str = "rewrite"
  pure val NO_POLICY: str = "none"

  pure val NO_OUTCOME: str = "none"
  pure val FETCH_OK: str = "fetch_ok"
  pure val FETCH_FAIL: str = "fetch_fail"
  pure val SUCCESS_OBSERVED: str = "success_observed"
  pure val SUCCESS_LOST: str = "success_lost"
  pure val FAIL_BEFORE_COMMIT: str = "fail_before_commit"

  pure val MAX_OP: int = 4
  pure val MAX_TXN: int = 4
  pure val MAX_CHANGE: int = 12
  pure val OPS: Set[int] = 1.to(MAX_OP)
  pure val TXNS: Set[int] = 1.to(MAX_TXN)
  pure val CHANGE_IDS: Set[int] = 1.to(MAX_CHANGE)
  pure val THRESHOLDS: Set[int] = 0.to(2)
  pure val POLICIES: Set[str] = Set(KEEP, SKIP, REWRITE)
  pure val OUTCOMES: Set[str] =
    Set(NO_OUTCOME, FETCH_OK, FETCH_FAIL, SUCCESS_OBSERVED, SUCCESS_LOST, FAIL_BEFORE_COMMIT)

  // One client, one pull generation. This composes the transform cursor rule
  // with threshold batching and intentionally excludes ignored tables and DDL
  // ignored-step errors.
  var threshold: int
  var localPullGen: int
  var remotePullGen: int
  var remoteCursor: int
  var remoteAppliedOps: Set[int]

  var localOps: Set[int]
  var localTxns: Set[int]
  var opPolicy: int -> str
  var opTxn: int -> int
  var opChangeId: int -> int
  var txnFirstOp: int -> int
  var txnLastOp: int -> int
  var txnCommitId: int -> int
  var nextOp: int
  var nextTxn: int
  var nextChange: int

  // Active push state. The stream frontier advances after every observed
  // successful send_push_batch call, including all-skipped batches. The
  // batchInputCursor is the last_change_id argument for the next batch and
  // advances only when a batch emits at least one SQL row.
  var pushActive: bool
  var streamFrontierTxn: int
  var streamStartCursor: int
  var batchInputCursor: int

  var transformPushCalls: int -> int
  var skippedLeftPending: Set[int]
  var droppedAfterRetry: Set[int]
  var outcomeSensitiveSkip: Set[int]

  // Ghost values for the most recent batch.
  var lastBatchTxns: Set[int]
  var lastBatchOps: Set[int]
  var lastAppliedOps: Set[int]
  var lastSkippedOps: Set[int]
  var lastBatchStreamFrontier: int
  var lastBatchStreamStartCursor: int
  var lastBatchInputCursor: int
  var lastBatchRemoteCursor: int
  var lastOutcome: str

  pure val noPolicyByOp: int -> str =
    OPS.mapBy(_ => NO_POLICY)

  pure val zeroOpInts: int -> int =
    OPS.mapBy(_ => 0)

  pure val zeroTxnInts: int -> int =
    TXNS.mapBy(_ => 0)

  def trustedRemoteCursor: int =
    if (remotePullGen == localPullGen) { remoteCursor } else { 0 }

  def opAfterCursor(op: int, cursor: int): bool =
    op.in(localOps) and opChangeId.get(op) > cursor

  def txnPendingOpsFrom(cursor: int, txn: int): Set[int] =
    localOps.filter(op => opTxn.get(op) == txn and opChangeId.get(op) > cursor)

  def txnHasStreamRows(txn: int): bool =
    txn >= streamFrontierTxn and txnPendingOpsFrom(streamStartCursor, txn).size() > 0

  def txnHasRowsFrom(frontier: int, cursor: int, txn: int): bool =
    txn >= frontier and txnPendingOpsFrom(cursor, txn).size() > 0

  def prefixTxnsTo(txn: int): Set[int] =
    localTxns.filter(t => t >= streamFrontierTxn and t <= txn and txnPendingOpsFrom(streamStartCursor, t).size() > 0)

  def prefixTxnsToFrom(frontier: int, cursor: int, txn: int): Set[int] =
    localTxns.filter(t => t >= frontier and t <= txn and txnPendingOpsFrom(cursor, t).size() > 0)

  def rowCount(txns: Set[int]): int =
    (if (1.in(txns)) { txnPendingOpsFrom(streamStartCursor, 1).size() } else { 0 }) +
    (if (2.in(txns)) { txnPendingOpsFrom(streamStartCursor, 2).size() } else { 0 }) +
    (if (3.in(txns)) { txnPendingOpsFrom(streamStartCursor, 3).size() } else { 0 }) +
    (if (4.in(txns)) { txnPendingOpsFrom(streamStartCursor, 4).size() } else { 0 })

  def rowCountFrom(cursor: int, txns: Set[int]): int =
    (if (1.in(txns)) { txnPendingOpsFrom(cursor, 1).size() } else { 0 }) +
    (if (2.in(txns)) { txnPendingOpsFrom(cursor, 2).size() } else { 0 }) +
    (if (3.in(txns)) { txnPendingOpsFrom(cursor, 3).size() } else { 0 }) +
    (if (4.in(txns)) { txnPendingOpsFrom(cursor, 4).size() } else { 0 })

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

  def laterStreamTxnExists(txn: int): bool =
    TXNS.exists(t => t > txn and txnHasStreamRows(t))

  def laterTxnExistsFrom(frontier: int, cursor: int, txn: int): bool =
    TXNS.exists(t => t > txn and txnHasRowsFrom(frontier, cursor, t))

  def isBatchEnd(txn: int): bool =
    and {
      txnHasStreamRows(txn),
      if (threshold == 0) {
        not(laterStreamTxnExists(txn))
      } else {
        rowCount(prefixTxnsTo(txn)) >= threshold or not(laterStreamTxnExists(txn))
      },
    }

  def isBatchEndFrom(frontier: int, cursor: int, txn: int): bool =
    and {
      txnHasRowsFrom(frontier, cursor, txn),
      if (threshold == 0) {
        not(laterTxnExistsFrom(frontier, cursor, txn))
      } else {
        rowCountFrom(cursor, prefixTxnsToFrom(frontier, cursor, txn)) >= threshold or
        not(laterTxnExistsFrom(frontier, cursor, txn))
      },
    }

  // Deterministic Rust-like batch choice. The threshold is counted before
  // transform, over CDC rows in the batch, and the batch can only close when a
  // Commit boundary is reached.
  def nextBatchEnd: int =
    if (isBatchEnd(1)) {
      1
    } else if (isBatchEnd(2)) {
      2
    } else if (isBatchEnd(3)) {
      3
    } else if (isBatchEnd(4)) {
      4
    } else {
      0
    }

  def nextBatchEndFrom(frontier: int, cursor: int): int =
    if (isBatchEndFrom(frontier, cursor, 1)) {
      1
    } else if (isBatchEndFrom(frontier, cursor, 2)) {
      2
    } else if (isBatchEndFrom(frontier, cursor, 3)) {
      3
    } else if (isBatchEndFrom(frontier, cursor, 4)) {
      4
    } else {
      0
    }

  def currentBatchTxns: Set[int] =
    if (nextBatchEnd == 0) { Set() } else { prefixTxnsTo(nextBatchEnd) }

  def opsOfTxnsAfterCursor(txns: Set[int], cursor: int): Set[int] =
    localOps.filter(op => opTxn.get(op).in(txns) and opChangeId.get(op) > cursor)

  def currentBatchOps: Set[int] =
    opsOfTxnsAfterCursor(currentBatchTxns, streamStartCursor)

  def transformedApplied(ops: Set[int]): Set[int] =
    ops.filter(op => opPolicy.get(op) != SKIP)

  def transformedSkipped(ops: Set[int]): Set[int] =
    ops.filter(op => opPolicy.get(op) == SKIP)

  def maxChangeOfOpsOr(ops: Set[int], fallback: int): int =
    if (4.in(ops)) {
      opChangeId.get(4)
    } else if (3.in(ops)) {
      opChangeId.get(3)
    } else if (2.in(ops)) {
      opChangeId.get(2)
    } else if (1.in(ops)) {
      opChangeId.get(1)
    } else {
      fallback
    }

  def incCalls(calls: int -> int, ops: Set[int]): int -> int =
    OPS.mapBy(op => if (op.in(ops)) { calls.get(op) + 1 } else { calls.get(op) })

  def pendingOps: Set[int] =
    localOps.filter(op => opChangeId.get(op) > trustedRemoteCursor)

  def txnOps(txn: int): Set[int] =
    localOps.filter(op => opTxn.get(op) == txn)

  def txnPartiallyApplied(txn: int): bool = {
    val ops = txnOps(txn)
    val applied = ops.intersect(remoteAppliedOps)
    and {
      ops.size() > 1,
      applied.size() > 0,
      not(ops.subseteq(remoteAppliedOps)),
    }
  }

  def priorPrefixesBelowThreshold(txns: Set[int]): bool =
    threshold == 0 or
    TXNS.forall(t =>
      not(txnHasStreamRows(t)) or
      t >= maxTxnIn(txns) or
      rowCount(prefixTxnsTo(t)) < threshold
    )

  def priorPrefixesBelowThresholdFrom(frontier: int, cursor: int, txns: Set[int]): bool =
    threshold == 0 or
    TXNS.forall(t =>
      not(txnHasRowsFrom(frontier, cursor, t)) or
      t >= maxTxnIn(txns) or
      rowCountFrom(cursor, prefixTxnsToFrom(frontier, cursor, t)) < threshold
    )

  def isFinalBatch(txns: Set[int]): bool =
    not(laterStreamTxnExists(maxTxnIn(txns)))

  def isFinalBatchFrom(frontier: int, cursor: int, txns: Set[int]): bool =
    not(laterTxnExistsFrom(frontier, cursor, maxTxnIn(txns)))

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
    remoteAppliedOps' = Set(),
    localOps' = Set(),
    localTxns' = Set(),
    opPolicy' = noPolicyByOp,
    opTxn' = zeroOpInts,
    opChangeId' = zeroOpInts,
    txnFirstOp' = zeroTxnInts,
    txnLastOp' = zeroTxnInts,
    txnCommitId' = zeroTxnInts,
    nextOp' = 1,
    nextTxn' = 1,
    nextChange' = 1,
    pushActive' = false,
    streamFrontierTxn' = 1,
    streamStartCursor' = 0,
    batchInputCursor' = 0,
    transformPushCalls' = zeroOpInts,
    skippedLeftPending' = Set(),
    droppedAfterRetry' = Set(),
    outcomeSensitiveSkip' = Set(),
    lastBatchTxns' = Set(),
    lastBatchOps' = Set(),
    lastAppliedOps' = Set(),
    lastSkippedOps' = Set(),
    lastBatchStreamFrontier' = 1,
    lastBatchStreamStartCursor' = 0,
    lastBatchInputCursor' = 0,
    lastBatchRemoteCursor' = 0,
    lastOutcome' = NO_OUTCOME,
  }

  action keepConfig = all {
    threshold' = threshold,
    localPullGen' = localPullGen,
  }

  action keepRemote = all {
    remotePullGen' = remotePullGen,
    remoteCursor' = remoteCursor,
    remoteAppliedOps' = remoteAppliedOps,
  }

  action keepLocal = all {
    localOps' = localOps,
    localTxns' = localTxns,
    opPolicy' = opPolicy,
    opTxn' = opTxn,
    opChangeId' = opChangeId,
    txnFirstOp' = txnFirstOp,
    txnLastOp' = txnLastOp,
    txnCommitId' = txnCommitId,
    nextOp' = nextOp,
    nextTxn' = nextTxn,
    nextChange' = nextChange,
  }

  action keepPush = all {
    pushActive' = pushActive,
    streamFrontierTxn' = streamFrontierTxn,
    streamStartCursor' = streamStartCursor,
    batchInputCursor' = batchInputCursor,
  }

  action clearPush = all {
    pushActive' = false,
    streamFrontierTxn' = streamFrontierTxn,
    streamStartCursor' = streamStartCursor,
    batchInputCursor' = batchInputCursor,
  }

  action keepGhost = all {
    transformPushCalls' = transformPushCalls,
    skippedLeftPending' = skippedLeftPending,
    droppedAfterRetry' = droppedAfterRetry,
    outcomeSensitiveSkip' = outcomeSensitiveSkip,
  }

  action recordNoBatch(outcome: str): bool = all {
    lastBatchTxns' = Set(),
    lastBatchOps' = Set(),
    lastAppliedOps' = Set(),
    lastSkippedOps' = Set(),
    lastBatchStreamFrontier' = streamFrontierTxn,
    lastBatchStreamStartCursor' = streamStartCursor,
    lastBatchInputCursor' = batchInputCursor,
    lastBatchRemoteCursor' = remoteCursor,
    lastOutcome' = outcome,
  }

  action recordBatch(txns: Set[int], ops: Set[int], applied: Set[int], skipped: Set[int], outcome: str): bool = all {
    lastBatchTxns' = txns,
    lastBatchOps' = ops,
    lastAppliedOps' = applied,
    lastSkippedOps' = skipped,
    lastBatchStreamFrontier' = streamFrontierTxn,
    lastBatchStreamStartCursor' = streamStartCursor,
    lastBatchInputCursor' = batchInputCursor,
    lastBatchRemoteCursor' = remoteCursor,
    lastOutcome' = outcome,
  }

  action localOneOpTxn = {
    nondet policy = POLICIES.oneOf()
    localOneOpTxnFor(policy)
  }

  action localOneOpTxnFor(policy: str): bool = all {
    policy.in(POLICIES),
    not(pushActive),
    nextTxn <= MAX_TXN,
    nextOp <= MAX_OP,
    nextChange + 1 <= MAX_CHANGE,
    keepConfig,
    keepRemote,
    localOps' = localOps.union(Set(nextOp)),
    localTxns' = localTxns.union(Set(nextTxn)),
    opPolicy' = opPolicy.set(nextOp, policy),
    opTxn' = opTxn.set(nextOp, nextTxn),
    opChangeId' = opChangeId.set(nextOp, nextChange),
    txnFirstOp' = txnFirstOp.set(nextTxn, nextOp),
    txnLastOp' = txnLastOp.set(nextTxn, nextOp),
    txnCommitId' = txnCommitId.set(nextTxn, nextChange + 1),
    nextOp' = nextOp + 1,
    nextTxn' = nextTxn + 1,
    nextChange' = nextChange + 2,
    keepPush,
    keepGhost,
    recordNoBatch(NO_OUTCOME),
  }

  action localTwoOpTxn = {
    nondet policy1 = POLICIES.oneOf()
    nondet policy2 = POLICIES.oneOf()
    localTwoOpTxnFor(policy1, policy2)
  }

  action localTwoOpTxnFor(policy1: str, policy2: str): bool = all {
    policy1.in(POLICIES),
    policy2.in(POLICIES),
    not(pushActive),
    nextTxn <= MAX_TXN,
    nextOp + 1 <= MAX_OP,
    nextChange + 2 <= MAX_CHANGE,
    keepConfig,
    keepRemote,
    localOps' = localOps.union(Set(nextOp, nextOp + 1)),
    localTxns' = localTxns.union(Set(nextTxn)),
    opPolicy' = opPolicy.set(nextOp, policy1).set(nextOp + 1, policy2),
    opTxn' = opTxn.set(nextOp, nextTxn).set(nextOp + 1, nextTxn),
    opChangeId' = opChangeId.set(nextOp, nextChange).set(nextOp + 1, nextChange + 1),
    txnFirstOp' = txnFirstOp.set(nextTxn, nextOp),
    txnLastOp' = txnLastOp.set(nextTxn, nextOp + 1),
    txnCommitId' = txnCommitId.set(nextTxn, nextChange + 2),
    nextOp' = nextOp + 2,
    nextTxn' = nextTxn + 1,
    nextChange' = nextChange + 3,
    keepPush,
    keepGhost,
    recordNoBatch(NO_OUTCOME),
  }

  action startPushFetchOk = all {
    not(pushActive),
    keepConfig,
    keepRemote,
    keepLocal,
    pushActive' = true,
    streamFrontierTxn' = 1,
    streamStartCursor' = trustedRemoteCursor,
    batchInputCursor' = trustedRemoteCursor,
    keepGhost,
    recordNoBatch(FETCH_OK),
  }

  action startPushFetchFail = all {
    not(pushActive),
    keepConfig,
    keepRemote,
    keepLocal,
    clearPush,
    keepGhost,
    recordNoBatch(FETCH_FAIL),
  }

  action finishNoopPush = all {
    pushActive,
    currentBatchOps.size() == 0,
    keepConfig,
    keepRemote,
    keepLocal,
    clearPush,
    keepGhost,
    recordNoBatch(SUCCESS_OBSERVED),
  }

  action sendBatchSuccessObserved = {
    val txns = currentBatchTxns
    val ops = currentBatchOps
    val applied = transformedApplied(ops)
    val skipped = transformedSkipped(ops)
    val nextCursor = maxChangeOfOpsOr(applied, batchInputCursor)
    val newlyDropped = skippedLeftPending.filter(op => opChangeId.get(op) <= nextCursor and not(op.in(remoteAppliedOps.union(applied))))
    all {
      pushActive,
      ops.size() > 0,
      keepConfig,
      remotePullGen' = if (applied.size() > 0) { localPullGen } else { remotePullGen },
      remoteCursor' = if (applied.size() > 0) { nextCursor } else { remoteCursor },
      remoteAppliedOps' = remoteAppliedOps.union(applied),
      keepLocal,
      pushActive' = true,
      streamFrontierTxn' = maxTxnIn(txns) + 1,
      streamStartCursor' = streamStartCursor,
      batchInputCursor' = nextCursor,
      transformPushCalls' = incCalls(transformPushCalls, ops),
      skippedLeftPending' = skippedLeftPending.union(skipped.filter(op => opChangeId.get(op) > nextCursor)),
      droppedAfterRetry' = droppedAfterRetry.union(newlyDropped),
      outcomeSensitiveSkip' = outcomeSensitiveSkip,
      recordBatch(txns, ops, applied, skipped, SUCCESS_OBSERVED),
    }
  }

  action sendBatchSuccessLostResponse = {
    val txns = currentBatchTxns
    val ops = currentBatchOps
    val applied = transformedApplied(ops)
    val skipped = transformedSkipped(ops)
    val nextCursor = maxChangeOfOpsOr(applied, batchInputCursor)
    val newlyDropped = skippedLeftPending.filter(op => opChangeId.get(op) <= nextCursor and not(op.in(remoteAppliedOps.union(applied))))
    all {
      pushActive,
      ops.size() > 0,
      keepConfig,
      remotePullGen' = if (applied.size() > 0) { localPullGen } else { remotePullGen },
      remoteCursor' = if (applied.size() > 0) { nextCursor } else { remoteCursor },
      remoteAppliedOps' = remoteAppliedOps.union(applied),
      keepLocal,
      clearPush,
      transformPushCalls' = incCalls(transformPushCalls, ops),
      skippedLeftPending' = skippedLeftPending.union(skipped.filter(op => opChangeId.get(op) > nextCursor)),
      droppedAfterRetry' = droppedAfterRetry.union(newlyDropped),
      outcomeSensitiveSkip' = outcomeSensitiveSkip,
      recordBatch(txns, ops, applied, skipped, SUCCESS_LOST),
    }
  }

  action sendBatchFailBeforeCommit = {
    val txns = currentBatchTxns
    val ops = currentBatchOps
    val applied = transformedApplied(ops)
    val skipped = transformedSkipped(ops)
    all {
      pushActive,
      ops.size() > 0,
      keepConfig,
      keepRemote,
      keepLocal,
      clearPush,
      transformPushCalls' = incCalls(transformPushCalls, ops),
      skippedLeftPending' = skippedLeftPending.union(skipped.filter(op => opChangeId.get(op) > remoteCursor)),
      droppedAfterRetry' = droppedAfterRetry,
      outcomeSensitiveSkip' = outcomeSensitiveSkip.union(skippedLeftPending.filter(op => opChangeId.get(op) > remoteCursor)),
      recordBatch(txns, ops, applied, skipped, FAIL_BEFORE_COMMIT),
    }
  }

  run reproThresholdOneSkipThenKeepDropsSkippedPrefix =
    initWith(1)
      .then(localOneOpTxnFor(SKIP))
      .then(localOneOpTxnFor(KEEP))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchOps == Set(1))
      .expect(remoteCursor == 0)
      .expect(1.in(skippedLeftPending))
      .then(sendBatchSuccessObserved)
      .expect(lastBatchOps == Set(2))
      .expect(remoteCursor == opChangeId.get(2))
      .expect(not(1.in(remoteAppliedOps)))
      .expect(not(1.in(pendingOps)))
      .expect(not(RetriedSkipNotLaterAckedAcrossBatches))

  run reproThresholdOneSkipThenKeepFailureLeavesSkippedPending =
    initWith(1)
      .then(localOneOpTxnFor(SKIP))
      .then(localOneOpTxnFor(KEEP))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(1.in(skippedLeftPending))
      .then(sendBatchFailBeforeCommit)
      .expect(remoteCursor == 0)
      .expect(1.in(pendingOps))
      .expect(1.in(outcomeSensitiveSkip))

  run reproLostKeptSuffixAlsoDropsSkippedPrefix =
    initWith(1)
      .then(localOneOpTxnFor(SKIP))
      .then(localOneOpTxnFor(KEEP))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .then(sendBatchSuccessLostResponse)
      .expect(remoteCursor == opChangeId.get(2))
      .then(startPushFetchOk)
      .expect(not(1.in(pendingOps)))
      .expect(not(1.in(remoteAppliedOps)))

  run reproThresholdZeroReducesToSingleBatchSkipThenKeep =
    initWith(0)
      .then(localOneOpTxnFor(SKIP))
      .then(localOneOpTxnFor(KEEP))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchOps == Set(1, 2))
      .expect(remoteCursor == opChangeId.get(2))
      .expect(not(1.in(remoteAppliedOps)))
      .expect(not(1.in(pendingOps)))

  run reproKeepThenSkipSuffixRemainsPending =
    initWith(1)
      .then(localOneOpTxnFor(KEEP))
      .then(localOneOpTxnFor(SKIP))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(remoteCursor == opChangeId.get(1))
      .then(sendBatchSuccessObserved)
      .expect(remoteCursor == opChangeId.get(1))
      .expect(2.in(pendingOps))
      .then(finishNoopPush)
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(transformPushCalls.get(2) == 2)

  run reproTransformCanPartiallyApplyTxnWithBatching =
    initWith(1)
      .then(localTwoOpTxnFor(KEEP, SKIP))
      .then(startPushFetchOk)
      .then(sendBatchSuccessObserved)
      .expect(lastBatchOps == Set(1, 2))
      .expect(1.in(remoteAppliedOps))
      .expect(not(2.in(remoteAppliedOps)))
      .expect(txnPartiallyApplied(1))
      .expect(not(RemoteTxnAtomic))

  action step = any {
    localOneOpTxn,
    localTwoOpTxn,
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
      remoteAppliedOps.subseteq(localOps),
      localOps.subseteq(OPS),
      localTxns.subseteq(TXNS),
      opPolicy.keys() == OPS,
      opTxn.keys() == OPS,
      opChangeId.keys() == OPS,
      txnFirstOp.keys() == TXNS,
      txnLastOp.keys() == TXNS,
      txnCommitId.keys() == TXNS,
      nextOp >= 1,
      nextOp <= MAX_OP + 1,
      nextTxn >= 1,
      nextTxn <= MAX_TXN + 1,
      nextChange >= 1,
      nextChange <= MAX_CHANGE + 1,
      streamFrontierTxn >= 1,
      streamFrontierTxn <= MAX_TXN + 1,
      streamStartCursor >= 0,
      streamStartCursor <= MAX_CHANGE,
      batchInputCursor >= 0,
      batchInputCursor <= MAX_CHANGE,
      transformPushCalls.keys() == OPS,
      skippedLeftPending.subseteq(OPS),
      droppedAfterRetry.subseteq(OPS),
      outcomeSensitiveSkip.subseteq(OPS),
      lastBatchTxns.subseteq(TXNS),
      lastBatchOps.subseteq(OPS),
      lastAppliedOps.subseteq(lastBatchOps),
      lastSkippedOps.subseteq(lastBatchOps),
      lastAppliedOps.intersect(lastSkippedOps).size() == 0,
      lastBatchStreamFrontier >= 1,
      lastBatchStreamFrontier <= MAX_TXN + 1,
      lastBatchStreamStartCursor >= 0,
      lastBatchStreamStartCursor <= MAX_CHANGE,
      lastBatchInputCursor >= 0,
      lastBatchInputCursor <= MAX_CHANGE,
      lastBatchRemoteCursor >= 0,
      lastBatchRemoteCursor <= MAX_CHANGE,
      lastOutcome.in(OUTCOMES),
      OPS.forall(op =>
        and {
          opPolicy.get(op).in(POLICIES.union(Set(NO_POLICY))),
          opTxn.get(op) >= 0,
          opTxn.get(op) <= MAX_TXN,
          opChangeId.get(op) >= 0,
          opChangeId.get(op) <= MAX_CHANGE,
          transformPushCalls.get(op) >= 0,
        }
      ),
      TXNS.forall(txn =>
        and {
          txnFirstOp.get(txn) >= 0,
          txnFirstOp.get(txn) <= MAX_OP,
          txnLastOp.get(txn) >= 0,
          txnLastOp.get(txn) <= MAX_OP,
          txnCommitId.get(txn) >= 0,
          txnCommitId.get(txn) <= MAX_CHANGE,
          not(txn.in(localTxns)) or
            and {
              txnFirstOp.get(txn) <= txnLastOp.get(txn),
              txnOps(txn).size() > 0,
              txnCommitId.get(txn) == maxChangeOfOpsOr(txnOps(txn), 0) + 1,
            },
        }
      ),
    }

  pure def DeterministicBatchShape: bool =
    lastBatchOps.size() == 0 or
      and {
        lastBatchTxns == (
          if (nextBatchEndFrom(lastBatchStreamFrontier, lastBatchStreamStartCursor) == 0) {
            Set()
          } else {
            prefixTxnsToFrom(
              lastBatchStreamFrontier,
              lastBatchStreamStartCursor,
              nextBatchEndFrom(lastBatchStreamFrontier, lastBatchStreamStartCursor)
            )
          }
        ),
        lastBatchOps == opsOfTxnsAfterCursor(lastBatchTxns, lastBatchStreamStartCursor),
        priorPrefixesBelowThresholdFrom(lastBatchStreamFrontier, lastBatchStreamStartCursor, lastBatchTxns),
        threshold == 0 or
          isFinalBatchFrom(lastBatchStreamFrontier, lastBatchStreamStartCursor, lastBatchTxns) or
          rowCountFrom(lastBatchStreamStartCursor, lastBatchTxns) >= threshold,
      }

  pure def SkippedOpsNeverApplyRemoteSql: bool =
    remoteAppliedOps.forall(op => opPolicy.get(op) != SKIP)

  pure def SuccessfulBatchCursorShape: bool =
    lastOutcome != SUCCESS_OBSERVED and lastOutcome != SUCCESS_LOST or
      if (lastAppliedOps.size() == 0) {
        remoteCursor == lastBatchRemoteCursor
      } else {
        remoteCursor == maxChangeOfOpsOr(lastAppliedOps, lastBatchInputCursor)
      }

  pure def AllSkippedBatchDoesNotAdvanceCursor: bool =
    lastOutcome != SUCCESS_OBSERVED and lastOutcome != SUCCESS_LOST or
      lastAppliedOps.size() > 0 or remoteCursor == lastBatchRemoteCursor

  pure def FailedBatchDoesNotChangeDurableRemote: bool =
    lastOutcome != FAIL_BEFORE_COMMIT or
      and {
        remoteCursor == lastBatchRemoteCursor,
        lastAppliedOps.intersect(remoteAppliedOps).size() == 0,
      }

  pure def RetriedSkipNotLaterAckedAcrossBatches: bool =
    skippedLeftPending.forall(op => opChangeId.get(op) > trustedRemoteCursor)

  pure def SkippedDispositionIndependentOfLaterBatchOutcome: bool =
    outcomeSensitiveSkip.intersect(droppedAfterRetry).size() == 0

  pure def RemoteTxnAtomic: bool =
    TXNS.forall(txn => not(txnPartiallyApplied(txn)))

  temporal spec = init.and(always(step.orKeep(
    (
      threshold,
      localPullGen,
      remotePullGen,
      remoteCursor,
      remoteAppliedOps,
      localOps,
      localTxns,
      opPolicy,
      opTxn,
      opChangeId,
      txnFirstOp,
      txnLastOp,
      txnCommitId,
      nextOp,
      nextTxn,
      nextChange,
      pushActive,
      streamFrontierTxn,
      streamStartCursor,
      batchInputCursor,
      transformPushCalls,
      skippedLeftPending,
      droppedAfterRetry,
      outcomeSensitiveSkip,
      lastBatchTxns,
      lastBatchOps,
      lastAppliedOps,
      lastSkippedOps,
      lastBatchStreamFrontier,
      lastBatchStreamStartCursor,
      lastBatchInputCursor,
      lastBatchRemoteCursor,
      lastOutcome
    )
  )))
}
