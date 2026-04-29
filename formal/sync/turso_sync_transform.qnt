module turso_sync_transform {
  pure val CLIENT: str = "c1"
  pure val NO_POLICY: str = "none"
  pure val KEEP: str = "keep"
  pure val SKIP: str = "skip"
  pure val REWRITE: str = "rewrite"
  pure val NO_CONTEXT: str = "none"
  pure val LOCAL: str = "local"
  pure val REMOTE: str = "remote"
  pure val PUSH: str = "push"
  pure val PULL: str = "pull"
  pure val NO_TXN: int = 0
  pure val REMOTE_MARK: int = 10
  pure val MAX_OP: int = 4
  pure val OPS: Set[int] = 1.to(MAX_OP)
  pure val ROWS: Set[int] = OPS.union(Set(REMOTE_MARK))
  pure val TXNS: Set[int] = 1.to(MAX_OP)
  pure val POLICIES: Set[str] = Set(KEEP, SKIP, REWRITE)
  pure val CONTEXTS: Set[str] = Set(NO_CONTEXT, LOCAL, REMOTE, PUSH, PULL)

  // User-local logical work that still exists in the modeled local tape.
  var localOps: Set[int]
  // User-local logical work ever created. This lets us express preservation
  // obligations even when pull replay omits a local mutation.
  var createdOps: Set[int]
  // Remote cursor from turso_sync_last_change_id.
  var remoteCursor: int
  // Local ops that actually emitted SQL on the remote. This is distinct from
  // remoteCursor because skipped ops can be <= remoteCursor without applying.
  var remoteApplied: Set[int]
  // A remote change marker, used only to make pull/apply meaningful.
  var remoteBase: Set[int]
  // Local visible row markers after user writes or pull replay.
  var localVisible: Set[int]

  var opPolicy: int -> str
  var opTxn: int -> int
  var nextOp: int
  var nextTxn: int

  var transformPushCalls: int -> int
  var transformPullCalls: int -> int
  // A skipped op that was left pending after a push. If the same deterministic
  // skip later becomes <= cursor only because a suffix op was kept, the
  // implementation has changed that op's disposition from retry to ack/drop.
  var skipRetried: Set[int]

  var lastBatch: Set[int]
  var lastSkipped: Set[int]
  var lastApplied: Set[int]
  var lastContext: str

  pure val noPolicyMap: int -> str =
    OPS.mapBy(_ => NO_POLICY)

  pure val noTxnMap: int -> int =
    OPS.mapBy(_ => NO_TXN)

  pure val zeroOpInts: int -> int =
    OPS.mapBy(_ => 0)

  def pendingOps: Set[int] =
    localOps.filter(op => op > remoteCursor)

  def batchUpTo(upTo: int): Set[int] =
    localOps.filter(op => and { op > remoteCursor, op <= upTo })

  def transformedApplied(batch: Set[int]): Set[int] =
    batch.filter(op => opPolicy.get(op) != SKIP)

  def transformedSkipped(batch: Set[int]): Set[int] =
    batch.filter(op => opPolicy.get(op) == SKIP)

  def maxAppliedOrCursor(applied: Set[int]): int =
    if (4.in(applied)) {
      4
    } else if (3.in(applied)) {
      3
    } else if (2.in(applied)) {
      2
    } else if (1.in(applied)) {
      1
    } else {
      remoteCursor
    }

  def incCalls(calls: int -> int, batch: Set[int]): int -> int =
    OPS.mapBy(op => if (op.in(batch)) { calls.get(op) + 1 } else { calls.get(op) })

  def txnOps(txn: int): Set[int] =
    createdOps.filter(op => opTxn.get(op) == txn)

  def txnPartiallyApplied(txn: int): bool = {
    val ops = txnOps(txn)
    val applied = ops.filter(op => op.in(remoteApplied))
    and {
      ops.size() > 1,
      applied.size() > 0,
      not(ops.subseteq(remoteApplied)),
    }
  }

  action init = all {
    localOps' = Set(),
    createdOps' = Set(),
    remoteCursor' = 0,
    remoteApplied' = Set(),
    remoteBase' = Set(),
    localVisible' = Set(),
    opPolicy' = noPolicyMap,
    opTxn' = noTxnMap,
    nextOp' = 1,
    nextTxn' = 1,
    transformPushCalls' = zeroOpInts,
    transformPullCalls' = zeroOpInts,
    skipRetried' = Set(),
    lastBatch' = Set(),
    lastSkipped' = Set(),
    lastApplied' = Set(),
    lastContext' = NO_CONTEXT,
  }

  action keepRemote = all {
    remoteCursor' = remoteCursor,
    remoteApplied' = remoteApplied,
    remoteBase' = remoteBase,
  }

  action keepLocalTape = all {
    localOps' = localOps,
    createdOps' = createdOps,
    localVisible' = localVisible,
    opPolicy' = opPolicy,
    opTxn' = opTxn,
    nextOp' = nextOp,
    nextTxn' = nextTxn,
  }

  action keepCounters = all {
    transformPushCalls' = transformPushCalls,
    transformPullCalls' = transformPullCalls,
    skipRetried' = skipRetried,
  }

  action localWrite = {
    nondet policy = POLICIES.oneOf()
    localWriteFor(policy)
  }

  action localWriteFor(policy: str): bool = all {
    policy.in(POLICIES),
    nextOp <= MAX_OP,
    nextTxn <= MAX_OP,
    keepRemote,
    localOps' = localOps.union(Set(nextOp)),
    createdOps' = createdOps.union(Set(nextOp)),
    localVisible' = localVisible.union(Set(nextOp)),
    opPolicy' = opPolicy.set(nextOp, policy),
    opTxn' = opTxn.set(nextOp, nextTxn),
    nextOp' = nextOp + 1,
    nextTxn' = nextTxn + 1,
    keepCounters,
    lastBatch' = Set(nextOp),
    lastSkipped' = Set(),
    lastApplied' = Set(),
    lastContext' = LOCAL,
  }

  action localTwoOpTxn = {
    nondet policy1 = POLICIES.oneOf()
    nondet policy2 = POLICIES.oneOf()
    localTwoOpTxnFor(policy1, policy2)
  }

  action localTwoOpTxnFor(policy1: str, policy2: str): bool = all {
    policy1.in(POLICIES),
    policy2.in(POLICIES),
    nextOp + 1 <= MAX_OP,
    nextTxn <= MAX_OP,
    keepRemote,
    localOps' = localOps.union(Set(nextOp, nextOp + 1)),
    createdOps' = createdOps.union(Set(nextOp, nextOp + 1)),
    localVisible' = localVisible.union(Set(nextOp, nextOp + 1)),
    opPolicy' = opPolicy.set(nextOp, policy1).set(nextOp + 1, policy2),
    opTxn' = opTxn.set(nextOp, nextTxn).set(nextOp + 1, nextTxn),
    nextOp' = nextOp + 2,
    nextTxn' = nextTxn + 1,
    keepCounters,
    lastBatch' = Set(nextOp, nextOp + 1),
    lastSkipped' = Set(),
    lastApplied' = Set(),
    lastContext' = LOCAL,
  }

  action remoteWrite = all {
    remoteCursor' = remoteCursor,
    remoteApplied' = remoteApplied,
    remoteBase' = remoteBase.union(Set(REMOTE_MARK)),
    keepLocalTape,
    keepCounters,
    lastBatch' = Set(),
    lastSkipped' = Set(),
    lastApplied' = Set(),
    lastContext' = REMOTE,
  }

  action pushBatch = {
    nondet upTo = OPS.oneOf()
    pushBatchFor(upTo)
  }

  // Rust-like implementation rule:
  // - every pending row in the chosen prefix is passed to transform,
  // - skipped rows emit no SQL and do not update last_change_id,
  // - keep/rewrite rows emit SQL and update last_change_id,
  // - the durable cursor becomes the last non-skipped change in the batch,
  //   if any non-skipped change exists.
  action pushBatchFor(upTo: int): bool = {
    val batch = batchUpTo(upTo)
    val applied = transformedApplied(batch)
    val skipped = transformedSkipped(batch)
    val nextCursor = maxAppliedOrCursor(applied)
    all {
      upTo.in(OPS),
      batch.size() > 0,
      keepLocalTape,
      remoteCursor' = nextCursor,
      remoteApplied' = remoteApplied.union(applied),
      remoteBase' = remoteBase,
      transformPushCalls' = incCalls(transformPushCalls, batch),
      transformPullCalls' = transformPullCalls,
      skipRetried' = skipRetried.union(skipped.filter(op => op > nextCursor)),
      lastBatch' = batch,
      lastSkipped' = skipped,
      lastApplied' = applied,
      lastContext' = PUSH,
    }
  }

  action applyPull = {
    val suffix = pendingOps
    val replayed = transformedApplied(suffix)
    val skipped = transformedSkipped(suffix)
    all {
      remoteBase.size() > 0,
      suffix.size() > 0,
      remoteCursor' = remoteCursor,
      remoteApplied' = remoteApplied,
      remoteBase' = remoteBase,
      localOps' = replayed,
      createdOps' = createdOps,
      localVisible' = remoteBase.union(remoteApplied).union(replayed),
      opPolicy' = opPolicy,
      opTxn' = opTxn,
      nextOp' = nextOp,
      nextTxn' = nextTxn,
      transformPushCalls' = transformPushCalls,
      transformPullCalls' = incCalls(transformPullCalls, suffix),
      skipRetried' = skipRetried,
      lastBatch' = suffix,
      lastSkipped' = skipped,
      lastApplied' = replayed,
      lastContext' = PULL,
    }
  }

  run reproAllSkippedPushDoesNotAdvanceCursor =
    init
      .then(localWriteFor(SKIP))
      .then(pushBatchFor(1))
      .expect(remoteCursor == 0)
      .expect(1.in(pendingOps))
      .expect(transformPushCalls.get(1) == 1)

  run reproTrailingSkipIsRetried =
    init
      .then(localWriteFor(KEEP))
      .then(localWriteFor(SKIP))
      .then(pushBatchFor(2))
      .expect(remoteCursor == 1)
      .expect(2.in(pendingOps))
      .then(pushBatchFor(2))
      .expect(remoteCursor == 1)
      .expect(transformPushCalls.get(2) == 2)

  run reproMiddleSkipAckedByLaterKeep =
    init
      .then(localWriteFor(SKIP))
      .then(localWriteFor(KEEP))
      .then(pushBatchFor(2))
      .expect(remoteCursor == 2)
      .expect(not(1.in(remoteApplied)))
      .expect(not(1.in(pendingOps)))

  run reproSkipRetryThenAckedByLaterKeep =
    init
      .then(localWriteFor(SKIP))
      .then(pushBatchFor(1))
      .expect(1.in(skipRetried))
      .then(localWriteFor(KEEP))
      .then(pushBatchFor(2))
      .expect(remoteCursor == 2)
      .expect(1.in(skipRetried))
      .expect(not(RetriedSkipNotLaterAcked))

  run reproPullReplaySkipDropsLocalChange =
    init
      .then(localWriteFor(SKIP))
      .then(remoteWrite)
      .then(applyPull)
      .expect(1.in(createdOps))
      .expect(1 > remoteCursor)
      .expect(not(1.in(localVisible)))
      .expect(not(UnackedLocalWritesVisible))

  run reproTransformCanPartiallyApplyTxn =
    init
      .then(localTwoOpTxnFor(KEEP, SKIP))
      .then(pushBatchFor(2))
      .expect(1.in(remoteApplied))
      .expect(not(2.in(remoteApplied)))
      .expect(txnPartiallyApplied(1))
      .expect(not(RemoteTxnAtomic))

  action step = any {
    localWrite,
    localTwoOpTxn,
    remoteWrite,
    pushBatch,
    applyPull,
  }

  pure def TypeOK: bool =
    and {
      localOps.subseteq(OPS),
      createdOps.subseteq(OPS),
      localOps.subseteq(createdOps),
      remoteCursor >= 0,
      remoteCursor <= MAX_OP,
      remoteApplied.subseteq(createdOps),
      remoteBase.subseteq(Set(REMOTE_MARK)),
      localVisible.subseteq(ROWS),
      opPolicy.keys() == OPS,
      opTxn.keys() == OPS,
      transformPushCalls.keys() == OPS,
      transformPullCalls.keys() == OPS,
      skipRetried.subseteq(OPS),
      lastBatch.subseteq(OPS),
      lastSkipped.subseteq(lastBatch),
      lastApplied.subseteq(lastBatch),
      lastSkipped.filter(op => op.in(lastApplied)).size() == 0,
      lastContext.in(CONTEXTS),
      nextOp >= 1,
      nextOp <= MAX_OP + 1,
      nextTxn >= 1,
      nextTxn <= MAX_OP + 1,
      OPS.forall(op =>
        and {
          opPolicy.get(op).in(POLICIES.union(Set(NO_POLICY))),
          opTxn.get(op) >= NO_TXN,
          opTxn.get(op) <= MAX_OP,
          transformPushCalls.get(op) >= 0,
          transformPullCalls.get(op) >= 0,
        }
      ),
      createdOps.forall(op => opPolicy.get(op).in(POLICIES)),
    }

  pure def RustPushCursorShape: bool =
    lastContext != PUSH or
      if (lastApplied.size() == 0) {
        lastBatch.forall(op => op > remoteCursor)
      } else {
        remoteCursor == maxAppliedOrCursor(lastApplied)
      }

  pure def SkippedOpsNeverApplyRemoteSql: bool =
    remoteApplied.forall(op => opPolicy.get(op) != SKIP)

  // Contract candidate: if a deterministic skip was previously retried because
  // it remained pending, a later batch should not silently convert it into an
  // acknowledged/drop disposition merely because a suffix op was kept.
  pure def RetriedSkipNotLaterAcked: bool =
    skipRetried.forall(op => op > remoteCursor)

  // Contract candidate from JS docs: transform is described as running before
  // push sends mutations to the remote. If pull replay also applies transform,
  // a local unacknowledged write can disappear from the local view.
  pure def UnackedLocalWritesVisible: bool =
    createdOps.filter(op => op > remoteCursor).forall(op => op.in(localVisible))

  // Contract candidate: CDC transactions should not be half-applied remotely.
  // This is intentionally stronger than the current transform implementation,
  // because skip/rewrite gives the callback row-level control.
  pure def RemoteTxnAtomic: bool =
    TXNS.forall(txn => not(txnPartiallyApplied(txn)))

  temporal spec = init.and(always(step.orKeep(
    (
      localOps,
      createdOps,
      remoteCursor,
      remoteApplied,
      remoteBase,
      localVisible,
      opPolicy,
      opTxn,
      nextOp,
      nextTxn,
      transformPushCalls,
      transformPullCalls,
      skipRetried,
      lastBatch,
      lastSkipped,
      lastApplied,
      lastContext
    )
  )))
}
