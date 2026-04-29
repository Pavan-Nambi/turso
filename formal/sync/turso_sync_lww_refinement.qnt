module turso_sync_lww_refinement {
  pure val CLIENTS: Set[str] = Set("c1", "c2")
  pure val NO_CLIENT: str = "none"
  pure val ABSENT: int = 0
  pure val BASE: int = 1
  pure val A_VALUE: int = 2
  pure val B_VALUE: int = 3
  pure val VALUES: Set[int] = Set(ABSENT, BASE, A_VALUE, B_VALUE)
  pure val OPS: Set[int] = 1.to(4)

  var idealRemote: int
  var rustRemote: int
  var clientRows: str -> int
  var localOps: str -> Set[int]
  var pushedOps: str -> Set[int]
  var opOwner: int -> str
  var opKind: int -> str
  var opValue: int -> int
  var opSeq: int -> int
  var nextOp: int
  var nextSeq: int

  pure val emptyClientOps: str -> Set[int] =
    CLIENTS.mapBy(_ => Set())

  pure val baseRows: str -> int =
    CLIENTS.mapBy(_ => BASE)

  def applyIdeal(row: int, op: int): int =
    if (opKind.get(op) == "delete") {
      ABSENT
    } else {
      opValue.get(op)
    }

  def applyRust(row: int, op: int): int =
    if (opKind.get(op) == "delete") {
      ABSENT
    } else if (opKind.get(op) == "insert") {
      opValue.get(op)
    } else if (row == ABSENT) {
      ABSENT
    } else {
      opValue.get(op)
    }

  def applyOpSetIdeal(row: int, ops: Set[int]): int = {
    val after1 = if (1.in(ops)) { applyIdeal(row, 1) } else { row }
    val after2 = if (2.in(ops)) { applyIdeal(after1, 2) } else { after1 }
    val after3 = if (3.in(ops)) { applyIdeal(after2, 3) } else { after2 }
    if (4.in(ops)) { applyIdeal(after3, 4) } else { after3 }
  }

  def applyOpSetRust(row: int, ops: Set[int]): int = {
    val after1 = if (1.in(ops)) { applyRust(row, 1) } else { row }
    val after2 = if (2.in(ops)) { applyRust(after1, 2) } else { after1 }
    val after3 = if (3.in(ops)) { applyRust(after2, 3) } else { after2 }
    if (4.in(ops)) { applyRust(after3, 4) } else { after3 }
  }

  def unpushedOps(c: str): Set[int] =
    localOps.get(c).exclude(pushedOps.get(c))

  def chooseValue(c: str): int =
    if (c == "c1") { A_VALUE } else { B_VALUE }

  action init = all {
    idealRemote' = BASE,
    rustRemote' = BASE,
    clientRows' = baseRows,
    localOps' = emptyClientOps,
    pushedOps' = emptyClientOps,
    opOwner' = OPS.mapBy(_ => NO_CLIENT),
    opKind' = OPS.mapBy(_ => "none"),
    opValue' = OPS.mapBy(_ => ABSENT),
    opSeq' = OPS.mapBy(_ => 0),
    nextOp' = 1,
    nextSeq' = 1,
  }

  action keepRemote = all {
    idealRemote' = idealRemote,
    rustRemote' = rustRemote,
  }

  action keepLocal = all {
    clientRows' = clientRows,
    localOps' = localOps,
    pushedOps' = pushedOps,
    opOwner' = opOwner,
    opKind' = opKind,
    opValue' = opValue,
    opSeq' = opSeq,
    nextOp' = nextOp,
    nextSeq' = nextSeq,
  }

  action localDelete = {
    nondet c = CLIENTS.oneOf()
    localOpFor(c, "delete", ABSENT)
  }

  action localUpdate = {
    nondet c = CLIENTS.oneOf()
    localOpFor(c, "update", chooseValue(c))
  }

  action localInsert = {
    nondet c = CLIENTS.oneOf()
    localOpFor(c, "insert", chooseValue(c))
  }

  action localOpFor(c: str, kind: str, value: int): bool = all {
    c.in(CLIENTS),
    kind.in(Set("delete", "update", "insert")),
    value.in(VALUES),
    kind != "delete" implies value != ABSENT,
    nextOp <= 4,
    keepRemote,
    clientRows' = clientRows.set(c, if (kind == "delete") { ABSENT } else { value }),
    localOps' = localOps.set(c, localOps.get(c).union(Set(nextOp))),
    pushedOps' = pushedOps,
    opOwner' = opOwner.set(nextOp, c),
    opKind' = opKind.set(nextOp, kind),
    opValue' = opValue.set(nextOp, value),
    opSeq' = opSeq.set(nextOp, nextSeq),
    nextOp' = nextOp + 1,
    nextSeq' = nextSeq + 1,
  }

  action push = {
    nondet c = CLIENTS.oneOf()
    pushFor(c)
  }

  action pushFor(c: str): bool = {
    val sent = unpushedOps(c)
    all {
      c.in(CLIENTS),
      sent.size() > 0,
      idealRemote' = applyOpSetIdeal(idealRemote, sent),
      rustRemote' = applyOpSetRust(rustRemote, sent),
      clientRows' = clientRows,
      localOps' = localOps,
      pushedOps' = pushedOps.set(c, pushedOps.get(c).union(sent)),
      opOwner' = opOwner,
      opKind' = opKind,
      opValue' = opValue,
      opSeq' = opSeq,
      nextOp' = nextOp,
      nextSeq' = nextSeq,
    }
  }

  action pull = {
    nondet c = CLIENTS.oneOf()
    pullFor(c)
  }

  action pullFor(c: str): bool = {
    val suffix = unpushedOps(c)
    all {
      c.in(CLIENTS),
      keepRemote,
      clientRows' = clientRows.set(c, applyOpSetIdeal(idealRemote, suffix)),
      localOps' = localOps.set(c, suffix),
      pushedOps' = pushedOps.set(c, Set()),
      opOwner' = opOwner,
      opKind' = opKind,
      opValue' = opValue,
      opSeq' = opSeq,
      nextOp' = nextOp,
      nextSeq' = nextSeq,
    }
  }

  run reproUpdateAfterDeleteDiverges =
    init
      .then(localOpFor("c1", "delete", ABSENT))
      .then(pushFor("c1"))
      .then(localOpFor("c2", "update", B_VALUE))
      .then(pushFor("c2"))
      .expect(idealRemote == B_VALUE)
      .expect(rustRemote == ABSENT)

  run reproInsertAfterDeleteConverges =
    init
      .then(localOpFor("c1", "delete", ABSENT))
      .then(pushFor("c1"))
      .then(localOpFor("c2", "insert", B_VALUE))
      .then(pushFor("c2"))
      .expect(idealRemote == B_VALUE)
      .expect(rustRemote == B_VALUE)

  action step = any {
    localDelete,
    localUpdate,
    localInsert,
    push,
    pull,
  }

  pure def TypeOK: bool =
    and {
      idealRemote.in(VALUES),
      rustRemote.in(VALUES),
      clientRows.keys() == CLIENTS,
      localOps.keys() == CLIENTS,
      pushedOps.keys() == CLIENTS,
      opOwner.keys() == OPS,
      opKind.keys() == OPS,
      opValue.keys() == OPS,
      opSeq.keys() == OPS,
      nextOp >= 1,
      nextOp <= 5,
      nextSeq >= 1,
      nextSeq <= 5,
      CLIENTS.forall(c =>
        and {
          clientRows.get(c).in(VALUES),
          localOps.get(c).subseteq(OPS),
          pushedOps.get(c).subseteq(localOps.get(c)),
          localOps.get(c).forall(op => opOwner.get(op) == c),
        }
      ),
      OPS.forall(op =>
        and {
          opOwner.get(op).in(CLIENTS.union(Set(NO_CLIENT))),
          opKind.get(op).in(Set("none", "delete", "update", "insert")),
          opValue.get(op).in(VALUES),
          opSeq.get(op) >= 0,
        }
      ),
    }

  pure def RustRefinesLww: bool =
    rustRemote == idealRemote

  pure def PushedOpsAffectRemote: bool =
    CLIENTS.forall(c => pushedOps.get(c).subseteq(localOps.get(c)))

  temporal spec = init.and(always(step.orKeep(
    (
      idealRemote,
      rustRemote,
      clientRows,
      localOps,
      pushedOps,
      opOwner,
      opKind,
      opValue,
      opSeq,
      nextOp,
      nextSeq
    )
  )))
}
