# W2CONFLICT — differential findings (conflict resolution / triggers)

Engine: turso @ HEAD bad083fa vs SQLite 3.45.1 (python3 sqlite3).
Harness: /tmp/claude-0/-home-user-turso/cb07b0ad-0190-5b80-a162-e52287968e66/scratchpad/dt3.py (single-connection script comparator; foreign_keys=ON both).

## [WCONFLICT-1] Outer `OR ABORT` does not override a trigger body's conflict clause
- area: conflict resolution / triggers
- at-head: present
- category: sql-semantics
- severity: medium
- confidence: high
- description:
    SQLite rule (lang_createtrigger.html): when the statement that fires a
    trigger carries an explicit ON CONFLICT clause, that policy overrides the
    conflict clause of every INSERT/UPDATE in the trigger body. `OR ABORT` is
    an explicit clause and must override. Turso decides whether to override by
    testing the *collapsed* resolve type `!= Abort` (insert.rs:596,
    update.rs:610), which cannot tell a plain statement (no OR clause,
    OE_Default -> defers to body) apart from an explicit `OR ABORT`
    (OE_Abort -> overrides body). Both collapse to `ResolveType::Abort`, so
    turso never overrides for `OR ABORT`. Result: a trigger body's own
    `OR IGNORE`/`OR REPLACE` wrongly stays in effect, so a constraint
    violation SQLite raises is silently swallowed (and the row is
    inserted/replaced when SQLite would roll the statement back).
    The correct signal already exists in the codebase
    (`statement_on_conflict: Option<ResolveType>` / `has_statement_conflict`,
    used in the NOT NULL / index paths) but is not used at the trigger-override
    site. FAIL/ROLLBACK/IGNORE/REPLACE outer clauses work (they are `!= Abort`);
    only `OR ABORT` is broken. Affects both INSERT OR ABORT and UPDATE OR ABORT.
- failure: |
    Schema:
      CREATE TABLE t(id INTEGER PRIMARY KEY, a);
      CREATE TABLE u(x UNIQUE, y);
      INSERT INTO u VALUES(5,50);
      CREATE TRIGGER ai AFTER INSERT ON t BEGIN INSERT OR IGNORE INTO u VALUES(5, new.a); END;
    Statement:
      INSERT OR ABORT INTO t VALUES(1,99);
    SQLite: aborts -> "UNIQUE constraint failed: u.x"; t and u unchanged.
    Turso : no error; t = {1|99}; u = {5|50}  (body OR IGNORE wrongly applied).

    With body `INSERT OR REPLACE INTO u VALUES(5,new.a)` and same outer:
    SQLite: aborts -> "UNIQUE constraint failed: u.x".
    Turso : no error; t = {1|99}; u = {5|99}  (body REPLACE wrongly applied).

    UPDATE variant (AFTER UPDATE trigger, body INSERT OR IGNORE into u):
      UPDATE OR ABORT t SET a=99 WHERE id=1;
    SQLite: aborts. Turso: no error, u unchanged, t updated.
- evidence: |
    dt3 transcript:
      [outer-ABORT-overrides-body-IGNORE] MISMATCH (error-state)
        turso : err=False out='1|99\n5|50\n'
        sqlite: err=True  'IntegrityError: UNIQUE constraint failed: u.x'
      [outer-ABORT-overrides-body-REPLACE] MISMATCH
        turso : err=False out='1|99\n5|99\n'
        sqlite: err=True  'UNIQUE constraint failed: u.x'
      [UPD-outer-ABORT-body-IGNORE] MISMATCH
        turso : err=False out='1|99\n5|50\n'
        sqlite: err=True  'UNIQUE constraint failed: u.x'
      Controls (all OK): outer plain INSERT defers to body IGNORE; outer
        OR FAIL / OR ROLLBACK correctly override (error on both engines).
    Code path:
      core/translate/insert.rs:596
        `} else if !matches!(ctx.on_conflict, ResolveType::Abort) {`  (override)
      core/translate/emitter/update.rs:610
        `.or_else(|| (!matches!(or_conflict, ResolveType::Abort)).then_some(or_conflict))`
      Correct signal available: insert.rs:139 `statement_on_conflict: Option<ResolveType>`,
      builder `has_statement_conflict` (update.rs:106 set from `plan.or_conflict.is_some()`).

## [WCONFLICT-3] Outer `OR IGNORE` leaks through the DELETE-trigger boundary (a48e3f01 fix incomplete)
- area: conflict resolution / triggers
- at-head: present
- category: sql-semantics / data-corruption (wrong side effect)
- severity: high
- confidence: high
- description:
    Commit a48e3f01 made DELETE triggers fire with the *default* conflict
    policy (SQLite codes row-delete triggers with OE_Default), so a plain
    INSERT inside a DELETE trigger aborts even when an outer OR REPLACE fired
    the delete. That fix only reset the compile-time `trigger_conflict_override`
    (delete.rs:934/998 build `TriggerContext::new`), which cures OR REPLACE. But
    outer `OR IGNORE` also propagates at RUNTIME via the `ignore_jump_target`
    carried on `Insn::Program` (trigger_exec.rs:678-682): when an outer
    OR IGNORE statement fires a trigger whose body DELETEs rows, the DELETE's
    own trigger body still jumps to the outer ignore target on a conflict
    instead of aborting. So the constraint violation SQLite raises is silently
    swallowed, the DELETE-trigger body is truncated, and the delete proceeds —
    a wrong side effect, not just a missing error. Even an explicit
    `INSERT OR ABORT` inside the DELETE trigger is overridden by the leaked
    IGNORE (contradicting a48e3f01's own invariant that "a trigger statement's
    own explicit OR clause still applies"). OR REPLACE and OR FAIL outer
    clauses are unaffected; only OR IGNORE leaks. Affects both INSERT OR IGNORE
    and UPDATE OR IGNORE as the outer statement, and swallows UNIQUE/PK, CHECK,
    and NOT NULL violations alike in the DELETE-trigger body.
- failure: |
    CREATE TABLE t(pk INTEGER PRIMARY KEY, x);
    CREATE TABLE t2(pk INTEGER PRIMARY KEY, y);
    INSERT INTO t VALUES(1,0);
    INSERT INTO t2 VALUES(1,0);
    CREATE TRIGGER t2_bd BEFORE DELETE ON t2 BEGIN
      INSERT INTO t2(pk,y) VALUES(1,1);   -- conflicts with pk=1 (still present)
    END;
    CREATE TRIGGER t_au AFTER UPDATE ON t BEGIN DELETE FROM t2 WHERE pk=1; END;
    UPDATE OR IGNORE t SET x=9;
    SQLite: aborts -> "UNIQUE constraint failed: t2.pk"; t={1,0}, t2={1,0} (whole stmt rolled back).
    Turso : NO error; t={1,9} (UPDATE applied!), t2={1,0}  (conflict silently swallowed).
    (Exactly a48e3f01's own repro with OR IGNORE substituted for OR REPLACE. Direct-CLI
     verified. A variant that also logs inside t2_bd shows t2 left EMPTY, i.e. the
     BEFORE DELETE body is truncated mid-way and the delete still applies — the exact
     wrong-side-effect shape depends on the body, but turso never raises the error.)
- evidence: |
    Granular turso probe (log rows):
      au-fired
      bd-fired old.pk=1
      au-after-delete
      -> 'bd-after-insert' NEVER logged: the INSERT(1,1) conflict jumped to the
         outer ignore target, skipping the rest of the BEFORE DELETE body; t2 empty.
    SQLite: raises 'UNIQUE constraint failed: t2.pk', log empty (rolled back).
    dt3 matrix:
      [a48-exact-OR-REPLACE]  OK   (a48e3f01 fixed)
      [a48-variant-OR-FAIL]   OK   (FAIL errors like default ABORT, masks nothing here)
      [a48-variant-OR-IGNORE] MISMATCH  turso err=False t2 empty; sqlite aborts
      [a48-INSERT-outer-OR-IGNORE] MISMATCH  (INSERT OR IGNORE outer, same leak)
      [inner-OR-ABORT] MISMATCH  even explicit inner INSERT OR ABORT is ignored by turso
      [inner-OR-REPLACE] OK      (inner's own REPLACE applies)
    Code: runtime path trigger_exec.rs:678-682 (`Insn::Program { ignore_jump_target }`),
    fire_trigger ignore_jump_target param (:531); a48e3f01 only touched the
    compile-time context in delete.rs:934/998.

## [WCONFLICT-2] `PRAGMA recursive_triggers=ON` is silently ignored (always behaves OFF)
- area: conflict resolution / triggers
- at-head: present
- category: sql-semantics
- severity: low
- confidence: high
- description:
    Turso treats every unknown PRAGMA as a no-op (intentional, see
    sqlite-sqltests/pragma-unknown-no-op.sqltest, which only asserts the
    default `recursive_triggers=OFF`). `recursive_triggers` is not implemented
    anywhere in core/, so `PRAGMA recursive_triggers=ON` is accepted but has no
    effect and turso always behaves as if recursive triggers are OFF. Two
    observable SQLite behaviors are then wrong when a user turns it ON:
      (a) INSERT/UPDATE OR REPLACE that deletes rows to satisfy a constraint
          fires BEFORE/AFTER DELETE triggers on the deleted rows (SQLite:
          "delete triggers fire iff recursive triggers are enabled"). Turso
          never fires them.
      (b) A trigger that modifies its own table does not re-fire recursively.
    At the DEFAULT setting (OFF) both engines agree, so impact is limited to
    code that explicitly enables the pragma.
- failure: |
    PRAGMA recursive_triggers=ON;
    CREATE TABLE t(id INTEGER PRIMARY KEY, a UNIQUE, b);
    CREATE TABLE log(msg);
    INSERT INTO t VALUES(1,10,100);
    CREATE TRIGGER bd BEFORE DELETE ON t BEGIN INSERT INTO log VALUES('bd:'||old.id); END;
    CREATE TRIGGER ad AFTER  DELETE ON t BEGIN INSERT INTO log VALUES('ad:'||old.id); END;
    INSERT OR REPLACE INTO t VALUES(2,10,200);   -- conflict on a=10 deletes row 1
    SELECT msg FROM log ORDER BY msg;
    SQLite: 'ad:1' , 'bd:1'   (delete triggers fired)
    Turso : (empty)           (delete triggers never fired)
- evidence: |
    dt2 transcript:
      [replace-delete-trig-recursive-ON/verify1] MISMATCH
        turso : out=''
        sqlite: out='ad:1\nbd:1'
      [replace-delete-trig-recursive-OFF] OK
      [trigger-self-recursion-ON] MISMATCH
        turso : out='1|0\n101|1'
        sqlite: out='1|0\n101|1\n201|2\n301|3'
    `grep -rn recursive_triggers core/` -> no matches (pragma unimplemented).
