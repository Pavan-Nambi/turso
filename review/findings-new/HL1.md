# HL1 — LIMIT/OFFSET + joins differential findings

## [HL1-1] OFFSET on a nested-loop join skips offset × inner-size rows instead of offset rows
- area: LIMIT/OFFSET + joins
- at-head: present (confirmed identical code at working tree bad083fa and reviewed HEAD 5f6098a0)
- category: sql-semantics
- severity: critical
- confidence: high
- description: >
    For any multi-table nested-loop join (cross join, or an inner/left join the
    optimizer does NOT turn into a hash join, e.g. a non-equi ON condition),
    a positive OFFSET makes turso skip the wrong number of rows and return
    wrong rows — and often drops real rows entirely. When OFFSET decrements,
    turso jumps to the OUTERMOST loop's "next" instead of the INNERMOST loop's
    "next". So each unit of OFFSET advances the outer cursor by one and rewinds
    all inner cursors, discarding a whole inner-table pass. Net effect: turso
    skips roughly offset × (product of inner table sizes) output rows instead
    of offset rows. This is a genuine value mismatch (wrong rows and/or missing
    rows), not a formatting/ordering difference.

    The prior fix 5ff86579 ("Fix/6078 join limit offset false corruption")
    changed the offset jump target to `plan.join_order.first()`. That resolves
    the crash/unresolved-label case for hash joins (where join_order has exactly
    one main-loop table, so first == last == the probe table), but `.first()`
    is the OUTERMOST loop for a genuine multi-table nested loop. The correct
    target is `plan.join_order.last()` (the innermost loop). The fix is
    therefore incomplete for nested-loop joins.

    Masked by (still correct): ORDER BY queries (offset is applied at the
    sorter-output stage, not in the main loop), hash joins / equi-joins that
    become hash joins (one main-loop table), single-table selects, OFFSET 0,
    and LIMIT 0.
- failure: |
    Schema:
      CREATE TABLE a(x); INSERT INTO a VALUES (1),(2),(3);
      CREATE TABLE b(y); INSERT INTO b VALUES (10),(20),(30),(40);

    Query:  SELECT x,y FROM a, b LIMIT 3 OFFSET 2;
      turso : 3|10 / 3|20 / 3|30      (starts at output row 8 = offset 2 × inner-size 4)
      sqlite: 1|30 / 1|40 / 2|10      (correct: starts at output row 2)

    Minimal 2x2 repro:
      CREATE TABLE a(x); INSERT INTO a VALUES (1),(2);
      CREATE TABLE b(y); INSERT INTO b VALUES (10),(20);
      SELECT x,y FROM a, b LIMIT 1 OFFSET 1;
      turso : 2|10        sqlite: 1|20

    Data loss (rows silently dropped):
      SELECT x,y FROM a, b LIMIT 100 OFFSET 3;   (a=3 rows, b=4 rows, 12 total)
      turso : <empty>     sqlite: 9 rows (1|40, 2|10, ... 3|40)

    Also fails on nested-loop inner joins without ORDER BY:
      SELECT x,y FROM a JOIN b ON x<y WHERE y>10 LIMIT 3 OFFSET 2;
      turso : 1|40 / 2|40 / 3|40      sqlite: 3|20 / 1|30 / 2|30
    And 3-table cross joins:
      SELECT x,y,z FROM a,b,c LIMIT 4 OFFSET 1;   (c = 100,200)
      turso : 2|10|100 / 2|10|200 / 2|20|100 / 2|20|200
      sqlite: 1|10|200 / 1|20|100 / 1|20|200 / 1|30|100
- evidence: |
    Root cause — core/translate/main_loop/body.rs:420-425 (LoopEmitTarget::QueryResult):
        let offset_jump_to = plan
            .join_order
            .first()                                  // <-- OUTERMOST loop; should be .last() (innermost)
            .and_then(|j| t_ctx.labels_main_loop.get(j.original_idx))
            .map(|l| l.next)
            .or(t_ctx.label_main_loop_end);
    This BranchOffset is passed to emit_select_result -> emit_offset
    (core/translate/result_row.rs:497-506), which emits
        IfPos { reg: reg_offset, target_pc: jump_to, decrement_by: 1 }
    i.e. "while offset>0, decrement and jump to jump_to". jump_to must be the
    innermost loop's Next so it advances only the inner cursor; pointing it at
    the outermost loop's Next discards the rest of the inner scan.

    join_order ordering: open.rs (core/translate/main_loop/open.rs:61) opens
    loops in join_order order, so index 0 (.first()) is the OUTERMOST loop;
    close.rs (core/translate/main_loop/close.rs:26) closes in reverse, so
    .last() is the INNERMOST loop where the result row is formed.

    Bytecode for `SELECT x,y FROM a, b LIMIT 3 OFFSET 2` (EXPLAIN, turso):
        8 |Rewind|0|17     Rewind a (outer)
        9 |Rewind|1|16     Rewind b (inner)
        10|IfPos|4|16|1    r[4]>0 -> r[4]-=1, goto 16      <-- offset jump
        11|Column|0|0|1    r[1]=a.x
        12|Column|1|0|2    r[2]=b.y
        13|ResultRow|1|2
        14|DecrJumpZero|3|17
        15|Next|1|10       Next b (INNER)  <-- correct offset target
        16|Next|0|9        Next a (OUTER)  <-- where offset WRONGLY jumps
        17|Halt
    The offset IfPos at line 10 targets line 16 (outer table a's Next) instead
    of line 15 (inner table b's Next). Each offset decrement runs Next a +
    Rewind b, throwing away b's remaining rows.

    History: git show 5ff865795fff6240aba07632fdd74e657b80260d (merge of
    a209889b) introduced the `.first()` form to fix an unresolved-label crash
    for hash joins (#6078). git diff bad083fa 5f6098a0 -- body.rs result_row.rs
    is EMPTY, so the reviewed HEAD carries the same defect.

    Differential harness (22 queries) found 10 mismatches, all multi-table
    nested-loop joins with positive OFFSET and no ORDER BY:
    /tmp/claude-0/-home-user-turso/cb07b0ad-0190-5b80-a162-e52287968e66/scratchpad/vw/HL1/diff.py
