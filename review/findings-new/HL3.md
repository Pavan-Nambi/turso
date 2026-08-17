# HL3 — multi-index OR / access-path differential testing

## [HL3-1] GROUP BY / ORDER BY sorter wrongly elided when the sort-key table is the build side of an INNER hash join
- area: access-path selection (ordering optimization) / hash join — surfaced while fuzzing OR predicates
- at-head: present (bad083fa)
- category: sql-semantics
- severity: high
- confidence: high
- description: >
    When turso can serve a query's GROUP BY / ORDER BY from a secondary index on
    the grouping/ordering column, it drops the sorter and relies on the streaming
    (already-sorted) input. That reasoning is wrong when the grouped table becomes
    the BUILD side of an INNER hash join: the join output is ordered by the PROBE
    side, not by the build-side index scan, so the streaming GROUP BY sees the
    grouping key out of order and SPLITS a single group into several. Results are
    wrong values (not just wrong order): a group is emitted multiple times with
    partial aggregates. With ORDER BY the rows come back unsorted; with
    `HAVING count(*) > 1` every split group fails the predicate and the query
    silently returns ZERO rows.
    turso already guards this for LEFT/FULL outer hash joins
    (core/translate/optimizer/order.rs:249-257) but not for inner hash joins whose
    ordered table is on the build side.
    OR predicates are one trigger (they steer the optimizer to the index scan on
    the build-side table); simple `col >= v` / `col IN (...)` filters trigger it
    too. A plain rowid filter (`id > 0`) does not, because turso then scans via
    the rowid rather than the secondary index and keeps the sorter.
- failure: |
    Schema:
      CREATE TABLE t1(id INTEGER PRIMARY KEY, a, b, c);
      CREATE INDEX t1b ON t1(b);
      INSERT INTO t1 VALUES(1,10,0,0),(2,20,1,9);
      CREATE TABLE t2(id INTEGER PRIMARY KEY, a);
      INSERT INTO t2 VALUES(1,10),(2,20),(3,10),(4,20);

    Query:
      SELECT t1.b, count(*) FROM t1 JOIN t2 ON t2.a=t1.a
      WHERE t1.c >= 0 GROUP BY t1.b;

    turso  : 0|1 / 0|1 / 1|1 / 1|1     (group b=0 and b=1 each split into two rows)
    sqlite : 0|2 / 1|2                 (correct)

    OR forms of the same bug (HL3 focus):
      ... WHERE (t1.a=20 OR t1.c=0)  GROUP BY t1.b   -> turso 0|1,0|1,1|1,1|1
      ... WHERE t1.a=10 OR t1.a=20   GROUP BY t1.b   -> turso 0|1,0|1,1|1,1|1
      ... WHERE t1.c<5 OR t1.c>=5    GROUP BY t1.b   -> turso 0|1,0|1,1|1,1|1
- evidence: |
    Reproduced with target/debug/tursodb (HEAD bad083fa) vs SQLite 3.45.1.

    GROUP BY (wrong aggregate values):
      SELECT t1.b,count(*) FROM t1 JOIN t2 ON t2.a=t1.a WHERE t1.c>=0 GROUP BY t1.b;
        turso  = ['0|1', '0|1', '1|1', '1|1']
        sqlite = ['0|2', '1|2']
      EXPLAIN QUERY PLAN:
        --HASH JOIN t2
        `--SCAN t1 USING INDEX t1b          <-- no "USE SORTER FOR GROUP BY"

    ORDER BY (wrong row order — same root cause):
      SELECT t1.id,t1.b FROM t1 JOIN t2 ON t2.a=t1.a WHERE t1.c>=0 ORDER BY t1.b;
        turso  = ['1|5','2|1','1|5','2|1']   (b = 5,1,5,1 — unsorted)
        sqlite = ['2|1','2|1','1|5','1|5']   (b = 1,1,5,5)

    HAVING (silent total row loss):
      SELECT t1.b,count(*) ... WHERE t1.c>=0 GROUP BY t1.b HAVING count(*)>1;
        turso  = []            (every split group has count 1)
        sqlite = ['0|2','1|2']

    MIN/MAX/SUM equally wrong:
      SELECT t1.b,sum(t2.id),min(t2.id),max(t2.id) ... GROUP BY t1.b;
        turso  = ['0|1|1|1','0|3|3|3','1|2|2|2','1|4|4|4']
        sqlite = ['0|4|1|3','1|6|2|4']

    Isolation / root cause:
      - Drop INDEX t1b  -> plan becomes "...SCAN t1 / USE SORTER FOR GROUP BY" -> CORRECT (0|2,1|2).
      - Non-join control "SELECT b,count(*) FROM t1 WHERE c>=0 GROUP BY b" -> CORRECT
        (t1 is the driver there, so the t1b scan order really is the output order).
      - `WHERE t1.id>0` (rowid access, keeps sorter) -> CORRECT; `WHERE t1.c>=0`/`IN`/OR -> WRONG.
      - INNER JOIN -> WRONG; `t1 LEFT JOIN t2` -> CORRECT (caught by the outer-hash-join
        guard at core/translate/optimizer/order.rs:249-257).
      Deterministic across repeated runs.

    Code path: core/translate/optimizer/order.rs `plan_satisfies_order_target`.
    Lines 249-257 reject order satisfaction only for HashJoinType::LeftOuter/FullOuter.
    For an inner hash join it then walks each table (lines 262-382) and counts the
    build-side table's BTreeTable index scan (btree_access_order_consumed, line 305)
    as satisfying the ORDER/GROUP target — but the build side's scan order is not
    preserved through the probe-driven output, so the sorter is dropped incorrectly.

---

## Scope note: the multi-index OR path itself tested clean
Roughly 24,000 differential queries (turso HEAD vs SQLite 3.45.1, sorted full-row
comparison to catch dropped AND duplicated rows) exercised the multi-index OR /
access-path machinery with no divergence:
- SELECT multi-index OR: single/compound/rowid/IN-list/IN-subquery branches,
  ranges (`a<x OR a>y`), heavy-overlap dedup, IS/IS NULL seeks, partial indexes
  (used and correctly rejected), NOCASE collation, nested `(AND)OR(AND)`, 5-way OR,
  pre/post residual filters, OR as the inner loop of a join (per-outer-row re-init),
  large-scale RowSet dedup (20k rows, sum(id) checksum verified).
- DML with multi-index OR: 1,500 DELETE/UPDATE (incl. Halloween `SET c=c+10`).
- InSeek primary access: duplicate/NULL/mixed-type IN lists, rowid IN, empty subquery.
- Broad single-index paths, multi-table LEFT/INNER joins with OR in ON and
  skip-level references, and ANALYZE-driven plans (ANALYZE makes turso rarely
  pick multi-index OR).
The only failures found were the ordering-elision bug above (HL3-1), which is an
access-path bug but not in the OR-union machinery proper.
