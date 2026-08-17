# HL4 findings — OUTER JOIN correctness (differential vs SQLite 3.45.1)

Binary tested: /home/user/turso/target/debug/tursodb at working-tree HEAD bad083fa.

## [HL4-1] LEFT/RIGHT/FULL OUTER JOIN uses the wrong collation for `col = col`, producing wrong null-padding
- area: outer join correctness
- at-head: present
- category: sql-semantics
- severity: high
- confidence: high
- description: |
    When an outer-join ON comparison is `left_col = right_col` and NEITHER operand has an
    explicit COLLATE, turso resolves the collating sequence by picking whichever column has a
    NON-binary (explicit) collation, regardless of operand side. SQLite instead gives precedence
    to the LEFT operand's column collation (a column always has one; BINARY by default).
    They diverge exactly when the left column is BINARY (default) and the right column has an
    explicit collation such as NOCASE: SQLite compares with BINARY, turso compares with NOCASE.
    In a LEFT/RIGHT/FULL OUTER JOIN this changes which rows count as matched, so turso emits
    spurious matched rows and DROPS the null-padded rows SQLite produces — i.e. wrong
    null-padding, silently. (The same wrong collation also affects INNER JOIN and a plain
    WHERE cross-join; the correlated scalar-subquery path is NOT affected, so the bug is
    specific to the main query's comparison/join emit path.)
- failure: |
    Schema:
      CREATE TABLE tb(b TEXT);                 -- default BINARY collation
      CREATE TABLE tn(n TEXT COLLATE NOCASE);  -- NOCASE collation
      INSERT INTO tb VALUES ('abc'),('ABC');
      INSERT INTO tn VALUES ('abc');

      SELECT tb.b, tn.n FROM tb LEFT JOIN tn ON tb.b = tn.n ORDER BY tb.b;
        SQLite: ('ABC', NULL), ('abc', 'abc')     -- 'ABC' unmatched under BINARY -> null-padded
        Turso : ('ABC', 'abc'), ('abc', 'abc')    -- WRONG: 'ABC' matched via NOCASE, no null-pad

      SELECT tb.b, tn.n FROM tn RIGHT JOIN tb ON tb.b = tn.n ORDER BY tb.b;
        SQLite: ('ABC', NULL), ('abc', 'abc')
        Turso : ('ABC', 'abc'), ('abc', 'abc')    -- WRONG

      SELECT tb.b, tn.n FROM tb FULL OUTER JOIN tn ON tb.b = tn.n;  (same wrong match/null-pad)

    Reverse operand order is correct because the left column then carries the NOCASE:
      SELECT tb.b FROM tn JOIN tb ON tn.n = tb.b;   -- left = tn.n (NOCASE): both engines NOCASE, OK

    Not limited to `=` — every comparison operator is affected. Range example (same schema):
      SELECT tb.b, tn.n FROM tb LEFT JOIN tn ON tb.b < tn.n ORDER BY tb.b;
        SQLite: ('ABC','abc'), ('abc', NULL)   -- 'ABC' < 'abc' TRUE under BINARY
        Turso : ('ABC', NULL), ('abc', NULL)   -- WRONG: NOCASE makes 'ABC'=='abc', so < is false
      `>=`, `<>`, BETWEEN behave the same way.
- evidence: |
    Manual transcript (both engines, identical schema+data):

      $ tursodb  (LEFT JOIN)            $ sqlite3 / python (LEFT JOIN)
        ABC|abc                           ('ABC', None)
        abc|abc                           ('abc', 'abc')
      $ tursodb  (INNER JOIN)           $ sqlite3 (INNER JOIN)
        ABC|abc                           ('abc', 'abc')
        abc|abc
      $ tursodb (WHERE tb.b=tn.n cross) $ sqlite3
        ABC                               ('abc',)
        abc
      $ tursodb (correlated scalar subq: SELECT tb.b,(SELECT count(*) FROM tn WHERE tb.b=tn.n))
        ABC|0   abc|1   == SQLite  (this path is CORRECT, so bug is main-query emit path only)

    Code path (root cause):
      - core/schema.rs:5379  Column::collation_opt() returns None when the column has no
        EXPLICIT collation (default BINARY) — it cannot distinguish "BINARY column" from
        "no collation".
      - core/translate/collate.rs:495  get_collseq_parts_from_expr_with_symbols() uses
        column.collation_opt(), so a default-BINARY column contributes None.
      - core/translate/expr/binary.rs:449-462 comparison_collation():
            let lhs_collation = get_collseq_from_expr_with_symbols(lhs_expr, ...)?; // None.or(None)=None for a BINARY column
            if lhs_collation.is_some() { return Ok(lhs_collation); }
            return get_collseq_from_expr_with_symbols(rhs_expr, ...);               // None.or(Some(NoCase)) = NoCase
        The BINARY left column is transparent, so resolution falls through to the RHS's
        explicit NOCASE.
      - SQLite's own rule is quoted verbatim in turso's doc comment collate.rs:349:
        "If either operand is a column, then the collating function of that column is used
        with precedence to the left operand." The code violates this doc comment.

    Fix direction: when an operand IS a column reference (Column/RowId, possibly through
    unary + / CAST), it must contribute its collation (BINARY included) at the column-precedence
    step, so a left BINARY column wins over a right explicit collation — matching SQLite and the
    already-correct `resolve_comparison_collseq_with_symbols` ordering intent.

## [HL4-2] FULL OUTER JOIN rejected (misleading error) when the right table has an index on the join column
- area: outer join correctness
- at-head: present
- category: sql-semantics
- severity: medium
- confidence: high
- description: |
    A valid `FULL OUTER JOIN ... ON a=b` is rejected at compile time with the misleading
    message "FULL OUTER JOIN requires an equality condition in the ON clause" whenever the
    right-hand (probe) table has an index / PRIMARY KEY / UNIQUE constraint on the join column.
    SQLite runs the query fine. This is NOT a wrong-results bug (it fails loudly), but it is a
    broad, easily-triggered SQLite incompatibility in the outer-join area: indexing a join key
    is extremely common, so many real schemas cannot use FULL OUTER JOIN at all. The message
    is also wrong — an equality condition IS present.
- failure: |
      CREATE TABLE t1(a); CREATE TABLE t2(c);
      INSERT INTO t1 VALUES (1),(2),(5); INSERT INTO t2 VALUES (2),(3);
      CREATE INDEX i2 ON t2(c);            -- index on the RIGHT table's join column
      SELECT t1.a, t2.c FROM t1 FULL OUTER JOIN t2 ON t1.a = t2.c;
        SQLite: (2,2), (1,NULL), (5,NULL), (NULL,3)
        Turso : Parse error: FULL OUTER JOIN requires an equality condition in the ON clause
    Also triggered by:  t2(c INTEGER PRIMARY KEY),  t2(c UNIQUE),  and  ON t1.rowid = t2.rowid.
    NOT triggered by: no index, index on a non-join column, or an index only on the LEFT table.
- evidence: |
    Trigger matrix (tursodb, in-memory):
      no index                          -> correct rows
      index on right(build) join col    -> Parse error (rejected)
      index right + WHERE / + ORDER BY  -> Parse error
      right col INTEGER PRIMARY KEY      -> Parse error
      right col UNIQUE                   -> Parse error
      index on right NON-join column     -> correct rows
      index only on LEFT table          -> correct rows

    Code path:
      - core/translate/optimizer/join.rs:427  rhs_has_selective_seek becomes true when the
        probe (right) table's chosen access method is a BTreeTable index seek with non-empty
        constraint_refs (the equijoin term seeks the right table's index).
      - join.rs:634  allow_hash_join = !rhs_has_selective_seek && ...  -> false, so the hash
        join is never attempted for this ordering. This "prefer nested-loop seek" heuristic is
        fine for INNER/LEFT (they have a nested-loop fallback) but fatal for FULL OUTER.
      - join.rs:875-891  FULL OUTER has no nested-loop fallback, so the ordering returns
        Ok(None); the FULL-OUTER ordering constraint forbids the reverse order, so no plan is
        found for any ordering.
      - join.rs:1548-1556  the catch-all then emits the misleading "requires an equality
        condition in the ON clause".
    Fix direction: for FULL OUTER (which must use a hash join), do not let rhs_has_selective_seek
    veto allow_hash_join — the selective-seek preference has no valid nested-loop fallback here.
