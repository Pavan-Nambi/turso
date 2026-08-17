## [HL2-1] Hash join ignores left-column collation precedence: applies the RHS column's collation and emits wrong rows
- area: join collation / hash join
- at-head: present
- category: sql-semantics
- severity: high
- confidence: high
- description: |
    In an equijoin `A.x = B.y` where the LEFT column `A.x` has the default
    (implicit) BINARY collation and the RIGHT column `B.y` is declared with a
    non-default collation (COLLATE NOCASE or RTRIM), turso's hash-join path
    applies the RIGHT column's collation instead of BINARY, producing extra
    (spurious) matches. SQLite uses the LEFT column's collation here, per its
    documented rule: "If either operand is a column, then the collating
    function of that column is used with precedence to the left operand." A
    column ALWAYS carries a collation (BINARY by default), so a default-BINARY
    left column must win over a right NOCASE column.

    This is a hash-join vs nested-loop DIVERGENCE (the A20 lead): for the exact
    same query, turso's own nested-loop path returns the correct SQLite answer,
    while its hash-join path is wrong. It is independent of operand order in the
    sense that turso's hash join effectively uses whichever side has an explicit
    (declared) collation, ignoring the "left column wins" tie-break.

    Root cause: the hash-join key collation is computed by
    `resolve_comparison_collseq_with_symbols` (core/translate/collate.rs:446),
    which resolves the pair with
        lhs_explicit.or(rhs_explicit).or(lhs_column).or(rhs_column)
    where per-side column collation comes from `Column::collation_opt()`
    (core/schema.rs:5379), returning `None` for a column with no EXPLICIT
    collation (default BINARY). So a default-BINARY LEFT column contributes
    `None`, and the `.or()` chain falls through to the RIGHT column's collation,
    breaking the left-column precedence. The general/nested-loop comparison path
    (core/translate/expr/binary.rs:133) instead uses `Column::collation()`
    (translator.rs:2311: "a column always needs to have a collation", returns
    BINARY for defaults), which is why only the hash-join path is wrong.
    Introduced by commit aeaec6e4 ("Fix collation with reordered hash joins"),
    which switched hash-join collation resolution to resolve_comparison_collseq.

    Note: hash joins whose build input is MATERIALIZED (a build table shared
    across multiple hash joins / star-probe reuse) happen to resolve correctly;
    the bug reproduces on the common direct 2-table / comma / star-probe hash
    join. Confirmed root cause: declaring the LEFT column explicitly
    `COLLATE BINARY` (so collation_opt() returns Some(Binary)) makes the hash
    join return the correct result, proving the bug is precisely
    collation_opt() returning None for implicit-BINARY columns.
- failure: |
    SELECT a.id, b.id FROM a JOIN b ON a.k = b.k;
    -- a.k is default BINARY, b.k is COLLATE NOCASE
    -- SQLite: uses BINARY (left column) -> 3 rows
    -- turso : uses NOCASE -> 9 rows (via HASH JOIN); turso's own nested-loop
    --         path for the SAME query returns the correct 3 rows.
- evidence: |
    Schema/data:
      CREATE TABLE a(id INTEGER PRIMARY KEY, k TEXT);              -- implicit BINARY
      CREATE TABLE b(id INTEGER PRIMARY KEY, k TEXT COLLATE NOCASE);
      INSERT INTO a VALUES (1,'DEF'),(2,'Abc'),(3,'foo'),(4,'bar'),(5,'x'),(6,'ABC');
      INSERT INTO b VALUES (1,'abc'),(2,'ABC'),(3,'def'),(4,'FOO'),(5,'bar'),(6,'ABC');

    turso (default plan = HASH JOIN b / SCAN a):
      EXPLAIN QUERY PLAN SELECT a.id,b.id FROM a JOIN b ON a.k=b.k;
        1|0|0|HASH JOIN b
        2|0|0|SCAN a
      SELECT a.id,b.id FROM a JOIN b ON a.k=b.k;
        -> 9 rows: (2,1)(6,1)(2,2)(6,2)(1,3)(3,4)(4,5)(2,6)(6,6)   WRONG

    turso (forced NESTED LOOP, same query):
      SELECT a.id,b.id FROM a NOT INDEXED JOIN b NOT INDEXED ON a.k=b.k;
        -> 3 rows: (4,5)(6,2)(6,6)                                  CORRECT

    SQLite 3.45.1:
      SELECT a.id,b.id FROM a JOIN b ON a.k=b.k;  -> [(4,5),(6,2),(6,6)]   (3 rows, BINARY)
      SELECT a.id,b.id FROM a JOIN b ON b.k=a.k;  -> 9 rows (NOCASE, left col b.k)
      (turso's HASH result for a.k=b.k == SQLite's b.k=a.k: hash join applied
       the RHS column's collation regardless of operand order.)

    Minimal repro (1 spurious row):
      CREATE TABLE t1(a TEXT);  CREATE TABLE t2(b TEXT COLLATE NOCASE);
      INSERT INTO t1 VALUES ('x');  INSERT INTO t2 VALUES ('X');
      SELECT t1.a,t2.b FROM t1 JOIN t2 ON t1.a=t2.b;
        SQLite: 0 rows ; turso HASH JOIN: 1 row 'x|X'
      (Declaring t2 col ... ok; declaring t1 col explicitly COLLATE BINARY makes
       turso return 0 rows -> pinpoints collation_opt()==None as the cause.)

    RTRIM variant (same bug, different collation):
      CREATE TABLE l(k TEXT COLLATE RTRIM); CREATE TABLE r(k TEXT);
      SELECT l.k,r.k FROM l JOIN r ON r.k = l.k;   -- r.k binary on LEFT
        SQLite: BINARY -> only exact matches ; turso: RTRIM -> spurious matches

    LEFT JOIN variant (changes OUTPUT VALUES, not just row count):
      CREATE TABLE big(k TEXT); CREATE TABLE nc(k TEXT COLLATE NOCASE);
      -- big rows that should be NULL-extended instead get wrongly matched:
      SELECT big.k, nc.k FROM big LEFT JOIN nc ON big.k = nc.k;
        SQLite:  'alice|'      (NULL, no binary match)
        turso :  'alice|Alice' (wrongly matched NOCASE)  <-- silent value change

    Comma-join / WHERE form (not ON-clause-specific): same divergence for
      SELECT big.k,nc.k FROM big, nc WHERE big.k = nc.k;

    Fuzzing (random schemas, mixed-case data, 2- and 3-table, single/multi-col):
      - 200-seed x6-query and 400-seed x5-query sweeps: every divergence is this
        same over-matching root cause; multi-col inflates further (both keys
        wrongly non-binary). The 19 "missing-row" LEFT JOIN cases are the same
        bug (a wrongly-matched row replaces its NULL-extended row).
      - Pure integer-key multiplicity/cross-product sweep (500 seeds x5 queries,
        many-to-many, 3-way chain/star, LEFT JOIN): 0 diffs. So hash-join
        cardinality (the 3e1429a3 area) is correct at HEAD; collation is the
        remaining hash-join correctness gap.
      - Affinity (INTEGER/REAL vs TEXT keys) and NULL / IS handling in hash
        joins: correct (no diffs).

    Code path:
      core/translate/main_loop/hash.rs:124-147  builds `collations` via
        resolve_comparison_collseq_with_symbols(original_lhs, original_rhs, ...)
      core/translate/collate.rs:446-461  the buggy `.or()` chain
      core/translate/collate.rs:494-495  maybe_column_collseq = column.collation_opt()
      core/schema.rs:5379-5385  collation_opt() returns None when no explicit collation
      (correct counterpart: core/translate/expr/translator.rs:2311 uses .collation())
