# W2FILTER — aggregate FILTER clause differential testing

## Summary: no reproducible divergence found

Target: `agg(x) FILTER (WHERE cond)` in turso (working tree HEAD bad083fa) vs
SQLite 3.45.1. After ~130 hand-built differential cases and ~20,000 generated
fuzz queries, I found **no reproducible wrong-results or crash bug** in the
aggregate FILTER clause. Every value difference observed reduced to
implementation-defined `group_concat` element ordering (see "Non-bugs" below),
which is not FILTER-specific and not a correctness violation.

## What I tested (all matched SQLite exactly)

Aggregates: count(*), count(x), sum, avg, min, max, total, group_concat
(incl. explicit separator), each with FILTER.

Structural coverage, run against BOTH group-by code paths:
- Sorter path (unindexed GROUP BY) and MainLoop path (indexed GROUP BY, no
  sorter) — verified via EXPLAIN that `CREATE INDEX` on the group column
  eliminates SorterOpen and takes the `GroupByRowSource::MainLoop` branch.
- Plain (no GROUP BY), single and multi-column GROUP BY, many groups.
- DISTINCT inside the aggregate combined with FILTER (filter applied before the
  distinct dedup, matching SQLite).
- Multiple aggregates in one query, each with a different FILTER; mixed arity
  (count(*) with 0 args next to sum/group_concat with args) to stress the
  MainLoop `offset += agg.args.len()` register layout.
- FILTER referencing a column NOT used as an aggregate argument (and not in
  GROUP BY / SELECT) — the case the "sorted path" lead warned about; the column
  is carried through the sorter by `collect_agg_leaf_columns` (which walks
  `filter_expr`) and resolved via `expr_to_reg_cache`, consistent with args.
- FILTER with subqueries: non-correlated `IN (SELECT ...)`, correlated
  `IN (SELECT ... WHERE k=t.g)`, correlated/non-correlated scalar subqueries,
  EXISTS / NOT EXISTS, and IN with a complex LHS expression `(a+b) IN (...)`.
- FILTER combined with HAVING and ORDER BY (incl. aggregate-with-FILTER that
  appears only in HAVING or only in ORDER BY, not in the SELECT list), + LIMIT.
- FILTER over JOINs: inner, LEFT (right side NULL), cross; aggregate argument
  and filter drawn from different tables; GROUP BY on either side.
- always-false FILTER (WHERE 0) and always-NULL FILTER (WHERE NULL): count -> 0,
  sum/avg/min/max/group_concat -> NULL, total -> 0.0 (all correct).
- WHERE + FILTER interaction; LIKE / GLOB / BETWEEN / COLLATE NOCASE / CAST
  inside the filter; empty table; all-rows-filtered groups.
- Aggregate results wrapped in scalar exprs (coalesce/abs/+1), compound
  UNION / UNION ALL, and CTEs carrying FILTER aggregates.

Test drivers (kept in scratchpad vw/W2FILTER): t1.py..t6.py (structured),
fuzz.py and fuzz2.py (generative, JOIN + expr-wrap + ORDER BY/LIMIT modes),
diff.py (oracle harness). Fuzz seeds 1-59 across both fuzzers, 0 real findings.

## Code paths audited (explain why it's correct)

- `core/translate/group_by.rs` two grouped agg loops (Sorter ~L760, MainLoop
  ~L812): Sorter path enables `expr_to_reg_cache` mapping sorter leaf columns to
  registers, so `translate_expr(filter_expr)` and the aggregate args both read
  the sorted row's cached values — no read from the exhausted table cursor.
  MainLoop path reads the filter from the live cursor and args from registers,
  but both correspond to the same current row (cursor does not advance between
  the arg capture in `main_loop/body.rs` ~L197 and the AggStep). The specific
  "filter vs registers mismatch" hypothesized by the lead does not occur.
- `core/translate/group_by.rs::collect_agg_leaf_columns` (L354): walks both
  `agg.args` and `agg.filter_expr`, and descends into non-correlated subqueries
  to carry the probe's LHS columns through the sorter (commit 4791151c / #6807),
  so filter columns are never read stale. Confirmed by correlated + IN-subquery
  filters over the sorter path all matching.
- `core/translate/optimizer/mod.rs::detect_simple_aggregate` (L803): the simple
  index-based MIN/MAX fast path (which reads only the first index row and would
  otherwise ignore the FILTER) is correctly disabled when
  `filter_expr.is_some()`. Verified empirically: `min(a) FILTER (WHERE a>5)` etc.
  with an index on the argument return the filtered extremum, not the global one.
- `core/translate/main_loop/body.rs` simple (non-grouped) agg loop (L286): FILTER
  IfNot guard emitted before the AggStep, including before the DISTINCT dedup.

## Non-bugs observed (dismissed with evidence)

`group_concat(x)` without an explicit ORDER BY has implementation-defined element
order. turso sometimes concatenates in index-scan order where SQLite uses
rowid order (and the chosen order can flip depending on the other aggregates /
their filters in the query — a query-planning artifact). The concatenated
multiset is always identical. This surfaced as scalar "value" diffs only when a
group_concat was wrapped in an affinity-applying scalar (e.g.
`(group_concat(b) FILTER(...))+1` -> 53 vs 26, because `+1` takes the leading
token). Not FILTER-specific and not a wrong-result; excluded from the verdict.
Example: `group_concat(b) FILTER (WHERE g<=193)` -> turso `52,25,54,56`,
SQLite `25,52,56,54` (same set {25,52,54,56}).
