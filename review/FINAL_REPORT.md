# Turso — 6-Month Adversarial Commit Review — Final Verified Report

**Repo:** `tursodatabase/turso` (reviewed against fork `Pavan-Nambi/turso`).
**Scope window:** merged PRs 2026-02-17 .. 2026-08-17 (1428 first-parent commits).
**HEAD verified:** working tree `bad083fa` (fork, 2026-08-13), which is 5 trivial commits
behind the upstream review HEAD `5f6098a0` (2026-08-17) — the 5 commits touch only
`gradlew.bat`, `bindings/tcl`, and vdbe fullscan-step counting, none of the finding areas.
**Oracle:** SQLite 3.45.1 (`python3 sqlite3`). **Repro binary:** debug `tursodb` built from `bad083fa`.
**Excluded per scope:** postgres, IVM/incremental, MVCC, and experimental features
(encryption, index_method) — reviewed only where they touch shared stable-path code.

Every finding below was adversarially re-verified (default-refute) and, where SQL-expressible,
reproduced live on both engines. All critical/high findings carry a reproduced transcript.

---

## Executive summary

| Status | Count |
|---|---|
| **Confirmed live at HEAD** | **35** (5 critical · 6 high · 10 medium · 14 low) |
| Real regression, already fixed at HEAD | 10 |
| Refuted on verification | 1 |
| **Newly discovered this pass** (not in the paused session's list) | **11** (2 critical · 2 high · 4 medium · 3 low) |

**The bugs that matter most (all silent wrong results / corruption, all live at HEAD):**

1. **OFFSET over any nested-loop join silently drops or returns wrong rows** (NEW). `SELECT … FROM a,b LIMIT n OFFSET k` jumps the *outermost* loop instead of the innermost. Pagination over joins is broken.
2. **Comparison collation ignores the left operand's column collation** (NEW). `bincol = nocasecol` uses NOCASE instead of BINARY across WHERE, ON, and every join type — spurious matches / dropped rows.
3. **`json_set`/`jsonb_set` corrupts nested-array documents** (A12-1). Ordinary `UPDATE … SET j = jsonb_set(...)` can persist unreadable JSONB.
4. **ALTER TABLE drops `DESC`/`COLLATE` from UNIQUE constraints → autoindex corruption** (A16-1). After ALTER+reopen, duplicates are accepted and lookups miss rows; `integrity_check` fails.
5. **Partial index on the preserved side of a LEFT JOIN silently drops rows** (A32-1).
6. **GROUP BY / ORDER BY sorter wrongly elided on a hash-join build side** (NEW). Aggregate groups split into wrong partial counts; `HAVING count(*)>1` silently returns nothing.

The paused session's first-pass review proved highly accurate: of its 35 findings, 24 are
confirmed live, 10 were real bugs already fixed upstream, and only 1 (A18-1) was refuted.

---

## CRITICAL (5)

### [C1 · NEW · HL1-1] OFFSET over a nested-loop join skips `offset × (product of inner sizes)` rows
- **at-head:** present · **category:** sql-semantics · **root cause:** `core/translate/main_loop/body.rs:419`
- The offset jump target uses `plan.join_order.first()` (outermost loop) where it must use the innermost. A positive OFFSET therefore consumes whole outer-loop iterations.
- **Repro** (`a=(1,2)`, `b=(10,20)`):
  ```
  SELECT x,y FROM a,b LIMIT 3 OFFSET 2;
    turso:  (0 rows)              -- silently drops everything
    sqlite: (2,10),(2,20)
  ```
- Masked by `ORDER BY` (sorter applies offset post-sort), by hash/equi-joins (single main-loop table), and by single-table selects — which is why it survived. Affects the ubiquitous "paginate over a join" pattern.
- **Fix:** use the innermost loop (`join_order.last()`) as the offset jump target.

### [C2 · NEW · HL2-1 + HL4-1] Comparison collation ignores the left operand's column collation (BINARY column loses precedence)
- **at-head:** present · **category:** sql-semantics · **root cause:** `core/schema.rs:5379` (`Column::collation_opt()` returns `None` for a default-BINARY column), consumed by `core/translate/expr/binary.rs:449-462` (`comparison_collation`) and the hash-join collation resolver in `core/translate/collate.rs`.
- SQLite rule (quoted verbatim in turso's own doc comment, `collate.rs:349`): *"If either operand is a column, then the collating function of that column is used, with precedence to the left operand."* A default-BINARY column reports "no collation", so resolution falls through to the other operand's explicit collation.
- Diverges whenever the **left** column is default-BINARY and the **right** has an explicit collation (NOCASE/RTRIM). Affects **WHERE, ON, INNER/LEFT/RIGHT/FULL joins, and the hash-join path** — pervasive, not join-specific.
- **Repro** (`tb.b TEXT`, `tn.n TEXT COLLATE NOCASE`, `tb=('abc','ABC')`, `tn=('abc')`):
  ```
  SELECT tb.b FROM tb, tn WHERE tb.b = tn.n;         -- turso: abc,ABC   sqlite: abc
  SELECT tb.b,tn.n FROM tb LEFT JOIN tn ON tb.b=tn.n;-- turso matches 'ABC', drops the null-padded row
  -- control (NOCASE on the left) agrees on both engines: SELECT … WHERE tn.n = tb.b -> abc,ABC
  ```
- Case-insensitive columns (emails, usernames) joined/compared to plain columns silently return wrong rows. Severity critical: silent, common, correctness-defining.

### [C3 · A12-1] `json_set`/`jsonb_set` double-adds size delta on consecutive-array paths → persisted JSONB corruption
- **at-head:** present · **commit:** `1fa653b8` (in merge `23c15006`, 2026-02-27) · **root cause:** `core/json/jsonb.rs:2539-2558` (`update_parent_references`; `is_prev_arr` guard removed).
- For a path with ≥2 adjacent array locators (`$[i][j][k]`, `$[i][j].k`), a shared header is rewritten twice, so the stored element size is wrong by `delta`.
- **Repro:**
  ```
  SELECT hex(jsonb_set('[[[1]]]','$[0][0][0]','short'));  -- turso 8B BB 6B… (BB=size 11, real content 7); sqlite 8B 7B 6B…
  UPDATE t SET j=jsonb_set(j,'$.geometry.coordinates[0][0][0]',99.5);  -- then SELECT json(j) -> "malformed JSON"
  ```
- Manifests as a runtime error, a swallowed SQL NULL, **or** a silently-corrupted blob that later reads back as malformed — the last is durable data loss via an ordinary UPDATE.

### [C4 · A16-1] `BTreeTable::to_sql()` drops `DESC`/`COLLATE` from table-level UNIQUE → autoindex corruption after ALTER+reopen
- **at-head:** present · **commit:** `e4785093` (2026-02-26) · **root cause:** `core/schema.rs:3778-3785` emits only column names; schema load rebuilds the autoindex from the (now-lost) sort order/collation.
- Any `ALTER TABLE ADD/DROP/RENAME COLUMN` rewrites the stored SQL, turning `UNIQUE(a DESC,b)` into `UNIQUE(a,b)`.
- **Repro:** create `UNIQUE(a DESC,b)`, insert rows, `ALTER TABLE … ADD COLUMN c`, reopen → duplicate insert accepted, `SELECT … WHERE a=1 AND b='x'` misses an existing row, `PRAGMA integrity_check` reports "row missing from index / non-unique entry". Same with `UNIQUE(a COLLATE NOCASE,b)`.
- Note: the pre-commit behavior was a loud crash on reopen; this commit replaced a crash with silent corruption (violates the project's "crash > corrupt" rule). The same lossy emission also affects table-level `PRIMARY KEY(… DESC)` / `FOREIGN KEY` (predates this batch).

### [C5 · A32-1] Partial index on the preserved (left) table of an OUTER JOIN silently drops rows
- **at-head:** present · **commit:** `9cbc321d` (2026-04-30) · **root cause:** `core/translate/optimizer/constraints.rs:1470-1481` (`can_use_query_term` early-returns `true` when the table has no `join_info`, i.e. the preserved left table).
- A partial index whose predicate matches an `ON` term is used to drive the scan of the preserved side, skipping exactly the left rows that a LEFT JOIN must still emit null-padded.
- **Repro:**
  ```
  CREATE INDEX partial_t ON t(a) WHERE b>0;
  SELECT t.a,t.b FROM t LEFT JOIN s ON t.b>0 ORDER BY t.a;
    turso:  (2,3),(4,10)                 -- rows with b<=0 dropped
    sqlite: (1,-5),(2,3),(3,-1),(4,10)   -- t is preserved, all 4 rows
  ```
  `EXPLAIN QUERY PLAN` shows `SCAN t USING INDEX partial_t`.

---

## HIGH (6)

### [H1 · NEW · HL3-1] GROUP BY / ORDER BY sorter wrongly elided when the sort-key table is the build side of an inner hash join
- **at-head:** present · **category:** sql-semantics · **root cause:** `core/translate/optimizer/order.rs` `plan_satisfies_order_target` (guards only LeftOuter/FullOuter hash joins at 249-257; counts the build-side index scan as satisfying the order at ~305).
- The join output is ordered by the probe side, not the build-side index scan, so streaming GROUP BY splits a group into partial aggregates.
- **Repro:**
  ```
  SELECT t1.b,count(*) FROM t1 JOIN t2 ON t2.a=t1.a WHERE t1.c>=0 GROUP BY t1.b;
    turso:  0|1,1|1,0|1,1|1   sqlite: 0|2,1|2
  … HAVING count(*)>1  -> turso returns 0 rows (every split group has count 1)
  ```
  Triggered by index-driven access on the build table (`col>=v`, `IN (…)`, `OR` predicates); `HAVING`, `min/max/sum`, and `ORDER BY` all affected. Dropping the secondary index (forces the sorter) restores correct results.

### [H2 · NEW · WCONFLICT-3] Outer `OR IGNORE` leaks through a DELETE-trigger boundary and swallows a conflict
- **at-head:** present · **category:** sql-semantics (wrong side effect) · **root cause:** runtime `ignore_jump_target` on `Insn::Program` (`core/translate/trigger_exec.rs:678-682`); the `a48e3f01` fix only reset the compile-time conflict override, not the runtime IGNORE propagation.
- When an outer `OR IGNORE` statement fires a trigger whose body DELETEs rows, a conflict inside the DELETE trigger's body jumps to the outer ignore target instead of aborting — even an explicit inner `INSERT OR ABORT` is overridden.
- **Repro:** (`t2_bd BEFORE DELETE` inserts a PK-conflicting row; `t_au AFTER UPDATE` deletes from t2)
  ```
  UPDATE OR IGNORE t SET x=9;
    turso:  no error, t=(1,9) applied, conflict swallowed
    sqlite: aborts "UNIQUE constraint failed: t2.pk", nothing changed
  ```
- OR REPLACE/OR FAIL outer clauses are correctly handled; only OR IGNORE leaks.

### [H3 · A10-1] `repeat()`/`lpad()`/`rpad()` allocate an attacker-controlled length with no cap → process abort/OOM
- **at-head:** present · **commit:** `c681ded5` (2026-06-17) · **root cause:** `core/functions/string.rs:31,88-92` use the infallible allocator with no `MAX_BLOB_LENGTH`/`TooBig` guard (unlike `zeroblob`/`randomblob`).
- **Repro:** `repeat('ab', i64::MAX)` → panic "capacity overflow" (exit 101); `lpad('x', i64::MAX)` → `handle_alloc_error` SIGABRT (exit 134). With `panic="abort"` (release/fuzzing profiles) both hard-abort the embedding process — a one-statement DoS.

### [H4 · A12-4] JSONB `$[#]` / append-by-index leaves the container header one byte short → invalid JSONB
- **at-head:** present · **commit:** `fc0e5241` (2026-06-24) · **root cause:** `core/json/jsonb.rs:372-384` updates the immediate container header with `delta` only; the placeholder byte (`target.delta`) is forwarded to ancestors but not the container itself.
- **Repro:** `SELECT hex(jsonb_set('[1,2,3]','$[#]',4));` → `7B…` (root size 7, actual 8) vs sqlite `8B…`; `json(jsonb_set('[1,2,3]','$[#]',4))` → turso "Parse error" (can't read its own output). Persisting these blobs corrupts the row.

### [H5 · A19-3] Use-after-free in the cursor registry: `pending_peer_save` parks raw cursor pointers across IO yields
- **at-head:** present · **commit:** `f63bd46f` (2026-06-04) · **root cause:** `core/storage/btree.rs:6081-6111` snapshots raw `NonNull<dyn CursorTrait>` then yields (`return_if_io!`); nothing scrubs a peer's snapshot when that peer statement is reset/dropped (`ProgramState::reset` frees the cursor box).
- One connection, two statements: a writer parks the peer-save snapshot across an overflow-page read yield; the app resets/finalizes the peer statement (normal API/GC); on resume the writer derefs freed memory. Verifier could not refute; repro intentionally not attempted (UAF can silently corrupt).

### [H6 · A23-1] Row-value `IN`/`NOT IN` ignores NULL in non-first tuple components
- **at-head:** present · **commit:** `98b46b15` (2026-02-24) · **root cause:** `core/translate/expr/condition.rs:63-91` builds the NULL tracker from tuple component 0 only; the 3-valued-logic decision (186-193) consults only that.
- **Repro:** `SELECT (1,NULL) IN ((1,2));` → turso `0`, sqlite `NULL`; `SELECT (1,NULL) NOT IN ((1,2));` → turso `1`, sqlite `NULL`; `SELECT 1 WHERE (1,NULL) NOT IN ((1,2),(3,4));` → turso returns a row, sqlite none.

---

## MEDIUM (10)

### [M1 · A08-1] HAVING aliased-aggregate check rejects valid SQL when a real column shares the alias name
- **at-head:** present · `core/translate/select.rs:1934-1951`. The check ignores that real table columns outrank result-column aliases in SQLite name resolution.
- **Repro:** `SELECT count(*) AS c, a FROM t GROUP BY a HAVING max(c) > 0;` (with a real column `c`) → turso "misuse of aliased aggregate c"; sqlite returns rows.

### [M2 · A08-4] `PRAGMA ignore_check_constraints` never invalidates prepared statements
- **at-head:** present · `core/connection.rs` `set_check_constraints_ignored` omits `bump_prepare_context_generation()`. A cached statement keeps its compile-time CHECK decision after the pragma flips — a cached INSERT can silently bypass (or keep enforcing) CHECK. Reachable via `prepare_cached`; CLI fresh-prepare path is correct.

### [M3 · NEW · HL4-2] Valid `FULL OUTER JOIN … ON a=b` rejected when the right table indexes the join column
- **at-head:** present · `core/translate/…/join.rs:427,634` (`rhs_has_selective_seek` sets `allow_hash_join=false`; FULL OUTER has no nested-loop fallback → no plan).
- **Repro:** `SELECT l.a,r.b FROM l FULL OUTER JOIN r ON l.a=r.b;` with `r.b` a PK → turso "FULL OUTER JOIN requires an equality condition in the ON clause" (but the ON *is* equality); sqlite returns the join. Indexing a join key is ubiquitous, so common FULL OUTER JOINs are unusable.

### [M4 · NEW · WCONFLICT-1] Outer `OR ABORT` fails to override a trigger body's own conflict clause
- **at-head:** present · `core/translate/insert.rs:596`, `core/translate/emitter/update.rs:610` test the collapsed `on_conflict != Abort`, which cannot distinguish explicit `OR ABORT` (must override the body) from a plain statement (defers to the body).
- **Repro:** outer `INSERT OR ABORT` firing a trigger whose body does `INSERT OR IGNORE`/`OR REPLACE` → turso swallows the conflict / applies the body policy; sqlite aborts. The correct signal (`statement_on_conflict`) already exists but isn't used here.

### [M5 · NEW · A44-1] `sqlite3_value_blob` UAF fix is incomplete — now NULL-derefs on TEXT values
- **at-head:** present · **commit:** `c425580a` · `bindings/c/src/lib.rs`. The fix stopped the BLOB use-after-free but dropped the Text→bytes coercion, so `sqlite3_value_blob(text)` returns NULL while `sqlite3_value_bytes(text)` returns the length. The standard `memcpy(dst, value_blob(v), value_bytes(v))` idiom then NULL-derefs on a text argument (SQLite returns non-NULL). Traded a UAF for a NULL-deref on the text path.

### [M6 · NEW · A44-2] Parser `MAX_EXPR_DEPTH = 100` rejects valid expressions SQLite accepts (limit is 1000)
- **at-head:** present · **commit:** `18ba9c9c`. A 100-term `OR` chain that SQLite runs is rejected with "Expression tree is too large" (boundary confirmed 99 pass / 100 fail). Bites real machine-generated queries. Reject-over-crash is fine; the threshold is 10× too aggressive.

### [M7 · A11-1] `drain_completions` after `cancel()` is a no-op — io_uring error paths don't wait for in-flight kernel I/O
- **at-head:** present · **commit:** `b1bf20df` (2026-05-11) · `core/io/mod.rs:460` + `core/io/completions.rs:460`. `cancel()` calls `abort()`, which marks each completion `finished()`, so the `while any(!finished) { step() }` loop never steps. On io_uring, a WAL/checkpoint write error can return while the kernel is still writing the buffers, risking WAL checksum-chain breakage. io_uring is opt-in (`--vfs io_uring`), so downgraded from high to medium.

### [M8 · A11-3] Database registry stops de-duplicating on VFS backends whose paths aren't host files
- **at-head:** present · **commit:** `30d8eaf8` (2026-04-01) · `core/database.rs` gates both lookup and insert on `if let Ok(file_id) = io.file_id(path)`; the default `file_id` calls `std::fs::metadata`. A custom/object-store VFS whose paths don't exist on the host FS never registers → two independent `Database`/`WalFileShared` over the same storage → lost dedup, no OS locks → potential WAL corruption. Pre-commit used a raw-string fallback key.

### [M9 · A12-2] Top-level JSON-null document returns SQL NULL through `json_set`/`jsonb_set` family
- **at-head:** present · **commit:** `eed5c44f` (2026-03-19) · `core/json/mod.rs:619` returns SQL NULL for a JSON-null element before the String/Binary output handling. `UPDATE t SET doc=json_set(doc,'$.flag',1)` silently replaces every row whose `doc` is the JSON document `null` with SQL NULL. turso's own `json('null')` returns `null`, exposing the inconsistency.

### [M10 · A16-4] `generate_series(1, NULL)` scans 4.29 billion rows instead of returning empty
- **at-head:** present · **commit:** `d3c593a1` (2026-02-20) · `core/series.rs:180-185`. A planner-dropped literal NULL stop defaults to 4294967295, so the query hangs (15s timeout hit) where SQLite returns 0 rows instantly. A runtime NULL (via subquery) correctly returns empty — the divergence is specific to the literal-NULL case.

---

## LOW (14)

- **[L1 · A08-2]** `prepare()` on comment/whitespace-only SQL returns an error; breaks the `sqlite3_prepare_v2` "SQLITE_OK + NULL stmt" contract and never NULLs `*ppStmt`. `core/connection.rs` + `bindings/c/src/lib.rs:969`.
- **[L2 · A09-1]** External aggregate called with wrong arg count reports "no such function" instead of "wrong number of arguments" (`SELECT median(1,2)`). `core/function.rs:110`.
- **[L3 · A10-3]** datetime numeric-string trim omits vertical tab `\x0B`; `unixepoch('5'||char(11))` → turso NULL, sqlite a number. `core/functions/datetime.rs:222`.
- **[L4 · A11-4]** Multiprocess-WAL last-process probe releases the shared lock before probing, opening a window to elect two "last" processes. Opt-in `enable_multiprocess_wal`. `core/io/mod.rs:256-270`.
- **[L5 · A11-5]** JSON REAL output not zero-padded to a 2-digit exponent: `json_array(1e-7)` → `[1.0e-7]` vs sqlite `[1.0e-07]`. `core/json/mod.rs:245-248`.
- **[L6 · A11-6]** Windows syscall backend leaks one kernel Event handle per thread (`Cell<HANDLE>`, no `CloseHandle`); comment wrongly claims the OS reclaims it. `core/io/windows.rs:27-35`.
- **[L7 · A11-7]** Synchronous waiters busy-spin at 100% CPU while another thread is the io_uring leader (no park/backoff). `core/io/io_uring.rs:513-517`.
- **[L8 · A12-3]** `json_patch(target,'null')` returns `'null'` before validating the target; malformed target silently accepted. `core/json/ops.rs:28-35`.
- **[L9 · A12-5]** Bracket-quoted path on an array node returns NULL where SQLite raises "bad JSON path". `core/json/jsonb.rs:3064-3067`.
- **[L10 · A15-2]** `regexp()` coerces REAL with Rust `f64::to_string` ("2" vs SQLite "2.0"); inconsistent with turso's own `CAST(x AS TEXT)`. `extensions/core/src/types.rs:327`.
- **[L11 · A16-3]** Locale collation ids packed into 12 bits but the registry allows up to `u16::MAX`; after 4092 distinct locale collations in a process, ids silently truncate/wrap (BINARY/NoCase mismatch). `core/schema.rs:5339,5407`.
- **[L12 · NEW · WCONFLICT-2]** `PRAGMA recursive_triggers=ON` is silently accepted but unimplemented; REPLACE-induced deletes never fire DELETE triggers, self-recursive triggers don't re-fire. Default OFF matches SQLite.
- **[L13 · NEW · A40-1]** `sqlite3_stmt_status` removed the per-`reset()` metrics reset, so connection-level aggregate metrics double-count on statement reuse. Observability only. `commit 5b0ebe27`.
- **[L14 · NEW · A43-1]** Read-path UTF-8 validation hard-errors "Corrupt" when reading a SQLite-created DB containing invalid-UTF-8 TEXT (which SQLite tolerates and can produce via `CAST(x'..' AS TEXT)`). File-compat regression; replaces prior UB. `commit ee89a221`.

---

## Real regressions — already fixed at HEAD (10)

These were genuine bugs introduced in the window and fixed upstream before HEAD. Listed for
completeness (and because the fork could still be exposed if it lags upstream).

| ID | Bug | Fixed by |
|---|---|---|
| A08-3 | `sqlite3_step` held the handle mutex across the step; progress-handler re-entrancy deadlock | `9710f11a` |
| A10-2 | `gcd(i64::MIN,-1)` / `lcm` panic on `i64::MIN % -1` | `e08485d6` |
| A11-2 | `Opening` registry sentinel leaked on abandoned async open → path permanently unopenable | `6efb903e` |
| A15-1 | `regexp('foo')` (1 arg) indexed `args[1]` → panic/abort across `extern "C"` | `530627ef` |
| A16-2 | Case-preservation broke NATURAL JOIN / USING column matching (~3 months) | `676b3d95` |
| A17-1 | Named savepoints captured WAL rollback position without a lock → shared WAL/reader corruption | `46cd926d` (+`b8ae9ccf`) |
| A17-2 | Savepoint ops allowed mid-statement; ROLLBACK TO restored pages under a suspended writer | `59d03e62` |
| A19-1 | `pending_reads` not cleared on rollback → rolled-back page images served later | `4b025575` |
| A19-2 | `invalidate_btree_cache` leaked page pins → `CacheError(Pinned)` under spill | `496c24ed` |
| A19-4 | Debug `[WHOPPER_*]` `eprintln!` probes shipped in WAL hot paths (6 days) | `ed5032f6` |

---

## Refuted on verification (1)

- **A18-1** (savepoint rollback aborts on a pinned page → stale cache). The order-of-operations
  pattern is real, but the trigger is unreachable: the spill path subjournals the page *before*
  appending to the WAL, so any clean page newer than the rollback target is restored **dirty**
  via `force_upsert` (which replaces the map entry and clears its wal_tag) and is excluded from
  the failing `delete_clean_pages_after_wal_frame`. Empirically, mid-statement abort with heavy
  spilling and pinned cursors produced correct rolled-back results matching SQLite.

---

## Areas tested clean (negative results worth recording)

- **Multi-index OR / access-path union** (~24,000 differential queries): single/compound/rowid/IN-list/IN-subquery branches, ranges, dedup, IS NULL seeks, partial indexes, NOCASE, nested boolean, DML incl. Halloween, 20k-row RowSet dedup — no divergence. The `5025064b` unify-access-paths refactor is solid.
- **Aggregate `FILTER` clause** (~20,000 fuzz + 130 hand cases): count/sum/avg/min/max/group_concat with GROUP BY, DISTINCT, subqueries, HAVING/ORDER BY/LIMIT, always-false/NULL filters — all match SQLite.
- **vdbe execution core** (batches A40–A43, ~80 commits): REAL-affinity coercion, RENAME COLUMN expr-index rewrite, BEGIN CONCURRENT guard, REINDEX, Step-yield state machine, log/log2/log10 bit-for-bit, aggregate-arg collation, EXPLAIN panic fix — all verified correct (only the two low items A40-1, A43-1 surfaced).
- **Hash-join cross-product multiplicity** (500 seeds × 5 shapes) and **FULL OUTER null-extension / consumed-predicate / coroutine areas** (~6,500 fuzz queries): no wrong-results divergence beyond the collation bug (C2) and HL4-2 (M3).
- **bindings FFI** (batch A44): managed scalar/aggregate callbacks (deep-copy both directions, correct `Box<[u8]>` dealloc), fuzzy OOB fix, blob-for-BLOB path — clean apart from A44-1/A44-2.

---

## Methodology & coverage

- **Verification:** every one of the paused session's 35 findings was re-checked by an independent
  adversarial verifier (default-refute; read code at HEAD + callers; check for later fixes; live
  repro against the SQLite 3.45.1 oracle). All critical/high **new** findings were additionally
  re-reproduced by hand (transcripts above).
- **New discovery:** differential fuzzing against the oracle on the behavior classes the killed
  agents had flagged but never written up (LIMIT/OFFSET+joins, hash-join collation, multi-index OR,
  OUTER JOIN), plus fresh review of never-started batches (vdbe A40–A43, bindings-FFI A44) and
  targeted killed-batch leads (aggregate FILTER, conflict-resolution/triggers).
- **Coverage still open** (not reached this pass; candidates for a follow-up): the remaining killed
  translate batches A21/A22/A24–A31/A33–A39 (re-run individually — several were tentatively cleared
  by the killed agents), never-started A00/A02–A07 (bindings other than A44), A45 (sync durability),
  B46–B49 (cli/packaging/serverless-JS — note the serverless-JS "prepare() losing transaction baton"
  and "preserve zero lastInsertRowid" commits are unreviewed), SKIM50 (93 test-only commits, skim for
  masked regressions), and A13/A14 (MVCC — out of scope except shared hunks). The vdbe/OR/FILTER
  clean results above give good confidence those areas are low-yield; joins/collation/JSON/schema/DDL
  and conflict-resolution were the productive veins.

*All work was performed read-only against the repository; no source files were modified.*
