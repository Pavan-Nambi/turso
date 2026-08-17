# Turso 6-Month Adversarial Commit Review

Out-of-tree audit artifact (not part of the turso engine). A read-only review of
merged `tursodatabase/turso` PRs from **2026-02-17 .. 2026-08-17** for introduced
correctness and durability regressions.

- **Verified HEAD:** `bad083fa` (fork; 5 trivial commits behind upstream review HEAD `5f6098a0`).
- **Oracle:** SQLite 3.45.1. **Excluded from scope:** postgres, IVM/incremental, MVCC, encryption (reviewed only where they touch shared stable-path code).
- No engine source was modified by this review.

## Result

| Status | Count |
|---|---|
| Confirmed live at HEAD | **35** (5 critical · 6 high · 10 medium · 14 low) |
| Real regression, already fixed upstream | 10 |
| Refuted on verification | 1 |
| Newly discovered this pass | 11 (2 critical · 2 high · 4 medium · 3 low) |

**Top bugs (all silent wrong results / corruption, all live):**
1. `C1` OFFSET over a nested-loop join silently drops/returns wrong rows (pagination over joins). *(new)*
2. `C2` Comparison collation ignores the left operand's column collation — `bincol = nocasecol` uses NOCASE across WHERE/ON/all joins. *(new)*
3. `C3` `jsonb_set` corrupts nested-array documents (ordinary UPDATE persists unreadable JSONB).
4. `C4` ALTER TABLE drops `DESC`/`COLLATE` from UNIQUE → autoindex corruption after reopen.
5. `C5` Partial index drops rows from a LEFT JOIN's preserved side.
6. `H1` GROUP BY sorter elided on a hash-join build side → split groups / wrong counts. *(new)*

## Files

- **`FINAL_REPORT.md`** — the full verified report (start here).
- **`turso-bug-review.html`** — same report as a standalone styled page.
- **`findings-first-pass/`** — the 35 first-pass findings (A08–A19, A23, A32).
- **`findings-new/`** — newly discovered this pass (HL1–HL4 differential hot leads; A40–A44 vdbe/FFI batches; W2CONFLICT/W2FILTER targeted leads).
- **`verify-verdicts/`** — per-finding adversarial verification verdicts (CONFIRMED / FIXED-AT-HEAD / REFUTED) with repro transcripts.

## Method

Every first-pass finding was independently re-verified with a default-refute stance:
read the code at HEAD plus its callers, check whether a later commit fixed it, and —
where SQL-expressible — reproduce live against the SQLite 3.45.1 oracle. New findings
came from differential fuzzing on flagged behavior classes (LIMIT/OFFSET+joins,
collation, multi-index OR, OUTER JOIN, conflict-resolution/triggers) plus fresh review
of never-started batches. All critical/high findings carry a reproduced transcript.
