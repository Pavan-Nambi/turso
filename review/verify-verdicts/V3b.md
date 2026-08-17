## VERDICT [A11-5] JSON REAL output diverges from SQLite for single-digit negative exponents (`1.0e-7` vs `1.0e-07`)
- verdict: CONFIRMED
- severity: low
- repro: yes (transcript below)
- reasoning: Reproduced live on both engines. `core/json/mod.rs:245-248` (identical at working tree and reviewed HEAD `5f6098a0`) appends the ryu exponent verbatim after inserting `.0`/`+`, with no two-digit zero-padding. SQLite's number formatter always emits at least two exponent digits, so any REAL that ryu renders with a one-digit exponent diverges: `1e-6`→Turso `[1.0e-6]` vs SQLite `[1.0e-06]`; `1e-7`→`[1.0e-7]` vs `[1.0e-07]`; `1.5e-7`→`[1.5e-7]` vs `[1.5e-07]`; `json_quote(1e-7)`→`1.0e-7` vs `1.0e-07`. Two-digit exponents (`1e-10`, `1.5e99`, `1e16`) match. No fix commit touches this region between the cited `2fb47a06` and `5f6098a0` (verified `git log ... -- core/json/mod.rs`). Correctly rated low: it is a text-formatting/differential-compat divergence, no corruption. (Bonus divergence, not part of the finding: `1e-5`→Turso `[0.00001]` vs SQLite `[1.0e-05]` — here ryu stays in plain notation while SQLite goes scientific, an even wider mismatch from a separate ryu-threshold cause; does not affect this verdict.)
- repro-transcript: |
    $ printf '.mode list\nSELECT json_array(1e-7);\nSELECT json_array(1e-6);\nSELECT json_array(1.5e-7);\nSELECT json_array(1e-10);\nSELECT json_quote(1e-7);\n' | timeout 30 tursodb -q test.db
    [1.0e-7]      <- SQLite: [1.0e-07]   MISMATCH
    [1.0e-6]      <- SQLite: [1.0e-06]   MISMATCH
    [1.5e-7]      <- SQLite: [1.5e-07]   MISMATCH
    [1.0e-10]     <- SQLite: [1.0e-10]   match
    1.0e-7        <- SQLite: 1.0e-07     MISMATCH (json_quote)
    $ python3 -c "import sqlite3;c=sqlite3.connect(':memory:');print(sqlite3.sqlite_version);[print(c.execute(q).fetchone()[0]) for q in ['SELECT json_array(1e-7)','SELECT json_array(1e-6)','SELECT json_array(1.5e-7)','SELECT json_array(1e-10)','SELECT json_quote(1e-7)']]"
    3.45.1
    [1.0e-07]
    [1.0e-06]
    [1.5e-07]
    [1.0e-10]
    1.0e-07

## VERDICT [A11-6] Windows syscall backend leaks one kernel Event handle per thread; comment wrongly claims the OS reclaims them at thread exit
- verdict: CONFIRMED
- severity: low
- repro: not-attempted (Windows-only kernel-handle behavior; no Windows host available — verified by code reading + documented Win32 handle semantics + git history)
- reasoning: All load-bearing facts hold. (1) The leaking backend is live, not dead: `core/io/mod.rs:38` aliases `windows::WindowsIO as PlatformIO` under `#[cfg(all(target_os="windows", not(miri)))]` with no feature gate — `WindowsIO` is the DEFAULT Windows backend; `WindowsIOCP` is the opt-in `experimental_win_iocp` alternative. (2) `core/io/windows.rs:34-35` stores the `CreateEventW` handle in `thread_local!{ static IO_EVENT: Cell<HANDLE> }`. `HANDLE` is `*mut c_void`; `Cell<*mut c_void>` has no destructor, so thread exit drops the Cell as a no-op. (3) There is no `CloseHandle` for `IO_EVENT` anywhere — the only `CloseHandle` calls (windows.rs:182 open-error, :450 `impl Drop for WindowsFile`) close file handles, never the event. (4) The comment "closed by the OS on thread exit" (windows.rs:30) is factually wrong: Win32 handles live in a single process-wide handle table and are reclaimed only at process exit or explicit `CloseHandle`, never at thread termination. (5) The leak is newly introduced by the rewrite: pre-image `873d1a82^:core/io/windows.rs` used synchronous handles with `hEvent: null_mut()` and no per-thread event at all. (6) No later fix — only `bb493cd3` (WAL lock coordination) touched windows.rs after the cited commit. Net: every thread that does >=1 I/O via `with_io_event` (pread/pwrite/pwritev/sync all route through it, windows.rs:277/343/385) leaks exactly one Event object for the process lifetime; unbounded growth under thread-per-request / churning pools, bounded under a fixed pool. Low severity (slow Windows-only resource leak, no correctness impact on the happy path). Secondary claim in the finding is also real but rare: in the `ERROR_IO_PENDING` branch of `write_chunk`/`pread`, a failed `WaitForSingleObject`/`GetOverlappedResult` returns `Err` while a stack `OVERLAPPED` + destination buffer are still registered with the kernel — the textbook overlapped-I/O use-after-free pattern, only reachable on a rare wait/result failure.
- repro-transcript: |
    # code facts (grep/read)
    core/io/mod.rs:38            pub use windows::WindowsIO as PlatformIO;   # default backend, no feature gate
    core/io/windows.rs:30        // ... (closed by the OS on thread exit)    # incorrect comment
    core/io/windows.rs:35        static IO_EVENT: Cell<HANDLE> = ...;         # Cell<*mut c_void>, no Drop
    grep CloseHandle core/io/windows.rs -> only file-handle closes (:182 open err, :450 WindowsFile Drop); none for IO_EVENT
    # provenance / history
    git log -S IO_EVENT -- core/io/windows.rs   -> 873d1a82 "remove unnecessary mutex locks on File IO" (the cited PR 0adb0f66)
    git show 873d1a82^:core/io/windows.rs | grep hEvent -> "hEvent: std::ptr::null_mut()"  # no per-thread event before rewrite
    git log --oneline 0adb0f66..5f6098a0 -- core/io/windows.rs -> bb493cd3 (WAL lock coord only; no leak fix)

## VERDICT [A11-7] Synchronous waiters busy-spin at 100% CPU while another thread is the io_uring leader
- verdict: CONFIRMED
- severity: low
- repro: not-attempted (needs two threads sharing one UringIO with a leader mid-kernel-wait; CPU-spin timing is not reliably observable through the SQL CLI — verified by code reading + git-proven behavioral regression)
- reasoning: The spin mechanism is present and undeniable at reviewed HEAD. `core/io/io_uring.rs:519-521`: a follower whose `wait_lock.try_lock()` fails `return Ok(())` immediately, with NO `yield_now`/`sleep`/`park`/backoff on that path (grep confirms the trait's `yield_now`/`sleep` helpers at `core/io/mod.rs:500-508` are never called from the follower branch or the wait loops). `UringIO` overrides only `step` (io_uring.rs:513), so it inherits the default sync-wait helpers `wait_for_completion` (mod.rs:467-470) and `drain_completions` (mod.rs:460-465), both of which are bare `while !finished { self.step()? }` loops with no backoff. So while thread A holds `wait_lock` inside `submit_and_wait` (a blocking kernel wait), thread B sitting in either helper calls `step()`→try_lock-fail→`Ok(())`→re-check (still not finished)→loop, burning a full core for the whole duration of A's kernel wait until A's `drain_cq` marks B's completion finished. This is a genuine regression: pre-image `git show b1bf20df^:core/io/io_uring.rs` shows the old `step()` (line 522) took `self.inner.lock()` — a blocking parking_lot lock — so a losing waiter slept instead of spinning. No fix after: `git log b1bf20df..5f6098a0 -- core/io/io_uring.rs` is empty. It is a perf issue only (the loop still terminates once the leader drains the CQE — not a hang), so low severity is right. Live sync-wait callers exist (mvcc `logical_log.rs`, `mvcc/database/tests.rs`, plus the error-path `drain_completions` sites in pager/wal/sqlite3_ondisk/sorter cited in A11-1); the hottest production paths are async/waker-based, so observable 100% CPU is bounded to multi-threaded io_uring contention on those synchronous helpers.
- repro-transcript: |
    core/io/io_uring.rs:519    let Some(_wait_guard) = self.wait_lock.try_lock() else {
    core/io/io_uring.rs:520        return Ok(());          # follower: immediate return, no yield/sleep
    core/io/mod.rs:460-465     drain_completions: while any !finished { self.step()? }   # no backoff
    core/io/mod.rs:467-470     wait_for_completion: while !c.finished() { self.step()? } # no backoff
    grep yield_now|sleep|park|spin_loop|backoff core/io/io_uring.rs -> none in step follower path
    git show b1bf20df^:core/io/io_uring.rs | sed -n '521,528p' -> step() { let mut inner = self.inner.lock(); ... }  # OLD: blocked
    git log --oneline b1bf20df..5f6098a0 -- core/io/io_uring.rs -> (empty; no later fix)
