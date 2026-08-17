## VERDICT [A11-1] `drain_completions` after `cancel()` is a no-op — error paths no longer wait for in-flight kernel I/O
- verdict: CONFIRMED
- severity: medium
- repro: not-attempted (io_uring-only, requires a mid-batch write-preparation failure plus a kernel-ordering/cancel timing race; not SQL-reproducible and the runtime default backend is syscall)
- reasoning: |
    The core defect is proven by code + history. HEAD `IO::cancel` (core/io/mod.rs:443 default; core/io/io_uring.rs:476-488 override) calls `c.abort()` on every completion. `abort()` (core/io/completions.rs:460) => `error(Aborted)` => `callback` => `inner.result.get_or_init(..)`, after which `finished()` (completions.rs:430-434, non-group arm `result.get().is_some()`) returns true. `drain_completions` (mod.rs:460-465) is `while completions.iter().any(|c| !c.finished()) { self.step()?; }` — so after `cancel()` marks every completion finished, the loop condition is false on entry and `step()` is NEVER called. The function's own doc ("Used after cancel() so cancelled ops actually release their buffers before the caller returns") is therefore silently unfulfilled.
    This is a real regression: pre-commit (`git show b1bf20df^:core/io/io_uring.rs`) the error sites used `io.drain()`, which loops `submit_and_wait` + drain the CQ until `ring.empty()` — a true kernel barrier that ran `handle_writev_completion` and freed WritevState. All four cited sites used `cancel()`+`drain()` pre-commit (pager.rs:3372-3373 & 3571-3572, wal.rs:4563-4564, sqlite3_ondisk.rs:739-740, sorter.rs:313-314) and now use `cancel()`+`drain_completions()`. `fn drain()` no longer exists on the IO trait (only win_iocp keeps a private one). The completions in question are Single Write completions (wal.rs:4588 `Completion::new_write` -> `pwritev`), and the group sites drain `group.completions()` (the aborted Single children) — so the no-op holds for every cited site.
    The accumulation is real: `flush_page_batch` (pager.rs:3779) is called once per IOV_MAX batch during a cacheflush and pushes each completion onto `state.completions`, so a later batch erroring leaves earlier batches' writes in flight; `spill_pages_to_disk` (pager.rs:4039) accumulates likewise. The error path (e.g. a page-codec/encryption encode failure in `prepare_transformed_frame`, wal.rs:4539) is reachable. No use-after-free results (CompletionInner is kept alive by the kernel's `Arc::into_raw` user_data ref, and pwritev buffers by `RingState.writev_states`), but the intended durability barrier is gone: the caller returns while the kernel may still be writing WAL frame offsets that the next (rolled-back-then-reused) transaction overwrites, and `handle_writev_completion` even RE-SUBMITS a partial "cancelled" writev (io_uring.rs:413-427). A stale write landing after a committed frame breaks the WAL checksum chain -> silent lost/unreadable transaction — the exact hazard the old `io.drain()` prevented. Severity reduced from the finding's "high" to medium: io_uring is opt-in (PlatformIO on Linux = UnixIO/syscall; io_uring reached only via `--vfs io_uring` or an embedder constructing UringIO), and the trigger is a narrow mid-batch write-prep failure plus a timing race — but the outcome is silent data corruption, so it is high-impact for any io_uring deployment that hits it. The no-op-barrier defect itself is confirmed unconditionally.
- repro-transcript: |
    # code (HEAD)
    core/io/mod.rs:460  fn drain_completions: while completions.iter().any(|c| !c.finished()) { self.step()?; }
    core/io/completions.rs:460  pub fn abort(&self){ self.error(CompletionError::Aborted); }  // sets result -> finished()==true
    core/io/io_uring.rs:479     for c in completions { c.abort(); ... AsyncCancel ... }  // aborts, never waits
    core/storage/pager.rs:3796-3797  cancel(&state.completions)?; drain_completions(&state.completions)?;  // second call = no-op
    # history
    $ git show b1bf20df^:core/io/io_uring.rs  # fn drain(): loop { flush_overflow; if ring.empty(){return}; submit_and_wait(); drain CQ }  <-- real barrier
    $ git show b1bf20df^:core/storage/pager.rs | grep -n 'cancel(\|drain('  -> 3372 cancel(&state.completions); 3373 io.drain();
    $ grep -rn 'fn drain(' core/io/  -> only win_iocp.rs (barrier removed from the trait)

## VERDICT [A11-2] `Opening` registry sentinel leaks when an async open is abandoned — later opens of the same path yield forever
- verdict: FIXED-AT-HEAD (fixed by 6efb903e)
- severity: medium
- repro: not-attempted (already fixed at HEAD; would require an abandoned async open)
- reasoning: |
    The bug was real at the cited commit and is fixed at HEAD. At f2908fd4 there was no `impl Drop for OpenDbAsyncState` (`git show f2908fd4:core/lib.rs | grep -c 'impl Drop for OpenDbAsyncState'` => 0), so an abandoned async open (state dropped mid-flight while `registry_key = Some(..)` and `RegistryEntry::Opening` still in DATABASE_MANAGER) left the sentinel forever; every later open of that path hits the `Some(RegistryEntry::Opening)` arm and returns `IOResult::IO(Completion::new_yield())` (still present at HEAD, core/database.rs:1199-1205), livelocking the sync wrapper. At HEAD the Drop impl exists (core/database.rs:461-467) and removes `registry_key` from the registry on drop. `git log -S "impl Drop for OpenDbAsyncState"` shows it first introduced by 6efb903e (later moved to database.rs by 34decbd4), and 6efb903e is an ancestor of HEAD 5f6098a0. Matches the finding's own at-head claim.
- repro-transcript: |
    $ git show f2908fd4:core/lib.rs | grep -c 'impl Drop for OpenDbAsyncState'   -> 0
    $ git show f2908fd4:core/database.rs                                          -> no database.rs at f2908fd4
    $ git log --oneline -S 'impl Drop for OpenDbAsyncState' -- core/lib.rs core/database.rs | tail -1
        6efb903e add durable snapshot_seq ...   # introducer
    $ git merge-base --is-ancestor 6efb903e 5f6098a0 && echo YES   -> YES
    core/database.rs:461-467  impl Drop for OpenDbAsyncState { fn drop { if let Some(k)=registry_key.take(){ DATABASE_MANAGER.lock().remove(&k) } } }

## VERDICT [A11-3] Registry keyed by OS file identity silently stops de-duplicating databases on IO backends whose paths are not host-filesystem files
- verdict: CONFIRMED
- severity: medium
- repro: not-attempted (requires a custom VFS extension backend with virtual paths; not SQL-reproducible from the CLI)
- reasoning: |
    Confirmed as a real regression for VFS extension backends. At HEAD the registry lookup AND registration both live inside `if let Ok(file_id) = io.file_id(path)` (core/database.rs:1177-1212): on `Err` there is no lookup, no `Ready`/`Opening` insert, no `state.registry_key`, and no error — the database silently never enters the registry. The default `IO::file_id` (core/io/mod.rs:513) uses host `std::fs::metadata`, and `impl IO for VfsMod` (core/io/vfs.rs:21) does NOT override it (overrides exist only in memory.rs, memory_yield.rs, and a vacuum.rs test IO). The VfsImpl FFI has no identity hook, so an extension VFS whose paths are not host files (object-store/network VFS) errors on every `file_id` call and is never deduplicated. VFS opens do route through this path: `open_with_vfs` (core/ext/mod.rs:215-241) -> `open_file` -> the async open state machine -> the file_id guard.
    Pre-commit (`git show 30d8eaf8^:core/lib.rs`) the authoritative async path `open_with_flags_async_internal` computed `canonical_path = canonicalize(path).ok()...unwrap_or_else(|| path.to_string())` and used that SAME raw-string-fallback key for both `registry.get(&canonical_path)` and `registry.insert(canonical_path, ..)`, so a second open of the same VFS path string returned the first `Database`. (A separate early-check helper `lookup_in_registry` lacked the fallback, but the full open path's `get()` did the real dedup.) 30d8eaf8 replaced that with the FileId key and the `if let Ok` skip, dropping VFS dedup. Losing it means two independent `Database`/`WalFileShared` for one underlying store; a VFS has no OS advisory locks, so the "single shared Database per file" invariant (database.rs:479-482) is silently lost -> conflicting WAL frame appends / checksum-chain breakage. Severity medium: niche (custom VFS + same path opened twice in-process via separate opens) but silent-corruption outcome. 30d8eaf8 is an ancestor of HEAD.
- repro-transcript: |
    core/database.rs:1177  if let Ok(file_id) = io.file_id(path) { <lookup + insert + state.registry_key> }   // Err => nothing, silently
    core/io/mod.rs:513     fn file_id: get_file_id(path)  // std::fs::metadata -> Err for virtual VFS paths
    $ grep -rn 'fn file_id' core/  -> memory.rs, memory_yield.rs, vacuum.rs(test) ONLY; vfs.rs has none
    core/ext/mod.rs:240   let db = Self::open_file(io.clone(), path, dialect)?;   // VFS goes through the registry path
    $ git show 30d8eaf8^:core/lib.rs  # open_with_flags_async_internal: canonical_path = canonicalize().ok()....unwrap_or_else(|| path.to_string());
                                      #   registry.get(&canonical_path) ... registry.insert(canonical_path, downgrade(db))  <-- string dedup for VFS

## VERDICT [A11-4] Unix last-process probe now releases the shared lifetime lock before probing, creating a no-lock window that can elect two "last" processes
- verdict: CONFIRMED
- severity: low
- repro: not-attempted (requires experimental multiprocess WAL + two processes closing concurrently with a specific interleaving)
- reasoning: |
    Confirmed as a real regression, scoped to the experimental multiprocess-WAL feature. The new default `shared_wal_probe_exclusive_while_shared_byte` (core/io/mod.rs:256-271) unconditionally `shared_wal_unlock_byte(..)` BEFORE probing, then `shared_wal_probe_exclusive_byte` (which itself acquires exclusive and immediately releases it, mod.rs:242-252), then re-locks shared — so on EVERY path the caller passes through a window holding no lock. `is_last_process_mapping` (core/storage/shared_wal_coordination.rs:1078-1085) uses it, gating shutdown checkpointing (wal.rs:2383-2384 -> connection.rs:2375-2387 `checkpoint_shutdown`). Unix does not override the default (`grep` shows only win_iocp.rs overrides it), and Unix implements the byte primitives via fcntl (F_OFD_SETLK/F_SETLK, F_WRLCK/F_RDLCK — unix.rs:134-207), for which acquiring F_WRLCK while already holding F_RDLCK on the same range is an atomic conversion that RETAINS the existing shared lock on EAGAIN. Pre-commit (`git show 220c0d16^:core/storage/shared_wal_coordination.rs`) `is_last_process_mapping` did exactly that atomic try-exclusive-while-holding-shared and only unlocked/reacquired on success — so a failing probe never passed through an unlocked state.
    Because the exclusive probe is non-holding (acquire+immediate-release), two processes P1/P2 both closing their last connection can interleave (P1 unlock -> P2 unlock -> P1 probe succeeds -> ... -> P2 probe also succeeds, or P1 wins and P2 loses) so that a prober reports "I am the last mapping holder" while the other process is still alive and mapped — exactly what the lifetime lock exists to prevent. P1 then runs the last-process truncate checkpoint / coordination teardown while P2 is mid-close, racing P2's `release_owned_locks_on_drop` writes into the (possibly truncated) mapped region. The old atomic path could only yield a true "last" when the prober genuinely was alone. Severity low because it is reachable only under opt-in `enable_multiprocess_wal`. 220c0d16 is an ancestor of HEAD.
- repro-transcript: |
    core/io/mod.rs:261  self.shared_wal_unlock_byte(offset, kind)?;      // releases shared BEFORE probing (all paths)
    core/io/mod.rs:247  let locked = try_lock(exclusive); if locked { unlock }  // exclusive probe does not hold
    core/io/mod.rs:269  self.shared_wal_lock_byte(offset, false, kind)?; // re-lock shared afterward
    $ grep -n shared_wal_probe_exclusive_while_shared_byte core/io/unix.rs   -> (none: uses default)
    $ git show 220c0d16^:core/storage/shared_wal_coordination.rs  # is_last_process_mapping:
        #   if !matches!(try_lock_byte(LIFETIME, exclusive=true), Ok(true)) { return false; }  // atomic upgrade, shared retained on fail
        #   unlock; reacquire_shared_lifetime_lock; true                                        // unlock only on success
    $ git merge-base --is-ancestor 220c0d16 5f6098a0 && echo YES   -> YES
