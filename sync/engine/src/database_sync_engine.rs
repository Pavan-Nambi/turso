use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use turso_core::{Buffer, Completion, DatabaseStorage, OpenDbAsyncState, OpenFlags};

use crate::{
    database_replay_generator::DatabaseReplayGenerator,
    database_sync_engine_io::SyncEngineIo,
    database_sync_lazy_storage::LazyDatabaseStorage,
    database_sync_operations::{
        acquire_slot, apply_transformation, bootstrap_db_file, connect_untracked,
        count_local_changes, has_table, push_logical_changes, read_last_change_id, read_wal_salt,
        reset_wal_file, update_last_change_id, wait_all_results, wal_apply_from_file,
        wal_pull_to_file, SyncEngineIoStats, SyncOperationCtx, PAGE_SIZE, WAL_FRAME_HEADER,
        WAL_FRAME_SIZE,
    },
    database_tape::{
        DatabaseChangesIteratorMode, DatabaseChangesIteratorOpts, DatabaseReplaySession,
        DatabaseReplaySessionOpts, DatabaseTape, DatabaseTapeOpts, DatabaseWalSession,
        CDC_PRAGMA_NAME,
    },
    errors::Error,
    io_operations::IoOperations,
    types::{
        Coro, DatabaseMetadata, DatabasePullRevision, DatabaseRowTransformResult,
        DatabaseSavedConfiguration, DatabaseSyncEngineProtocolVersion, DatabaseTapeOperation,
        DbChangesStatus, PartialSyncOpts, SyncEngineIoResult, SyncEngineStats,
        DATABASE_METADATA_VERSION,
    },
    wal_session::WalSession,
    Result,
};

#[derive(Clone, Debug)]
pub struct DatabaseSyncEngineOpts {
    pub remote_url: Option<String>,
    pub client_name: String,
    pub tables_ignore: Vec<String>,
    pub use_transform: bool,
    pub wal_pull_batch_size: u64,
    pub long_poll_timeout: Option<std::time::Duration>,
    pub protocol_version_hint: DatabaseSyncEngineProtocolVersion,
    pub bootstrap_if_empty: bool,
    pub reserved_bytes: usize,
    pub partial_sync_opts: Option<PartialSyncOpts>,
    /// Base64-encoded encryption key for the Turso Cloud database
    pub remote_encryption_key: Option<String>,
    /// When set, [`push_changes_to_remote`] sends the local change set to the
    /// remote in multiple HTTP batches, sealing the current batch as soon as it
    /// has accumulated >= `push_operations_threshold` operations *and* the
    /// next batch boundary lines up with a transaction boundary in the local
    /// CDC log. Splits never happen mid-transaction. `None` preserves the
    /// previous behaviour of pushing the whole change set in one batch.
    pub push_operations_threshold: Option<usize>,
    /// Optional hint, in bytes, to chunk the initial bootstrap download into
    /// multiple `/pull-updates` HTTP requests using the `server_pages_selector`
    /// bitmap. Each chunk covers the smallest contiguous range of pages whose
    /// total size is >= `pull_bytes_threshold`. `None` (default) bootstraps in
    /// a single HTTP round-trip. Currently applied only to the bootstrap phase
    /// — incremental pulls are unaffected. **No-op when partial-sync uses the
    /// `Query` bootstrap strategy** — the server picks the page set, so the
    /// client can't chunk it locally.
    pub pull_bytes_threshold: Option<usize>,
}

pub struct DataStats {
    pub written_bytes: AtomicUsize,
    pub read_bytes: AtomicUsize,
}

impl Default for DataStats {
    fn default() -> Self {
        Self::new()
    }
}

impl DataStats {
    pub fn new() -> Self {
        Self {
            written_bytes: AtomicUsize::new(0),
            read_bytes: AtomicUsize::new(0),
        }
    }
    pub fn write(&self, size: usize) {
        self.written_bytes.fetch_add(size, Ordering::SeqCst);
    }
    pub fn read(&self, size: usize) {
        self.read_bytes.fetch_add(size, Ordering::SeqCst);
    }
}

pub struct DatabaseSyncEngine<IO: SyncEngineIo> {
    io: Arc<dyn turso_core::IO>,
    sync_engine_io: SyncEngineIoStats<IO>,
    db_file: Arc<dyn turso_core::storage::database::DatabaseStorage>,
    main_tape: DatabaseTape,
    main_db_wal_path: String,
    revert_db_wal_path: String,
    main_db_path: String,
    meta_path: String,
    changes_file: Arc<Mutex<Option<Arc<dyn turso_core::File>>>>,
    opts: DatabaseSyncEngineOpts,
    meta: Mutex<DatabaseMetadata>,
    client_unique_id: String,
}

fn db_size_from_page(page: &[u8]) -> u32 {
    u32::from_be_bytes(page[28..28 + 4].try_into().unwrap())
}
fn is_memory(main_db_path: &str) -> bool {
    main_db_path == ":memory:"
}
fn create_main_db_wal_path(main_db_path: &str) -> String {
    format!("{main_db_path}-wal")
}
fn create_revert_db_wal_path(main_db_path: &str) -> String {
    format!("{main_db_path}-wal-revert")
}
fn create_meta_path(main_db_path: &str) -> String {
    format!("{main_db_path}-info")
}
fn create_changes_path(main_db_path: &str) -> String {
    format!("{main_db_path}-changes")
}

/// caller has no access to the memory io - so we handle it here implicitly
/// ideally, we should add necessary methods to the turso_core::IO trait - but so far I am struggling with nice interface to do that
/// so, I decided to keep a little bit of mess in sync-engine for a little bit longer
async fn full_read<Ctx, IO: SyncEngineIo>(
    coro: &Coro<Ctx>,
    io: Option<Arc<dyn turso_core::IO>>,
    sync_engine_io: Arc<IO>,
    path: &str,
    is_memory: bool,
) -> Result<Option<Vec<u8>>> {
    if !is_memory {
        let completion = sync_engine_io.full_read(path)?;
        let data = wait_all_results(coro, &completion, None).await?;
        if data.is_empty() {
            return Ok(None);
        } else {
            return Ok(Some(data));
        }
    }
    let Some(io) = io else {
        return Err(Error::DatabaseSyncEngineError(
            "MemoryIO must be set".to_string(),
        ));
    };
    let Ok(file) = io.open_file(path, OpenFlags::None, false) else {
        return Ok(None);
    };
    let mut content = Vec::new();
    let mut offset = 0;
    let buffer = Arc::new(Buffer::new_temporary(4096));
    let read_len = Arc::new(Mutex::new(0));
    loop {
        let c = Completion::new_read(buffer.clone(), {
            let read_len = read_len.clone();
            move |r| {
                *read_len.lock().unwrap() = r.expect("memory io must not fail").1;
                None
            }
        });
        let read = file.pread(offset, c).expect("memory io must not fail");
        assert!(read.finished(), "memory io must complete immediately");
        let read_len = *read_len.lock().unwrap();
        if read_len == 0 {
            break;
        }
        content.extend_from_slice(&buffer.as_slice()[0..read_len as usize]);
        offset += read_len as u64;
    }
    Ok(Some(content))
}

/// caller has no access to the memory io - so we handle it here implicitly
/// ideally, we should add necessary methods to the turso_core::IO trait - but so far I am struggling with nice interface to do that
/// so, I decided to keep a little bit of mess in sync-engine for a little bit longer
async fn full_write<Ctx, IO: SyncEngineIo>(
    coro: &Coro<Ctx>,
    io: Arc<dyn turso_core::IO>,
    sync_engine_io: Arc<IO>,
    path: &str,
    is_memory: bool,
    content: Vec<u8>,
) -> Result<()> {
    if !is_memory {
        let completion = sync_engine_io.full_write(path, content)?;
        wait_all_results(coro, &completion, None).await?;
        return Ok(());
    }
    let file = io.open_file(path, OpenFlags::Create, false)?;
    let trunc = file
        .truncate(0, Completion::new_trunc(|_| {}))
        .expect("memory io must not fail");
    assert!(trunc.finished(), "memory io must complete immediately");
    let write = file
        .pwrite(
            0,
            Arc::new(Buffer::new(content)),
            Completion::new_write(|_| {}),
        )
        .expect("memory io must nof fail");
    assert!(write.finished(), "memory io must complete immediately");
    Ok(())
}

impl<IO: SyncEngineIo> DatabaseSyncEngine<IO> {
    pub async fn read_db_meta<Ctx>(
        coro: &Coro<Ctx>,
        io: Option<Arc<dyn turso_core::IO>>,
        sync_engine_io: SyncEngineIoStats<IO>,
        main_db_path: &str,
    ) -> Result<Option<DatabaseMetadata>> {
        let path = create_meta_path(main_db_path);
        let is_memory = is_memory(main_db_path);
        let meta = full_read(coro, io, sync_engine_io.io.clone(), &path, is_memory).await?;
        match meta {
            Some(meta) => Ok(Some(DatabaseMetadata::load(&meta)?)),
            None => Ok(None),
        }
    }

    pub async fn bootstrap_db<Ctx>(
        coro: &Coro<Ctx>,
        io: Arc<dyn turso_core::IO>,
        sync_engine_io: SyncEngineIoStats<IO>,
        main_db_path: &str,
        opts: &DatabaseSyncEngineOpts,
        meta: Option<DatabaseMetadata>,
    ) -> Result<DatabaseMetadata> {
        tracing::info!("bootstrap_db(path={}): opts={:?}", main_db_path, opts);
        let meta_path = create_meta_path(main_db_path);
        let partial_sync_opts = opts.partial_sync_opts.clone();
        let partial = partial_sync_opts.is_some();

        let configuration = DatabaseSavedConfiguration {
            remote_url: opts.remote_url.clone(),
            partial_sync_prefetch: opts.partial_sync_opts.as_ref().map(|p| p.prefetch),
            partial_sync_segment_size: opts.partial_sync_opts.as_ref().map(|p| p.segment_size),
        };
        let meta = match meta {
            Some(mut meta) => {
                if meta.update_configuration(configuration) {
                    full_write(
                        coro,
                        io.clone(),
                        sync_engine_io.io.clone(),
                        &meta_path,
                        is_memory(main_db_path),
                        meta.dump()?,
                    )
                    .await?;
                }
                meta
            }
            None if opts.bootstrap_if_empty => {
                let client_unique_id = format!("{}-{}", opts.client_name, uuid::Uuid::new_v4());
                let revision = bootstrap_db_file(
                    &SyncOperationCtx::new(
                        coro,
                        &sync_engine_io,
                        opts.remote_url.clone(),
                        opts.remote_encryption_key.as_deref(),
                    ),
                    &io,
                    main_db_path,
                    opts.protocol_version_hint,
                    partial_sync_opts,
                    opts.pull_bytes_threshold,
                )
                .await?;
                let meta = DatabaseMetadata {
                    version: DATABASE_METADATA_VERSION.to_string(),
                    client_unique_id,
                    synced_revision: Some(revision.clone()),
                    revert_since_wal_salt: None,
                    revert_since_wal_watermark: 0,
                    last_pushed_change_id_hint: 0,
                    last_pushed_pull_gen_hint: 0,
                    last_pull_unix_time: Some(io.current_time_wall_clock().secs),
                    last_push_unix_time: None,
                    partial_bootstrap_server_revision: if partial {
                        Some(revision.clone())
                    } else {
                        None
                    },
                    saved_configuration: Some(configuration),
                };
                tracing::info!("write meta after successful bootstrap: meta={meta:?}");

                full_write(
                    coro,
                    io.clone(),
                    sync_engine_io.io.clone(),
                    &meta_path,
                    is_memory(main_db_path),
                    meta.dump()?,
                )
                .await?;
                // todo: what happen if we will actually update the metadata on disk but fail and so in memory state will not be updated
                meta
            }
            None => {
                if opts.protocol_version_hint == DatabaseSyncEngineProtocolVersion::Legacy {
                    return Err(Error::DatabaseSyncEngineError(
                        "deferred bootstrap is not supported for legacy protocol".to_string(),
                    ));
                }
                if partial {
                    return Err(Error::DatabaseSyncEngineError(
                        "deferred bootstrap is not supported for partial sync".to_string(),
                    ));
                }
                let client_unique_id = format!("{}-{}", opts.client_name, uuid::Uuid::new_v4());
                let meta = DatabaseMetadata {
                    version: DATABASE_METADATA_VERSION.to_string(),
                    client_unique_id,
                    synced_revision: None,
                    revert_since_wal_salt: None,
                    revert_since_wal_watermark: 0,
                    last_pushed_change_id_hint: 0,
                    last_pushed_pull_gen_hint: 0,
                    last_pull_unix_time: None,
                    last_push_unix_time: None,
                    partial_bootstrap_server_revision: None,
                    saved_configuration: Some(configuration),
                };
                tracing::info!("write meta after successful bootstrap: meta={meta:?}");
                full_write(
                    coro,
                    io.clone(),
                    sync_engine_io.io.clone(),
                    &meta_path,
                    is_memory(main_db_path),
                    meta.dump()?,
                )
                .await?;
                // todo: what happen if we will actually update the metadata on disk but fail and so in memory state will not be updated
                meta
            }
        };

        if meta.version != DATABASE_METADATA_VERSION {
            return Err(Error::DatabaseSyncEngineError(format!(
                "unsupported metadata version: {}",
                meta.version
            )));
        }

        tracing::info!("check if main db file exists");

        let main_exists = io.try_open(main_db_path)?.is_some();
        if !main_exists && meta.synced_revision.is_some() {
            let error = "main DB file doesn't exists, but metadata is".to_string();
            return Err(Error::DatabaseSyncEngineError(error));
        }

        Ok(meta)
    }

    pub fn init_db_storage(
        io: Arc<dyn turso_core::IO>,
        sync_engine_io: SyncEngineIoStats<IO>,
        meta: &DatabaseMetadata,
        main_db_path: &str,
        remote_encryption_key: Option<&str>,
    ) -> Result<Arc<dyn DatabaseStorage>> {
        let db_file = io.open_file(main_db_path, turso_core::OpenFlags::Create, false)?;
        let db_file: Arc<dyn DatabaseStorage> = if let Some(partial_sync_opts) =
            meta.partial_sync_opts()
        {
            let Some(partial_bootstrap_server_revision) = &meta.partial_bootstrap_server_revision
            else {
                return Err(Error::DatabaseSyncEngineError(
                    "partial_bootstrap_server_revision must be set in the metadata".to_string(),
                ));
            };
            let DatabasePullRevision::V1 { revision } = &partial_bootstrap_server_revision else {
                return Err(Error::DatabaseSyncEngineError(
                    "partial sync is supported only for V1 protocol".to_string(),
                ));
            };
            tracing::info!("create LazyDatabaseStorage database storage");
            let encoded_key = remote_encryption_key.map(|k| k.to_string());
            Arc::new(LazyDatabaseStorage::new(
                db_file,
                None, // todo(sivukhin): allocate dirty file for FS IO
                sync_engine_io.clone(),
                revision.to_string(),
                partial_sync_opts,
                meta.saved_configuration
                    .as_ref()
                    .and_then(|x| x.remote_url.as_ref())
                    .cloned(),
                encoded_key,
            )?)
        } else {
            Arc::new(turso_core::storage::database::DatabaseFile::new(db_file))
        };

        Ok(db_file)
    }

    pub async fn open_db<Ctx>(
        coro: &Coro<Ctx>,
        io: Arc<dyn turso_core::IO>,
        sync_engine_io: SyncEngineIoStats<IO>,
        main_db: Arc<turso_core::Database>,
        opts: DatabaseSyncEngineOpts,
    ) -> Result<Self> {
        let main_db_path = main_db.path.to_string();
        tracing::info!("open_db(path={}): opts={:?}", main_db_path, opts);

        let meta_path = create_meta_path(&main_db_path);

        let meta = full_read(
            coro,
            Some(io.clone()),
            sync_engine_io.io.clone(),
            &meta_path,
            is_memory(&main_db_path),
        )
        .await?;
        let Some(meta) = meta else {
            return Err(Error::DatabaseSyncEngineError(
                "meta must be initialized before open".to_string(),
            ));
        };
        let meta = DatabaseMetadata::load(&meta)?;

        // DB wasn't synced with remote but will be encrypted on remote - so we must properly set reserved bytes field in advance
        if meta.synced_revision.is_none() && opts.reserved_bytes != 0 {
            let conn = main_db.connect()?;
            conn.wal_auto_checkpoint_disable();
            conn.set_reserved_bytes(opts.reserved_bytes as u8)?;

            // write transaction forces allocation of root DB page
            conn.execute("BEGIN IMMEDIATE")?;
            conn.execute("COMMIT")?;
        }

        let tape_opts = DatabaseTapeOpts {
            cdc_table: None,
            cdc_mode: Some("full".to_string()),
            disable_auto_checkpoint: true,
        };
        tracing::info!("initialize database tape connection: path={}", main_db_path);
        let main_db_io = main_db.io.clone();
        let main_db_file = main_db.db_file.clone();
        let main_tape = DatabaseTape::new_with_opts(main_db, tape_opts);
        // Initialize CDC pragma and cache CDC version so iterate_changes() can work
        main_tape.connect(coro).await?;

        let changes_path = create_changes_path(&main_db_path);
        let changes_file = main_db_io.open_file(&changes_path, OpenFlags::Create, false)?;

        let db = Self {
            io: main_db_io,
            sync_engine_io,
            db_file: main_db_file,
            main_tape,
            main_db_path: main_db_path.to_string(),
            main_db_wal_path: create_main_db_wal_path(&main_db_path),
            revert_db_wal_path: create_revert_db_wal_path(&main_db_path),
            meta_path: create_meta_path(&main_db_path),
            changes_file: Arc::new(Mutex::new(Some(changes_file))),
            opts,
            meta: Mutex::new(meta.clone()),
            client_unique_id: meta.client_unique_id.clone(),
        };

        let synced_revision = meta.synced_revision.as_ref();
        if let Some(DatabasePullRevision::Legacy {
            synced_frame_no: None,
            ..
        }) = synced_revision
        {
            // sync WAL from the remote in case of bootstrap - all subsequent initializations will be fast
            db.pull_changes_from_remote(coro).await?;
        }

        tracing::info!("sync engine was initialized");
        Ok(db)
    }

    /// Creates new instance of SyncEngine and initialize it immediately if no consistent local data exists
    pub async fn create_db<Ctx>(
        coro: &Coro<Ctx>,
        io: Arc<dyn turso_core::IO>,
        sync_engine_io: SyncEngineIoStats<IO>,
        main_db_path: &str,
        opts: DatabaseSyncEngineOpts,
    ) -> Result<Self> {
        let meta = Self::read_db_meta(coro, Some(io.clone()), sync_engine_io.clone(), main_db_path)
            .await?;
        let meta = Self::bootstrap_db(
            coro,
            io.clone(),
            sync_engine_io.clone(),
            main_db_path,
            &opts,
            meta,
        )
        .await?;
        let main_db_storage = Self::init_db_storage(
            io.clone(),
            sync_engine_io.clone(),
            &meta,
            main_db_path,
            opts.remote_encryption_key.as_deref(),
        )?;

        // Use async database opening that yields on IO for large schemas
        let mut open_state = turso_core::OpenDbAsyncState::new();
        let main_db = loop {
            match turso_core::Database::open_with_flags_async(
                &mut open_state,
                io.clone(),
                main_db_path,
                main_db_storage.clone(),
                OpenFlags::Create,
                turso_core::DatabaseOpts::new(),
                None,
                None,
            )? {
                turso_core::IOResult::Done(db) => break db,
                turso_core::IOResult::IO(io_completion) => {
                    while !io_completion.finished() {
                        coro.yield_(SyncEngineIoResult::IO).await?;
                    }
                }
            }
        };

        Self::open_db(coro, io, sync_engine_io, main_db, opts).await
    }

    async fn open_revert_db_conn<Ctx>(
        &self,
        coro: &Coro<Ctx>,
    ) -> Result<Arc<turso_core::Connection>> {
        let db = {
            let mut state = OpenDbAsyncState::new();
            loop {
                match turso_core::Database::open_with_flags_bypass_registry_async(
                    &mut state,
                    self.io.clone(),
                    &self.main_db_path,
                    Some(&self.revert_db_wal_path),
                    self.db_file.clone(),
                    OpenFlags::Create,
                    turso_core::DatabaseOpts::new(),
                    None,
                    None,
                )? {
                    turso_core::IOResult::Done(db) => break db,
                    turso_core::IOResult::IO(io_completion) => {
                        while !io_completion.finished() {
                            coro.yield_(SyncEngineIoResult::IO).await?;
                        }
                        continue;
                    }
                }
            }
        };
        let conn = db.connect()?;
        conn.wal_auto_checkpoint_disable();
        Ok(conn)
    }

    async fn checkpoint_passive<Ctx>(&self, coro: &Coro<Ctx>) -> Result<(Option<Vec<u32>>, u64)> {
        let watermark = self.meta().revert_since_wal_watermark;
        tracing::info!(
            "checkpoint(path={:?}): revert_since_wal_watermark={}",
            self.main_db_path,
            watermark
        );
        let main_conn = connect_untracked(&self.main_tape)?;
        let main_wal = self.io.try_open(&self.main_db_wal_path)?;
        let main_wal_salt = if let Some(main_wal) = main_wal {
            read_wal_salt(coro, &main_wal).await?
        } else {
            None
        };

        tracing::info!(
            "checkpoint(path={:?}): main_wal_salt={:?}",
            self.main_db_path,
            main_wal_salt
        );

        let revert_since_wal_salt = self.meta().revert_since_wal_salt.clone();
        if revert_since_wal_salt.is_some() && main_wal_salt != revert_since_wal_salt {
            self.update_meta(coro, |meta| {
                meta.revert_since_wal_watermark = 0;
                meta.revert_since_wal_salt = main_wal_salt.clone();
            })
            .await?;
            return Ok((main_wal_salt, 0));
        }
        // we do this Passive checkpoint in order to transfer all synced frames to the DB file and make history of revert DB valid
        // if we will not do that we will be in situation where WAL in the revert DB is not valid relative to the DB file
        let result = main_conn.checkpoint(turso_core::CheckpointMode::Passive {
            upper_bound_inclusive: Some(watermark),
        })?;
        tracing::info!(
            "checkpoint(path={:?}): checkpointed portion of WAL: {:?}",
            self.main_db_path,
            result
        );
        if result.wal_max_frame < watermark {
            return Err(Error::DatabaseSyncEngineError(
                format!("unable to checkpoint synced portion of WAL: result={result:?}, watermark={watermark}"),
            ));
        }
        Ok((main_wal_salt, watermark))
    }

    pub async fn stats<Ctx>(&self, coro: &Coro<Ctx>) -> Result<SyncEngineStats> {
        let main_conn = connect_untracked(&self.main_tape)?;
        let change_id = self.meta().last_pushed_change_id_hint;
        let last_pull_unix_time = self.meta().last_pull_unix_time;
        let revision = self.meta().synced_revision.clone().map(|x| match x {
            DatabasePullRevision::Legacy {
                generation,
                synced_frame_no,
            } => format!("generation={generation},synced_frame_no={synced_frame_no:?}"),
            DatabasePullRevision::V1 { revision } => revision,
        });
        let last_push_unix_time = self.meta().last_push_unix_time;
        let revert_wal_path = &self.revert_db_wal_path;
        let revert_wal_file = self.io.try_open(revert_wal_path)?;
        let revert_wal_size = revert_wal_file.map(|f| f.size()).transpose()?.unwrap_or(0);
        let main_wal_frames = main_conn.wal_state()?.max_frame;
        let main_wal_size = if main_wal_frames == 0 {
            0
        } else {
            WAL_FRAME_HEADER as u64 + WAL_FRAME_SIZE as u64 * main_wal_frames
        };
        Ok(SyncEngineStats {
            cdc_operations: count_local_changes(coro, &main_conn, change_id).await?,
            main_wal_size,
            revert_wal_size,
            last_pull_unix_time,
            last_push_unix_time,
            revision,
            network_sent_bytes: self
                .sync_engine_io
                .network_stats
                .written_bytes
                .load(Ordering::SeqCst),
            network_received_bytes: self
                .sync_engine_io
                .network_stats
                .read_bytes
                .load(Ordering::SeqCst),
        })
    }

    pub async fn checkpoint<Ctx>(&self, coro: &Coro<Ctx>) -> Result<()> {
        let (main_wal_salt, watermark) = self.checkpoint_passive(coro).await?;

        tracing::info!(
            "checkpoint(path={:?}): passive checkpoint is done",
            self.main_db_path
        );
        let main_conn = connect_untracked(&self.main_tape)?;
        let revert_conn = self.open_revert_db_conn(coro).await?;

        let mut page = [0u8; PAGE_SIZE];
        let db_size = if revert_conn.try_wal_watermark_read_page(1, &mut page, None)? {
            db_size_from_page(&page)
        } else {
            0
        };

        tracing::info!(
            "checkpoint(path={:?}): revert DB initial size: {}",
            self.main_db_path,
            db_size
        );

        let main_wal_state;
        {
            let mut revert_session = WalSession::new(revert_conn.clone());
            revert_session.begin()?;

            let mut main_session = WalSession::new(main_conn.clone());
            main_session.begin()?;

            main_wal_state = main_conn.wal_state()?;
            tracing::info!(
                "checkpoint(path={:?}): main DB WAL state: {:?}",
                self.main_db_path,
                main_wal_state
            );

            let mut revert_session = DatabaseWalSession::new(coro, revert_session).await?;

            let main_changed_pages = main_conn.wal_changed_pages_after(watermark)?;
            tracing::info!(
                "checkpoint(path={:?}): collected {} changed pages",
                self.main_db_path,
                main_changed_pages.len()
            );
            let revert_changed_pages: HashSet<u32> = revert_conn
                .wal_changed_pages_after(0)?
                .into_iter()
                .collect();
            for page_no in main_changed_pages {
                if revert_changed_pages.contains(&page_no) {
                    tracing::debug!(
                        "checkpoint(path={:?}): skip page {} as it present in revert WAL",
                        self.main_db_path,
                        page_no
                    );
                    continue;
                }
                if page_no > db_size {
                    tracing::debug!(
                        "checkpoint(path={:?}): skip page {} as it ahead of revert-DB size",
                        self.main_db_path,
                        page_no
                    );
                    continue;
                }

                let begin_read_result =
                    main_conn.try_wal_watermark_read_page_begin(page_no, Some(watermark))?;
                let end_read_result = match begin_read_result {
                    Some((page_ref, c)) => {
                        while !c.succeeded() {
                            let _ = coro.yield_(crate::types::SyncEngineIoResult::IO).await;
                        }
                        main_conn.try_wal_watermark_read_page_end(&mut page, page_ref)?
                    }
                    None => false,
                };
                if !end_read_result {
                    tracing::debug!(
                        "checkpoint(path={:?}): skip page {} as it was allocated in the WAL portion for revert",
                        self.main_db_path,
                        page_no
                    );
                    continue;
                }
                tracing::debug!(
                    "checkpoint(path={:?}): append page {} (current db_size={})",
                    self.main_db_path,
                    page_no,
                    db_size
                );
                revert_session.append_page(page_no, &page)?;
            }
            revert_session.commit(db_size)?;
            revert_session.wal_session.end(false)?;
        }
        self.update_meta(coro, |meta| {
            meta.revert_since_wal_salt = main_wal_salt;
            meta.revert_since_wal_watermark = main_wal_state.max_frame;
        })
        .await?;

        let result = main_conn.checkpoint(turso_core::CheckpointMode::Truncate {
            upper_bound_inclusive: Some(main_wal_state.max_frame),
        })?;
        tracing::info!(
            "checkpoint(path={:?}): main DB TRUNCATE checkpoint result: {:?}",
            self.main_db_path,
            result
        );

        Ok(())
    }

    pub async fn wait_changes_from_remote<Ctx>(&self, coro: &Coro<Ctx>) -> Result<DbChangesStatus> {
        tracing::info!("wait_changes(path={})", self.main_db_path);

        let file = acquire_slot(&self.changes_file)?;

        let now = self.io.current_time_wall_clock();
        let revision = self.meta().synced_revision.clone();
        let ctx = &SyncOperationCtx::new(
            coro,
            &self.sync_engine_io,
            self.meta().remote_url(),
            self.opts.remote_encryption_key.as_deref(),
        );
        let next_revision = wal_pull_to_file(
            ctx,
            &file.value,
            &revision,
            self.opts.wal_pull_batch_size,
            self.opts.long_poll_timeout,
        )
        .await?;

        if file.value.size()? == 0 {
            tracing::info!(
                "wait_changes(path={}): no changes detected",
                self.main_db_path
            );
            return Ok(DbChangesStatus {
                time: now,
                revision: next_revision,
                file_slot: None,
            });
        }

        tracing::info!(
            "wait_changes_from_remote(path={}): revision: {:?} -> {:?}",
            self.main_db_path,
            revision,
            next_revision
        );

        Ok(DbChangesStatus {
            time: now,
            revision: next_revision,
            file_slot: Some(file),
        })
    }

    /// Sync all new changes from remote DB and apply them locally
    /// This method will **not** send local changed to the remote
    /// This method will block writes for the period of pull
    pub async fn apply_changes_from_remote<Ctx>(
        &self,
        coro: &Coro<Ctx>,
        remote_changes: DbChangesStatus,
    ) -> Result<()> {
        if remote_changes.file_slot.is_none() {
            self.update_meta(coro, |m| {
                m.last_pull_unix_time = Some(remote_changes.time.secs);
            })
            .await?;
            return Ok(());
        }
        assert!(remote_changes.file_slot.is_some(), "file_slot must be set");
        let changes_file = remote_changes.file_slot.as_ref().unwrap().value.clone();
        let pull_result = self.apply_changes_internal(coro, &changes_file).await;
        let Ok(revert_since_wal_watermark) = pull_result else {
            return Err(pull_result.err().unwrap());
        };

        let revert_wal_file = self.io.open_file(
            &self.revert_db_wal_path,
            turso_core::OpenFlags::Create,
            false,
        )?;
        reset_wal_file(coro, revert_wal_file, 0).await?;

        self.update_meta(coro, |m| {
            m.revert_since_wal_watermark = revert_since_wal_watermark;
            m.synced_revision = Some(remote_changes.revision);
            m.last_pushed_change_id_hint = 0;
            m.last_pull_unix_time = Some(remote_changes.time.secs);
        })
        .await?;
        Ok(())
    }
    async fn apply_changes_internal<Ctx>(
        &self,
        coro: &Coro<Ctx>,
        changes_file: &Arc<dyn turso_core::File>,
    ) -> Result<u64> {
        tracing::info!("apply_changes(path={})", self.main_db_path);

        let (_, watermark) = self.checkpoint_passive(coro).await?;

        let revert_conn = self.open_revert_db_conn(coro).await?;
        let main_conn = connect_untracked(&self.main_tape)?;

        let mut revert_session = WalSession::new(revert_conn.clone());
        revert_session.begin()?;

        // start of the pull updates apply process
        // during this process we need to be very careful with the state of the WAL as at some points it can be not safe to read data from it
        // the reasons why this can be not safe:
        // 1. we are in the middle of rollback or apply from remote WAL - so DB now is in some weird state and no operations can be made safely
        // 2. after rollback or apply from remote WAL it's unsafe to prepare statements because schema cookie can go "back in time" and we first need to adjust it before executing any statement over DB
        let mut main_session = WalSession::new(main_conn.clone());
        main_session.begin()?;

        // we need to make sure that updates from the session will not be commited accidentally in the middle of the pull process
        // in order to achieve that we mark current session as "nested program" which eliminates possibility that data will be actually commited without our explicit command
        //
        // the reason to not use auto-commit is because it has its own rules which resets the flag in case of statement reset - which we do under the hood sometimes
        // that's why nested executed was chosen instead of auto-commit=false mode
        main_conn.start_nested();

        let had_cdc_table = has_table(coro, &main_conn, "turso_cdc").await?;

        // read current pull generation from local table for the given client
        let (local_pull_gen, _) =
            read_last_change_id(coro, &main_conn, &self.client_unique_id).await?;

        // read schema version after initiating WAL session (in order to read it with consistent max_frame_no)
        // note, that as we initiated WAL session earlier - no changes can be made in between and we will have consistent race-free view of schema version
        let main_conn_schema_version = main_conn.read_schema_version()?;

        let mut main_session = DatabaseWalSession::new(coro, main_session).await?;

        // Phase 1 (start): rollback local changes from the WAL

        // Phase 1.a: rollback local changes not checkpointed to the revert-db
        tracing::info!(
            "apply_changes(path={}): rolling back frames after {} watermark, max_frame={}",
            self.main_db_path,
            watermark,
            main_conn.wal_state()?.max_frame
        );
        let local_rollback = main_session.rollback_changes_after(coro, watermark).await?;
        let mut frame = [0u8; WAL_FRAME_SIZE];

        let remote_rollback = revert_conn.wal_state()?.max_frame;
        tracing::info!(
            "apply_changes(path={}): rolling back {} frames from revert DB",
            self.main_db_path,
            remote_rollback
        );
        // Phase 1.b: rollback local changes by using frames from revert-db
        // it's important to append pages from revert-db after local revert - because pages from revert-db must overwrite rollback from main DB
        for frame_no in 1..=remote_rollback {
            let info = revert_session.read_at(frame_no, &mut frame)?;
            main_session.append_page(info.page_no, &frame[WAL_FRAME_HEADER..])?;
        }

        // Phase 2: after revert DB has no local changes in its latest state - so its safe to apply changes from remote
        let db_size = wal_apply_from_file(coro, changes_file, &mut main_session).await?;
        tracing::info!(
            "apply_changes(path={}): applied changes from remote: db_size={}",
            self.main_db_path,
            db_size,
        );

        main_session.commit(0)?;
        // now DB is equivalent to the some remote state (all local changes reverted, all remote changes applied)
        // remember this frame watermark as a checkpoint for revert for pull operations in future
        let revert_since_wal_watermark = main_session.frames_count()?;

        // Phase 3: DB now has sane WAL - but schema cookie can be arbitrary - so we need to bump it (potentially forcing re-prepare for cached statement)
        let current_schema_version = main_conn.read_schema_version()?;
        let final_schema_version = current_schema_version.max(main_conn_schema_version) + 1;
        main_conn.write_schema_version(final_schema_version)?;
        tracing::info!(
            "apply_changes(path={}): updated schema version to {}",
            self.main_db_path,
            final_schema_version
        );

        // Phase 4: as now DB has all data from remote - let's read pull generation and last change id for current client
        // we will use last_change_id in order to replay local changes made strictly after that id locally
        let (remote_pull_gen, remote_last_change_id) =
            read_last_change_id(coro, &main_conn, &self.client_unique_id).await?;

        // we update pull generation and last_change_id at remote on push, but locally its updated on pull
        // so its impossible to have remote pull generation to be greater than local one
        if remote_pull_gen > local_pull_gen {
            return Err(Error::DatabaseSyncEngineError(format!("protocol error: remote_pull_gen > local_pull_gen: {remote_pull_gen} > {local_pull_gen}")));
        }
        let last_change_id = if remote_pull_gen == local_pull_gen {
            // if remote_pull_gen == local_pull gen - this means that remote portion of WAL have overlap with our local changes
            // (because we did one or more push operations since last pull) - so we need to take some suffix of local changes for replay
            remote_last_change_id
        } else {
            // if remove_pull_gen < local_pull_gen - this means that remote portion of WAL have no overlaps with all our local changes and we need to replay all of them
            Some(0)
        };

        // Phase 5: collect local changes
        // note, that collecting chanages from main_conn will yield zero rows as we already rolled back everything from it
        // but since we didn't commited these changes yet - we can just collect changes from another connection
        let iterate_opts = DatabaseChangesIteratorOpts {
            first_change_id: last_change_id.map(|x| x + 1),
            mode: DatabaseChangesIteratorMode::Apply,
            ignore_schema_changes: false,
            ..Default::default()
        };
        let mut local_changes = Vec::new();
        {
            // it's important here that DatabaseTape create fresh connection under the hood
            let mut iterator = self.main_tape.iterate_changes(iterate_opts)?;
            while let Some(operation) = iterator.next(coro).await? {
                match operation {
                    DatabaseTapeOperation::StmtReplay(_) => {
                        panic!("changes iterator must not use StmtReplay option")
                    }
                    DatabaseTapeOperation::RowChange(change) => local_changes.push(change),
                    DatabaseTapeOperation::Commit => continue,
                }
            }
        }
        tracing::info!(
            "apply_changes(path={}): collected {} changes",
            self.main_db_path,
            local_changes.len()
        );

        // Phase 6: replay local changes
        // we can skip this phase if we are sure that we had no local changes before
        if !local_changes.is_empty() || local_rollback != 0 || remote_rollback != 0 || had_cdc_table
        {
            // first, we update last_change id in the local meta table for sync
            update_last_change_id(
                coro,
                &main_conn,
                &self.client_unique_id,
                local_pull_gen + 1,
                0,
            )
            .await
            .inspect_err(|e| tracing::error!("update_last_change_id failed: {e}"))?;

            if had_cdc_table {
                tracing::info!(
                    "apply_changes(path={}): initiate CDC pragma again in order to recreate CDC table",
                    self.main_db_path,
                );
                let _ = main_conn.pragma_update(CDC_PRAGMA_NAME, "'full'")?;
            }

            let mut replay = DatabaseReplaySession {
                conn: main_conn.clone(),
                cached_delete_stmt: HashMap::new(),
                cached_insert_stmt: HashMap::new(),
                cached_update_stmt: HashMap::new(),
                in_txn: true,
                generator: DatabaseReplayGenerator {
                    conn: main_conn.clone(),
                    opts: DatabaseReplaySessionOpts {
                        use_implicit_rowid: false,
                    },
                },
            };

            let mut transformed = if self.opts.use_transform {
                let ctx = &SyncOperationCtx::new(
                    coro,
                    &self.sync_engine_io,
                    self.meta().remote_url(),
                    self.opts.remote_encryption_key.as_deref(),
                );
                Some(apply_transformation(ctx, &local_changes, &replay.generator).await?)
            } else {
                None
            };

            assert!(!replay.conn().get_auto_commit());
            // Replay local changes collected on Phase 5
            for (i, change) in local_changes.into_iter().enumerate() {
                let operation = if let Some(transformed) = &mut transformed {
                    match std::mem::replace(&mut transformed[i], DatabaseRowTransformResult::Skip) {
                        DatabaseRowTransformResult::Keep => {
                            DatabaseTapeOperation::RowChange(change)
                        }
                        DatabaseRowTransformResult::Skip => continue,
                        DatabaseRowTransformResult::Rewrite(replay) => {
                            DatabaseTapeOperation::StmtReplay(replay)
                        }
                    }
                } else {
                    DatabaseTapeOperation::RowChange(change)
                };
                replay.replay(coro, operation).await?;
            }
            assert!(!replay.conn().get_auto_commit());
        }

        // Final: now we did all necessary operations as one big transaction and we are ready to commit
        main_conn.end_nested();
        main_session.wal_session.end(true)?;

        Ok(revert_since_wal_watermark)
    }

    /// Sync local changes to remote DB
    /// This method will **not** pull remote changes to the local DB
    /// This method will **not** block writes for the period of sync
    pub async fn push_changes_to_remote<Ctx>(&self, coro: &Coro<Ctx>) -> Result<()> {
        tracing::info!("push_changes(path={})", self.main_db_path);

        let ctx = &SyncOperationCtx::new(
            coro,
            &self.sync_engine_io,
            self.meta().remote_url(),
            self.opts.remote_encryption_key.as_deref(),
        );
        let (_, change_id) =
            push_logical_changes(ctx, &self.main_tape, &self.client_unique_id, &self.opts).await?;

        self.update_meta(coro, |m| {
            m.last_pushed_change_id_hint = change_id;
            m.last_push_unix_time = Some(self.io.current_time_wall_clock().secs);
        })
        .await?;

        Ok(())
    }

    /// Create read/write database connection and appropriately configure it before use
    pub async fn connect_rw<Ctx>(&self, coro: &Coro<Ctx>) -> Result<Arc<turso_core::Connection>> {
        let conn = self.main_tape.connect(coro).await?;
        assert!(
            conn.is_wal_auto_checkpoint_disabled(),
            "tape must be configured to have autocheckpoint disabled"
        );
        Ok(conn)
    }

    /// Sync local changes to remote DB and bring new changes from remote to local
    /// This method will block writes for the period of sync
    pub async fn sync<Ctx>(&self, coro: &Coro<Ctx>) -> Result<()> {
        // todo(sivukhin): this is bit suboptimal as both 'push' and 'pull' will call pull_synced_from_remote
        // but for now - keep it simple
        self.push_changes_to_remote(coro).await?;
        self.pull_changes_from_remote(coro).await?;
        Ok(())
    }

    pub async fn pull_changes_from_remote<Ctx>(&self, coro: &Coro<Ctx>) -> Result<()> {
        let changes = self.wait_changes_from_remote(coro).await?;
        self.apply_changes_from_remote(coro, changes).await?;
        Ok(())
    }

    fn meta(&self) -> std::sync::MutexGuard<'_, DatabaseMetadata> {
        self.meta.lock().unwrap()
    }

    async fn update_meta<Ctx>(
        &self,
        coro: &Coro<Ctx>,
        update: impl FnOnce(&mut DatabaseMetadata),
    ) -> Result<()> {
        let mut meta = self.meta().clone();
        update(&mut meta);
        tracing::info!("update_meta: {meta:?}");
        full_write(
            coro,
            self.io.clone(),
            self.sync_engine_io.io.clone(),
            &self.meta_path,
            is_memory(&self.main_db_path),
            meta.dump()?,
        )
        .await?;
        // todo: what happen if we will actually update the metadata on disk but fail and so in memory state will not be updated
        *self.meta.lock().unwrap() = meta;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        path::Path,
        sync::{Arc, Mutex},
    };

    use bytes::Bytes;
    use genawaiter::GeneratorState;
    use prost::Message;
    use quint_connect::{quint_run, switch, Driver, Step};
    use roaring::RoaringBitmap;
    use tempfile::NamedTempFile;
    use turso_core::{types::WalFrameInfo, CheckpointMode, OpenFlags, PlatformIO, Value};

    use crate::{
        database_sync_engine_io::{DataCompletion, DataPollResult, SyncEngineIo},
        database_sync_operations::{
            acquire_slot, bootstrap_db_file, connect_untracked, reset_wal_file, PAGE_SIZE,
            WAL_FRAME_HEADER, WAL_FRAME_SIZE,
        },
        database_tape::{run_stmt_once, DatabaseWalSession},
        server_proto::{
            BatchCond, BatchResult, BatchStreamReq, BatchStreamResp, Col, Error as HranaError,
            ExecuteStreamReq, ExecuteStreamResp, PipelineReqBody, PipelineRespBody, Row,
            StmtResult, StreamRequest, StreamResponse, StreamResult, Value as HranaValue,
        },
        types::{
            Coro, DatabaseMetadata, DatabasePullRevision, DatabaseRowTransformResult,
            DatabaseSavedConfiguration, DatabaseSyncEngineProtocolVersion, DbChangesStatus,
            PartialBootstrapStrategy, PartialSyncOpts, SyncEngineIoResult,
            DATABASE_METADATA_VERSION,
        },
        wal_session::WalSession,
    };

    use super::{
        create_changes_path, create_meta_path, create_revert_db_wal_path, db_size_from_page,
        DatabaseSyncEngine, DatabaseSyncEngineOpts,
    };

    #[derive(Clone)]
    struct TestPollResult<T>(Vec<T>);

    impl<T: Send + Sync + 'static> DataPollResult<T> for TestPollResult<T> {
        fn data(&self) -> &[T] {
            &self.0
        }
    }

    struct TestCompletion<T> {
        status: Option<u16>,
        data: Mutex<Option<Vec<T>>>,
    }

    impl<T: Clone + Send + Sync + 'static> DataCompletion<T> for TestCompletion<T> {
        type DataPollResult = TestPollResult<T>;

        fn status(&self) -> crate::Result<Option<u16>> {
            Ok(self.status)
        }

        fn poll_data(&self) -> crate::Result<Option<Self::DataPollResult>> {
            Ok(self.data.lock().unwrap().take().map(TestPollResult))
        }

        fn is_done(&self) -> crate::Result<bool> {
            Ok(self.data.lock().unwrap().is_none())
        }
    }

    #[derive(Default)]
    struct TestSyncEngineIo;

    impl TestSyncEngineIo {
        fn done_bytes(data: Vec<u8>) -> TestCompletion<u8> {
            TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(data)),
            }
        }
    }

    impl SyncEngineIo for TestSyncEngineIo {
        type DataCompletionBytes = TestCompletion<u8>;
        type DataCompletionTransform = TestCompletion<DatabaseRowTransformResult>;

        fn full_read(&self, path: &str) -> crate::Result<Self::DataCompletionBytes> {
            let data = std::fs::read(path).unwrap_or_default();
            Ok(Self::done_bytes(data))
        }

        fn full_write(
            &self,
            path: &str,
            content: Vec<u8>,
        ) -> crate::Result<Self::DataCompletionBytes> {
            std::fs::write(path, content)?;
            Ok(Self::done_bytes(Vec::new()))
        }

        fn transform(
            &self,
            mutations: Vec<crate::types::DatabaseRowMutation>,
        ) -> crate::Result<Self::DataCompletionTransform> {
            Ok(TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(
                    mutations
                        .into_iter()
                        .map(|_| DatabaseRowTransformResult::Keep)
                        .collect(),
                )),
            })
        }

        fn http(
            &self,
            _url: Option<&str>,
            _method: &str,
            _path: &str,
            _body: Option<Vec<u8>>,
            _headers: &[(&str, &str)],
        ) -> crate::Result<Self::DataCompletionBytes> {
            panic!("this test drives sync internals without HTTP")
        }

        fn add_io_callback(&self, _callback: Box<dyn FnMut() -> bool + Send>) {}

        fn step_io_callbacks(&self) {}
    }

    struct TestRemoteSyncEngineIo {
        remote_conn: Arc<turso_core::Connection>,
    }

    impl TestRemoteSyncEngineIo {
        fn new(remote_conn: Arc<turso_core::Connection>) -> Self {
            Self { remote_conn }
        }

        fn done_bytes(data: Vec<u8>) -> TestCompletion<u8> {
            TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(data)),
            }
        }

        fn pipeline_response(&self, body: &[u8]) -> crate::Result<Vec<u8>> {
            let request: PipelineReqBody = serde_json::from_slice(body)?;
            let results = request
                .requests
                .into_iter()
                .map(|request| match request {
                    StreamRequest::Execute(request) => self
                        .execute_statement(&request)
                        .unwrap_or_else(Self::hrana_error),
                    StreamRequest::Batch(request) => self
                        .execute_batch(&request)
                        .unwrap_or_else(Self::hrana_error),
                    StreamRequest::None => Self::hrana_error("unknown stream request".to_string()),
                })
                .collect();
            let response = PipelineRespBody {
                baton: request.baton,
                base_url: None,
                results,
            };
            Ok(serde_json::to_vec(&response)?)
        }

        fn execute_statement(&self, request: &ExecuteStreamReq) -> Result<StreamResult, String> {
            let result = self.execute_stmt(&request.stmt)?;
            Ok(StreamResult::Ok {
                response: StreamResponse::Execute(ExecuteStreamResp { result }),
            })
        }

        fn execute_batch(&self, request: &BatchStreamReq) -> Result<StreamResult, String> {
            let mut step_results = Vec::with_capacity(request.batch.steps.len());
            let mut step_errors = Vec::with_capacity(request.batch.steps.len());

            for step in &request.batch.steps {
                let should_execute = Self::condition_matches(
                    &step.condition,
                    &step_results,
                    &step_errors,
                    &self.remote_conn,
                );
                if !should_execute {
                    step_results.push(None);
                    step_errors.push(None);
                    continue;
                }

                match self.execute_stmt(&step.stmt) {
                    Ok(result) => {
                        step_results.push(Some(result));
                        step_errors.push(None);
                    }
                    Err(error) => {
                        step_results.push(None);
                        step_errors.push(Some(HranaError {
                            message: error,
                            code: "BATCH_STEP_ERROR".to_string(),
                        }));
                    }
                }
            }

            Ok(StreamResult::Ok {
                response: StreamResponse::Batch(BatchStreamResp {
                    result: BatchResult {
                        step_results,
                        step_errors,
                        replication_index: None,
                    },
                }),
            })
        }

        fn execute_stmt(&self, stmt: &crate::server_proto::Stmt) -> Result<StmtResult, String> {
            let sql = stmt
                .sql
                .as_deref()
                .ok_or_else(|| "missing SQL".to_string())?;
            let mut prepared = self
                .remote_conn
                .prepare(sql)
                .map_err(|error| error.to_string())?;
            for (i, arg) in stmt.args.iter().enumerate() {
                prepared.bind_at(
                    std::num::NonZero::new(i + 1).unwrap(),
                    Self::hrana_to_core(arg),
                );
            }

            if stmt.want_rows.unwrap_or(true) {
                let rows = prepared
                    .run_collect_rows()
                    .map_err(|error| error.to_string())?;
                let cols = (0..prepared.num_columns())
                    .map(|i| Col {
                        name: Some(prepared.get_column_name(i).to_string()),
                        decltype: prepared.get_column_decltype(i),
                    })
                    .collect();
                Ok(StmtResult {
                    cols,
                    rows: rows
                        .into_iter()
                        .map(|row| Row {
                            values: row.into_iter().map(Self::core_to_hrana).collect(),
                        })
                        .collect(),
                    affected_row_count: 0,
                    last_insert_rowid: None,
                    replication_index: None,
                    rows_read: 0,
                    rows_written: 0,
                    query_duration_ms: 0.0,
                })
            } else {
                prepared
                    .run_ignore_rows()
                    .map_err(|error| error.to_string())?;
                Ok(StmtResult {
                    cols: Vec::new(),
                    rows: Vec::new(),
                    affected_row_count: 0,
                    last_insert_rowid: None,
                    replication_index: None,
                    rows_read: 0,
                    rows_written: 0,
                    query_duration_ms: 0.0,
                })
            }
        }

        fn condition_matches(
            condition: &Option<BatchCond>,
            step_results: &[Option<StmtResult>],
            step_errors: &[Option<HranaError>],
            conn: &Arc<turso_core::Connection>,
        ) -> bool {
            match condition {
                None | Some(BatchCond::None) => true,
                Some(BatchCond::Ok { step }) => step_results
                    .get(*step as usize)
                    .is_some_and(|result| result.is_some()),
                Some(BatchCond::Error { step }) => step_errors
                    .get(*step as usize)
                    .is_some_and(|error| error.is_some()),
                Some(BatchCond::Not { cond }) => !Self::condition_matches(
                    &Some((**cond).clone()),
                    step_results,
                    step_errors,
                    conn,
                ),
                Some(BatchCond::And(list)) => list.conds.iter().all(|cond| {
                    Self::condition_matches(&Some(cond.clone()), step_results, step_errors, conn)
                }),
                Some(BatchCond::Or(list)) => list.conds.iter().any(|cond| {
                    Self::condition_matches(&Some(cond.clone()), step_results, step_errors, conn)
                }),
                Some(BatchCond::IsAutocommit {}) => conn.get_auto_commit(),
            }
        }

        fn hrana_to_core(value: &HranaValue) -> turso_core::Value {
            match value {
                HranaValue::None | HranaValue::Null => turso_core::Value::Null,
                HranaValue::Integer { value } => turso_core::Value::from_i64(*value),
                HranaValue::Float { value } => turso_core::Value::from_f64(*value),
                HranaValue::Text { value } => turso_core::Value::Text(turso_core::types::Text {
                    value: std::borrow::Cow::Owned(value.clone()),
                    subtype: turso_core::types::TextSubtype::Text,
                }),
                HranaValue::Blob { value } => turso_core::Value::Blob(value.to_vec()),
            }
        }

        fn core_to_hrana(value: turso_core::Value) -> HranaValue {
            match value {
                turso_core::Value::Null => HranaValue::Null,
                turso_core::Value::Numeric(turso_core::Numeric::Integer(value)) => {
                    HranaValue::Integer { value }
                }
                turso_core::Value::Numeric(turso_core::Numeric::Float(value)) => {
                    HranaValue::Float {
                        value: f64::from(value),
                    }
                }
                turso_core::Value::Text(value) => HranaValue::Text {
                    value: value.value.to_string(),
                },
                turso_core::Value::Blob(value) => HranaValue::Blob {
                    value: Bytes::from(value),
                },
            }
        }

        fn hrana_error(message: String) -> StreamResult {
            StreamResult::Error {
                error: HranaError {
                    message,
                    code: "TEST_REMOTE_ERROR".to_string(),
                },
            }
        }
    }

    impl SyncEngineIo for TestRemoteSyncEngineIo {
        type DataCompletionBytes = TestCompletion<u8>;
        type DataCompletionTransform = TestCompletion<DatabaseRowTransformResult>;

        fn full_read(&self, path: &str) -> crate::Result<Self::DataCompletionBytes> {
            let data = std::fs::read(path).unwrap_or_default();
            Ok(Self::done_bytes(data))
        }

        fn full_write(
            &self,
            path: &str,
            content: Vec<u8>,
        ) -> crate::Result<Self::DataCompletionBytes> {
            std::fs::write(path, content)?;
            Ok(Self::done_bytes(Vec::new()))
        }

        fn transform(
            &self,
            mutations: Vec<crate::types::DatabaseRowMutation>,
        ) -> crate::Result<Self::DataCompletionTransform> {
            Ok(TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(
                    mutations
                        .into_iter()
                        .map(|_| DatabaseRowTransformResult::Keep)
                        .collect(),
                )),
            })
        }

        fn http(
            &self,
            _url: Option<&str>,
            method: &str,
            path: &str,
            body: Option<Vec<u8>>,
            _headers: &[(&str, &str)],
        ) -> crate::Result<Self::DataCompletionBytes> {
            assert_eq!(method, "POST");
            assert_eq!(path, "/v2/pipeline");
            let body = body.unwrap_or_default();
            Ok(Self::done_bytes(self.pipeline_response(&body)?))
        }

        fn add_io_callback(&self, _callback: Box<dyn FnMut() -> bool + Send>) {}

        fn step_io_callbacks(&self) {}
    }

    struct TestTransformRemoteSyncEngineIo {
        remote: TestRemoteSyncEngineIo,
        skip_rowids: HashSet<i64>,
        calls: Arc<Mutex<Vec<i64>>>,
    }

    impl TestTransformRemoteSyncEngineIo {
        fn new(remote_conn: Arc<turso_core::Connection>, skip_rowids: &[i64]) -> Self {
            Self {
                remote: TestRemoteSyncEngineIo::new(remote_conn),
                skip_rowids: skip_rowids.iter().copied().collect(),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn done_bytes(data: Vec<u8>) -> TestCompletion<u8> {
            TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(data)),
            }
        }

        fn calls_for(&self, rowid: i64) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|seen| **seen == rowid)
                .count()
        }
    }

    impl SyncEngineIo for TestTransformRemoteSyncEngineIo {
        type DataCompletionBytes = TestCompletion<u8>;
        type DataCompletionTransform = TestCompletion<DatabaseRowTransformResult>;

        fn full_read(&self, path: &str) -> crate::Result<Self::DataCompletionBytes> {
            let data = std::fs::read(path).unwrap_or_default();
            Ok(Self::done_bytes(data))
        }

        fn full_write(
            &self,
            path: &str,
            content: Vec<u8>,
        ) -> crate::Result<Self::DataCompletionBytes> {
            std::fs::write(path, content)?;
            Ok(Self::done_bytes(Vec::new()))
        }

        fn transform(
            &self,
            mutations: Vec<crate::types::DatabaseRowMutation>,
        ) -> crate::Result<Self::DataCompletionTransform> {
            let mut calls = self.calls.lock().unwrap();
            let transformed = mutations
                .into_iter()
                .map(|mutation| {
                    calls.push(mutation.id);
                    if self.skip_rowids.contains(&mutation.id) {
                        DatabaseRowTransformResult::Skip
                    } else {
                        DatabaseRowTransformResult::Keep
                    }
                })
                .collect();
            Ok(TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(transformed)),
            })
        }

        fn http(
            &self,
            _url: Option<&str>,
            method: &str,
            path: &str,
            body: Option<Vec<u8>>,
            _headers: &[(&str, &str)],
        ) -> crate::Result<Self::DataCompletionBytes> {
            assert_eq!(method, "POST");
            assert_eq!(path, "/v2/pipeline");
            let body = body.unwrap_or_default();
            Ok(Self::done_bytes(self.remote.pipeline_response(&body)?))
        }

        fn add_io_callback(&self, _callback: Box<dyn FnMut() -> bool + Send>) {}

        fn step_io_callbacks(&self) {}
    }

    struct TestPartialBootstrapSyncEngineIo {
        db_pages: u64,
        selectors: Arc<Mutex<Vec<Vec<u32>>>>,
        revisions: Arc<Mutex<Vec<String>>>,
    }

    impl TestPartialBootstrapSyncEngineIo {
        fn new(db_pages: u64) -> Self {
            Self {
                db_pages,
                selectors: Arc::new(Mutex::new(Vec::new())),
                revisions: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn done_bytes(data: Vec<u8>) -> TestCompletion<u8> {
            TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(data)),
            }
        }

        fn selector_requests(&self) -> Vec<Vec<u32>> {
            self.selectors.lock().unwrap().clone()
        }

        fn revision_requests(&self) -> Vec<String> {
            self.revisions.lock().unwrap().clone()
        }

        fn response_for_pull_updates(&self, body: &[u8]) -> crate::Result<Vec<u8>> {
            let request =
                crate::server_proto::PullUpdatesReqProtoBody::decode(body).map_err(|error| {
                    crate::errors::Error::DatabaseSyncEngineError(error.to_string())
                })?;
            self.revisions
                .lock()
                .unwrap()
                .push(request.server_revision.clone());
            let selected_pages = if request.server_pages_selector.is_empty() {
                (0..self.db_pages as u32).collect::<Vec<_>>()
            } else {
                let bitmap =
                    RoaringBitmap::deserialize_from(&mut request.server_pages_selector.as_ref())?;
                bitmap.iter().collect::<Vec<_>>()
            };
            self.selectors.lock().unwrap().push(selected_pages.clone());

            let mut response = Vec::new();
            let header = crate::server_proto::PullUpdatesRespProtoBody {
                server_revision: "rev1".to_string(),
                db_size: self.db_pages,
                raw_encoding: Some(crate::server_proto::PageSetRawEncodingProto {}),
                zstd_encoding: None,
            };
            response.extend_from_slice(&header.encode_length_delimited_to_vec());
            for page_id in selected_pages {
                let page = crate::server_proto::PageData {
                    page_id: page_id as u64,
                    encoded_page: vec![page_id as u8; PAGE_SIZE].into(),
                };
                response.extend_from_slice(&page.encode_length_delimited_to_vec());
            }
            Ok(response)
        }
    }

    impl SyncEngineIo for TestPartialBootstrapSyncEngineIo {
        type DataCompletionBytes = TestCompletion<u8>;
        type DataCompletionTransform = TestCompletion<DatabaseRowTransformResult>;

        fn full_read(&self, path: &str) -> crate::Result<Self::DataCompletionBytes> {
            let data = std::fs::read(path).unwrap_or_default();
            Ok(Self::done_bytes(data))
        }

        fn full_write(
            &self,
            path: &str,
            content: Vec<u8>,
        ) -> crate::Result<Self::DataCompletionBytes> {
            std::fs::write(path, content)?;
            Ok(Self::done_bytes(Vec::new()))
        }

        fn transform(
            &self,
            mutations: Vec<crate::types::DatabaseRowMutation>,
        ) -> crate::Result<Self::DataCompletionTransform> {
            Ok(TestCompletion {
                status: Some(200),
                data: Mutex::new(Some(
                    mutations
                        .into_iter()
                        .map(|_| DatabaseRowTransformResult::Keep)
                        .collect(),
                )),
            })
        }

        fn http(
            &self,
            _url: Option<&str>,
            method: &str,
            path: &str,
            body: Option<Vec<u8>>,
            _headers: &[(&str, &str)],
        ) -> crate::Result<Self::DataCompletionBytes> {
            assert_eq!(method, "POST");
            assert_eq!(path, "/pull-updates");
            let body = body.unwrap_or_default();
            Ok(Self::done_bytes(self.response_for_pull_updates(&body)?))
        }

        fn add_io_callback(&self, _callback: Box<dyn FnMut() -> bool + Send>) {}

        fn step_io_callbacks(&self) {}
    }

    fn run_with_io<T>(
        io: Arc<dyn turso_core::IO>,
        f: impl FnOnce(Coro<()>) -> std::pin::Pin<Box<dyn std::future::Future<Output = T>>>,
    ) -> T {
        let mut gen = genawaiter::sync::Gen::new(|co| async move {
            let coro = Coro::from(co);
            f(coro).await
        });

        loop {
            match gen.resume_with(Ok(())) {
                GeneratorState::Yielded(SyncEngineIoResult::IO) => io.step().unwrap(),
                GeneratorState::Complete(result) => return result,
            }
        }
    }

    fn sync_opts() -> DatabaseSyncEngineOpts {
        DatabaseSyncEngineOpts {
            remote_url: None,
            client_name: "sync-crash-test".to_string(),
            tables_ignore: Vec::new(),
            use_transform: false,
            wal_pull_batch_size: 100,
            long_poll_timeout: None,
            protocol_version_hint: DatabaseSyncEngineProtocolVersion::V1,
            bootstrap_if_empty: false,
            reserved_bytes: 0,
            partial_sync_opts: None,
            remote_encryption_key: None,
            push_operations_threshold: None,
            pull_bytes_threshold: None,
        }
    }

    fn sync_transform_opts() -> DatabaseSyncEngineOpts {
        DatabaseSyncEngineOpts {
            use_transform: true,
            ..sync_opts()
        }
    }

    fn partial_prefix_bootstrap_request_trace(
        prefix_len: usize,
        pull_bytes_threshold: Option<usize>,
    ) -> (Vec<Vec<u32>>, Vec<String>) {
        let dst = NamedTempFile::new().unwrap();
        let dst_path = dst.path().to_str().unwrap().to_string();
        let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());
        let sync_io = Arc::new(TestPartialBootstrapSyncEngineIo::new(4));
        run_with_io(io.clone(), {
            let sync_io = sync_io.clone();
            move |coro| {
                Box::pin(async move {
                    let stats = crate::database_sync_operations::SyncEngineIoStats::new(sync_io);
                    let ctx = crate::database_sync_operations::SyncOperationCtx::new(
                        &coro, &stats, None, None,
                    );
                    let revision = bootstrap_db_file(
                        &ctx,
                        &io,
                        &dst_path,
                        DatabaseSyncEngineProtocolVersion::V1,
                        Some(PartialSyncOpts {
                            bootstrap_strategy: Some(PartialBootstrapStrategy::Prefix {
                                length: prefix_len,
                            }),
                            segment_size: 0,
                            prefetch: false,
                        }),
                        pull_bytes_threshold,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        revision,
                        DatabasePullRevision::V1 {
                            revision: "rev1".to_string()
                        }
                    );
                })
            }
        });
        (sync_io.selector_requests(), sync_io.revision_requests())
    }

    fn write_initial_meta(path: &str) {
        let meta = DatabaseMetadata {
            version: DATABASE_METADATA_VERSION.to_string(),
            client_unique_id: "dst-client".to_string(),
            synced_revision: Some(DatabasePullRevision::V1 {
                revision: "rev0".to_string(),
            }),
            revert_since_wal_salt: None,
            revert_since_wal_watermark: 0,
            last_pull_unix_time: None,
            last_push_unix_time: None,
            last_pushed_pull_gen_hint: 0,
            last_pushed_change_id_hint: 0,
            partial_bootstrap_server_revision: None,
            saved_configuration: Some(DatabaseSavedConfiguration {
                remote_url: None,
                partial_sync_prefetch: None,
                partial_sync_segment_size: None,
            }),
        };
        std::fs::write(create_meta_path(path), meta.dump().unwrap()).unwrap();
    }

    fn checkpoint(conn: &Arc<turso_core::Connection>) {
        conn.checkpoint(CheckpointMode::Truncate {
            upper_bound_inclusive: None,
        })
        .unwrap();
    }

    fn source_snapshot(sql: &[&str]) -> Vec<u8> {
        let source = NamedTempFile::new().unwrap();
        let source_path = source.path().to_str().unwrap();
        let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());
        let db = turso_core::Database::open_file(io, source_path).unwrap();
        let conn = db.connect().unwrap();

        for stmt in sql {
            conn.execute(stmt).unwrap();
        }
        checkpoint(&conn);

        std::fs::read(source_path).unwrap()
    }

    fn snapshot_to_frames(snapshot: &[u8]) -> Vec<u8> {
        assert_eq!(
            snapshot.len() % crate::database_sync_operations::PAGE_SIZE,
            0
        );
        let page_count = snapshot.len() / crate::database_sync_operations::PAGE_SIZE;
        let mut frames = Vec::with_capacity(page_count * WAL_FRAME_SIZE);

        for (page_idx, page) in snapshot
            .chunks_exact(crate::database_sync_operations::PAGE_SIZE)
            .enumerate()
        {
            let mut frame = vec![0; WAL_FRAME_SIZE];
            let info = WalFrameInfo {
                page_no: (page_idx + 1) as u32,
                db_size: if page_idx + 1 == page_count {
                    page_count as u32
                } else {
                    0
                },
            };
            info.put_to_frame_header(&mut frame);
            frame[WAL_FRAME_HEADER..].copy_from_slice(page);
            frames.extend_from_slice(&frame);
        }

        frames
    }

    fn write_file(path: impl AsRef<Path>, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    async fn open_engine(
        coro: &Coro<()>,
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestSyncEngineIo>,
        path: &str,
    ) -> DatabaseSyncEngine<TestSyncEngineIo> {
        let sync_io = crate::database_sync_operations::SyncEngineIoStats::new(sync_io);
        DatabaseSyncEngine::create_db(coro, io, sync_io, path, sync_opts())
            .await
            .unwrap()
    }

    async fn open_remote_engine(
        coro: &Coro<()>,
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestRemoteSyncEngineIo>,
        path: &str,
    ) -> DatabaseSyncEngine<TestRemoteSyncEngineIo> {
        let sync_io = crate::database_sync_operations::SyncEngineIoStats::new(sync_io);
        DatabaseSyncEngine::create_db(coro, io, sync_io, path, sync_opts())
            .await
            .unwrap()
    }

    async fn open_transform_remote_engine(
        coro: &Coro<()>,
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestTransformRemoteSyncEngineIo>,
        path: &str,
    ) -> DatabaseSyncEngine<TestTransformRemoteSyncEngineIo> {
        let sync_io = crate::database_sync_operations::SyncEngineIoStats::new(sync_io);
        DatabaseSyncEngine::create_db(coro, io, sync_io, path, sync_transform_opts())
            .await
            .unwrap()
    }

    fn seed_base_row(io: Arc<dyn turso_core::IO>, path: &str) -> Arc<turso_core::Connection> {
        let db = turso_core::Database::open_file(io, path).unwrap();
        let conn = db.connect().unwrap();
        conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
            .unwrap();
        conn.execute("INSERT INTO t VALUES (1, 'base')").unwrap();
        checkpoint(&conn);
        conn
    }

    fn seed_empty_t(io: Arc<dyn turso_core::IO>, path: &str) -> Arc<turso_core::Connection> {
        let db = turso_core::Database::open_file(io, path).unwrap();
        let conn = db.connect().unwrap();
        conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
            .unwrap();
        checkpoint(&conn);
        conn
    }

    fn read_remote_t(conn: &Arc<turso_core::Connection>) -> Vec<(i64, String)> {
        let mut stmt = conn.prepare("SELECT id, v FROM t ORDER BY id").unwrap();
        stmt.run_collect_rows()
            .unwrap()
            .into_iter()
            .map(|row| {
                let id = match &row[0] {
                    Value::Numeric(turso_core::Numeric::Integer(value)) => *value,
                    value => panic!("unexpected id value: {value:?}"),
                };
                let text = match &row[1] {
                    Value::Text(value) => value.value.to_string(),
                    value => panic!("unexpected text value: {value:?}"),
                };
                (id, text)
            })
            .collect()
    }

    fn read_remote_cursor(conn: &Arc<turso_core::Connection>) -> Option<i64> {
        let mut stmt = conn
            .prepare("SELECT change_id FROM turso_sync_last_change_id")
            .unwrap();
        let rows = stmt.run_collect_rows().unwrap();
        match rows.as_slice() {
            [] => None,
            [row] => match &row[0] {
                Value::Numeric(turso_core::Numeric::Integer(value)) => Some(*value),
                value => panic!("unexpected cursor value: {value:?}"),
            },
            rows => panic!("unexpected cursor rows: {rows:?}"),
        }
    }

    async fn read_engine_t<IO: SyncEngineIo>(
        coro: &Coro<()>,
        engine: &DatabaseSyncEngine<IO>,
    ) -> Vec<(i64, String)> {
        let conn = engine.connect_rw(coro).await.unwrap();
        read_remote_t(&conn)
    }

    async fn read_t_values(
        coro: &Coro<()>,
        engine: &DatabaseSyncEngine<TestSyncEngineIo>,
    ) -> Vec<i64> {
        let conn = engine.connect_rw(coro).await.unwrap();
        let mut stmt = conn.prepare("SELECT x FROM t ORDER BY x").unwrap();
        let mut rows = Vec::new();
        while let Some(row) = run_stmt_once(coro, &mut stmt).await.unwrap() {
            let value = row.get_value(0);
            let Value::Numeric(turso_core::Numeric::Integer(value)) = value else {
                panic!("unexpected value: {value:?}");
            };
            rows.push(*value);
        }
        rows
    }

    fn crash_after_revert_reset(
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestSyncEngineIo>,
        dst_path: String,
        frames: Vec<u8>,
    ) {
        run_with_io(io.clone(), {
            let sync_io = sync_io.clone();
            let io = io.clone();
            move |coro| {
                Box::pin(async move {
                    let engine = open_engine(&coro, io.clone(), sync_io.clone(), &dst_path).await;
                    write_file(create_changes_path(&dst_path), &frames);

                    let changes_file = io
                        .open_file(&create_changes_path(&dst_path), OpenFlags::Create, false)
                        .unwrap();
                    let watermark = engine
                        .apply_changes_internal(&coro, &changes_file)
                        .await
                        .unwrap();
                    let revert_wal = io
                        .open_file(
                            &create_revert_db_wal_path(&dst_path),
                            OpenFlags::Create,
                            false,
                        )
                        .unwrap();
                    reset_wal_file(&coro, revert_wal, 0).await.unwrap();
                    assert!(watermark > 0);
                })
            }
        });
    }

    fn apply_remote_snapshot(
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestSyncEngineIo>,
        dst_path: String,
        revision: &str,
        frames: Vec<u8>,
    ) -> Vec<i64> {
        run_with_io(io.clone(), {
            let sync_io = sync_io.clone();
            let io = io.clone();
            let revision = revision.to_string();
            move |coro| {
                Box::pin(async move {
                    let engine = open_engine(&coro, io.clone(), sync_io.clone(), &dst_path).await;
                    write_file(create_changes_path(&dst_path), &frames);
                    let remote_changes = DbChangesStatus {
                        time: io.current_time_wall_clock(),
                        revision: DatabasePullRevision::V1 { revision },
                        file_slot: Some(acquire_slot(&engine.changes_file).unwrap()),
                    };
                    engine
                        .apply_changes_from_remote(&coro, remote_changes)
                        .await
                        .unwrap();
                    read_t_values(&coro, &engine).await
                })
            }
        })
    }

    fn apply_remote_snapshot_t_with_transform(
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestTransformRemoteSyncEngineIo>,
        dst_path: String,
        revision: &str,
        frames: Vec<u8>,
    ) -> Vec<(i64, String)> {
        run_with_io(io.clone(), {
            let sync_io = sync_io.clone();
            let io = io.clone();
            let revision = revision.to_string();
            move |coro| {
                Box::pin(async move {
                    let engine =
                        open_transform_remote_engine(&coro, io.clone(), sync_io, &dst_path).await;
                    write_file(create_changes_path(&dst_path), &frames);
                    let remote_changes = DbChangesStatus {
                        time: io.current_time_wall_clock(),
                        revision: DatabasePullRevision::V1 { revision },
                        file_slot: Some(acquire_slot(&engine.changes_file).unwrap()),
                    };
                    engine
                        .apply_changes_from_remote(&coro, remote_changes)
                        .await
                        .unwrap();
                    read_engine_t(&coro, &engine).await
                })
            }
        })
    }

    fn local_insert_t_with_transform(
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestTransformRemoteSyncEngineIo>,
        path: String,
        id: i64,
        value: &str,
    ) -> Vec<(i64, String)> {
        run_with_io(io.clone(), {
            let value = value.to_string();
            move |coro| {
                Box::pin(async move {
                    let engine = open_transform_remote_engine(&coro, io, sync_io, &path).await;
                    let conn = engine.connect_rw(&coro).await.unwrap();
                    conn.execute(&format!("INSERT INTO t VALUES ({id}, '{value}')"))
                        .unwrap();
                    read_engine_t(&coro, &engine).await
                })
            }
        })
    }

    async fn checkpoint_until_meta_update_before_main_truncate(
        coro: &Coro<()>,
        engine: &DatabaseSyncEngine<TestSyncEngineIo>,
    ) {
        let (main_wal_salt, watermark) = engine.checkpoint_passive(coro).await.unwrap();
        let main_conn = connect_untracked(&engine.main_tape).unwrap();
        let revert_conn = engine.open_revert_db_conn(coro).await.unwrap();

        let mut page = [0; PAGE_SIZE];
        let db_size = if revert_conn
            .try_wal_watermark_read_page(1, &mut page, None)
            .unwrap()
        {
            db_size_from_page(&page)
        } else {
            0
        };

        let main_wal_state;
        {
            let mut revert_session = WalSession::new(revert_conn.clone());
            revert_session.begin().unwrap();

            let mut main_session = WalSession::new(main_conn.clone());
            main_session.begin().unwrap();

            main_wal_state = main_conn.wal_state().unwrap();
            let mut revert_session = DatabaseWalSession::new(coro, revert_session).await.unwrap();

            let main_changed_pages = main_conn.wal_changed_pages_after(watermark).unwrap();
            let revert_changed_pages: HashSet<u32> = revert_conn
                .wal_changed_pages_after(0)
                .unwrap()
                .into_iter()
                .collect();

            for page_no in main_changed_pages {
                if revert_changed_pages.contains(&page_no) || page_no > db_size {
                    continue;
                }

                let begin_read_result = main_conn
                    .try_wal_watermark_read_page_begin(page_no, Some(watermark))
                    .unwrap();
                let end_read_result = match begin_read_result {
                    Some((page_ref, completion)) => {
                        while !completion.succeeded() {
                            coro.yield_(SyncEngineIoResult::IO).await.unwrap();
                        }
                        main_conn
                            .try_wal_watermark_read_page_end(&mut page, page_ref)
                            .unwrap()
                    }
                    None => false,
                };
                if end_read_result {
                    revert_session.append_page(page_no, &page).unwrap();
                }
            }

            revert_session.commit(db_size).unwrap();
            revert_session.wal_session.end(false).unwrap();
        }

        engine
            .update_meta(coro, |meta| {
                meta.revert_since_wal_salt = main_wal_salt;
                meta.revert_since_wal_watermark = main_wal_state.max_frame;
            })
            .await
            .unwrap();
    }

    struct SyncLastPushWinsQuintConnectDriver {
        client_a: NamedTempFile,
        client_b: NamedTempFile,
        _remote: NamedTempFile,
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestRemoteSyncEngineIo>,
        remote_conn: Arc<turso_core::Connection>,
    }

    impl Default for SyncLastPushWinsQuintConnectDriver {
        fn default() -> Self {
            let client_a = NamedTempFile::new().unwrap();
            let client_b = NamedTempFile::new().unwrap();
            let remote = NamedTempFile::new().unwrap();
            let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());

            seed_base_row(io.clone(), client_a.path().to_str().unwrap());
            seed_base_row(io.clone(), client_b.path().to_str().unwrap());
            let remote_conn = seed_base_row(io.clone(), remote.path().to_str().unwrap());

            Self {
                client_a,
                client_b,
                _remote: remote,
                io,
                sync_io: Arc::new(TestRemoteSyncEngineIo::new(remote_conn.clone())),
                remote_conn,
            }
        }
    }

    impl SyncLastPushWinsQuintConnectDriver {
        fn client_a_path(&self) -> String {
            self.client_a.path().to_str().unwrap().to_string()
        }

        fn client_b_path(&self) -> String {
            self.client_b.path().to_str().unwrap().to_string()
        }

        fn client_a_delete(&mut self) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_a_path();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_remote_engine(&coro, io, sync_io, &path).await;
                        let conn = engine.connect_rw(&coro).await.unwrap();
                        conn.execute("DELETE FROM t WHERE id = 1").unwrap();
                    })
                }
            });
        }

        fn client_a_push(&mut self) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_a_path();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_remote_engine(&coro, io, sync_io, &path).await;
                        engine.push_changes_to_remote(&coro).await.unwrap();
                    })
                }
            });
            assert_eq!(
                read_remote_t(&self.remote_conn),
                Vec::<(i64, String)>::new()
            );
        }

        fn client_b_update(&mut self) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_b_path();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_remote_engine(&coro, io, sync_io, &path).await;
                        let conn = engine.connect_rw(&coro).await.unwrap();
                        conn.execute("UPDATE t SET v = 'client-b' WHERE id = 1")
                            .unwrap();
                    })
                }
            });
        }

        fn client_b_push(&mut self) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_b_path();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_remote_engine(&coro, io, sync_io, &path).await;
                        engine.push_changes_to_remote(&coro).await.unwrap();
                    })
                }
            });
        }

        fn expect_last_push_wins(&mut self) {
            assert_eq!(
                read_remote_t(&self.remote_conn),
                vec![(1, "client-b".to_string())]
            );
        }
    }

    impl Driver for SyncLastPushWinsQuintConnectDriver {
        type State = ();

        fn step(&mut self, step: &Step) -> quint_connect::Result {
            switch!(step {
                init => {},
                clientADelete => self.client_a_delete(),
                clientAPush => self.client_a_push(),
                clientBUpdate => self.client_b_update(),
                clientBPush => self.client_b_push(),
                expectLastPushWins => self.expect_last_push_wins(),
            })
        }
    }

    #[quint_run(
        spec = "../../formal/sync/turso_sync_lww_connect_repro.qnt",
        max_samples = 1,
        max_steps = 5,
        seed = "0"
    )]
    #[ignore = "desired_contract_repro: later pushed UPDATE should win after an earlier pushed DELETE"]
    fn quint_connect_delete_then_update_last_push_wins_repro() -> impl Driver {
        SyncLastPushWinsQuintConnectDriver::default()
    }

    struct SyncTransformQuintConnectDriver {
        client: NamedTempFile,
        _remote: NamedTempFile,
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestTransformRemoteSyncEngineIo>,
        remote_conn: Arc<turso_core::Connection>,
    }

    impl Default for SyncTransformQuintConnectDriver {
        fn default() -> Self {
            Self::with_skips(&[1])
        }
    }

    impl SyncTransformQuintConnectDriver {
        fn with_skips(skip_rowids: &[i64]) -> Self {
            let client = NamedTempFile::new().unwrap();
            let remote = NamedTempFile::new().unwrap();
            let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());

            seed_empty_t(io.clone(), client.path().to_str().unwrap());
            let remote_conn = seed_empty_t(io.clone(), remote.path().to_str().unwrap());

            Self {
                client,
                _remote: remote,
                io,
                sync_io: Arc::new(TestTransformRemoteSyncEngineIo::new(
                    remote_conn.clone(),
                    skip_rowids,
                )),
                remote_conn,
            }
        }
    }

    impl SyncTransformQuintConnectDriver {
        fn client_path(&self) -> String {
            self.client.path().to_str().unwrap().to_string()
        }

        fn local_insert(&mut self, id: i64, value: &str) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_path();
                let value = value.to_string();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_transform_remote_engine(&coro, io, sync_io, &path).await;
                        let conn = engine.connect_rw(&coro).await.unwrap();
                        conn.execute(&format!("INSERT INTO t VALUES ({id}, '{value}')"))
                            .unwrap();
                    })
                }
            });
        }

        fn local_two_insert_txn(&mut self, first: (i64, &str), second: (i64, &str)) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_path();
                let first_value = first.1.to_string();
                let second_value = second.1.to_string();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_transform_remote_engine(&coro, io, sync_io, &path).await;
                        let conn = engine.connect_rw(&coro).await.unwrap();
                        conn.execute("BEGIN").unwrap();
                        conn.execute(&format!(
                            "INSERT INTO t VALUES ({}, '{}')",
                            first.0, first_value
                        ))
                        .unwrap();
                        conn.execute(&format!(
                            "INSERT INTO t VALUES ({}, '{}')",
                            second.0, second_value
                        ))
                        .unwrap();
                        conn.execute("COMMIT").unwrap();
                    })
                }
            });
        }

        fn push(&mut self) {
            run_with_io(self.io.clone(), {
                let io = self.io.clone();
                let sync_io = self.sync_io.clone();
                let path = self.client_path();
                move |coro| {
                    Box::pin(async move {
                        let engine = open_transform_remote_engine(&coro, io, sync_io, &path).await;
                        engine.push_changes_to_remote(&coro).await.unwrap();
                    })
                }
            });
        }

        fn expect_skip_id1_retried(&mut self) {
            assert_eq!(self.sync_io.calls_for(1), 1);
            assert_eq!(read_remote_cursor(&self.remote_conn), None);
            assert_eq!(
                read_remote_t(&self.remote_conn),
                Vec::<(i64, String)>::new()
            );
        }

        fn expect_skip_id1_acked_by_later_keep(&mut self) {
            assert_eq!(self.sync_io.calls_for(1), 2);
            assert_eq!(self.sync_io.calls_for(2), 1);
            assert_eq!(read_remote_cursor(&self.remote_conn), Some(3));
            assert_eq!(
                read_remote_t(&self.remote_conn),
                vec![(2, "keep".to_string())]
            );
        }
    }

    impl Driver for SyncTransformQuintConnectDriver {
        type State = ();

        fn step(&mut self, step: &Step) -> quint_connect::Result {
            switch!(step {
                init => {},
                localSkipId1 => self.local_insert(1, "skip"),
                push => self.push(),
                expectSkipId1Retried => self.expect_skip_id1_retried(),
                localKeepId2 => self.local_insert(2, "keep"),
                expectSkipId1AckedByLaterKeep => {
                    self.expect_skip_id1_acked_by_later_keep()
                },
            })
        }
    }

    #[quint_run(
        spec = "../../formal/sync/turso_sync_transform_connect_repro.qnt",
        max_samples = 1,
        max_steps = 7,
        seed = "0"
    )]
    #[ignore = "current_behavior_repro: deterministic skip changes from retry to ack/drop when a later row is kept"]
    fn quint_connect_transform_skip_retry_then_ack_repro() -> impl Driver {
        SyncTransformQuintConnectDriver::default()
    }

    #[test]
    #[ignore = "current_behavior_repro: all-skipped push leaves the skipped mutation pending"]
    fn transform_skip_only_push_retries_repro() {
        let mut driver = SyncTransformQuintConnectDriver::with_skips(&[1]);

        driver.local_insert(1, "skip");
        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 1);
        assert_eq!(read_remote_cursor(&driver.remote_conn), None);
        assert_eq!(
            read_remote_t(&driver.remote_conn),
            Vec::<(i64, String)>::new()
        );

        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 2);
        assert_eq!(read_remote_cursor(&driver.remote_conn), None);
        assert_eq!(
            read_remote_t(&driver.remote_conn),
            Vec::<(i64, String)>::new()
        );
    }

    #[test]
    #[ignore = "current_behavior_repro: skipped prefix row is acknowledged when a later row is kept"]
    fn transform_skip_then_keep_acks_skipped_prefix_repro() {
        let mut driver = SyncTransformQuintConnectDriver::with_skips(&[1]);

        driver.local_insert(1, "skip");
        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 1);
        assert_eq!(read_remote_cursor(&driver.remote_conn), None);

        driver.local_insert(2, "keep");
        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 2);
        assert_eq!(driver.sync_io.calls_for(2), 1);
        assert_eq!(read_remote_cursor(&driver.remote_conn), Some(3));
        assert_eq!(
            read_remote_t(&driver.remote_conn),
            vec![(2, "keep".to_string())]
        );

        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 2);
        assert_eq!(driver.sync_io.calls_for(2), 1);
    }

    #[test]
    #[ignore = "current_behavior_repro: skipped trailing row remains pending after a kept row"]
    fn transform_keep_then_skip_retries_trailing_skip_repro() {
        let mut driver = SyncTransformQuintConnectDriver::with_skips(&[2]);

        driver.local_insert(1, "keep");
        driver.local_insert(2, "skip");
        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 1);
        assert_eq!(driver.sync_io.calls_for(2), 1);
        assert_eq!(read_remote_cursor(&driver.remote_conn), Some(1));
        assert_eq!(
            read_remote_t(&driver.remote_conn),
            vec![(1, "keep".to_string())]
        );

        driver.push();
        assert_eq!(driver.sync_io.calls_for(1), 1);
        assert_eq!(driver.sync_io.calls_for(2), 2);
        assert_eq!(read_remote_cursor(&driver.remote_conn), Some(1));
    }

    #[test]
    #[ignore = "current_behavior_repro: row-level transform can partially apply a multi-row transaction"]
    fn transform_can_partially_apply_two_row_transaction_repro() {
        let mut driver = SyncTransformQuintConnectDriver::with_skips(&[2]);

        driver.local_two_insert_txn((1, "keep"), (2, "skip"));
        driver.push();

        assert_eq!(driver.sync_io.calls_for(1), 1);
        assert_eq!(driver.sync_io.calls_for(2), 1);
        assert_eq!(read_remote_cursor(&driver.remote_conn), Some(1));
        assert_eq!(
            read_remote_t(&driver.remote_conn),
            vec![(1, "keep".to_string())]
        );
    }

    #[test]
    #[ignore = "current_behavior_repro: transform also runs during pull replay and can drop local unpushed work"]
    fn transform_skip_during_pull_replay_drops_local_change_repro() {
        let dst = NamedTempFile::new().unwrap();
        let dst_path = dst.path().to_str().unwrap().to_string();
        write_initial_meta(&dst_path);

        let rev0 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)",
        ]));
        let rev1 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)",
            "INSERT INTO t VALUES (2, 'remote')",
        ]));

        let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());
        let remote = NamedTempFile::new().unwrap();
        let remote_conn = seed_empty_t(io.clone(), remote.path().to_str().unwrap());
        let sync_io = Arc::new(TestTransformRemoteSyncEngineIo::new(remote_conn, &[1]));

        assert_eq!(
            apply_remote_snapshot_t_with_transform(
                io.clone(),
                sync_io.clone(),
                dst_path.clone(),
                "rev0",
                rev0
            ),
            Vec::<(i64, String)>::new()
        );

        assert_eq!(
            local_insert_t_with_transform(
                io.clone(),
                sync_io.clone(),
                dst_path.clone(),
                1,
                "local"
            ),
            vec![(1, "local".to_string())]
        );

        assert_eq!(
            apply_remote_snapshot_t_with_transform(
                io.clone(),
                sync_io.clone(),
                dst_path,
                "rev1",
                rev1
            ),
            vec![(2, "remote".to_string())]
        );
        assert_eq!(sync_io.calls_for(1), 1);
    }

    #[test]
    #[ignore = "current_behavior_repro: sub-page prefix bootstrap sends an empty page bitmap"]
    fn partial_prefix_sub_page_length_requests_no_pages_repro() {
        let (selectors, revisions) = partial_prefix_bootstrap_request_trace(1, None);

        assert_eq!(revisions, vec!["".to_string()]);
        assert_eq!(selectors, vec![Vec::<u32>::new()]);
    }

    #[test]
    #[ignore = "current_behavior_repro: non-page-aligned prefix misses the final partially-covered page"]
    fn partial_prefix_non_aligned_length_misses_partial_page_repro() {
        let (selectors, revisions) = partial_prefix_bootstrap_request_trace(PAGE_SIZE + 1, None);

        assert_eq!(revisions, vec!["".to_string()]);
        assert_eq!(selectors, vec![vec![0]]);
    }

    #[test]
    #[ignore = "current_behavior_repro: chunked non-page-aligned prefix still stops at floored page count"]
    fn partial_prefix_chunked_non_aligned_length_misses_partial_page_repro() {
        let (selectors, revisions) =
            partial_prefix_bootstrap_request_trace((2 * PAGE_SIZE) + 1, Some(PAGE_SIZE));

        assert_eq!(revisions, vec!["".to_string(), "rev1".to_string()]);
        assert_eq!(selectors, vec![vec![0], vec![1]]);
    }

    struct SyncCrashQuintConnectDriver {
        dst: NamedTempFile,
        io: Arc<dyn turso_core::IO>,
        sync_io: Arc<TestSyncEngineIo>,
        rev1: Vec<u8>,
        rev2: Vec<u8>,
    }

    impl Default for SyncCrashQuintConnectDriver {
        fn default() -> Self {
            Self {
                dst: NamedTempFile::new().unwrap(),
                io: Arc::new(PlatformIO::new().unwrap()),
                sync_io: Arc::new(TestSyncEngineIo),
                rev1: Vec::new(),
                rev2: Vec::new(),
            }
        }
    }

    impl SyncCrashQuintConnectDriver {
        fn dst_path(&self) -> String {
            self.dst.path().to_str().unwrap().to_string()
        }

        fn init(&mut self) {
            write_initial_meta(&self.dst_path());

            self.rev1 = snapshot_to_frames(&source_snapshot(&[
                "CREATE TABLE t(x INTEGER PRIMARY KEY)",
                "INSERT INTO t VALUES (1)",
            ]));
            self.rev2 = snapshot_to_frames(&source_snapshot(&[
                "CREATE TABLE t(x INTEGER PRIMARY KEY)",
                "INSERT INTO t VALUES (1)",
                "INSERT INTO t VALUES (2)",
            ]));
        }

        fn apply_remote_rev1_then_reset_revert(&mut self) {
            crash_after_revert_reset(
                self.io.clone(),
                self.sync_io.clone(),
                self.dst_path(),
                self.rev1.clone(),
            );
        }

        fn checkpoint_to_metadata_before_main_truncate(&mut self) {
            run_with_io(self.io.clone(), {
                let dst_path = self.dst_path();
                let sync_io = self.sync_io.clone();
                let io = self.io.clone();
                move |coro| {
                    Box::pin(async move {
                        let engine =
                            open_engine(&coro, io.clone(), sync_io.clone(), &dst_path).await;
                        assert_eq!(read_t_values(&coro, &engine).await, vec![1]);
                        checkpoint_until_meta_update_before_main_truncate(&coro, &engine).await;
                        assert_eq!(read_t_values(&coro, &engine).await, vec![1]);
                    })
                }
            });
        }

        fn crash_restart_after_checkpoint_meta(&mut self) {
            // The previous step drops the engine after metadata is durable; the
            // next step reopens it, which is the crash/restart boundary.
        }

        fn apply_remote_rev2_after_checkpoint_meta_crash(&mut self) {
            assert_eq!(
                apply_remote_snapshot(
                    self.io.clone(),
                    self.sync_io.clone(),
                    self.dst_path(),
                    "rev2",
                    self.rev2.clone()
                ),
                vec![1, 2]
            );
        }
    }

    impl Driver for SyncCrashQuintConnectDriver {
        type State = ();

        fn step(&mut self, step: &Step) -> quint_connect::Result {
            switch!(step {
                init => self.init(),
                applyRemoteRev1ThenResetRevert => self.apply_remote_rev1_then_reset_revert(),
                checkpointToMetadataBeforeMainTruncate => {
                    self.checkpoint_to_metadata_before_main_truncate()
                },
                crashRestartAfterCheckpointMeta => self.crash_restart_after_checkpoint_meta(),
                applyRemoteRev2AfterCheckpointMetaCrash => {
                    self.apply_remote_rev2_after_checkpoint_meta_crash()
                },
            })
        }
    }

    #[quint_run(
        spec = "../../formal/sync/turso_sync_connect_repro.qnt",
        max_samples = 1,
        max_steps = 4,
        seed = "0"
    )]
    #[ignore = "desired_contract_repro: Quint Connect replay of checkpoint metadata crash before main WAL truncate"]
    fn quint_connect_checkpoint_meta_crash_repro() -> impl Driver {
        SyncCrashQuintConnectDriver::default()
    }

    #[test]
    fn apply_crash_after_revert_reset_can_recover_on_next_pull() {
        let dst = NamedTempFile::new().unwrap();
        let dst_path = dst.path().to_str().unwrap().to_string();
        write_initial_meta(&dst_path);

        let rev1 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(x INTEGER PRIMARY KEY)",
            "INSERT INTO t VALUES (1)",
        ]));
        let rev2 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(x INTEGER PRIMARY KEY)",
            "INSERT INTO t VALUES (1)",
            "INSERT INTO t VALUES (2)",
        ]));

        let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());
        let sync_io = Arc::new(TestSyncEngineIo);

        crash_after_revert_reset(io.clone(), sync_io.clone(), dst_path.clone(), rev1);

        let old_meta =
            DatabaseMetadata::load(&std::fs::read(create_meta_path(&dst_path)).unwrap()).unwrap();
        assert_eq!(
            old_meta.synced_revision,
            Some(DatabasePullRevision::V1 {
                revision: "rev0".to_string()
            })
        );

        assert_eq!(
            apply_remote_snapshot(io.clone(), sync_io.clone(), dst_path.clone(), "rev2", rev2),
            vec![1, 2]
        );

        let new_meta =
            DatabaseMetadata::load(&std::fs::read(create_meta_path(&dst_path)).unwrap()).unwrap();
        assert_eq!(
            new_meta.synced_revision,
            Some(DatabasePullRevision::V1 {
                revision: "rev2".to_string()
            })
        );
    }

    #[test]
    fn apply_crash_after_revert_reset_then_checkpoint_can_recover_on_next_pull() {
        let dst = NamedTempFile::new().unwrap();
        let dst_path = dst.path().to_str().unwrap().to_string();
        write_initial_meta(&dst_path);

        let rev1 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(x INTEGER PRIMARY KEY)",
            "INSERT INTO t VALUES (1)",
        ]));
        let rev2 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(x INTEGER PRIMARY KEY)",
            "INSERT INTO t VALUES (1)",
            "INSERT INTO t VALUES (2)",
        ]));

        let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());
        let sync_io = Arc::new(TestSyncEngineIo);

        crash_after_revert_reset(io.clone(), sync_io.clone(), dst_path.clone(), rev1);

        run_with_io(io.clone(), {
            let dst_path = dst_path.clone();
            let sync_io = sync_io.clone();
            let io = io.clone();
            move |coro| {
                Box::pin(async move {
                    let engine = open_engine(&coro, io.clone(), sync_io.clone(), &dst_path).await;
                    assert_eq!(read_t_values(&coro, &engine).await, vec![1]);
                    engine.checkpoint(&coro).await.unwrap();
                    assert_eq!(read_t_values(&coro, &engine).await, vec![1]);
                    assert_eq!(
                        engine.meta().synced_revision,
                        Some(DatabasePullRevision::V1 {
                            revision: "rev0".to_string()
                        })
                    );
                })
            }
        });

        assert_eq!(
            apply_remote_snapshot(io.clone(), sync_io.clone(), dst_path.clone(), "rev2", rev2),
            vec![1, 2]
        );
    }

    #[test]
    #[ignore = "desired_contract_repro: crash after checkpoint metadata update before main WAL truncate"]
    fn apply_crash_after_revert_reset_then_checkpoint_meta_update_can_recover_on_next_pull() {
        let dst = NamedTempFile::new().unwrap();
        let dst_path = dst.path().to_str().unwrap().to_string();
        write_initial_meta(&dst_path);

        let rev1 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(x INTEGER PRIMARY KEY)",
            "INSERT INTO t VALUES (1)",
        ]));
        let rev2 = snapshot_to_frames(&source_snapshot(&[
            "CREATE TABLE t(x INTEGER PRIMARY KEY)",
            "INSERT INTO t VALUES (1)",
            "INSERT INTO t VALUES (2)",
        ]));

        let io: Arc<dyn turso_core::IO> = Arc::new(PlatformIO::new().unwrap());
        let sync_io = Arc::new(TestSyncEngineIo);

        crash_after_revert_reset(io.clone(), sync_io.clone(), dst_path.clone(), rev1);

        run_with_io(io.clone(), {
            let dst_path = dst_path.clone();
            let sync_io = sync_io.clone();
            let io = io.clone();
            move |coro| {
                Box::pin(async move {
                    let engine = open_engine(&coro, io.clone(), sync_io.clone(), &dst_path).await;
                    assert_eq!(read_t_values(&coro, &engine).await, vec![1]);
                    checkpoint_until_meta_update_before_main_truncate(&coro, &engine).await;
                    assert_eq!(read_t_values(&coro, &engine).await, vec![1]);
                    assert_eq!(
                        engine.meta().synced_revision,
                        Some(DatabasePullRevision::V1 {
                            revision: "rev0".to_string()
                        })
                    );
                })
            }
        });

        assert_eq!(
            apply_remote_snapshot(io.clone(), sync_io.clone(), dst_path.clone(), "rev2", rev2),
            vec![1, 2]
        );
    }
}
