module wal_corruption {
  var txActive: int -> bool
  var blobSizes: str -> int
  var tableReady: bool
  var reopenCount: int

  pure val CONNECTIONS = Set(0, 1, 2, 3, 4, 5, 6, 7)
  pure val KEYS = Set("k0", "k1", "k2", "k3", "k4", "k5")
  pure val BEGIN_MODES = Set("default", "deferred", "immediate")
  pure val CHECKPOINT_MODES = Set("PASSIVE", "FULL", "RESTART", "TRUNCATE")

  pure val CREATE_SQL = "CREATE TABLE IF NOT EXISTS quint_corrupt (key TEXT PRIMARY KEY, value BLOB)"
  pure val WRITE_SQL = Set(
    CREATE_SQL,
    "INSERT OR REPLACE INTO quint_corrupt (key, value) VALUES ('k0', zeroblob(1024))",
    "INSERT OR REPLACE INTO quint_corrupt (key, value) VALUES ('k1', zeroblob(4096))",
    "INSERT OR REPLACE INTO quint_corrupt (key, value) VALUES ('k2', zeroblob(65536))",
    "UPDATE quint_corrupt SET value = zeroblob(8192) WHERE key = 'k0'",
    "UPDATE quint_corrupt SET value = zeroblob(16384) WHERE key = 'k1'",
    "DELETE FROM quint_corrupt WHERE key = 'k2'",
  )
  pure val READ_TABLE_SQL = Set(
    "SELECT count(*) FROM quint_corrupt",
    "SELECT key, length(value) FROM quint_corrupt ORDER BY key",
    "SELECT key FROM quint_corrupt WHERE key = 'k0'",
  )
  pure val READ_PRAGMA_SQL = Set(
    "PRAGMA integrity_check",
    "PRAGMA quick_check",
    "PRAGMA page_count",
    "PRAGMA freelist_count",
  )

  action opBegin(fiber, mode) = all {
    CONNECTIONS.contains(fiber),
    BEGIN_MODES.contains(mode),
    not(txActive.get(fiber)),
    mode != "immediate" or CONNECTIONS.forall(c => not(txActive.get(c))),
    txActive' = txActive.setBy(fiber, _ => true),
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opCommit(fiber) = all {
    CONNECTIONS.contains(fiber),
    txActive.get(fiber),
    txActive' = txActive.setBy(fiber, _ => false),
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opRollback(fiber) = all {
    CONNECTIONS.contains(fiber),
    txActive.get(fiber),
    txActive' = txActive.setBy(fiber, _ => false),
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opCheckpoint(fiber, mode) = all {
    CONNECTIONS.contains(fiber),
    CHECKPOINT_MODES.contains(mode),
    txActive' = txActive,
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opReopen(fiber) = all {
    CONNECTIONS.contains(fiber),
    CONNECTIONS.forall(c => not(txActive.get(c))),
    txActive' = txActive,
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount + 1,
  }

  action opWriteBlob(fiber, key, bytes) = all {
    CONNECTIONS.contains(fiber),
    KEYS.contains(key),
    tableReady,
    bytes >= 1,
    bytes <= 262144,
    txActive' = txActive,
    blobSizes' = blobSizes.setBy(key, _ => bytes),
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opDeleteBlob(fiber, key) = all {
    CONNECTIONS.contains(fiber),
    KEYS.contains(key),
    tableReady,
    txActive' = txActive,
    blobSizes' = blobSizes.setBy(key, _ => 0),
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opWriteSql(fiber, sqlWrite) = all {
    CONNECTIONS.contains(fiber),
    WRITE_SQL.contains(sqlWrite),
    tableReady or sqlWrite == CREATE_SQL,
    txActive' = txActive,
    blobSizes' = blobSizes,
    tableReady' = (tableReady or sqlWrite == CREATE_SQL),
    reopenCount' = reopenCount,
  }

  action opReadTableSql(fiber, sqlRead) = all {
    CONNECTIONS.contains(fiber),
    READ_TABLE_SQL.contains(sqlRead),
    tableReady,
    txActive' = txActive,
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opReadPragmaSql(fiber, sqlRead) = all {
    CONNECTIONS.contains(fiber),
    READ_PRAGMA_SQL.contains(sqlRead),
    txActive' = txActive,
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action opIntegrityCheck(fiber) = all {
    CONNECTIONS.contains(fiber),
    txActive' = txActive,
    blobSizes' = blobSizes,
    tableReady' = tableReady,
    reopenCount' = reopenCount,
  }

  action init = all {
    txActive' = CONNECTIONS.mapBy(_ => false),
    blobSizes' = KEYS.mapBy(_ => 0),
    tableReady' = false,
    reopenCount' = 0,
  }

  action step = {
    nondet fiber = CONNECTIONS.oneOf()
    nondet key = KEYS.oneOf()
    nondet bytes = 1.to(262144).oneOf()
    nondet ckptMode = CHECKPOINT_MODES.oneOf()
    nondet sqlWrite = WRITE_SQL.oneOf()
    nondet sqlReadTable = READ_TABLE_SQL.oneOf()
    nondet sqlReadPragma = READ_PRAGMA_SQL.oneOf()
    any {
      opCheckpoint(fiber, ckptMode),
      opReopen(fiber),
      opWriteBlob(fiber, key, bytes),
      opDeleteBlob(fiber, key),
      opWriteSql(fiber, sqlWrite),
      opReadTableSql(fiber, sqlReadTable),
      opReadPragmaSql(fiber, sqlReadPragma),
      opIntegrityCheck(fiber),
    }
  }

  val non_negative_blob_sizes = KEYS.forall(k => blobSizes.get(k) >= 0)
  val no_blob_before_create = not(tableReady) implies KEYS.forall(k => blobSizes.get(k) == 0)
  val can_recover_after_writes = reopenCount > 0 and KEYS.exists(k => blobSizes.get(k) > 0)
}
