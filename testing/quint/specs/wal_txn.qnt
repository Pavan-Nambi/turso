module wal_txn {
  var balances: str -> int
  var txActive: int -> bool
  var tableReady: bool

  pure val ADDRESSES = Set("alice", "bob", "charlie")
  pure val CONNECTIONS = Set(0, 1, 2, 3)
  pure val BEGIN_MODES = Set("default", "deferred", "immediate", "concurrent")
  pure val CHECKPOINT_MODES = Set("PASSIVE", "FULL", "RESTART", "TRUNCATE")
  pure val CREATE_SQL = "CREATE TABLE IF NOT EXISTS quint_seed_kv (key TEXT PRIMARY KEY, value INTEGER)"

  // SQL corpus entries consumed by Turso adapters via mbt::nondetPicks.sql
  pure val WRITE_SQL = Set(
    CREATE_SQL,
    "INSERT OR REPLACE INTO quint_seed_kv (key, value) VALUES ('alice', 11)",
    "INSERT OR REPLACE INTO quint_seed_kv (key, value) VALUES ('bob', 29)",
    "INSERT OR REPLACE INTO quint_seed_kv (key, value) VALUES ('charlie', 57)",
    "UPDATE quint_seed_kv SET value = value + 1 WHERE key = 'alice'",
    "DELETE FROM quint_seed_kv WHERE key = 'charlie'",
  )
  pure val READ_SQL = Set(
    "SELECT key, value FROM quint_seed_kv WHERE key = 'alice'",
    "SELECT key, value FROM quint_seed_kv ORDER BY key",
    "SELECT count(*) FROM quint_seed_kv",
  )

  action opBegin(fiber, mode) = all {
    CONNECTIONS.contains(fiber),
    BEGIN_MODES.contains(mode),
    not(txActive.get(fiber)),
    txActive' = txActive.setBy(fiber, _ => true),
    balances' = balances,
    tableReady' = tableReady,
  }

  action opCommit(fiber) = all {
    CONNECTIONS.contains(fiber),
    txActive.get(fiber),
    txActive' = txActive.setBy(fiber, _ => false),
    balances' = balances,
    tableReady' = tableReady,
  }

  action opRollback(fiber) = all {
    CONNECTIONS.contains(fiber),
    txActive.get(fiber),
    txActive' = txActive.setBy(fiber, _ => false),
    balances' = balances,
    tableReady' = tableReady,
  }

  action opCheckpoint(fiber, mode) = all {
    CONNECTIONS.contains(fiber),
    CHECKPOINT_MODES.contains(mode),
    txActive' = txActive,
    balances' = balances,
    tableReady' = tableReady,
  }

  action opReopen(fiber) = all {
    CONNECTIONS.contains(fiber),
    CONNECTIONS.forall(c => not(txActive.get(c))),
    txActive' = txActive,
    balances' = balances,
    tableReady' = tableReady,
  }

  action opInsert(fiber, account, amount) = all {
    CONNECTIONS.contains(fiber),
    balances' = balances.setBy(account, curr => curr + amount),
    txActive' = txActive,
    tableReady' = tableReady,
  }

  action opSelect(fiber, account) = all {
    CONNECTIONS.contains(fiber),
    ADDRESSES.contains(account),
    txActive' = txActive,
    balances' = balances,
    tableReady' = tableReady,
  }

  action opInsertSql(fiber, sql) = all {
    CONNECTIONS.contains(fiber),
    WRITE_SQL.contains(sql),
    tableReady or sql == CREATE_SQL,
    txActive' = txActive,
    balances' = balances,
    tableReady' = (tableReady or sql == CREATE_SQL),
  }

  action opSelectSql(fiber, sql) = all {
    CONNECTIONS.contains(fiber),
    READ_SQL.contains(sql),
    tableReady,
    txActive' = txActive,
    balances' = balances,
    tableReady' = tableReady,
  }

  action init = all {
    balances' = ADDRESSES.mapBy(_ => 0),
    txActive' = CONNECTIONS.mapBy(_ => false),
    tableReady' = false,
  }

  action step = {
    nondet fiber = CONNECTIONS.oneOf()
    nondet account = ADDRESSES.oneOf()
    nondet amount = 1.to(100).oneOf()
    nondet txMode = BEGIN_MODES.oneOf()
    nondet ckptMode = CHECKPOINT_MODES.oneOf()
    nondet sqlWrite = WRITE_SQL.oneOf()
    nondet sqlRead = READ_SQL.oneOf()
    any {
      opBegin(fiber, txMode),
      opCommit(fiber),
      opRollback(fiber),
      opCheckpoint(fiber, ckptMode),
      opReopen(fiber),
      opInsert(fiber, account, amount),
      opSelect(fiber, account),
      opInsertSql(fiber, sqlWrite),
      opSelectSql(fiber, sqlRead),
    }
  }

  val map_domain_is_stable = ADDRESSES.forall(addr => balances.get(addr) >= 0)
}
