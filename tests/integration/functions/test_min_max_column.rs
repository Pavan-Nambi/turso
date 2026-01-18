//! Test for MIN/MAX aggregate with non-aggregated column
//!
//! Bug: When SELECT includes MIN()/MAX() with a non-aggregated column,
//! SQLite guarantees the non-aggregated column value comes from the row
//! that contains the MIN/MAX. Turso incorrectly returns the value from
//! the first row scanned.
//!
//! Expected: SELECT MIN(c0), c1 FROM t returns c1 from the row where c0 is minimum
//! Actual: Turso returns c1 from the first row regardless of MIN
//!
//! Related: core/translate/main_loop.rs (emit_loop_source, LoopEmitTarget::AggStep)
//!          Uses a simple "first row" flag instead of tracking when MIN/MAX changes

use crate::common::{sqlite_exec_rows, ExecRows, TempDatabase};

/// Test that MIN() returns the non-aggregated column from the correct row
#[turso_macros::test(mvcc)]
fn min_with_non_aggregated_column(tmp_db: TempDatabase) {
    let _ = env_logger::try_init();

    let conn = tmp_db.connect_limbo();
    let sqlite_conn = rusqlite::Connection::open_in_memory().unwrap();

    // Setup: Create table with data where MIN is NOT in the first row
    conn.execute("CREATE TABLE t0(c0 INTEGER, c1 TEXT)").unwrap();
    sqlite_exec_rows(&sqlite_conn, "CREATE TABLE t0(c0 INTEGER, c1 TEXT)");

    // Insert rows: row0 has c0=10, row1 has c0=-5 (the MIN), row2 has c0=20
    conn.execute("INSERT INTO t0 VALUES(10, 'row0')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t0 VALUES(10, 'row0')");

    conn.execute("INSERT INTO t0 VALUES(-5, 'row1')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t0 VALUES(-5, 'row1')");

    conn.execute("INSERT INTO t0 VALUES(20, 'row2')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t0 VALUES(20, 'row2')");

    // Query: SELECT MIN(c0), c1 - should return (-5, 'row1')
    let turso_result: Vec<(i64, String)> = conn.exec_rows("SELECT MIN(c0), c1 FROM t0");
    let sqlite_result = sqlite_exec_rows(&sqlite_conn, "SELECT MIN(c0), c1 FROM t0");

    // SQLite returns: [[-5, "row1"]]
    assert_eq!(
        sqlite_result,
        vec![vec![
            rusqlite::types::Value::Integer(-5),
            rusqlite::types::Value::Text("row1".to_string())
        ]],
        "SQLite result sanity check"
    );

    // Turso SHOULD return the same as SQLite
    // Currently fails: Turso returns (-5, "row0") instead of (-5, "row1")
    assert_eq!(
        turso_result,
        vec![(-5i64, "row1".to_string())],
        "MIN with non-aggregated column should return value from the MIN row, not the first row"
    );
}

/// Test that MAX() returns the non-aggregated column from the correct row
#[turso_macros::test(mvcc)]
fn max_with_non_aggregated_column(tmp_db: TempDatabase) {
    let _ = env_logger::try_init();

    let conn = tmp_db.connect_limbo();
    let sqlite_conn = rusqlite::Connection::open_in_memory().unwrap();

    // Setup: Create table with data where MAX is NOT in the first row
    conn.execute("CREATE TABLE t0(c0 INTEGER, c1 TEXT)").unwrap();
    sqlite_exec_rows(&sqlite_conn, "CREATE TABLE t0(c0 INTEGER, c1 TEXT)");

    // Insert rows: row0 has c0=10, row1 has c0=-5, row2 has c0=20 (the MAX)
    conn.execute("INSERT INTO t0 VALUES(10, 'row0')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t0 VALUES(10, 'row0')");

    conn.execute("INSERT INTO t0 VALUES(-5, 'row1')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t0 VALUES(-5, 'row1')");

    conn.execute("INSERT INTO t0 VALUES(20, 'row2')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t0 VALUES(20, 'row2')");

    // Query: SELECT MAX(c0), c1 - should return (20, 'row2')
    let turso_result: Vec<(i64, String)> = conn.exec_rows("SELECT MAX(c0), c1 FROM t0");
    let sqlite_result = sqlite_exec_rows(&sqlite_conn, "SELECT MAX(c0), c1 FROM t0");

    // SQLite returns: [[20, "row2"]]
    assert_eq!(
        sqlite_result,
        vec![vec![
            rusqlite::types::Value::Integer(20),
            rusqlite::types::Value::Text("row2".to_string())
        ]],
        "SQLite result sanity check"
    );

    // Turso SHOULD return the same as SQLite
    // Currently fails: Turso returns (20, "row0") instead of (20, "row2")
    assert_eq!(
        turso_result,
        vec![(20i64, "row2".to_string())],
        "MAX with non-aggregated column should return value from the MAX row, not the first row"
    );
}

/// Test MIN with multiple non-aggregated columns
#[turso_macros::test(mvcc)]
fn min_with_multiple_non_aggregated_columns(tmp_db: TempDatabase) {
    let _ = env_logger::try_init();

    let conn = tmp_db.connect_limbo();
    let sqlite_conn = rusqlite::Connection::open_in_memory().unwrap();

    conn.execute("CREATE TABLE t(id INTEGER, val INTEGER, name TEXT)")
        .unwrap();
    sqlite_exec_rows(&sqlite_conn, "CREATE TABLE t(id INTEGER, val INTEGER, name TEXT)");

    conn.execute("INSERT INTO t VALUES(1, 100, 'alpha')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(1, 100, 'alpha')");

    conn.execute("INSERT INTO t VALUES(2, 50, 'beta')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(2, 50, 'beta')");

    conn.execute("INSERT INTO t VALUES(3, 75, 'gamma')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(3, 75, 'gamma')");

    // MIN(val) is 50, so id and name should come from that row
    let turso_result: Vec<(i64, i64, String)> =
        conn.exec_rows("SELECT id, MIN(val), name FROM t");
    let sqlite_result = sqlite_exec_rows(&sqlite_conn, "SELECT id, MIN(val), name FROM t");

    assert_eq!(
        sqlite_result,
        vec![vec![
            rusqlite::types::Value::Integer(2),
            rusqlite::types::Value::Integer(50),
            rusqlite::types::Value::Text("beta".to_string())
        ]],
        "SQLite result sanity check"
    );

    // All non-aggregated columns should come from the same row as MIN
    assert_eq!(
        turso_result,
        vec![(2i64, 50i64, "beta".to_string())],
        "All non-aggregated columns should come from the MIN row"
    );
}

/// Test MIN/MAX where the extreme value is in the first row (should still work)
#[turso_macros::test(mvcc)]
fn min_when_first_row_is_min(tmp_db: TempDatabase) {
    let _ = env_logger::try_init();

    let conn = tmp_db.connect_limbo();
    let sqlite_conn = rusqlite::Connection::open_in_memory().unwrap();

    conn.execute("CREATE TABLE t(c0 INTEGER, c1 TEXT)").unwrap();
    sqlite_exec_rows(&sqlite_conn, "CREATE TABLE t(c0 INTEGER, c1 TEXT)");

    // MIN is in the first row
    conn.execute("INSERT INTO t VALUES(-10, 'first')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(-10, 'first')");

    conn.execute("INSERT INTO t VALUES(5, 'second')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(5, 'second')");

    let turso_result: Vec<(i64, String)> = conn.exec_rows("SELECT MIN(c0), c1 FROM t");
    let sqlite_result = sqlite_exec_rows(&sqlite_conn, "SELECT MIN(c0), c1 FROM t");

    assert_eq!(
        sqlite_result,
        vec![vec![
            rusqlite::types::Value::Integer(-10),
            rusqlite::types::Value::Text("first".to_string())
        ]],
        "SQLite result sanity check"
    );

    // This case happens to work in Turso because first row IS the min row
    assert_eq!(
        turso_result,
        vec![(-10i64, "first".to_string())],
        "MIN when first row has min value"
    );
}

/// Test MIN with NULL values - NULL should be ignored
#[turso_macros::test(mvcc)]
fn min_ignores_null_values(tmp_db: TempDatabase) {
    let _ = env_logger::try_init();

    let conn = tmp_db.connect_limbo();
    let sqlite_conn = rusqlite::Connection::open_in_memory().unwrap();

    conn.execute("CREATE TABLE t(c0 INTEGER, c1 TEXT)").unwrap();
    sqlite_exec_rows(&sqlite_conn, "CREATE TABLE t(c0 INTEGER, c1 TEXT)");

    // First row has NULL c0
    conn.execute("INSERT INTO t VALUES(NULL, 'null_row')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(NULL, 'null_row')");

    conn.execute("INSERT INTO t VALUES(10, 'ten')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(10, 'ten')");

    conn.execute("INSERT INTO t VALUES(5, 'five')").unwrap();
    sqlite_exec_rows(&sqlite_conn, "INSERT INTO t VALUES(5, 'five')");

    let turso_result: Vec<(i64, String)> = conn.exec_rows("SELECT MIN(c0), c1 FROM t");
    let sqlite_result = sqlite_exec_rows(&sqlite_conn, "SELECT MIN(c0), c1 FROM t");

    assert_eq!(
        sqlite_result,
        vec![vec![
            rusqlite::types::Value::Integer(5),
            rusqlite::types::Value::Text("five".to_string())
        ]],
        "SQLite result sanity check - NULL should be ignored"
    );

    // MIN(c0) is 5, c1 should be 'five'
    assert_eq!(
        turso_result,
        vec![(5i64, "five".to_string())],
        "MIN should ignore NULL and return non-agg column from MIN row"
    );
}
