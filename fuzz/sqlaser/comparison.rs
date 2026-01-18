//! Turso vs SQLite Comparison Framework
//!
//! This module provides the comparison engine that runs queries against
//! both Turso and SQLite (via rusqlite) and compares results.
//!
//! Any discrepancy indicates either:
//! 1. A logic bug in Turso
//! 2. An intentional behavioral difference (should be documented)
//! 3. A bug in SQLite (unlikely but possible)

use crate::sqlaser::generator::TestCase;
use crate::sqlaser::oracles::{
    IndexOracle, LikelyOracle, NoRecOracle, Oracle, OracleResult, OracleType, QueryResult,
    RowidOracle, SerializedValue, TlpOracle,
};
use std::sync::Arc;

/// Result of comparing Turso and SQLite behavior.
#[derive(Debug)]
pub struct ComparisonResult {
    /// The test case that was run
    pub test_case_description: String,
    /// Whether both engines executed successfully
    pub execution_success: bool,
    /// Turso execution error, if any
    pub turso_error: Option<String>,
    /// SQLite execution error, if any
    pub sqlite_error: Option<String>,
    /// Direct comparison result (Turso vs SQLite)
    pub direct_match: bool,
    /// Oracle results
    pub oracle_results: Vec<OracleResult>,
    /// Overall verdict
    pub verdict: Verdict,
    /// Detailed explanation
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No issues detected
    Pass,
    /// Turso and SQLite return different results
    Mismatch,
    /// An oracle detected a logic bug
    OracleFailure,
    /// Turso crashed or panicked
    TursoCrash,
    /// Turso returned an error where SQLite succeeded
    TursoError,
    /// SQLite returned an error where Turso succeeded (possible Turso extension)
    SqliteError,
    /// Both errored (possibly invalid SQL)
    BothError,
}

/// The comparison engine.
pub struct ComparisonEngine {
    /// Turso connection
    turso_conn: Arc<turso_core::Connection>,
    /// SQLite connection
    sqlite_conn: rusqlite::Connection,
    /// Which oracles to run
    oracles: Vec<Box<dyn Oracle + Send + Sync>>,
}

impl ComparisonEngine {
    /// Create a new comparison engine with in-memory databases.
    pub fn new_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let io = Arc::new(turso_core::MemoryIO::new());
        let db = turso_core::Database::open_file(io, ":memory:")?;
        let turso_conn = db.connect()?;
        let sqlite_conn = rusqlite::Connection::open_in_memory()?;

        Ok(Self {
            turso_conn,
            sqlite_conn,
            oracles: vec![
                Box::new(NoRecOracle),
                Box::new(TlpOracle),
                Box::new(LikelyOracle),
                // Index and Rowid oracles need special setup
            ],
        })
    }

    /// Run a test case and compare results.
    pub fn run_test_case(&mut self, test_case: &TestCase) -> ComparisonResult {
        let mut turso_error = None;
        let mut sqlite_error = None;
        let mut oracle_results = Vec::new();

        // Run setup on both engines
        for stmt in &test_case.setup {
            if let Err(e) = self.execute_turso(stmt) {
                turso_error = Some(format!("Setup error: {}", e));
            }
            if let Err(e) = self.execute_sqlite(stmt) {
                sqlite_error = Some(format!("Setup error: {}", e));
            }
        }

        // If setup failed, return early
        if turso_error.is_some() || sqlite_error.is_some() {
            return ComparisonResult {
                test_case_description: test_case.description.clone(),
                execution_success: false,
                turso_error,
                sqlite_error,
                direct_match: false,
                oracle_results: vec![],
                verdict: if turso_error.is_some() && sqlite_error.is_some() {
                    Verdict::BothError
                } else if turso_error.is_some() {
                    Verdict::TursoError
                } else {
                    Verdict::SqliteError
                },
                explanation: "Setup failed".to_string(),
            };
        }

        // Run queries and compare
        let mut all_match = true;
        let mut explanation = String::new();

        for query in &test_case.queries {
            let turso_result = self.query_turso(query);
            let sqlite_result = self.query_sqlite(query);

            match (&turso_result, &sqlite_result) {
                (Ok(t_res), Ok(s_res)) => {
                    if !compare_results(t_res, s_res) {
                        all_match = false;
                        explanation.push_str(&format!(
                            "Query mismatch:\n  Query: {}\n  Turso: {} rows\n  SQLite: {} rows\n",
                            query, t_res.row_count, s_res.row_count
                        ));
                    }

                    // Run oracles
                    for oracle in &self.oracles {
                        if let Some(transformed) = oracle.transform(query) {
                            let mut transformed_results = Vec::new();
                            for tq in &transformed {
                                if let Ok(res) = self.query_turso(tq) {
                                    transformed_results.push(res);
                                }
                            }

                            let valid = oracle.validate(t_res, &transformed_results);
                            let oracle_result = OracleResult {
                                oracle: oracle.oracle_type(),
                                original_query: query.clone(),
                                transformed_queries: transformed,
                                detected_mismatch: !valid,
                                original_result: t_res.clone(),
                                transformed_results: transformed_results.clone(),
                                explanation: if !valid {
                                    Some(oracle.explain_mismatch(t_res, &transformed_results))
                                } else {
                                    None
                                },
                            };
                            oracle_results.push(oracle_result);
                        }
                    }
                }
                (Err(e), Ok(_)) => {
                    turso_error = Some(format!("Query error: {}", e));
                    all_match = false;
                }
                (Ok(_), Err(e)) => {
                    sqlite_error = Some(format!("Query error: {}", e));
                }
                (Err(te), Err(se)) => {
                    // Both errored - might be invalid SQL, which is fine
                    explanation.push_str(&format!(
                        "Both engines errored:\n  Turso: {}\n  SQLite: {}\n",
                        te, se
                    ));
                }
            }
        }

        // Determine verdict
        let oracle_failed = oracle_results.iter().any(|r| r.detected_mismatch);
        let verdict = if turso_error.is_some() && sqlite_error.is_some() {
            Verdict::BothError
        } else if turso_error.is_some() {
            Verdict::TursoError
        } else if sqlite_error.is_some() {
            Verdict::SqliteError
        } else if oracle_failed {
            Verdict::OracleFailure
        } else if !all_match {
            Verdict::Mismatch
        } else {
            Verdict::Pass
        };

        ComparisonResult {
            test_case_description: test_case.description.clone(),
            execution_success: turso_error.is_none() && sqlite_error.is_none(),
            turso_error,
            sqlite_error,
            direct_match: all_match,
            oracle_results,
            verdict,
            explanation,
        }
    }

    /// Reset both databases (for running multiple independent test cases).
    pub fn reset(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // For in-memory databases, we need to recreate them
        let io = Arc::new(turso_core::MemoryIO::new());
        let db = turso_core::Database::open_file(io, ":memory:")?;
        self.turso_conn = db.connect()?;
        self.sqlite_conn = rusqlite::Connection::open_in_memory()?;
        Ok(())
    }

    // ========================================================================
    // Internal execution methods
    // ========================================================================

    fn execute_turso(&self, sql: &str) -> Result<(), String> {
        self.turso_conn
            .execute(sql)
            .map_err(|e| format!("{}", e))
    }

    fn execute_sqlite(&self, sql: &str) -> Result<(), String> {
        self.sqlite_conn
            .execute(sql, [])
            .map(|_| ())
            .map_err(|e| format!("{}", e))
    }

    fn query_turso(&self, sql: &str) -> Result<QueryResult, String> {
        let mut stmt = self
            .turso_conn
            .prepare(sql)
            .map_err(|e| format!("{}", e))?;

        let mut rows = Vec::new();
        let mut columns = Vec::new();

        // Get column names
        let num_cols = stmt.num_columns();
        for i in 0..num_cols {
            columns.push(stmt.get_column_name(i).to_string());
        }

        stmt.run_with_row_callback(|row| {
            let mut row_values = Vec::new();
            for val in row.get_values() {
                let serialized = match val {
                    turso_core::Value::Null => SerializedValue::Null,
                    turso_core::Value::Integer(i) => SerializedValue::Integer(*i),
                    turso_core::Value::Float(f) => SerializedValue::Real(*f),
                    turso_core::Value::Text(t) => SerializedValue::Text(t.as_str().to_string()),
                    turso_core::Value::Blob(b) => SerializedValue::Blob(b.to_vec()),
                };
                row_values.push(serialized);
            }
            rows.push(row_values);
            Ok(())
        })
        .map_err(|e| format!("{}", e))?;

        Ok(QueryResult {
            row_count: rows.len(),
            rows,
            columns,
        })
    }

    fn query_sqlite(&self, sql: &str) -> Result<QueryResult, String> {
        let mut stmt = self
            .sqlite_conn
            .prepare(sql)
            .map_err(|e| format!("{}", e))?;

        let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

        let mut rows = Vec::new();
        let mut sql_rows = stmt.query([]).map_err(|e| format!("{}", e))?;

        while let Some(row) = sql_rows.next().map_err(|e| format!("{}", e))? {
            let mut row_values = Vec::new();
            for i in 0..columns.len() {
                let val: rusqlite::types::Value = row.get(i).map_err(|e| format!("{}", e))?;
                let serialized = match val {
                    rusqlite::types::Value::Null => SerializedValue::Null,
                    rusqlite::types::Value::Integer(i) => SerializedValue::Integer(i),
                    rusqlite::types::Value::Real(f) => SerializedValue::Real(f),
                    rusqlite::types::Value::Text(t) => SerializedValue::Text(t),
                    rusqlite::types::Value::Blob(b) => SerializedValue::Blob(b),
                };
                row_values.push(serialized);
            }
            rows.push(row_values);
        }

        Ok(QueryResult {
            row_count: rows.len(),
            rows,
            columns,
        })
    }
}

/// Compare two query results for equality.
fn compare_results(a: &QueryResult, b: &QueryResult) -> bool {
    if a.row_count != b.row_count {
        return false;
    }

    if a.columns.len() != b.columns.len() {
        return false;
    }

    // Compare rows (order-independent)
    let mut matched = vec![false; b.rows.len()];

    for row_a in &a.rows {
        let mut found = false;
        for (i, row_b) in b.rows.iter().enumerate() {
            if matched[i] {
                continue;
            }
            if rows_match(row_a, row_b) {
                matched[i] = true;
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }

    true
}

fn rows_match(a: &[SerializedValue], b: &[SerializedValue]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for (va, vb) in a.iter().zip(b.iter()) {
        if !va.approximately_equal(vb) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlaser::generator::{GeneratorConfig, SqlGenerator};
    use crate::sqlaser::patterns::BUG_PATTERNS;
    use arbitrary::Unstructured;

    #[test]
    fn test_comparison_engine_basic() {
        let mut engine = ComparisonEngine::new_in_memory().unwrap();

        // Run a simple test
        let test_case = crate::sqlaser::generator::TestCase {
            pattern: &BUG_PATTERNS[0],
            setup: vec![
                "CREATE TABLE t (x INTEGER, y TEXT)".to_string(),
                "INSERT INTO t VALUES (1, 'a')".to_string(),
                "INSERT INTO t VALUES (2, 'b')".to_string(),
            ],
            queries: vec!["SELECT * FROM t".to_string()],
            description: "Basic test".to_string(),
        };

        let result = engine.run_test_case(&test_case);
        assert_eq!(result.verdict, Verdict::Pass, "{:?}", result);
    }

    #[test]
    fn test_comparison_engine_with_oracles() {
        let mut engine = ComparisonEngine::new_in_memory().unwrap();

        let test_case = crate::sqlaser::generator::TestCase {
            pattern: &BUG_PATTERNS[0],
            setup: vec![
                "CREATE TABLE t (x INTEGER)".to_string(),
                "INSERT INTO t VALUES (1)".to_string(),
                "INSERT INTO t VALUES (2)".to_string(),
                "INSERT INTO t VALUES (NULL)".to_string(),
            ],
            queries: vec!["SELECT * FROM t WHERE x > 0".to_string()],
            description: "Test with oracles".to_string(),
        };

        let result = engine.run_test_case(&test_case);

        // Should have oracle results
        assert!(!result.oracle_results.is_empty());

        // Oracles should pass for correct behavior
        for oracle_result in &result.oracle_results {
            assert!(
                !oracle_result.detected_mismatch,
                "Oracle {} detected mismatch: {:?}",
                oracle_result.oracle,
                oracle_result.explanation
            );
        }
    }

    #[test]
    fn test_comparison_with_generated_test_case() {
        let data = [42u8; 256];
        let mut u = Unstructured::new(&data);
        let config = GeneratorConfig::default();
        let mut gen = SqlGenerator::new(&mut u, config);

        let test_case = gen.generate_random().unwrap();
        println!("Generated test case:\n{}", test_case.to_sql());

        let mut engine = ComparisonEngine::new_in_memory().unwrap();
        let result = engine.run_test_case(&test_case);

        println!("Verdict: {:?}", result.verdict);
        if result.verdict != Verdict::Pass {
            println!("Explanation: {}", result.explanation);
        }
    }
}
