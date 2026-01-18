//! Testing Oracles for Logic Bug Detection
//!
//! This module implements the testing oracles from the SQLaser paper:
//! - NoREC: Non-optimizing Reference Engine Construction
//! - TLP: Ternary Logic Partitioning
//! - INDEX: Index presence/absence comparison
//! - ROWID: WITHOUT ROWID table comparison
//! - LIKELY: LIKELY/UNLIKELY hint comparison
//!
//! Each oracle transforms a query into an equivalent form and checks
//! if the results match. Mismatches indicate logic bugs.

use std::fmt;

/// Result of running a query through an oracle.
#[derive(Debug, Clone)]
pub struct OracleResult {
    /// The oracle that was applied
    pub oracle: OracleType,
    /// Original query
    pub original_query: String,
    /// Transformed query (or queries for TLP)
    pub transformed_queries: Vec<String>,
    /// Whether the oracle detected a potential bug
    pub detected_mismatch: bool,
    /// Original result (serialized for comparison)
    pub original_result: QueryResult,
    /// Transformed result(s)
    pub transformed_results: Vec<QueryResult>,
    /// Human-readable explanation of the mismatch
    pub explanation: Option<String>,
}

/// Serialized query result for comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct QueryResult {
    /// Number of rows returned
    pub row_count: usize,
    /// Serialized rows (each row is a vector of values)
    pub rows: Vec<Vec<SerializedValue>>,
    /// Column names
    pub columns: Vec<String>,
}

/// A value that can be compared across different DBMS implementations.
#[derive(Debug, Clone, PartialEq)]
pub enum SerializedValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl SerializedValue {
    /// Compare values with tolerance for floating point.
    pub fn approximately_equal(&self, other: &SerializedValue) -> bool {
        match (self, other) {
            (SerializedValue::Null, SerializedValue::Null) => true,
            (SerializedValue::Integer(a), SerializedValue::Integer(b)) => a == b,
            (SerializedValue::Real(a), SerializedValue::Real(b)) => {
                // Handle NaN
                if a.is_nan() && b.is_nan() {
                    return true;
                }
                // Handle infinity
                if a.is_infinite() && b.is_infinite() {
                    return a.signum() == b.signum();
                }
                // Relative tolerance for normal floats
                let epsilon = 1e-10;
                let diff = (a - b).abs();
                let max_val = a.abs().max(b.abs());
                if max_val == 0.0 {
                    diff < epsilon
                } else {
                    diff / max_val < epsilon
                }
            }
            (SerializedValue::Text(a), SerializedValue::Text(b)) => a == b,
            (SerializedValue::Blob(a), SerializedValue::Blob(b)) => a == b,
            // Type mismatch - could be a bug or affinity difference
            _ => false,
        }
    }
}

impl fmt::Display for SerializedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializedValue::Null => write!(f, "NULL"),
            SerializedValue::Integer(i) => write!(f, "{}", i),
            SerializedValue::Real(r) => write!(f, "{}", r),
            SerializedValue::Text(s) => write!(f, "'{}'", s.replace('\'', "''")),
            SerializedValue::Blob(b) => write!(f, "X'{}'", hex::encode(b)),
        }
    }
}

/// Types of testing oracles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleType {
    /// Non-optimizing Reference Engine Construction
    /// Transforms: SELECT ... WHERE predicate
    /// Into: SELECT * FROM (SELECT ...) WHERE predicate
    /// If results differ, the optimizer has a bug.
    NoREC,

    /// Ternary Logic Partitioning
    /// Transforms: SELECT ... WHERE predicate
    /// Into three queries:
    ///   1. SELECT ... WHERE predicate
    ///   2. SELECT ... WHERE NOT predicate
    ///   3. SELECT ... WHERE predicate IS NULL
    /// The union of 1+2+3 should equal SELECT ... (without WHERE)
    TLP,

    /// Index Oracle
    /// Compares query results with and without indexes.
    /// If adding/removing an index changes results, there's a bug.
    Index,

    /// ROWID Oracle
    /// Compares behavior of tables with and without ROWID.
    /// Adds WITHOUT ROWID and checks for result differences.
    Rowid,

    /// LIKELY Oracle
    /// Adds LIKELY/UNLIKELY hints and checks for result differences.
    /// Optimizer hints should not change results.
    Likely,

    /// SQLite Comparison Oracle
    /// Runs the same query on Turso and SQLite.
    /// Results must match for compatibility.
    SqliteComparison,
}

impl fmt::Display for OracleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleType::NoREC => write!(f, "NoREC"),
            OracleType::TLP => write!(f, "TLP"),
            OracleType::Index => write!(f, "INDEX"),
            OracleType::Rowid => write!(f, "ROWID"),
            OracleType::Likely => write!(f, "LIKELY"),
            OracleType::SqliteComparison => write!(f, "SQLite"),
        }
    }
}

/// Trait for implementing testing oracles.
pub trait Oracle {
    /// Returns the type of this oracle.
    fn oracle_type(&self) -> OracleType;

    /// Transform the original query into one or more equivalent queries.
    ///
    /// Returns None if this oracle cannot be applied to the given query.
    fn transform(&self, query: &str) -> Option<Vec<String>>;

    /// Compare the original result with transformed results.
    ///
    /// Returns true if results match (no bug detected).
    fn validate(&self, original: &QueryResult, transformed: &[QueryResult]) -> bool;

    /// Generate an explanation of why results don't match.
    fn explain_mismatch(&self, original: &QueryResult, transformed: &[QueryResult]) -> String;
}

/// NoREC Oracle Implementation
///
/// The Non-optimizing Reference Engine Construction oracle works by
/// wrapping the query in a subquery that prevents optimization of
/// the WHERE clause.
///
/// Original: SELECT cols FROM table WHERE predicate
/// NoREC:    SELECT * FROM (SELECT cols FROM table) WHERE predicate
///
/// The inner query fetches all rows, then the outer query filters.
/// This prevents the optimizer from using indexes for the predicate.
pub struct NoRecOracle;

impl Oracle for NoRecOracle {
    fn oracle_type(&self) -> OracleType {
        OracleType::NoREC
    }

    fn transform(&self, query: &str) -> Option<Vec<String>> {
        // Parse to find WHERE clause
        let query_upper = query.to_uppercase();

        // Must be a SELECT with WHERE
        if !query_upper.contains("SELECT") || !query_upper.contains("WHERE") {
            return None;
        }

        // Find WHERE position
        let where_pos = query_upper.find(" WHERE ")?;
        let select_part = &query[..where_pos];
        let where_part = &query[where_pos..];

        // Construct NoREC query
        let norec_query = format!("SELECT * FROM ({}) AS __norec{}", select_part, where_part);

        Some(vec![norec_query])
    }

    fn validate(&self, original: &QueryResult, transformed: &[QueryResult]) -> bool {
        if transformed.is_empty() {
            return true; // Can't validate
        }

        let transformed = &transformed[0];

        // Row count must match
        if original.row_count != transformed.row_count {
            return false;
        }

        // All rows must match (order-independent for NoREC)
        compare_result_sets(original, transformed)
    }

    fn explain_mismatch(&self, original: &QueryResult, transformed: &[QueryResult]) -> String {
        if transformed.is_empty() {
            return "No transformed result available".to_string();
        }

        let transformed = &transformed[0];
        format!(
            "NoREC mismatch: Original returned {} rows, NoREC returned {} rows.\n\
             This suggests the query optimizer incorrectly affects results.",
            original.row_count, transformed.row_count
        )
    }
}

/// TLP Oracle Implementation
///
/// Ternary Logic Partitioning splits a query into three partitions:
/// 1. WHERE predicate (true)
/// 2. WHERE NOT predicate (false)
/// 3. WHERE predicate IS NULL (unknown)
///
/// The union of all three must equal the unfiltered query.
pub struct TlpOracle;

impl Oracle for TlpOracle {
    fn oracle_type(&self) -> OracleType {
        OracleType::TLP
    }

    fn transform(&self, query: &str) -> Option<Vec<String>> {
        let query_upper = query.to_uppercase();

        // Must be a SELECT with WHERE
        if !query_upper.contains("SELECT") || !query_upper.contains("WHERE") {
            return None;
        }

        // Find WHERE clause
        let where_pos = query_upper.find(" WHERE ")?;
        let base_query = &query[..where_pos];
        let where_clause_start = where_pos + 7; // " WHERE " is 7 chars
        let predicate = query[where_clause_start..].trim();

        // Remove trailing semicolon if present
        let predicate = predicate.trim_end_matches(';').trim();

        // Generate three partitioned queries
        let q_true = format!("{} WHERE ({})", base_query, predicate);
        let q_false = format!("{} WHERE NOT ({})", base_query, predicate);
        let q_null = format!("{} WHERE ({}) IS NULL", base_query, predicate);

        // The unfiltered query (for comparison)
        let q_all = base_query.to_string();

        Some(vec![q_true, q_false, q_null, q_all])
    }

    fn validate(&self, _original: &QueryResult, transformed: &[QueryResult]) -> bool {
        if transformed.len() != 4 {
            return true; // Can't validate
        }

        let q_true = &transformed[0];
        let q_false = &transformed[1];
        let q_null = &transformed[2];
        let q_all = &transformed[3];

        // Union of true + false + null should equal all
        let combined_count = q_true.row_count + q_false.row_count + q_null.row_count;

        combined_count == q_all.row_count
    }

    fn explain_mismatch(&self, _original: &QueryResult, transformed: &[QueryResult]) -> String {
        if transformed.len() != 4 {
            return "Insufficient transformed results for TLP".to_string();
        }

        format!(
            "TLP mismatch: WHERE true={} + WHERE false={} + WHERE null={} != all={}.\n\
             This suggests incorrect ternary logic handling.",
            transformed[0].row_count,
            transformed[1].row_count,
            transformed[2].row_count,
            transformed[3].row_count
        )
    }
}

/// Index Oracle Implementation
///
/// Compares query results with and without an index.
/// If results differ, the index implementation has a bug.
pub struct IndexOracle;

impl Oracle for IndexOracle {
    fn oracle_type(&self) -> OracleType {
        OracleType::Index
    }

    fn transform(&self, query: &str) -> Option<Vec<String>> {
        // This oracle needs to be applied at the test setup level,
        // not at the query level. Return the same query to indicate
        // it should be run in both environments.
        Some(vec![query.to_string()])
    }

    fn validate(&self, original: &QueryResult, transformed: &[QueryResult]) -> bool {
        if transformed.is_empty() {
            return true;
        }

        compare_result_sets(original, &transformed[0])
    }

    fn explain_mismatch(&self, original: &QueryResult, transformed: &[QueryResult]) -> String {
        if transformed.is_empty() {
            return "No transformed result available".to_string();
        }

        format!(
            "INDEX mismatch: With index {} rows, without index {} rows.\n\
             This suggests the index affects query correctness.",
            original.row_count, transformed[0].row_count
        )
    }
}

/// ROWID Oracle Implementation
///
/// Compares behavior of tables with and without ROWID.
pub struct RowidOracle;

impl Oracle for RowidOracle {
    fn oracle_type(&self) -> OracleType {
        OracleType::Rowid
    }

    fn transform(&self, query: &str) -> Option<Vec<String>> {
        // Similar to Index oracle, this needs setup-level comparison
        Some(vec![query.to_string()])
    }

    fn validate(&self, original: &QueryResult, transformed: &[QueryResult]) -> bool {
        if transformed.is_empty() {
            return true;
        }

        compare_result_sets(original, &transformed[0])
    }

    fn explain_mismatch(&self, original: &QueryResult, transformed: &[QueryResult]) -> String {
        if transformed.is_empty() {
            return "No transformed result available".to_string();
        }

        format!(
            "ROWID mismatch: With ROWID {} rows, WITHOUT ROWID {} rows.\n\
             This suggests WITHOUT ROWID affects query correctness.",
            original.row_count, transformed[0].row_count
        )
    }
}

/// LIKELY Oracle Implementation
///
/// Adds LIKELY/UNLIKELY hints and checks for result differences.
/// These are optimizer hints that should NOT change results.
pub struct LikelyOracle;

impl Oracle for LikelyOracle {
    fn oracle_type(&self) -> OracleType {
        OracleType::Likely
    }

    fn transform(&self, query: &str) -> Option<Vec<String>> {
        let query_upper = query.to_uppercase();

        // Must be a SELECT with WHERE
        if !query_upper.contains("SELECT") || !query_upper.contains("WHERE") {
            return None;
        }

        // Find WHERE clause
        let where_pos = query_upper.find(" WHERE ")?;
        let base_query = &query[..where_pos + 7];
        let predicate = &query[where_pos + 7..];

        // Wrap predicate in LIKELY
        let likely_query = format!("{}LIKELY({})", base_query, predicate.trim_end_matches(';'));

        // Wrap predicate in UNLIKELY
        let unlikely_query = format!(
            "{}UNLIKELY({})",
            base_query,
            predicate.trim_end_matches(';')
        );

        Some(vec![likely_query, unlikely_query])
    }

    fn validate(&self, original: &QueryResult, transformed: &[QueryResult]) -> bool {
        // Both LIKELY and UNLIKELY should produce same results as original
        for t in transformed {
            if !compare_result_sets(original, t) {
                return false;
            }
        }
        true
    }

    fn explain_mismatch(&self, original: &QueryResult, transformed: &[QueryResult]) -> String {
        let mut msg = String::from("LIKELY/UNLIKELY mismatch:\n");
        msg.push_str(&format!("  Original: {} rows\n", original.row_count));
        if !transformed.is_empty() {
            msg.push_str(&format!("  LIKELY: {} rows\n", transformed[0].row_count));
        }
        if transformed.len() > 1 {
            msg.push_str(&format!("  UNLIKELY: {} rows\n", transformed[1].row_count));
        }
        msg.push_str("Optimizer hints should not change results.");
        msg
    }
}

/// Compare two result sets (order-independent).
fn compare_result_sets(a: &QueryResult, b: &QueryResult) -> bool {
    if a.row_count != b.row_count {
        return false;
    }

    if a.columns.len() != b.columns.len() {
        return false;
    }

    // For each row in a, find a matching row in b
    // This is O(n²) but correct for unordered comparison
    let mut matched = vec![false; b.rows.len()];

    for row_a in &a.rows {
        let mut found = false;
        for (i, row_b) in b.rows.iter().enumerate() {
            if matched[i] {
                continue;
            }
            if rows_equal(row_a, row_b) {
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

/// Compare two rows for equality.
fn rows_equal(a: &[SerializedValue], b: &[SerializedValue]) -> bool {
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

/// Hex encoding for blob values.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_norec_transform() {
        let oracle = NoRecOracle;

        let query = "SELECT * FROM t WHERE x > 5";
        let transformed = oracle.transform(query).unwrap();

        assert_eq!(transformed.len(), 1);
        assert!(transformed[0].contains("SELECT * FROM (SELECT * FROM t) AS __norec WHERE x > 5"));
    }

    #[test]
    fn test_tlp_transform() {
        let oracle = TlpOracle;

        let query = "SELECT * FROM t WHERE x > 5";
        let transformed = oracle.transform(query).unwrap();

        assert_eq!(transformed.len(), 4);
        assert!(transformed[0].contains("WHERE (x > 5)"));
        assert!(transformed[1].contains("WHERE NOT (x > 5)"));
        assert!(transformed[2].contains("WHERE (x > 5) IS NULL"));
        assert!(!transformed[3].contains("WHERE"));
    }

    #[test]
    fn test_likely_transform() {
        let oracle = LikelyOracle;

        let query = "SELECT * FROM t WHERE x > 5";
        let transformed = oracle.transform(query).unwrap();

        assert_eq!(transformed.len(), 2);
        assert!(transformed[0].contains("LIKELY(x > 5)"));
        assert!(transformed[1].contains("UNLIKELY(x > 5)"));
    }

    #[test]
    fn test_serialized_value_equality() {
        assert!(SerializedValue::Null.approximately_equal(&SerializedValue::Null));
        assert!(SerializedValue::Integer(42).approximately_equal(&SerializedValue::Integer(42)));
        assert!(SerializedValue::Real(3.14159).approximately_equal(&SerializedValue::Real(3.14159)));

        // Float tolerance
        assert!(SerializedValue::Real(1.0000000001).approximately_equal(&SerializedValue::Real(1.0)));
    }

    #[test]
    fn test_result_set_comparison() {
        let result1 = QueryResult {
            row_count: 2,
            columns: vec!["x".to_string()],
            rows: vec![
                vec![SerializedValue::Integer(1)],
                vec![SerializedValue::Integer(2)],
            ],
        };

        // Same rows, different order
        let result2 = QueryResult {
            row_count: 2,
            columns: vec!["x".to_string()],
            rows: vec![
                vec![SerializedValue::Integer(2)],
                vec![SerializedValue::Integer(1)],
            ],
        };

        assert!(compare_result_sets(&result1, &result2));

        // Different rows
        let result3 = QueryResult {
            row_count: 2,
            columns: vec!["x".to_string()],
            rows: vec![
                vec![SerializedValue::Integer(1)],
                vec![SerializedValue::Integer(3)],
            ],
        };

        assert!(!compare_result_sets(&result1, &result3));
    }
}
