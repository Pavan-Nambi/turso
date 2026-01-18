//! Pattern-Aware SQL Generator
//!
//! This module generates SQL statements that exercise specific bug patterns.
//! Unlike random SQL generation, this generator deliberately constructs
//! queries targeting the clause combinations known to trigger logic bugs.
//!
//! The generator is designed to work with the `arbitrary` crate for fuzzing.

use crate::sqlaser::patterns::{BugPattern, SqlClause, BUG_PATTERNS};
use arbitrary::{Arbitrary, Unstructured};
use std::fmt::Write;

/// Configuration for SQL generation.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Maximum number of columns in generated tables
    pub max_columns: usize,
    /// Maximum number of rows to insert
    pub max_rows: usize,
    /// Maximum expression nesting depth
    pub max_expr_depth: usize,
    /// Which patterns to target (empty = all applicable)
    pub target_patterns: Vec<String>,
    /// Include edge case values (MAX_INT, NaN, etc.)
    pub include_edge_cases: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            max_columns: 8,
            max_rows: 10,
            max_expr_depth: 5,
            target_patterns: vec![],
            include_edge_cases: true,
        }
    }
}

/// A generated test case consisting of setup SQL and query SQL.
#[derive(Debug, Clone)]
pub struct TestCase {
    /// The bug pattern this test case targets
    pub pattern: &'static BugPattern,
    /// Setup statements (CREATE TABLE, CREATE INDEX, INSERT, etc.)
    pub setup: Vec<String>,
    /// The query statement(s) to test
    pub queries: Vec<String>,
    /// Description of what this test case is checking
    pub description: String,
}

impl TestCase {
    /// Combine all SQL into a single script.
    pub fn to_sql(&self) -> String {
        let mut sql = String::new();
        for stmt in &self.setup {
            writeln!(sql, "{};", stmt).unwrap();
        }
        for query in &self.queries {
            writeln!(sql, "{};", query).unwrap();
        }
        sql
    }
}

/// Pattern-aware SQL generator.
pub struct SqlGenerator<'a> {
    config: GeneratorConfig,
    u: &'a mut Unstructured<'a>,
    table_counter: usize,
    index_counter: usize,
}

impl<'a> SqlGenerator<'a> {
    pub fn new(u: &'a mut Unstructured<'a>, config: GeneratorConfig) -> Self {
        Self {
            config,
            u,
            table_counter: 0,
            index_counter: 0,
        }
    }

    /// Generate a test case for a specific pattern.
    pub fn generate_for_pattern(&mut self, pattern: &'static BugPattern) -> arbitrary::Result<TestCase> {
        let mut setup = Vec::new();
        let mut queries = Vec::new();

        // Determine what clauses we need
        let clauses = pattern.clauses;

        // Generate table definition based on required clauses
        let table_name = self.gen_table_name();
        let (create_table, columns) = self.gen_create_table(&table_name, clauses)?;
        setup.push(create_table);

        // Generate indexes if needed
        if clauses.contains(&SqlClause::Index) || clauses.contains(&SqlClause::PartialIndex) {
            let create_index = self.gen_create_index(&table_name, &columns, clauses)?;
            setup.push(create_index);
        }

        // Generate view if needed
        if clauses.contains(&SqlClause::View) {
            let (view_name, create_view) = self.gen_create_view(&table_name, &columns)?;
            setup.push(create_view);
            // Add view to available tables for queries
        }

        // Generate sample data
        let inserts = self.gen_inserts(&table_name, &columns, clauses)?;
        setup.extend(inserts);

        // Generate query targeting the pattern
        let query = self.gen_query(&table_name, &columns, clauses)?;
        queries.push(query);

        // Generate additional variant queries if applicable
        if clauses.contains(&SqlClause::OrderBy) {
            let order_query = self.gen_order_by_variant(&table_name, &columns)?;
            queries.push(order_query);
        }

        Ok(TestCase {
            pattern,
            setup,
            queries,
            description: format!("Testing pattern: {} - {}", pattern.id, pattern.description),
        })
    }

    /// Generate a test case for a random applicable pattern.
    pub fn generate_random(&mut self) -> arbitrary::Result<TestCase> {
        let applicable: Vec<_> = BUG_PATTERNS
            .iter()
            .filter(|p| p.applicable_to_turso)
            .collect();

        if applicable.is_empty() {
            // Fallback to any pattern
            let idx = self.u.int_in_range(0..=BUG_PATTERNS.len() - 1)?;
            return self.generate_for_pattern(&BUG_PATTERNS[idx]);
        }

        let idx = self.u.int_in_range(0..=applicable.len() - 1)?;
        self.generate_for_pattern(applicable[idx])
    }

    // ========================================================================
    // Table Generation
    // ========================================================================

    fn gen_table_name(&mut self) -> String {
        self.table_counter += 1;
        format!("t{}", self.table_counter)
    }

    fn gen_index_name(&mut self) -> String {
        self.index_counter += 1;
        format!("idx{}", self.index_counter)
    }

    fn gen_create_table(
        &mut self,
        name: &str,
        clauses: &[SqlClause],
    ) -> arbitrary::Result<(String, Vec<ColumnDef>)> {
        let num_cols = self.u.int_in_range(2..=self.config.max_columns)?;
        let mut columns = Vec::with_capacity(num_cols);

        for i in 0..num_cols {
            let col_name = format!("c{}", i);
            let col_type = self.gen_column_type(clauses)?;
            let collation = if clauses.contains(&SqlClause::Nocase) && i == 0 {
                Some(Collation::Nocase)
            } else if clauses.contains(&SqlClause::Rtrim) && i == 0 {
                Some(Collation::Rtrim)
            } else {
                None
            };

            columns.push(ColumnDef {
                name: col_name,
                col_type,
                collation,
                is_primary_key: false,
            });
        }

        // Mark first column as primary key if needed
        if clauses.contains(&SqlClause::PrimaryKey) {
            columns[0].is_primary_key = true;
        }

        // Build CREATE TABLE statement
        let mut sql = format!("CREATE TABLE {} (", name);

        for (i, col) in columns.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            sql.push_str(&col.name);
            sql.push(' ');
            sql.push_str(col.col_type.to_sql());

            if let Some(ref coll) = col.collation {
                write!(sql, " COLLATE {}", coll.to_sql()).unwrap();
            }

            if col.is_primary_key {
                sql.push_str(" PRIMARY KEY");
                if clauses.contains(&SqlClause::PrimaryKeyDesc) {
                    sql.push_str(" DESC");
                }
            }
        }

        sql.push(')');

        // Add WITHOUT ROWID if needed
        if clauses.contains(&SqlClause::WithoutRowid) {
            sql.push_str(" WITHOUT ROWID");
        }

        Ok((sql, columns))
    }

    fn gen_column_type(&mut self, clauses: &[SqlClause]) -> arbitrary::Result<ColumnType> {
        // Bias toward types that trigger bugs
        if clauses.contains(&SqlClause::Cast) || clauses.contains(&SqlClause::Nocase) {
            Ok(ColumnType::Text)
        } else if clauses.contains(&SqlClause::Round) {
            Ok(ColumnType::Real)
        } else {
            let types = [
                ColumnType::Integer,
                ColumnType::Text,
                ColumnType::Real,
                ColumnType::Blob,
            ];
            let idx = self.u.int_in_range(0..=types.len() - 1)?;
            Ok(types[idx])
        }
    }

    // ========================================================================
    // Index Generation
    // ========================================================================

    fn gen_create_index(
        &mut self,
        table: &str,
        columns: &[ColumnDef],
        clauses: &[SqlClause],
    ) -> arbitrary::Result<String> {
        let idx_name = self.gen_index_name();
        let col_idx = self.u.int_in_range(0..=columns.len() - 1)?;
        let col_name = &columns[col_idx].name;

        let mut sql = format!("CREATE INDEX {} ON {} ({})", idx_name, table, col_name);

        // Add partial index WHERE clause if needed
        if clauses.contains(&SqlClause::PartialIndex) {
            let other_col_idx = if col_idx == 0 { 1 } else { 0 };
            if other_col_idx < columns.len() {
                write!(
                    sql,
                    " WHERE {} IS NOT NULL",
                    columns[other_col_idx].name
                )
                .unwrap();
            }
        }

        Ok(sql)
    }

    // ========================================================================
    // View Generation
    // ========================================================================

    fn gen_create_view(
        &mut self,
        table: &str,
        columns: &[ColumnDef],
    ) -> arbitrary::Result<(String, String)> {
        let view_name = format!("v{}", self.table_counter);
        let cols: Vec<_> = columns.iter().map(|c| c.name.as_str()).collect();

        let sql = format!(
            "CREATE VIEW {} AS SELECT {} FROM {}",
            view_name,
            cols.join(", "),
            table
        );

        Ok((view_name, sql))
    }

    // ========================================================================
    // Data Generation
    // ========================================================================

    fn gen_inserts(
        &mut self,
        table: &str,
        columns: &[ColumnDef],
        clauses: &[SqlClause],
    ) -> arbitrary::Result<Vec<String>> {
        let num_rows = self.u.int_in_range(1..=self.config.max_rows)?;
        let mut inserts = Vec::with_capacity(num_rows);

        for _ in 0..num_rows {
            let values = self.gen_row_values(columns, clauses)?;
            let sql = format!("INSERT INTO {} VALUES ({})", table, values.join(", "));
            inserts.push(sql);
        }

        Ok(inserts)
    }

    fn gen_row_values(
        &mut self,
        columns: &[ColumnDef],
        clauses: &[SqlClause],
    ) -> arbitrary::Result<Vec<String>> {
        let mut values = Vec::with_capacity(columns.len());

        for col in columns {
            let value = self.gen_value(&col.col_type, clauses)?;
            values.push(value);
        }

        Ok(values)
    }

    fn gen_value(&mut self, col_type: &ColumnType, clauses: &[SqlClause]) -> arbitrary::Result<String> {
        // Include edge cases for bug patterns
        if self.config.include_edge_cases {
            let use_edge_case: bool = self.u.arbitrary()?;
            if use_edge_case {
                if let Some(edge) = self.gen_edge_case_value(col_type, clauses)? {
                    return Ok(edge);
                }
            }
        }

        match col_type {
            ColumnType::Integer => {
                let val: i64 = self.u.arbitrary()?;
                Ok(val.to_string())
            }
            ColumnType::Real => {
                let val: f64 = self.u.arbitrary()?;
                if val.is_nan() || val.is_infinite() {
                    Ok("0.0".to_string()) // SQLite doesn't support NaN/Inf literals
                } else {
                    Ok(format!("{}", val))
                }
            }
            ColumnType::Text => {
                let len = self.u.int_in_range(1..=20)?;
                let chars: String = (0..len)
                    .map(|_| {
                        let c: u8 = self.u.int_in_range(b'a'..=b'z').unwrap_or(b'x');
                        c as char
                    })
                    .collect();
                Ok(format!("'{}'", chars))
            }
            ColumnType::Blob => {
                let len = self.u.int_in_range(1..=10)?;
                let bytes: Vec<u8> = (0..len).map(|_| self.u.arbitrary().unwrap_or(0)).collect();
                Ok(format!("X'{}'", hex_encode(&bytes)))
            }
        }
    }

    fn gen_edge_case_value(
        &mut self,
        col_type: &ColumnType,
        clauses: &[SqlClause],
    ) -> arbitrary::Result<Option<String>> {
        // Edge case values from the bug hunting primitives
        match col_type {
            ColumnType::Integer => {
                let edge_cases = [
                    "0",
                    "-1",
                    "1",
                    "127",
                    "128",
                    "255",
                    "256",
                    "32767",
                    "32768",
                    "65535",
                    "65536",
                    "2147483647",  // i32::MAX
                    "2147483648",  // i32::MAX + 1
                    "-2147483648", // i32::MIN
                    "9223372036854775807",  // i64::MAX
                    "-9223372036854775808", // i64::MIN
                ];
                let idx = self.u.int_in_range(0..=edge_cases.len() - 1)?;
                Ok(Some(edge_cases[idx].to_string()))
            }
            ColumnType::Real => {
                let edge_cases = [
                    "0.0",
                    "-0.0",
                    "1.0",
                    "-1.0",
                    "0.5",
                    "1e10",
                    "1e-10",
                    "1.7976931348623157e308", // f64::MAX
                ];
                let idx = self.u.int_in_range(0..=edge_cases.len() - 1)?;
                Ok(Some(edge_cases[idx].to_string()))
            }
            ColumnType::Text => {
                if clauses.contains(&SqlClause::Nocase) {
                    // Case sensitivity edge cases
                    let edge_cases = ["''", "'a'", "'A'", "'aA'", "'Aa'", "'aBc'", "'ABC'"];
                    let idx = self.u.int_in_range(0..=edge_cases.len() - 1)?;
                    Ok(Some(edge_cases[idx].to_string()))
                } else {
                    Ok(None)
                }
            }
            ColumnType::Blob => Ok(None),
        }
    }

    // ========================================================================
    // Query Generation
    // ========================================================================

    fn gen_query(
        &mut self,
        table: &str,
        columns: &[ColumnDef],
        clauses: &[SqlClause],
    ) -> arbitrary::Result<String> {
        let mut sql = String::from("SELECT ");

        // DISTINCT if needed
        if clauses.contains(&SqlClause::Distinct) {
            sql.push_str("DISTINCT ");
        }

        // Columns to select
        let select_cols = self.gen_select_columns(columns, clauses)?;
        sql.push_str(&select_cols);

        // FROM clause
        write!(sql, " FROM {}", table).unwrap();

        // WHERE clause
        let where_clause = self.gen_where_clause(columns, clauses)?;
        if !where_clause.is_empty() {
            write!(sql, " WHERE {}", where_clause).unwrap();
        }

        // GROUP BY if needed
        if clauses.contains(&SqlClause::GroupBy) {
            let col = &columns[0].name;
            write!(sql, " GROUP BY {}", col).unwrap();

            if clauses.contains(&SqlClause::Having) {
                sql.push_str(" HAVING COUNT(*) > 0");
            }
        }

        // ORDER BY if needed
        if clauses.contains(&SqlClause::OrderBy) {
            let col = &columns[0].name;
            write!(sql, " ORDER BY {}", col).unwrap();
        }

        Ok(sql)
    }

    fn gen_select_columns(
        &mut self,
        columns: &[ColumnDef],
        clauses: &[SqlClause],
    ) -> arbitrary::Result<String> {
        // Use aggregates if needed
        if clauses.contains(&SqlClause::Min) {
            return Ok(format!("MIN({})", columns[0].name));
        }
        if clauses.contains(&SqlClause::Max) {
            return Ok(format!("MAX({})", columns[0].name));
        }
        if clauses.contains(&SqlClause::Count) {
            return Ok("COUNT(*)".to_string());
        }
        if clauses.contains(&SqlClause::Sum) {
            return Ok(format!("SUM({})", columns[0].name));
        }

        // Use CAST if needed
        if clauses.contains(&SqlClause::Cast) {
            return Ok(format!("CAST({} AS TEXT)", columns[0].name));
        }

        // Default: select all columns
        let cols: Vec<_> = columns.iter().map(|c| c.name.as_str()).collect();
        Ok(cols.join(", "))
    }

    fn gen_where_clause(
        &mut self,
        columns: &[ColumnDef],
        clauses: &[SqlClause],
    ) -> arbitrary::Result<String> {
        let col = &columns[0].name;

        // Generate predicate based on clauses
        if clauses.contains(&SqlClause::Likely) {
            return Ok(format!("LIKELY({} IS NOT NULL)", col));
        }
        if clauses.contains(&SqlClause::Unlikely) {
            return Ok(format!("UNLIKELY({} IS NULL)", col));
        }
        if clauses.contains(&SqlClause::Exists) {
            return Ok("EXISTS (SELECT 1)".to_string());
        }
        if clauses.contains(&SqlClause::In) {
            return Ok(format!("{} IN (1, 2, 3)", col));
        }
        if clauses.contains(&SqlClause::Like) {
            return Ok(format!("{} LIKE '%a%'", col));
        }
        if clauses.contains(&SqlClause::Glob) {
            return Ok(format!("{} GLOB '*a*'", col));
        }
        if clauses.contains(&SqlClause::Between) {
            return Ok(format!("{} BETWEEN 1 AND 10", col));
        }
        if clauses.contains(&SqlClause::IsTrue) {
            return Ok(format!("({} > 0) IS TRUE", col));
        }
        if clauses.contains(&SqlClause::IsFalse) {
            return Ok(format!("({} > 0) IS FALSE", col));
        }

        // Default: simple comparison
        Ok(format!("{} IS NOT NULL", col))
    }

    fn gen_order_by_variant(
        &mut self,
        table: &str,
        columns: &[ColumnDef],
    ) -> arbitrary::Result<String> {
        let col = &columns[0].name;
        Ok(format!("SELECT * FROM {} ORDER BY {} DESC", table, col))
    }
}

// ============================================================================
// Helper Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: ColumnType,
    pub collation: Option<Collation>,
    pub is_primary_key: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum ColumnType {
    Integer,
    Text,
    Real,
    Blob,
}

impl ColumnType {
    pub fn to_sql(&self) -> &'static str {
        match self {
            ColumnType::Integer => "INTEGER",
            ColumnType::Text => "TEXT",
            ColumnType::Real => "REAL",
            ColumnType::Blob => "BLOB",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Collation {
    Binary,
    Nocase,
    Rtrim,
}

impl Collation {
    pub fn to_sql(&self) -> &'static str {
        match self {
            Collation::Binary => "BINARY",
            Collation::Nocase => "NOCASE",
            Collation::Rtrim => "RTRIM",
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// ============================================================================
// Arbitrary Implementation for Fuzzing
// ============================================================================

impl<'a> Arbitrary<'a> for TestCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Clone u for the generator (workaround for lifetime issues)
        let bytes: Vec<u8> = u.bytes(u.len().min(1024))?.to_vec();
        let mut u2 = Unstructured::new(&bytes);

        let config = GeneratorConfig::default();
        let mut gen = SqlGenerator::new(&mut u2, config);
        gen.generate_random()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_for_pattern() {
        let data = [0u8; 256];
        let mut u = Unstructured::new(&data);
        let config = GeneratorConfig::default();
        let mut gen = SqlGenerator::new(&mut u, config);

        // Generate for first applicable pattern
        let pattern = BUG_PATTERNS
            .iter()
            .find(|p| p.applicable_to_turso)
            .unwrap();

        let test_case = gen.generate_for_pattern(pattern).unwrap();

        assert!(!test_case.setup.is_empty());
        assert!(!test_case.queries.is_empty());

        // Verify SQL is valid-looking
        for stmt in &test_case.setup {
            assert!(
                stmt.starts_with("CREATE") || stmt.starts_with("INSERT"),
                "Unexpected setup statement: {}",
                stmt
            );
        }

        for query in &test_case.queries {
            assert!(query.starts_with("SELECT"), "Expected SELECT query: {}", query);
        }
    }

    #[test]
    fn test_edge_case_values() {
        let data = [0xFFu8; 256]; // Use high bytes to trigger edge cases
        let mut u = Unstructured::new(&data);
        let config = GeneratorConfig {
            include_edge_cases: true,
            ..Default::default()
        };
        let mut gen = SqlGenerator::new(&mut u, config);

        // Edge cases should be generated for integers
        let pattern = &BUG_PATTERNS[0];
        let test_case = gen.generate_for_pattern(pattern).unwrap();

        println!("Generated SQL:");
        println!("{}", test_case.to_sql());
    }

    #[test]
    fn test_without_rowid_pattern() {
        let data = [42u8; 256];
        let mut u = Unstructured::new(&data);
        let config = GeneratorConfig::default();
        let mut gen = SqlGenerator::new(&mut u, config);

        // Find a WITHOUT ROWID pattern
        let pattern = BUG_PATTERNS
            .iter()
            .find(|p| p.clauses.contains(&SqlClause::WithoutRowid))
            .unwrap();

        let test_case = gen.generate_for_pattern(pattern).unwrap();

        // Verify WITHOUT ROWID is in the CREATE TABLE
        let has_without_rowid = test_case
            .setup
            .iter()
            .any(|s| s.contains("WITHOUT ROWID"));
        assert!(has_without_rowid, "Expected WITHOUT ROWID in table creation");
    }
}
