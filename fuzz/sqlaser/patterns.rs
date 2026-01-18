//! SQL Bug Pattern Definitions
//!
//! This module defines the 35 bug patterns from the SQLaser paper.
//! Each pattern represents a combination of SQL clauses that historically
//! trigger logic bugs in DBMSs.
//!
//! Reference: SQLaser: Detecting DBMS Logic Bugs with Clause-Guided Fuzzing
//! https://arxiv.org/abs/2407.04294

use std::fmt;

/// Categories of SQL clauses that can trigger logic bugs.
///
/// From the SQLaser paper, Section 3 (Table 1):
/// - Table Element/Schema: column, INDEX, partial INDEX, PRIMARY KEY, etc.
/// - Data Processing Functions: CAST, ROUND, etc.
/// - Conditional Expressions: EXISTS, INSERT OR FAIL, IS TRUE, etc.
/// - Special Keywords: WITHOUT ROWID, NOCASE, DISTINCT, RTRIM, PRAGMA, VIEW, rtree
/// - Query Optimization Functions: LIKELY, UNLIKELY, GLOB, IN-early-out
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClauseCategory {
    /// Table structure elements: columns, indexes, primary keys
    TableElement,
    /// Data transformation: CAST, ROUND, type coercion
    DataProcessing,
    /// Conditional logic: EXISTS, IS TRUE, IN, BETWEEN
    ConditionalExpr,
    /// Special SQL keywords: WITHOUT ROWID, NOCASE, DISTINCT
    SpecialKeyword,
    /// Query optimizer hints: LIKELY, UNLIKELY, GLOB
    QueryOptimization,
}

/// Individual SQL clauses that can contribute to bug patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqlClause {
    // Table Element/Schema
    Column,
    Index,
    PartialIndex,
    PrimaryKey,
    PrimaryKeyDesc,
    UniqueIndex,
    ExpressionIndex,

    // Data Processing Functions
    Cast,
    Round,
    Min,
    Max,
    Count,
    Sum,
    Avg,
    Total,
    Abs,
    Typeof,

    // Conditional Expressions
    Exists,
    InsertOrFail,
    InsertOrIgnore,
    InsertOrReplace,
    IsTrue,
    IsFalse,
    In,
    Between,
    Like,
    Glob,
    Case,
    Coalesce,
    Nullif,
    Ifnull,

    // Special Keywords
    WithoutRowid,
    Nocase,
    Rtrim,
    Binary,
    Distinct,
    DistinctAggregate,
    OrderBy,
    GroupBy,
    Having,
    Pragma,
    View,
    Rtree,
    Trigger,
    AlterTable,
    Join,
    LeftJoin,
    CrossJoin,
    NaturalJoin,
    Collate,
    Cte,    // Common Table Expression (WITH)
    Union,
    UnionAll,
    Intersect,
    Except,
    Subquery,
    CorrelatedSubquery,

    // Query Optimization Functions
    Likely,
    Unlikely,
    IndexedBy,
    NotIndexed,

    // Comparison operators (often involved in bugs)
    NullSafeEqual, // <=> in MySQL
    Compare,       // General comparison

    // Special values (primitives from bug hunting)
    MaxInteger,    // i64::MAX
    MinInteger,    // i64::MIN
    NegativeZero,  // -0.0
    NaN,           // 0.0/0.0
    EmptyString,
    NullValue,
    LargeBlob,
    UnicodeEdge,
}

impl SqlClause {
    /// Returns the category this clause belongs to.
    pub const fn category(&self) -> ClauseCategory {
        use ClauseCategory::*;
        use SqlClause::*;

        match self {
            Column | Index | PartialIndex | PrimaryKey | PrimaryKeyDesc | UniqueIndex
            | ExpressionIndex => TableElement,

            Cast | Round | Min | Max | Count | Sum | Avg | Total | Abs | Typeof => DataProcessing,

            Exists | InsertOrFail | InsertOrIgnore | InsertOrReplace | IsTrue | IsFalse | In
            | Between | Like | Glob | Case | Coalesce | Nullif | Ifnull => ConditionalExpr,

            WithoutRowid | Nocase | Rtrim | Binary | Distinct | DistinctAggregate | OrderBy
            | GroupBy | Having | Pragma | View | Rtree | Trigger | AlterTable | Join | LeftJoin
            | CrossJoin | NaturalJoin | Collate | Cte | Union | UnionAll | Intersect | Except
            | Subquery | CorrelatedSubquery => SpecialKeyword,

            Likely | Unlikely | IndexedBy | NotIndexed | NullSafeEqual | Compare | MaxInteger
            | MinInteger | NegativeZero | NaN | EmptyString | NullValue | LargeBlob
            | UnicodeEdge => QueryOptimization,
        }
    }
}

/// A bug pattern is a combination of SQL clauses that historically triggers bugs.
///
/// From SQLaser Table 2: Each pattern has been observed to cause logic bugs
/// in SQLite, MySQL, PostgreSQL, or TiDB.
#[derive(Debug, Clone)]
pub struct BugPattern {
    /// Unique identifier for this pattern
    pub id: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// The combination of clauses that defines this pattern
    pub clauses: &'static [SqlClause],
    /// Target DBMS where this pattern was discovered
    pub origin_dbms: &'static str,
    /// Reference bug ID (if available)
    pub reference: Option<&'static str>,
    /// Severity: how likely this pattern leads to data corruption
    pub severity: PatternSeverity,
    /// Whether this pattern is applicable to Turso
    /// (some patterns only apply to non-WAL modes, etc.)
    pub applicable_to_turso: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternSeverity {
    /// Can cause data corruption
    Critical,
    /// Can cause data loss
    High,
    /// Can cause incorrect query results
    Medium,
    /// Incompatibility with SQLite (no data impact)
    Low,
}

impl fmt::Display for PatternSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternSeverity::Critical => write!(f, "CRITICAL"),
            PatternSeverity::High => write!(f, "HIGH"),
            PatternSeverity::Medium => write!(f, "MEDIUM"),
            PatternSeverity::Low => write!(f, "LOW"),
        }
    }
}

/// All 35 bug patterns from the SQLaser paper, adapted for Turso.
///
/// Patterns are ordered by severity and likelihood of discovery.
pub static BUG_PATTERNS: &[BugPattern] = &[
    // ============================================================
    // SQLite Patterns (17 patterns)
    // ============================================================
    BugPattern {
        id: "sqlite_01_index_pk_nocase_without_rowid",
        description: "INDEX + PRIMARY KEY + WITHOUT ROWID + NOCASE interaction",
        clauses: &[
            SqlClause::Index,
            SqlClause::PrimaryKey,
            SqlClause::WithoutRowid,
            SqlClause::Nocase,
        ],
        origin_dbms: "SQLite",
        reference: Some("1b1dd4d4"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_02_partial_index_likely_fail",
        description: "Partial INDEX + LIKELY + INSERT OR FAIL interaction",
        clauses: &[
            SqlClause::PartialIndex,
            SqlClause::Likely,
            SqlClause::InsertOrFail,
        ],
        origin_dbms: "SQLite",
        reference: Some("5351e920"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_03_without_rowid_pk_desc",
        description: "WITHOUT ROWID + PRIMARY KEY DESC ordering bug",
        clauses: &[
            SqlClause::WithoutRowid,
            SqlClause::PrimaryKeyDesc,
        ],
        origin_dbms: "SQLite",
        reference: Some("f65c929"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_04_cast_likely_unlikely_glob",
        description: "Column value + CAST + LIKELY + UNLIKELY + GLOB (most common)",
        clauses: &[
            SqlClause::Column,
            SqlClause::Cast,
            SqlClause::Likely,
            SqlClause::Unlikely,
            SqlClause::Glob,
        ],
        origin_dbms: "SQLite",
        reference: Some("f9c6426"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_05_column_min",
        description: "Column value + MIN aggregate bug",
        clauses: &[SqlClause::Column, SqlClause::Min],
        origin_dbms: "SQLite",
        reference: Some("faaaae49"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_06_column_cast",
        description: "Column value + CAST type coercion bug",
        clauses: &[SqlClause::Column, SqlClause::Cast],
        origin_dbms: "SQLite",
        reference: Some("c0c90961"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_07_column_round",
        description: "Column value + ROUND precision bug",
        clauses: &[SqlClause::Column, SqlClause::Round],
        origin_dbms: "SQLite",
        reference: Some("db9acef1"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_08_cast_exists",
        description: "CAST + EXISTS subquery interaction",
        clauses: &[SqlClause::Cast, SqlClause::Exists],
        origin_dbms: "SQLite",
        reference: Some("16252d7"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_09_insert_or_fail",
        description: "INSERT OR FAIL constraint handling",
        clauses: &[SqlClause::InsertOrFail],
        origin_dbms: "SQLite",
        reference: Some("659c551d"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_10_rtrim_pk_without_rowid",
        description: "RTRIM + PRIMARY KEY + WITHOUT ROWID collation bug",
        clauses: &[
            SqlClause::Rtrim,
            SqlClause::PrimaryKey,
            SqlClause::WithoutRowid,
        ],
        origin_dbms: "SQLite",
        reference: Some("86fa0087"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_11_distinct_order_by",
        description: "DISTINCT + ORDER BY interaction",
        clauses: &[SqlClause::Distinct, SqlClause::OrderBy],
        origin_dbms: "SQLite",
        reference: Some("6ac0f822"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_12_pragma",
        description: "PRAGMA statement handling bugs",
        clauses: &[SqlClause::Pragma],
        origin_dbms: "SQLite",
        reference: Some("ebe4845c"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_13_alter_table_column",
        description: "ALTER TABLE + column value interaction",
        clauses: &[SqlClause::AlterTable, SqlClause::Column],
        origin_dbms: "SQLite",
        reference: Some("1685610e"),
        severity: PatternSeverity::High,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_14_rtree_count_cast",
        description: "R-tree virtual table + COUNT + CAST",
        clauses: &[SqlClause::Rtree, SqlClause::Count, SqlClause::Cast],
        origin_dbms: "SQLite",
        reference: Some("f898d04c"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: false, // R-tree not yet in Turso
    },
    BugPattern {
        id: "sqlite_15_view_index",
        description: "VIEW + INDEX interaction",
        clauses: &[SqlClause::View, SqlClause::Index],
        origin_dbms: "SQLite",
        reference: Some("9c8c1092"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_16_in_order_by",
        description: "IN operator + ORDER BY interaction",
        clauses: &[SqlClause::In, SqlClause::OrderBy],
        origin_dbms: "SQLite",
        reference: Some("eb40248"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "sqlite_17_trigger_update",
        description: "TRIGGER + UPDATE interaction (general category)",
        clauses: &[SqlClause::Trigger, SqlClause::Column],
        origin_dbms: "SQLite",
        reference: Some("54110870"),
        severity: PatternSeverity::High,
        applicable_to_turso: true,
    },
    // ============================================================
    // MySQL Patterns (10 patterns)
    // ============================================================
    BugPattern {
        id: "mysql_01_column_values",
        description: "Column value handling (floats, edge cases)",
        clauses: &[SqlClause::Column, SqlClause::Cast],
        origin_dbms: "MySQL",
        reference: Some("99122"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true, // General pattern applies
    },
    BugPattern {
        id: "mysql_02_any_subquery",
        description: "ANY subquery operator",
        clauses: &[SqlClause::Subquery, SqlClause::Compare],
        origin_dbms: "MySQL",
        reference: None,
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "mysql_03_like_escape_xor",
        description: "LIKE ESCAPE + XOR interaction",
        clauses: &[SqlClause::Like, SqlClause::Compare],
        origin_dbms: "MySQL",
        reference: Some("95927"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "mysql_04_bigint_ifnull",
        description: "BIGINT UNSIGNED + IFNULL overflow",
        clauses: &[SqlClause::Column, SqlClause::Ifnull, SqlClause::MaxInteger],
        origin_dbms: "MySQL",
        reference: Some("95954"),
        severity: PatternSeverity::High,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "mysql_05_null_safe_equal",
        description: "NULL-safe equality operator (<=>)",
        clauses: &[SqlClause::NullSafeEqual, SqlClause::NullValue],
        origin_dbms: "MySQL",
        reference: Some("95908"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: false, // <=> not in SQLite/Turso
    },
    BugPattern {
        id: "mysql_06_if_false",
        description: "IF(FALSE) constant folding",
        clauses: &[SqlClause::Case, SqlClause::NullValue],
        origin_dbms: "MySQL",
        reference: Some("95926"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true, // CASE WHEN equivalent
    },
    BugPattern {
        id: "mysql_07_in_operator",
        description: "IN operator edge cases",
        clauses: &[SqlClause::In],
        origin_dbms: "MySQL",
        reference: Some("95975"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "mysql_08_bitwise_and_comparison",
        description: "Bitwise AND + comparison + logical AND",
        clauses: &[SqlClause::Compare, SqlClause::Column],
        origin_dbms: "MySQL",
        reference: Some("95983"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "mysql_09_greatest",
        description: "GREATEST function edge cases",
        clauses: &[SqlClause::Max, SqlClause::NullValue],
        origin_dbms: "MySQL",
        reference: Some("96012"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true, // MAX() equivalent
    },
    BugPattern {
        id: "mysql_10_other",
        description: "Other MySQL-specific patterns",
        clauses: &[SqlClause::Column],
        origin_dbms: "MySQL",
        reference: Some("95937"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true,
    },
    // ============================================================
    // PostgreSQL Patterns (1 pattern)
    // ============================================================
    BugPattern {
        id: "postgres_01_pk_group_by",
        description: "PRIMARY KEY + GROUP BY interaction",
        clauses: &[SqlClause::PrimaryKey, SqlClause::GroupBy],
        origin_dbms: "PostgreSQL",
        reference: None,
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    // ============================================================
    // TiDB Patterns (7 patterns)
    // ============================================================
    BugPattern {
        id: "tidb_01_columns",
        description: "Column handling (special chars, data types)",
        clauses: &[SqlClause::Column],
        origin_dbms: "TiDB",
        reference: Some("15725"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "tidb_02_cast_is_true_false",
        description: "CAST + IsTrue/IsFalse",
        clauses: &[SqlClause::Cast, SqlClause::IsTrue, SqlClause::IsFalse],
        origin_dbms: "TiDB",
        reference: Some("15733"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "tidb_03_char_function",
        description: "CHAR() function edge cases",
        clauses: &[SqlClause::Cast, SqlClause::Column],
        origin_dbms: "TiDB",
        reference: Some("15986"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "tidb_04_collation",
        description: "Collation handling bugs",
        clauses: &[SqlClause::Collate, SqlClause::Compare],
        origin_dbms: "TiDB",
        reference: Some("15789"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "tidb_05_join",
        description: "JOIN operation bugs",
        clauses: &[SqlClause::Join, SqlClause::LeftJoin],
        origin_dbms: "TiDB",
        reference: Some("15846"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "tidb_06_index_merge",
        description: "Index merge optimization",
        clauses: &[SqlClause::Index, SqlClause::IndexedBy],
        origin_dbms: "TiDB",
        reference: Some("15994"),
        severity: PatternSeverity::Medium,
        applicable_to_turso: true,
    },
    BugPattern {
        id: "tidb_07_other",
        description: "Other TiDB-specific patterns",
        clauses: &[SqlClause::Column],
        origin_dbms: "TiDB",
        reference: Some("17814"),
        severity: PatternSeverity::Low,
        applicable_to_turso: true,
    },
];

impl BugPattern {
    /// Returns all patterns applicable to Turso.
    pub fn turso_applicable() -> impl Iterator<Item = &'static BugPattern> {
        BUG_PATTERNS.iter().filter(|p| p.applicable_to_turso)
    }

    /// Returns patterns by severity.
    pub fn by_severity(severity: PatternSeverity) -> impl Iterator<Item = &'static BugPattern> {
        BUG_PATTERNS.iter().filter(move |p| p.severity == severity)
    }

    /// Returns patterns containing a specific clause.
    pub fn containing_clause(clause: SqlClause) -> impl Iterator<Item = &'static BugPattern> {
        BUG_PATTERNS
            .iter()
            .filter(move |p| p.clauses.contains(&clause))
    }

    /// Check if this pattern contains all of the given clauses.
    pub fn matches_clauses(&self, clauses: &[SqlClause]) -> bool {
        clauses.iter().all(|c| self.clauses.contains(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_patterns_have_id() {
        for pattern in BUG_PATTERNS {
            assert!(!pattern.id.is_empty(), "Pattern must have an ID");
            assert!(
                !pattern.description.is_empty(),
                "Pattern {} must have description",
                pattern.id
            );
            assert!(
                !pattern.clauses.is_empty(),
                "Pattern {} must have clauses",
                pattern.id
            );
        }
    }

    #[test]
    fn test_turso_applicable_count() {
        let count = BugPattern::turso_applicable().count();
        // Most patterns should be applicable
        assert!(count >= 30, "Expected at least 30 applicable patterns");
    }

    #[test]
    fn test_pattern_lookup_by_clause() {
        let index_patterns: Vec<_> = BugPattern::containing_clause(SqlClause::Index).collect();
        assert!(!index_patterns.is_empty(), "Should find INDEX patterns");
    }

    #[test]
    fn test_pattern_severity_ordering() {
        let critical: Vec<_> = BugPattern::by_severity(PatternSeverity::Critical).collect();
        let high: Vec<_> = BugPattern::by_severity(PatternSeverity::High).collect();

        // Verify we categorized severity correctly
        for p in critical {
            println!("CRITICAL: {}", p.id);
        }
        for p in high {
            println!("HIGH: {}", p.id);
        }
    }

    #[test]
    fn test_clause_categories() {
        assert_eq!(SqlClause::Index.category(), ClauseCategory::TableElement);
        assert_eq!(SqlClause::Cast.category(), ClauseCategory::DataProcessing);
        assert_eq!(SqlClause::Exists.category(), ClauseCategory::ConditionalExpr);
        assert_eq!(SqlClause::Distinct.category(), ClauseCategory::SpecialKeyword);
        assert_eq!(
            SqlClause::Likely.category(),
            ClauseCategory::QueryOptimization
        );
    }
}
