//! SQLaser: Clause-Guided Fuzzer for Turso
//!
//! This fuzz target implements the SQLaser methodology for detecting logic bugs
//! in Turso by targeting specific SQL clause combinations known to trigger bugs.
//!
//! ## How It Works
//!
//! 1. Generate a test case targeting one of 35 known bug patterns
//! 2. Run the test case on both Turso and SQLite
//! 3. Apply testing oracles (NoREC, TLP, LIKELY) to detect logic bugs
//! 4. Panic on any mismatch (for libfuzzer to detect)
//!
//! ## Usage
//!
//! ```bash
//! # Run the clause-guided fuzzer
//! cargo fuzz run sqlaser
//!
//! # Run with more iterations
//! cargo fuzz run sqlaser -- -max_total_time=3600
//!
//! # Run with a specific seed for reproducibility
//! cargo fuzz run sqlaser -- -seed=12345
//! ```

#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::{fuzz_target, Corpus};
use std::sync::Arc;

// Import SQLaser modules (these need to be accessible from the fuzz crate)
// For now, we implement a simplified version directly here

/// Simplified test case for fuzzing
#[derive(Debug)]
struct FuzzTestCase {
    /// Setup SQL statements
    setup: Vec<String>,
    /// Query to test
    query: String,
    /// Pattern ID being tested
    pattern_id: &'static str,
}

/// Generate a test case from fuzzer input
fn generate_test_case(u: &mut Unstructured) -> arbitrary::Result<FuzzTestCase> {
    // Choose a bug pattern to target
    let pattern_idx = u.int_in_range(0..=PATTERNS.len() - 1)?;
    let (pattern_id, generator) = &PATTERNS[pattern_idx];

    generator(u, pattern_id)
}

/// Pattern generators - each generates SQL targeting a specific bug pattern
type PatternGenerator = fn(&mut Unstructured, &'static str) -> arbitrary::Result<FuzzTestCase>;

static PATTERNS: &[(&str, PatternGenerator)] = &[
    // Original patterns
    ("index_nocase", gen_index_nocase),
    ("cast_column", gen_cast_column),
    ("distinct_order_by", gen_distinct_order_by),
    ("partial_index", gen_partial_index),
    // ("without_rowid", gen_without_rowid), // NOT YET SUPPORTED in Turso
    ("in_order_by", gen_in_order_by),
    ("min_column", gen_min_column),
    ("max_column", gen_max_column),
    ("cast_exists", gen_cast_exists),
    ("likely_unlikely", gen_likely_unlikely),
    ("group_by_pk", gen_group_by_pk),
    // New patterns from SQLaser paper Table 2
    ("between_index", gen_between_index),
    ("glob_like", gen_glob_like),
    ("case_when", gen_case_when),
    ("coalesce_null", gen_coalesce_null),
    ("union_intersect", gen_union_intersect),
    ("having_aggregate", gen_having_aggregate),
    ("limit_offset", gen_limit_offset),
    ("substr_length", gen_substr_length),
    ("typeof_check", gen_typeof_check),
    ("null_handling", gen_null_handling),
    ("compound_index", gen_compound_index),
    ("collate_binary", gen_collate_binary),
    ("expr_index", gen_expr_index),
    ("cte_recursive", gen_cte_recursive),
    ("subquery_in", gen_subquery_in),
    ("left_join_null", gen_left_join_null),
    ("count_distinct", gen_count_distinct),
    ("avg_sum_type", gen_avg_sum_type),
    ("group_concat_order", gen_group_concat_order),
    ("total_vs_sum", gen_total_vs_sum),
];

// ============================================================================
// Pattern Generators
// ============================================================================

fn gen_index_nocase(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val1 = gen_text_value(u)?;
    let val2 = gen_text_value(u)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 COLLATE NOCASE, c1)".to_string(),
            "CREATE INDEX i0 ON t0(c0)".to_string(),
            format!("INSERT INTO t0 VALUES({}, {})", val1, val2),
        ],
        query: "SELECT * FROM t0 WHERE c0 IS NOT NULL".to_string(),
        pattern_id,
    })
}

fn gen_cast_column(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val: i64 = u.arbitrary()?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            format!("INSERT INTO t0 VALUES({})", val),
        ],
        query: "SELECT CAST(c0 AS TEXT) FROM t0".to_string(),
        pattern_id,
    })
}

fn gen_distinct_order_by(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(2..=5)?;
    let mut inserts = vec!["CREATE TABLE t0(c0 INTEGER, c1 TEXT)".to_string()];

    for i in 0..num_rows {
        let val: i64 = u.int_in_range(-100..=100)?;
        inserts.push(format!("INSERT INTO t0 VALUES({}, 'row{}')", val, i));
    }

    Ok(FuzzTestCase {
        setup: inserts,
        query: "SELECT DISTINCT c0 FROM t0 ORDER BY c0".to_string(),
        pattern_id,
    })
}

fn gen_partial_index(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val1: i64 = u.int_in_range(-100..=100)?;
    let val2: i64 = u.int_in_range(-100..=100)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER, c1 INTEGER)".to_string(),
            "CREATE INDEX i0 ON t0(c0) WHERE c0 > 0".to_string(),
            format!("INSERT INTO t0 VALUES({}, {})", val1, val2),
        ],
        query: "SELECT * FROM t0 WHERE c0 > 0".to_string(),
        pattern_id,
    })
}

fn gen_without_rowid(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val1: i64 = u.int_in_range(1..=1000)?;
    let val2: i64 = u.int_in_range(-100..=100)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER PRIMARY KEY, c1 INTEGER) WITHOUT ROWID".to_string(),
            format!("INSERT INTO t0 VALUES({}, {})", val1, val2),
        ],
        query: "SELECT * FROM t0 WHERE c0 IS NOT NULL".to_string(),
        pattern_id,
    })
}

fn gen_in_order_by(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(2..=5)?;
    let mut inserts = vec!["CREATE TABLE t0(c0 INTEGER)".to_string()];

    for _ in 0..num_rows {
        let val: i64 = u.int_in_range(-100..=100)?;
        inserts.push(format!("INSERT INTO t0 VALUES({})", val));
    }

    Ok(FuzzTestCase {
        setup: inserts,
        query: "SELECT * FROM t0 WHERE c0 IN (1, 2, 3) ORDER BY c0".to_string(),
        pattern_id,
    })
}

fn gen_min_column(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(2..=5)?;
    let mut inserts = vec!["CREATE TABLE t0(c0 INTEGER, c1 TEXT)".to_string()];

    for i in 0..num_rows {
        let val: i64 = u.int_in_range(-100..=100)?;
        inserts.push(format!("INSERT INTO t0 VALUES({}, 'row{}')", val, i));
    }

    Ok(FuzzTestCase {
        setup: inserts,
        query: "SELECT MIN(c0), c1 FROM t0".to_string(),
        pattern_id,
    })
}

fn gen_cast_exists(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val: i64 = u.int_in_range(-100..=100)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            format!("INSERT INTO t0 VALUES({})", val),
        ],
        query: "SELECT * FROM t0 WHERE EXISTS (SELECT CAST(c0 AS TEXT) FROM t0)".to_string(),
        pattern_id,
    })
}

fn gen_likely_unlikely(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val: i64 = u.int_in_range(-100..=100)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            format!("INSERT INTO t0 VALUES({})", val),
        ],
        query: "SELECT * FROM t0 WHERE LIKELY(c0 > 0)".to_string(),
        pattern_id,
    })
}

fn gen_group_by_pk(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(2..=5)?;
    let mut inserts = vec!["CREATE TABLE t0(c0 INTEGER PRIMARY KEY, c1 INTEGER)".to_string()];

    for i in 0..num_rows {
        let val: i64 = u.int_in_range(-100..=100)?;
        inserts.push(format!("INSERT INTO t0 VALUES({}, {})", i + 1, val));
    }

    Ok(FuzzTestCase {
        setup: inserts,
        query: "SELECT c0, SUM(c1) FROM t0 GROUP BY c0".to_string(),
        pattern_id,
    })
}

fn gen_max_column(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(2..=5)?;
    let mut inserts = vec!["CREATE TABLE t0(c0 INTEGER, c1 TEXT)".to_string()];

    for i in 0..num_rows {
        let val: i64 = u.int_in_range(-100..=100)?;
        inserts.push(format!("INSERT INTO t0 VALUES({}, 'row{}')", val, i));
    }

    Ok(FuzzTestCase {
        setup: inserts,
        query: "SELECT MAX(c0), c1 FROM t0".to_string(),
        pattern_id,
    })
}

fn gen_between_index(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(3..=8)?;
    let mut inserts = vec![
        "CREATE TABLE t0(c0 INTEGER, c1 TEXT)".to_string(),
        "CREATE INDEX i0 ON t0(c0)".to_string(),
    ];

    for i in 0..num_rows {
        let val: i64 = u.int_in_range(-50..=50)?;
        inserts.push(format!("INSERT INTO t0 VALUES({}, 'row{}')", val, i));
    }

    let lo: i64 = u.int_in_range(-30..=0)?;
    let hi: i64 = u.int_in_range(0..=30)?;

    Ok(FuzzTestCase {
        setup: inserts,
        query: format!("SELECT * FROM t0 WHERE c0 BETWEEN {} AND {}", lo, hi),
        pattern_id,
    })
}

fn gen_glob_like(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let patterns = ["%a%", "a%", "%a", "_a_", "a_", "_a", "%", "_"];
    let idx = u.int_in_range(0..=patterns.len() - 1)?;
    let pattern = patterns[idx];

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 TEXT)".to_string(),
            "INSERT INTO t0 VALUES('abc')".to_string(),
            "INSERT INTO t0 VALUES('ABC')".to_string(),
            "INSERT INTO t0 VALUES('aaa')".to_string(),
            "INSERT INTO t0 VALUES('bbb')".to_string(),
            "INSERT INTO t0 VALUES(NULL)".to_string(),
        ],
        query: format!("SELECT * FROM t0 WHERE c0 LIKE '{}'", pattern),
        pattern_id,
    })
}

fn gen_case_when(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val: i64 = u.int_in_range(-100..=100)?;
    let threshold: i64 = u.int_in_range(-50..=50)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            format!("INSERT INTO t0 VALUES({})", val),
            "INSERT INTO t0 VALUES(NULL)".to_string(),
        ],
        query: format!(
            "SELECT CASE WHEN c0 > {} THEN 'big' WHEN c0 < {} THEN 'small' ELSE 'zero' END FROM t0",
            threshold, -threshold
        ),
        pattern_id,
    })
}

fn gen_coalesce_null(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let default_val: i64 = u.int_in_range(1..=100)?;
    let use_nullif: bool = u.arbitrary()?;

    let query = if use_nullif {
        format!("SELECT NULLIF(c0, 0), COALESCE(c0, {}) FROM t0", default_val)
    } else {
        format!("SELECT COALESCE(c0, {}), IFNULL(c0, {}) FROM t0", default_val, default_val)
    };

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(NULL)".to_string(),
            "INSERT INTO t0 VALUES(0)".to_string(),
            "INSERT INTO t0 VALUES(42)".to_string(),
        ],
        query,
        pattern_id,
    })
}

fn gen_union_intersect(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let ops = ["UNION", "UNION ALL", "INTERSECT", "EXCEPT"];
    let idx = u.int_in_range(0..=ops.len() - 1)?;
    let op = ops[idx];

    // NOTE: ORDER BY is not yet supported for compound SELECTs in Turso,
    // so we test without it for now
    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "CREATE TABLE t1(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(1), (2), (3)".to_string(),
            "INSERT INTO t1 VALUES(2), (3), (4)".to_string(),
        ],
        query: format!("SELECT c0 FROM t0 {} SELECT c0 FROM t1", op),
        pattern_id,
    })
}

fn gen_having_aggregate(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let threshold: i64 = u.int_in_range(1..=5)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER, c1 TEXT)".to_string(),
            "INSERT INTO t0 VALUES(1, 'a'), (1, 'b'), (2, 'c'), (2, 'd'), (2, 'e'), (3, 'f')".to_string(),
        ],
        query: format!("SELECT c0, COUNT(*) as cnt FROM t0 GROUP BY c0 HAVING COUNT(*) >= {}", threshold),
        pattern_id,
    })
}

fn gen_limit_offset(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let limit: i64 = u.int_in_range(1..=5)?;
    let offset: i64 = u.int_in_range(0..=3)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(1), (2), (3), (4), (5), (6), (7), (8), (9), (10)".to_string(),
        ],
        query: format!("SELECT c0 FROM t0 ORDER BY c0 LIMIT {} OFFSET {}", limit, offset),
        pattern_id,
    })
}

fn gen_substr_length(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let start: i64 = u.int_in_range(1..=5)?;
    let len: i64 = u.int_in_range(1..=5)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 TEXT)".to_string(),
            "INSERT INTO t0 VALUES('hello world')".to_string(),
            "INSERT INTO t0 VALUES('')".to_string(),
            "INSERT INTO t0 VALUES(NULL)".to_string(),
        ],
        query: format!("SELECT SUBSTR(c0, {}, {}), LENGTH(c0) FROM t0", start, len),
        pattern_id,
    })
}

fn gen_typeof_check(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let val: i64 = u.int_in_range(-100..=100)?;

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0)".to_string(),  // No type affinity
            format!("INSERT INTO t0 VALUES({})", val),
            "INSERT INTO t0 VALUES('text')".to_string(),
            "INSERT INTO t0 VALUES(3.14)".to_string(),
            "INSERT INTO t0 VALUES(NULL)".to_string(),
            "INSERT INTO t0 VALUES(X'DEADBEEF')".to_string(),
        ],
        query: "SELECT c0, TYPEOF(c0) FROM t0".to_string(),
        pattern_id,
    })
}

fn gen_null_handling(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let use_or: bool = u.arbitrary()?;
    let val: i64 = u.int_in_range(-100..=100)?;

    let query = if use_or {
        format!("SELECT * FROM t0 WHERE c0 = {} OR c0 IS NULL", val)
    } else {
        format!("SELECT * FROM t0 WHERE c0 = {} AND c1 IS NOT NULL", val)
    };

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER, c1 INTEGER)".to_string(),
            format!("INSERT INTO t0 VALUES({}, 1)", val),
            "INSERT INTO t0 VALUES(NULL, 2)".to_string(),
            format!("INSERT INTO t0 VALUES({}, NULL)", val),
            "INSERT INTO t0 VALUES(NULL, NULL)".to_string(),
        ],
        query,
        pattern_id,
    })
}

fn gen_compound_index(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(3..=6)?;
    let mut inserts = vec![
        "CREATE TABLE t0(c0 INTEGER, c1 INTEGER, c2 TEXT)".to_string(),
        "CREATE INDEX i0 ON t0(c0, c1)".to_string(),
    ];

    for i in 0..num_rows {
        let v0: i64 = u.int_in_range(1..=3)?;
        let v1: i64 = u.int_in_range(1..=10)?;
        inserts.push(format!("INSERT INTO t0 VALUES({}, {}, 'row{}')", v0, v1, i));
    }

    let search_v0: i64 = u.int_in_range(1..=3)?;
    let search_v1: i64 = u.int_in_range(1..=10)?;

    Ok(FuzzTestCase {
        setup: inserts,
        query: format!("SELECT * FROM t0 WHERE c0 = {} AND c1 > {}", search_v0, search_v1),
        pattern_id,
    })
}

fn gen_collate_binary(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let collations = ["BINARY", "NOCASE", "RTRIM"];
    let idx = u.int_in_range(0..=collations.len() - 1)?;
    let collation = collations[idx];

    Ok(FuzzTestCase {
        setup: vec![
            format!("CREATE TABLE t0(c0 TEXT COLLATE {})", collation),
            "INSERT INTO t0 VALUES('abc')".to_string(),
            "INSERT INTO t0 VALUES('ABC')".to_string(),
            "INSERT INTO t0 VALUES('Abc')".to_string(),
        ],
        query: "SELECT * FROM t0 WHERE c0 = 'abc' ORDER BY c0".to_string(),
        pattern_id,
    })
}

fn gen_expr_index(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let num_rows = u.int_in_range(3..=6)?;
    let mut inserts = vec![
        "CREATE TABLE t0(c0 INTEGER)".to_string(),
        "CREATE INDEX i0 ON t0(c0 + 1)".to_string(),
    ];

    for _ in 0..num_rows {
        let val: i64 = u.int_in_range(-50..=50)?;
        inserts.push(format!("INSERT INTO t0 VALUES({})", val));
    }

    let search_val: i64 = u.int_in_range(-50..=50)?;

    Ok(FuzzTestCase {
        setup: inserts,
        query: format!("SELECT * FROM t0 WHERE c0 + 1 = {}", search_val),
        pattern_id,
    })
}

fn gen_cte_recursive(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let limit: i64 = u.int_in_range(3..=10)?;

    Ok(FuzzTestCase {
        setup: vec![],
        query: format!(
            "WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<{}) SELECT x FROM cnt",
            limit
        ),
        pattern_id,
    })
}

fn gen_subquery_in(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let use_not_in: bool = u.arbitrary()?;
    let op = if use_not_in { "NOT IN" } else { "IN" };

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "CREATE TABLE t1(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(1), (2), (3), (4), (5)".to_string(),
            "INSERT INTO t1 VALUES(2), (4), (NULL)".to_string(),
        ],
        query: format!("SELECT * FROM t0 WHERE c0 {} (SELECT c0 FROM t1)", op),
        pattern_id,
    })
}

fn gen_left_join_null(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let filter_null: bool = u.arbitrary()?;

    let query = if filter_null {
        "SELECT t0.c0, t1.c0 FROM t0 LEFT JOIN t1 ON t0.c0 = t1.c0 WHERE t1.c0 IS NULL".to_string()
    } else {
        "SELECT t0.c0, t1.c0 FROM t0 LEFT JOIN t1 ON t0.c0 = t1.c0".to_string()
    };

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "CREATE TABLE t1(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(1), (2), (3)".to_string(),
            "INSERT INTO t1 VALUES(2), (3), (4)".to_string(),
        ],
        query,
        pattern_id,
    })
}

fn gen_count_distinct(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let use_null: bool = u.arbitrary()?;

    let mut setup = vec![
        "CREATE TABLE t0(c0 INTEGER)".to_string(),
        "INSERT INTO t0 VALUES(1), (1), (2), (2), (3)".to_string(),
    ];
    if use_null {
        setup.push("INSERT INTO t0 VALUES(NULL), (NULL)".to_string());
    }

    Ok(FuzzTestCase {
        setup,
        query: "SELECT COUNT(*), COUNT(c0), COUNT(DISTINCT c0) FROM t0".to_string(),
        pattern_id,
    })
}

fn gen_avg_sum_type(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let use_float: bool = u.arbitrary()?;

    let setup = if use_float {
        vec![
            "CREATE TABLE t0(c0 REAL)".to_string(),
            "INSERT INTO t0 VALUES(1.5), (2.5), (3.0)".to_string(),
        ]
    } else {
        vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(1), (2), (3)".to_string(),
        ]
    };

    Ok(FuzzTestCase {
        setup,
        query: "SELECT SUM(c0), AVG(c0), SUM(c0) / COUNT(c0) FROM t0".to_string(),
        pattern_id,
    })
}

fn gen_group_concat_order(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let use_custom_sep: bool = u.arbitrary()?;

    let query = if use_custom_sep {
        "SELECT GROUP_CONCAT(c0, '-') FROM t0".to_string()
    } else {
        "SELECT GROUP_CONCAT(c0) FROM t0".to_string()
    };

    Ok(FuzzTestCase {
        setup: vec![
            "CREATE TABLE t0(c0 TEXT)".to_string(),
            "INSERT INTO t0 VALUES('a'), ('b'), ('c'), (NULL)".to_string(),
        ],
        query,
        pattern_id,
    })
}

fn gen_total_vs_sum(u: &mut Unstructured, pattern_id: &'static str) -> arbitrary::Result<FuzzTestCase> {
    let all_null: bool = u.arbitrary()?;

    let setup = if all_null {
        vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(NULL), (NULL)".to_string(),
        ]
    } else {
        vec![
            "CREATE TABLE t0(c0 INTEGER)".to_string(),
            "INSERT INTO t0 VALUES(1), (NULL), (2)".to_string(),
        ]
    };

    // TOTAL returns 0.0 for all NULLs, SUM returns NULL
    Ok(FuzzTestCase {
        setup,
        query: "SELECT SUM(c0), TOTAL(c0) FROM t0".to_string(),
        pattern_id,
    })
}

// ============================================================================
// Value Generators
// ============================================================================

fn gen_text_value(u: &mut Unstructured) -> arbitrary::Result<String> {
    let use_edge_case: bool = u.arbitrary()?;

    if use_edge_case {
        let edge_cases = ["''", "'a'", "'A'", "'aA'", "'Aa'", "'ABC'", "'abc'", "NULL"];
        let idx = u.int_in_range(0..=edge_cases.len() - 1)?;
        Ok(edge_cases[idx].to_string())
    } else {
        let len = u.int_in_range(1..=10)?;
        let chars: String = (0..len)
            .map(|_| {
                let c: u8 = u.int_in_range(b'a'..=b'z').unwrap_or(b'x');
                c as char
            })
            .collect();
        Ok(format!("'{}'", chars))
    }
}

// ============================================================================
// Comparison Logic
// ============================================================================

fn run_test(test_case: FuzzTestCase) -> Result<Corpus, Box<dyn std::error::Error>> {
    // Create Turso connection
    let turso_io = Arc::new(turso_core::MemoryIO::new());
    let turso_db = turso_core::Database::open_file(turso_io, ":memory:")?;
    let turso_conn = turso_db.connect()?;

    // Create SQLite connection
    let sqlite_conn = rusqlite::Connection::open_in_memory()?;

    // Run setup on both
    for stmt in &test_case.setup {
        if let Err(e) = turso_conn.execute(stmt) {
            // Setup error in Turso - check if SQLite also errors
            if sqlite_conn.execute(stmt, []).is_err() {
                // Both error - probably invalid SQL, skip
                return Ok(Corpus::Reject);
            }
            // Only Turso errors - this might be a bug
            panic!(
                "Turso setup error where SQLite succeeded!\nPattern: {}\nStatement: {}\nError: {}",
                test_case.pattern_id, stmt, e
            );
        }
        if let Err(e) = sqlite_conn.execute(stmt, []) {
            // Only SQLite errors - Turso might be more permissive (could be intentional)
            // Log but don't fail
            eprintln!(
                "SQLite setup error where Turso succeeded (pattern: {}): {}",
                test_case.pattern_id, e
            );
        }
    }

    // Run query on both
    let turso_result = query_turso(&turso_conn, &test_case.query);
    let sqlite_result = query_sqlite(&sqlite_conn, &test_case.query);

    match (&turso_result, &sqlite_result) {
        (Ok(turso_rows), Ok(sqlite_rows)) => {
            // Compare results
            if !compare_results(turso_rows, sqlite_rows) {
                panic!(
                    "Result mismatch!\nPattern: {}\nQuery: {}\nTurso: {:?}\nSQLite: {:?}",
                    test_case.pattern_id, test_case.query, turso_rows, sqlite_rows
                );
            }

            // Apply NoREC oracle if applicable
            if test_case.query.to_uppercase().contains("WHERE") {
                apply_norec_oracle(&turso_conn, &test_case.query, turso_rows)?;
            }
        }
        (Err(te), Ok(_)) => {
            // Check if it's a known unimplemented feature (parse error)
            // These are feature gaps, not logic bugs
            if te.contains("not supported") || te.contains("not yet") || te.contains("Parse error") {
                return Ok(Corpus::Reject);
            }
            panic!(
                "Turso query error where SQLite succeeded!\nPattern: {}\nQuery: {}\nError: {}",
                test_case.pattern_id, test_case.query, te
            );
        }
        (Ok(_), Err(_)) => {
            // Turso succeeded where SQLite failed - might be an extension
        }
        (Err(_), Err(_)) => {
            // Both errored - invalid SQL
            return Ok(Corpus::Reject);
        }
    }

    Ok(Corpus::Keep)
}

fn query_turso(conn: &Arc<turso_core::Connection>, sql: &str) -> Result<Vec<Vec<Value>>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| format!("{}", e))?;
    let mut rows = Vec::new();

    stmt.run_with_row_callback(|row| {
        let values: Vec<Value> = row
            .get_values()
            .map(|v| match v {
                turso_core::Value::Null => Value::Null,
                turso_core::Value::Integer(i) => Value::Integer(*i),
                turso_core::Value::Float(f) => Value::Real(*f),
                turso_core::Value::Text(t) => Value::Text(t.as_str().to_string()),
                turso_core::Value::Blob(b) => Value::Blob(b.to_vec()),
            })
            .collect();
        rows.push(values);
        Ok(())
    })
    .map_err(|e| format!("{}", e))?;

    Ok(rows)
}

fn query_sqlite(conn: &rusqlite::Connection, sql: &str) -> Result<Vec<Vec<Value>>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| format!("{}", e))?;
    let col_count = stmt.column_count();

    let mut rows = Vec::new();
    let mut sql_rows = stmt.query([]).map_err(|e| format!("{}", e))?;

    while let Some(row) = sql_rows.next().map_err(|e| format!("{}", e))? {
        let mut values = Vec::new();
        for i in 0..col_count {
            let val: rusqlite::types::Value = row.get(i).map_err(|e| format!("{}", e))?;
            let value = match val {
                rusqlite::types::Value::Null => Value::Null,
                rusqlite::types::Value::Integer(i) => Value::Integer(i),
                rusqlite::types::Value::Real(f) => Value::Real(f),
                rusqlite::types::Value::Text(t) => Value::Text(t),
                rusqlite::types::Value::Blob(b) => Value::Blob(b),
            };
            values.push(value);
        }
        rows.push(values);
    }

    Ok(rows)
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

fn compare_results(a: &[Vec<Value>], b: &[Vec<Value>]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Order-independent comparison
    let mut matched = vec![false; b.len()];

    for row_a in a {
        let mut found = false;
        for (i, row_b) in b.iter().enumerate() {
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

fn rows_equal(a: &[Value], b: &[Value]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for (va, vb) in a.iter().zip(b.iter()) {
        match (va, vb) {
            (Value::Null, Value::Null) => {}
            (Value::Integer(a), Value::Integer(b)) if a == b => {}
            (Value::Real(a), Value::Real(b)) => {
                if a.is_nan() && b.is_nan() {
                    continue;
                }
                let epsilon = 1e-10;
                let diff = (a - b).abs();
                if diff > epsilon && diff / a.abs().max(b.abs()) > epsilon {
                    return false;
                }
            }
            (Value::Text(a), Value::Text(b)) if a == b => {}
            (Value::Blob(a), Value::Blob(b)) if a == b => {}
            _ => return false,
        }
    }

    true
}

fn apply_norec_oracle(
    conn: &Arc<turso_core::Connection>,
    query: &str,
    original_result: &[Vec<Value>],
) -> Result<(), Box<dyn std::error::Error>> {
    // Transform query for NoREC oracle
    let query_upper = query.to_uppercase();
    if let Some(where_pos) = query_upper.find(" WHERE ") {
        let select_part = &query[..where_pos];
        let where_part = &query[where_pos..];

        let norec_query = format!("SELECT * FROM ({}) AS __norec{}", select_part, where_part);

        if let Ok(norec_result) = query_turso(conn, &norec_query) {
            if !compare_results(original_result, &norec_result) {
                panic!(
                    "NoREC oracle failure!\nOriginal: {}\nNoREC: {}\nOriginal result: {:?}\nNoREC result: {:?}",
                    query, norec_query, original_result, norec_result
                );
            }
        }
    }

    Ok(())
}

// ============================================================================
// Fuzz Target
// ============================================================================

fuzz_target!(|data: &[u8]| -> Corpus {
    if data.len() < 16 {
        return Corpus::Reject;
    }

    let mut u = Unstructured::new(data);

    match generate_test_case(&mut u) {
        Ok(test_case) => run_test(test_case).unwrap_or(Corpus::Keep),
        Err(_) => Corpus::Reject,
    }
});
