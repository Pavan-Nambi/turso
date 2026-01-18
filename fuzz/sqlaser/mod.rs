//! SQLaser: Clause-Guided Fuzzing for Turso
//!
//! This module implements clause-guided fuzzing for detecting logic bugs in Turso,
//! based on the SQLaser paper: https://arxiv.org/abs/2407.04294
//!
//! ## Key Concepts
//!
//! 1. **Bug Patterns**: 35 SQL clause combinations that historically trigger logic bugs
//! 2. **Testing Oracles**: Transforms that should produce equivalent results (NoREC, TLP, etc.)
//! 3. **Comparison Engine**: Runs queries on both Turso and SQLite to detect divergence
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sqlaser::{ComparisonEngine, SqlGenerator, GeneratorConfig};
//!
//! let mut engine = ComparisonEngine::new_in_memory()?;
//! let mut gen = SqlGenerator::new(&mut rng, GeneratorConfig::default());
//!
//! let test_case = gen.generate_random()?;
//! let result = engine.run_test_case(&test_case);
//!
//! assert_eq!(result.verdict, Verdict::Pass);
//! ```
//!
//! ## Implementation Status
//!
//! ### Phase 1 (Current): Oracle-Based Detection
//! - [x] 35 bug pattern definitions
//! - [x] Testing oracles (NoREC, TLP, LIKELY)
//! - [x] Pattern-aware SQL generator
//! - [x] Turso vs SQLite comparison engine
//! - [ ] Fuzz target integration
//!
//! ### Phase 2 (TODO): Seed Prioritization
//! - [ ] Track which patterns each seed exercises
//! - [ ] Distance-based energy allocation
//! - [ ] Pattern coverage metrics
//!
//! ### Phase 3 (TODO): LLVM Instrumentation
//! - [ ] Function call chain tracing
//! - [ ] Path-to-path distance calculation
//! - [ ] Full SQLaser algorithm

pub mod comparison;
pub mod generator;
pub mod oracles;
pub mod patterns;

// Re-exports for convenience
pub use comparison::{ComparisonEngine, ComparisonResult, Verdict};
pub use generator::{GeneratorConfig, SqlGenerator, TestCase};
pub use oracles::{NoRecOracle, Oracle, OracleResult, OracleType, QueryResult, TlpOracle};
pub use patterns::{BugPattern, PatternSeverity, SqlClause, BUG_PATTERNS};

// ============================================================================
// Phase 2 TODOs: Seed Prioritization
// ============================================================================
//
// TODO(phase2): Implement seed energy calculation
// The SQLaser paper uses distance-based energy:
//   energy = 1 / d_CallChain
//
// For Phase 2, we approximate this with pattern coverage:
//   energy = number_of_patterns_exercised * pattern_severity_weight
//
// Implementation steps:
// 1. Track which SqlClauses appear in each test case
// 2. Map clauses to BugPatterns
// 3. Assign higher energy to seeds that hit more/rarer patterns
// 4. Integrate with libfuzzer's energy scheduling

// TODO(phase2): Implement pattern coverage tracking
// Track which patterns have been exercised during the fuzzing run.
// This helps identify blind spots in our testing.
//
// struct PatternCoverage {
//     exercised: HashSet<&'static str>,  // Pattern IDs
//     bug_counts: HashMap<&'static str, usize>,  // Bugs found per pattern
// }

// TODO(phase2): Implement distance calculation for seed prioritization
// From SQLaser paper, Equation 8:
//   d_CallChain = sum_{b in SBB} d(b, TBB)
//
// where SBB = seed basic blocks, TBB = target basic blocks
//
// For Phase 2 (without LLVM), we approximate with clause distance:
//   d_Clause = |target_clauses - seed_clauses|

// ============================================================================
// Phase 3 TODOs: LLVM Instrumentation
// ============================================================================
//
// TODO(phase3): LLVM pass for function call chain tracing
// This requires a separate crate that links against LLVM.
// The pass should:
// 1. Insert hooks at function entry points
// 2. Record call sequences at runtime
// 3. Compare against target call chains
//
// Target call chains for Turso (examples):
// - INDEX + NOCASE: translate_create_index -> resolve_sorted_columns -> CollationSeq::NoCase
// - CAST: translate_expr -> Insn::Cast -> exec_cast
// - DISTINCT: init_distinct -> Insn::OpenEphemeral -> Insn::Found

// TODO(phase3): Implement path-to-path distance calculation
// From SQLaser paper, Section 4.2:
//   d(b, TBB) = (sum_{tb in TBB} d(b, tb)^-1)^-1  (harmonic mean)
//   d(b, tb) = undefined if same function, else df(b, tb)
//   df(b, tb) = shortest path in function call graph

// TODO(phase3): Implement trimmed call chain extraction
// The paper describes "trimming" call chains by tracking clause-related data:
// 1. Identify variables representing clause attributes (e.g., TK_COLLATE, pWhere)
// 2. Track data flow through functions
// 3. Extract only functions that manipulate these variables
//
// For Turso, clause-related data objects:
// - CollationSeq::NoCase -> core/translate/collate.rs
// - Index::where_clause -> core/schema.rs
// - BTreeTable::has_rowid -> core/schema.rs
// - Distinctness::Distinct -> core/translate/plan.rs

// ============================================================================
// Bug Report Template (for discovered bugs)
// ============================================================================
//
// When SQLaser finds a bug, generate a report in this format:
//
// ## Summary
// [One line description]
//
// ## Pattern
// {pattern_id}: {pattern_description}
//
// ## Reproduction SQL
// ```sql
// {setup_statements}
// {query}
// ```
//
// ## Expected (SQLite)
// {sqlite_result}
//
// ## Actual (Turso)
// {turso_result}
//
// ## Oracle
// {oracle_type}: {oracle_explanation}
//
// ## Severity Assessment
// - Can corrupt data? [Analysis based on escalation questions]
// - Can chain with primitives? [List applicable primitives]

/// Marker trait for Phase 2 features.
/// These are not yet implemented but are planned.
#[doc(hidden)]
pub trait Phase2Feature {}

/// Marker trait for Phase 3 features.
/// These require LLVM instrumentation and are planned for later.
#[doc(hidden)]
pub trait Phase3Feature {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_reexports() {
        // Verify all major types are accessible
        let _patterns: &[BugPattern] = BUG_PATTERNS;
        let _severity = PatternSeverity::Critical;
        let _clause = SqlClause::Index;
    }

    #[test]
    fn test_applicable_patterns() {
        let applicable: Vec<_> = BugPattern::turso_applicable().collect();
        assert!(
            applicable.len() >= 30,
            "Expected at least 30 applicable patterns, got {}",
            applicable.len()
        );
    }

    #[test]
    fn test_pattern_by_severity() {
        // Should have patterns at each severity level
        let high: Vec<_> = BugPattern::by_severity(PatternSeverity::High).collect();
        let medium: Vec<_> = BugPattern::by_severity(PatternSeverity::Medium).collect();

        assert!(!high.is_empty(), "Should have HIGH severity patterns");
        assert!(!medium.is_empty(), "Should have MEDIUM severity patterns");
    }
}
