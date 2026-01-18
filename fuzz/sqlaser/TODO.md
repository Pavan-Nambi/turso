# SQLaser Implementation TODOs

## Phase 1: Oracle-Based Detection ✅ COMPLETE

- [x] Bug pattern definitions (35 patterns from paper)
- [x] Testing oracles (NoREC, TLP, LIKELY, INDEX, ROWID)
- [x] Pattern-aware SQL generator
- [x] Turso vs SQLite comparison engine
- [x] Fuzz target integration (`sqlaser.rs`)

## Phase 2: Seed Prioritization

### Pattern Coverage Tracking
- [ ] Track which `SqlClause` values appear in each generated test case
- [ ] Map observed clauses to `BugPattern` definitions
- [ ] Compute coverage metrics (patterns exercised / total applicable patterns)
- [ ] Report gaps in pattern coverage after fuzzing runs

### Energy-Based Seed Selection
From SQLaser paper (Equation 12): `energy = 1 / d_CallChain`

For Phase 2 (without LLVM), approximate with pattern-based energy:
- [ ] Assign base energy to each pattern based on severity
  - CRITICAL: 4x
  - HIGH: 2x
  - MEDIUM: 1x
  - LOW: 0.5x
- [ ] Bonus energy for seeds exercising multiple patterns
- [ ] Bonus energy for patterns not yet exercised
- [ ] Integrate with libfuzzer's energy scheduling (may require custom mutator)

### Implementation Location
```rust
// fuzz/sqlaser/energy.rs
pub struct EnergyCalculator {
    pattern_coverage: HashSet<&'static str>,
    pattern_weights: HashMap<&'static str, f64>,
}

impl EnergyCalculator {
    pub fn calculate_energy(&self, test_case: &TestCase) -> f64 {
        let base = self.pattern_weight(test_case.pattern.id);
        let novelty = if self.pattern_coverage.contains(test_case.pattern.id) {
            1.0
        } else {
            2.0 // Bonus for uncovered patterns
        };
        base * novelty
    }
}
```

## Phase 3: LLVM Instrumentation

### Function Call Chain Tracing
From SQLaser paper (Section 4.1):
- [ ] LLVM pass to insert hooks at function entry points
- [ ] Runtime collection of call sequences
- [ ] Map SQL patterns to Turso function chains

**Target Call Chains for Turso** (to be validated):

| Pattern | Expected Call Chain |
|---------|---------------------|
| INDEX + NOCASE | `translate_create_index` → `resolve_sorted_columns` → collation handling |
| CAST | `translate_expr` → `Insn::Cast` → `exec_cast` |
| DISTINCT | `init_distinct` → `Insn::OpenEphemeral` → `Insn::Found` |
| WITHOUT ROWID | Schema creation → `BTreeTable::has_rowid = false` |
| Partial INDEX | `translate_create_index` → `where_clause` validation |

### Distance Calculation (Section 4.2)
From paper:
```
d_CallChain = d_BB = Σ_{b ∈ SBB} d(b, TBB)

where:
  d(b, TBB) = (Σ_{tb ∈ TBB} d(b, tb)^-1)^-1  (harmonic mean)
  d(b, tb) = undefined if same function, else df(b, tb)
  df(b, tb) = shortest path in function call graph
```

- [ ] Build function call graph at compile time
- [ ] Compute shortest paths between all function pairs
- [ ] Instrument basic blocks with distance information
- [ ] Runtime distance calculation for seeds

### Trimmed Call Chain Extraction
- [ ] Identify clause-related data objects in Turso
  - `CollationSeq::NoCase` → `core/translate/collate.rs`
  - `Index::where_clause` → `core/schema.rs`
  - `BTreeTable::has_rowid` → `core/schema.rs`
  - `Distinctness::Distinct` → `core/translate/plan.rs`
- [ ] Track data flow through functions
- [ ] Extract minimal call chains that manipulate these objects

### Separate LLVM Tooling Crate
```
sqlaser-llvm/
├── Cargo.toml           # depends on inkwell or llvm-sys
├── src/
│   ├── lib.rs
│   ├── call_chain_tracer.rs
│   ├── distance_calculator.rs
│   └── function_instrumenter.rs
└── build.rs             # LLVM linking setup
```

## Testing Requirements

### Unit Tests (Phase 1)
- [x] Pattern definition validation
- [x] Oracle transformation correctness
- [x] Result comparison logic

### Integration Tests (Phase 2)
- [ ] Energy calculation accuracy
- [ ] Pattern coverage tracking
- [ ] Multi-pattern seed handling

### Fuzz Verification (Phase 3)
- [ ] Distance calculation correctness
- [ ] Call chain extraction accuracy
- [ ] End-to-end bug detection

## Metrics to Track

### Bug Detection
- Bugs found per phase
- Time to first bug (TTE)
- Bug pattern distribution

### Coverage
- Code coverage (lines, branches)
- Pattern coverage (patterns exercised)
- Oracle coverage (oracles triggered)

### Performance
- Test cases per second
- Comparison overhead (Turso vs SQLite)
- Oracle overhead

## Known Limitations

1. **No PQS Oracle**: SQLaser paper uses Pivoted Query Synthesis, which we haven't implemented
2. **No rtree Pattern**: R-tree virtual tables not yet supported in Turso
3. **MySQL Patterns**: Some MySQL-specific patterns (e.g., `<=>` operator) don't apply to SQLite/Turso

## References

- [SQLaser Paper](https://arxiv.org/abs/2407.04294)
- [SQLancer](https://github.com/sqlancer/sqlancer) - Reference oracle implementations
- [SQLRight](https://github.com/psu-security-universe/sqlright) - Coverage-guided SQL fuzzing
- [Turso Bug Hunter Guide](./turso-bug-hunter.md) - Internal bug hunting methodology
