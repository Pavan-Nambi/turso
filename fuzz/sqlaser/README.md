# SQLaser: Clause-Guided Fuzzing for Turso

Clause-guided fuzzing for detecting logic bugs in Turso, inspired by the [SQLaser paper](https://arxiv.org/abs/2407.04294).

## Overview

SQLaser targets **error-prone SQL clause combinations** that historically trigger logic bugs in DBMSs. Rather than blind coverage-guided fuzzing, we focus testing energy on the 35 bug patterns identified in the research.

**Key insight**: Logic bugs cluster around specific clause combinations (e.g., `INDEX + NOCASE + WITHOUT ROWID`). By generating SQL that exercises these combinations and validating with oracles, we catch bugs more efficiently.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SQLaser Fuzzer                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Bug Pattern  │───▶│ SQL Generator │───▶│  Turso Execution     │   │
│  │ Definitions  │    │ (Clause-Aware)│    │                      │   │
│  └──────────────┘    └──────────────┘    └──────────┬───────────┘   │
│                                                      │               │
│  ┌──────────────┐    ┌──────────────┐              ▼               │
│  │   SQLite     │◀───│  Comparison  │◀───────────────────────────   │
│  │  (rusqlite)  │    │   Engine     │                               │
│  └──────────────┘    └──────────────┘                               │
│                            │                                         │
│                            ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Testing Oracles                           │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ │    │
│  │  │ NoREC   │ │  TLP    │ │  INDEX  │ │ ROWID   │ │ LIKELY │ │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                            │                                         │
│                            ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Bug Detection                               │   │
│  │  • Result mismatch (Turso vs Oracle)                          │   │
│  │  • Result mismatch (Turso vs SQLite)                          │   │
│  │  • Crash/panic detection                                      │   │
│  │  • Timeout detection                                          │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Phases

### Phase 1: Oracle-Based Detection (Current)

Pure SQL-level testing without LLVM instrumentation:
- Pattern-aware SQL generation
- Testing oracles (NoREC, TLP, INDEX, ROWID, LIKELY)
- Turso vs SQLite comparison
- Crash and timeout detection

### Phase 2: Seed Prioritization (TODO)

Add intelligent seed selection:
- Track which patterns each seed exercises
- Prioritize seeds hitting multiple bug patterns
- Distance-based energy allocation

### Phase 3: LLVM Instrumentation (TODO)

Function-chain-guided fuzzing:
- LLVM passes to trace call chains
- Distance calculation between seed chains and target chains
- Full SQLaser algorithm implementation

## Usage

```bash
# Run the clause-guided fuzzer
cargo fuzz run sqlaser

# Run with specific pattern focus
cargo fuzz run sqlaser -- --pattern=index_nocase

# Run with extended timeout for complex patterns
cargo fuzz run sqlaser -- --timeout=60
```

## Testing

```bash
# Run unit tests for patterns and oracles
cargo test -p limbo-fuzz --lib

# Run integration tests
cargo test -p limbo-fuzz --test sqlaser_integration
```
