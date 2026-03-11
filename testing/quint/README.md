# Quint Trace Lane (WAL First)

This directory hosts the spec-driven lane that feeds Turso's existing bug-finding stack.

- Quint produces deterministic ITF traces with MBT metadata.
- `turso_whopper --script-itf` replays those traces against the real engine.
- `differential_fuzzer --seed-corpus` can consume the same trace files (or derived SQL).

## Generate deterministic traces

```bash
testing/quint/generate_traces.sh \
  --spec testing/quint/specs/wal_txn.qnt \
  --out-dir simulator-output/quint-wal \
  --seed 0x5eed \
  --n-traces 8 \
  --max-steps 64 \
  --max-samples 20000 \
  --invariant map_domain_is_stable
```

Corruption-focused lane (WAL + reopen + integrity probes):

```bash
testing/quint/generate_traces.sh \
  --spec testing/quint/specs/wal_corruption.qnt \
  --out-dir simulator-output/quint-corruption \
  --seed 0xc011ab1e \
  --n-traces 64 \
  --max-steps 80 \
  --max-samples 120000 \
  --invariant non_negative_blob_sizes
```

Outputs:

- `trace_*.itf.json` files
- `manifest.json` (seed, spec hash, quint version, options, traces)

The generator hard-fails if any state in any ITF trace is missing:

- `mbt::actionTaken`
- `mbt::nondetPicks`

## Replay in concurrent simulator

```bash
cargo run -p turso_whopper -- \
  --mode fast \
  --max-connections 4 \
  --script-itf simulator-output/quint-wal/trace_0.itf.json \
  --script-strict \
  --script-repeat 4
```

For corruption campaigns, use strict replay with one pass per trace:

```bash
cargo run -p turso_whopper -- \
  --mode chaos \
  --max-connections 8 \
  --script-itf simulator-output/quint-corruption/trace_0.itf.json \
  --script-strict \
  --script-repeat 1
```

The corruption spec emits `opIntegrityCheck`, which maps to `Operation::IntegrityCheck`.
`IntegrityCheckProperty` validates that the result is exactly `"ok"` (or a known busy retry class),
so corrupted states fail loudly.

End-to-end helper:

```bash
bash testing/quint/run_corruption_campaign.sh \
  simulator-output/quint-corruption \
  0xc011ab1e \
  32 \
  72 \
  100000
```

## Seed differential fuzzer

```bash
cargo run --bin differential_fuzzer -- \
  --seed 123 \
  --n 500 \
  --seed-corpus simulator-output/quint-wal/trace_0.itf.json
```
