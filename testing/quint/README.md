# MVCC model-based testing

This branch is the minimized version of the MVCC model-based testing work in
the other experimental branches. It keeps one small Quint model and the
essential Quint-to-Whopper adapter. The larger models, shrinker, retained
corpora, and broader campaign machinery are intentionally not included.

The model generates legal histories containing setup operations, one writer
transaction, an optional pinned reader, and concurrent PASSIVE checkpoints.
Whopper replays each history under different deterministic schedules and
checks Turso's public results against the state calculated by the model.

## Install

The runner requires Quint `0.32.0`:

```bash
npm install --global @informalsystems/quint@0.32.0
```

## Run

Run a small smoke campaign:

```bash
TRACE_COUNT=8 ACTOR_SCHEDULES=1 YIELD_PLANS=1 \
  testing/quint/run_mvcc_mbt.sh /tmp/turso-mvcc-mbt-smoke
```

Run the default campaign:

```bash
testing/quint/run_mvcc_mbt.sh
```

The default campaign generates 256 fresh Quint traces, removes semantically
identical programs, and runs every remaining program with eight actor schedules
and four injected-yield plans.

The script prints the Quint seed, search seed, and report directory. Generated
ITF traces are written under `simulator-output/quint-mvcc-mbt/`.
`campaign.report.json` contains the aggregate result, and each failure artifact
contains the trace, operation history, error, and exact replay seeds. A run
exits nonzero when an oracle finds a failure.

To repeat a campaign, reuse the two seeds printed by the original run:

```bash
QUINT_SEED=123 SEARCH_SEED=456 \
  testing/quint/run_mvcc_mbt.sh /tmp/turso-mvcc-mbt-replay
```

To check the bounded model independently:

```bash
quint verify testing/quint/specs/mvcc_semantic_programs.qnt \
  --backend=apalache \
  --invariants=Safety \
  --max-steps=20
```
