#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPEC="$REPO_ROOT/testing/quint/specs/mvcc_semantic_programs.qnt"
OUT_DIR="${1:-$REPO_ROOT/simulator-output/quint-mvcc-mbt}"
TRACE_COUNT="${TRACE_COUNT:-256}"
ACTOR_SCHEDULES="${ACTOR_SCHEDULES:-8}"
YIELD_PLANS="${YIELD_PLANS:-4}"
EXPECTED_QUINT_VERSION="${EXPECTED_QUINT_VERSION:-0.32.0}"

if ! command -v quint >/dev/null 2>&1; then
  echo "quint is required to generate MVCC programs" >&2
  exit 1
fi
if [[ "$(quint --version)" != "$EXPECTED_QUINT_VERSION" ]]; then
  echo "expected Quint $EXPECTED_QUINT_VERSION, found $(quint --version)" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
REPORT_DIR="${REPORT_DIR:-$(mktemp -d "$OUT_DIR/reports.XXXXXX")}"
mkdir -p "$REPORT_DIR"

(
  cd "$REPO_ROOT"
  cargo build -q -p turso_whopper
)

TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$REPO_ROOT/$TARGET_DIR"
fi
WHOPPER_BIN="$TARGET_DIR/debug/turso_whopper"

random_u64() {
  od -An -N8 -tu8 /dev/urandom | tr -d '[:space:]'
}

quint_seed="${QUINT_SEED:-$(random_u64)}"
search_seed="${SEARCH_SEED:-${SEED:-$(random_u64)}}"

echo "quint seed: $quint_seed"
echo "search seed: $search_seed"

quint run "$SPEC" \
  --backend=rust \
  --mbt \
  "--out-itf=$OUT_DIR/trace_{seq}.itf.json" \
  "--n-traces=$TRACE_COUNT" \
  --max-steps=20 \
  --max-samples=20000 \
  --invariant=Safety \
  --witnesses=CampaignComplete \
  --verbosity=1 \
  "--seed=$quint_seed"

args=(
  --mvcc-mbt-corpus-dir "$OUT_DIR"
  --mvcc-mbt-trace-count "$TRACE_COUNT"
  --mvcc-mbt-actor-schedules "$ACTOR_SCHEDULES"
  --mvcc-mbt-yield-plans "$YIELD_PLANS"
  --mvcc-mbt-report-dir "$REPORT_DIR"
  --mvcc-mbt-keep-going
)

status=0
env "RUST_LOG=${RUST_LOG:-off}" "SEED=$search_seed" \
  "$WHOPPER_BIN" "${args[@]}" || status=$?
echo "reports: $REPORT_DIR"
exit "$status"
