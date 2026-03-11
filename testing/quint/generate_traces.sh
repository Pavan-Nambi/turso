#!/usr/bin/env bash
set -euo pipefail

SPEC=""
OUT_DIR=""
SEED=""
N_TRACES=4
MAX_STEPS=64
MAX_SAMPLES=20000
BACKEND="rust"
INVARIANT=""
WITNESS=""

usage() {
  cat <<'EOF'
Usage:
  generate_traces.sh --spec <file.qnt> --out-dir <dir> --seed <seed>
                     [--n-traces <n>] [--max-steps <n>] [--max-samples <n>]
                     [--backend rust|typescript]
                     [--invariant <name> | --witness <name>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --spec)
      SPEC="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --n-traces)
      N_TRACES="$2"
      shift 2
      ;;
    --max-steps)
      MAX_STEPS="$2"
      shift 2
      ;;
    --max-samples)
      MAX_SAMPLES="$2"
      shift 2
      ;;
    --backend)
      BACKEND="$2"
      shift 2
      ;;
    --invariant)
      INVARIANT="$2"
      shift 2
      ;;
    --witness)
      WITNESS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SPEC" || -z "$OUT_DIR" || -z "$SEED" ]]; then
  echo "Missing required flags." >&2
  usage
  exit 1
fi

if [[ -n "$INVARIANT" && -n "$WITNESS" ]]; then
  echo "Use either --invariant or --witness, not both." >&2
  exit 1
fi

if ! command -v quint >/dev/null 2>&1; then
  echo "quint CLI is not installed or not on PATH." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/trace_*.itf.json

TRACE_PATTERN="$OUT_DIR/trace_{seq}.itf.json"

CMD=(
  quint run
  "--backend=$BACKEND"
  "--mbt"
  "--out-itf=$TRACE_PATTERN"
  "--seed=$SEED"
  "--n-traces=$N_TRACES"
  "--max-steps=$MAX_STEPS"
  "--max-samples=$MAX_SAMPLES"
  "$SPEC"
)

if [[ -n "$INVARIANT" ]]; then
  CMD+=("--invariant=$INVARIANT")
fi
if [[ -n "$WITNESS" ]]; then
  CMD+=("--witness=$WITNESS")
fi

"${CMD[@]}"

python3 - <<'PY' "$OUT_DIR"
import glob
import json
import os
import sys

out_dir = sys.argv[1]
files = sorted(glob.glob(os.path.join(out_dir, "trace_*.itf.json")))
if not files:
    raise SystemExit(f"no ITF traces generated in {out_dir}")

for path in files:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    states = doc.get("states")
    if not isinstance(states, list) or not states:
        raise SystemExit(f"{path}: missing/empty states array")
    for i, state in enumerate(states):
        if "mbt::actionTaken" not in state:
            raise SystemExit(f"{path}: state {i} missing mbt::actionTaken")
        if "mbt::nondetPicks" not in state:
            raise SystemExit(f"{path}: state {i} missing mbt::nondetPicks")
PY

SPEC_HASH="$(sha256sum "$SPEC" | awk '{print $1}')"
QUINT_VERSION="$(quint --version | head -n 1)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - <<'PY' \
  "$OUT_DIR" "$TIMESTAMP" "$SEED" "$SPEC" "$SPEC_HASH" "$QUINT_VERSION" \
  "$BACKEND" "$N_TRACES" "$MAX_STEPS" "$MAX_SAMPLES" "$INVARIANT" "$WITNESS"
import glob
import json
import os
import sys

(
    out_dir,
    generated_at,
    seed,
    spec,
    spec_hash,
    quint_version,
    backend,
    n_traces,
    max_steps,
    max_samples,
    invariant,
    witness,
) = sys.argv[1:]

trace_files = [os.path.basename(p) for p in sorted(glob.glob(os.path.join(out_dir, "trace_*.itf.json")))]
manifest = {
    "schema_version": 1,
    "generated_at_utc": generated_at,
    "seed": seed,
    "spec_path": spec,
    "spec_sha256": spec_hash,
    "quint_version": quint_version,
    "backend": backend,
    "n_traces": int(n_traces),
    "max_steps": int(max_steps),
    "max_samples": int(max_samples),
    "invariant": invariant or None,
    "witness": witness or None,
    "trace_files": trace_files,
}

with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "Generated $(ls "$OUT_DIR"/trace_*.itf.json | wc -l | tr -d ' ') traces in $OUT_DIR"
echo "Manifest: $OUT_DIR/manifest.json"
