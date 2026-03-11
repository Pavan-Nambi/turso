#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-simulator-output/quint-corruption}"
SEED="${2:-0xc011ab1e}"
N_TRACES="${3:-32}"
MAX_STEPS="${4:-72}"
MAX_SAMPLES="${5:-100000}"

SPEC="testing/quint/specs/wal_corruption.qnt"

testing/quint/generate_traces.sh \
  --spec "$SPEC" \
  --out-dir "$OUT_DIR" \
  --seed "$SEED" \
  --n-traces "$N_TRACES" \
  --max-steps "$MAX_STEPS" \
  --max-samples "$MAX_SAMPLES" \
  --backend rust \
  --invariant non_negative_blob_sizes

cargo build -q -p turso_whopper

python3 - <<'PY' "$OUT_DIR"
import re
import subprocess
import sys
import time
from pathlib import Path

out_dir = Path(sys.argv[1])
trace_files = sorted(
    out_dir.glob("trace_*.itf.json"),
    key=lambda p: int(re.search(r"trace_(\d+)\.itf\.json$", p.name).group(1)),
)
if not trace_files:
    raise SystemExit(f"no traces found in {out_dir}")

result_tsv = out_dir / "whopper_corruption_results.tsv"
fail_dir = out_dir / "whopper_corruption_failures"
fail_dir.mkdir(parents=True, exist_ok=True)
result_tsv.write_text("idx\ttrace\trc\tstatus\tduration_s\n")

base_cmd = [
    "target/debug/turso_whopper",
    "--mode",
    "chaos",
    "--max-connections",
    "8",
    "--script-strict",
    "--script-repeat",
    "1",
]

ok = fail = timeout = 0
start = time.time()
for i, trace in enumerate(trace_files):
    cmd = base_cmd + ["--script-itf", str(trace)]
    t0 = time.time()
    status = "ok"
    rc = 0
    out = ""
    err = ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        rc = proc.returncode
        out = proc.stdout
        err = proc.stderr
        if rc == 0:
            ok += 1
        else:
            fail += 1
            status = "fail"
    except subprocess.TimeoutExpired as ex:
        rc = 124
        fail += 1
        timeout += 1
        status = "timeout"
        out = ex.stdout or ""
        err = ex.stderr or ""

    dt = time.time() - t0
    with result_tsv.open("a", encoding="utf-8") as f:
        f.write(f"{i}\t{trace.name}\t{rc}\t{status}\t{dt:.3f}\n")

    if status != "ok":
        (fail_dir / f"{trace.stem}.log").write_text(
            f"cmd: {' '.join(cmd)}\n"
            f"rc: {rc}\n"
            f"status: {status}\n"
            f"duration_s: {dt:.3f}\n\n"
            f"--- stdout ---\n{out}\n\n"
            f"--- stderr ---\n{err}\n",
            encoding="utf-8",
        )

    if (i + 1) % 10 == 0 or (i + 1) == len(trace_files):
        elapsed = time.time() - start
        print(
            f"progress {i + 1}/{len(trace_files)} ok={ok} fail={fail} timeout={timeout} elapsed={elapsed:.1f}s",
            flush=True,
        )

print(
    f"DONE total={len(trace_files)} ok={ok} fail={fail} timeout={timeout} results={result_tsv}",
    flush=True,
)
PY
