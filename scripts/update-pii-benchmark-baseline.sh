#!/usr/bin/env bash
# Regenerate the platform-specific BenchmarkPIIScan baseline artifact.
# Usage: bash scripts/update-pii-benchmark-baseline.sh
set -euo pipefail

cd "$(dirname "$0")/.."

BENCH_TIME="${BENCH_TIME:-1s}"
BENCH_COUNT="${BENCH_COUNT:-5}"
THRESHOLD="${THRESHOLD:-10.0}"

GOOS="$(go env GOOS)"
GOARCH="$(go env GOARCH)"
OUT="testdata/benchmarks/pii_scan_baseline.${GOOS}.${GOARCH}.json"

if [ "$(uname -s)" = "Darwin" ]; then
  GO_ENV=(env -u CC CC=/usr/bin/clang CGO_ENABLED=1)
else
  GO_ENV=(env CGO_ENABLED=1)
fi

bench_out=$("${GO_ENV[@]}" go test ./internal/classifier \
  -run '^$' \
  -bench '^BenchmarkPIIScan$' \
  -benchmem \
  -benchtime="$BENCH_TIME" \
  -count="$BENCH_COUNT" 2>&1) || {
  echo "$bench_out" >&2
  exit 1
}

echo "$bench_out"

BENCH_OUT="$bench_out" OUT="$OUT" GOOS="$GOOS" GOARCH="$GOARCH" \
  BENCH_TIME="$BENCH_TIME" BENCH_COUNT="$BENCH_COUNT" THRESHOLD="$THRESHOLD" \
  python3 <<'PY'
import json
import os
import re
import statistics
from datetime import datetime, timezone

out_path = os.environ["OUT"]
goos = os.environ["GOOS"]
goarch = os.environ["GOARCH"]
bench_time = os.environ["BENCH_TIME"]
bench_count = int(os.environ["BENCH_COUNT"])
threshold = float(os.environ["THRESHOLD"])

vals = []
for line in os.environ.get("BENCH_OUT", "").splitlines():
    m = re.search(r"^BenchmarkPIIScan-\d+\s+\d+\s+([0-9.]+)\s+ns/op", line)
    if m:
        vals.append(float(m.group(1)))

if not vals:
    raise SystemExit("unable to parse BenchmarkPIIScan ns/op from benchmark output")

median_ns = statistics.median(vals)
payload = {
    "benchmark": "BenchmarkPIIScan",
    "unit": "ns/op",
    "baseline_ns_per_op": int(round(median_ns)),
    "threshold_percent": threshold,
    "sample_count": bench_count,
    "bench_time": bench_time,
    "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "platform": f"{goos}/{goarch}",
    "notes": f"Median from BenchmarkPIIScan ({bench_count}x -count={bench_count}, -benchtime={bench_time}) on this host.",
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")

print(f"Wrote baseline median {median_ns:.0f} ns/op to {out_path}")
PY
