#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

GOOS="$(go env GOOS)"
GOARCH="$(go env GOARCH)"
PLATFORM="${GOOS}.${GOARCH}"
DEFAULT_BASELINE="testdata/benchmarks/pii_scan_baseline.${PLATFORM}.json"
BASELINE_FILE="${BASELINE_FILE:-$DEFAULT_BASELINE}"
BENCH_TIME="${BENCH_TIME:-1s}"
BENCH_COUNT="${BENCH_COUNT:-5}"

if [ ! -f "$BASELINE_FILE" ]; then
  echo "baseline file not found for ${GOOS}/${GOARCH}: $BASELINE_FILE" >&2
  echo "Generate one with: make benchmark-baseline-update" >&2
  echo "Or skip this gate with: SKIP_BENCHMARK_REGRESSION=1 make proof-gates" >&2
  exit 2
fi

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

if ! BENCH_OUT="$bench_out" python3 - "$BASELINE_FILE" <<'PY'
import json
import os
import re
import statistics
import sys

baseline_path = sys.argv[1]
with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = json.load(f)

threshold = float(baseline.get("threshold_percent", 10.0))
baseline_ns = float(baseline["baseline_ns_per_op"])
allowed_ns = baseline_ns * (1.0 + threshold / 100.0)

vals = []
for line in os.environ.get("BENCH_OUT", "").splitlines():
    m = re.search(r"^BenchmarkPIIScan-\d+\s+\d+\s+([0-9.]+)\s+ns/op", line)
    if m:
        vals.append(float(m.group(1)))

if not vals:
    print("unable to parse BenchmarkPIIScan ns/op from benchmark output", file=sys.stderr)
    sys.exit(2)

median_ns = statistics.median(vals)
platform = baseline.get("platform", "unknown")
print(
    f"BenchmarkPIIScan median: {median_ns:.0f} ns/op "
    f"(baseline {baseline_ns:.0f}, allowed <= {allowed_ns:.0f}, threshold {threshold:.1f}%, platform {platform})"
)

if median_ns > allowed_ns:
    print("regression threshold exceeded", file=sys.stderr)
    sys.exit(1)
PY
then
  echo "$bench_out" >&2
  exit 1
fi
