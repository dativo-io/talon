#!/usr/bin/env bash
#
# run-benchmarks.sh — reproducible micro-benchmarks for Talon proof-bar metrics.
#
# Measures:
#   - Gateway pipeline overhead (ServeHTTP + local mock upstream, no WAN RTT)
#   - Gateway pipeline overhead with a ~50KB Anthropic prompt (informational)
#   - PII scan latency (classifier)
#   - Evidence write throughput (signed SQLite record per op)
#
# Usage:
#   scripts/run-benchmarks.sh              # print markdown table to stdout
#   scripts/run-benchmarks.sh -o FILE.md   # also write table to FILE
#
# See docs/reference/benchmarks.md for methodology and how to interpret results.
#
set -euo pipefail

cd "$(dirname "$0")/.."

OUTPUT=""
BENCH_TIME="${BENCH_TIME:-2s}"
BENCH_COUNT="${BENCH_COUNT:-5}"
BENCH_PKGS="./internal/gateway/... ./internal/classifier/... ./internal/evidence/..."
BENCH_REGEX='Benchmark(GatewayPipelineOverhead|GatewayPipelineOverheadLargePrompt|PIIScan|EvidenceStore)$'

while getopts "o:" opt; do
  case "$opt" in
    o) OUTPUT="$OPTARG" ;;
    *) echo "Usage: $0 [-o outfile.md]" >&2; exit 2 ;;
  esac
done

if [ "$(uname -s)" = "Darwin" ]; then
  GO_ENV=(env -u CC CC=/usr/bin/clang CGO_ENABLED=1)
else
  GO_ENV=(env CGO_ENABLED=1)
fi

bench_out=$("${GO_ENV[@]}" go test \
  -bench="$BENCH_REGEX" \
  -benchmem \
  -benchtime="$BENCH_TIME" \
  -count="$BENCH_COUNT" \
  -run='^$' \
  $BENCH_PKGS 2>&1) || {
  echo "$bench_out" >&2
  exit 1
}

# Parse last result line per benchmark name (go test -count repeats runs).
# The name match is anchored ("Name" or "Name-GOMAXPROCS", nothing after) so
# BenchmarkGatewayPipelineOverhead never swallows ...OverheadLargePrompt lines.
parse_ns_per_op() {
  local name="$1"
  printf '%s\n' "$bench_out" \
    | awk -v n="$name" '$1 ~ ("^Benchmark" n "(-[0-9]+)?$") { last=$3 } END { print last+0 }'
}

parse_allocs() {
  local name="$1"
  printf '%s\n' "$bench_out" \
    | awk -v n="$name" '$1 ~ ("^Benchmark" n "(-[0-9]+)?$") && $0 ~ /allocs\/op/ { last=$(NF-1)" "$NF } END { print last }'
}

ns_to_ms() {
  awk -v ns="$1" 'BEGIN { if (ns+0 <= 0) { print "n/a"; exit } printf "%.2f", ns/1e6 }'
}

ns_to_ops_per_sec() {
  awk -v ns="$1" 'BEGIN { if (ns+0 <= 0) { print "n/a"; exit } printf "%.0f", 1e9/ns }'
}

gw_ns=$(parse_ns_per_op GatewayPipelineOverhead)
gwlp_ns=$(parse_ns_per_op GatewayPipelineOverheadLargePrompt)
pii_ns=$(parse_ns_per_op PIIScan)
ev_ns=$(parse_ns_per_op EvidenceStore)

gw_ms=$(ns_to_ms "$gw_ns")
gwlp_ms=$(ns_to_ms "$gwlp_ns")
pii_ms=$(ns_to_ms "$pii_ns")
ev_ms=$(ns_to_ms "$ev_ns")
ev_ops=$(ns_to_ops_per_sec "$ev_ns")

gw_allocs=$(parse_allocs GatewayPipelineOverhead)
gwlp_allocs=$(parse_allocs GatewayPipelineOverheadLargePrompt)
pii_allocs=$(parse_allocs PIIScan)
ev_allocs=$(parse_allocs EvidenceStore)

commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
generated=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
go_ver=$("${GO_ENV[@]}" go version | sed 's/^go version //')
os_info=$(uname -srm 2>/dev/null || uname -a)
cpu_info=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | xargs || echo "unknown")

table=$(cat <<EOF
## Benchmark results (generated)

| Metric | Benchmark | Median (last of ${BENCH_COUNT} runs) | Allocs/op |
|--------|-----------|--------------------------------------|-----------|
| Gateway pipeline overhead | \`BenchmarkGatewayPipelineOverhead\` | **${gw_ms} ms**/req | ${gw_allocs:-n/a} |
| Gateway overhead — ~50KB Anthropic prompt (informational) | \`BenchmarkGatewayPipelineOverheadLargePrompt\` | **${gwlp_ms} ms**/req | ${gwlp_allocs:-n/a} |
| PII scan latency | \`BenchmarkPIIScan\` | **${pii_ms} ms**/scan | ${pii_allocs:-n/a} |
| Evidence write throughput | \`BenchmarkEvidenceStore\` | **${ev_ops} writes/s** (~${ev_ms} ms/write) | ${ev_allocs:-n/a} |

**Environment:** ${go_ver} · ${os_info} · ${cpu_info}  
**Commit:** \`${commit}\` · **Generated:** ${generated}  
**Settings:** \`-benchtime=${BENCH_TIME}\` \`-count=${BENCH_COUNT}\` \`-benchmem\`

Gateway overhead uses a local \`httptest\` upstream (no WAN RTT). Compare to the README
"< 15 ms excluding upstream" claim and the step budget in
[What Talon does to your request](../explanation/what-talon-does-to-your-request.md).

Retry/fallback decision overhead is **not** included until Epic #113 (#138/#139) lands.
The ~50KB Anthropic large-prompt benchmark is informational only and does not join the
benchmark regression gate yet.
EOF
)

echo "$table"

if [ -n "$OUTPUT" ]; then
  mkdir -p "$(dirname "$OUTPUT")"
  {
    echo "# Talon benchmark snapshot"
    echo ""
    echo "$table"
    echo ""
    echo "Reproduce: \`make benchmarks\` or \`scripts/run-benchmarks.sh\`."
  } >"$OUTPUT"
  echo "Wrote $OUTPUT" >&2
fi

# Raw bench output for auditors who want the full go test lines.
echo "" >&2
echo "--- raw go test -bench output ---" >&2
printf '%s\n' "$bench_out" | grep -E '^Benchmark|^[0-9]+ ' >&2
