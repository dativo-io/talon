#!/usr/bin/env bash
# Fleet Operations v1 demo (#270, epic #265): an operator discovers a fleet of
# AI use cases, reads the attention queue, stops one, and watches it flip to
# STOPPED — offline, deterministic, one command, no API keys.
#
#   ./demo.sh
#
# Every line printed below the "$ ..." prompts is the actual command the script
# runs — nothing is faked. It builds `talon` from this checkout into a temp
# workspace and never touches your real ~/.talon.
set -euo pipefail

trap 'echo "ERROR: demo aborted at line $LINENO (see above)." >&2' ERR

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export TALON_HOME="$WORK/.talon"
mkdir -p "$TALON_HOME"

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
run()  { printf '\n\033[2m$ %s\033[0m\n' "$*"; eval "$*"; }

say "Build talon from this checkout"
run "(cd '$REPO_ROOT' && go build -o '$WORK/talon' ./cmd/talon)"
TALON="$WORK/talon"

say "Discover a fleet: three AI use cases under agents_dir"
mkdir -p "$WORK/agents/customer-support" "$WORK/agents/coding" "$WORK/agents/summarizer"
cat > "$WORK/talon.config.yaml" <<'YAML'
agents_dir: agents
signing_key: "demo-signing-key-0123456789abcdef0123456789abcdef"
YAML
cat > "$WORK/agents/customer-support/agent.talon.yaml" <<'YAML'
agent:
  name: customer-support
  version: "1.0.0"
  tenant_id: acme
policies:
  cost_limits:
    daily: 50
    monthly: 500
YAML
cat > "$WORK/agents/coding/agent.talon.yaml" <<'YAML'
agent:
  name: coding
  version: "1.0.0"
  tenant_id: acme
policies:
  cost_limits:
    daily: 100
    monthly: 1000
YAML
cat > "$WORK/agents/summarizer/agent.talon.yaml" <<'YAML'
agent:
  name: summarizer
  version: "1.0.0"
  tenant_id: acme
policies:
  cost_limits:
    daily: 20
    monthly: 200
YAML
run "(cd '$WORK' && '$TALON' validate --dir agents)"

say "The attention queue: STATE / HEALTH / COST / WHY (offline config view — no gateway running)"
run "(cd '$WORK' && '$TALON' agents)"

say "Stop one agent — host-local, config-backed, signed evidence"
run "(cd '$WORK' && '$TALON' agents disable coding)"

say "The queue reflects it immediately: coding is STOPPED / 'disabled by operator'"
run "(cd '$WORK' && '$TALON' agents)"

say "Inspect one agent"
run "(cd '$WORK' && '$TALON' agents show customer-support)"

say "Done"
note_done() { printf '   %s\n' "$*"; }
note_done "A running 'talon serve' applies the disable within its reload interval (default 30s), no restart."
note_done "Against a live server, 'talon agents' shows RUNTIME state; with none, it labels itself OFFLINE."
