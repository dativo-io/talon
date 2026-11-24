#!/usr/bin/env bash
# n8n x Talon conformance (#575; the pinned n8n profile shared with #576).
#
# Stock n8n nodes call the model through Talon's OpenAI-compatible gateway
# with the onboarding guide's settings (an OpenAI credential: Base URL
# <talon>/v1/proxy/openai/v1, API key = the use case's Talon key). A
# deterministic mock provider stands behind Talon and records what Talon
# forwarded; nothing calls a real provider. Checked (tests/n8n/check.py):
# Basic LLM Chain and AI Agent with the Chat Model's Responses API on and off,
# a tool round trip, JSON output, streaming through a streaming webhook, the
# HTTP Request node, a company PII denial with zero provider calls, and a
# forbidden tool removed before the model sees it.
#
# n8n: the pinned image through Docker (TALON_N8N_IMAGE), or a local n8n
# executable (TALON_N8N_BIN, node >= 24) where Docker is unavailable.
# Talon: TALON_E2E_BINARY (a release executable) or a source build.
# Prerequisites: python3, curl, openssl; go for a source build.
set -euo pipefail

N8N_IMAGE="${TALON_N8N_IMAGE:-n8nio/n8n:2.49.5@sha256:c349b24d6e242b4ea14d75e6f1a90c50e348cf4b1c4512b4a0a50219ead6533d}"
TALON_PORT=18080 MOCK_PORT=18999 N8N_PORT=15678
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
missing=()
for tool in python3 curl openssl; do command -v "$tool" >/dev/null 2>&1 || missing+=("$tool"); done
if [ -z "${TALON_N8N_BIN:-}" ]; then command -v docker >/dev/null 2>&1 || missing+=("docker (or TALON_N8N_BIN)"); fi
if [ "${#missing[@]}" -gt 0 ]; then echo "n8n-compat: missing prerequisite(s): ${missing[*]}" >&2; exit 2; fi

W="$(mktemp -d "${TMPDIR:-/tmp}/n8n-compat.XXXXXX")"
pids=()
n8n_container=""
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  if [ -n "$n8n_container" ]; then docker rm -f "$n8n_container" >/dev/null 2>&1 || true; fi
  if [ -z "${KEEP_N8N_COMPAT:-}" ]; then rm -rf "$W"; else echo "n8n-compat: run directory kept: $W"; fi
}
trap cleanup EXIT

# --- Talon, set up as the onboarding guide does --------------------------
if [ -n "${TALON_E2E_BINARY:-}" ]; then
  TALON="$TALON_E2E_BINARY"
else
  (cd "$REPO_ROOT" && go build -o "$W/talon" ./cmd/talon)
  TALON="$W/talon"
fi
echo "n8n-compat: $("$TALON" version | head -1); n8n: ${TALON_N8N_BIN:-$N8N_IMAGE}"
python3 "$REPO_ROOT/tests/n8n/mock_openai.py" "$MOCK_PORT" "$W/requests.jsonl" & pids+=($!)
mkdir -p "$W/talon-home" "$W/install"
cd "$W/install"
export HOME="$W/talon-home"
unset TALON_DATA_DIR TALON_SECRETS_KEY TALON_SIGNING_KEY TALON_ADMIN_KEY TALON_AGENTS_DIR TALON_GATEWAY_CONFIG
(umask 077; printf 'TALON_SECRETS_KEY=%s\nTALON_SIGNING_KEY=%s\nTALON_ADMIN_KEY=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > talon.env)
set -a
# talon.env is generated just above, so there is nothing to follow.
# shellcheck source=/dev/null
. ./talon.env
set +a
cat > talon.config.yaml <<YAML
agents_dir: ./agents
gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      secret_name: "openai-api-key"
      base_url: "http://127.0.0.1:$MOCK_PORT"
  organization_policy:
    defaults:
      pii_action: block
      daily_cost: 50
      monthly_cost: 500
    constraints:
      forbidden_tools: ["delete_*"]
YAML
printf '%s' mock-provider-key | "$TALON" secrets set openai-api-key >/dev/null
"$TALON" agents add n8n-support --owner support-ops --description "n8n Customer Support workflow" > "$W/register.txt"
KEY="$(awk '/Application key/{getline; gsub(/^ +| +$/,""); print; exit}' "$W/register.txt")"
[ -n "$KEY" ] || { echo "FAIL n8n-compat: talon agents add printed no key" >&2; exit 1; }
"$TALON" serve --host 127.0.0.1 --port "$TALON_PORT" --gateway --gateway-config talon.config.yaml > "$W/serve.log" 2>&1 & pids+=($!)
for _ in $(seq 1 300); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TALON_PORT/v1/secrets")" = 401 ] && break; sleep 0.1; done
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TALON_PORT/v1/secrets")" = 401 ] || { echo "FAIL n8n-compat: talon serve did not start" >&2; tail -20 "$W/serve.log" >&2; exit 1; }

# --- n8n: the same commands through Docker or a local executable ---------
n8n_vars=(
  "N8N_USER_FOLDER=$W/n8n" "HOME=$W/n8n-home" "N8N_ENCRYPTION_KEY=$(openssl rand -hex 24)"
  "N8N_DIAGNOSTICS_ENABLED=false" "N8N_VERSION_NOTIFICATIONS_ENABLED=false" "N8N_TEMPLATES_ENABLED=false"
  "N8N_PERSONALIZATION_ENABLED=false" "N8N_LOG_LEVEL=info" "N8N_PORT=$N8N_PORT" "N8N_LISTEN_ADDRESS=127.0.0.1"
)
mkdir -p "$W/n8n" "$W/n8n-home"
n8n_cli() {
  if [ -n "${TALON_N8N_BIN:-}" ]; then
    env "${n8n_vars[@]}" "$TALON_N8N_BIN" "$@"
  else
    local e=(); for v in "${n8n_vars[@]}"; do e+=(-e "$v"); done
    docker run --rm --network host --user "$(id -u):$(id -g)" -v "$W:$W" "${e[@]}" --entrypoint n8n "$N8N_IMAGE" "$@"
  fi
}
python3 "$REPO_ROOT/tests/n8n/workflows.py" "$W/wf" "http://127.0.0.1:$TALON_PORT" "$KEY" >/dev/null
mkdir -p "$W/wf/workflows" && mv "$W"/wf/w*.json "$W/wf/workflows/"
n8n_cli import:credentials --input="$W/wf/credentials.json" > "$W/import-credentials.log" 2>&1
n8n_cli import:workflow --separate --input="$W/wf/workflows" > "$W/import-workflows.log" 2>&1
lines() { if [ -f "$W/requests.jsonl" ]; then wc -l < "$W/requests.jsonl" | tr -d ' '; else echo 0; fi; }

for f in "$W"/wf/workflows/w*.json; do
  id="$(basename "$f" .json)"
  case "$id" in *stream*) continue ;; esac
  before="$(lines)"
  set +e; n8n_cli execute --id="$id" > "$W/out-$id.txt" 2>&1; code=$?; set -e
  echo "$code" > "$W/exit-$id.txt"; echo "$before $(lines)" > "$W/slice-$id.txt"
  echo "n8n-compat: executed $id (exit $code)"
done

# Streaming needs n8n as a server: a streaming webhook in front of the agent.
for id in w9streamresp0001 wAstreamcompl001; do n8n_cli publish:workflow --id="$id" > "$W/publish-$id.log" 2>&1; done
if [ -n "${TALON_N8N_BIN:-}" ]; then
  env "${n8n_vars[@]}" "$TALON_N8N_BIN" start > "$W/n8n-server.log" 2>&1 & pids+=($!)
else
  n8n_container="talon-n8n-compat-$$"
  e=(); for v in "${n8n_vars[@]}"; do e+=(-e "$v"); done
  docker run -d --name "$n8n_container" --network host --user "$(id -u):$(id -g)" -v "$W:$W" "${e[@]}" --entrypoint n8n "$N8N_IMAGE" start > /dev/null
fi
registered=0
for _ in $(seq 1 360); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$N8N_PORT/healthz")" = 200 ]; then
    registered="$(python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('select count(*) from webhook_entity').fetchone()[0])" "$W/n8n/.n8n/database.sqlite" 2>/dev/null || echo 0)"
    [ "$registered" -ge 2 ] && break
  fi
  sleep 0.5
done
[ "$registered" -ge 2 ] || { echo "FAIL n8n-compat: n8n registered $registered of 2 streaming webhooks" >&2; exit 1; }
for path in talon-stream-responses talon-stream-completions; do
  before="$(lines)"
  curl -sN --max-time 60 -X POST -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$N8N_PORT/webhook/$path" > "$W/body-$path.txt" || true
  echo "$before $(lines)" > "$W/slice-$path.txt"
  echo "n8n-compat: streamed through webhook $path"
done

"$TALON" agents show n8n-support > "$W/agents-show.txt" 2>&1 || true
python3 "$REPO_ROOT/tests/n8n/check.py" "$W"
