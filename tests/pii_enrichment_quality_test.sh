#!/usr/bin/env bash
#
# Dativo Talon — PII Semantic Enrichment Quality Comparison Test
#
# Compares LLM response quality when the INPUT prompt is redacted with basic
# placeholders vs semantically enriched placeholders.
#
# WHAT THIS MEASURES:
#   Talon redacts PII from the INPUT prompt BEFORE the LLM sees it (redact_input: true).
#   Output redaction is OFF (redact_output: false) so we see raw LLM responses.
#   - Variant A: basic input redaction → LLM sees [PERSON], [LOCATION]
#   - Variant B: enriched input redaction → LLM sees <PII type="person" gender="male"/>,
#     <PII type="location" scope="city"/>
#   The prompts are designed to REQUIRE gender/scope reasoning, so Variant A loses
#   critical context while Variant B retains it. The judge evaluates whether the
#   enriched placeholders enable better reasoning.
#
# Examples of what each variant sees:
#   Original: "Mr. Kowalski and Mrs. Kowalski are comparing heights. Who is taller?"
#   A: "[PERSON] and [PERSON] are comparing heights. Who is taller?" → can't reason
#   B: "<PII type="person" gender="male" id="1"/> and <PII ... gender="female" .../>"
#      → knows id=1 is male → statistically taller → correct reasoning
#
#   Original: "IBAN DE89370400440532013000 — use SEPA or SWIFT for transfer?"
#   A: "[IBAN] — use SEPA or SWIFT?" → can't determine country → uncertain
#   B: "<PII type="iban" country_code="DE" .../>" → knows it's DE → SEPA → correct
#
#   Original: "Lead emailed from j.smith@gmail.com. Route to B2B or B2C?"
#   A: "[EMAIL]. Route to B2B or B2C?" → no domain info → guessing
#   B: "<PII type="email" domain_type="free" .../>" → free email → B2C → correct
#
# Phase 0: LLM generates N prompts that REQUIRE semantic attributes to answer:
#   gender (person), scope (location), country_code (IBAN/phone), domain_type (email).
# Phase 1: Sends each prompt through Talon twice with input redaction ON, output
#   redaction OFF. Each variant sends a DIFFERENTLY redacted prompt to the LLM.
# Phase 2: LLM-as-Judge evaluates which variant produced better reasoning.
#
# Evaluation methodology:
#   - Criteria: Attribute-Based Reasoning, Utility Preservation, Semantic Coherence,
#     Helpfulness — designed to measure whether enriched attributes enable reasoning.
#   - Position bias mitigation: response order randomised per prompt.
#   - Self-enhancement bias acknowledged: same model generates and judges (documented
#     limitation; acceptable for relative A-vs-B comparison on identical prompts).
#
# Usage:
#   ./pii_enrichment_quality_test.sh               # 10 prompts, gpt-4o-mini (defaults)
#   NUM_PROMPTS=5 ./pii_enrichment_quality_test.sh  # 5 prompts per variant
#   MODEL=gpt-4o ./pii_enrichment_quality_test.sh   # use gpt-4o for all LLM calls
#   MODEL=gpt-4o NUM_PROMPTS=3 ./pii_enrichment_quality_test.sh  # both
#
# Prerequisites (same as smoke_test.sh):
#   - talon in PATH (or run from repo root after make build)
#   - TALON_SECRETS_KEY set (32-byte for AES-256-GCM vault)
#   - OPENAI_API_KEY set (or already in vault)
#   - jq in PATH
#   - yq in PATH (optional; falls back to sed for YAML patching)
#
# Output: side-by-side comparison table, per-prompt quality scores, per-criterion
# breakdown, and a summary verdict. Logs:
#   - pii_quality_consolidated_*.log — full trace, [ERROR]/[WARN], talon stderr, parse dumps
#   - pii_quality_failures_*.log       — errors only (duplicate detail for quick grep)
# Optional: SMOKE_LOG_TAIL_LINES=200 for longer assert tails in consolidated log.
# Optional: PII_QUALITY_LOG_RESPONSE_CHARS=N caps each variant response in the consolidated
#   log (default 0 = full text). Use if logs grow too large.

set -o pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly NUM_PROMPTS="${NUM_PROMPTS:-10}"
readonly MODEL="${MODEL:-gpt-4o-mini}"

# Source the shared smoke request layer (canonical paths, bodies, HTTP helpers)
# shellcheck source=./smoke_lib.sh
source "$SCRIPT_DIR/smoke_lib.sh"

# --- State (mirrors smoke_test.sh conventions) ---
PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()
TALON_DATA_DIR=""
SMOKE_LOG_FILE=""
SMOKE_COUNTS_FILE=""
SMOKE_FAILED_TESTS_FILE=""
SMOKE_CONSOLIDATED_LOG=""
CURRENT_SECTION=""
HAS_YQ=0

# Prompt array populated at runtime by generate_prompts()
PROMPTS=()

# --- Colours (skip if not a terminal) ---
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

# --- Helpers (same pattern as smoke_test.sh) --------------------------------

record_pass() {
  if [[ -n "${SMOKE_COUNTS_FILE:-}" ]]; then echo "P" >> "$SMOKE_COUNTS_FILE"; else ((PASS_COUNT++)) || true; fi
}
record_fail() {
  local d="${1:-}"
  if [[ -n "${SMOKE_COUNTS_FILE:-}" ]]; then
    echo "F" >> "$SMOKE_COUNTS_FILE"
    [[ -n "$d" ]] && echo "$d" >> "$SMOKE_FAILED_TESTS_FILE"
  else
    ((FAIL_COUNT++)) || true
    [[ -n "$d" ]] && FAILED_TESTS+=("$d")
  fi
}

# Lines of stdout/stderr to capture per assert (increased on failure paths)
SMOKE_LOG_TAIL_LINES="${SMOKE_LOG_TAIL_LINES:-120}"

write_cmd_log() {
  local description="$1" cmd="$2" code="$3" tmp_out="$4" tmp_err="$5"
  [[ -z "${SMOKE_CONSOLIDATED_LOG:-}" ]] && return 0
  local n="$SMOKE_LOG_TAIL_LINES"
  [[ "$code" -ne 0 ]] && n=$((SMOKE_LOG_TAIL_LINES * 2))
  {
    echo "[SMOKE] SECTION|$CURRENT_SECTION"
    echo "[SMOKE] ASSERT_DESC|$description"
    echo "[SMOKE] CMD|$cmd"
    echo "[SMOKE] EXIT|$code"
    echo "[SMOKE] STDOUT_TAIL<<"
    [[ -f "$tmp_out" ]] && tail -"$n" "$tmp_out"
    echo "[SMOKE] STDOUT_TAIL>>"
    echo "[SMOKE] STDERR_TAIL<<"
    [[ -f "$tmp_err" ]] && tail -"$n" "$tmp_err"
    echo "[SMOKE] STDERR_TAIL>>"
    echo ""
  } >> "$SMOKE_CONSOLIDATED_LOG"
}

log_timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Verbose error: consolidated log + dedicated failure log (for grep / sharing).
log_error() {
  local summary="$1"
  local detail="${2:-}"
  local ts
  ts="$(log_timestamp)"
  echo "  ✗  $summary" >&2
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
    {
      echo ""
      echo "[ERROR] $ts section=${CURRENT_SECTION:-?} $summary"
      if [[ -n "$detail" ]]; then
        echo "[ERROR] detail<<"
        echo "$detail"
        echo "[ERROR] detail>>"
      fi
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
  if [[ -n "${SMOKE_LOG_FILE:-}" ]]; then
    {
      echo "=== ERROR $ts section=${CURRENT_SECTION:-?} ==="
      echo "$summary"
      [[ -n "$detail" ]] && echo "--- detail ---" && echo "$detail"
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
}

log_warn() {
  local summary="$1"
  local detail="${2:-}"
  local ts
  ts="$(log_timestamp)"
  echo "  ⚠  $summary" >&2
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
    {
      echo ""
      echo "[WARN] $ts section=${CURRENT_SECTION:-?} $summary"
      if [[ -n "$detail" ]]; then
        echo "[WARN] detail<<"
        echo "$detail"
        echo "[WARN] detail>>"
      fi
      echo ""
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
}

log_verbose_block() {
  local tag="$1"
  local body="$2"
  local max="${3:-20000}"
  [[ -z "${SMOKE_CONSOLIDATED_LOG:-}" ]] || [[ -z "$body" ]] && return 0
  {
    echo ""
    echo "[VERBOSE] $tag<<"
    echo "${body:0:$max}"
    [[ "${#body}" -gt "$max" ]] && echo "... (truncated at ${max} chars, total ${#body})"
    echo "[VERBOSE] $tag>>"
  } >> "$SMOKE_CONSOLIDATED_LOG"
}

assert_pass() {
  local description="$1"; shift
  local tmp_out tmp_err code=0
  tmp_out="$(mktemp)" tmp_err="$(mktemp)"
  "$@" >"$tmp_out" 2>"$tmp_err" || code=$?
  if [[ "$code" -eq 0 ]]; then
    echo "  ✓  $description"
    write_cmd_log "$description" "$*" 0 "$tmp_out" "$tmp_err"
    record_pass
    rm -f "$tmp_out" "$tmp_err"
    return 0
  fi
  echo "  ✗  $description (exit $code) [$*]"
  write_cmd_log "$description" "$*" "$code" "$tmp_out" "$tmp_err"
  record_fail "$description"
  if [[ -n "$SMOKE_LOG_FILE" ]]; then
    {
      echo "--- FAIL: $description ---"
      echo "Section: $CURRENT_SECTION"
      echo "Command: $*"
      echo "Exit code: $code"
      echo "Stdout (last 200 lines):"; tail -200 "$tmp_out"
      echo "Stderr (last 200 lines):"; tail -200 "$tmp_err"
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
  if [[ -s "$tmp_err" ]]; then
    echo "    Last stderr:"
    tail -12 "$tmp_err" | sed 's/^/    | /'
  fi
  rm -f "$tmp_out" "$tmp_err"
  return 1
}

log_to_file() {
  local msg="$1"
  echo -e "$msg"
  [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]] && echo -e "$msg" >> "$SMOKE_CONSOLIDATED_LOG"
}

log_plain_to_file() {
  local msg="$1"
  echo "$msg"
  [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]] && echo "$msg" >> "$SMOKE_CONSOLIDATED_LOG"
}

# Emit response text for consolidated log; respects PII_QUALITY_LOG_RESPONSE_CHARS (0 = unlimited).
pii_emit_body_for_log() {
  local body="$1"
  local max="${PII_QUALITY_LOG_RESPONSE_CHARS:-0}"
  [[ "$max" =~ ^[0-9]+$ ]] || max=0
  if [[ "$max" -eq 0 ]] || [[ ${#body} -le "$max" ]]; then
    printf '%s\n' "$body"
    return
  fi
  printf '%s\n' "${body:0:$max}"
  printf '(truncated: %s chars shown of %s total; PII_QUALITY_LOG_RESPONSE_CHARS=0 for full)\n' "$max" "${#body}"
}

run_talon() {
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon "$@"
}

# Run talon with state under data_dir. For `run`, pass --policy so the agent file is found
# regardless of shell cwd (talon otherwise resolves DefaultPolicy relative to PWD, not TALON_DATA_DIR).
run_talon_in() {
  local data_dir="$1"; shift
  local policy="$data_dir/agent.talon.yaml"
  if [[ "${1:-}" == "run" ]]; then
    shift
    if [[ ! -f "$policy" ]]; then
      echo "run_talon_in: expected policy at $policy (missing — did talon init run in this dir?)" >&2
    fi
    env TALON_DATA_DIR="$data_dir" talon run --policy "$policy" "$@"
  else
    env TALON_DATA_DIR="$data_dir" talon "$@"
  fi
}

setup_section_dir() {
  local name="$1"
  mkdir -p "$TALON_DATA_DIR/sections/$name"
  echo "$TALON_DATA_DIR/sections/$name"
}

# Generator must not scan/redact model output, or JSON with emails/IBANs breaks parsing.
# Without yq this was never applied (only yq branch ran) — fixed here for sed users.
disable_pii_scan_generator_yaml() {
  local yaml_file="$1"
  [[ -f "$yaml_file" ]] || return 1
  if [[ "$HAS_YQ" -eq 1 ]]; then
    yq -i '.policies.data_classification.input_scan = false | .policies.data_classification.output_scan = false | .policies.data_classification.redact_pii = false' \
      "$yaml_file" 2>/dev/null || true
  else
    if grep -q 'data_classification:' "$yaml_file" 2>/dev/null; then
      sed -i.bak 's/input_scan: *true/input_scan: false/; s/output_scan: *true/output_scan: false/; s/redact_pii: *true/redact_pii: false/' \
        "$yaml_file" 2>/dev/null || true
    else
      echo -e "\npolicies:\n  data_classification: { input_scan: false, output_scan: false, redact_pii: false }" >> "$yaml_file"
    fi
  fi
}

# Extract first JSON array of strings from LLM text (markdown fences, multiline).
# grep -o '\[.*\]' fails on GNU grep when JSON spans lines; use python3 when available.
extract_prompt_json_array() {
  local raw="$1"
  local out=""
  if command -v python3 &>/dev/null; then
    out="$(printf '%s' "$raw" | python3 -c '
import sys, json, re
text = sys.stdin.read()
text = re.sub(r"(?s)\A\s*```(?:json)?\s*", "", text)
text = re.sub(r"(?s)\s*```\s*\Z", "", text)
dec = json.JSONDecoder()
for i, c in enumerate(text):
    if c != "[":
        continue
    try:
        obj, _end = dec.raw_decode(text[i:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, list) and obj and all(isinstance(x, str) for x in obj):
        print(json.dumps(obj, ensure_ascii=False))
        sys.exit(0)
sys.exit(1)
')" || true
    if [[ -n "$out" ]] && echo "$out" | jq -e 'type == "array" and length > 0' &>/dev/null; then
      printf '%s\n' "$out"
      return 0
    fi
  fi
  # Fallback: collapse newlines (best-effort for single-line JSON from model)
  local collapsed
  collapsed="$(printf '%s' "$raw" | tr '\n' ' ')"
  out="$(echo "$collapsed" | grep -o '\[.*\]' | head -1)" || true
  if [[ -n "$out" ]] && echo "$out" | jq -e 'type == "array" and length > 0' &>/dev/null; then
    printf '%s\n' "$out"
    return 0
  fi
  return 1
}

# First JSON object in text (multiline). grep -o '{.*}' cannot cross newlines.
extract_first_json_object() {
  local raw="$1"
  local out=""
  if command -v python3 &>/dev/null; then
    out="$(printf '%s' "$raw" | python3 -c '
import sys, json
text = sys.stdin.read()
dec = json.JSONDecoder()
for i, c in enumerate(text):
    if c != "{":
        continue
    try:
        obj, _end = dec.raw_decode(text[i:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and (
        "verdict" in obj or "r1_utility" in obj
    ):
        print(json.dumps(obj, ensure_ascii=False))
        sys.exit(0)
sys.exit(1)
')" || true
    if [[ -n "$out" ]] && echo "$out" | jq -e . &>/dev/null; then
      printf '%s\n' "$out"
      return 0
    fi
  fi
  local collapsed
  collapsed="$(printf '%s' "$raw" | tr '\n' ' ')"
  out="$(echo "$collapsed" | grep -oE '\{.*\}' | head -1)" || true
  if [[ -n "$out" ]] && echo "$out" | jq -e . &>/dev/null; then
    printf '%s\n' "$out"
    return 0
  fi
  return 1
}

log_parse_failure() {
  local title="$1" raw="$2"
  local max="${3:-16000}"
  local ts
  ts="$(log_timestamp)"
  local snippet="${raw:0:$max}"
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
    {
      echo ""
      echo "=== PARSE_FAIL $ts $title ==="
      echo "$snippet"
      [[ "${#raw}" -gt "$max" ]] && echo "... truncated raw output (${#raw} chars) at ${max} chars"
      echo "=== end parse_fail ==="
      echo ""
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
  if [[ -n "${SMOKE_LOG_FILE:-}" ]]; then
    {
      echo "=== PARSE_FAIL $ts $title ==="
      echo "$snippet"
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
}

# --- Prerequisites (same pattern as smoke_test.sh) --------------------------
check_prereqs() {
  echo "Checking prerequisites..."
  local missing=()
  command -v talon &>/dev/null || missing+=("talon in PATH")
  [[ -n "${TALON_SECRETS_KEY:-}" ]] || missing+=("TALON_SECRETS_KEY")
  command -v jq &>/dev/null || missing+=("jq")
  [[ -n "${OPENAI_API_KEY:-}" ]] || missing+=("OPENAI_API_KEY")
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing: ${missing[*]}"
    exit 2
  fi
  command -v yq &>/dev/null && HAS_YQ=1 || echo "  Note: yq not found; falling back to sed for YAML patching."
  command -v python3 &>/dev/null || echo "  Note: python3 not found; JSON prompt extraction may fail on multiline LLM output (install python3)."
  command -v sqlite3 &>/dev/null || echo "  Note: sqlite3 not found; cannot hard-verify actual LLM input from step_evidence."

  TALON_DATA_DIR="$(mktemp -d)"
  SMOKE_CREATED_DATA_DIR=1
  export TALON_DATA_DIR
  export TALON_SIGNING_KEY="${TALON_SIGNING_KEY:-$(openssl rand -hex 32 2>/dev/null || echo "pii-quality-signing-key-pad32")}"
  echo "  All prerequisites met."
  echo "  TALON_DATA_DIR=$TALON_DATA_DIR"
}

# --- YAML patching (yq with sed fallback, matching smoke_test.sh) -----------
# Input redaction ON, output redaction OFF: the LLM sees redacted prompts but
# we get raw responses back. This is the core of the A/B comparison.
patch_yaml() {
  local yaml_file="$1" enrichment_enabled="$2" enrichment_mode="$3"
  if [[ "$HAS_YQ" -eq 1 ]]; then
    yq -i '
      .policies.data_classification.input_scan = true |
      .policies.data_classification.output_scan = true |
      .policies.data_classification.redact_pii = false |
      .policies.data_classification.redact_input = true |
      .policies.data_classification.redact_output = false |
      .audit.include_prompts = true |
      .policies.semantic_enrichment.enabled = '"$enrichment_enabled"' |
      .policies.semantic_enrichment.mode = "'"$enrichment_mode"'" |
      .policies.semantic_enrichment.allowed_attributes = ["gender", "scope", "country_code", "domain_type"]
    ' "$yaml_file" 2>/dev/null || true
  else
    # Enable scanning, keep redact_pii false, set granular fields explicitly.
    sed -i.bak \
      -e 's/input_scan: *false/input_scan: true/' \
      -e 's/output_scan: *false/output_scan: true/' \
      -e 's/include_prompts: *false/include_prompts: true/' \
      "$yaml_file" 2>/dev/null || true
    # Remove commented redact_input/redact_output lines so we can insert active ones
    sed -i.bak '/^[[:space:]]*#.*redact_input:/d; /^[[:space:]]*#.*redact_output:/d' "$yaml_file" 2>/dev/null || true
    # Now insert active redact_input/redact_output after redact_pii
    if ! grep -q '^[[:space:]]*redact_input:' "$yaml_file" 2>/dev/null; then
      sed -i.bak '/redact_pii:/a\    redact_input: true\n    redact_output: false' "$yaml_file" 2>/dev/null || true
    fi
    # If data_classification section is entirely missing (custom yaml), append it.
    if ! grep -q 'data_classification:' "$yaml_file" 2>/dev/null; then
      echo -e "\n  data_classification:\n    input_scan: true\n    output_scan: true\n    redact_pii: false\n    redact_input: true\n    redact_output: false" >> "$yaml_file"
    fi
    # Semantic enrichment — insert before model_routing (sibling of data_classification under policies:)
    if [[ "$enrichment_enabled" == "true" ]]; then
      if ! grep -q 'semantic_enrichment:' "$yaml_file"; then
        sed -i.bak '/^  model_routing:/i\  semantic_enrichment:\n    enabled: true\n    mode: '"${enrichment_mode}"'\n    allowed_attributes: [gender, scope, country_code, domain_type]' "$yaml_file" 2>/dev/null || true
      fi
    else
      if grep -q 'semantic_enrichment:' "$yaml_file"; then
        sed -i.bak 's/semantic_enrichment:.*/semantic_enrichment: { enabled: false }/' "$yaml_file" 2>/dev/null || true
      fi
    fi
  fi
}

# --- Patch all model routing tiers to use $MODEL. ---------------------------
# Tier 2 defaults to Bedrock-only Claude; CI and many dev machines have no Bedrock.
# We also unify all tiers so the test uses a single, consistent model throughout.
patch_yaml_model() {
  local yaml_file="$1"
  [[ -f "$yaml_file" ]] || return 0
  if [[ "$HAS_YQ" -eq 1 ]]; then
    yq -i '
      .policies.model_routing.tier_0.primary = "'"$MODEL"'" |
      .policies.model_routing.tier_1.primary = "'"$MODEL"'" |
      .policies.model_routing.tier_1.fallback = "'"$MODEL"'" |
      .policies.model_routing.tier_2.primary = "'"$MODEL"'" |
      .policies.model_routing.tier_2.fallback = "'"$MODEL"'" |
      .policies.model_routing.tier_2.bedrock_only = false
    ' "$yaml_file" 2>/dev/null || true
  else
    sed -i.bak \
      -e "s/primary: gpt-[^[:space:]]*/primary: ${MODEL}/" \
      -e "s/primary: claude[^[:space:]]*/primary: ${MODEL}/" \
      -e "s/fallback: gpt-[^[:space:]]*/fallback: ${MODEL}/" \
      -e "s/fallback: claude[^[:space:]]*/fallback: ${MODEL}/" \
      -e 's/bedrock_only: true/bedrock_only: false/' \
      "$yaml_file" 2>/dev/null || true
  fi
}

# Scale the Talon rate limiter to handle NUM_PROMPTS without self-throttling.
# The default scaffold sets requests_per_minute=30 which is far too low for
# 100-prompt runs (Phase 1 sends 2*N requests, Phase 3 sends N more).
patch_yaml_rate_limit() {
  local yaml_file="$1"
  local rpm="${2:-500}"
  [[ -f "$yaml_file" ]] || return 0
  if [[ "$HAS_YQ" -eq 1 ]]; then
    yq -i '.policies.rate_limits.requests_per_minute = '"$rpm"'' "$yaml_file" 2>/dev/null || true
  else
    sed -i.bak "s/requests_per_minute: *[0-9]*/requests_per_minute: ${rpm}/" "$yaml_file" 2>/dev/null || true
  fi
}

# --- Setup an isolated Talon environment for a variant ----------------------
setup_variant() {
  local label="$1" enrichment_enabled="$2" enrichment_mode="$3"
  local dir agent_slug
  dir="$(setup_section_dir "pii_quality_${label}")"
  agent_slug="$(echo "${label}" | tr '[:upper:]' '[:lower:]')"
  (
    cd "$dir" || exit 1
    # agent.name must match ^[a-z0-9_-]+$ (no uppercase)
    TALON_DATA_DIR="$dir" talon init --scaffold --name "pii-quality-${agent_slug}" &>/dev/null || true
    [[ -n "${OPENAI_API_KEY:-}" ]] && TALON_DATA_DIR="$dir" talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null || true
    patch_yaml "$dir/agent.talon.yaml" "$enrichment_enabled" "$enrichment_mode"
    patch_yaml_model "$dir/agent.talon.yaml"
    patch_yaml_rate_limit "$dir/agent.talon.yaml"
  )
  echo "$dir"
}

# --- Single-batch prompt generation helpers ----------------------------------
generate_prompt_batch() {
  local gen_dir="$1" batch_size="$2"
  local gen_instruction
  read -r -d '' gen_instruction <<'GEN_EOF' || true
Generate exactly NUM_PLACEHOLDER prompts as a JSON array of strings.

CRITICAL: All personal data will be replaced with anonymous placeholders before the AI
sees the prompt. Each prompt MUST ask a question whose answer DEPENDS on semantic
attributes of the PII entities. The enriched placeholders preserve these attributes;
basic placeholders lose them. Design prompts so the answer quality degrades noticeably
when the attributes are stripped.

ENRICHABLE ATTRIBUTES (design prompts that exploit these):
1. PERSON gender (male/female) — from titles Mr./Mrs./Herr/Frau etc.
2. LOCATION scope (city/region/country) — Munich=city, Bavaria=region, Germany=country
3. IBAN country_code — first 2 letters reveal the country (DE=Germany, FR=France, PL=Poland)
4. PHONE country_code — dialing prefix reveals the country (+49=Germany, +33=France)
5. EMAIL domain_type — gmail.com=free/personal, acme-corp.eu=corporate

Good examples (mix these categories across prompts):
- "Mr. Schmidt and Mrs. Mueller are comparing average heights. Statistically, who is taller?"
  (needs gender — basic placeholder loses it)
- "An employee IBAN is DE89370400440532013000. Should payroll use SEPA or SWIFT?"
  (needs IBAN country — basic placeholder [IBAN] loses the DE prefix)
- "Contact reached us from +48 22 123 45 67. Route to the correct EU support desk."
  (needs phone country_code — basic placeholder [PHONE] loses +48=Poland)
- "A lead emailed from j.kowalski@gmail.com. Should we route to B2B or B2C sales?"
  (needs email domain_type — basic placeholder [EMAIL] loses free vs corporate)
- "Should the Munich office follow city-level or federal-level waste regulations?"
  (needs location scope — basic placeholder [LOCATION] loses city vs country)

IMPORTANT RULES for realistic PII values:
- IBANs MUST be real, valid IBANs that pass MOD-97 checksum (use well-known test IBANs):
  DE89370400440532013000, FR7630006000011234567890189, GB29NWBK60161331926819,
  ES9121000418450200051332, IT60X0542811101000000123456, NL91ABNA0417164300,
  PL61109010140000071219812874, AT611904300234573201, BE68539007547034
- Phone numbers MUST use E.164 format with spaces: "+49 30 1234567", "+33 1 40 20 30 40"
- Emails MUST use real domains (gmail.com, yahoo.com for free; company-name.eu for corporate)

Requirements for EVERY prompt:
- Contains at least one EU person name WITH gendered title (Mr., Mrs., Frau, Herr)
- Contains at least one of: valid IBAN, phone with +country prefix, email, or EU city/region
- The question MUST REQUIRE knowing the semantic attribute to answer correctly
- If all attributes are stripped, the AI should struggle or refuse to answer
- Mix categories: ~40% gender, ~20% IBAN/phone country, ~20% email type, ~20% location scope
- Do NOT use possessive apostrophes (no "Weber's", use "of Weber" instead)
- Keep prompts to 1-3 sentences, focused on the reasoning question

Reply ONLY with a valid JSON array. No markdown fences, no explanation.
GEN_EOF
  gen_instruction="${gen_instruction//NUM_PLACEHOLDER/$batch_size}"

  local raw_output
  raw_output="$(run_talon_in "$gen_dir" run "$gen_instruction" 2>&1)" || true
  local json_array
  json_array="$(extract_prompt_json_array "$raw_output")" || true
  if [[ -z "$json_array" ]] || ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
    log_parse_failure "Phase 0 batch (parse failed)" "$raw_output"
    return 1
  fi
  printf '%s\n' "$json_array"
}

generate_prompt_batch_simple() {
  local gen_dir="$1" batch_size="$2"
  local raw_output
  raw_output="$(run_talon_in "$gen_dir" run \
    "Generate ${batch_size} one-sentence prompts as a JSON array. Each must contain a European person name with Mr/Mrs title AND one of: a valid IBAN (use DE89370400440532013000 or FR7630006000011234567890189), a phone like +49 30 1234567, or an email. The prompt must ask a question requiring gender, country code, or email type to answer. Reply ONLY with a JSON array of strings." \
    2>&1)" || true
  local json_array
  json_array="$(extract_prompt_json_array "$raw_output")" || true
  if [[ -z "$json_array" ]] || ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
    log_parse_failure "Phase 0 batch simple retry (parse failed)" "$raw_output"
    return 1
  fi
  printf '%s\n' "$json_array"
}

# --- Generate prompt corpus via LLM (batched for large counts) --------------
# The runner's max_tokens is 2000 which fits ~15-20 prompts as JSON.  For
# larger counts we generate in batches of BATCH_SIZE and merge the results.
readonly PROMPT_BATCH_SIZE="${PROMPT_BATCH_SIZE:-15}"

generate_prompts() {
  local count="$1"
  CURRENT_SECTION="00_generate_prompts"

  log_to_file "${CYAN}Phase 0: Generating ${count} test prompts via LLM...${RESET}"

  local gen_dir
  gen_dir="$(setup_section_dir "pii_quality_gen")"
  (
    cd "$gen_dir" || exit 1
    TALON_DATA_DIR="$gen_dir" talon init --scaffold --name "prompt-gen" &>/dev/null || true
    [[ -n "${OPENAI_API_KEY:-}" ]] && TALON_DATA_DIR="$gen_dir" talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null || true
    disable_pii_scan_generator_yaml "$gen_dir/agent.talon.yaml"
    patch_yaml_model "$gen_dir/agent.talon.yaml"
    patch_yaml_rate_limit "$gen_dir/agent.talon.yaml"
  )

  local remaining="$count" batch_num=0 total_failures=0
  while [[ "$remaining" -gt 0 ]]; do
    local batch_size="$remaining"
    [[ "$batch_size" -gt "$PROMPT_BATCH_SIZE" ]] && batch_size="$PROMPT_BATCH_SIZE"
    ((batch_num++)) || true
    local so_far="${#PROMPTS[@]}"
    echo "  Batch ${batch_num}: requesting ${batch_size} prompts (${so_far}/${count} so far)..."

    local json_array
    json_array="$(generate_prompt_batch "$gen_dir" "$batch_size")" || true

    if [[ -z "$json_array" ]] || ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
      ((total_failures++)) || true
      echo "  ⚠  Batch ${batch_num} failed; retrying once..."
      json_array="$(generate_prompt_batch_simple "$gen_dir" "$batch_size")" || true
      if [[ -z "$json_array" ]] || ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
        ((total_failures++)) || true
        echo "  ✗  Batch ${batch_num} failed after retry. Continuing with remaining batches."
        log_parse_failure "Phase 0 batch ${batch_num} retry (parse failed)" "${json_array:-empty}"
        remaining=$((remaining - batch_size))
        continue
      fi
    fi

    local generated_count i
    generated_count="$(echo "$json_array" | jq 'length')"
    for (( i=0; i<generated_count; i++ )); do
      local p
      p="$(echo "$json_array" | jq -r ".[$i]")"
      [[ -n "$p" ]] && [[ "$p" != "null" ]] && PROMPTS+=("$p")
    done
    echo "  ✓  Batch ${batch_num}: got ${generated_count} prompts (${#PROMPTS[@]}/${count} total)"
    remaining=$((remaining - batch_size))
  done

  if [[ "${#PROMPTS[@]}" -eq 0 ]]; then
    echo "  ✗  Prompt generation failed: no valid prompts after ${batch_num} batches."
    log_error "Prompt generation failed: zero prompts after all batches" \
      "Batches attempted: ${batch_num}, failures: ${total_failures}. See PARSE_FAIL blocks above."
    record_fail "prompt generation"
    exit 3
  fi

  echo "  ✓  Generated ${#PROMPTS[@]} prompts (requested ${count}, ${total_failures} batch failures)"
  record_pass
  for (( i=0; i<${#PROMPTS[@]}; i++ )); do
    echo ""
    echo "    [$((i+1))] ${PROMPTS[$i]}"
  done
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]] && [[ ${#PROMPTS[@]} -gt 0 ]]; then
    {
      echo ""
      echo "=== Phase 0 — generated prompts (full text, ${#PROMPTS[@]} items) ==="
      for (( i=0; i<${#PROMPTS[@]}; i++ )); do
        echo ""
        echo "    [$((i+1))] ${PROMPTS[$i]}"
      done
      echo ""
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi
  echo ""
}

# --- Simulate redacted prompts for console display -------------------------
# Talon redacts input internally; we approximate for display purposes only.
# Variant A (basic): "Mr. Kowalski" → [PERSON], "DE89..." → [IBAN]
# Variant B (enriched): preserves gender, country_code, domain_type, scope
simulate_basic_redaction() {
  local text="$1"
  text="$(echo "$text" | sed -E 's/(Mr\.|Mrs\.|Ms\.|Frau|Herr|Dr\.)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/[PERSON]/g')"
  text="$(echo "$text" | sed -E 's/\b(Munich|Berlin|Hamburg|Frankfurt|Stuttgart|Paris|Lyon|Marseille|Warsaw|Krakow|Kraków|Rome|Milan|Madrid|Barcelona|Amsterdam|Rotterdam|Bucharest|Stockholm|Vienna|Prague|Budapest|Brussels|Lisbon|Dublin|Copenhagen|Helsinki|Oslo|Zurich|Geneva|Luxembourg)\b/[LOCATION]/g')"
  text="$(echo "$text" | sed -E 's/\b(Bavaria|Catalonia|Lombardy|Tuscany|Saxony|Andalusia|Flanders|Wallonia|Transylvania)[[:>:]]*/[LOCATION]/g' 2>/dev/null || echo "$text" | sed -E 's/(Bavaria|Catalonia|Lombardy|Tuscany|Saxony|Andalusia|Flanders|Wallonia|Transylvania)/[LOCATION]/g')"
  text="$(echo "$text" | sed -E 's/[A-Z]{2}[0-9]{2}[[:space:]]*[A-Z0-9]{4}[[:space:]]*[0-9]{4}[[:space:]]*[0-9A-Z[:space:]]{4,30}/[IBAN]/g')"
  text="$(echo "$text" | sed -E 's/\+[0-9]{1,3}[[:space:]-]*[0-9][0-9[:space:]-]{6,15}/[PHONE]/g')"
  text="$(echo "$text" | sed -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[EMAIL]/g')"
  printf '%s' "$text"
}

simulate_enriched_redaction() {
  local text="$1"
  local pid=0 lid=0 iid=0 phid=0 eid=0
  # Person: Mr./Herr → male
  while echo "$text" | grep -qE '(Mr\.|Herr)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+'; do
    ((pid++)) || true
    text="$(echo "$text" | sed -E "s/(Mr\.|Herr)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/<PII type=\"person\" gender=\"male\" id=\"${pid}\"\/>/1")"
  done
  # Person: Mrs./Ms./Frau → female
  while echo "$text" | grep -qE '(Mrs\.|Ms\.|Frau)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+'; do
    ((pid++)) || true
    text="$(echo "$text" | sed -E "s/(Mrs\.|Ms\.|Frau)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/<PII type=\"person\" gender=\"female\" id=\"${pid}\"\/>/1")"
  done
  # Person: Dr. → unknown gender
  while echo "$text" | grep -qE 'Dr\.\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+'; do
    ((pid++)) || true
    text="$(echo "$text" | sed -E "s/Dr\.\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/<PII type=\"person\" id=\"${pid}\"\/>/1")"
  done
  # Location: cities → scope="city"
  for city in Munich Berlin Hamburg Frankfurt Stuttgart Paris Lyon Marseille Warsaw Krakow Kraków Rome Milan Madrid Barcelona Amsterdam Rotterdam Bucharest Stockholm Vienna Prague Budapest Brussels Lisbon Dublin Copenhagen Helsinki Oslo Zurich Geneva Luxembourg; do
    if echo "$text" | grep -q "${city}" 2>/dev/null; then
      ((lid++)) || true
      text="$(echo "$text" | sed "s/${city}/<PII type=\"location\" scope=\"city\" id=\"loc_${lid}\"\/>/1")"
    fi
  done
  # Location: regions → scope="region"
  for region in Bavaria Catalonia Lombardy Tuscany Saxony Andalusia Flanders Wallonia Transylvania; do
    if echo "$text" | grep -q "${region}" 2>/dev/null; then
      ((lid++)) || true
      text="$(echo "$text" | sed "s/${region}/<PII type=\"location\" scope=\"region\" id=\"loc_${lid}\"\/>/1")"
    fi
  done
  # IBAN: extract country_code from first 2 chars
  while echo "$text" | grep -qE '[A-Z]{2}[0-9]{2}[[:space:]]*[A-Z0-9]{4}'; do
    ((iid++)) || true
    local iban_cc
    iban_cc="$(echo "$text" | grep -oE '[A-Z]{2}[0-9]{2}[[:space:]]*[A-Z0-9]{4}' | head -1 | cut -c1-2)"
    text="$(echo "$text" | sed -E "s/[A-Z]{2}[0-9]{2}[[:space:]]*[A-Z0-9]{4}[[:space:]]*[0-9A-Z[:space:]]{4,30}/<PII type=\"iban\" country_code=\"${iban_cc}\" id=\"iban_${iid}\"\/>/1")"
  done
  # Phone: extract country_code from prefix
  while echo "$text" | grep -qE '\+[0-9]{1,3}[[:space:]-]*[0-9]'; do
    ((phid++)) || true
    local phone_prefix phone_cc="??"
    phone_prefix="$(echo "$text" | grep -oE '\+[0-9]{1,3}' | head -1)"
    case "$phone_prefix" in
      +49) phone_cc="DE";; +33) phone_cc="FR";; +34) phone_cc="ES";; +39) phone_cc="IT";;
      +31) phone_cc="NL";; +32) phone_cc="BE";; +43) phone_cc="AT";; +48) phone_cc="PL";;
      +44) phone_cc="GB";; +41) phone_cc="CH";; +351) phone_cc="PT";; +353) phone_cc="IE";;
      +46) phone_cc="SE";; +45) phone_cc="DK";; +358) phone_cc="FI";; +47) phone_cc="NO";;
      +420) phone_cc="CZ";; +40) phone_cc="RO";; +36) phone_cc="HU";; +352) phone_cc="LU";;
    esac
    text="$(echo "$text" | sed -E "s/\+[0-9]{1,3}[[:space:]-]*[0-9][0-9[:space:]-]{6,15}/<PII type=\"phone\" country_code=\"${phone_cc}\" id=\"ph_${phid}\"\/>/1")"
  done
  # Email: classify domain_type
  while echo "$text" | grep -qE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'; do
    ((eid++)) || true
    local email_domain email_dtype="corporate"
    email_domain="$(echo "$text" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1 | sed 's/.*@//')"
    case "$email_domain" in
      gmail.com|googlemail.com|yahoo.*|outlook.com|hotmail.*|live.com|aol.com|mail.com|gmx.*|web.de|protonmail.com|proton.me|icloud.com|t-online.de)
        email_dtype="free";;
    esac
    text="$(echo "$text" | sed -E "s/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/<PII type=\"email\" domain_type=\"${email_dtype}\" id=\"em_${eid}\"\/>/1")"
  done
  printf '%s' "$text"
}

# --- Run a single prompt through a variant and capture the response ---------
run_prompt() {
  local data_dir="$1" prompt="$2"
  local variant="${3:-variant}"
  local outf errf code=0
  outf="$(mktemp)" errf="$(mktemp)"
  run_talon_in "$data_dir" run "$prompt" >"$outf" 2>"$errf" || code=$?
  local body errtxt
  body="$(cat "$outf" 2>/dev/null || true)"
  errtxt="$(cat "$errf" 2>/dev/null || true)"
  rm -f "$outf" "$errf"

  if [[ "$code" -ne 0 ]] || [[ -z "$body" ]] || [[ "$body" == "null" ]]; then
    log_error "talon run failed or empty response (variant ${variant}, exit ${code})" \
      "data_dir=${data_dir}
prompt_preview=${prompt:0:500}
--- stderr ---
${errtxt:0:12000}
--- stdout (first 8000 chars) ---
${body:0:8000}"
  fi
  printf '%s' "$body"
}

# Extract evidence id from talon output line: "Evidence stored: req_xxxxxxxx"
extract_evidence_id() {
  local output="$1"
  echo "$output" | sed -n 's/.*Evidence stored:[[:space:]]*\(req_[a-z0-9]\+\).*/\1/p' | head -1
}

# Read first llm_call input_summary from step_evidence for this evidence id.
# This is the exact prompt payload captured at LLM call time (post-redaction).
fetch_llm_input_summary() {
  local data_dir="$1" evidence_id="$2"
  local db_path="$data_dir/evidence.db"
  [[ -n "$evidence_id" ]] || return 0
  [[ -f "$db_path" ]] || return 0
  if ! command -v sqlite3 &>/dev/null; then
    return 0
  fi
  sqlite3 "$db_path" "
SELECT COALESCE(json_extract(se.step_json, '\$.input_summary'), '')
FROM step_evidence se
WHERE se.step_type = 'llm_call'
  AND se.correlation_id = (
    SELECT correlation_id FROM evidence WHERE id = '$evidence_id' LIMIT 1
  )
ORDER BY se.step_index ASC
LIMIT 1;
" 2>/dev/null || true
}

# --- LLM-as-Judge (MT-Bench pairwise style with position-bias mitigation) ---
#
# Evaluation criteria (designed for input-redaction A/B testing):
#   1. ATTRIBUTE_REASONING: Can the AI use PII attributes (gender, country_code, etc.)?
#   2. UTILITY_PRESERVATION (tau-eval): task completion despite redaction
#   3. SEMANTIC_COHERENCE (RedacBench): logical consistency despite placeholders
#   4. HELPFULNESS (MT-Bench): actionable, complete, useful response
#
# Position-bias mitigation: response order randomised per prompt.
judge_response() {
  local judge_dir="$1" original_prompt="$2" response_a="$3" response_b="$4"
  local prompt_idx="${5:-?}"

  local first_resp second_resp swap=0
  if (( RANDOM % 2 )); then
    swap=1
    first_resp="$response_b"; second_resp="$response_a"
  else
    first_resp="$response_a"; second_resp="$response_b"
  fi

  local judge_prompt
  read -r -d '' judge_prompt <<'JUDGE_EOF' || true
You are an expert evaluator for AI-generated responses. Two AI systems received the SAME
original prompt but with DIFFERENT input redaction formats:
- System A received basic placeholders: [PERSON], [LOCATION], [IBAN], [PHONE], [EMAIL]
  (no semantic attributes — gender, country, domain type are all stripped)
- System B received enriched placeholders with semantic attributes preserved:
  <PII type="person" gender="male" id="1"/>, <PII type="location" scope="city" id="loc_1"/>,
  <PII type="iban" country_code="DE" id="iban_1"/>, <PII type="phone" country_code="PL" id="ph_1"/>,
  <PII type="email" domain_type="free" id="em_1"/>

The original prompt was designed so that KNOWING these attributes is ESSENTIAL to answer
correctly. For example: gender for salutation/statistics, IBAN country for SEPA vs SWIFT,
phone country for routing, email domain_type for B2B vs B2C classification.

Score each response on these four criteria (1-10 each):

1. ATTRIBUTE_REASONING: Did the response correctly use PII attributes (gender, country_code,
   scope, domain_type) to reason about the question? Did it identify and leverage these
   attributes in its answer?
   Score 1-3 if the response admits it cannot determine the attribute or guesses randomly.
   Score 4-6 if it partially reasons but hedges due to missing information.
   Score 7-10 if it confidently and correctly uses attributes in its reasoning.

2. UTILITY_PRESERVATION: Does the response accomplish the original task despite PII
   redaction? Would the requester be able to use this response?

3. SEMANTIC_COHERENCE: Is the response logically structured, internally consistent, and
   free of contradictions introduced by placeholder tokens?

4. HELPFULNESS: Is the response genuinely useful, actionable, and complete?

IMPORTANT: Reply ONLY with valid JSON, no markdown fences, no explanation. Use exactly:
{"r1_utility":N,"r1_context":N,"r1_coherence":N,"r1_helpful":N,"r2_utility":N,"r2_context":N,"r2_coherence":N,"r2_helpful":N,"verdict":"Response_1|Response_2|tie","reason":"one sentence explaining the key differentiator"}
JUDGE_EOF
  judge_prompt="${judge_prompt}

Original prompt (before any redaction):
${original_prompt}

--- Response 1 ---
${first_resp}

--- Response 2 ---
${second_resp}"

  local j_out j_err j_code=0
  j_out="$(mktemp)" j_err="$(mktemp)"
  run_talon_in "$judge_dir" run "$judge_prompt" >"$j_out" 2>"$j_err" || j_code=$?
  local judge_out j_errtxt
  judge_out="$(cat "$j_out" 2>/dev/null || true)"
  j_errtxt="$(cat "$j_err" 2>/dev/null || true)"
  rm -f "$j_out" "$j_err"

  if [[ "$j_code" -ne 0 ]]; then
    log_error "judge talon run non-zero exit (prompt_index=${prompt_idx})" \
      "exit=${j_code}
stderr<<
${j_errtxt:0:12000}
stdout<<
${judge_out:0:8000}"
  fi

  local json_part parse_failed=0
  json_part="$(extract_first_json_object "$judge_out")" || true

  if ! echo "$json_part" | jq -e '.verdict' &>/dev/null 2>&1; then
    parse_failed=1
    log_error "judge JSON parse failed (prompt_index=${prompt_idx}, using neutral tie scores)" \
      "grepped_json_candidate<<
${json_part:0:4000}
raw_judge_stdout<<
${judge_out:0:16000}
judge_stderr<<
${j_errtxt:0:8000}"
    json_part='{"r1_utility":5,"r1_context":5,"r1_coherence":5,"r1_helpful":5,"r2_utility":5,"r2_context":5,"r2_coherence":5,"r2_helpful":5,"verdict":"tie","reason":"judge parse error"}'
  fi

  # Un-swap scores back to A/B regardless of presentation order
  local a_u a_c a_s a_h b_u b_c b_s b_h verdict
  if [[ "$swap" -eq 1 ]]; then
    a_u="$(echo "$json_part" | jq '.r2_utility // 5')";   a_c="$(echo "$json_part" | jq '.r2_context // 5')"
    a_s="$(echo "$json_part" | jq '.r2_coherence // 5')";  a_h="$(echo "$json_part" | jq '.r2_helpful // 5')"
    b_u="$(echo "$json_part" | jq '.r1_utility // 5')";   b_c="$(echo "$json_part" | jq '.r1_context // 5')"
    b_s="$(echo "$json_part" | jq '.r1_coherence // 5')";  b_h="$(echo "$json_part" | jq '.r1_helpful // 5')"
    verdict="$(echo "$json_part" | jq -r '.verdict // "tie"')"
    case "$verdict" in Response_1) verdict="B_better";; Response_2) verdict="A_better";; *) verdict="tie";; esac
  else
    a_u="$(echo "$json_part" | jq '.r1_utility // 5')";   a_c="$(echo "$json_part" | jq '.r1_context // 5')"
    a_s="$(echo "$json_part" | jq '.r1_coherence // 5')";  a_h="$(echo "$json_part" | jq '.r1_helpful // 5')"
    b_u="$(echo "$json_part" | jq '.r2_utility // 5')";   b_c="$(echo "$json_part" | jq '.r2_context // 5')"
    b_s="$(echo "$json_part" | jq '.r2_coherence // 5')";  b_h="$(echo "$json_part" | jq '.r2_helpful // 5')"
    verdict="$(echo "$json_part" | jq -r '.verdict // "tie"')"
    case "$verdict" in Response_1) verdict="A_better";; Response_2) verdict="B_better";; *) verdict="tie";; esac
  fi
  local reason
  reason="$(echo "$json_part" | jq -r '.reason // "n/a"')"

  jq -n \
    --argjson au "$a_u" --argjson ac "$a_c" --argjson as "$a_s" --argjson ah "$a_h" \
    --argjson bu "$b_u" --argjson bc "$b_c" --argjson bs "$b_s" --argjson bh "$b_h" \
    --arg v "$verdict" --arg r "$reason" --argjson sw "$swap" \
    --argjson jf "$j_code" --argjson pf "$parse_failed" \
    '{a_utility:$au,a_context:$ac,a_coherence:$as,a_helpful:$ah,
      b_utility:$bu,b_context:$bc,b_coherence:$bs,b_helpful:$bh,
      verdict:$v,reason:$r,position_swapped:$sw,
      judge_talon_exit:$jf,judge_parse_failed:$pf}'
}

# --- Teardown ---------------------------------------------------------------
SMOKE_CREATED_DATA_DIR=0
teardown() {
  if [[ "${SMOKE_CREATED_DATA_DIR:-0}" -eq 1 ]] && [[ -n "$TALON_DATA_DIR" ]] && [[ -d "$TALON_DATA_DIR" ]]; then
    rm -rf "$TALON_DATA_DIR" 2>/dev/null || true
  fi
}
trap teardown EXIT

# =============================================================================
# Main
# =============================================================================
main() {
  check_prereqs

  SMOKE_LOG_FILE="${SCRIPT_DIR}/pii_quality_failures_$(date +%Y%m%d_%H%M%S).log"
  if ! touch "$SMOKE_LOG_FILE" 2>/dev/null; then
    SMOKE_LOG_FILE="$(pwd)/pii_quality_failures_$(date +%Y%m%d_%H%M%S).log"
    touch "$SMOKE_LOG_FILE" 2>/dev/null || SMOKE_LOG_FILE="/tmp/talon_pii_quality_failures_$$.log"
  fi
  SMOKE_CONSOLIDATED_LOG="${SCRIPT_DIR}/pii_quality_consolidated_$(date +%Y%m%d_%H%M%S).log"
  if ! touch "$SMOKE_CONSOLIDATED_LOG" 2>/dev/null; then
    SMOKE_CONSOLIDATED_LOG="$(pwd)/pii_quality_consolidated_$(date +%Y%m%d_%H%M%S).log"
    touch "$SMOKE_CONSOLIDATED_LOG" 2>/dev/null || SMOKE_CONSOLIDATED_LOG="/tmp/talon_pii_quality_consolidated_$$.log"
  fi
  SMOKE_COUNTS_FILE="$TALON_DATA_DIR/pii_quality_counts.txt"
  SMOKE_FAILED_TESTS_FILE="$TALON_DATA_DIR/pii_quality_failed.txt"
  : > "$SMOKE_LOG_FILE"
  : > "$SMOKE_CONSOLIDATED_LOG"
  : > "$SMOKE_COUNTS_FILE"
  : > "$SMOKE_FAILED_TESTS_FILE"

  {
    echo "=== PII enrichment quality test — run start $(log_timestamp) ==="
    echo "NUM_PROMPTS=$NUM_PROMPTS"
    echo "MODEL=$MODEL"
    echo "TALON_DATA_DIR=$TALON_DATA_DIR"
    echo "SCRIPT_DIR=$SCRIPT_DIR"
    echo "HAS_YQ=$HAS_YQ python3=$(command -v python3 2>/dev/null || echo missing) jq=$(command -v jq 2>/dev/null || echo missing)"
    echo "OPENAI_API_KEY=${OPENAI_API_KEY:+(set, ${#OPENAI_API_KEY} chars)}"
    echo "TALON_SECRETS_KEY=${TALON_SECRETS_KEY:+(set, ${#TALON_SECRETS_KEY} chars)}"
    echo "Failure log: $SMOKE_LOG_FILE"
    echo "=== end header ==="
    echo ""
  } >> "$SMOKE_CONSOLIDATED_LOG"
  {
    echo "=== PII enrichment quality test — failure log $(log_timestamp) ==="
    echo "Consolidated log: $SMOKE_CONSOLIDATED_LOG"
    echo ""
  } >> "$SMOKE_LOG_FILE"

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║   PII Semantic Enrichment — Input Redaction Quality Test  ║"
  echo "║   Prompts per variant: ${NUM_PROMPTS}                                   ║"
  echo "║   Model: ${MODEL}                                        ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Methodology: LLM-as-Judge pairwise comparison (MT-Bench style)"
  echo "  Model: ${MODEL} (override: MODEL=gpt-4o ./pii_enrichment_quality_test.sh)"
  echo "  Config: redact_input=true, redact_output=false"
  echo "  Criteria: Attribute Reasoning, Utility, Coherence, Helpfulness"
  echo "  Bias mitigation: response presentation order randomised per prompt"
  echo "  Prompt source: LLM-generated (gender/scope-dependent reasoning prompts)"
  echo "  Consolidated log: $SMOKE_CONSOLIDATED_LOG"
  echo "  Failure log:      $SMOKE_LOG_FILE"
  echo ""

  # --- Phase 0: Generate prompts via LLM ---
  generate_prompts "$NUM_PROMPTS"

  local actual_count="${#PROMPTS[@]}"
  if [[ "$actual_count" -eq 0 ]]; then
    echo "  ✗  No prompts available. Aborting."
    log_error "No prompts in PROMPTS array after Phase 0" "Check Phase 0 logs and PARSE_FAIL sections in $SMOKE_CONSOLIDATED_LOG"
    exit 3
  fi

  # --- Setup two enrichment variants ---
  CURRENT_SECTION="01_setup"
  log_to_file "${CYAN}Setting up Variant A (enrichment OFF)...${RESET}"
  local dir_a
  dir_a="$(setup_variant "A" "false" "off")"
  log_to_file "  Data dir: $dir_a"

  log_to_file "${CYAN}Setting up Variant B (enrichment ON, mode=enforce)...${RESET}"
  local dir_b
  dir_b="$(setup_variant "B" "true" "enforce")"
  log_to_file "  Data dir: $dir_b"

  # Dump final agent.talon.yaml for both variants (for debugging redaction/enrichment config)
  if [[ -n "${SMOKE_CONSOLIDATED_LOG:-}" ]]; then
    {
      echo ""
      echo "=== Variant A — agent.talon.yaml (after patching) ==="
      cat "$dir_a/agent.talon.yaml" 2>/dev/null || echo "(missing)"
      echo ""
      echo "=== Variant B — agent.talon.yaml (after patching) ==="
      cat "$dir_b/agent.talon.yaml" 2>/dev/null || echo "(missing)"
      echo ""
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi

  log_to_file "${CYAN}Setting up Judge directory (PII scanning OFF)...${RESET}"
  local dir_judge
  dir_judge="$(setup_section_dir "pii_quality_judge")"
  (
    cd "$dir_judge" || exit 1
    TALON_DATA_DIR="$dir_judge" talon init --scaffold --name "pii-quality-judge" &>/dev/null || true
    [[ -n "${OPENAI_API_KEY:-}" ]] && TALON_DATA_DIR="$dir_judge" talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null || true
    if [[ "$HAS_YQ" -eq 1 ]]; then
      yq -i '.policies.data_classification.input_scan = false | .policies.data_classification.output_scan = false | .policies.data_classification.redact_pii = false' \
        "$dir_judge/agent.talon.yaml" 2>/dev/null || true
    else
      local _yaml="$dir_judge/agent.talon.yaml"
      if grep -q 'data_classification:' "$_yaml" 2>/dev/null; then
        sed -i.bak 's/input_scan: *true/input_scan: false/; s/output_scan: *true/output_scan: false/; s/redact_pii: *true/redact_pii: false/' "$_yaml" 2>/dev/null || true
      else
        echo -e "\npolicies:\n  data_classification: { input_scan: false, output_scan: false, redact_pii: false }" >> "$_yaml"
      fi
    fi
    patch_yaml_model "$dir_judge/agent.talon.yaml"
    patch_yaml_rate_limit "$dir_judge/agent.talon.yaml"
  )
  log_to_file "  Data dir: $dir_judge"
  echo ""

  # --- Phase 1: Collect responses ---
  CURRENT_SECTION="02_collect_responses"
  local -a responses_a=()
  local -a responses_b=()
  local -a llm_input_a=()
  local -a llm_input_b=()
  local -a evidence_id_a=()
  local -a evidence_id_b=()

  echo "=== Phase 1: Collecting responses (${actual_count} prompts x 2 variants) ==="
  echo "  Config: redact_input=true, redact_output=false (raw LLM responses)"
  echo ""

  for (( i=0; i<actual_count; i++ )); do
    local prompt="${PROMPTS[$i]}"
    echo "  [$((i+1))/$actual_count] Original: ${prompt}"
    local sim_a sim_b
    sim_a="$(simulate_basic_redaction "$prompt")"
    sim_b="$(simulate_enriched_redaction "$prompt")"
    echo "    A input (expected basic):    ${sim_a}"
    echo "    B input (expected enriched): ${sim_b}"

    local resp_a
    resp_a="$(run_prompt "$dir_a" "$prompt" "A")"
    responses_a+=("$resp_a")
    local ev_a seen_a
    ev_a="$(extract_evidence_id "$resp_a")"
    seen_a="$(fetch_llm_input_summary "$dir_a" "$ev_a")"
    evidence_id_a+=("$ev_a")
    llm_input_a+=("$seen_a")
    if [[ -n "$seen_a" ]]; then
      echo "    A input (actual seen):       ${seen_a}"
    fi
    if [[ -n "$resp_a" ]] && [[ "$resp_a" != "null" ]]; then
      echo "    A response: ✓ ${#resp_a} chars — ${resp_a:0:120}..."
      record_pass
    else
      echo "    A response: ✗ empty"
      record_fail "response_a_empty_prompt_$((i+1))"
    fi

    local resp_b
    resp_b="$(run_prompt "$dir_b" "$prompt" "B")"
    responses_b+=("$resp_b")
    local ev_b seen_b
    ev_b="$(extract_evidence_id "$resp_b")"
    seen_b="$(fetch_llm_input_summary "$dir_b" "$ev_b")"
    evidence_id_b+=("$ev_b")
    llm_input_b+=("$seen_b")
    if [[ -n "$seen_b" ]]; then
      echo "    B input (actual seen):       ${seen_b}"
    fi
    if [[ -n "$resp_b" ]] && [[ "$resp_b" != "null" ]]; then
      echo "    B response: ✓ ${#resp_b} chars — ${resp_b:0:120}..."
      record_pass
    else
      echo "    B response: ✗ empty"
      record_fail "response_b_empty_prompt_$((i+1))"
    fi
    echo ""
  done

  # --- Hard verification: verify actual LLM input from step evidence ---
  # We inspect step_evidence.input_summary for first llm_call correlated to each run.
  local verify_ok=0 verify_fail=0 verify_missing=0
  for (( i=0; i<actual_count; i++ )); do
    local seen_a="${llm_input_a[$i]}"
    local seen_b="${llm_input_b[$i]}"
    if [[ -z "$seen_a" ]] || [[ -z "$seen_b" ]]; then
      ((verify_missing++)) || true
      continue
    fi
    local a_has_basic=0 b_has_enriched=0
    if echo "$seen_a" | grep -qE '\[PERSON\]|\[LOCATION\]|\[EMAIL\]|\[IBAN\]|\[PHONE\]' 2>/dev/null; then
      a_has_basic=1
    fi
    if echo "$seen_b" | grep -qE '<PII |gender="|scope="|country_code="|domain_type="' 2>/dev/null; then
      b_has_enriched=1
    fi
    if [[ "$a_has_basic" -eq 1 ]] && [[ "$b_has_enriched" -eq 1 ]]; then
      ((verify_ok++)) || true
    else
      ((verify_fail++)) || true
      log_warn "Input redaction verification failed for prompt $((i+1))" \
        "A_seen=${seen_a}
B_seen=${seen_b}"
    fi
  done

  echo ""
  if [[ "$verify_ok" -gt 0 ]]; then
    echo "  ✓  Input redaction verified via evidence: $verify_ok/$actual_count prompts."
  fi
  if [[ "$verify_missing" -gt 0 ]]; then
    echo "  ⚠  Could not verify $verify_missing/$actual_count prompts (missing sqlite3 or step evidence input_summary)."
    log_warn "Input redaction verification incomplete: missing step evidence input_summary" \
      "Ensure sqlite3 is installed and audit.include_prompts=true."
  fi
  if [[ "$verify_fail" -gt 0 ]]; then
    echo "  ✗  Input redaction verification FAILED for $verify_fail/$actual_count prompts."
    record_fail "input_redaction_verification_failed_${verify_fail}_of_${actual_count}"
  else
    echo "  ✓  Input redaction verification passed."
  fi
  echo ""

  # --- Phase 2: LLM-as-Judge ---
  CURRENT_SECTION="03_judge"
  local -a verdicts=()
  local -a judge_results=()
  local a_wins=0 b_wins=0 ties=0
  local a_total=0 b_total=0 swaps_used=0

  echo ""
  echo "=== Phase 2: LLM-as-Judge evaluation ==="

  for (( i=0; i<actual_count; i++ )); do
    log_plain_to_file "  [$((i+1))/$actual_count] Judging: ${PROMPTS[$i]:0:70}..."

    local jj
    jj="$(judge_response "$dir_judge" "${PROMPTS[$i]}" "${responses_a[$i]}" "${responses_b[$i]}" "$((i+1))")"
    judge_results+=("$jj")

    local v r sw
    v="$(echo "$jj" | jq -r '.verdict // "tie"')"
    r="$(echo "$jj" | jq -r '.reason // "n/a"')"
    sw="$(echo "$jj" | jq -r '.position_swapped // 0')"
    verdicts+=("$v")
    [[ "$sw" == "1" ]] && ((swaps_used++)) || true

    local as bs
    as="$(echo "$jj" | jq '(.a_utility + .a_context + .a_coherence + .a_helpful) // 20')"
    bs="$(echo "$jj" | jq '(.b_utility + .b_context + .b_coherence + .b_helpful) // 20')"
    a_total=$((a_total + as))
    b_total=$((b_total + bs))

    local swap_tag=""
    [[ "$sw" == "1" ]] && swap_tag=" [swapped]"
    case "$v" in
      A_better) ((a_wins++)) || true; echo "    ${v} (A:${as}/40 B:${bs}/40)${swap_tag} — ${r}" ;;
      B_better) ((b_wins++)) || true; echo "    ${v} (A:${as}/40 B:${bs}/40)${swap_tag} — ${r}" ;;
      *)        ((ties++))   || true; echo "    tie     (A:${as}/40 B:${bs}/40)${swap_tag} — ${r}" ;;
    esac
  done

  # --- Phase 3: Results ---
  CURRENT_SECTION="04_results"
  echo ""
  echo "=== Phase 3: Results ==="
  echo "═══════════════════════════════════════════════════════════════"
  echo ""

  printf "  %-4s  %-40s  %-8s  %-8s  %-10s  %-7s\n" "#" "Prompt (truncated)" "A" "B" "Winner" "Swap"
  printf "  %-4s  %-40s  %-8s  %-8s  %-10s  %-7s\n" "----" "----------------------------------------" "--------" "--------" "----------" "-------"
  for (( i=0; i<actual_count; i++ )); do
    local sa sb sv ss
    sa="$(echo "${judge_results[$i]}" | jq '(.a_utility + .a_context + .a_coherence + .a_helpful) // 20')"
    sb="$(echo "${judge_results[$i]}" | jq '(.b_utility + .b_context + .b_coherence + .b_helpful) // 20')"
    sv="${verdicts[$i]}"
    ss="$(echo "${judge_results[$i]}" | jq -r 'if .position_swapped == 1 then "yes" else "no" end')"
    printf "  %-4s  %-40s  %-8s  %-8s  %-10s  %-7s\n" "$((i+1))" "${PROMPTS[$i]:0:40}" "${sa}/40" "${sb}/40" "$sv" "$ss"
  done

  echo ""

  local a_avg b_avg
  if [[ "$actual_count" -gt 0 ]]; then
    a_avg="$(awk "BEGIN{printf \"%.1f\", $a_total / $actual_count}")"
    b_avg="$(awk "BEGIN{printf \"%.1f\", $b_total / $actual_count}")"
  else
    a_avg="0.0"; b_avg="0.0"
  fi

  echo "  Summary"
  echo "  ───────────────────────────────────────"
  echo "  Variant A (basic [PERSON]):        avg ${a_avg}/40   wins: ${a_wins}"
  echo "  Variant B (enriched <PII .../>):   avg ${b_avg}/40   wins: ${b_wins}"
  echo "  Ties:                                                ${ties}"
  echo "  Position swaps used:                                 ${swaps_used}/${actual_count}"
  echo ""

  if [[ "$b_wins" -gt "$a_wins" ]]; then
    echo "  VERDICT: Enriched input redaction (B) enabled better attribute-based reasoning."
    echo "  B won ${b_wins}/${actual_count} comparisons (avg ${b_avg}/40 vs A ${a_avg}/40)."
  elif [[ "$a_wins" -gt "$b_wins" ]]; then
    echo "  VERDICT: Basic input redaction (A) produced better responses (unexpected)."
    echo "  A won ${a_wins}/${actual_count} comparisons (avg ${a_avg}/40 vs B ${b_avg}/40)."
  else
    echo "  VERDICT: Tie — no significant quality difference detected."
  fi
  echo ""

  # Per-criterion breakdown
  local au_t=0 ac_t=0 as_t=0 ah_t=0 bu_t=0 bc_t=0 bs_t=0 bh_t=0
  for (( i=0; i<actual_count; i++ )); do
    au_t=$((au_t + $(echo "${judge_results[$i]}" | jq '.a_utility // 5')))
    ac_t=$((ac_t + $(echo "${judge_results[$i]}" | jq '.a_context // 5')))
    as_t=$((as_t + $(echo "${judge_results[$i]}" | jq '.a_coherence // 5')))
    ah_t=$((ah_t + $(echo "${judge_results[$i]}" | jq '.a_helpful // 5')))
    bu_t=$((bu_t + $(echo "${judge_results[$i]}" | jq '.b_utility // 5')))
    bc_t=$((bc_t + $(echo "${judge_results[$i]}" | jq '.b_context // 5')))
    bs_t=$((bs_t + $(echo "${judge_results[$i]}" | jq '.b_coherence // 5')))
    bh_t=$((bh_t + $(echo "${judge_results[$i]}" | jq '.b_helpful // 5')))
  done
  local mx=$((actual_count * 10))

  echo "  Per-Criterion Breakdown (max ${mx} per criterion)"
  echo "  ───────────────────────────────────────────────────"
  printf "  %-25s  %-12s  %-12s  %-6s\n" "Criterion" "A (basic)" "B (enriched)" "Delta"
  printf "  %-25s  %-12s  %-12s  %-6s\n" "-------------------------" "------------" "------------" "------"
  printf "  %-25s  %-12s  %-12s  %+d\n" "Utility Preservation" "${au_t}/${mx}" "${bu_t}/${mx}" "$((bu_t - au_t))"
  printf "  %-25s  %-12s  %-12s  %+d\n" "Attribute Reasoning"  "${ac_t}/${mx}" "${bc_t}/${mx}" "$((bc_t - ac_t))"
  printf "  %-25s  %-12s  %-12s  %+d\n" "Semantic Coherence"   "${as_t}/${mx}" "${bs_t}/${mx}" "$((bs_t - as_t))"
  printf "  %-25s  %-12s  %-12s  %+d\n" "Helpfulness"          "${ah_t}/${mx}" "${bh_t}/${mx}" "$((bh_t - ah_t))"
  echo ""

  # Methodology notes
  echo "  Methodology Notes"
  echo "  ─────────────────"
  echo "  Criteria: tau-eval, RedacBench, MT-Bench, plus PII-domain context sensitivity."
  echo "  Position bias: mitigated by randomising response order (${swaps_used}/${actual_count} swapped)."
  echo "  Prompts: LLM-generated (not fixtures) for diversity."
  echo "  Limitation: same model generates, responds, and judges (self-enhancement bias)."
  echo "  References: arxiv.org/abs/2506.05979 | openreview.net/pdf?id=wf73W2xatC | arxiv.org/abs/2306.05685"
  echo ""

  # --- Cost Report (from evidence records) ---
  echo "  Cost Report"
  echo "  ───────────"
  local cost_a_total=0 cost_b_total=0 cost_judge_total=0
  for variant_label in A B; do
    local vdir cost_json cost_sum=0
    if [[ "$variant_label" == "A" ]]; then vdir="$dir_a"; else vdir="$dir_b"; fi
    cost_json="$(env TALON_DATA_DIR="$vdir" talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
    if echo "$cost_json" | jq -e '.records' &>/dev/null 2>&1; then
      cost_sum="$(echo "$cost_json" | jq '[.records[].cost // 0] | add // 0' 2>/dev/null)" || cost_sum=0
      local rec_count
      rec_count="$(echo "$cost_json" | jq '.records | length' 2>/dev/null)" || rec_count=0
      printf "  Variant %s: €%.6f total  (%s evidence records, model: %s)\n" "$variant_label" "$cost_sum" "$rec_count" "$MODEL"
      if [[ "$variant_label" == "A" ]]; then cost_a_total="$cost_sum"; else cost_b_total="$cost_sum"; fi
    else
      printf "  Variant %s: (cost data unavailable)\n" "$variant_label"
    fi
  done
  # Judge costs
  local judge_cost_json
  judge_cost_json="$(env TALON_DATA_DIR="$dir_judge" talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
  if echo "$judge_cost_json" | jq -e '.records' &>/dev/null 2>&1; then
    cost_judge_total="$(echo "$judge_cost_json" | jq '[.records[].cost // 0] | add // 0' 2>/dev/null)" || cost_judge_total=0
    local judge_rec_count
    judge_rec_count="$(echo "$judge_cost_json" | jq '.records | length' 2>/dev/null)" || judge_rec_count=0
    printf "  Judge:     €%.6f total  (%s evidence records, model: %s)\n" "$cost_judge_total" "$judge_rec_count" "$MODEL"
  fi
  local total_cost
  total_cost="$(printf '%.6f' "$(echo "$cost_a_total $cost_b_total $cost_judge_total" | awk '{print $1+$2+$3}')")"
  local ca_fmt cb_fmt cj_fmt
  ca_fmt="$(printf '%.6f' "$cost_a_total")"
  cb_fmt="$(printf '%.6f' "$cost_b_total")"
  cj_fmt="$(printf '%.6f' "$cost_judge_total")"
  printf "  ─────────\n"
  printf "  Total:     €%s (A: €%s + B: €%s + Judge: €%s)\n" "$total_cost" "$ca_fmt" "$cb_fmt" "$cj_fmt"
  echo "  (Costs sum the per-run cost field from talon audit export JSON for each isolated TALON_DATA_DIR; A vs B differ when token usage differs.)"
  echo ""

  # --- Compliance Report (per variant) ---
  # Schema matches internal/compliance/report.go (no .summary.*): evidence_count,
  # pii_record_count, denied_count, total_cost_eur, mappings (static control matrix).
  echo "  Compliance Report"
  echo "  ─────────────────"
  for variant_label in A B; do
    local vdir
    if [[ "$variant_label" == "A" ]]; then vdir="$dir_a"; else vdir="$dir_b"; fi
    local comp_json
    comp_json="$(env TALON_DATA_DIR="$vdir" talon compliance report --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null)" || true
    if [[ -n "$comp_json" ]] && echo "$comp_json" | jq -e '.evidence_count != null' &>/dev/null 2>&1; then
      echo "  Variant ${variant_label}:"
      local evc pii_cnt denied comp_cost pii_pct map_fw
      evc="$(echo "$comp_json" | jq -r '.evidence_count // 0')"
      pii_cnt="$(echo "$comp_json" | jq -r '.pii_record_count // 0')"
      denied="$(echo "$comp_json" | jq -r '.denied_count // 0')"
      comp_cost="$(echo "$comp_json" | jq -r '.total_cost_eur // 0')"
      pii_pct="$(echo "$comp_json" | jq -r 'if ((.evidence_count // 0) | tonumber) > 0 then (((.pii_record_count // 0) * 10000 / .evidence_count | floor) / 100 | tostring) + "% of runs had PII flagged in evidence" else "n/a (no evidence)" end' 2>/dev/null)" || pii_pct="n/a"
      map_fw="$(echo "$comp_json" | jq -r '[.mappings[]?.framework] | unique | join(", ")' 2>/dev/null)" || map_fw=""
      echo "    Evidence records:   ${evc}"
      echo "    Policy denials:     ${denied}"
      echo "    PII in evidence:    ${pii_cnt} runs (${pii_pct})"
      echo "    Total cost (report): €$(printf '%.6f' "$comp_cost") (should match audit export sum)"
      [[ -n "$map_fw" ]] && echo "    Control mappings:   $(echo "$comp_json" | jq -r '.mappings | length') rows (frameworks: ${map_fw})"
      echo "    Secrets / residency: not in this JSON — talon compliance report is evidence-derived only; see agent policy and vault docs."
    else
      echo "  Variant ${variant_label}: (compliance report unavailable — run 'talon compliance report --format json' manually)"
    fi
  done
  echo ""

  # Append full reports to consolidated log for auditors
  {
    echo ""
    echo "=== Cost Report (detailed) ==="
    echo "Model: $MODEL"
    for variant_label in A B Judge; do
      local vdir
      case "$variant_label" in A) vdir="$dir_a";; B) vdir="$dir_b";; Judge) vdir="$dir_judge";; esac
      echo "--- Variant ${variant_label} evidence ---"
      env TALON_DATA_DIR="$vdir" talon audit export --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null \
        | jq -r '.records[] | "\(.id) model=\(.model_used // "?") cost=€\(.cost // 0) tokens_in=\(.tokens.input // 0) tokens_out=\(.tokens.output // 0)"' 2>/dev/null || echo "(no records)"
      echo ""
    done
    echo "=== Compliance Report (Variant A) ==="
    env TALON_DATA_DIR="$dir_a" talon compliance report --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null \
      | jq . 2>/dev/null || echo "(unavailable)"
    echo ""
    echo "=== Compliance Report (Variant B) ==="
    env TALON_DATA_DIR="$dir_b" talon compliance report --format json --from 2020-01-01 --to 2099-12-31 2>/dev/null \
      | jq . 2>/dev/null || echo "(unavailable)"
    echo ""
  } >> "$SMOKE_CONSOLIDATED_LOG"

  # Per-prompt A vs B for human review (interpretation guide + full prompt + both outputs + judge)
  {
    echo ""
    echo "=== Per-prompt comparison: Variant A (basic input [PERSON]) vs Variant B (enriched input <PII .../>) ==="
    echo ""
    echo "How to read this file:"
    echo "  • Both variants use redact_input=true, redact_output=false (raw LLM responses)"
    echo "  • Variant A — basic input redaction: LLM sees [PERSON], [LOCATION], [PHONE], [IBAN], [EMAIL]"
    echo "  • Variant B — enriched input redaction: LLM sees <PII .../> with semantic attributes"
    echo "  • Inputs below are pulled from step_evidence.input_summary when available (actual captured LLM input)"
    echo "  • If step_evidence is unavailable, script falls back to simulated expected redaction"
    echo "  • Judge scores a_* vs b_* always mean A vs B (order shown to judge may be swapped)"
    echo ""
    for (( i=0; i<actual_count; i++ )); do
      local sim_a_log sim_b_log seen_a_log seen_b_log
      sim_a_log="$(simulate_basic_redaction "${PROMPTS[$i]}")"
      sim_b_log="$(simulate_enriched_redaction "${PROMPTS[$i]}")"
      seen_a_log="${llm_input_a[$i]}"
      seen_b_log="${llm_input_b[$i]}"
      if [[ -z "$seen_a_log" ]]; then
        seen_a_log="$sim_a_log"
      fi
      if [[ -z "$seen_b_log" ]]; then
        seen_b_log="$sim_b_log"
      fi
      echo "######################################################################"
      echo "### Prompt $((i+1))/${actual_count}"
      echo "######################################################################"
      echo ""
      echo "--- Original prompt ---"
      printf '%s\n' "${PROMPTS[$i]}"
      echo ""
      echo "--- Variant A input (captured from evidence, what LLM sees) ---"
      printf '%s\n' "$seen_a_log"
      echo ""
      echo "--- Variant B input (captured from evidence, what LLM sees) ---"
      printf '%s\n' "$seen_b_log"
      echo ""
      echo "--- Variant A response — raw LLM output (${#responses_a[$i]} chars) ---"
      pii_emit_body_for_log "${responses_a[$i]}"
      echo ""
      echo "--- Variant B response — raw LLM output (${#responses_b[$i]} chars) ---"
      pii_emit_body_for_log "${responses_b[$i]}"
      echo ""
      echo "--- LLM judge (scores: a_* = Variant A, b_* = Variant B) ---"
      echo "${judge_results[$i]}" | jq . 2>/dev/null || echo "${judge_results[$i]}"
      echo ""
    done
  } >> "$SMOKE_CONSOLIDATED_LOG"

  if [[ -s "$SMOKE_FAILED_TESTS_FILE" ]]; then
    {
      echo ""
      echo "=== record_fail / empty-response ids (SMOKE_FAILED_TESTS_FILE) ==="
      cat "$SMOKE_FAILED_TESTS_FILE"
      echo "=== end failed ids ==="
    } >> "$SMOKE_CONSOLIDATED_LOG"
  fi

  # Aggregate counts from file (matching smoke_test.sh pattern)
  local final_pass final_fail
  # grep -c emits 0 but exits 1 when count is zero; "|| echo 0" would yield "0\n0".
  final_pass="$(grep -c '^P$' "$SMOKE_COUNTS_FILE" 2>/dev/null || true)"
  final_fail="$(grep -c '^F$' "$SMOKE_COUNTS_FILE" 2>/dev/null || true)"
  final_pass="${final_pass:-0}"
  final_fail="${final_fail:-0}"

  echo "  Pass: ${final_pass}  Fail: ${final_fail}"
  echo "  Consolidated log: $SMOKE_CONSOLIDATED_LOG"
  [[ "$final_fail" -gt 0 ]] && echo "  Failure log: $SMOKE_LOG_FILE"
  echo ""
  echo "[SMOKE] SUMMARY|PASS_COUNT|${final_pass} FAIL_COUNT|${final_fail} MODEL|${MODEL}" >> "$SMOKE_CONSOLIDATED_LOG"

  if [[ "$a_wins" -gt "$b_wins" ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
