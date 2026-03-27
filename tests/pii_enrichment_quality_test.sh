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
# Example:
#   Original: "Mr. Kowalski and Mrs. Kowalski are comparing heights. Who is taller?"
#   Variant A sees: "[PERSON] and [PERSON] are comparing heights. Who is taller?"
#     → LLM cannot reason about gender → poor response
#   Variant B sees: "<PII type="person" gender="male" id="1"/> and <PII type="person"
#     gender="female" id="2"/> are comparing heights. Who is taller?"
#     → LLM can reason that id="1" is male → statistically taller → good response
#
# Phase 0: LLM generates N prompts that REQUIRE gender/scope reasoning (not just
#   business boilerplate). Each prompt must have a question whose answer depends on
#   knowing the gender or location scope of the PII entities.
# Phase 1: Sends each prompt through Talon twice with input redaction ON, output
#   redaction OFF. Each variant sends a DIFFERENTLY redacted prompt to the LLM.
# Phase 2: LLM-as-Judge evaluates which variant produced better reasoning.
#
# Evaluation methodology:
#   - Criteria: Gender/Scope Reasoning, Utility Preservation, Semantic Coherence,
#     Helpfulness — designed to measure whether enriched attributes enable reasoning.
#   - Position bias mitigation: response order randomised per prompt.
#   - Self-enhancement bias acknowledged: same model generates and judges (documented
#     limitation; acceptable for relative A-vs-B comparison on identical prompts).
#
# Usage:
#   ./pii_enrichment_quality_test.sh               # 10 prompts per variant (default)
#   NUM_PROMPTS=5 ./pii_enrichment_quality_test.sh  # 5 prompts per variant
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
      .policies.semantic_enrichment.enabled = '"$enrichment_enabled"' |
      .policies.semantic_enrichment.mode = "'"$enrichment_mode"'" |
      .policies.semantic_enrichment.allowed_attributes = ["gender", "scope"]
    ' "$yaml_file" 2>/dev/null || true
  else
    # Enable scanning, keep redact_pii false, set granular fields explicitly.
    sed -i.bak \
      -e 's/input_scan: *false/input_scan: true/' \
      -e 's/output_scan: *false/output_scan: true/' \
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
        sed -i.bak '/^  model_routing:/i\  semantic_enrichment:\n    enabled: true\n    mode: '"${enrichment_mode}"'\n    allowed_attributes: [gender, scope]' "$yaml_file" 2>/dev/null || true
      fi
    else
      if grep -q 'semantic_enrichment:' "$yaml_file"; then
        sed -i.bak 's/semantic_enrichment:.*/semantic_enrichment: { enabled: false }/' "$yaml_file" 2>/dev/null || true
      fi
    fi
  fi
}

# --- Tier 2 defaults to Bedrock-only Claude; CI and many dev machines have no Bedrock. ----------
# Align with agent.talon.yaml.tmpl comment: use OpenAI for tier_2 when Bedrock is unavailable.
patch_yaml_openai_tier2() {
  local yaml_file="$1"
  [[ -f "$yaml_file" ]] || return 0
  if [[ "$HAS_YQ" -eq 1 ]]; then
    yq -i '
      .policies.model_routing.tier_2.primary = "gpt-4o-mini" |
      .policies.model_routing.tier_2.fallback = "gpt-4o-mini" |
      .policies.model_routing.tier_2.bedrock_only = false
    ' "$yaml_file" 2>/dev/null || true
  else
    sed -i.bak \
      -e 's/primary: claude[^[:space:]]*/primary: gpt-4o-mini/' \
      -e 's/bedrock_only: true/bedrock_only: false/' \
      "$yaml_file" 2>/dev/null || true
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
    patch_yaml_openai_tier2 "$dir/agent.talon.yaml"
  )
  echo "$dir"
}

# --- Generate prompt corpus via LLM ----------------------------------------
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
    patch_yaml_openai_tier2 "$gen_dir/agent.talon.yaml"
  )

  local gen_instruction
  read -r -d '' gen_instruction <<'GEN_EOF' || true
Generate exactly NUM_PLACEHOLDER prompts as a JSON array of strings.

CRITICAL: Each prompt MUST ask a question or request a task where the ANSWER DEPENDS on
knowing the GENDER of a person or the SCOPE of a location (city vs country vs region).
The names will be replaced with anonymous placeholders before the AI sees them, so the
prompt must be designed so that knowing "this person is male" or "this place is a city"
is ESSENTIAL to give a correct answer.

Good examples of gender-dependent prompts:
- "Mr. Schmidt and Mrs. Mueller are comparing average heights. Based on statistics, who is likely taller?"
- "Herr Fischer and Frau Weber both applied for a nursing position. Statistically, which candidate profile is more common in nursing in Germany?"
- "Write a formal German letter to Herr Braun using the correct salutation and pronouns."

Good examples of location-scope-dependent prompts:
- "Should the Munich office follow city-level or federal-level waste regulations?"
- "Is Bavaria a suitable location for a nationwide product launch, or should we target a single city first?"

Requirements for EVERY prompt:
- Contains at least one European person name WITH a gendered title (Mr., Mrs., Ms., Frau, Herr, Dr.)
- Contains at least one European city or region name
- The question or task MUST REQUIRE knowing the gender or location scope to answer correctly
- If gender info is removed, the AI should NOT be able to answer properly
- Mix genders roughly equally; use varied EU countries
- Do NOT use possessive apostrophes (no "Weber's", use "of Weber" instead)
- Keep prompts to 1-3 sentences, focused on the reasoning question

Reply ONLY with a valid JSON array. No markdown fences, no explanation.
Example: ["Mr. X and Mrs. Y are competing in a strength contest. Statistically, who has the advantage?", "..."]
GEN_EOF

  gen_instruction="${gen_instruction//NUM_PLACEHOLDER/$count}"

  local raw_output json_array
  raw_output="$(run_talon_in "$gen_dir" run "$gen_instruction" 2>&1)" || true
  json_array="$(extract_prompt_json_array "$raw_output")" || true

  if [[ -z "$json_array" ]] || ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
    local jq_diag=""
    jq_diag="$(echo "$raw_output" | jq . 2>&1 | head -30 || true)"
    log_warn "Phase 0: could not extract JSON array from first LLM run" "jq . on raw (first 30 lines): ${jq_diag}"
    echo "  -  First attempt failed to parse; retrying with simpler instruction..."
    log_parse_failure "Phase 0 first LLM output (parse failed)" "$raw_output"
    raw_output="$(run_talon_in "$gen_dir" run \
      "Generate ${count} one-sentence business email prompts as a JSON array. Each must include a European name with Mr/Mrs/Dr title, a European city, and a fictional email address. Reply ONLY with a JSON array of strings." \
      2>&1)" || true
    json_array="$(extract_prompt_json_array "$raw_output")" || true
  fi

  if [[ -z "$json_array" ]] || ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
    echo "  ✗  Prompt generation failed after retry. Cannot proceed."
    log_parse_failure "Phase 0 retry LLM output (parse failed)" "$raw_output"
    log_error "Prompt generation failed: no valid JSON array after two LLM attempts" "See PARSE_FAIL blocks above. TALON_DATA_DIR=${TALON_DATA_DIR:-} gen_dir=${gen_dir:-}"
    record_fail "prompt generation"
    exit 3
  fi

  local generated_count i
  generated_count="$(echo "$json_array" | jq 'length')"
  for (( i=0; i<generated_count; i++ )); do
    local p
    p="$(echo "$json_array" | jq -r ".[$i]")"
    [[ -n "$p" ]] && [[ "$p" != "null" ]] && PROMPTS+=("$p")
  done

  echo "  ✓  Generated ${#PROMPTS[@]} prompts (requested ${count})"
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
# Variant A (basic): "Mr. Kowalski" → [PERSON], "Munich" → [LOCATION]
# Variant B (enriched): "Mr. Kowalski" → <PII type="person" gender="male" id="N"/>
simulate_basic_redaction() {
  local text="$1"
  local id=0
  # Replace gendered titles + names with [PERSON]
  text="$(echo "$text" | sed -E 's/(Mr\.|Mrs\.|Ms\.|Frau|Herr|Dr\.)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/[PERSON]/g')"
  # Replace known EU city/region names (common ones)
  text="$(echo "$text" | sed -E 's/\b(Munich|Berlin|Hamburg|Frankfurt|Stuttgart|Paris|Lyon|Marseille|Warsaw|Krakow|Kraków|Rome|Milan|Madrid|Barcelona|Amsterdam|Rotterdam|Bucharest|Stockholm|Vienna|Prague|Budapest|Brussels|Lisbon|Dublin|Copenhagen|Helsinki|Oslo|Zurich|Geneva|Luxembourg)\b/[LOCATION]/g')"
  # Replace IBAN patterns
  text="$(echo "$text" | sed -E 's/[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}/[IBAN]/g')"
  # Replace email patterns
  text="$(echo "$text" | sed -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[EMAIL]/g')"
  printf '%s' "$text"
}

simulate_enriched_redaction() {
  local text="$1"
  local pid=0 lid=0
  # Replace Mr./Herr + name with enriched male tag
  while echo "$text" | grep -qE '(Mr\.|Herr)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+'; do
    ((pid++)) || true
    text="$(echo "$text" | sed -E "s/(Mr\.|Herr)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/<PII type=\"person\" gender=\"male\" id=\"${pid}\"\/>/1")"
  done
  # Replace Mrs./Ms./Frau + name with enriched female tag
  while echo "$text" | grep -qE '(Mrs\.|Ms\.|Frau)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+'; do
    ((pid++)) || true
    text="$(echo "$text" | sed -E "s/(Mrs\.|Ms\.|Frau)\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/<PII type=\"person\" gender=\"female\" id=\"${pid}\"\/>/1")"
  done
  # Replace Dr. + name with enriched tag (unknown gender)
  while echo "$text" | grep -qE 'Dr\.\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+'; do
    ((pid++)) || true
    text="$(echo "$text" | sed -E "s/Dr\.\s+[A-ZÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zàáâãäåæçèéêëìíîïñòóôõöùúûüý]+/<PII type=\"person\" id=\"${pid}\"\/>/1")"
  done
  # Replace cities with enriched location tags
  for city in Munich Berlin Hamburg Frankfurt Stuttgart Paris Lyon Marseille Warsaw Krakow Kraków Rome Milan Madrid Barcelona Amsterdam Rotterdam Bucharest Stockholm Vienna Prague Budapest Brussels Lisbon Dublin Copenhagen Helsinki Oslo Zurich Geneva Luxembourg; do
    if echo "$text" | grep -q "\b${city}\b" 2>/dev/null; then
      ((lid++)) || true
      text="$(echo "$text" | sed -E "s/\b${city}\b/<PII type=\"location\" scope=\"city\" id=\"loc_${lid}\"\/>/1")"
    fi
  done
  # Replace IBANs
  text="$(echo "$text" | sed -E 's/[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}/<PII type="iban"\/>/g')"
  # Replace emails
  text="$(echo "$text" | sed -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/<PII type="email"\/>/g')"
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

# --- LLM-as-Judge (MT-Bench pairwise style with position-bias mitigation) ---
#
# Evaluation criteria (designed for input-redaction A/B testing):
#   1. GENDER_SCOPE_REASONING: Can the AI reason about gender/location despite redaction?
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
- One system received basic placeholders like [PERSON], [LOCATION] (no gender or scope info)
- The other received enriched placeholders like <PII type="person" gender="male" id="1"/>
  or <PII type="location" scope="city" id="loc_1"/>

The original prompt was designed so that KNOWING the gender of persons or the scope of
locations (city vs country vs region) is ESSENTIAL to answer correctly. The system with
enriched placeholders should be able to reason better about gender-dependent or
location-scope-dependent questions.

Score each response on these four criteria (1-10 each):

1. GENDER_SCOPE_REASONING: Did the response correctly use gender or location-scope
   information to reason about the question? Did it identify which person is male/female,
   or whether a location is a city/region/country, and use that in its answer?
   Score 1-3 if the response admits it cannot determine gender/scope or guesses randomly.
   Score 4-6 if it partially reasons but with caveats about missing information.
   Score 7-10 if it confidently and correctly uses gender/scope attributes in reasoning.

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
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Methodology: LLM-as-Judge pairwise comparison (MT-Bench style)"
  echo "  Config: redact_input=true, redact_output=false"
  echo "  Criteria: Gender/Scope Reasoning, Utility, Coherence, Helpfulness"
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
    patch_yaml_openai_tier2 "$dir_judge/agent.talon.yaml"
  )
  log_to_file "  Data dir: $dir_judge"
  echo ""

  # --- Phase 1: Collect responses ---
  CURRENT_SECTION="02_collect_responses"
  local -a responses_a=()
  local -a responses_b=()

  echo "=== Phase 1: Collecting responses (${actual_count} prompts x 2 variants) ==="
  echo "  Config: redact_input=true, redact_output=false (raw LLM responses)"
  echo ""

  for (( i=0; i<actual_count; i++ )); do
    local prompt="${PROMPTS[$i]}"
    echo "  [$((i+1))/$actual_count] Original: ${prompt}"
    local sim_a sim_b
    sim_a="$(simulate_basic_redaction "$prompt")"
    sim_b="$(simulate_enriched_redaction "$prompt")"
    echo "    A input (basic):    ${sim_a}"
    echo "    B input (enriched): ${sim_b}"

    local resp_a
    resp_a="$(run_prompt "$dir_a" "$prompt" "A")"
    responses_a+=("$resp_a")
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
    if [[ -n "$resp_b" ]] && [[ "$resp_b" != "null" ]]; then
      echo "    B response: ✓ ${#resp_b} chars — ${resp_b:0:120}..."
      record_pass
    else
      echo "    B response: ✗ empty"
      record_fail "response_b_empty_prompt_$((i+1))"
    fi
    echo ""
  done

  # --- Sanity check: verify INPUT redaction is working ---
  # With redact_output: false, LLM responses are raw. If the LLM response references
  # placeholder tokens ([PERSON], <PII .../>), input redaction is working. If responses
  # echo back original names, input redaction failed.
  local redaction_evidence=0 redaction_no_evidence=0
  for (( i=0; i<actual_count; i++ )); do
    local prompt="${PROMPTS[$i]}"
    local ra="${responses_a[$i]}" rb="${responses_b[$i]}"
    # Check if Variant A response references basic placeholders or lacks original names
    local a_has_placeholder=0
    if echo "$ra" | grep -qE '\[PERSON\]|\[LOCATION\]|\[EMAIL\]|\[IBAN\]' 2>/dev/null; then
      a_has_placeholder=1
    fi
    # Check if Variant B response references enriched placeholders
    local b_has_enriched=0
    if echo "$rb" | grep -qE '<PII |type="person"|gender="|scope="' 2>/dev/null; then
      b_has_enriched=1
    fi
    if [[ "$a_has_placeholder" -eq 1 ]] || [[ "$b_has_enriched" -eq 1 ]]; then
      ((redaction_evidence++)) || true
    else
      ((redaction_no_evidence++)) || true
    fi
  done

  echo ""
  if [[ "$redaction_evidence" -gt 0 ]]; then
    echo "  ✓  Input redaction check: $redaction_evidence/$actual_count responses reference placeholder tokens."
  fi
  if [[ "$redaction_no_evidence" -gt 0 ]]; then
    echo "  ⚠  Input redaction check: $redaction_no_evidence/$actual_count responses show no placeholder tokens."
    echo "     The LLM may have paraphrased away the placeholders, or input redaction is not active."
    log_warn "Input redaction check: $redaction_no_evidence/$actual_count responses lack placeholder references" \
      "This is expected if LLM paraphrased, but worth checking agent.talon.yaml"
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
    echo "  VERDICT: Enriched input redaction (B) enabled better gender/scope reasoning."
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
  printf "  %-25s  %-12s  %-12s  %+d\n" "Gender/Scope Reasoning"  "${ac_t}/${mx}" "${bc_t}/${mx}" "$((bc_t - ac_t))"
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

  # Per-prompt A vs B for human review (interpretation guide + full prompt + both outputs + judge)
  {
    echo ""
    echo "=== Per-prompt comparison: Variant A (basic input [PERSON]) vs Variant B (enriched input <PII .../>) ==="
    echo ""
    echo "How to read this file:"
    echo "  • Both variants use redact_input=true, redact_output=false (raw LLM responses)"
    echo "  • Variant A — basic input redaction: LLM sees [PERSON], [LOCATION] (no gender/scope info)"
    echo "  • Variant B — enriched input redaction: LLM sees <PII type=\"person\" gender=\"male\"/> etc."
    echo "  • Prompts require gender/scope reasoning; Variant A should struggle, Variant B should succeed"
    echo "  • Judge scores a_* vs b_* always mean A vs B (order shown to judge may be swapped)"
    echo ""
    for (( i=0; i<actual_count; i++ )); do
      local sim_a_log sim_b_log
      sim_a_log="$(simulate_basic_redaction "${PROMPTS[$i]}")"
      sim_b_log="$(simulate_enriched_redaction "${PROMPTS[$i]}")"
      echo "######################################################################"
      echo "### Prompt $((i+1))/${actual_count}"
      echo "######################################################################"
      echo ""
      echo "--- Original prompt ---"
      printf '%s\n' "${PROMPTS[$i]}"
      echo ""
      echo "--- Variant A input (basic, what LLM sees) ---"
      printf '%s\n' "$sim_a_log"
      echo ""
      echo "--- Variant B input (enriched, what LLM sees) ---"
      printf '%s\n' "$sim_b_log"
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
  echo "[SMOKE] SUMMARY|PASS_COUNT|${final_pass} FAIL_COUNT|${final_fail}" >> "$SMOKE_CONSOLIDATED_LOG"

  if [[ "$a_wins" -gt "$b_wins" ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
