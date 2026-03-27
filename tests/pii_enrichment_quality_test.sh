#!/usr/bin/env bash
#
# Dativo Talon — PII Semantic Enrichment Quality Comparison Test
#
# Compares LLM response quality with vs without semantic enrichment on PII redaction.
#
# Phase 0: Uses the LLM itself to generate N diverse business prompts containing
#   EU PII (gendered titles, cities, emails, IBANs) — no hardcoded fixtures.
# Phase 1: Sends each prompt through Talon twice:
#   Variant A: enrichment OFF  → placeholders like [PERSON], [LOCATION]
#   Variant B: enrichment ON   → placeholders like <PII type="person" gender="female"/>, <PII type="location" scope="city"/>
# Phase 2: LLM-as-Judge (MT-Bench pairwise style) evaluates which variant
#   produces higher-quality responses.
#
# Evaluation methodology:
#   - Criteria aligned with tau-eval (utility preservation), RedacBench (semantic
#     coherence), and MT-Bench (pairwise comparison with position-bias mitigation).
#   - Four orthogonal axes: Utility Preservation, Context Sensitivity, Semantic
#     Coherence, Helpfulness.
#   - Position bias mitigation: response order (first/second) is randomised per prompt
#     so the judge cannot develop a positional preference.
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
# breakdown, and a summary verdict. Full results logged to consolidated log.

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

write_cmd_log() {
  local description="$1" cmd="$2" code="$3" tmp_out="$4" tmp_err="$5"
  [[ -z "${SMOKE_CONSOLIDATED_LOG:-}" ]] && return 0
  {
    echo "[SMOKE] SECTION|$CURRENT_SECTION"
    echo "[SMOKE] ASSERT_DESC|$description"
    echo "[SMOKE] CMD|$cmd"
    echo "[SMOKE] EXIT|$code"
    echo "[SMOKE] STDOUT_TAIL<<"
    [[ -f "$tmp_out" ]] && tail -30 "$tmp_out"
    echo "[SMOKE] STDOUT_TAIL>>"
    echo "[SMOKE] STDERR_TAIL<<"
    [[ -f "$tmp_err" ]] && tail -30 "$tmp_err"
    echo "[SMOKE] STDERR_TAIL>>"
    echo ""
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
      echo "Stdout (last 50 lines):"; tail -50 "$tmp_out"
      echo "Stderr (last 50 lines):"; tail -50 "$tmp_err"
      echo ""
    } >> "$SMOKE_LOG_FILE"
  fi
  if [[ -s "$tmp_err" ]]; then
    echo "    Last stderr:"
    tail -5 "$tmp_err" | sed 's/^/    | /'
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

run_talon() {
  env TALON_DATA_DIR="$TALON_DATA_DIR" talon "$@"
}

run_talon_in() {
  local data_dir="$1"; shift
  env TALON_DATA_DIR="$data_dir" talon "$@"
}

setup_section_dir() {
  local name="$1"
  mkdir -p "$TALON_DATA_DIR/sections/$name"
  echo "$TALON_DATA_DIR/sections/$name"
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

  TALON_DATA_DIR="$(mktemp -d)"
  SMOKE_CREATED_DATA_DIR=1
  export TALON_DATA_DIR
  export TALON_SIGNING_KEY="${TALON_SIGNING_KEY:-$(openssl rand -hex 32 2>/dev/null || echo "pii-quality-signing-key-pad32")}"
  echo "  All prerequisites met."
  echo "  TALON_DATA_DIR=$TALON_DATA_DIR"
}

# --- YAML patching (yq with sed fallback, matching smoke_test.sh) -----------
patch_yaml() {
  local yaml_file="$1" enrichment_enabled="$2" enrichment_mode="$3"
  if [[ "$HAS_YQ" -eq 1 ]]; then
    yq -i '
      .policies.data_classification.input_scan = true |
      .policies.data_classification.output_scan = true |
      .policies.data_classification.redact_pii = true |
      .policies.semantic_enrichment.enabled = '"$enrichment_enabled"' |
      .policies.semantic_enrichment.mode = "'"$enrichment_mode"'" |
      .policies.semantic_enrichment.allowed_attributes = ["gender", "scope"]
    ' "$yaml_file" 2>/dev/null || true
  else
    grep -q 'data_classification:' "$yaml_file" || \
      echo -e "\npolicies:\n  data_classification: { input_scan: true, output_scan: true, redact_pii: true }" >> "$yaml_file"
    if [[ "$enrichment_enabled" == "true" ]]; then
      if ! grep -q 'semantic_enrichment:' "$yaml_file"; then
        echo "  semantic_enrichment: { enabled: true, mode: ${enrichment_mode}, allowed_attributes: [gender, scope] }" >> "$yaml_file"
      fi
    else
      if grep -q 'semantic_enrichment:' "$yaml_file"; then
        sed -i.bak 's/semantic_enrichment:.*/semantic_enrichment: { enabled: false }/' "$yaml_file" 2>/dev/null || true
      fi
    fi
  fi
}

# --- Setup an isolated Talon environment for a variant ----------------------
setup_variant() {
  local label="$1" enrichment_enabled="$2" enrichment_mode="$3"
  local dir
  dir="$(setup_section_dir "pii_quality_${label}")"
  (
    cd "$dir" || exit 1
    TALON_DATA_DIR="$dir" talon init --scaffold --name "pii-quality-${label}" &>/dev/null || true
    [[ -n "${OPENAI_API_KEY:-}" ]] && TALON_DATA_DIR="$dir" talon secrets set openai-api-key "$OPENAI_API_KEY" &>/dev/null || true
    patch_yaml "$dir/agent.talon.yaml" "$enrichment_enabled" "$enrichment_mode"
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
    if [[ "$HAS_YQ" -eq 1 ]]; then
      yq -i '.policies.data_classification.input_scan = false | .policies.data_classification.output_scan = false | .policies.data_classification.redact_pii = false' \
        "$gen_dir/agent.talon.yaml" 2>/dev/null || true
    else
      local _yaml="$gen_dir/agent.talon.yaml"
      if grep -q 'data_classification:' "$_yaml" 2>/dev/null; then
        sed -i.bak 's/input_scan: *true/input_scan: false/; s/output_scan: *true/output_scan: false/; s/redact_pii: *true/redact_pii: false/' "$_yaml" 2>/dev/null || true
      else
        echo -e "\npolicies:\n  data_classification: { input_scan: false, output_scan: false, redact_pii: false }" >> "$_yaml"
      fi
    fi
  )

  local gen_instruction
  read -r -d '' gen_instruction <<'GEN_EOF' || true
Generate exactly NUM_PLACEHOLDER diverse business prompts as a JSON array of strings.

Requirements for EVERY prompt:
- Contains at least one European person name WITH a gendered title (Mr., Mrs., Ms., Frau, Herr, Dr., etc.)
- Contains at least one European city or region name
- Contains at least one of: email address, IBAN, or phone number (use realistic but fictional values)
- Represents a realistic business task (email drafting, report writing, compliance summary, meeting invite, onboarding, apology, reference letter, etc.)
- The gendered title and location MUST matter for the task (e.g. correct salutation, locale-appropriate formality)
- Mix genders roughly equally across the batch
- Use a variety of EU countries (Germany, France, Poland, Italy, Spain, Netherlands, Romania, Sweden, etc.)
- Do NOT use possessive apostrophes (no "Weber's", use "of Weber" instead)

Reply ONLY with a valid JSON array. No markdown fences, no explanation, no numbering.
Example format: ["Prompt one here.", "Prompt two here."]
GEN_EOF

  gen_instruction="${gen_instruction//NUM_PLACEHOLDER/$count}"

  local raw_output
  raw_output="$(run_talon_in "$gen_dir" run "$gen_instruction" 2>/dev/null)" || true

  local json_array
  json_array="$(echo "$raw_output" | grep -o '\[.*\]')" || true

  if ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
    echo "  -  First attempt failed to parse; retrying with simpler instruction..."
    raw_output="$(run_talon_in "$gen_dir" run \
      "Generate ${count} one-sentence business email prompts as a JSON array. Each must include a European name with Mr/Mrs/Dr title, a European city, and a fictional email address. Reply ONLY with a JSON array of strings." \
      2>/dev/null)" || true
    json_array="$(echo "$raw_output" | grep -o '\[.*\]')" || true
  fi

  if ! echo "$json_array" | jq -e 'type == "array" and length > 0' &>/dev/null 2>&1; then
    echo "  ✗  Prompt generation failed after retry. Cannot proceed."
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
    log_plain_to_file "    [$((i+1))] ${PROMPTS[$i]:0:90}..."
  done
  echo ""
}

# --- Run a single prompt through a variant and capture the response ---------
run_prompt() {
  local data_dir="$1" prompt="$2"
  run_talon_in "$data_dir" run "$prompt" 2>/dev/null || true
}

# --- LLM-as-Judge (MT-Bench pairwise style with position-bias mitigation) ---
#
# Evaluation criteria (research-aligned):
#   1. UTILITY_PRESERVATION (tau-eval): task completion despite redaction
#   2. CONTEXT_SENSITIVITY (PII-specific): gender/locale cue preservation
#   3. SEMANTIC_COHERENCE (RedacBench): logical consistency despite placeholders
#   4. HELPFULNESS (MT-Bench): actionable, complete, useful response
#
# Position-bias mitigation: response order randomised per prompt.
judge_response() {
  local judge_dir="$1" original_prompt="$2" response_a="$3" response_b="$4"

  local first_resp second_resp swap=0
  if (( RANDOM % 2 )); then
    swap=1
    first_resp="$response_b"; second_resp="$response_a"
  else
    first_resp="$response_a"; second_resp="$response_b"
  fi

  local judge_prompt
  read -r -d '' judge_prompt <<'JUDGE_EOF' || true
You are an expert evaluator for AI-generated text produced from PII-redacted prompts.
The original prompt contained personal data (names, emails, IBANs, addresses) that was
redacted before reaching the AI. You will see two responses generated from differently-
redacted versions of that prompt. Your job is to score each response independently.

Score each response on these four criteria (1-10 each). These criteria are orthogonal;
score them independently:

1. UTILITY_PRESERVATION: Does the response accomplish the original task despite PII
   redaction? Would the requester be able to use this response for its intended purpose?
   (Aligned with tau-eval anonymisation utility metric.)

2. CONTEXT_SENSITIVITY: Are gender-specific cues (pronouns, salutations like Mr/Mrs/Dr),
   location-appropriate formality, and cultural conventions correctly maintained despite
   redacted PII? A response using "Dear Sir" for a female recipient scores low here.
   (PII-redaction-specific criterion from de-identification research.)

3. SEMANTIC_COHERENCE: Is the response logically structured, internally consistent, and
   free of contradictions or nonsensical references introduced by placeholder tokens?
   (Aligned with RedacBench proposition-level coherence metric.)

4. HELPFULNESS: Is the response genuinely useful, actionable, appropriately detailed,
   and complete enough to serve what the requester needs?
   (Aligned with MT-Bench helpfulness criterion.)

IMPORTANT: Reply ONLY with valid JSON, no markdown fences, no explanation. Use exactly:
{"r1_utility":N,"r1_context":N,"r1_coherence":N,"r1_helpful":N,"r2_utility":N,"r2_context":N,"r2_coherence":N,"r2_helpful":N,"verdict":"Response_1|Response_2|tie","reason":"one sentence explaining the key differentiator"}
JUDGE_EOF
  judge_prompt="${judge_prompt}

Original prompt (before redaction):
${original_prompt}

--- Response 1 ---
${first_resp}

--- Response 2 ---
${second_resp}"

  local judge_out
  judge_out="$(run_talon_in "$judge_dir" run "$judge_prompt" 2>/dev/null)" || true

  local json_part
  json_part="$(echo "$judge_out" | grep -o '{.*}' | head -1)" || true

  if ! echo "$json_part" | jq -e '.verdict' &>/dev/null 2>&1; then
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
    '{a_utility:$au,a_context:$ac,a_coherence:$as,a_helpful:$ah,
      b_utility:$bu,b_context:$bc,b_coherence:$bs,b_helpful:$bh,
      verdict:$v,reason:$r,position_swapped:$sw}'
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

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║   PII Semantic Enrichment — Quality Comparison Test        ║"
  echo "║   Prompts per variant: ${NUM_PROMPTS}                                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Methodology: LLM-as-Judge pairwise comparison (MT-Bench style)"
  echo "  Criteria: Utility Preservation, Context Sensitivity, Semantic Coherence, Helpfulness"
  echo "  Bias mitigation: response presentation order randomised per prompt"
  echo "  Prompt source: LLM-generated (not fixtures)"
  echo "  Log: $SMOKE_CONSOLIDATED_LOG"
  echo ""

  # --- Phase 0: Generate prompts via LLM ---
  generate_prompts "$NUM_PROMPTS"

  local actual_count="${#PROMPTS[@]}"
  if [[ "$actual_count" -eq 0 ]]; then
    echo "  ✗  No prompts available. Aborting."
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
  )
  log_to_file "  Data dir: $dir_judge"
  echo ""

  # --- Phase 1: Collect responses ---
  CURRENT_SECTION="02_collect_responses"
  local -a responses_a=()
  local -a responses_b=()

  echo "=== Phase 1: Collecting responses (${actual_count} prompts x 2 variants) ==="

  for (( i=0; i<actual_count; i++ )); do
    local prompt="${PROMPTS[$i]}"
    log_plain_to_file "  [$((i+1))/$actual_count] ${prompt:0:70}..."

    local resp_a
    resp_a="$(run_prompt "$dir_a" "$prompt")"
    responses_a+=("$resp_a")
    if [[ -n "$resp_a" ]] && [[ "$resp_a" != "null" ]]; then
      echo "    A: ✓ ${#resp_a} chars"
      record_pass
    else
      echo "    A: ✗ empty"
      record_fail "response_a_empty_prompt_$((i+1))"
    fi

    local resp_b
    resp_b="$(run_prompt "$dir_b" "$prompt")"
    responses_b+=("$resp_b")
    if [[ -n "$resp_b" ]] && [[ "$resp_b" != "null" ]]; then
      echo "    B: ✓ ${#resp_b} chars"
      record_pass
    else
      echo "    B: ✗ empty"
      record_fail "response_b_empty_prompt_$((i+1))"
    fi
  done

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
    jj="$(judge_response "$dir_judge" "${PROMPTS[$i]}" "${responses_a[$i]}" "${responses_b[$i]}")"
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
  echo "  Variant A (no enrichment):   avg ${a_avg}/40   wins: ${a_wins}"
  echo "  Variant B (enriched):        avg ${b_avg}/40   wins: ${b_wins}"
  echo "  Ties:                                          ${ties}"
  echo "  Position swaps used:                           ${swaps_used}/${actual_count}"
  echo ""

  if [[ "$b_wins" -gt "$a_wins" ]]; then
    echo "  VERDICT: Semantic enrichment (B) produced better responses."
    echo "  B won ${b_wins}/${actual_count} comparisons (avg ${b_avg}/40 vs A ${a_avg}/40)."
  elif [[ "$a_wins" -gt "$b_wins" ]]; then
    echo "  VERDICT: Basic redaction (A) produced better responses (unexpected)."
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
  printf "  %-25s  %-12s  %-12s  %+d\n" "Context Sensitivity"  "${ac_t}/${mx}" "${bc_t}/${mx}" "$((bc_t - ac_t))"
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

  # Dump full judge JSON to consolidated log for post-mortem
  {
    echo ""
    echo "=== Full Judge Results (JSON per prompt) ==="
    for (( i=0; i<actual_count; i++ )); do
      echo "--- Prompt $((i+1)): ${PROMPTS[$i]:0:80}... ---"
      echo "Response A (${#responses_a[$i]} chars): ${responses_a[$i]:0:300}..."
      echo "Response B (${#responses_b[$i]} chars): ${responses_b[$i]:0:300}..."
      echo "Judge: ${judge_results[$i]}"
      echo ""
    done
  } >> "$SMOKE_CONSOLIDATED_LOG"

  # Aggregate counts from file (matching smoke_test.sh pattern)
  local final_pass final_fail
  final_pass="$(grep -c '^P$' "$SMOKE_COUNTS_FILE" 2>/dev/null || echo 0)"
  final_fail="$(grep -c '^F$' "$SMOKE_COUNTS_FILE" 2>/dev/null || echo 0)"

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
