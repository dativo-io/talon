#!/usr/bin/env bash
# Render a deterministic, evidence-backed Talon hero from hero-state.json.
# Pure presentation: no provider calls, no policy evaluation, no live Talon state.
set -euo pipefail

STATE="${1:-}"
[[ -n "$STATE" ]] || { echo "usage: $0 <hero-state.json>" >&2; exit 2; }
[[ -f "$STATE" ]] || { echo "hero state not found: $STATE" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

# HERO_SPEED=0 makes CI/preview instantaneous. HERO_SPEED=1 is the default pacing.
SPEED="${HERO_SPEED:-1}"
REVEAL="${HERO_REVEAL_DELAY:-0.22}"

# Fail before drawing anything unless the complete, verified state is present.
SCHEMA="$(cat <<'JQ'
  ((.org | type) == "string" and (.org | length) > 0) and
  ((.mode | type) == "string" and (.mode | length) > 0) and
  ((.fleet_before | type) == "array" and (.fleet_before | length) == 3) and
  (all(.fleet_before[]; ((.name | type) == "string") and
      ((.health | type) == "string") and ((.spend_day | type) == "number"))) and
  ((.support.pii | type) == "array") and
  ((.support.pii | index("email")) != null) and
  ((.support.pii | index("iban")) != null) and
  (.support.tier == 2) and
  ((.support.failed_provider | type) == "string" and
      (.support.failed_provider | length) > 0) and
  ((.support.skipped_provider | type) == "string" and
      (.support.skipped_provider | length) > 0) and
  ((.support.skip_reason | type) == "string" and
      (.support.skip_reason | length) > 0) and
  ((.support.selected_provider | type) == "string" and
      (.support.selected_provider | length) > 0) and
  (.support.outcome == "completed") and
  ((.support.cost | type) == "number") and
  ((.tool_boundary.requested | type) == "array" and
      (.tool_boundary.requested | length) >= 3) and
  ((.tool_boundary.boundary | type) == "string" and
      (.tool_boundary.boundary | length) > 0) and
  (.tool_boundary.provider_calls == 0) and (.tool_boundary.cost == 0) and
  ((.cost.spent | type) == "number") and
  ((.cost.estimate | type) == "number") and
  ((.cost.limit | type) == "number") and
  ((.cost.spent + .cost.estimate) > .cost.limit) and
  ((.policy_edit.event | type) == "string" and
      (.policy_edit.event | length) > 0) and
  ((.policy_edit.old_cap | type) == "number") and
  ((.policy_edit.new_cap | type) == "number") and
  ((.policy_edit.spend_day | type) == "number") and
  (.policy_edit.health == "blocked") and
  ((.fleet_after | type) == "array" and (.fleet_after | length) == 3) and
  (any(.fleet_after[]; .name == "document-summary" and .health == "blocked")) and
  ((.evidence.total | type) == "number" and .evidence.total > 0) and
  (.evidence.valid == .evidence.total) and (.evidence.invalid == 0) and
  (.evidence.failover == "valid_fallback") and
  ((.session.id | type) == "string" and (.session.id | length) > 0) and
  (.session.outcome == "completed")
JQ
)"
jq -e "$SCHEMA" "$STATE" >/dev/null || {
  echo "hero-state.json is incomplete or internally inconsistent" >&2
  exit 1
}

ORG="$(jq -r '.org|ascii_upcase' "$STATE")"
MODE="$(jq -r '.mode|ascii_upcase' "$STATE")"

# ANSI palette: cyan=product/info, green=success, amber=policy/budget,
# red=real technical failure only, grey=context.
R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'
CYN=$'\033[36m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RED=$'\033[31m'
CLEAR=$'\033[2J\033[H'

sleep_scaled() {
  local seconds="$1"
  [[ "$SPEED" == 0 || "$SPEED" == "0" ]] && return 0
  sleep "$(awk -v s="$seconds" -v m="$SPEED" 'BEGIN{printf "%.3f",s*m}')"
}
reveal() { printf '%b\n' "$1"; sleep_scaled "$REVEAL"; }
frame() { printf '%s' "$CLEAR"; }
header() {
  printf '%s%sTALON / %-12s%s%38s%s ●%s\n' "$B" "$CYN" "$ORG" "$R" "" "$MODE" "$R"
  printf '%s3 AI USE CASES · 1 ORG POLICY · 1 OPERATING VIEW%s\n' "$DIM" "$R"
  printf '%s\n' '────────────────────────────────────────────────────────────────────────────'
}
title() { printf '%s%-62s%s %5s\n\n' "$B" "$1" "$R" "$2 / 8"; }
money() { awk -v v="$1" 'BEGIN{printf "%.4f",v}'; }
health_mark() {
  case "$1" in
    healthy) printf '%s● healthy%s' "$GRN" "$R" ;;
    blocked) printf '%s■ blocked%s' "$YEL" "$R" ;;
    *)       printf '%s%s%s' "$DIM" "$1" "$R" ;;
  esac
}
fleet_rows() {
  local file="$1" name health spend
  while IFS=$'\t' read -r name health spend; do
    printf '  %-22s ' "$name"
    health_mark "$health"
    printf '%*s$%s\n' "$((18-${#health}))" "" "$(money "$spend")"
  done < <(jq -r ".${file}[]|[.name,.health,(.spend_day|tostring)]|@tsv" "$STATE")
}

# 1 — Category
frame; header; title "ONE OPERATING LAYER" 1
reveal ""
reveal "                 ${B}3 PRODUCTION AI USE CASES${R}"
reveal ""
reveal "      ${CYN}customer-support${R}    ${CYN}coding-assistant${R}"
reveal "                 ${CYN}document-summary${R}"
reveal ""
reveal "              ${DIM}1 policy · 1 operating view${R}"
sleep_scaled 2.8

# 2 — Fleet
frame; header; title "THE FLEET" 2
reveal "${DIM}\$ talon agents${R}"
reveal ""
reveal "  ${B}USE CASE               HEALTH              SPEND${R}"
fleet_rows fleet_before
sleep_scaled 3.2

# 3 — Customer-support incident
frame; header; title "CUSTOMER-SUPPORT INCIDENT" 3
reveal "  ${DIM}Refund Anna Kowalska · email + IBAN in the request${R}"
reveal ""
reveal "  ${GRN}✓ EMAIL + IBAN REDACTED${R}"
reveal "    ${DIM}classification remains confidential (tier $(jq -r '.support.tier' "$STATE"))${R}"
reveal ""
reveal "  ${RED}× $(jq -r '.support.failed_provider' "$STATE")${R}       connection error"
reveal "  ${YEL}⊘ $(jq -r '.support.skipped_provider' "$STATE")${R}      blocked by use-case policy"
reveal "  ${GRN}✓ $(jq -r '.support.selected_provider' "$STATE")${R}             selected"
reveal ""
reveal "  ${GRN}${B}RESULT          COMPLETED${R}"
sleep_scaled 4.0

# 4 — Organization tool boundary
frame; header; title "ORGANIZATION TOOL BOUNDARY" 4
reveal "  ${YEL}${B}ORGANIZATION BOUNDARY     $(jq -r '.tool_boundary.boundary' "$STATE")${R}"
reveal ""
reveal "  Requested capabilities"
while IFS= read -r tool; do
  if [[ "$tool" == admin_* ]]; then
    reveal "    ${YEL}⊘ ${tool}${R}"
  else
    reveal "    ${DIM}• ${tool}${R}"
  fi
done < <(jq -r '.tool_boundary.requested[]' "$STATE")
reveal ""
reveal "  ${GRN}${B}✓ BLOCKED BEFORE MODEL${R}"
reveal "    provider calls  0     cost  \$0.0000"
sleep_scaled 2.5

# 5 — Cost control
spent="$(jq -r '.cost.spent' "$STATE")"
estimate="$(jq -r '.cost.estimate' "$STATE")"
limit="$(jq -r '.cost.limit' "$STATE")"
projected="$(awk -v a="$spent" -v b="$estimate" 'BEGIN{printf "%.4f",a+b}')"
frame; header; title "COST CONTROL BEFORE SPEND" 5
reveal "  SESSION SPEND          \$$(money "$spent")"
reveal "  NEXT ESTIMATE          \$$(money "$estimate")"
reveal "  PROJECTED TOTAL        ${YEL}\$${projected}${R}"
reveal "  SESSION LIMIT          \$$(money "$limit")"
reveal "                         ─────────"
reveal "  ${DIM}[████████░░░░░░] + next call → over limit${R}"
reveal ""
reveal "  ${GRN}${B}✓ NEXT CALL PREVENTED${R}"
reveal "    Anthropic not called     cost  \$0.0000"
sleep_scaled 3.0

# 6 — Live operational control
old_cap="$(jq -r '.policy_edit.old_cap' "$STATE")"
new_cap="$(jq -r '.policy_edit.new_cap' "$STATE")"
day_spend="$(jq -r '.policy_edit.spend_day' "$STATE")"
frame; header; title "LIVE OPERATIONAL CONTROL" 6
reveal "  ${YEL}${B}FINANCE SETS AN EMERGENCY DAILY CEILING${R}"
reveal ""
reveal "  Daily budget       \$$(money "$old_cap") → ${YEL}\$$(money "$new_cap")${R}"
reveal "  Policy reload      ${GRN}✓ activated safely${R}"
reveal "  Current spend      \$$(money "$day_spend")"
reveal ""
reveal "  ${B}USE CASE               HEALTH              SPEND${R}"
fleet_rows fleet_after
reveal ""
reveal "  ${YEL}${B}document-summary can no longer accept new work${R}"
sleep_scaled 3.0

# 7 — Session explanation
session_id="$(jq -r '.session.id' "$STATE")"
support_cost="$(jq -r '.support.cost' "$STATE")"
if awk -v c="$support_cost" 'BEGIN{exit !(c<0.0001)}'; then
  cost_text="< \$0.0001"
else
  cost_text="\$$(money "$support_cost")"
fi
frame; header; title "SESSION EXPLANATION" 7
reveal "  SESSION        ${CYN}${session_id}${R}"
reveal "  OUTCOME        ${GRN}completed${R}"
reveal "  PII            email + IBAN redacted"
reveal "  PRIMARY        ${RED}$(jq -r '.support.failed_provider' "$STATE") failed${R}"
reveal "  POLICY SKIP    ${YEL}$(jq -r '.support.skipped_provider' "$STATE")${R}"
reveal "  SELECTED       ${GRN}$(jq -r '.support.selected_provider' "$STATE")${R}"
reveal "  COST           ${cost_text}"
reveal ""
reveal "  ${DIM}One incident · one outcome · every decision explained${R}"
sleep_scaled 2.5

# 8 — Verify and close
total="$(jq -r '.evidence.total' "$STATE")"
valid="$(jq -r '.evidence.valid' "$STATE")"
invalid="$(jq -r '.evidence.invalid' "$STATE")"
frame; header; title "SIGNED EVIDENCE" 8
reveal ""
reveal "  ${B}${total} records${R}          ${GRN}${valid} valid${R}          ${GRN}${invalid} invalid${R}"
reveal "  failover chain     ${GRN}$(jq -r '.evidence.failover' "$STATE")${R}"
reveal ""
reveal "             ${GRN}${B}✓ VERIFIED OFFLINE${R}"
sleep_scaled 1.0
reveal ""
reveal "  ${CYN}${B}TALON${R}"
reveal "  ${B}Operate every AI use case through one shared control plane${R}"
reveal "  ${DIM}cost · reliability · policy · session understanding${R}"
sleep_scaled 3.2
printf '\nHERO_COMPLETE\n'
