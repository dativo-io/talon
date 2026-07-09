# Plan Review — E2E test case

Plan review is an **optional layer** for native `talon run` agents; this document is its test inventory.

Structured end-to-end test for all **user-facing** Plan Review workflows. Pair with [How to test and operate Plan Review](plan-review-operators.md) for command reference.

**Scope:** Pre-execution plan gate (`human_oversight` / `compliance.plan_review`).  
**Out of scope:** Per-tool approval mid-run (`/v1/tool-approvals`); webhook `require_approval: true` (returns `pending_approval` without a plan record).

---

## User-facing features and workflows affected

| # | Area | User surface | PR behavior |
|---|------|--------------|-------------|
| F1 | Policy | `agent.talon.yaml` → `compliance.human_oversight` | `always` / `on-demand` / `none` controls whether gate can fire |
| F2 | Policy | `compliance.plan_review` thresholds | Selective triggers: registry tools, cost, tier, volume (intent path) |
| F3 | Trigger | `talon run "..."` | Creates `plan_<id>`, no LLM until approved + dispatched |
| F4 | Trigger | `talon run --dry-run` | Policy check only; **skips** plan gate (no plan created) |
| F5 | Trigger | `POST /v1/agents/run` | HTTP 202 + `plan_pending` + `session_id` when gated |
| F6 | Trigger | `POST /v1/chat/completions` | HTTP 202 OpenAI-style `plan_pending` error when gated |
| F7 | Gate rules | `on-demand` + plain text | Run proceeds without plan (no PII, low cost, empty tool registry) |
| F8 | Gate rules | `on-demand` + PII input | Tier ≥ 2 → plan created |
| F9 | Gate rules | `human_oversight: always` | Every run gated regardless of tier/cost/tools |
| F10 | Intent preview | `talon intent classify` / `talon intent classes` | Shows tool-level review posture; **does not** gate `talon run` |
| F11 | List | `talon plan pending --tenant <id>` | Lists pending plans for tenant |
| F12 | List | `GET /v1/plans/pending` | Same; tenant or admin key |
| F13 | Detail | `GET /v1/plans/{id}` | Plan JSON (model, tier, cost estimate, prompt) |
| F14 | Approve | `talon plan approve` | Status → approved; `plan_review` evidence |
| F15 | Approve | `POST /v1/plans/{id}/approve` | Admin key only; optional approver bearer key |
| F16 | Reject | `talon plan reject` / `POST .../reject` | Status → rejected; reason in evidence; never executes |
| F17 | Modify | `POST /v1/plans/{id}/modify` | Approve-with-annotations; `plan_modified` evidence |
| F18 | Dispatch CLI | `talon plan execute` | Runs approved plan when serve not running |
| F19 | Dispatch serve | Auto-dispatcher (~2s) | Picks approved undispatched plans; `invocation_type=plan_dispatch` |
| F20 | Dashboard | `/dashboard` → Plans Awaiting Review | Approve/reject buttons; pending count cards |
| F21 | Dashboard | Review history tab | `GET /v1/dashboard/review-history` |
| F22 | Metrics | `/api/v1/metrics` summary | `pending_plans`, `approved_plans`, `dispatched_plans`, `plan_dispatch_errors` |
| F23 | FinOps | Dashboard tenant table | Per-tenant `pending_plans` column |
| F24 | Auth | Tenant key | Can trigger runs and **read** plans; **cannot** approve |
| F25 | Auth | Admin key | Approve/reject/modify; dashboard; evidence read on minimal serve |
| F26 | Evidence | `plan_review` invocation | Records approve/reject/modify decision |
| F27 | Evidence | `plan_dispatch` + final run | Dispatch reuses `session_id` from gated trigger |
| F28 | Approvers | `talon approver add/list/delete` | Named reviewer keys for API approve |
| F29 | Compliance export | `talon compliance annex-iv` | Includes plan-review human-oversight event counts |
| F30 | Status | `GET /v1/status` | `plan_review` component ok/disabled |

---

## Test environment

| Variable | Required |
|----------|----------|
| `TALON_SECRETS_KEY` | Yes |
| `OPENAI_API_KEY` or vault secret | Yes (live LLM steps) |
| `TALON_ADMIN_KEY` | Yes (API/dashboard approve, evidence read) |
| `jq` | Recommended |
| `curl` | For API phases |
| `sed` | YAML edits without `yq` |

```bash
export WORKDIR=~/talon_pr_e2e_$(date +%Y%m%d)
mkdir -p "$WORKDIR" && cd "$WORKDIR"
export TALON_SECRETS_KEY="${TALON_SECRETS_KEY:-$(openssl rand -hex 32)}"
export TALON_ADMIN_KEY="${TALON_ADMIN_KEY:-test-admin-key-change-me}"

talon init --scaffold --name my-agent
[[ -n "${OPENAI_API_KEY:-}" ]] && talon secrets set openai-api-key "$OPENAI_API_KEY"
```

Record outputs in a log:

```bash
export E2E_LOG="$WORKDIR/e2e-results.log"
exec > >(tee -a "$E2E_LOG") 2>&1
```

---

## E2E procedure

Run phases in order. Each testcase has **steps**, **expected result**, and **pass criterion**.

### Phase 0 — Baseline policy

```bash
grep -A8 '^compliance:' agent.talon.yaml
```

Ensure `plan_review` block exists. For this runbook, start with:

```bash
sed -i 's/human_oversight:.*/human_oversight: "on-demand"/' agent.talon.yaml
```

---

### TC-PR-001 — On-demand: low-risk run passes without gate

| Field | Value |
|-------|-------|
| Features | F1, F3, F7 |
| Config | `human_oversight: on-demand` |

```bash
talon run "Summarize EU AI Act milestones for compliance teams"
```

**Pass:** Output includes LLM body and `Evidence stored`. **No** line `Plan pending human review`.

---

### TC-PR-002 — On-demand: PII input gates (tier 2)

| Field | Value |
|-------|-------|
| Features | F2, F3, F8 |
| Config | `require_for_tier: tier_2` in YAML |

```bash
talon run "Customer: jan.kowalski@example.com IBAN DE89370400440532013000"
export PLAN_PII="$(talon plan pending --tenant default | awk '/my-agent/ {print $1; exit}')"
echo "PLAN_PII=$PLAN_PII"
```

**Pass:** `Plan pending human review: plan_<id>`; no LLM body. `PLAN_PII` non-empty.

---

### TC-PR-003 — Always: every run gates

| Field | Value |
|-------|-------|
| Features | F1, F9 |

```bash
sed -i 's/human_oversight:.*/human_oversight: "always"/' agent.talon.yaml
talon run "test"
export PLAN_ALWAYS="$(talon plan pending --tenant default | awk '/my-agent/ {print $1; exit}')"
```

**Pass:** `plan_pending` only; `PLAN_ALWAYS` non-empty.

---

### TC-PR-004 — Intent classify (informational; does not gate runs)

| Field | Value |
|-------|-------|
| Features | F10 |

```bash
talon intent classify delete_records '{"count": 10000}'
talon intent classes
```

**Pass:** First command shows `Plan review: true`, `Bulk detected: true`. Second lists operation classes.

---

### TC-PR-005 — Dry-run skips plan gate

| Field | Value |
|-------|-------|
| Features | F4 |

```bash
talon run --dry-run "test dry run with always oversight"
```

**Pass:** Policy check output only; **no** `Plan pending human review` (dry-run returns before gate).

---

### TC-PR-006 — CLI approve + execute (no serve)

| Field | Value |
|-------|-------|
| Features | F11, F14, F18, F26, F27 |

Use `PLAN_ALWAYS` from TC-PR-003 (or any pending `my-agent` plan):

```bash
talon plan pending --tenant default
talon plan approve "$PLAN_ALWAYS" --tenant default --reviewed-by e2e-tester
talon plan pending --tenant default | grep -q "$PLAN_ALWAYS" && echo FAIL_still_pending || echo OK_not_pending
talon plan execute "$PLAN_ALWAYS" --tenant default
```

**Pass:** Approve succeeds; plan absent from pending; execute prints LLM output + `Evidence stored`.

---

### TC-PR-007 — Reject path

| Field | Value |
|-------|-------|
| Features | F16, F26 |

```bash
talon run "another gated test"
export PLAN_REJECT="$(talon plan pending --tenant default | awk '/my-agent/ {print $1; exit}')"
talon plan reject "$PLAN_REJECT" --tenant default --reviewed-by e2e-tester --reason "E2E reject test"
talon plan execute "$PLAN_REJECT" --tenant default ; echo "exit=$?"
```

**Pass:** Reject succeeds; `plan execute` fails (plan not approved). Exit non-zero on execute.

---

### TC-PR-008 — Serve: API trigger + admin approve + auto-dispatch

| Field | Value |
|-------|-------|
| Features | F5, F15, F19, F24, F25, F27 |

Terminal 1:

```bash
export TALON_ADMIN_KEY
talon serve --port 8080
```

Terminal 2:

```bash
BASE=http://127.0.0.1:8080
RUN_JSON="$(curl -s -X POST "$BASE/v1/agents/run" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"default","agent_name":"my-agent","prompt":"E2E serve auto-dispatch test"}')"
echo "$RUN_JSON"
PLAN_SERVE="$(echo "$RUN_JSON" | jq -r '.plan_pending // empty')"
SESSION_SERVE="$(echo "$RUN_JSON" | jq -r '.session_id // empty')"

# Tenant cannot approve (use dummy bearer if no tenant key configured — expect 401)
curl -s -o /dev/null -w "tenant_approve_http=%{http_code}\n" \
  -X POST "$BASE/v1/plans/$PLAN_SERVE/approve" \
  -H "Authorization: Bearer not-a-real-tenant-key" \
  -H "Content-Type: application/json" \
  -d '{"reviewed_by":"attacker"}'

curl -s -X POST "$BASE/v1/plans/$PLAN_SERVE/approve" \
  -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reviewed_by":"e2e-tester"}' | jq .

sleep 4
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" \
  "$BASE/v1/evidence?limit=10&invocation_type=plan_dispatch" | jq '.entries[] | {id, session_id, invocation_type}'
```

**Pass:** `plan_pending` and `session_id` in run JSON; tenant approve HTTP 401 or 403; admin approve `status=approved`; within 4s a `plan_dispatch` evidence row with matching `session_id`.

Stop serve after phase (Ctrl+C).

---

### TC-PR-009 — HTTP read paths

| Field | Value |
|-------|-------|
| Features | F12, F13, F30 |

With serve running (or from TC-PR-008 before stop):

```bash
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://127.0.0.1:8080/v1/plans/pending | jq '.plans | length'
curl -s -H "X-Talon-Admin-Key: $TALON_ADMIN_KEY" http://127.0.0.1:8080/v1/status | jq '.components.plan_review // .plan_review // .'
```

**Pass:** Pending list returns JSON; status shows plan_review component not `disabled`.

---

### TC-PR-010 — Dashboard metrics (manual)

| Field | Value |
|-------|-------|
| Features | F20, F21, F22, F23 |

1. Start serve; trigger one gated run (leave pending).
2. Open `http://127.0.0.1:8080/dashboard?talon_admin_key=$TALON_ADMIN_KEY`
3. Verify **Pending plans** card > 0.
4. Open **Plans Awaiting Review** → approve one plan.
5. Confirm pending count drops; check **Review history** tab.

**Pass:** UI matches CLI pending count; approve removes row; history shows decision.

---

### TC-PR-011 — PII plan execute (optional; infra dependent)

| Field | Value |
|-------|-------|
| Features | F8, F18 |

Only if `PLAN_PII` from TC-PR-002 still pending:

```bash
talon plan approve "$PLAN_PII" --tenant default --reviewed-by e2e-tester
talon plan execute "$PLAN_PII" --tenant default
```

**Pass:** Execute succeeds **or** fails with clear Bedrock/provider error (tier_2 routing). Plan review approve/dispatch path still exercised.

---

### TC-PR-012 — Cleanup

```bash
talon plan pending --tenant default
# Reject any remaining test plans:
# talon plan reject <id> --tenant default --reviewed-by e2e-tester --reason "E2E cleanup"

sed -i 's/human_oversight:.*/human_oversight: "on-demand"/' agent.talon.yaml
```

---

## Master pass/fail checklist

| TC | ID | Pass |
|----|-----|------|
| Low risk no gate | TC-PR-001 | ☐ |
| PII gates | TC-PR-002 | ☐ |
| Always gates | TC-PR-003 | ☐ |
| Intent preview | TC-PR-004 | ☐ |
| Dry-run skips gate | TC-PR-005 | ☐ |
| CLI approve + execute | TC-PR-006 | ☐ |
| Reject blocks execute | TC-PR-007 | ☐ |
| Serve auto-dispatch | TC-PR-008 | ☐ |
| API read + status | TC-PR-009 | ☐ |
| Dashboard (manual) | TC-PR-010 | ☐ |
| PII execute (optional) | TC-PR-011 | ☐ |
| Cleanup | TC-PR-012 | ☐ |

**E2E complete when:** TC-PR-001 through TC-PR-010 pass (TC-PR-011 optional).

---

## Automated smoke parity

CI covers a subset in [tests/smoke_sections/24_plan_dispatch.sh](../../tests/smoke_sections/24_plan_dispatch.sh):

- CLI: run → pending → approve → execute
- Serve: `POST /v1/agents/run` → admin approve → auto-dispatch → `plan_dispatch` evidence + `session_id`

---

## Related

- [Plan Review operator guide](plan-review-operators.md)
- [Authentication and key scopes](../reference/authentication-and-key-scopes.md)
- [Agent planning](../AGENT_PLANNING.md)
