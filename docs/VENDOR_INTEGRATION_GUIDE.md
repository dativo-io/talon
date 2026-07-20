# Dativo Talon — Vendor Integration Guide

**Governing Third-Party AI Vendors**

---

## Overview

This guide shows how to add Talon compliance to **existing AI automation**, whether custom-built or third-party SaaS vendors. Talon doesn't replace your existing tools — it adds governance, audit trails, and compliance controls.

**Three integration patterns (all shipped):**
1. **MCP Proxy** (recommended) — Talon sits between the vendor and your data (`talon serve --proxy-config`)
2. **LLM API Gateway** — the vendor/bot calls its LLM provider *through* Talon (`talon serve --gateway`)
3. **Shadow Mode** — the MCP proxy in non-blocking audit mode (`proxy.mode: shadow`)

---

## Why This Matters

### The Compliance Problem with Third-Party Vendors

You're using great AI tools like:
- Zendesk AI Agent
- Intercom Resolution Bot
- Drift AI Chatbot
- HubSpot AI Assistant
- Custom Slack bots
- OpenAI Assistants API

**But when audited (GDPR, NIS2, EU AI Act), you can't answer:**
- ✗ What customer data did the vendor access on January 15th?
- ✗ Was PII redacted before sending to LLMs?
- ✗ Where is data stored? (EU data residency requirement)
- ✗ Which high-risk decisions lacked human oversight?
- ✗ Can you export GDPR Article 30 processing records?

**Legal reality:**
- **You** are the data controller (GDPR Article 4)
- **Vendor** is the data processor (GDPR Article 28)
- **You're liable** even if vendor claims compliance
- "Vendor said they're compliant" is NOT a defense in AEPD audits

---

## Pattern 1: MCP Proxy (Recommended)

### Architecture

```
BEFORE (Black box):
Third-Party AI Agent → Directly accesses your Zendesk/CRM → No visibility

AFTER (Full audit trail):
                    ┌──────────────────────────────────┐
                    │  Talon (your infrastructure)     │
                    │  - Logs all access               │
                    │  - Redacts PII                   │
                    │  - Enforces policies             │
                    │  - Generates audit trail         │
                    └──────────────────────────────────┘
                                 ↓
Third-Party AI Agent → Talon MCP Server → Your Zendesk/CRM
                                 ↓
                    You have complete evidence trail
```

### Implementation (30 minutes)

#### Step 1: Install Talon
```bash
# On your infrastructure (VM, EC2, on-prem server) — check
# https://github.com/dativo-io/talon/releases/latest for the newest version
TALON_VERSION=1.9.1   # set to the latest release tag
wget https://github.com/dativo-io/talon/releases/download/v${TALON_VERSION}/talon_${TALON_VERSION}_linux_amd64.tar.gz
tar -xzf talon_${TALON_VERSION}_linux_amd64.tar.gz
sudo mv talon /usr/local/bin/talon
```

macOS archives (`talon_<version>_darwin_arm64.tar.gz` / `_darwin_amd64.tar.gz`)
ship from v1.9.2 onward; earlier releases are linux_amd64 only — on macOS use
`go install github.com/dativo-io/talon/cmd/talon@<tag>` (prefix with
`CC=/usr/bin/clang` if the linker errors) or `make install` from a clone.

#### Step 2: Create the Proxy Policy

The schema is `ProxyPolicyConfig` (`internal/policy/proxy.go`); a complete
working file ships in the repo as
`examples/vendor-proxy/zendesk-proxy.talon.yaml`. Unknown keys fail the load
(the parser is strict), so what you write is what is enforced.

```yaml
# /opt/talon/agents/zendesk-vendor-proxy.talon.yaml
agent:
  name: "zendesk-vendor-proxy"
  description: "Governance layer for Zendesk AI Agent vendor"
  version: "1.0.0"
  type: "mcp_proxy"

proxy:
  mode: "intercept"  # intercept | passthrough | shadow
  upstream:
    vendor: "zendesk-ai-agent"
    url: "https://zendesk-ai.example.com/mcp"
    region: "EU"     # jurisdiction, recorded in evidence; omitted = "unknown"

  allowed_tools:
    - name: zendesk_ticket_search
    - name: zendesk_ticket_read
    - name: zendesk_ticket_update

  forbidden_tools:
    - zendesk_user_delete  # Block destructive operations
    - zendesk_export_all   # Block mass data export

  rate_limits:
    requests_per_minute: 100

pii_handling:
  redaction_rules:
    - field: "requester.email"
      method: "hash"
    - field: "requester.phone"
      method: "mask_middle"  # +34 6XX XXX 789
    - field: "custom_fields.credit_card"
      method: "redact_full"  # Complete removal

compliance:
  frameworks: ["gdpr", "nis2"]
  data_residency: "eu-only"   # requires upstream.region in the EU
```

Every proxied call produces a signed evidence record unconditionally — there
is no capture toggle to get wrong.

#### Step 3: Start Talon with the MCP Proxy
```bash
talon serve --port 8080 --proxy-config /opt/talon/agents/zendesk-vendor-proxy.talon.yaml

# The startup log confirms the proxy is mounted:
#   INF talon_serve_started addr=:8080 agent=zendesk-vendor-proxy ... mcp_proxy=true
```

For production, set `TALON_ADMIN_KEY` (and agent keys) — without any keys
configured the endpoint is unrestricted and `talon serve` warns loudly.

#### Step 4: Point Vendor to Talon

The proxy endpoint is `POST /mcp/proxy` (JSON-RPC 2.0):

```
In Zendesk AI Agent settings:
┌──────────────────────────────────────────────────────────┐
│ Data Sources Configuration                               │
│                                                          │
│ ☐ Direct Zendesk API access                             │
│ ☑ Custom MCP Server                                     │
│   MCP Endpoint: https://talon.your-company.local/mcp/proxy │
│   Auth Token: <Talon agent or admin key>                │
└──────────────────────────────────────────────────────────┘
```

Terminate TLS at your reverse proxy — `talon serve` itself speaks plain HTTP.

### What Happens Now

```
Vendor wants to search tickets
    ↓
POST /mcp/proxy  {"method": "tools/call", "params": {"name": "zendesk_ticket_search", ...}}
    ↓
Talon intercepts:
    ├─ Policy check: Is "zendesk_ticket_search" in allowed_tools? ✓ YES
    ├─ Rate limit check (requests_per_minute)
    ├─ PII scan on arguments; redaction per redaction_rules (fail-closed
    │  if the scanner is unavailable — unclassifiable data is never forwarded)
    ├─ Forwards to the upstream endpoint (tool name mapped via upstream_name)
    ├─ PII scan + redaction on the upstream response
    ├─ Generates a signed evidence record (who, what, when, findings, data flow)
    └─ Returns the redacted result to the vendor
    ↓
Vendor receives data (works normally, unaware of governance layer)
    ↓
Your compliance officer has a complete audit trail

Note: the proxy speaks the MCP lifecycle (initialize is answered locally —
never forwarded; notifications/initialized accepted) and governs tools/list
and tools/call. Any OTHER method (resources/read, prompts/get, ...) is
rejected fail-closed with error.data.talon_code TALON_METHOD_NOT_ALLOWED
and a signed evidence record — never forwarded ungoverned. All Talon-shaped
denials carry stable machine-readable codes in error.data.talon_code (see
ARCHITECTURE_MCP_PROXY.md for the full table).

Also: tools/list responses are filtered — the vendor only ever discovers
tools you listed in allowed_tools.
```

**Benefits:**
- ✅ Vendor functionality unchanged (transparent proxy)
- ✅ Full visibility into vendor data access
- ✅ PII never reaches vendor's systems unredacted
- ✅ Can block forbidden operations (user deletes, mass exports)
- ✅ Generate GDPR Article 30 records on demand
- ✅ Prove NIS2 compliance to auditors

---

## Pattern 2: LLM API Gateway

### When to Use
- The vendor tool or bot calls an LLM API (OpenAI, Anthropic, Ollama) and
  lets you configure the base URL — Slack bots, desktop apps, scripts,
  self-built automations
- You want per-agent budgets, PII scanning, and signed evidence on every
  LLM request without touching the tool's logic

### Implementation (15 minutes)

Point the tool at Talon instead of the provider. Talon authenticates the
caller with a Talon **agent key**, enforces the agent's model/cost/PII
policy, injects the vault-stored provider key upstream, and signs evidence:

```bash
talon serve --port 8080 --gateway

# The tool calls Talon's provider-native route:
curl -X POST http://localhost:8080/v1/proxy/openai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AGENT_KEY" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Help me reset my password"}]}'
```

The real provider key never reaches the vendor tool — it lives in Talon's
encrypted vault only. See the dedicated guides:
[Slack bot integration](guides/slack-bot-integration.md),
[Desktop app governance](guides/desktop-app-governance.md),
[Governing coding agents](guides/governing-coding-agents.md).

**Benefits:**
- ✅ Every LLM request audited and attributed to an agent + tenant
- ✅ Budgets enforced per session / day / month
- ✅ PII scanning on prompts and responses per your policy
- ✅ Provider keys leave the laptops and live in the vault

### What About Webhooks?

Talon ships **webhook triggers**, not a webhook forwarding proxy: a
`triggers.webhooks` entry on an agent (`name`, `source`, `prompt_template`,
`require_approval`) dispatches a **governed agent run** when the webhook
fires — the payload becomes a policy-checked, audited Talon execution.

What Talon does **not** do today: sit between a SaaS webhook and a vendor
endpoint to log/redact/forward the payload transparently. If your vendor is
webhook-driven and you cannot reroute its LLM traffic (Pattern 2) or its
data access (Pattern 1), use Shadow Mode below for visibility, or front the
vendor with your own relay.

---

## Pattern 3: Shadow Mode (Audit Without Enforcement)

### When to Use
- First step before full interception — validate Talon policies against
  live vendor traffic with zero enforcement risk
- You can route the vendor's MCP traffic through Talon, but aren't ready
  to let policies block anything yet

### How It Works

Shadow mode is the same MCP proxy as Pattern 1 with one config change —
traffic still flows through Talon on the same wire path:

```yaml
proxy:
  mode: "shadow"
```

- Policy and PII violations are recorded as **would-have-denied** signed
  evidence, then forwarded — policy evaluation blocks nothing
- Explicitly `forbidden_tools` are audited and then **still blocked** —
  destructive operations are never forwarded outside passthrough mode
- A working minimal config ships as `examples/mcp-proxy-minimal/proxy.talon.yaml`

#### Run and Review
```bash
talon serve --port 8080 --proxy-config /opt/talon/agents/zendesk-vendor-proxy.talon.yaml

# After a few days of traffic:
talon audit list --agent zendesk-vendor-proxy --limit 50
talon audit export --format csv   # review would-have-denied decisions
```

When the evidence shows the policy is denying the right things, flip
`mode: "shadow"` to `mode: "intercept"` and restart.

**Benefits:**
- ✅ Zero enforcement risk while policies are tuned
- ✅ Full signed evidence trail from day one
- ✅ Destructive tools blocked even while observing
- ✅ One-line switch to enforcement

**Limitations:**
- ❌ Requires the vendor's MCP traffic to route through Talon (like Pattern 1)
- ❌ Policy violations are recorded, not prevented, until you flip to intercept
- ❌ If the vendor cannot be rerouted at all, Talon cannot see its traffic —
  there is no passive "poll the vendor's own audit logs" mode

---

## Pattern Comparison Table

| Feature | MCP Proxy (intercept) | LLM API Gateway | Shadow Mode |
|---------|-----------------------|-----------------|-------------|
| **Setup Time** | 30 min | 15 min | 30 min (same as MCP proxy) |
| **What It Governs** | Vendor's tool/data access (MCP) | Vendor's LLM API calls | Same wire as MCP proxy |
| **Vendor Changes Required** | MCP endpoint config | Base-URL + key config | MCP endpoint config |
| **Blocks Violations** | ✅ Yes | ✅ Yes (budget/policy denials) | Forbidden tools only |
| **PII Redaction** | ✅ Before vendor sees it | ✅ Per policy (scan/redact/block) | Recorded, not enforced |
| **Audit Trail** | ✅ Complete, signed | ✅ Complete, signed | ✅ Complete, signed |
| **Best For** | Vendors with MCP support | Bots/tools calling LLM APIs | Policy validation before enforcement |

---

## Common Integration Scenarios

### Scenario 1: Zendesk AI Agent
```yaml
vendor: "Zendesk AI Agent"
pattern: "MCP Proxy"
reason: "Zendesk supports custom MCP servers in enterprise plan"
setup_time: "30 minutes"
compliance_gain: "Full GDPR Article 30 records + PII redaction"
```

### Scenario 2: Intercom Resolution Bot
```yaml
vendor: "Intercom Resolution Bot"
pattern: "Shadow Mode -> MCP Proxy"
reason: "Route its data access through Talon; validate policies in shadow, then intercept"
setup_time: "30 minutes"
compliance_gain: "Signed audit trail + PII redaction on tool traffic"
```

### Scenario 3: Custom Slack Bot (Self-Built)
```yaml
vendor: "Internal Slack bot (Python script)"
pattern: "LLM API Gateway"
reason: "You control the code — point its OpenAI client at Talon's gateway"
setup_time: "15 minutes (base URL + key change)"
compliance_gain: "Full governance + policy enforcement + signed evidence"
code_change: |
  # Before
  client = OpenAI(api_key=REAL_OPENAI_KEY)

  # After — Talon agent key in, vault-stored provider key out
  client = OpenAI(api_key=TALON_AGENT_KEY,
                  base_url="http://localhost:8080/v1/proxy/openai/v1")
docs: guides/slack-bot-integration.md
```

### Scenario 4: HubSpot AI Assistant (No Reroute Possible)
```yaml
vendor: "HubSpot AI Assistant"
pattern: "None today — honest boundary"
reason: "No custom MCP endpoint, no configurable LLM base URL, no webhook reroute"
compliance_gain: "None until the vendor exposes a routing surface"
limitation: "If Talon cannot sit on the traffic path, it cannot see or govern it —
  there is no passive vendor-log monitoring mode"
next_step: "Escalate to HubSpot for MCP support (see Vendor Negotiation Guide)
  or choose a governable alternative"
```

---

## Vendor Negotiation Guide

### Conversation Template

**When vendor resists Talon integration:**

```
You: "We need to route your API access through our compliance proxy."

Vendor: "Why? Don't you trust us? We're already GDPR compliant."

You: "Spanish regulation requires independent audit trails. We're the 
      data controller, so we're liable even with your DPA in place."

Vendor: "But our system needs direct access to work properly."

You: "MCP is an industry standard. If you support it, integration is 
      seamless. If not, we'll need to evaluate alternatives."

Vendor: "That requires engineering work on our side..."

You: "We understand. However, GDPR Article 28 requires us to verify 
      processor compliance. Without independent audit trails, we can't 
      use your product. Can your team provide an ETA for MCP support?"
```

**Outcome:**
- **Vendor adds MCP support** → You get full transparency
- **Vendor refuses** → You find different vendor (market pressure works)
- **Vendor negotiates** → Maybe they provide better audit logs as alternative

### Market Pressure Strategy

If 10+ European companies demand MCP proxying:
1. Vendors will add support (competitive pressure)
2. MCP becomes standard in EU market
3. Talon becomes de facto compliance gateway

**This is already happening:**
- Anthropic supports MCP natively (Claude Desktop, Claude Code, API)
- OpenAI supports MCP (Agents SDK, ChatGPT connectors)
- Microsoft supports MCP (Copilot Studio, Windows AI Foundry)

**Talon's advantage:** First mover in compliance-grade MCP gateway.

---

## Verification & Testing

### Test Your Integration

The proxy speaks JSON-RPC 2.0 at `POST /mcp/proxy`.

#### 1. Verify Interception
```bash
# Send a test request through Talon
curl -X POST https://talon.your-company.local/mcp/proxy \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TALON_AGENT_KEY}" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "zendesk_ticket_search", "arguments": {"query": "test"}},
    "id": 1
  }'

# Then check the audit trail — the call appears as signed evidence:
talon audit list --agent zendesk-vendor-proxy --limit 5
```

#### 2. Verify PII Redaction
```bash
# Send arguments containing PII
curl -X POST https://talon.your-company.local/mcp/proxy \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TALON_AGENT_KEY}" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "zendesk_ticket_create",
      "arguments": {"subject": "Test", "requester_email": "test@example.com", "requester_phone": "+34612345678"}
    },
    "id": 2
  }'

# Inspect the record: PII findings and the data-flow section show what was
# detected and how it was redacted (evidence stores digests, never raw values)
talon audit show <evidence-id>
```

#### 3. Verify Policy Enforcement
```bash
# Try a forbidden operation
curl -X POST https://talon.your-company.local/mcp/proxy \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TALON_AGENT_KEY}" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"zendesk_user_delete","arguments":{"user_id":123}},"id":3}'

# Expected: a JSON-RPC error instead of a forwarded call —
#   {"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"tool not allowed by policy"}}
# and a proxy_tool_blocked evidence record:
talon audit list --agent zendesk-vendor-proxy --limit 1
```

---

## Migration Path

### Phase 1: Shadow Mode (Week 1)
- Route the vendor through Talon with `proxy.mode: shadow`
- Build a signed audit trail for 1 week
- Validate policies — would-have-denied decisions land in evidence, nothing
  policy-evaluated is blocked
- **Risk:** Low (one endpoint change at the vendor; no enforcement)
- **Goal:** Prove Talon works, tune policies

### Phase 2: Pilot Interception (Week 2)
- Flip a low-stakes vendor (or a staging instance) to `mode: intercept`
- Monitor for issues (latency, errors, false denials) in the audit trail
- **Risk:** Low (flip back to shadow is a one-line change)
- **Goal:** Verify production readiness

### Phase 3: Full Rollout (Week 3)
- Flip all proxied vendors to `mode: intercept`
- PII redaction and policy enforcement now active on every call
- **Risk:** Medium (vendor dependency)
- **Goal:** Full compliance coverage

### Phase 4: Human Oversight (Week 4)
- Add approval workflows for high-risk actions
- Train team on plan review dashboard
- Configure alert thresholds
- **Risk:** Low (improves control)
- **Goal:** EU AI Act Article 14 compliance

---

## Troubleshooting

### Issue: Vendor Rejects Talon's MCP Endpoint

**Symptom:** Vendor returns "Invalid MCP server" error

**Solutions:**
1. Check Talon MCP endpoint is publicly accessible
2. Verify SSL certificate (vendors may require valid HTTPS)
3. Check vendor's MCP implementation version (may need upgrade)
4. Contact vendor support with MCP spec URL: https://spec.modelcontextprotocol.io

### Issue: High Latency After Adding Talon

**Symptom:** API calls 2-3x slower through Talon

**Solutions:**
1. Inspect policy-evaluation spans: `talon serve --otel` (traces `policy.proxy.*`)
2. Keep redaction_rules pattern lists tight (each regex runs per call)
3. Deploy Talon closer to the vendor / upstream (reduce network hops)

### Issue: PII Still Reaching Vendor

**Symptom:** Audit shows unredacted PII in vendor logs

**Solutions:**
1. Verify redaction rules match actual field names
2. Check vendor uses nested fields: `requester.custom_fields.phone`
3. Enable debug logging: `talon serve --log-level debug`
4. Add catch-all regex patterns for PII detection

### Issue: Vendor Cannot Be Rerouted at All

**Symptom:** No MCP endpoint config, no LLM base-URL config, no way to put
Talon on the traffic path

**Honest answer:** Talon can only govern traffic that flows through it —
there is no passive mode that polls the vendor's own audit logs.

**Options:**
1. Check for an LLM base-URL setting (many tools have one buried in
   advanced/self-hosted options) → Pattern 2
2. Escalate to the vendor for MCP support (see Vendor Negotiation Guide)
3. Choose a governable alternative vendor

---

## Compliance Benefits Summary

### Before Talon
- ❌ No independent audit trail
- ❌ Vendor's "we're compliant" claims unverified
- ❌ Can't prove GDPR Article 30 compliance
- ❌ PII sent to vendors unredacted
- ❌ No human oversight for high-risk decisions
- ❌ Manual evidence gathering during audits (weeks)

### After Talon
- ✅ Independent audit trail (vendor-agnostic)
- ✅ Real-time verification of vendor compliance
- ✅ One-command GDPR Article 30 exports
- ✅ PII automatically redacted before vendor access
- ✅ Systematic human oversight (visual plan review)
- ✅ Audit-ready in minutes (not weeks)

---

## Cost-Benefit Analysis

### Scenario: Spanish Telecom (150 employees)

**Without Talon:**
- Vendor cost: €2,000/month (Zendesk AI Agent)
- Compliance audit prep: 40 hours/quarter × €100/hr = €4,000/quarter
- Risk of GDPR fine: €50,000 (if violation discovered)
- **Total annual risk: €16,000 + €50,000 exposure**

**With Talon:**
- Vendor cost: €2,000/month (unchanged)
- Talon cost: €0 (open source)
- Compliance audit prep: 2 hours/quarter × €100/hr = €200/quarter
- Risk of GDPR fine: ~€0 (full compliance)
- **Total annual cost: €800 + zero exposure**

**ROI: €15,200/year savings + eliminated fine risk**

---

## Next Steps

1. **Choose your pattern:**
   - Vendor with MCP support: **MCP Proxy**
   - Bot or tool calling an LLM API you can repoint: **LLM API Gateway**
   - Not ready to enforce: **Shadow Mode** first

2. **Start with pilot:**
   - Deploy the proxy in shadow mode for 1 week
   - Validate policies without impacting the vendor
   - Review audit trails with your compliance officer

3. **Gradual rollout:**
   - Flip a low-stakes vendor to `mode: intercept`
   - Monitor for issues (latency, errors, false denials)
   - Flip the rest after validation

4. **Prove compliance:**
   - Generate first GDPR Article 30 report
   - Show to compliance officer/auditors
   - Document time saved vs. manual process

5. **Expand usage:**
   - Add more vendors through Talon
   - Enable advanced features (memory, triggers)
   - Train team on plan review dashboard

---

## Support

- **Documentation:** https://github.com/dativo-io/talon#readme
- **GitHub Issues:** https://github.com/dativo-io/talon/issues
- **Community Slack:** https://dativo-community.slack.com
- **Enterprise Support:** enterprise@dativo.com

**Remember:** The goal isn't to replace your vendors — it's to govern them and generate your own evidence. Talon adds the governance and audit layer vendors can't provide; the compliance determination stays with you as the data controller.
