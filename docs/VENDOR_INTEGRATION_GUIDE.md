# Dativo Talon — Vendor Integration Guide

**Making Third-Party AI Vendors Compliant**

---

## Overview

This guide shows how to add Talon compliance to **existing AI automation**, whether custom-built or third-party SaaS vendors. Talon doesn't replace your existing tools — it adds governance, audit trails, and compliance controls.

**Three integration patterns:**
1. **MCP Proxy** (recommended) — Talon sits between vendor and your data
2. **Webhook Interception** — Talon logs/redacts webhook payloads
3. **Shadow Mode** — Read-only audit of vendor behavior

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
# On your infrastructure (VM, EC2, on-prem server)
wget https://github.com/dativo/talon/releases/download/v1.0.0/talon-linux-amd64
chmod +x talon-linux-amd64
sudo mv talon-linux-amd64 /usr/local/bin/talon
```

#### Step 2: Configure MCP Proxy for Zendesk
```bash
# Create MCP server config
mkdir -p /opt/talon/mcp-servers

cat > /opt/talon/mcp-servers/zendesk-proxy.json <<EOF
{
  "command": "talon",
  "args": ["mcp", "serve", "zendesk", "--mode", "proxy"],
  "env": {
    "ZENDESK_URL": "https://your-company.zendesk.com",
    "ZENDESK_API_KEY": "\${ZENDESK_KEY}"
  }
}
EOF
```

#### Step 3: Create Governance Policy
```yaml
# /opt/talon/agents/zendesk-vendor-proxy.talon.yaml
agent:
  name: "zendesk-vendor-proxy"
  description: "Governance layer for Zendesk AI Agent vendor"
  version: "1.0.0"
  type: "mcp_proxy"

proxy:
  mode: "intercept"  # Intercept all calls
  upstream:
    vendor: "zendesk-ai-agent"
    url: "https://zendesk-ai.example.com"
    auth: "bearer"  # Pass through vendor auth token

capabilities:
  allowed_tools:
    - zendesk_ticket_search
    - zendesk_ticket_read
    - zendesk_ticket_update
  
  forbidden_tools:
    - zendesk_user_delete  # Block destructive operations
    - zendesk_export_all   # Block mass data export

pii_handling:
  redaction_rules:
    - field: "requester.email"
      method: "hash"
    - field: "requester.phone"
      method: "mask_middle"  # +34 6XX XXX 789
    - field: "custom_fields.credit_card"
      method: "redact_full"  # Complete removal

compliance:
  frameworks: ["gdpr", "nis2", "iso27001"]
  data_residency: "eu-west-1"
  audit_retention: 365
  
  human_oversight:
    required_for:
      - "ticket_type:refund"
      - "priority:urgent AND value:>500"
      - "contains:account_closure"
    approvers:
      - "compliance@your-company.com"
      - "team-lead@your-company.com"

evidence:
  capture_requests: true
  capture_responses: true
  capture_pii_redactions: true
  exclude_fields:
    - "auth_token"
    - "internal_notes"
```

#### Step 4: Start Talon MCP Proxy
```bash
talon server \
  --port 8080 \
  --mcp-proxy \
  --config /opt/talon/agents/zendesk-vendor-proxy.talon.yaml

# Output:
# → MCP proxy listening on https://talon.your-company.local:8080
# → Proxying requests to https://zendesk-ai.example.com
# → Audit trail: /opt/talon/evidence.db
```

#### Step 5: Point Vendor to Talon
```
In Zendesk AI Agent settings:
┌──────────────────────────────────────────────┐
│ Data Sources Configuration                   │
│                                              │
│ ☐ Direct Zendesk API access                 │
│ ☑ Custom MCP Server                         │
│   MCP Endpoint: https://talon.your-company.local:8080 │
│   Auth Token: <your-talon-token>            │
└──────────────────────────────────────────────┘
```

### What Happens Now

```
Vendor wants to search tickets
    ↓
Calls Talon MCP endpoint: /tools/call {"name": "zendesk_ticket_search", ...}
    ↓
Talon intercepts:
    ├─ Logs: "Zendesk AI Agent requested tickets matching 'eSIM activation'"
    ├─ Policy check: Is "zendesk_ticket_search" in allowed_tools? ✓ YES
    ├─ PII redaction: Masks phone numbers per redaction_rules
    ├─ Fetches from real Zendesk API
    ├─ Redacts response before returning
    ├─ Generates evidence record (who, what, when, redacted_fields)
    └─ Returns to vendor
    ↓
Vendor receives data (works normally, unaware of governance layer)
    ↓
Your compliance officer has complete audit trail
```

**Benefits:**
- ✅ Vendor functionality unchanged (transparent proxy)
- ✅ Full visibility into vendor data access
- ✅ PII never reaches vendor's systems unredacted
- ✅ Can block forbidden operations (user deletes, mass exports)
- ✅ Generate GDPR Article 30 records on demand
- ✅ Prove NIS2 compliance to auditors

---

## Pattern 2: Webhook Interception

### When to Use
- Vendor triggers via webhooks (Zendesk → Vendor on ticket creation)
- You can control webhook destinations
- Simpler than MCP if vendor doesn't support custom servers

### Implementation (20 minutes)

#### Step 1: Configure Webhook Proxy
```yaml
# /opt/talon/agents/webhook-proxy.talon.yaml
agent:
  name: "zendesk-webhook-proxy"
  type: "webhook_interceptor"

triggers:
  - name: "intercept-vendor-webhooks"
    type: "webhook"
    endpoint: "/webhooks/zendesk"
    method: "POST"
    
    # Talon forwards to vendor after logging/redacting
    forward_to: "https://zendesk-ai-vendor.com/api/v1/tickets"
    forward_auth:
      type: "bearer"
      token: "${VENDOR_API_KEY}"

pii_handling:
  redaction_rules:
    - field: "ticket.requester.email"
      method: "hash"
    - field: "ticket.description"
      patterns:
        - "(\\+?\\d{1,3}[-.\\s]?)?\\d{9,15}"  # Phone numbers
      method: "mask"

compliance:
  audit_retention: 365
  frameworks: ["gdpr", "nis2"]

evidence:
  capture_webhook_payload: true
  capture_forwarded_payload: true  # See what vendor received
```

#### Step 2: Update Zendesk Webhook
```
BEFORE:
Zendesk Webhook URL: https://zendesk-ai-vendor.com/api/v1/tickets

AFTER:
Zendesk Webhook URL: https://talon.your-company.local/webhooks/zendesk
                      ↓
                  (Talon logs, redacts, forwards)
                      ↓
                  https://zendesk-ai-vendor.com/api/v1/tickets
```

#### Step 3: Verify Interception
```bash
talon logs --follow --agent webhook-proxy

# Output shows every webhook:
# [2025-02-16 10:23:15] Webhook received: ticket.created #45231
# [2025-02-16 10:23:15] PII redacted: 2 phone numbers, 1 email
# [2025-02-16 10:23:15] Forwarded to vendor: 1.2KB payload
# [2025-02-16 10:23:15] Evidence record generated: evt_abc123
```

**Benefits:**
- ✅ Logs every webhook payload vendor receives
- ✅ Redacts PII before vendor sees it
- ✅ Can block suspicious payloads
- ✅ Vendor unaware of proxy (transparent)
- ✅ Minimal setup (just change webhook URL)

---

## Pattern 3: Shadow Mode (Audit Only)

### When to Use
- Vendor doesn't support custom MCP or webhook routing
- You need compliance visibility but can't force vendor changes
- First step before full interception (validate Talon policies)

### Implementation (15 minutes)

#### Step 1: Shadow Audit Configuration
```yaml
# /opt/talon/agents/zendesk-shadow-audit.talon.yaml
agent:
  name: "zendesk-shadow-audit"
  mode: "shadow"  # Read-only, no interception

triggers:
  - name: "audit-zendesk-access"
    type: "cron"
    schedule: "*/5 * * * *"  # Every 5 minutes
    action: "compare_access_logs"

audit:
  # Talon independently fetches Zendesk audit logs
  sources:
    - name: "zendesk_api_logs"
      endpoint: "https://your-company.zendesk.com/api/v2/audit_logs"
      auth: "bearer:${ZENDESK_ADMIN_KEY}"
    
    - name: "vendor_claimed_access"
      endpoint: "https://zendesk-ai-vendor.com/api/audit"
      auth: "bearer:${VENDOR_API_KEY}"
  
  # Compare what vendor claims vs. what Zendesk logs show
  compare:
    - field: "accessed_ticket_ids"
      alert_if: "mismatch"
    
    - field: "accessed_user_ids"
      alert_if: "vendor_accessed_but_not_in_their_audit"
    
    - field: "data_center_location"
      alert_if: "non_eu_location"

  alerts:
    slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    email: "security@your-company.com"

compliance:
  generate_reports:
    - type: "gdpr_article_30"
      frequency: "weekly"
      recipients: ["compliance@your-company.com"]
```

#### Step 2: Run Shadow Audit
```bash
talon server --config /opt/talon/agents/zendesk-shadow-audit.talon.yaml

# Talon runs in background, auditing vendor behavior
```

#### Step 3: Review Findings
```bash
talon audit report --agent zendesk-shadow-audit --last 7d

# Output:
# Vendor Access Audit (2025-02-09 to 2025-02-16)
# ------------------------------------------------
# ✓ Total API calls: 1,247
# ✓ PII accessed: 423 customer records
# ⚠ Discrepancies found: 3
#   - Vendor accessed ticket #45299 (not in their audit log)
#   - API call from us-east-1 (outside EU data residency)
#   - User export at 3:47 AM (suspicious timing)
#
# Evidence: /opt/talon/evidence/shadow-audit-2025-02-16.json
```

**Benefits:**
- ✅ No changes to vendor setup (zero friction)
- ✅ Independent verification of vendor claims
- ✅ Alerts on policy violations
- ✅ Can't prevent violations, but detects them
- ✅ Good first step before forcing interception

**Limitations:**
- ❌ Cannot block vendor in real-time
- ❌ Relies on vendor providing audit logs
- ❌ PII already sent to vendor (can only detect, not prevent)

---

## Pattern Comparison Table

| Feature | MCP Proxy | Webhook Interception | Shadow Mode |
|---------|-----------|---------------------|-------------|
| **Setup Time** | 30 min | 20 min | 15 min |
| **Vendor Changes Required** | Medium (MCP endpoint config) | Low (webhook URL change) | None |
| **Blocks Violations** | ✅ Yes | ✅ Yes | ❌ No (detect only) |
| **PII Redaction** | ✅ Before vendor sees it | ✅ Before vendor sees it | ❌ After vendor has it |
| **Human Oversight** | ✅ Real-time approval | ✅ Real-time approval | ❌ Post-hoc review |
| **Audit Trail** | ✅ Complete | ✅ Complete | ✅ Partial |
| **Vendor Transparency** | Vendor aware | Transparent | Transparent |
| **Best For** | New vendors, controlled environments | Webhook-based vendors | Legacy vendors, validation |

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
pattern: "Webhook Interception"
reason: "Intercom triggers via webhooks, can change URL in settings"
setup_time: "20 minutes"
compliance_gain: "Audit trail + PII redaction on webhooks"
```

### Scenario 3: Custom Slack Bot (Self-Built)
```yaml
vendor: "Internal Slack bot (Python script)"
pattern: "Direct Integration"
reason: "You control the code, modify it to call Talon"
setup_time: "10 minutes (5 lines of code)"
compliance_gain: "Full governance + policy enforcement"
code_change: |
  # Before
  response = openai.ChatCompletion.create(...)
  
  # After
  response = requests.post("http://localhost:8081/v1/chat/completions", ...)
```

### Scenario 4: HubSpot AI Assistant (No API Access)
```yaml
vendor: "HubSpot AI Assistant"
pattern: "Shadow Mode"
reason: "HubSpot doesn't allow custom MCP or webhook routing"
setup_time: "15 minutes"
compliance_gain: "Audit detection, vendor behavior monitoring"
limitation: "Cannot block in real-time, only detect violations"
next_step: "Escalate to HubSpot for MCP support or find alternative"
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
- Anthropic supports MCP natively (Claude Desktop, API)
- OpenAI announced "Custom Tools Protocol" (MCP-compatible)
- Microsoft exploring MCP for Copilot

**Talon's advantage:** First mover in compliance-grade MCP gateway.

---

## Verification & Testing

### Test Your Integration

#### 1. Verify Interception
```bash
# Send test request through Talon
curl -X POST https://talon.your-company.local/tools/call \
  -H "Authorization: Bearer ${TALON_TOKEN}" \
  -d '{
    "name": "zendesk_ticket_search",
    "arguments": {"query": "test"}
  }'

# Check logs
talon logs --last 1m

# Expected output:
# → Policy check: ALLOWED (zendesk_ticket_search in allowed_tools)
# → PII redacted: 0 fields
# → Upstream call: 200 OK (154ms)
# → Evidence generated: evt_abc123
```

#### 2. Verify PII Redaction
```bash
# Create test ticket with PII
curl -X POST https://talon.your-company.local/tools/call \
  -d '{
    "name": "zendesk_ticket_create",
    "arguments": {
      "subject": "Test",
      "requester": {
        "email": "test@example.com",
        "phone": "+34612345678"
      }
    }
  }'

# Check evidence
talon evidence show evt_abc123

# Expected evidence:
# {
#   "pii_redacted": [
#     {"field": "requester.email", "method": "hash", "original_hash": "sha256:..."},
#     {"field": "requester.phone", "method": "mask_middle", "redacted_value": "+34 6XX XXX 678"}
#   ]
# }
```

#### 3. Verify Policy Enforcement
```bash
# Try forbidden operation
curl -X POST https://talon.your-company.local/tools/call \
  -d '{"name": "zendesk_user_delete", "arguments": {"user_id": 123}}'

# Expected: 403 Forbidden
# {
#   "error": "Policy violation: zendesk_user_delete not in allowed_tools",
#   "evidence_id": "evt_xyz789"
# }
```

---

## Migration Path

### Phase 1: Shadow Mode (Week 1)
- Deploy Talon in read-only mode
- Build audit trail for 1 week
- Validate policies without blocking vendor
- **Risk:** Zero (no vendor changes)
- **Goal:** Prove Talon works, tune policies

### Phase 2: Pilot Interception (Week 2)
- Enable MCP proxy or webhook interception
- Route 10% of traffic through Talon
- Monitor for issues (latency, errors)
- **Risk:** Low (easy rollback)
- **Goal:** Verify production readiness

### Phase 3: Full Rollout (Week 3)
- Route 100% traffic through Talon
- Enable PII redaction
- Enable policy enforcement
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
1. Check Talon's policy evaluation time: `talon metrics`
2. Optimize Rego policies (use indexed data structures)
3. Enable caching: `cache_ttl: 60s` in agent config
4. Deploy Talon closer to vendor (reduce network hops)

### Issue: PII Still Reaching Vendor

**Symptom:** Audit shows unredacted PII in vendor logs

**Solutions:**
1. Verify redaction rules match actual field names
2. Check vendor uses nested fields: `requester.custom_fields.phone`
3. Enable debug logging: `talon server --log-level debug`
4. Add catch-all regex patterns for PII detection

### Issue: Vendor Audit Logs Unavailable

**Symptom:** Shadow mode can't fetch vendor's audit logs

**Solutions:**
1. Check if vendor provides audit API (may be enterprise-only)
2. Request CSV export if API unavailable
3. Use Zendesk/CRM audit logs as source of truth
4. Escalate to vendor for better audit access

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
   - New vendor or greenfield: **MCP Proxy**
   - Webhook-based vendor: **Webhook Interception**
   - Legacy vendor or validation: **Shadow Mode**

2. **Start with pilot:**
   - Deploy Talon in shadow mode for 1 week
   - Validate policies without impacting vendor
   - Review audit trails with compliance officer

3. **Gradual rollout:**
   - Enable interception for 10% traffic
   - Monitor for issues (latency, errors)
   - Roll out to 100% after validation

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

- **Documentation:** https://docs.dativo.com
- **GitHub Issues:** https://github.com/dativo/talon/issues
- **Community Slack:** https://dativo-community.slack.com
- **Enterprise Support:** enterprise@dativo.com

**Remember:** The goal isn't to replace your vendors — it's to make them compliant. Talon adds the governance layer vendors can't provide.
