# Dativo Talon — Adoption Scenarios

**Three Paths to Compliant AI Automation**

---

## Overview

Companies adopt Talon in three ways:
1. **Greenfield** — Building new AI automation from scratch
2. **Brownfield Custom** — Adding governance to existing custom-built automation
3. **Brownfield Vendor** — Adding compliance to third-party SaaS vendors

This guide shows realistic timelines, effort, and ROI for each path.

---

## Scenario 1: Greenfield (Building New AI Automation)

### Profile
- **Company:** FinTech startup, 80 employees
- **Use Case:** Automated customer support for account questions
- **Current State:** Using ChatGPT manually, want to automate
- **Compliance:** GDPR + PCI-DSS required

### Timeline: 1 Week to Production

#### Day 1: Install & Configure (2 hours)
```bash
# Install Talon
wget https://github.com/dativo/talon/releases/download/v1.0.0/talon-linux-amd64
sudo mv talon-linux-amd64 /usr/local/bin/talon

# Initialize workspace
talon init --org "FinTech" --compliance "gdpr,pci-dss"

# Configure secrets
talon secrets set OPENAI_API_KEY "sk-proj-..."
talon secrets set STRIPE_API_KEY "sk_live_..."
```

#### Day 2-3: Create First Agent (4 hours)
```yaml
# agents/support-agent.talon.yaml
agent:
  name: "customer-support-agent"
  description: "Handles account balance inquiries"
  model_tier: 1  # GPT-4 class

capabilities:
  allowed_tools:
    - stripe_balance_check
    - zendesk_ticket_create
  
  forbidden_patterns:
    - "password|pin|cvv"  # PII protection
    - "credit_card_number"

compliance:
  frameworks: ["gdpr", "pci-dss"]
  human_oversight:
    required_for:
      - "balance_change_request"
      - "account_closure"
```

#### Day 4-5: Integration & Testing (8 hours)
- Connect to Stripe API (via MCP)
- Connect to Zendesk (via MCP)
- Write integration tests
- Dry-run with test accounts

#### Day 6-7: Pilot & Launch (4 hours)
- Deploy to 5 support agents
- Monitor first 50 interactions
- Review audit trail with compliance officer
- Launch to all agents

**Total Effort:** 18 hours (2-3 person-days)

**Compliance Benefits:**
- ✅ GDPR Article 30 records from Day 1
- ✅ PCI-DSS controls enforced by default
- ✅ Human oversight for sensitive actions
- ✅ Audit trail for every decision

**Cost Savings vs. Manual Build:**
- Without Talon: 6-8 weeks to build governance (€20,000-€30,000)
- With Talon: 1 week, zero custom code
- **ROI: €20,000+ saved**

---

## Scenario 2: Brownfield Custom (Existing Custom Automation)

### Profile
- **Company:** Spanish eSIM provider, 150 employees
- **Use Case:** Custom Slack bot for Tier 1 support (built 6 months ago)
- **Current State:** Python bot calling OpenAI, works great but not compliant
- **Compliance:** GDPR + NIS2 audit in 3 months

### Current Architecture (Before Talon)
```
Zendesk webhook → Python Slack bot (EC2) → OpenAI API → Slack
                      ↓
               No audit trail
               No PII redaction
               No policy enforcement
```

### Problem Discovery (Day 0)
```
Compliance Officer: "Show me GDPR Article 30 records for AI processing."
Dev Lead: "We... don't have those. It's just Slack logs."
Compliance Officer: "What customer data did you send to OpenAI last month?"
Dev Lead: "I can't tell you. We didn't log that."
Compliance Officer: "We have 3 months until NIS2 audit. Fix this or shut it down."
```

### Timeline: 1 Day to Compliant

#### Morning (2 hours): Add Talon Governance

**Step 1:** Install Talon on same EC2 instance
```bash
# On existing bot server
wget https://github.com/dativo/talon/releases/download/v1.0.0/talon-linux-amd64
sudo mv talon-linux-amd64 /usr/local/bin/talon

talon server --port 8081 &  # Runs alongside existing bot
```

**Step 2:** Update bot code (5 lines changed)
```python
# BEFORE (their existing Slack bot)
import openai

response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": ticket_data.description}]
)

# AFTER (5 lines changed, now governed)
import requests

response = requests.post("http://localhost:8081/v1/chat/completions", json={
    "agent_id": "slack-support-bot",
    "model": "gpt-4",
    "messages": [{"role": "user", "content": ticket_data.description}]
})
```

**Step 3:** Configure Talon policies (30 minutes)
```yaml
# /opt/talon/agents/slack-support-bot.talon.yaml
agent:
  name: "slack-support-bot"
  description: "Existing Slack bot, now governed"

pii_handling:
  redaction_rules:
    - field: "email"
      method: "hash"
    - field: "phone_number"
      method: "mask_middle"

compliance:
  frameworks: ["gdpr", "nis2"]
  audit_retention: 365
  
evidence:
  capture_llm_calls: true
  capture_tool_calls: true
```

#### Afternoon (2 hours): Testing & Validation

**Step 4:** Test with real tickets
```bash
# Send test ticket through bot
# Verify Talon intercepts and logs

talon logs --follow --agent slack-support-bot

# Output:
# [14:23:15] LLM call intercepted
# [14:23:15] PII redacted: 1 phone, 1 email
# [14:23:15] Evidence generated: evt_abc123
# [14:23:16] Response returned to bot
```

**Step 5:** Generate compliance report
```bash
talon audit export \
  --agent slack-support-bot \
  --format gdpr-art30 \
  --date-range 2025-02-16:2025-02-16 \
  --output /tmp/test-report.pdf

# Review with compliance officer
```

#### End of Day: Production Rollout

**Result:**
- ✅ Slack bot still works (same UX for support team)
- ✅ Now GDPR + NIS2 compliant (audit trail + PII redaction)
- ✅ No rewrite needed (5 lines of code changed)
- ✅ Can prove compliance to auditors

**Total Effort:** 4 hours (0.5 person-days)

**Compliance Benefits:**
- ✅ Turned compliance liability into asset
- ✅ Audit-ready in 1 day (not 3 months)
- ✅ No disruption to support team
- ✅ Bot maintainability unchanged

**Cost Savings:**
- Without Talon: Rebuild from scratch (€15,000 + 6 weeks)
- With Talon: 4 hours + zero rewrite
- **ROI: €15,000 saved + avoided NIS2 fine risk**

---

## Scenario 3: Brownfield Vendor (Third-Party SaaS)

### Profile
- **Company:** German healthcare provider, 400 employees
- **Use Case:** Zendesk AI Agent for patient appointment scheduling
- **Current State:** €3,000/month SaaS, works great, compliance unknown
- **Compliance:** GDPR + NIS2 + German medical privacy laws

### Current Architecture (Before Talon)
```
Zendesk AI Agent (US AWS) → Zendesk → Patient data
                                ↓
                    Black box (no visibility)
                    Unknown PII handling
                    Unknown data residency
```

### Problem Discovery (Day 0)
```
Compliance Officer: "Show me evidence that Zendesk AI Agent is GDPR compliant."
IT Lead: "They say they are. It's in their DPA."
Compliance Officer: "Can YOU prove it? Can you show what patient data they accessed?"
IT Lead: "No, that's in their logs. We don't have access."
Compliance Officer: "We're the data controller. We're liable. This is unacceptable."
```

### Timeline: 1 Week to Compliant

#### Week 1, Day 1-2: Shadow Mode Validation (4 hours)

**Goal:** Understand what vendor is actually doing

```yaml
# /opt/talon/agents/zendesk-shadow-audit.talon.yaml
agent:
  name: "zendesk-vendor-audit"
  mode: "shadow"  # Read-only, no interception yet

triggers:
  - name: "audit-vendor-access"
    type: "cron"
    schedule: "0 * * * *"  # Hourly
    action: "compare_access_logs"

audit:
  sources:
    - name: "zendesk_logs"
      endpoint: "https://our-company.zendesk.com/api/v2/audit_logs"
    
    - name: "vendor_logs"
      endpoint: "https://zendesk-ai-vendor.com/api/audit"
  
  alerts:
    - condition: "non_eu_access_detected"
      notify: "security@our-company.com"
```

**Results after 48 hours:**
```
Vendor Audit Report (2025-02-16 to 2025-02-18)
-----------------------------------------------
⚠ Findings:
  - 47 API calls from us-east-1 (outside EU)
  - 23 patient records accessed without PII redaction
  - 1 bulk export (all appointments, 3:27 AM)
  
Evidence: /opt/talon/evidence/shadow-audit.json
```

#### Week 1, Day 3-4: MCP Proxy Deployment (6 hours)

**Goal:** Route vendor through Talon for full control

**Step 1:** Configure MCP proxy
```yaml
# /opt/talon/agents/zendesk-vendor-proxy.talon.yaml
agent:
  name: "zendesk-vendor-proxy"
  type: "mcp_proxy"

proxy:
  mode: "intercept"
  upstream:
    url: "https://zendesk-ai-vendor.com"

capabilities:
  allowed_tools:
    - zendesk_appointment_search
    - zendesk_appointment_create
  
  forbidden_tools:
    - zendesk_patient_export_all  # Block mass export

pii_handling:
  redaction_rules:
    - field: "patient.ssn"
      method: "redact_full"
    - field: "patient.address"
      method: "hash"
    - field: "patient.phone"
      method: "mask_middle"

compliance:
  frameworks: ["gdpr", "nis2", "german_bdsg"]
  data_residency: "eu-central-1"  # Germany only
  audit_retention: 2555  # 7 years (German medical records law)
```

**Step 2:** Update Zendesk AI Agent settings
```
In Zendesk AI Agent config:
┌────────────────────────────────────────┐
│ Data Source                            │
│ ☐ Direct Zendesk API                  │
│ ☑ Custom MCP Server                   │
│   URL: https://talon.our-company.de   │
└────────────────────────────────────────┘
```

#### Week 1, Day 5: Testing & Validation (4 hours)

**Test 1:** Verify PII redaction
```bash
# Trigger appointment search via vendor
# Check Talon logs

talon audit show evt_abc123

# Evidence shows:
# {
#   "pii_redacted": [
#     {"field": "patient.ssn", "method": "redact_full"},
#     {"field": "patient.address", "method": "hash"}
#   ],
#   "upstream_received": "redacted_data_only"
# }
```

**Test 2:** Verify forbidden operations blocked
```bash
# Vendor attempts bulk export
# Talon blocks it

talon logs --last 5m

# [15:43:27] Policy violation: zendesk_patient_export_all not in allowed_tools
# [15:43:27] Request blocked: 403 Forbidden
# [15:43:27] Alert sent to: security@our-company.com
```

**Test 3:** Verify data residency
```bash
# Check all API calls stayed in EU

talon audit report --agent zendesk-vendor-proxy --last 24h

# All requests: eu-central-1 ✓
# No us-east-1 calls detected ✓
```

#### Week 1, Day 6-7: Production Rollout (2 hours)

**Step 1:** Route 100% traffic through Talon
**Step 2:** Monitor for issues (latency, errors)
**Step 3:** Generate first compliance report

```bash
talon audit export \
  --agent zendesk-vendor-proxy \
  --format gdpr-art30 \
  --output /tmp/vendor-compliance-report.pdf

# Share with compliance officer and legal
```

**Total Effort:** 16 hours (2 person-days)

**Compliance Benefits:**
- ✅ Independent audit trail (vendor-agnostic)
- ✅ PII never reaches vendor unredacted
- ✅ Forbidden operations blocked (mass exports)
- ✅ Data residency enforced (Germany only)
- ✅ GDPR Article 30 reports on demand
- ✅ NIS2 compliance proven

**Cost Savings:**
- Without Talon: Rip out vendor, rebuild (€100,000 + 6 months)
- With Talon: 2 days, keep vendor
- **ROI: €100,000 saved + kept working solution**

**Vendor Cost:** Still €3,000/month (unchanged)
**Talon Cost:** €0 (open source)
**Net Benefit:** Full compliance at zero additional cost

---

## Adoption Path Comparison

| Factor | Greenfield | Brownfield Custom | Brownfield Vendor |
|--------|-----------|------------------|------------------|
| **Timeline** | 1 week | 1 day | 1 week |
| **Effort** | 18 hours | 4 hours | 16 hours |
| **Code Changes** | New codebase | 5 lines | Zero (config only) |
| **Risk** | Low (clean slate) | Low (non-breaking) | Medium (vendor dependency) |
| **Compliance Gain** | Full from Day 1 | Retrofit existing | Vendor transparency |
| **Cost Savings** | €20k-€30k | €15k | €100k+ |
| **Best For** | New projects | Existing custom | Third-party SaaS |

---

## Decision Matrix: Which Path Are You?

### Questions to Ask

1. **Do you have AI automation in production?**
   - No → **Greenfield** (build with Talon from Day 1)
   - Yes → Next question

2. **Is it custom-built or third-party?**
   - Custom (you control code) → **Brownfield Custom** (wrap with Talon)
   - Third-party (SaaS vendor) → **Brownfield Vendor** (MCP proxy)

3. **Can you modify the code?**
   - Yes → **Brownfield Custom** (5 lines changed)
   - No → **Brownfield Vendor** (MCP proxy or shadow mode)

4. **Does vendor support custom MCP servers?**
   - Yes → **MCP Proxy** (full interception)
   - No → **Shadow Mode** (audit only) + escalate to vendor

5. **How urgent is compliance?**
   - Audit in <30 days → **Shadow Mode** first (immediate visibility)
   - Audit in 30-90 days → **MCP Proxy** (full compliance)
   - No immediate audit → **Greenfield** (build right from start)

---

## Common Questions

### Q: "We have 10+ AI automations across different teams. Do we need Talon for all of them?"

**A:** Start with highest-risk automation:
1. Which processes customer PII? (priority 1)
2. Which makes financial decisions? (priority 2)
3. Which handles medical data? (priority 3)
4. Which are just internal tools? (priority 4)

Deploy Talon for top 3 priorities first (1 week each = 3 weeks total).

### Q: "Our vendor won't support MCP. What now?"

**A:** Three options:
1. **Shadow Mode** (immediate) — Start auditing vendor behavior
2. **Escalate** (1-2 weeks) — Demand MCP support or contract review
3. **Alternative** (1 month) — Find MCP-compatible vendor

Market pressure works: If 10+ companies demand MCP, vendors adapt.

### Q: "Does Talon add latency to our AI calls?"

**A:** Typical overhead:
- Policy evaluation: 5-10ms
- PII redaction: 10-20ms (depends on content size)
- Evidence generation: 5ms (async)
- **Total: ~20-40ms added latency**

For comparison:
- LLM call: 500-2000ms
- Talon overhead: ~2-4% of total time

**Negligible for user experience.**

### Q: "What if Talon goes down? Does our AI automation stop?"

**A:** Depends on configuration:

**Strict Mode (default):**
```yaml
agent:
  enforcement_mode: "strict"
```
- Talon down → AI calls blocked (fail-safe)
- **Use for:** High-risk operations (financial, medical)

**Fallback Mode:**
```yaml
agent:
  enforcement_mode: "fallback"
  fallback:
    allow_direct_calls: true
    alert: "compliance@company.com"
```
- Talon down → Direct calls allowed (logged)
- **Use for:** Low-risk operations (internal tools)

**Best practice:** Run Talon with high availability (2+ replicas).

### Q: "How do we convince management to adopt Talon?"

**A:** Present the risk:

```
Without Talon:
❌ No proof of GDPR compliance during audit
❌ Risk: €50,000+ fines
❌ Audit prep: 40 hours/quarter (€16,000/year in staff time)

With Talon:
✅ Audit-ready in 1 command
✅ Zero fine risk (full compliance)
✅ Audit prep: 2 hours/quarter (€800/year)

ROI: €15,200/year + eliminated fine risk

Cost to implement: 1-2 days (€2,000-€4,000 equivalent)
```

**Management math:** €2,000 investment saves €15,000/year + protects from €50,000 fines.

---

## Next Steps

### For Greenfield
1. Read [QUICKSTART.md](QUICKSTART.md)
2. Follow `talon init` wizard
3. Build first agent with Talon from Day 1

### For Brownfield Custom
1. Install Talon on same server
2. Update 5 lines of code to call Talon
3. Deploy shadow mode for 1 week
4. Enable enforcement after validation

### For Brownfield Vendor
1. Read [VENDOR_INTEGRATION_GUIDE.md](VENDOR_INTEGRATION_GUIDE.md)
2. Choose pattern (MCP proxy, webhook, or shadow)
3. Deploy Talon MCP proxy
4. Point vendor to Talon endpoint

---

## Success Metrics

Track these to measure adoption success:

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Compliance readiness** | Audit-ready in <1 hour | `talon audit export` time |
| **Developer productivity** | Zero compliance code written | Lines of custom governance code |
| **Audit findings** | Zero compliance violations | External audit reports |
| **Time to compliance** | <1 week from install | Calendar days (install → first audit report) |
| **Cost savings** | >€10k/year | Staff time + avoided fines |

---

## Support

- **Documentation:** https://docs.dativo.com
- **GitHub:** https://github.com/dativo/talon
- **Community Slack:** https://dativo-community.slack.com
- **Enterprise Support:** enterprise@dativo.com

**Remember:** The best time to add compliance was before you built AI automation. The second best time is now.
