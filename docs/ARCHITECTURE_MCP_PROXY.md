# Dativo Talon — MCP Proxy Architecture

**This document describes how the MCP proxy fits Talon's architecture, and the vendor integration patterns it enables**

---

## MCP Proxy Pattern

### Overview

Talon's MCP server can operate in **three modes**:
1. **Native** — Expose Talon-governed tools to agents (default)
2. **Proxy** — Sit between third-party vendors and your data sources
3. **Hybrid** — Mix of native tools and proxied vendor access

The proxy mode enables compliance for third-party AI vendors (Zendesk, Intercom, HubSpot) without vendor rewrites.

---

## Architecture: Proxy Mode

```
Third-Party AI Vendor          Talon MCP Proxy               Your Data Sources
(Zendesk AI Agent,       │                            │    (Zendesk API, CRM, DB)
 Intercom, HubSpot)      │                            │
                         │                            │
         │               │                            │
         ▼               │                            │
┌─────────────────┐     │     ┌──────────────────┐   │    ┌──────────────────┐
│ Vendor calls    │───────────│ MCP Proxy Server │────────│ Your Zendesk API │
│ MCP endpoint    │     │     │                  │   │    │                  │
│                 │     │     │ ┌──────────────┐ │   │    │                  │
│ POST /tools/call│     │     │ │Policy Engine │ │   │    │                  │
│ {                │     │     │ │(Check ACL)   │ │   │    │                  │
│   "name":       │     │     │ └──────────────┘ │   │    │                  │
│   "zendesk_     │     │     │ ┌──────────────┐ │   │    │                  │
│   ticket_search"│     │     │ │PII Redaction │ │   │    │                  │
│ }               │     │     │ │(Mask fields) │ │   │    │                  │
└─────────────────┘     │     │ └──────────────┘ │   │    │                  │
                        │     │ ┌──────────────┐ │   │    │                  │
                        │     │ │Evidence Log  │ │   │    │                  │
                        │     │ │(Audit trail) │ │   │    │                  │
                        │     │ └──────────────┘ │   │    │                  │
                        │     └──────────────────┘   │    └──────────────────┘
                        │              │             │             │
                        │              │             │             │
                        │     ┌────────▼──────────┐  │    ┌────────▼─────────┐
                        │     │ Evidence Store    │  │    │ API Response     │
                        │     │ (SQLite)          │  │    │ (redacted)       │
                        │     │ - What accessed   │  │    └──────────────────┘
                        │     │ - What redacted   │  │             │
                        │     │ - Policy decision │  │             │
                        │     └───────────────────┘  │             │
                        │                            │             │
                        │◄───────────────────────────┴─────────────┘
                        │   Redacted response returned
                        │   (vendor unaware of governance)
```

**Key insight:** Vendor believes it's calling your Zendesk API directly, but Talon intercepts, logs, redacts, and enforces policies transparently.

---

## Implementation

### Directory Structure

```go
internal/mcp/
├── server.go         # JSON-RPC 2.0 server (native tool exposure at /mcp)
├── proxy.go          # Proxy mode implementation (/mcp/proxy)
└── proxy_config.go   # Proxy configuration loader (strict; fails closed)
```

### Proxy Configuration

The full shipped schema is `ProxyPolicyConfig` in `internal/policy/proxy.go`;
a complete working file ships as `examples/vendor-proxy/zendesk-proxy.talon.yaml`.
Unknown keys are rejected at load (the loader is strict — a mistyped or
unsupported block fails `talon serve` instead of being silently ignored):

```yaml
# agents/zendesk-vendor-proxy.talon.yaml
agent:
  name: "zendesk-vendor-proxy"
  type: "mcp_proxy"  # Activates proxy mode

proxy:
  upstream:
    vendor: "zendesk-ai-agent"
    url: "https://zendesk-ai-vendor.com"
    region: "EU"  # jurisdiction for policy input + data-flow evidence; omitted = "unknown"
    # Vault-backed upstream auth (#358): resolved PER REQUEST (rotation via
    # `talon secrets set` lands immediately); retrieval failure is
    # fail-closed — the request never leaves without its credential. The
    # vault ACL identity is the proxy's own agent.name. No env fallback,
    # no ${VAR} for secrets.
    auth:
      secret_name: "vendor-upstream-key"  # required when the block is present
      # header: "Authorization"           # default
      # scheme: "Bearer"                  # default; explicit "" = raw value

  allowed_tools:
    - name: "zendesk_ticket_search"
      upstream_name: "ticket_search"  # Map to vendor's naming
    - name: "zendesk_ticket_read"
      upstream_name: "get_ticket"

  forbidden_tools:
    - "zendesk_user_delete"      # Block destructive ops
    - "zendesk_export_all"       # Block mass exports
    - "zendesk_admin_*"          # Trailing-* wildcard block

  rate_limits:
    requests_per_minute: 100     # single global limit (default 100)

pii_handling:
  redaction_rules:
    - field: "requester.email"
      method: "hash"
    - field: "requester.phone"
      method: "mask_middle"
    - field: "description"
      patterns:
        - "(\\+?\\d{1,3}[-.\\s]?)?\\d{9,15}"  # Phone regex
      method: "mask"

compliance:
  frameworks: ["gdpr", "nis2"]
  data_residency: "eu-only"      # requires upstream.region in the EU
```

Evidence capture is not configurable per proxy: every proxied call produces a
signed evidence record (tool, decision, PII findings, data flow) unconditionally.

### Interception is unconditional

Governed MCP calls are always intercepted. The former `proxy.mode` (#442)
(`intercept | passthrough | shadow`) selector was removed in #442: a config
that still sets it fails at load with an error naming the key and the
non-live alternatives (`talon doctor`, `talon validate`, `talon run --dry-run`).
How permissive a rollout is follows from the rules you declare — the
`allowed_tools` list, the `forbidden_tools` globs, the redaction methods —
not from a runtime posture.

**Behavior:**
- Every MCP tool call goes through Talon
- Policy checks BEFORE upstream call
- Can block forbidden tools
- PII redacted BEFORE vendor sees it
- Full evidence trail

**Flow:**
```
Vendor → Talon (policy check) → Upstream API → Talon (redact response) → Vendor
```

**Historical records:** deployments that ran the removed `passthrough`/`shadow`
postures before #442 may hold `proxy_shadow_violation` evidence records with
`observation_mode_override: true` and `shadow_violations` entries. Those (#442)
records stay readable, exportable, and verifiable; no new record of that kind
is written.

**Fail-closed invariants:** a PII-scanner failure blocks the call — arguments
Talon cannot classify must not reach the upstream tool; a forbidden tool is
never forwarded; and both loaders reject unknown proxy keys at startup
(#346), so a mistyped rule can never silently widen the policy.

**Supported MCP protocol: `2026-07-28` only (#447).** Both endpoints share
one Streamable HTTP implementation (`internal/mcp/wire`): one parser, one
validation path, one normalized request, one set of protocol error codes.
There is no `initialize` handshake, no protocol-level session
(`Mcp-Session-Id` is ignored and never minted), no GET session stream, no
DELETE, no `Last-Event-ID` resumption, and no older protocol version —
pre-2026 clients fail loudly with a modern error naming the supported
version. Talon's `X-Talon-Session-ID` is application/use-case correlation
and is unrelated to the removed MCP transport session.

Every POST is self-describing and is validated **before** any governed
processing, in this order: HTTP method (POST only; GET/DELETE → 405) →
`Origin` (absent, loopback, same-origin or `TALON_MCP_ALLOWED_ORIGINS`, the
same list on both routes; anything else → 403; no wildcard) → `Accept` must
list both `application/json` and `text/event-stream` (406; wildcards do not
count and `q=0` means not acceptable) → `Content-Type: application/json` (415) → 1 MiB body cap (413) → one
JSON-RPC request or notification (no batches, no null ids) → required
`params._meta` (`io.modelcontextprotocol/protocolVersion`,
`io.modelcontextprotocol/clientCapabilities`; `clientInfo` optional) →
`MCP-Protocol-Version` header present, single and equal to `_meta`
(`HeaderMismatch -32020`), and exactly `2026-07-28`
(`UnsupportedProtocolVersion -32022` with `data.supported`) → `Mcp-Method`
present, single and equal to the body method → `Mcp-Name` present and equal
to `params.name` for `tools/call` (Base64 sentinel decoded) → method
allowlist. This surface defines **no client-to-server notification**: the
2026-07-28 core has no `initialize`/`initialized` exchange and cancellation
on Streamable HTTP is the request stream's lifecycle, so every id-less
message (including the removed `notifications/initialized` and
`notifications/cancelled`) is answered with HTTP 404 and `-32601`, nothing
is dispatched and no evidence is written. No `_meta` or header requirement
is invented for notifications.

Governed methods are `server/discover` (informational: `supportedVersions`,
the `tools` capability, `serverInfo`, cache hints — never an authorization),
`tools/list` (deterministic order, `ttlMs`/`cacheScope` hints; the proxy
keeps the upstream `ttlMs` and always answers `cacheScope: private`) and
`tools/call`. Every OTHER method (`resources/read`, `prompts/get`,
`subscriptions/listen`, `initialize`, …) is a protocol `-32601` with HTTP
404 — no `talon_code`, no evidence, nothing forwarded. Protocol rejections
are never policy decisions: they happen before a trustworthy action exists,
so they produce security/operational diagnostics only, while a governance
denial on a validated request still produces a signed record.

**Header/body integrity is a security boundary.** `Mcp-Method`, `Mcp-Name`
and schema-declared `Mcp-Param-*` headers exist for intermediaries; Talon
parses the body and requires the mirrors to agree. A header can never pick a
different tool than the body (`Mcp-Name: read_ticket` over a
`delete_customer` body is `-32020`, zero dispatch). Mirrored parameters
(`x-mcp-header` → `Mcp-Param-*`) have exactly **one** source of truth per
route: the definition Talon presents in `tools/list` is the definition it
validates against and generates from. On the native route that is the
registered tool's JSON Schema. On the proxy it is the **captured trusted
definition set**: the tool definitions of the last successfully validated
upstream `tools/list` (all pages followed, deterministic order), expiring on
the upstream's `ttlMs`, with any definition whose `x-mcp-header` annotation
violates the spec excluded and logged. The same capture drives all three:
what `tools/list` presents (the `allowed_tools` subset, exact definitions,
annotations intact, one page, a client cursor is invalid params), what
inbound `Mcp-Param-*` headers are validated against (the original parsed
arguments), and what outbound `Mcp-Param-*` headers are generated from (the
authorized, **redacted** arguments Talon forwards — never the inbound header
value). A `tools/call` whose definition is not in the capture is the spec's
protocol error (unknown tool); a call made while no fresh capture exists
fetches one through the same validation and fails closed, with an
upstream-error record, if the upstream cannot provide it. The capture is
protocol metadata only: it never defines policy, materiality or approval
(#427/#431 own the governed catalog). Where a declaration exists the body
remains the argument value and the header is an integrity duplicate
(integers compare numerically, Base64 sentinels are decoded, unrecognized
`Mcp-Param-*` headers are ignored and never forwarded). A drift test proves
a route can never advertise one declaration and validate another.

**Intermediary capability rule.** Talon identifies itself to the upstream as
the MCP client, so the capabilities it sends are the downstream client's
capabilities **intersected with what Talon can relay faithfully**:
`elicitation`, `sampling` and `roots` (MRTR input requests are passed
through to the originating client unchanged, so its answers are its own).
`extensions` (the Tasks extension above all), `experimental` and unknown
members are stripped: the upstream must not activate behaviour Talon
neither advertises in its own `server/discover` nor relays, and an upstream
`resultType: task` is refused regardless of what the downstream declared. On the way out the proxy builds a
**fresh** upstream request from the authorized, redacted body: canonical
upstream name, `_meta` with this protocol version, Talon's own identity, the
originating client's capabilities and permitted keys (progress token, trace
context, vendor extensions), the client's `requestState`/`inputResponses`
preserved verbatim, and `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name`/
`Mcp-Param-*` generated from that body. Inbound headers are never copied.
Redirects from the upstream are never followed, including after a runtime
timeout change. Upstream replies may be a JSON object or a request-scoped
SSE stream and are validated strictly: `jsonrpc: "2.0"`, a valid id
**exactly** equal to the request Talon sent (numbers compare as exact
rationals so `1 == 1.0` but adjacent large integers never collide; strings
never equal numbers; notifications on the stream are skipped; a message
with another id is a protocol violation), exactly one of `result`/`error`.
`resultType` truth table: missing → upstream protocol violation; `complete`
→ continued; `input_required` (MRTR) → passed through losslessly, ordinary
protocol continuation and never a Talon approval; `task` → unsupported
(the Tasks extension is not advertised, #448); any other value →
unsupported. Proxy `tools/list` accepts only the current `ListToolsResult`
shape: `resultType: complete`, a `tools` array, and the **required**
`CacheableResult` hints — `ttlMs` a non-negative JSON number (fractions are
legal and preserved exactly) and `cacheScope` exactly `public` or `private`.
Missing or malformed hints are an upstream protocol violation, never
repaired.

**Stable denial codes (#369):** every Talon-shaped proxy error carries
`error.data.talon_code` — the machine contract; messages are prose and may
change:

| talon_code | Meaning |
|---|---|
| `TALON_TOOL_FORBIDDEN` | explicit `forbidden_tools` match |
| `TALON_POLICY_DENIED` | tool-access policy deny (Rego) |
| `TALON_PII_BLOCKED` | PII deny, residual PII after redaction, invalid redaction output |
| `TALON_SCANNER_UNAVAILABLE` | PII scanner fail-closed (unavailable/unverifiable) |
| `TALON_METHOD_NOT_ALLOWED` | non-governed MCP method (#356) |
| `TALON_UPSTREAM_ERROR` | upstream transport/decode failure (vendor JSON-RPC errors pass through untagged) |

---

## Code: Proxy Implementation (design sketch)

> **Note:** the listing below is the original design sketch, kept for
> architectural orientation — it is NOT the shipped source. The real
> implementation lives in `internal/mcp/proxy.go` (`ProxyHandler`), with the
> config schema in `internal/policy/proxy.go` and policy evaluation via
> embedded OPA/Rego (`ProxyEngine`, `rego/proxy_*.rego`). Where the sketch
> and the code disagree (e.g. the sketch's `Upstream.Auth` field), the code
> is authoritative.

```go
package mcp

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/dativo-io/talon/internal/policy"
    "github.com/dativo-io/talon/internal/evidence"
    "github.com/dativo-io/talon/internal/classifier"
)

type ProxyServer struct {
    config       *ProxyConfig
    policyEngine *policy.Engine
    evidenceStore *evidence.Store
    classifier    *classifier.Classifier
    httpClient    *http.Client
}

type ProxyConfig struct {
    Upstream       UpstreamConfig   `yaml:"upstream"`
    AllowedTools   []ToolMapping    `yaml:"allowed_tools"`
    ForbiddenTools []string         `yaml:"forbidden_tools"`
    PIIRules       []RedactionRule  `yaml:"pii_handling"`
}

type UpstreamConfig struct {
    Vendor string `yaml:"vendor"`
    URL    string `yaml:"url"`
    Auth   Auth   `yaml:"auth"`
}

type ToolMapping struct {
    Name         string `yaml:"name"`           // Talon's tool name
    UpstreamName string `yaml:"upstream_name"`  // Vendor's tool name
}

func (p *ProxyServer) HandleToolCall(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error) {
    var params struct {
        Name      string                 `json:"name"`
        Arguments map[string]interface{} `json:"arguments"`
    }
    
    if err := json.Unmarshal(req.Params, &params); err != nil {
        return nil, fmt.Errorf("invalid params: %w", err)
    }
    
    // 1. Check if tool is allowed
    if p.isForbidden(params.Name) {
        return p.blockRequest(req.ID, "Tool not in allowed_tools")
    }
    
    // 2. Classify PII in arguments
    piiFields, err := p.classifier.DetectPII(params.Arguments)
    if err != nil {
        return nil, err
    }
    
    // 3. Evaluate policy
    decision, err := p.policyEngine.Evaluate(ctx, &policy.Input{
        ToolName:  params.Name,
        Arguments: params.Arguments,
        PIIFields: piiFields,
    })
    
    if err != nil || !decision.Allowed {
        return p.blockRequest(req.ID, decision.Reason)
    }
    
    // 4. Redact PII
    redactedArgs := p.redactPII(params.Arguments, p.config.PIIRules)
    
    // 5. Map to upstream tool name
    upstreamName := p.mapToolName(params.Name)
    
    // 6. Call upstream API
    upstreamReq := &JSONRPCRequest{
        JSONRPC: "2.0",
        Method:  "tools/call",
        Params:  json.RawMessage(mustMarshal(map[string]interface{}{
            "name":      upstreamName,
            "arguments": redactedArgs,
        })),
        ID: req.ID,
    }
    
    upstreamResp, err := p.callUpstream(ctx, upstreamReq)
    if err != nil {
        return nil, err
    }
    
    // 7. Redact PII in response
    redactedResp := p.redactPII(upstreamResp.Result, p.config.PIIRules)
    
    // 8. Generate evidence
    _ = p.evidenceStore.Record(ctx, &evidence.Record{
        Type:             "proxy_tool_call",
        ToolName:         params.Name,
        UpstreamToolName: upstreamName,
        PIIRedacted:      piiFields,
        PolicyDecision:   decision,
        Timestamp:        time.Now(),
    })
    
    // 9. Return redacted response to vendor
    return &JSONRPCResponse{
        JSONRPC: "2.0",
        Result:  redactedResp,
        ID:      req.ID,
    }, nil
}

func (p *ProxyServer) isForbidden(toolName string) bool {
    for _, forbidden := range p.config.ForbiddenTools {
        if matched, _ := filepath.Match(forbidden, toolName); matched {
            return true
        }
    }
    
    // Also check if it's in allowed_tools
    for _, allowed := range p.config.AllowedTools {
        if allowed.Name == toolName {
            return false
        }
    }
    
    // Not in allowed list = forbidden by default
    return true
}

func (p *ProxyServer) redactPII(data interface{}, rules []RedactionRule) interface{} {
    // Implementation:
    // - Walk JSON structure
    // - Match field paths against rules
    // - Apply redaction method (hash, mask, redact_full)
    // - Return redacted copy
    
    // Shipped implementation: internal/classifier/pii.go (analysis +
    // redaction) and internal/classifier/redact_guard.go (egress verify)
    return data
}

func (p *ProxyServer) callUpstream(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error) {
    body, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }
    
    httpReq, err := http.NewRequestWithContext(ctx, "POST", p.config.Upstream.URL, bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    
    // Add vendor auth
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set(p.config.Upstream.Auth.Header, p.config.Upstream.Auth.Value)
    
    resp, err := p.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var mcpResp JSONRPCResponse
    if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
        return nil, err
    }
    
    return &mcpResp, nil
}
```

---

## Testing Proxy Mode

### 1. Local Test Setup

```bash
# Terminal 1: Start Talon with the MCP proxy enabled
talon serve --port 8080 --proxy-config agents/zendesk-vendor-proxy.talon.yaml

# The startup log confirms the proxy is mounted:
#   INF talon_serve_started addr=:8080 agent=zendesk-vendor-proxy ... mcp_proxy=true
```

`--proxy-config` is the only proxy-related flag on `serve`; the `--config`
global flag selects the *infrastructure* config (talon.config.yaml), not the
proxy policy.

### 2. Test Tool Call

The proxy listens at `POST /mcp/proxy` (JSON-RPC 2.0). Locally without
`TALON_ADMIN_KEY` the endpoint is unrestricted (dev mode; the startup log
warns); in production send an agent or admin key as a Bearer token.

```bash
# Terminal 2: Simulate vendor calling Talon (MCP 2026-07-28: no handshake,
# every request carries its protocol metadata and the mirrored headers)
curl -X POST http://localhost:8080/mcp/proxy \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: zendesk_ticket_search" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "vendor-client", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
      },
      "name": "zendesk_ticket_search",
      "arguments": {
        "query": "eSIM activation issue",
        "requester_email": "customer@example.com"
      }
    },
    "id": 1
  }'
```

The response is the upstream's JSON-RPC result with PII redacted per your
`pii_handling` rules; a forbidden tool returns a JSON-RPC error
(`"tool not allowed by policy"`) instead of being forwarded.

### 3. Verify Evidence

```bash
# Check audit trail
talon audit list --agent zendesk-vendor-proxy --limit 10
talon audit show <evidence-id>   # full record incl. PII findings + data flow
```

---

## Deployment Patterns

### Pattern 1: Sidecar Proxy (Recommended)

```
┌─────────────────────────────────────────┐
│ Your Infrastructure (VPC)               │
│                                         │
│  ┌────────────┐       ┌──────────────┐ │
│  │ Talon MCP  │◄──────│ Zendesk API  │ │
│  │ Proxy      │       │              │ │
│  └────────────┘       └──────────────┘ │
│        ▲                                │
└────────│────────────────────────────────┘
         │ MCP endpoint exposed
         │
    ┌────▼──────────────┐
    │ Third-Party Vendor│
    │ (Zendesk AI Agent)│
    └───────────────────┘
```

**Setup:**
- Deploy Talon on same VPC as your data sources
- Expose MCP endpoint via HTTPS (with TLS cert)
- Point vendor to `https://talon.your-company.com`

---

### Pattern 2: Gateway Proxy (High-Scale) — future design

> **Not shipped:** Talon's evidence store is SQLite (single writer, one node);
> there is no PostgreSQL driver and no shared-state mode today. Multi-replica
> HA with a shared store is a future design direction, not a deployable
> pattern. What you CAN do today: run one Talon node per vendor/region behind
> your edge, each with its own evidence store, and merge audit exports
> (`talon audit export`) downstream.

```
┌───────────────────────────────────────────────┐
│ Edge (Cloudflare, AWS ALB)                    │
│   ├─ /mcp/proxy → Talon (one node per vendor) │
│   └─ Rate limiting, DDoS protection, TLS      │
└───────────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────┐
    ▼               ▼               ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│ Talon   │   │ Talon   │   │ Talon   │
│ vendor A│   │ vendor B│   │ vendor C│
└─────────┘   └─────────┘   └─────────┘
     │             │             │
  SQLite        SQLite        SQLite
  evidence      evidence      evidence
```

---

## Security Considerations

### 1. Vendor Authentication (inbound)

**How does the vendor authenticate to Talon?** `POST /mcp/proxy` is mounted
behind Talon's key middleware:

- Default: an **agent key** (vault-bound, `agent.key.secret_name`) or the
  **admin key** (`TALON_ADMIN_KEY`) as a Bearer token.
- With the LLM gateway enabled (`--gateway`), the endpoint requires the
  **admin key** specifically — agent keys are reserved for gateway traffic.
- With no keys configured, the endpoint is **unrestricted** (local dev only;
  `talon serve` warns loudly). Never expose that configuration.

Per-vendor scoped bearer tokens (one token per vendor, tool-scoped) are a
Roadmap item — there is no `proxy.auth` config block today, and the strict
config loader rejects one.

### 2. TLS / Mutual TLS

`talon serve` terminates **no TLS**. Run Talon behind your reverse proxy or
load balancer and terminate TLS (and, if required, client-certificate mTLS)
there. Native mTLS is a Roadmap item (Phase 3) — there is no `proxy.tls`
config block today.

### 3. Rate Limiting

`proxy.rate_limits.requests_per_minute` is parsed (default 100) and a
`proxy_rate_limits.rego` module exists, but the proxy handler evaluates only
tool access and PII redaction today (`internal/mcp/proxy.go`) — the value is
**not enforced**. Rate-limit your vendor at the reverse proxy in front of
Talon. Enforced per-vendor limits and burst allowances are Roadmap items.

---

## Monitoring & Alerts

**Shipped today:** every proxied call — allowed, blocked, redacted — lands in
the signed evidence store. Operational visibility comes from there:

```bash
talon audit list --agent zendesk-vendor-proxy --limit 50   # recent decisions
talon audit export --format json                           # feed your SIEM
```

OTel tracing (`talon serve --otel`) emits spans for proxy policy evaluation
(`policy.proxy.*`). Named Prometheus metrics for the proxy
(`proxy_requests_total`-style counters) and built-in alerting rules are
**Roadmap items** — today, alert off the exported evidence stream (e.g. a
`proxy_tool_blocked` record for a `*export*` tool is your exfiltration
signal).

---

## Cost Analysis

### Latency Overhead

**Measured on 4 CPU, 8GB RAM VM:**
- Policy evaluation: 5-10ms
- PII detection: 10-20ms (regex-based)
- Redaction: 5-10ms
- Evidence logging: 5ms (async)
- **Total: ~25-45ms**

**Compared to:**
- Upstream API latency: 200-500ms
- Talon overhead: ~5-10% of total request time

**Acceptable for most use cases.**

### Cost Savings

**Without Talon (custom build):**
- Engineering: 4 weeks × €5,000/week = €20,000
- Maintenance: €2,000/month = €24,000/year
- **Total Year 1: €44,000**

**With Talon:**
- Setup: 2 days × €1,000/day = €2,000
- Hosting: €200/month = €2,400/year
- **Total Year 1: €4,400**

**Illustrative build-vs-buy example: €39,600 saved (90% cost reduction)**

---

## Roadmap

### Phase 1 — shipped
- ✅ MCP proxy intercept mode
- ✅ PII redaction (bidirectional: request arguments and upstream responses)
- ✅ Policy enforcement on tool access (allowed/forbidden tools) and PII (redaction, scanner fail-closed)
- ✅ Evidence logging (signed, unconditional)
- ✅ Strict config loading — unknown proxy config keys fail closed
- ❌ Not wired today: the `proxy_rate_limits.rego` and `proxy_compliance.rego` evaluators exist but the proxy handler does not call them — `rate_limits` and `compliance` declarations are parsed and passed as policy data, not enforced

### Phase 2 — planned
- [ ] Tool usage analytics
- [ ] Multi-vendor config templates
- [ ] Plan review UI for proxy calls
- [ ] Named Prometheus metrics + alerting for proxy traffic

### Phase 3 — planned
- ✅ Vault-backed upstream auth injection (`proxy.upstream.auth`, per-request, fail-closed — #358)
- [ ] Per-vendor inbound bearer tokens (tool-scoped)
- [ ] mTLS support
- [ ] Per-vendor rate limits with burst
- [ ] Vendor-specific compliance overlays
- [ ] A2A protocol proxy

---

## Summary

Talon's MCP proxy pattern enables:

1. **Vendor transparency** - See what third-party AI accesses
2. **Policy enforcement** - Block forbidden operations
3. **PII protection** - Redact before vendor sees data
4. **Compliance proof** - Generate audit trails automatically
5. **No vendor lock-in** - Switch vendors without rewriting governance

**Key insight:** companies can adopt AI vendors (Zendesk, Intercom, HubSpot) while keeping the same control plane they use for their own AI use cases — shared policy, cost attribution, and signed evidence for vendor traffic too. Vendor "compliance claims" become independently verifiable supporting evidence for GDPR/NIS2/EU AI Act reviews.

---

## Implementation Notes

### Response-path PII scanning

Both the MCP proxy and the LLM API gateway now scan **responses** from upstream for PII before returning them to the caller. This is bidirectional: request arguments are scanned on the way in, and upstream responses are scanned on the way out. The gateway applies `redact`, `block`, or `warn` modes per the effective `pii_action` of the requesting agent. Evidence is recorded for every redaction.

### `tools/list` filtering

When a vendor calls `tools/list` via the MCP proxy, Talon filters the response so the caller only sees tools listed in `allowed_tools`. Forbidden tools and unlisted tools are stripped from the response before it reaches the vendor. This reduces the attack surface — agents cannot discover or attempt to call tools they are not authorized to use.

### Evidence attribution (#350)

Every proxy evidence record attributes to the real caller, resolved once at
the HTTP boundary and reused across all records of one call:

- **Agent**: the authenticated agent from the key middleware
  (`agent_id: coding-assistant` when the request presented that agent's key);
  on the admin-key and dev-open paths, which carry no agent identity, records
  attribute to the proxy config's own `agent.name`. The tenant derives the
  same way (key → agent → tenant, #266).
- **Session**: a caller-supplied `X-Talon-Session-ID` lands in the record's
  `session_id`, so MCP tool calls join the same session's LLM gateway
  traffic. Client-asserted — **attribution, not authentication**; never a
  policy input. No session is synthesized when none is asserted.
- **Correlation**: an inbound `X-Correlation-ID` is preserved; otherwise one
  request-scoped ID is generated and shared by every record of that call
  (intent and result records are joinable). Both resolved identifiers are
  echoed on the response headers.
- **Header hygiene**: the same contract as the gateway (128-byte cap, RFC
  7230 token charset, reject — never truncate; shared implementation in
  `internal/evidence`): an invalid attribution header is an HTTP 400 before
  any evidence is written. The `X-Talon-Agent-ID` / `X-Talon-Parent-Agent-ID`
  / `X-Talon-Client` identity headers populate the record's `orchestration`
  block exactly as on the gateway. Vendor header adapters (Claude Code,
  Codex) are an LLM-wire concern and are not consulted on the MCP wire.
- **Denied tool calls** carry the deterministic `POLICY_DENIED_TOOL`
  explanation code alongside the native trigger (`forbidden_tools`, Rego
  reasons) for debugging.

---

## Related: LLM API Gateway

Talon also provides an **LLM API Gateway** at `POST /v1/proxy/{provider}/v1/chat/completions`. Unlike the MCP proxy (which intercepts **tool-level** MCP calls from vendors), the LLM gateway intercepts **request-level** LLM API calls from any application: desktop apps, Slack bots, scripts. Clients send OpenAI/Anthropic/Ollama requests to Talon with an agent key; Talon enforces the agent's effective model and cost policy and records evidence. Enable with `talon serve --gateway --gateway-config <path>`. See [OpenClaw integration](guides/openclaw-integration.md), [Slack bot integration](guides/slack-bot-integration.md), and [Desktop app governance](guides/desktop-app-governance.md).
