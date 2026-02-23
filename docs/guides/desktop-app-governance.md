# Govern ChatGPT Desktop & Claude Desktop (Enterprise IT)

This guide describes how enterprise IT can route ChatGPT Desktop and Claude Desktop traffic through Talon using DNS and TLS interception. Every conversation from managed devices is then audited and policy-enforced.

**Prerequisites:** Enterprise-managed devices, internal CA, DNS control, and Talon deployed on an internal server.

## How it works

1. Enterprise DNS resolves `api.openai.com` (and optionally `api.anthropic.com`) to the Talon server IP.
2. Talon accepts HTTPS connections using certificates issued by your internal CA for those hostnames.
3. The gateway pipeline runs (PII scan, policy, evidence); Talon forwards to the real provider using vault-stored API keys.
4. Employees use ChatGPT Desktop or Claude Desktop as usual; the apps are unaware that Talon is in the path.

## Architecture

```
[Employee laptop] → DNS: api.openai.com → [Talon server]
                                        → TLS (internal CA)
                                        → Gateway (identify by source IP, PII scan, policy, evidence)
                                        → Forward to real api.openai.com with vault key
```

Caller identification for desktop apps is by **source IP range** (e.g. engineering VLAN), since the apps do not send Talon-issued API keys. Configure `identify_by: "source_ip"` and `source_ip_ranges` in the gateway `callers` block.

## Configuration (schema)

The gateway config supports a `network_interception` block for this use case. Implementation of TLS termination and host-based routing is planned for a later phase; the schema is available now:

```yaml
gateway:
  # ...
  callers:
    - name: "chatgpt-desktop-engineering"
      identify_by: "source_ip"
      source_ip_ranges: ["10.1.1.0/24"]
      tenant_id: "default"
      team: "engineering"
      policy_overrides:
        max_daily_cost_eur: 15.00
        pii_action: "warn"

  network_interception:
    enabled: false   # Phase 2
    intercept_hosts:
      - original: "api.openai.com"
        provider: "openai"
      - original: "api.anthropic.com"
        provider: "anthropic"
    tls:
      cert_dir: "/etc/talon/certs/"
```

## Steps (when network interception is implemented)

1. Deploy Talon on an internal server.
2. Generate TLS certificates for `api.openai.com` and `api.anthropic.com` using your internal CA.
3. Deploy the internal CA to managed devices (e.g. via MDM/GPO).
4. Update internal DNS so `api.openai.com` and `api.anthropic.com` resolve to the Talon server.
5. Store real provider API keys in Talon's vault.
6. Configure the gateway with `network_interception` enabled and the appropriate `callers` (source IP ranges and policy overrides).
7. Verify: an employee uses ChatGPT Desktop or Claude Desktop; Talon logs every request and applies policy.

## Compliance outcome

- Every ChatGPT/Claude conversation from managed devices is audited.
- PII in prompts is detected and logged (or blocked/warned per policy).
- Cost is tracked per team via source IP → caller mapping.
- Policy violations can be blocked or limited by model and cost.

## Current status

- **Now:** Gateway supports caller identification by API key and by source IP (`identify_by: "source_ip"`, `source_ip_ranges`). Use the gateway as a **proxy** by pointing clients at `http://talon:8080/v1/proxy/openai` with a Talon-issued key.
- **Phase 2:** Full DNS interception (Talon as TLS endpoint for `api.openai.com` / `api.anthropic.com`) so desktop apps need no config change.
