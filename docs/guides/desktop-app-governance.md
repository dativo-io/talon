# How to govern ChatGPT/Claude Desktop (enterprise)

This guide describes how enterprise IT can route ChatGPT Desktop and Claude Desktop traffic through Talon. Every conversation from managed devices is then audited and policy-enforced.

**Prerequisites:** Enterprise-managed devices, Talon deployed on an internal server, and (for the interception phase) an internal CA plus DNS control.

## How it works

1. Desktop clients (or the enterprise network path) send OpenAI/Anthropic-bound traffic to the Talon gateway.
2. Talon resolves the presented **agent key** to an agent identity — one `agent.talon.yaml` per desktop fleet or team, bound to a vault key (#266).
3. The gateway pipeline runs (PII scan, effective policy, evidence); Talon forwards to the real provider using vault-stored provider keys.
4. Employees use ChatGPT Desktop or Claude Desktop as usual.

## Architecture

```
[Employee laptop] → [Talon gateway]
                     → agent key → agent identity (per team/fleet)
                     → PII scan, effective policy, signed evidence
                     → Forward to real api.openai.com with vault key
```

Identity for desktop fleets is the same as for every other workload: a **Talon agent key**. There is no source-IP identity — `identify_by: source_ip` and `trusted_proxy_cidrs` were removed in the #266 cutover (network context is not use-case identity; a spoofable address must never select policy). Network-bound identity, if it returns, will be mTLS — an explicit future feature.

## Configuration

One agent file per desktop fleet or team:

```yaml
# chatgpt-desktop-engineering.talon.yaml
agent:
  name: chatgpt-desktop-engineering
  version: "1.0.0"
  tenant_id: default
  key:
    secret_name: chatgpt-desktop-engineering-talon-key

policies:
  cost_limits:
    daily: 15.00

metadata:
  team: engineering
```

Bind the traffic key and start the gateway:

```bash
talon secrets set chatgpt-desktop-engineering-talon-key <generated key>
talon serve --gateway
```

Distribute the agent key to the managed devices via MDM/GPO as the API key the desktop client presents (for clients that support a custom base URL + key), pointing them at `http://talon:8080/v1/proxy/openai/v1`.

The gateway config also carries a `network_interception` schema block for the DNS/TLS interception phase (not yet implemented):

```yaml
gateway:
  # ...
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
6. Configure the gateway with `network_interception` enabled and one agent identity per fleet.
7. Verify: an employee uses ChatGPT Desktop or Claude Desktop; Talon logs every request and applies policy.

Note that interception only moves the *transport* into Talon; identity remains the agent key. Desktop apps that cannot present a key cannot be attributed per-team until the mTLS identity feature exists — govern them behind a per-team egress proxy that injects the team's agent key.

## Compliance outcome

- Every ChatGPT/Claude conversation from managed devices is audited.
- PII in prompts is detected and logged (or blocked/warned per policy).
- Cost is tracked per team via the agent identity's `metadata.team`.
- Policy violations can be blocked or limited by model and cost.

## Current status

- **Now:** Use the gateway as a **proxy** by pointing clients at `http://talon:8080/v1/proxy/openai/v1` (trailing `/v1` so paths like `chat/completions` become `.../v1/chat/completions`) with the fleet's agent key.
- **Phase 2:** Full DNS interception (Talon as TLS endpoint for `api.openai.com` / `api.anthropic.com`) so desktop apps need no config change.

---

## You're done

You now know how to route ChatGPT/Claude Desktop traffic through Talon (proxy with an agent key today; DNS interception later). Talon logs every request and applies the fleet agent's effective policy.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Cap cost per team or application | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
| Route a Slack bot or script through Talon | [Add Talon to your existing app](add-talon-to-existing-app.md), [Slack bot](slack-bot-integration.md) |
| Export evidence for auditors | [How to export evidence for auditors](compliance-export-runbook.md) |
| Understand the gateway pipeline | [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) |
