# Shortlist demo (#107) — 10-minute proof path

Reproducible **enforce-mode** gateway demo for the north-star shortlist test
([GitHub #107](https://github.com/datio-io/talon/issues/107)). Uses the shared
mock OpenAI provider from `examples/docker-compose` — **no real LLM API key**.

This demo supports compliance evidence and documentation workflows. **It does not
make a company compliant by itself.**

## Prerequisites

- **Docker Engine** with the **Compose plugin** (`docker compose` — v2 plugin, not legacy `docker-compose`)
- **curl** and **bash** (`demo.sh` and `make shortlist-demo` health checks)
- No LLM API key (mock provider)

`make shortlist-demo` runs `docker compose up --build` under the hood. There is no
non-Docker path for this demo (unlike `make auditor-pack`, which can fall back to
offline fixtures).

### Install Docker

On Ubuntu (and most fresh cloud VMs), Docker is not pre-installed. Follow the
[official Docker Engine install guide](https://docs.docker.com/engine/install/ubuntu/)
or run:

```bash
# Ubuntu — Docker Engine + Compose plugin (official packages)
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verify, then run without `sudo` (recommended):

```bash
sudo docker run --rm hello-world
docker compose version
sudo usermod -aG docker "$USER"   # then log out and back in (or: newgrp docker)
```

If you started the stack with `sudo make shortlist-demo`, `./demo.sh` auto-uses
`sudo docker compose` when your user cannot access the Docker socket. For a cleaner
setup, add yourself to the `docker` group and run both `make shortlist-demo` and
`./demo.sh` without sudo.

## What this proves (in order)

| Step | Proof | How |
|------|--------|-----|
| 1 | Governed OpenAI-compatible request | Allowed request through proxy → HTTP 200 |
| 2 | Policy allow **and** deny with reasons | Allow caller vs model-allowlist deny → evidence reasons |
| 3 | PII handling before provider call | Server `default_pii_action: block` → HTTP 400, no upstream call |
| 4 | EU strict egress denial | Caller egress allows only `EU`/`LOCAL`; mock provider `region: US` → HTTP 403 with `egress_tier_destination_disallowed` in evidence (denied with evidence — **not** silent reroute) |
| 5 | Signed evidence verification | `talon audit verify` (+ optional tamper failure) |
| 6 | Auditor-ready export | `talon compliance ropa` + `talon compliance annex-iv` with filled declarations |

## Quick start

From repo root:

```bash
make shortlist-demo
cd examples/shortlist-demo
./demo.sh all
```

Or step by step:

```bash
cd examples/shortlist-demo
docker compose up --build -d
./demo.sh allowed-request
./demo.sh policy-deny
./demo.sh pii-request
./demo.sh eu-strict-routing
```

## Docker CLI (copy-paste)

With the stack running:

```bash
docker compose exec talon talon audit list --limit 10
docker compose exec talon talon audit show <evidence-id>
docker compose exec talon talon audit verify <evidence-id>
docker compose exec talon talon compliance ropa --format html --output /home/talon/shortlist-out/ropa.html
docker compose exec talon talon compliance annex-iv --format html --output /home/talon/shortlist-out/annex-iv.html
```

Generated files appear on the host under `examples/shortlist-demo/out/`.

## `demo.sh` commands

| Command | Purpose |
|---------|---------|
| `allowed-request` | Proof 1 — clean governed request |
| `policy-deny` | Proof 2 — model allowlist deny (not PII/routing) |
| `pii-request` | Proof 3 — PII **blocked** before provider call |
| `eu-strict-routing` | Proof 4 — EU-region egress deny |
| `audit` | List recent evidence |
| `verify [id]` | HMAC verify one record |
| `tamper-evidence` | Export, tamper, verify failure |
| `exports` | Write `out/ropa.html` and `out/annex-iv.html` |
| `all` | Full #107 path |

## Recording path (Screen Studio + voiceover)

Large terminal font. Run from `examples/shortlist-demo` after `make shortlist-demo`:

```bash
./demo.sh allowed-request      # Proof 1 — governed request (200)
./demo.sh policy-deny          # Proof 2 — policy deny + reason (403)
./demo.sh pii-request          # Proof 3 — PII blocked (400)
./demo.sh eu-strict-routing    # Proof 4 — EU egress deny (403)
docker compose exec talon talon audit list --limit 10
docker compose exec talon talon audit show <id-from-list>
docker compose exec talon talon audit verify <id-from-list>
./demo.sh tamper-evidence      # Proof 5 — tamper fails verify
./demo.sh exports              # Proof 6 — open out/ropa.html, out/annex-iv.html
```

Zoom moments: `HTTP 403` on policy deny, `HTTP 400` on PII, `egress_tier` in
`audit show`, `signature VALID`, `ropa.html` / `annex-iv.html`.

## Verification (CI / local)

```bash
bash scripts/verify-shortlist-demo.sh
```

Set `SHORTLIST_SKIP_DOWN=1` to leave the stack running after verification.

## Clean up

```bash
docker compose down -v
```

## Related docs

- [60-second demo (shadow mode)](../docker-compose/README.md) — generic onboarding
- [Evidence integrity 5-minute proof](../../docs/tutorials/evidence-integrity-demo.md)
- [LIMITATIONS.md](../../LIMITATIONS.md) — honest capability boundaries
