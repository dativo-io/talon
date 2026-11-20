# Talon Quick Start

This page points you to the right doc for what you want to do. For the full documentation map, see [docs/README.md](README.md).

---

**Trying Talon and connecting an application are two different paths.** The command below is *Try Talon*: real policy decisions and signed evidence from the published image, with no provider key and no application of yours. To put an existing application under your company policy (a registered use case with its own key, verified activation and traffic), follow [connect an existing application](guides/add-talon-to-existing-app.md).

## One command, no clone, no provider key

```bash
curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/vX.Y.Z/scripts/quickstart.sh | TALON_VERSION=X.Y.Z bash
```

Needs Docker and `curl`. Replace `X.Y.Z` in both places with one published release (v1.17.0 or later); the script never assumes `latest`. The script is fetched from that release's tag, not from `main`, so the script and the image are the pair the release verification ran after publication. It pulls `ghcr.io/dativo-io/talon:X.Y.Z` anonymously, starts it on `127.0.0.1:18080` with a small company policy, and sends three requests: one carrying an IBAN and an email address (blocked: `pii_policy_violation`), one for a model the policy does not allow (denied: `model_not_allowed`) and one with an unknown key (refused: `401`). No model provider exists in this setup, so both decisions are Talon's own, made before any provider call. It then verifies the signature of both evidence records with `talon audit verify`, prints the image digest it ran and the elapsed time, and removes its container and volume (`TALON_QUICKSTART_KEEP=1` keeps them). `TALON_IMAGE` takes a digest pin instead of a version.

What it does not show: a model answer, a redaction, the console, or a business action. For those, continue with the paths below: the [Operations Console from the published image](../examples/docker-compose/README.md) shows the same kind of decisions in the browser, and [add Talon to your existing app](guides/add-talon-to-existing-app.md) puts your own application behind it. The script prints both links for the version it ran.

---

## After trying it

**Connect your existing application.** One guide: prepare Talon once, register the application with one command, change two settings in it, and see that it works. Every further application is that one command again.

→ [Connect an existing application](guides/add-talon-to-existing-app.md), then [operate AI use cases](guides/operate-ai-use-cases.md) for day two.

Other things to look at, none of which you need first:

- [OpenAI proxy quickstart](tutorials/proxy-quickstart.md): the drop-in shape on your own machine, one local identity, no company policy.
- [Your first governed agent](tutorials/first-governed-agent.md): building a new agent on Talon's own runtime.
- [60-second demo](tutorials/quickstart-demo.md): the Docker Compose stack from a clone, no API key.
- [Sample auditor pack](../examples/auditor-pack/README.md): what an auditor handoff looks like.

---

## Install (native binary)

See the [README install matrix](../README.md#install). Summary:

| Platform | Recommended |
|----------|-------------|
| **linux/amd64 server** (verified installer path) | `curl -fsSL https://raw.githubusercontent.com/dativo-io/talon/main/scripts/install.sh \| sh` — checksum-verified published archive, `TALON_VERSION=vX.Y.Z` to pin, `INSTALL_DIR` to choose the directory; or the release tarball + `checksums.txt` by hand |
| **macOS** | The darwin archives on the release page (best effort, per-file `.sha256`; the same installer verifies them), or `git clone … && make install` / `go install github.com/dativo-io/talon/cmd/talon@latest` |
| **arm64 Linux** | `git clone … && make install` or `go install …@latest` (no published archive; the installer refuses to build from source unless `TALON_INSTALL_ALLOW_SOURCE=1`) |
| **No install** | [Docker Compose demo](../examples/docker-compose/README.md) — with `TALON_IMAGE=ghcr.io/dativo-io/talon:<version>` and the `docker-compose.published.yml` override it runs the published image, data plane and console, without building Talon — or `docker pull ghcr.io/dativo-io/talon:<version>` |

To check a published release before trusting it: `scripts/verify-release.sh --tag vX.Y.Z` (curl, jq, tar, sha256sum; no Go, no token) verifies checksums, the executable's version and commit against the tag, the OpenShell showcase manifest and bundle, and that both images are pullable anonymously.

On macOS, if linking fails with `unsupported tapi file type`, use `make install` (sets system Clang) or `CC=/usr/bin/clang CGO_ENABLED=1 go install …`.

---

## Minimal commands (if you already know Talon)

```bash
# Install (from repo)
make install    # → $(go env GOPATH)/bin/talon

# Secrets key (required for vault)
export TALON_SECRETS_KEY="$(openssl rand -hex 32)"

# New project
mkdir my-agents && cd my-agents
talon init --scaffold --name my-agent

# Policy check without LLM spend
talon run --dry-run "Your query here"

# Live run (needs provider key)
export OPENAI_API_KEY=sk-proj-...
talon run "Your query here"

# Server (API + optional gateway/proxy). Without TALON_ADMIN_KEY the
# administrative endpoints accept every request (development mode), and
# without --host the server listens on every interface: set both. For a real
# installation generate the keys into a 0600 file instead of exporting them
# in the shell (docs/guides/add-talon-to-existing-app.md, "1. Prepare Talon").
export TALON_ADMIN_KEY="$(openssl rand -hex 32)"
talon serve --host 127.0.0.1 --port 8080

# Verify a RUNNING server: which agents is it actually serving? (#370)
# An explicit --url is authoritative — it errors rather than silently
# falling back to a local config view; --json for scripting.
talon agents --url http://localhost:8080
talon agents --url http://localhost:8080 --json

# Check config without live traffic: infrastructure config, agent policy,
# and a native policy decision with no provider call
talon doctor
talon validate
talon run --dry-run "Your query here"
```

Active policy is always enforced — the former `gateway.mode` / `--gateway-mode` posture switch was removed in #442; a config that still sets it fails at load with the key name.

Verify the cold-start path from repo root: `make verify-newcomer`.

---

## Trust artifacts (Proof Pack)

- [LIMITATIONS.md](../LIMITATIONS.md)
- [Threat model](reference/threat-model.md)
- [Evidence integrity spec](reference/evidence-integrity-spec.md)
- [Sample auditor pack](../examples/auditor-pack/README.md)

---

## More

- [Documentation index](README.md)
- [Roadmap & focus](../ROADMAP.md)
