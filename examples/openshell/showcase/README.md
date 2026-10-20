# Talon × NVIDIA OpenShell — the customer showcase

**OpenShell contains the agent. Talon governs what the agent can do for the company.**

`demo.sh` is the one authoritative runner of the OpenShell customer scenario. The
same runner serves a standalone evaluation (this directory or the published
showcase bundle), the `talon-full-demo` orchestration (its OpenShell case calls
it in embedded mode) and the real-runtime CI lane (`demo.sh validate`).

The scenario: a customer-support agent built on the official OpenAI Go SDK runs
**inside a released OpenShell sandbox**. The model chooses tools; every tool is a
Talon action. It reads a ticket (allowed), is never shown the forbidden
`delete_customer` tool (and is denied if it asks anyway), proposes a synthetic
EUR 50 refund that **requires a human reviewer outside the sandbox**, resumes
after the decision, and Talon dispatches the approved refund **at most once** to
a mock business service the sandbox cannot reach directly. Everything is in
Talon's signed evidence under one session and one sandbox identity.

What the sandbox never holds: a Talon agent key, a reviewer credential, the
provider credential (OpenShell injects it after Talon's decision), the protected
service's credential.

## Supported topology

Linux host with Docker ≥ 28 (the OpenShell docker driver), OpenShell **v0.1.3**
(validated baseline) or v0.1.4 (pinned, experimental until green in the lane),
one self-hosted Talon (SQLite), the deterministic mock provider by default. A
real provider (`TALON_SHOWCASE_PROVIDER_MODE=real`, `OPENAI_API_KEY` given to
OpenShell only) is supported but costs money and its tool choices are not
scripted. No Kubernetes, PostgreSQL or Redis.

## Commands

```
demo.sh prepare | start | status | run | approval-status | approve | reject | validate | stop
```

Two shells make the human decision visible:

```bash
# shell 1
bash examples/openshell/showcase/demo.sh prepare     # configuration (idempotent), reviewer credential
bash examples/openshell/showcase/demo.sh start       # pinned OpenShell + mocks + sandbox (+ Talon in standalone mode)
bash examples/openshell/showcase/demo.sh status      # non-zero when a control is missing
bash examples/openshell/showcase/demo.sh run         # the SDK agent in the sandbox; waits for the reviewer

# shell 2, when shell 1 prints APPROVAL_ID=…
bash examples/openshell/showcase/demo.sh approval-status
bash examples/openshell/showcase/demo.sh approve     # or: reject

# afterwards
TALON_DATA_DIR=.talon-openshell-showcase/talon-data talon audit list --runtime-ref <sandbox id> --limit 200 --report
TALON_DATA_DIR=.talon-openshell-showcase/talon-data talon audit verify --operation <refund operation id>
bash examples/openshell/showcase/demo.sh stop
```

`run` prints the agent's `KEY=VALUE` transcript, checks the mock business
service's observed counts (one ticket read, exactly one refund on approval, zero
on rejection, zero deletions ever) and writes a receipt
`<run-dir>/<session>.result.json` with `session_id`, `runtime_ref` (the sandbox
id), `refund_operation_id`, the status and the observed counts. The receipt is a
locator, not proof: the proof is Talon's signed evidence, which the two `talon
audit` commands above reconstruct and verify. Re-running `run` with the same
session and operation prefix resumes the same business operation (stable
operation ids); it never creates a second refund.

## Development path vs customer path

- **Development (this checkout):** the runner builds `talon`, the helper
  binaries and the sandbox agent image (`talon-openshell-agent:local-<commit>`)
  from source. Needs Go and Docker.
- **Customer (published artifacts):** install the Talon release, download the
  versioned showcase bundle (`talon-openshell-showcase_<version>_linux_<arch>.tar.gz`
  with its `.sha256` and `showcase-manifest.json`), set
  `TALON_SHOWCASE_BUNDLE_DIR` to the extracted directory and
  `TALON_SHOWCASE_RELEASE_MANIFEST` to the manifest. The runner refuses any
  binary whose sha256 is not in the manifest and uses the agent image the
  manifest names (`ghcr.io/dativo-io/talon-openshell-agent:<version>`; pin it by
  digest in your own instructions). OpenShell's binaries are fetched from the
  official NVIDIA release and verified against the pinned checksums. No source
  checkout, no Go toolchain, no paid API key.

The bundle and the agent image are produced by Talon's release pipeline
(`scripts/build-showcase-bundle.sh`, `.goreleaser.yml`). Until a release that
contains them is published, the customer path is **not available** — see the
project's release notes for the first version that ships them.

## Embedded mode (talon-full-demo)

With `TALON_SHOWCASE_EMBEDDED=1` the Full Demo exports `TALON_SHOWCASE_CONFIG_DIR`,
`TALON_SHOWCASE_TALON_DATA_DIR`, `TALON_SHOWCASE_TALON_URL`, `TALON_SHOWCASE_TALON_BIN`,
`TALON_SHOWCASE_RUN_DIR`, `TALON_SHOWCASE_AGENT`, `TALON_SHOWCASE_PROVIDER_MODE`,
`TALON_SHOWCASE_SESSION`, `TALON_SHOWCASE_OPERATION_PREFIX` and
`TALON_SHOWCASE_RUN_START`. The runner then overlays the **same** generated
`talon.config.yaml` and agents directory the other cases use (`talon openshell
prepare`: it adds `gateway.openshell`, the mock provider entry and the
`sandboxed-support` use case; it never touches other agents or settings), uses
the shared Talon, evidence store and keys, and stops only what it started.
`prepare` changes `gateway.openshell`, which Talon reads at startup, so the
shared Talon must be (re)started between `prepare` and `start` — the Full
Demo's `real-prepare → real-start` order does exactly that.

## What `validate` proves (the CI lane)

In a private run dir, against the real released runtime: prepare, start,
status; an approved journey with the reviewer approving through Talon's reviewer
API from the host as soon as the agent reports the approval; a resumed run that
finds the refund already succeeded and dispatches nothing; a rejected journey
with zero downstream mutations; `talon audit verify --operation` VALID; a
complete, unpaginated `--runtime-ref --report` carrying the tool filtering and
the reviewer decision; and no provider secret, reviewer credential or key
material in the logs. The deterministic mock model's tool choices are scripted;
a real provider may choose differently, which is why the agent also runs a
labelled adversarial probe of the forbidden action.

## Honest boundaries

OpenShell enforces the model-path verdict and owns containment, network policy
and credential injection; Talon records `delegated_expected` for those decisions
and never claims to have verified the runtime's enforcement. Talon dispatches
business actions itself (`talon_enforced`). Imported OCSF containment events are
`external_asserted`. The refund endpoint is a mock: no money moves. See
`docs/integration/openshell.md` and `LIMITATIONS.md` §9.
