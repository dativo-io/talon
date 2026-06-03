# Sample auditor pack

This folder contains a **generated sample** of what you might hand to a DPO, customer security reviewer, or internal audit — produced from the no-API-key [docker-compose demo](../docker-compose/README.md).

It is **supporting controls and evidence** for review, not a completed legal filing or certification. See [LIMITATIONS.md](../../LIMITATIONS.md) and [ROADMAP.md](../../ROADMAP.md).

## Contents

| File | Purpose |
|------|---------|
| [manifest.json](manifest.json) | Generation metadata, verify commands, record count |
| [evidence.signed.json](evidence.signed.json) | Full HMAC-signed evidence records (offline verification) |
| [compliance-report.html](compliance-report.html) | Framework-mapped control summary (HTML) |
| [compliance-report.json](compliance-report.json) | Same report as JSON |

## Verify offline

From a machine with the `talon` CLI and the same signing key context as the demo (or verify signature structure only):

```bash
talon audit verify --file examples/auditor-pack/evidence.signed.json
```

For a live regeneration path, see [Evidence integrity 5-minute proof](../../docs/tutorials/evidence-integrity-demo.md).

## Regenerate

Requires Docker. From the repo root:

```bash
make auditor-pack
# or: scripts/generate-auditor-pack.sh
```

When Docker is available, the script starts `examples/docker-compose`, runs [demo-recorder.sh](../../scripts/demo-recorder.sh) to seed ~10 requests, then exports from the running container.

When Docker is not available, `make auditor-pack` falls back to [auditorpackgen](../../scripts/auditorpackgen/main.go) (synthetic demo records with a fixed test signing key — see `manifest.json`).

Commit updated artifacts when the evidence schema or compliance mapping changes.

## Related docs

- [How to export evidence for auditors](../../docs/guides/compliance-export-runbook.md)
- [Evidence integrity specification](../../docs/reference/evidence-integrity-spec.md)
- [Conformance suite & count](../../docs/reference/conformance.md)
