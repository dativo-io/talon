# Mission Control screenshot refresh

Maintainer workflow for updating dashboard screenshots used in README, release notes, and docs.

## When to refresh

- Governance or Gateway Mission Control layout changes ([`web/dashboard.html`](../../web/dashboard.html), [`web/gateway_dashboard.html`](../../web/gateway_dashboard.html))
- New evidence verify UX, compliance preview, or gateway widgets
- Release notes that promise a visual share artifact (see [CONTRIBUTING.md](../../CONTRIBUTING.md))

## Seed realistic data

```bash
cd examples/docker-compose
docker compose up -d --build
bash ../../scripts/demo-recorder.sh http://localhost:8080
```

This creates ~10 evidence rows (clean requests, PII variants, multiple models) suitable for screenshots.

## URLs to capture

| Surface | URL | What to show |
|---------|-----|----------------|
| Governance Mission Control | `http://localhost:8080/dashboard` | Evidence tab, verify action, signature/trust block |
| Gateway Mission Control | Gateway dashboard route (see [gateway dashboard reference](../reference/gateway-dashboard.md)) | Posture, interventions, PII/cost signals |

Open the **Evidence** tab first — that is the primary proof-bar surface for epic credibility work.

## Suggested captures

1. Evidence list with mixed allow/deny and PII flags visible.
2. Single record detail with **Verified** integrity state — click **Verify** on the row first, then **Detail** (Detail alone is read-only and leaves the record "Not checked").
3. Compliance tab with framework coverage cards and the export buttons.
4. Gateway overview with at least one blocked or PII-detected row (optional).

## Where to store assets

Prefer **`docs/images/mission-control/`** for README and tutorial embeds:

```
docs/images/mission-control/
  evidence-list.png
  evidence-detail-verified.png
  gateway-overview.png
```

Keep filenames stable; update references in docs when replacing files.

Optional: copy highlights into `examples/auditor-pack/screenshots/` only when they illustrate auditor handoff (not required for `make auditor-pack`).

## After capture

1. Link new images from [README.md](../../README.md) or release notes as needed.
2. Run `bash scripts/check-claim-discipline.sh` if doc text changed.
3. Note the refresh in CHANGELOG under the release that ships the UX change.

## Related scripts

- [`scripts/demo-recorder.sh`](../../scripts/demo-recorder.sh) — seed evidence
- [`scripts/generate-auditor-pack.sh`](../../scripts/generate-auditor-pack.sh) — export sample auditor pack (optional companion to screenshots)
