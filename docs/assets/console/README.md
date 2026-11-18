# Operations Console image assets

These are **real screenshots** of Talon's packaged, read-only Operations Console, generated against the synthetic Playwright fixture in `tests/browser/`. They are not captures of production customer data.

- `showcase.webp` is a faithful collage built from the screenshots, with correctly labeled pages.
- `overview-attention.webp`, `system-diagnostics.webp`: the intentionally broken-runtime Case G fixture.
- `use-case-summary.webp`: configured HR Analytics AI use case.
- `session-investigation.webp`, `evidence-verification.webp`: seeded People Analytics allow, deny, HR-rejected timeline and valid HMAC record.
- `tamper-detection.webp`: intentionally modified HMAC evidence, not a valid signed decision.
- `costs.webp`: example with incompatible currencies and unavailable measurements.
- `configuration.webp`: organization policy, shared proxy and per-agent declarations.
- `overview-mobile.webp`: responsive layout.
- `action-policy.webp`, `action-evidence.webp`: the Action Gateway block of the `refund-bot` use case (one company argument rule, one use-case argument rule) and the signed record of a refund that needed a reviewer. The fixture produces this lifecycle with the production action service (establish, reviewer decision, claim, dispatch to a loopback refund service that counts its calls); the records are not written by hand. The reviewer principal is the fixture's own, not an operator's credential.

The images are **illustrative**; CLI audit verification and downstream counters remain the proof for a real integration. An offline gateway in the synthetic fixture does not indicate Talon is currently offline in a deployment.

## Freshness in CI

The [Console screenshots workflow](../../../.github/workflows/console-screenshots.yml) runs on relevant changes to the console, read projections, capture fixture, renderer and committed assets. It captures fresh light, dark and mobile screenshots from the packaged binary without provider keys. The `console-screenshots` artifact contains raw captures, reviewed-candidate WebPs and collage in `curated/`, a candidate `baseline.json`, and an informational `visual-diff.json`.

The fixture is deterministic in its business scenarios, not pixel-exact: real clocks, temporary paths, generated IDs, versions and fonts can change pixels. CI therefore fails on stale **render-input or curated-asset Git blob IDs** recorded in `baseline.json`, not an arbitrary pixel threshold. The image comparison is informational; review the fresh captures for layout and semantic changes. The input list is deliberately conservative, so some backend changes may require re-review even if the rendered layout is unchanged. It is not a guarantee that every transitive behavior change is detected. This is a path-filtered workflow, not a global required status for unrelated PRs.

### Refresh the published images

1. Use the artifact from the PR's capture run, or manually dispatch **Console screenshots** on the branch containing the changes. Manual dispatch generates candidates without failing on a stale baseline.
2. Review the raw images and collage, including error states; copy the contents of `curated/` (the twelve WebPs and `baseline.json`) into `docs/assets/console/`.
3. Commit those files together with the matching render-input revision. The next relevant CI run verifies the committed baseline. No workflow writes commits, opens PRs or deploys images automatically.

For a local refresh on Linux with Go, Node, Chromium, Python 3, DejaVu fonts and Pillow installed (stage render-input changes first):

```bash
mkdir -p /tmp/talon-console-captures
CONSOLE_SCREENSHOTS=/tmp/talon-console-captures make test-browser-console
python3 -m pip install Pillow==11.3.0
python3 scripts/generate-console-visuals.py /tmp/talon-console-captures docs/assets/console
python3 scripts/console-visual-baseline.py write
python3 scripts/console-visual-baseline.py check
```

The capture suite uses `tests/browser/03-screenshots.spec.js`; the renderer `scripts/generate-console-visuals.py` crops the actual browser screenshots without modifying their in-app statuses or labels. The generated `showcase.webp` adds section headings and visual framing around these real source images. Do not replace these with fabricated UI mockups.
