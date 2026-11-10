# Operations Console image assets

These are **real screenshots** of Talon's packaged, read-only Operations Console, generated against the deterministic synthetic Playwright fixture in `tests/browser/`. They are not captures of production customer data.

- `showcase.webp` is a faithful collage built from the screenshots, with correctly labeled pages.
- `overview-attention.webp`, `system-diagnostics.webp`: the intentionally broken-runtime Case G fixture.
- `use-case-summary.webp`: configured HR Analytics AI use case.
- `session-investigation.webp`, `evidence-verification.webp`: seeded People Analytics allow, deny, HR-rejected timeline and valid HMAC record.
- `tamper-detection.webp`: intentionally modified HMAC evidence, not a valid signed decision.
- `costs.webp`: example with incompatible currencies and unavailable measurements.
- `configuration.webp`: organization policy, shared proxy and per-agent declarations.
- `overview-mobile.webp`: responsive layout.

The images are **illustrative**; CLI audit verification and downstream counters remain the proof for a real integration. An offline gateway in the synthetic fixture does not indicate Talon is currently offline in a deployment.

To regenerate with Go, Node, Chromium, Python 3 and Pillow installed:

```bash
mkdir -p /tmp/talon-console-captures
CONSOLE_SCREENSHOTS=/tmp/talon-console-captures make test-browser-console
python3 -m pip install Pillow
python3 scripts/generate-console-visuals.py /tmp/talon-console-captures docs/assets/console
```

The capture suite uses `tests/browser/03-screenshots.spec.js`; the renderer `scripts/generate-console-visuals.py` crops the actual browser screenshots without modifying their in-app statuses or labels. The generated `showcase.webp` adds section headings and visual framing around these real source images. Do not replace these with fabricated UI mockups.
