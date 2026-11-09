# Console frontend

React + TypeScript + Vite source of the operations console. `npm run build` writes the app into `../web/static`, which `internal/console/web` embeds into the `talon` binary. The installation never runs Node.

## Rules

- The frontend presents canonical Go projections. It must not compute health, budgets, costs across currencies, effective policy, sessions or dispatch outcomes. When a fact is missing, add a typed read in Go with tests (see `internal/console`), not logic here.
- `src/lib/availability.ts` is the single interpretation of availability states; a field listed as unavailable is never rendered as its number.
- No inline script or style (the console's CSP forbids them). No credential in URLs, storage or the bundle; the only browser storage is the theme preference.

## Workflow

```bash
make console-frontend        # npm ci + build into internal/console/web/static; commit the result
make test-console-frontend   # types, unit tests, and fail if the committed assets differ from a fresh build
make test-browser-console    # Playwright/Chromium against the built binary over a seeded signed installation
```

The build is deterministic for a given lockfile, so CI rebuilds and diffs the committed assets (`scripts/check-console-assets.sh`). Page screenshots for review: `CONSOLE_SCREENSHOTS=<dir> npx playwright test 03-screenshots.spec.js` in `tests/browser`.

`src/api/types.ts` mirrors the Go DTOs; when a DTO changes, update it in the same change.
