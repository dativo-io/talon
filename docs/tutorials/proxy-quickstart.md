# Tutorial: OpenAI proxy quickstart

Use this path when you already have an app using an OpenAI-compatible SDK and want Talon governance without writing gateway YAML.

## 1) Start Talon quickstart mode

```bash
talon serve --proxy-quickstart --port 8080
```

By default Talon binds `127.0.0.1` and enables:

- `POST /v1/chat/completions`
- `POST /v1/responses`

## 2) Point your app to Talon

```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/v1
export OPENAI_API_KEY=sk-your-key
```

Your app keeps using the OpenAI SDK. Talon is now in the request path.

## 3) Test with curl

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-test" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

Responses API:

```bash
curl -sS http://127.0.0.1:8080/v1/responses \
  -H "Authorization: Bearer sk-test" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","input":"hello"}'
```

## 4) Verify governance evidence

```bash
talon audit list --tenant quickstart --limit 5
```

Look for:

- `tenant_id=quickstart`
- `agent_id=quickstart-local`
- `upstream_auth_mode=client_bearer`

## Behavior notes

- Enforcement mode defaults to `enforce` (shadow optional via `TALON_QUICKSTART_MODE=shadow`).
- PII default action is `redact`.
- Key source precedence: client bearer > `OPENAI_API_KEY` > 401.
- Partial OpenAI compatibility: only chat completions and responses create endpoints are supported at host root.

For production gateway rollout, use `--gateway` and [gateway guides](../guides/add-talon-to-existing-app.md).
