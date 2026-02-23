# How to run governed LLM calls in CI/CD

Use Talon from GitHub Actions, GitLab CI, or any pipeline so every LLM call (e.g. PR summary, code review, security scan) is audited and cost-controlled. Two options: call the LLM API gateway from the job (no Talon binary in the runner), or call the native API or run `talon run` from the runner.

---

## Option A: LLM API gateway (recommended for CI)

The pipeline job has a **gateway caller API key**. It sends HTTP requests to your Talon server’s gateway; Talon forwards to the real provider and records evidence. No Talon binary is required in the runner.

### 1. Configure a caller for CI

In your gateway config, add a caller (e.g. `ci-openai`) with a dedicated API key and cost limits:

```yaml
gateway:
  callers:
    - name: "ci-openai"
      api_key: "talon-gw-ci-secret"
      tenant_id: "default"
      policy_overrides:
        max_daily_cost: 5.00
        allowed_models: ["gpt-4o-mini"]
```

Store the caller key as a secret in GitHub/GitLab (e.g. `TALON_GATEWAY_KEY`). Store the real OpenAI key in Talon’s vault on the server.

### 2. Point the job at the gateway

Set the base URL to Talon’s gateway. Example for OpenAI chat completions:

```bash
# In GitHub Actions or GitLab CI
export OPENAI_BASE_URL="https://talon.example.com/v1/proxy/openai/v1"
export OPENAI_API_KEY="$TALON_GATEWAY_KEY"   # caller key, not real OpenAI key
```

Then run your existing script or tool that uses the OpenAI SDK; it will call Talon instead of OpenAI. Talon will use the vault-stored real key to forward requests.

**Example step (curl):**

```yaml
# GitHub Actions
- name: Summarize PR with Talon
  env:
    TALON_URL: "https://talon.example.com"
    TALON_GATEWAY_KEY: ${{ secrets.TALON_GATEWAY_KEY }}
  run: |
    curl -s -X POST "$TALON_URL/v1/proxy/openai/v1/chat/completions" \
      -H "Authorization: Bearer $TALON_GATEWAY_KEY" \
      -H "Content-Type: application/json" \
      -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize the main changes in this PR."}]}'
```

### 3. Why this helps compliance

Every LLM call gets an evidence ID and is stored with tenant, caller, cost, and policy decision. For DORA/NIS2 you can demonstrate that automated changes (e.g. PR summaries) are logged and attributable.

---

## Option B: Native API or `talon run`

If the runner can call your Talon server or run the Talon binary:

- **REST:** `POST https://talon.example.com/v1/chat/completions` with `X-Talon-Key: <talon-api-key>` and body `{"model":"gpt-4o","messages":[...]}`. Same evidence and cost tracking as native agents.
- **CLI:** Install Talon on the runner and run `talon run "Summarize this PR"` with appropriate policy and secrets. Use `TALON_DATA_DIR` and vault/keys so the runner has access.

Use Option B when you need full agent features (tools, memory) or when the pipeline runner is already a controlled environment with Talon installed.
