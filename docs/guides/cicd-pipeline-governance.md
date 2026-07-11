# How to run governed LLM calls in CI/CD

Use Talon from GitHub Actions, GitLab CI, or any pipeline so every LLM call (e.g. PR summary, code review, security scan) is audited and cost-controlled. Two options: call the LLM API gateway from the job (no Talon binary in the runner), or call the native API or run `talon run` from the runner.

---

## Option A: LLM API gateway (recommended for CI)

The pipeline job has its own **agent key** — CI is one AI use case with one agent.talon.yaml (#266). It sends HTTP requests to your Talon server's gateway; Talon forwards to the real provider and records evidence. No Talon binary is required in the runner.

### 1. Configure an agent for CI

Create an agent file for the pipeline (e.g. `ci-openai`) with its own cost limits, and mint its key:

```yaml
# ci-openai/agent.talon.yaml
agent:
  name: ci-openai
  version: 1.0.0
  key:
    secret_name: "ci-openai-talon-key"
policies:
  cost_limits:
    daily: 5.00
  models:
    allowed: ["gpt-4o-mini"]
```

```bash
talon secrets set ci-openai-talon-key "$(openssl rand -hex 24)"
```

Store that key value as a secret in GitHub/GitLab (e.g. `TALON_GATEWAY_KEY`). Store the real OpenAI key in Talon’s vault on the server.

### 2. Point the job at the gateway

Set the base URL to Talon’s gateway. Example for OpenAI chat completions:

```bash
# In GitHub Actions or GitLab CI
export OPENAI_BASE_URL="https://talon.example.com/v1/proxy/openai/v1"
export OPENAI_API_KEY="$TALON_GATEWAY_KEY"   # agent key, not real OpenAI key
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

Every LLM call gets an evidence ID and is stored with tenant, agent, cost, and policy decision. For DORA/NIS2 you can demonstrate that automated changes (e.g. PR summaries) are logged and attributable.

---

## Option B: Native API or `talon run`

If the runner can call your Talon server or run the Talon binary:

- **REST:** `POST https://talon.example.com/v1/chat/completions` with `Authorization: Bearer <tenant-key>` and body `{"model":"gpt-4o","messages":[...]}`. Same evidence and cost tracking as native agents.
- **CLI:** Install Talon on the runner and run `talon run "Summarize this PR"` with appropriate policy and secrets. Use `TALON_DATA_DIR` and vault/keys so the runner has access.

Use Option B when you need full agent features (tools, memory) or when the pipeline runner is already a controlled environment with Talon installed.

---

## You're done

You now have CI/CD jobs calling Talon (gateway or native) so every LLM call is logged and cost-controlled. Talon is recording evidence for each request from your pipeline.

**Next steps:**

| I want to… | Doc |
|------------|-----|
| Export evidence from Talon for auditors | [How to export evidence for auditors](compliance-export-runbook.md) |
| Cap cost for the CI caller | [How to cap daily spend per team or application](cost-governance-by-agent.md) |
| Add Talon in front of another app | [Add Talon to your existing app](add-talon-to-existing-app.md) |
| Understand the request lifecycle | [What Talon does to your request](../explanation/what-talon-does-to-your-request.md) |
