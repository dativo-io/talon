# Code Reviewer Example

Code review agent with strict forbidden patterns (no secrets, API keys, passwords in prompts) and lower cost limits.

## Quick run

```bash
export OPENAI_API_KEY=sk-proj-...

talon run --tenant acme --agent code-reviewer --policy examples/code-reviewer/agent.talon.yaml \
  "Review this function for security issues: func auth(user string) { return db.Query(user) }"
```

## Dry run

```bash
talon run --tenant acme --agent code-reviewer --policy examples/code-reviewer/agent.talon.yaml --dry-run \
  "Review the error handling in this module"
```

## Validate

```bash
talon validate -f examples/code-reviewer/agent.talon.yaml
```

## Notes

- `model_tier: 0` keeps default routing to cheaper models when no PII is present.
- Forbidden patterns include `api_key`, `password`, `private_key` to reduce secret leakage in prompts.
- `include_prompts: true` in audit for compliance; adjust if prompts contain sensitive code.
