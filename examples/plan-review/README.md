# Plan Review Example — Human-in-the-Loop

Demonstrates Talon's human oversight capability, implementing EU AI Act
Article 14 (human oversight for high-risk AI systems).

## What This Shows

1. Agent receives a query and creates an execution plan
2. Plan is held in `PENDING` state -- not executed until approved
3. Operator reviews the plan via the dashboard or API
4. On approval, the agent executes the plan with full evidence logging

## Setup

```bash
# Build Talon
make build

# Set an LLM provider key
export OPENAI_API_KEY=sk-your-key

# Run the demo
bash examples/plan-review/run.sh
```

## API Endpoints

```bash
# List pending plans
curl http://localhost:8080/v1/plans/pending

# Approve a plan
curl -X POST http://localhost:8080/v1/plans/<plan-id>/approve \
  -H "X-Talon-Key: your-api-key"

# Reject a plan
curl -X POST http://localhost:8080/v1/plans/<plan-id>/reject \
  -H "X-Talon-Key: your-api-key" \
  -d '{"reason": "Too broad — narrow the search scope"}'
```

## EU AI Act Context

Article 14 of the EU AI Act requires that high-risk AI systems be designed to
allow effective human oversight. Talon's plan review gate implements this by:

- Requiring explicit approval before agent execution
- Showing the full execution plan (tools to be called, data to be accessed)
- Recording the approval decision in the evidence trail
- Allowing rejection with a reason (documented for auditors)

The `compliance.human_oversight: "always"` setting in the agent config enables
this for every execution. Use `"on-demand"` for optional review.

## Evidence

After execution, the evidence record includes:

- `plan_review.status`: "approved" or "rejected"
- `plan_review.reviewer`: who approved
- `plan_review.timestamp`: when the decision was made
- Full execution evidence with all the standard fields
