# Integrating Talon with LangChain and LangGraph

Talon governs AI agent execution with policy enforcement, PII detection, cost
control, and signed audit trails. This guide covers two integration tracks and
shows how to use each from notebooks and standalone applications.

---

## Architecture Overview

```
┌──────────────────┐     ┌───────────────────────────────────────┐
│  Your Agent Code │     │           Talon Server                │
│                  │     │                                       │
│  LangChain ──────┼──→──┤  /v1/proxy/openai   (Gateway Proxy)  │
│  (stateless)     │     │     ↓ PII scan → Policy → Route →    │
│                  │     │       Evidence → Forward to LLM       │
│  LangGraph ──────┼──→──┤                                       │
│  (stateful)      │     │  /v1/graph/events   (Graph Events)   │
│                  │     │     ↓ Policy → Evidence → Decision    │
│  OpenAI SDK ─────┼──→──┤                                       │
│  MCP clients ────┼──→──┤  /mcp               (MCP tools/call) │
└──────────────────┘     └───────────────────────────────────────┘
```

---

## Track 1: LangChain Stateless — Gateway Proxy

The simplest integration. Point LangChain's `base_url` at Talon's
OpenAI-compatible proxy. No SDK, no code changes beyond the URL.

### What Talon handles automatically

- PII detection and optional redaction on input and output
- Policy evaluation (cost limits, rate limits, time restrictions)
- Model routing with EU sovereignty enforcement
- Cost tracking per tenant/agent
- HMAC-signed evidence record per request

### Notebook usage (Jupyter / Colab)

```python
# Cell 1: Install
# !pip install langchain-openai

# Cell 2: Configure and call
import os
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0,
    base_url="http://localhost:8080/v1/proxy/openai",
    api_key=os.environ.get("TALON_CALLER_KEY", "your-caller-key"),
    default_headers={
        "X-Talon-Session-ID": "notebook-session-1",
    },
)

response = llm.invoke("Summarize EU AI Act requirements for SMBs.")
print(response.content)
```

### Standalone application usage

```python
import os
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0,
    base_url=os.environ["TALON_URL"] + "/v1/proxy/openai",
    api_key=os.environ["TALON_CALLER_KEY"],
    default_headers={
        "X-Talon-Session-ID": "worker-session-1",
        "X-Talon-Reasoning": "batch-summarization",
    },
)

response = llm.invoke("What are the key DORA requirements?")
print(response.content)
```

### Expected evidence output

Each request creates one evidence record with:

```json
{
  "id": "req_abc123",
  "correlation_id": "gw_xyz789",
  "session_id": "notebook-session-1",
  "tenant_id": "default",
  "invocation_type": "gateway",
  "policy_decision": {"allowed": true, "action": "allow"},
  "execution": {
    "model_used": "gpt-4o-mini",
    "cost": 0.0003,
    "duration_ms": 1200
  },
  "classification": {"input_tier": 0, "pii_detected": []}
}
```

### Failure behavior

- **Policy deny**: HTTP 403 with `{"error": "policy denied: daily limit exceeded"}`
- **PII blocked**: HTTP 403 with `{"error": "PII detected in input"}`
- **Rate limited**: HTTP 429 with retry-after header

---

## Track 2: LangGraph Stateful — Graph Events API

For multi-step agents that need per-step governance, retry control,
and graph-level evidence lineage.

### Authentication

The `/v1/graph/events` endpoint is protected by tenant key authentication.
When `tenant_keys` are configured in `talon.config.yaml`, requests must
include `Authorization: Bearer <tenant_key>`. In dev mode (no tenant keys
configured), the endpoint is open.

The Python SDK handles this automatically when you pass `tenant_key`:

```python
talon = TalonClient("http://localhost:8080", tenant_key="your-tenant-key")
# All requests include: Authorization: Bearer your-tenant-key
```

For raw HTTP calls (curl, requests):

```bash
curl -X POST http://localhost:8080/v1/graph/events \
  -H "Authorization: Bearer your-tenant-key" \
  -H "Content-Type: application/json" \
  -d '{"type": "run_start", "graph_run_id": "gr_001", ...}'
```

### Setup

```python
# !pip install langgraph langchain-openai requests

# Copy talon_sdk.py from examples/langchain-integration/
from talon_sdk import TalonClient

talon = TalonClient(
    base_url="http://localhost:8080",
    tenant_key="your-tenant-key",
)
```

### Event lifecycle

```
run_start ──→ step_start ──→ [tool_call] ──→ step_end ──→ ... ──→ run_end
                                   │
                                   └──→ [retry] (on failure)
```

Each event returns a Decision:

```json
{
  "action": "allow",
  "allowed": true,
  "reasons": [],
  "evidence_id": "ev_abc123"
}
```

Currently emitted actions: `allow`, `deny`. The following actions are
reserved for Phase 2 and not yet emitted by the adapter: `abort`,
`override_model`, `mutate_args`, `require_review`, `retry`.

The `evidence_id` field is populated when the evidence store is configured,
linking the decision to its audit record.

### Notebook usage (Jupyter / Colab)

```python
import time
from talon_sdk import TalonClient
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from typing import TypedDict

talon = TalonClient("http://localhost:8080", tenant_key="your-key")

class State(TypedDict):
    query: str
    result: str

def search(state: State) -> State:
    dec = talon.tool_call(state["_run_id"], "agent", 0, "web_search",
                          {"query": state["query"]})
    if not dec["allowed"]:
        raise RuntimeError(f"Denied: {dec['reasons']}")
    return {**state, "result": f"Found: {state['query']}"}

def answer(state: State) -> State:
    llm = ChatOpenAI(model="gpt-4o-mini")
    resp = llm.invoke(f"Answer from: {state['result']}")
    return {**state, "result": resp.content}

graph = StateGraph(State)
graph.add_node("search", search)
graph.add_node("answer", answer)
graph.set_entry_point("search")
graph.add_edge("search", "answer")
graph.add_edge("answer", END)
app = graph.compile()

# Governed execution
run_id = talon.new_run_id()
talon.run_start(run_id, "agent", framework="langgraph", node_count=2)

talon.step_start(run_id, "agent", 0, "search", node_type="tool")
result = app.invoke({"query": "EU compliance 2026", "_run_id": run_id})
talon.step_end(run_id, "agent", 0)

talon.step_start(run_id, "agent", 1, "answer", node_type="llm")
talon.step_end(run_id, "agent", 1, cost=0.001)

talon.run_end(run_id, "agent", total_cost=0.001)
print(result["result"])
```

### Standalone application usage

```python
import os
import time
from talon_sdk import TalonClient

talon = TalonClient(
    base_url=os.environ["TALON_URL"],
    tenant_key=os.environ["TALON_TENANT_KEY"],
)

def governed_pipeline(query: str):
    run_id = talon.new_run_id()

    dec = talon.run_start(run_id, "pipeline-agent", framework="langgraph",
                          node_count=3, planned_steps=["fetch", "process", "store"])
    if not dec["allowed"]:
        return {"error": dec["reasons"]}

    total_cost = 0.0
    start = time.time()

    for i, step_name in enumerate(["fetch", "process", "store"]):
        dec = talon.step_start(run_id, "pipeline-agent", i, step_name)
        if not dec["allowed"]:
            talon.run_end(run_id, "pipeline-agent", status="aborted")
            return {"error": f"Step {step_name} denied"}

        # ... execute step logic ...
        step_cost = 0.001
        total_cost += step_cost
        talon.step_end(run_id, "pipeline-agent", i, cost=step_cost)

    duration_ms = int((time.time() - start) * 1000)
    talon.run_end(run_id, "pipeline-agent", total_cost=total_cost, duration_ms=duration_ms)
    return {"status": "completed", "run_id": run_id}

if __name__ == "__main__":
    result = governed_pipeline("Process Q1 compliance data")
    print(result)
```

### Expected evidence output

Graph events produce both step-level and run-level evidence:

```json
{
  "id": "req_run123",
  "correlation_id": "gr_abc12345678",
  "graph_run_id": "gr_abc12345678",
  "invocation_type": "graph_run",
  "execution": {
    "cost": 0.003,
    "duration_ms": 4500,
    "tools_called": ["web_search"]
  }
}
```

Step evidence is linked by `correlation_id` = `graph_run_id`:

```json
{
  "id": "step_xyz456",
  "correlation_id": "gr_abc12345678",
  "step_index": 0,
  "type": "tool_call",
  "tool_name": "web_search",
  "status": "completed"
}
```

### Failure and deny behavior

- **Step denied**: Decision has `{"allowed": false, "action": "deny", "reasons": [...]}`
- **Retry limit exceeded**: Decision has `{"allowed": false, "reasons": ["retry_count 4 exceeds max_retries_per_node 3"]}`
- **Budget exceeded mid-run**: Decision has `{"allowed": false, "reasons": ["cost_so_far 5.0001 exceeds max_cost_per_run 5.0000"]}`
- **Tool blocked**: Tool-specific deny from OPA tool_access policy

The external runtime **must** respect deny/abort decisions and stop execution.

---

## Other Supported Patterns

### OpenAI SDK (Python)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1/proxy/openai",
    api_key="your-caller-key",
)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

### MCP Tool Invocation

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer your-tenant-key" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "web_search", "arguments": {"query": "test"}},
    "id": 1
  }'
```

### When to use which pattern

| Scenario | Pattern | Why |
|----------|---------|-----|
| Single LLM call | Gateway proxy | Zero friction, automatic governance |
| LangChain chain | Gateway proxy | Each LLM call governed individually |
| LangGraph graph | Graph events | Step-level control, lineage, retry governance |
| Custom multi-step agent | Graph events | Full lifecycle control |
| MCP tool execution | MCP endpoint | Native tool governance |
| Quick PoC / demo | Gateway proxy | Fastest to set up |
| EU AI Act compliance audit | Graph events | Full transparency and traceability |

---

## Configuration

### `.talon.yaml` policy for graph-governed agents

```yaml
agent:
  name: my-graph-agent
  model_tier: 1

policies:
  cost_limits:
    per_request: 2.0
    daily: 50.0
    monthly: 500.0
  resource_limits:
    max_iterations: 20       # max graph steps
    max_cost_per_run: 5.0    # abort if cost exceeds
    max_retries_per_node: 3  # retry governance
  rate_limits:
    requests_per_minute: 60

capabilities:
  allowed_tools:
    - web_search
    - calculator
    - sql_database_query

compliance:
  frameworks: [gdpr, eu-ai-act]
  human_oversight: on-demand
```

### `talon.config.yaml` server settings

```yaml
server:
  port: 8080
  admin_key: "your-admin-key"
  tenant_keys:
    default: "your-tenant-key"
```
