# LangChain / LangGraph Integration Examples

Talon can govern LangChain and LangGraph agents through two mechanisms:

## 1. Gateway Proxy (simplest, no SDK)

Point your LangChain `base_url` at Talon's OpenAI-compatible proxy. Talon
automatically applies PII detection, policy evaluation, cost tracking, model
routing, and evidence generation.

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4o-mini",
    base_url="http://localhost:8080/v1/proxy/openai",
    api_key="your-caller-key",
)
response = llm.invoke("What is GDPR Article 30?")
```

Best for: **single LLM calls, stateless usage, quick integration**.

For a full LangGraph walkthrough (safe vs dangerous tools, `filter` vs `block`, model
allowlist denials, and dashboard metrics), open
[`langgraph_talon_tool_governance.ipynb`](langgraph_talon_tool_governance.ipynb).

## 2. Graph Events API (full governance)

Send lifecycle events to `/v1/graph/events` for step-level control,
retry governance, and evidence lineage across multi-step workflows.

**Authentication:** When agent keys are configured in
`talon.config.yaml`, requests require `Authorization: Bearer <agent_key>`.
The Python SDK sets this automatically when you pass `agent_key`.
Do not include `tenant_id` in event payloads when auth is enabled; Talon
derives tenant identity from the bearer key.

**Session continuity:** Generate a `session_id` once per workflow and send the
same value on every graph event (`run_start`, `step_*`, `tool_call`, `retry`,
`run_end`). This keeps graph evidence joinable in session exports and timeline
views.
For LangGraph, emit `step_start`/`step_end` from node callbacks so event
boundaries match actual node execution.

```python
from talon_sdk import TalonClient

talon = TalonClient("http://localhost:8080", agent_key="your-key")
run_id = talon.new_run_id()
session_id = "sess_langgraph_demo_001"
talon.run_start(run_id, "my-agent", framework="langgraph", session_id=session_id)
talon.step_start(run_id, "my-agent", 0, "search_node", session_id=session_id)
# ... execute node ...
talon.step_end(run_id, "my-agent", 0, cost=0.001, session_id=session_id)
talon.run_end(run_id, "my-agent", total_cost=0.001, session_id=session_id)
```

Best for: **LangGraph stateful graphs, multi-step agents, compliance-heavy**.

## Files

| File | Description |
|------|-------------|
| `talon_sdk.py` | Lightweight Python client for graph governance events |
| `langchain_stateless.py` | Single LLM call via gateway proxy + optional events |
| `langgraph_stateful.py` | Multi-step LangGraph agent with per-step governance |
| `langgraph_talon_tool_governance.ipynb` | Colab notebook: LangGraph `ChatOpenAI` through Talon gateway (tool filter/block, model allowlist, audit + metrics) |
| `notebook_example.py` | Colab/Jupyter-ready cells for both patterns |

## Other Supported Patterns

Talon is framework-agnostic. The same governance applies to:

- **OpenAI SDK**: Point `base_url` at `http://localhost:8080/v1/proxy/openai`
- **Anthropic SDK**: Use `http://localhost:8080/v1/proxy/anthropic`
- **MCP clients**: Send tool calls to `POST /mcp` (JSON-RPC 2.0)
- **Custom agents**: Use the graph events API with any HTTP client

## When to Use Which

| Scenario | Recommended Pattern |
|----------|-------------------|
| Single LLM call from notebook | Gateway proxy |
| LangChain chain/pipeline | Gateway proxy |
| LangGraph multi-step graph | Graph events API |
| Custom agent with tool calls | Graph events API |
| Quick proof-of-concept | Gateway proxy |
| EU AI Act compliance audit | Graph events API |
