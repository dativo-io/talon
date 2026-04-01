"""
LangChain Stateless + Talon Governance — Single LLM Call

Demonstrates the simplest integration: a single LangChain LLM call
governed by Talon. This uses Talon as an OpenAI-compatible gateway
so LangChain's base_url points to Talon's proxy endpoint.

No graph events needed — Talon's gateway pipeline handles policy,
PII detection, cost tracking, and evidence generation automatically.

Works in notebooks and standalone scripts.

Prerequisites:
    pip install langchain-openai requests
    export TALON_URL=http://localhost:8080
    export TALON_CALLER_KEY=your-caller-api-key
    export OPENAI_API_KEY=your-openai-key  # stored in Talon vault

    # Start Talon with gateway:
    talon serve --gateway --port 8080
"""

import os

from langchain_openai import ChatOpenAI


def run_stateless_call():
    """Single governed LLM call through Talon gateway."""

    talon_url = os.environ.get("TALON_URL", "http://localhost:8080")
    caller_key = os.environ.get("TALON_CALLER_KEY", "")

    # Point LangChain at Talon's OpenAI-compatible proxy.
    # Talon handles: PII detection, policy evaluation, cost tracking,
    # model routing, evidence generation — all transparently.
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        base_url=f"{talon_url}/v1/proxy/openai",
        api_key=caller_key,
        default_headers={
            "X-Talon-Session-ID": "notebook-session-1",
            "X-Talon-Reasoning": "stateless-langchain-example",
        },
    )

    response = llm.invoke("Summarize the key requirements of the EU AI Act for SMBs.")

    print(f"Response: {response.content}")
    print(f"Model: {response.response_metadata.get('model_name', 'unknown')}")

    return response


def run_with_governance_events():
    """Single LLM call with explicit Talon governance events.

    Use this pattern when you want step-level evidence and control
    beyond what the gateway proxy provides automatically.
    """
    from talon_sdk import TalonClient

    talon = TalonClient(
        base_url=os.environ.get("TALON_URL", "http://localhost:8080"),
        tenant_key=os.environ.get("TALON_TENANT_KEY", ""),
    )

    run_id = talon.new_run_id()

    # Notify Talon (even for a single-step "run")
    dec = talon.run_start(
        graph_run_id=run_id,
        agent_id="summarizer",
        framework="langchain",
        model="gpt-4o-mini",
        node_count=1,
        planned_steps=["llm_call"],
    )
    if not dec["allowed"]:
        print(f"Denied: {dec.get('reasons', [])}")
        return None

    talon.step_start(run_id, "summarizer", 0, "llm_call", node_type="llm", model="gpt-4o-mini")

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    response = llm.invoke("What are DORA requirements for ICT risk management?")

    talon.step_end(run_id, "summarizer", 0, status="completed", cost=0.0005, duration_ms=800)
    talon.run_end(run_id, "summarizer", status="completed", total_cost=0.0005, duration_ms=800)

    print(f"Response: {response.content}")
    print(f"Graph run: {run_id}")
    return response


if __name__ == "__main__":
    print("=== Gateway proxy mode (simplest) ===")
    print("Point LangChain base_url at Talon — governance is automatic.\n")
    # run_stateless_call()  # Uncomment when Talon is running

    print("\n=== Explicit governance events mode ===")
    print("Send events to /v1/graph/events for step-level control.\n")
    # run_with_governance_events()  # Uncomment when Talon is running
