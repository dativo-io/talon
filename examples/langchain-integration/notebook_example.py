"""
Talon Governance — Notebook-Ready Example

Copy-paste this into a Jupyter notebook or Google Colab cell.
Works with both LangGraph (stateful) and LangChain (stateless) patterns.

Cell 1: Setup
Cell 2: LangChain stateless (gateway proxy)
Cell 3: LangGraph stateful with governance events
"""

# ============================================================
# Cell 1: Setup
# ============================================================

# !pip install langchain-openai langgraph requests

import os

# Configure these for your environment:
TALON_URL = os.environ.get("TALON_URL", "http://localhost:8080")
TALON_TENANT_KEY = os.environ.get("TALON_TENANT_KEY", "")
TALON_CALLER_KEY = os.environ.get("TALON_CALLER_KEY", "")


# ============================================================
# Cell 2: LangChain Stateless — Gateway Proxy (simplest)
# ============================================================

def cell_langchain_stateless():
    """Single LLM call governed by Talon gateway. No SDK needed."""
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        base_url=f"{TALON_URL}/v1/proxy/openai",
        api_key=TALON_CALLER_KEY,
        default_headers={"X-Talon-Session-ID": "notebook-demo"},
    )
    response = llm.invoke("What is GDPR Article 30?")
    print(response.content)
    return response


# ============================================================
# Cell 3: LangGraph Stateful — Governance Events
# ============================================================

def cell_langgraph_stateful():
    """Multi-step graph agent with per-step Talon governance."""
    import time
    from talon_sdk import TalonClient
    from langchain_openai import ChatOpenAI
    from langgraph.graph import StateGraph, END
    from typing import TypedDict

    talon = TalonClient(TALON_URL, TALON_TENANT_KEY)

    class State(TypedDict):
        question: str
        context: str
        answer: str

    def retrieve(state: State) -> State:
        dec = talon.tool_call(state["_run_id"], "qa-agent", 0, "retriever", {"query": state["question"]})
        if not dec["allowed"]:
            raise RuntimeError(f"Tool denied: {dec.get('reasons')}")
        return {**state, "context": f"Retrieved context for: {state['question']}"}

    def generate(state: State) -> State:
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        resp = llm.invoke(f"Answer using context: {state['context']}\nQuestion: {state['question']}")
        return {**state, "answer": resp.content}

    graph = StateGraph(State)
    graph.add_node("retrieve", retrieve)
    graph.add_node("generate", generate)
    graph.set_entry_point("retrieve")
    graph.add_edge("retrieve", "generate")
    graph.add_edge("generate", END)
    app = graph.compile()

    run_id = talon.new_run_id()
    dec = talon.run_start(run_id, "qa-agent", framework="langgraph", model="gpt-4o-mini", node_count=2)
    if not dec["allowed"]:
        print(f"Denied: {dec['reasons']}")
        return

    start = time.time()
    talon.step_start(run_id, "qa-agent", 0, "retrieve", node_type="tool")
    result = app.invoke({"question": "What is NIS2?", "_run_id": run_id})
    talon.step_end(run_id, "qa-agent", 0)
    talon.step_start(run_id, "qa-agent", 1, "generate", node_type="llm", model="gpt-4o-mini")
    talon.step_end(run_id, "qa-agent", 1, cost=0.001)
    duration_ms = int((time.time() - start) * 1000)
    talon.run_end(run_id, "qa-agent", total_cost=0.001, duration_ms=duration_ms)

    print(f"Answer: {result['answer']}")
    print(f"Run: {run_id}, duration: {duration_ms}ms")
    return result


# ============================================================
# Cell 4: Run examples (uncomment the one you want)
# ============================================================

# cell_langchain_stateless()
# cell_langgraph_stateful()
