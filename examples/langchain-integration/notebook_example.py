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
TALON_AGENT_KEY = os.environ.get("TALON_AGENT_KEY", "")


# ============================================================
# Cell 2: LangChain Stateless — Gateway Proxy (simplest)
# ============================================================

def cell_langchain_stateless():
    """Single LLM call governed by Talon gateway. No SDK needed."""
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        # Trailing /v1 required (#345): the OpenAI client appends /chat/completions.
        base_url=f"{TALON_URL}/v1/proxy/openai/v1",
        api_key=TALON_AGENT_KEY,
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
    from typing import TypedDict

    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, StateGraph
    from talon_sdk import TalonClient

    talon = TalonClient(TALON_URL, TALON_AGENT_KEY)
    run_id = talon.new_run_id()
    session_id = f"sess_{run_id}"

    class State(TypedDict):
        question: str
        context: str
        answer: str

    def retrieve(state: State) -> State:
        step_index = 0
        talon.step_start(run_id, "qa-agent", step_index, "retrieve", node_type="tool", session_id=session_id)
        dec = talon.tool_call(run_id, "qa-agent", step_index, "retriever", {"query": state["question"]}, session_id=session_id)
        if not dec["allowed"]:
            raise RuntimeError(f"Tool denied: {dec.get('reasons')}")
        talon.step_end(run_id, "qa-agent", step_index, session_id=session_id)
        return {**state, "context": f"Retrieved context for: {state['question']}"}

    def generate(state: State) -> State:
        step_index = 1
        talon.step_start(run_id, "qa-agent", step_index, "generate", node_type="llm", model="gpt-4o-mini", session_id=session_id)
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        resp = llm.invoke(f"Answer using context: {state['context']}\nQuestion: {state['question']}")
        talon.step_end(run_id, "qa-agent", step_index, cost=0.001, session_id=session_id)
        return {**state, "answer": resp.content}

    graph = StateGraph(State)
    graph.add_node("retrieve", retrieve)
    graph.add_node("generate", generate)
    graph.set_entry_point("retrieve")
    graph.add_edge("retrieve", "generate")
    graph.add_edge("generate", END)
    app = graph.compile()

    dec = talon.run_start(run_id, "qa-agent", framework="langgraph", model="gpt-4o-mini", node_count=2, session_id=session_id)
    if not dec["allowed"]:
        print(f"Denied: {dec['reasons']}")
        return

    start = time.time()
    result = app.invoke({"question": "What is NIS2?"})
    duration_ms = int((time.time() - start) * 1000)
    talon.run_end(run_id, "qa-agent", total_cost=0.001, duration_ms=duration_ms, session_id=session_id)

    print(f"Answer: {result['answer']}")
    print(f"Run: {run_id}, duration: {duration_ms}ms")
    return result


# ============================================================
# Cell 4: Run examples (uncomment the one you want)
# ============================================================

# cell_langchain_stateless()
# cell_langgraph_stateful()
