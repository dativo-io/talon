"""
LangGraph + Talon Governance — Stateful Multi-Step Agent

Demonstrates how a LangGraph graph executor sends governance events
to Talon at each lifecycle point (run_start, step_start/end, tool_call,
retry, run_end). Works in notebooks and standalone scripts.

Prerequisites:
    pip install langgraph langchain-openai requests
    export TALON_URL=http://localhost:8080
    export TALON_TENANT_KEY=your-tenant-key
    export OPENAI_API_KEY=your-key

    # Start Talon:
    talon serve --port 8080
"""

import os
import time

from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from typing import TypedDict

from talon_sdk import TalonClient

# --- Talon client setup ---
talon = TalonClient(
    base_url=os.environ.get("TALON_URL", "http://localhost:8080"),
    tenant_key=os.environ.get("TALON_TENANT_KEY", ""),
    tenant_id=os.environ.get("TALON_TENANT_ID", "default"),
)

# --- LangGraph state ---
class AgentState(TypedDict):
    query: str
    search_result: str
    answer: str


# --- LangGraph nodes ---
def search_node(state: AgentState) -> AgentState:
    """Simulate a search tool call."""
    # Check with Talon before tool execution
    dec = talon.tool_call(
        graph_run_id=state.get("_run_id", ""),
        agent_id="research-agent",
        step_index=1,
        tool_name="web_search",
        arguments={"query": state["query"]},
    )
    if not dec["allowed"]:
        raise RuntimeError(f"Talon denied tool call: {dec.get('reasons', [])}")

    # Simulate search
    return {**state, "search_result": f"Results for: {state['query']}"}


def answer_node(state: AgentState) -> AgentState:
    """Generate answer using LLM."""
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    resp = llm.invoke(f"Answer based on: {state['search_result']}")
    return {**state, "answer": resp.content}


# --- Build graph ---
def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("search", search_node)
    graph.add_node("answer", answer_node)
    graph.set_entry_point("search")
    graph.add_edge("search", "answer")
    graph.add_edge("answer", END)
    return graph.compile()


# --- Governed execution ---
def run_governed(query: str):
    run_id = talon.new_run_id()
    session_id = f"sess_{run_id}"

    # 1) Notify Talon of run start
    dec = talon.run_start(
        graph_run_id=run_id,
        agent_id="research-agent",
        framework="langgraph",
        model="gpt-4o-mini",
        node_count=2,
        planned_steps=["search", "answer"],
        session_id=session_id,
    )
    if not dec["allowed"]:
        print(f"Run denied by Talon: {dec.get('reasons', [])}")
        return None

    app = build_graph()
    start = time.time()
    total_cost = 0.0

    try:
        # 2) Step: search
        talon.step_start(run_id, "research-agent", 0, "search", node_type="tool", session_id=session_id)
        result = app.invoke({"query": query, "_run_id": run_id})
        talon.step_end(run_id, "research-agent", 0, status="completed", session_id=session_id)

        # 3) Step: answer
        talon.step_start(run_id, "research-agent", 1, "answer", node_type="llm", model="gpt-4o-mini", session_id=session_id)
        talon.step_end(run_id, "research-agent", 1, status="completed", cost=0.001, session_id=session_id)
        total_cost += 0.001

        # 4) Run complete
        duration_ms = int((time.time() - start) * 1000)
        talon.run_end(run_id, "research-agent", status="completed", total_cost=total_cost, duration_ms=duration_ms, session_id=session_id)

        print(f"Answer: {result.get('answer', 'N/A')}")
        print(f"Graph run: {run_id}, cost: ${total_cost:.4f}, duration: {duration_ms}ms")
        return result

    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        talon.run_end(run_id, "research-agent", status="failed", total_cost=total_cost, duration_ms=duration_ms, session_id=session_id)
        print(f"Run failed: {e}")
        raise


if __name__ == "__main__":
    run_governed("What are the latest GDPR enforcement actions in 2026?")
