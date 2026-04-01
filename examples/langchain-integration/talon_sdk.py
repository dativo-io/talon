"""
Talon Python SDK — Lightweight client for graph runtime governance.

Sends governance events to Talon's /v1/graph/events endpoint and returns
control decisions. Works from Jupyter notebooks, Colab, standalone scripts,
and production services.

Usage:
    from talon_sdk import TalonClient
    talon = TalonClient("http://localhost:8080", tenant_key="your-key")
    dec = talon.run_start(graph_run_id="gr_1", agent_id="my-agent", framework="langgraph")
    if not dec["allowed"]:
        raise RuntimeError(f"Talon denied: {dec['reasons']}")
"""

import time
import uuid
from typing import Any, Optional

import requests


class TalonClient:
    """Minimal HTTP client for Talon graph governance events."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        tenant_key: str = "",
        tenant_id: str = "default",
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.tenant_key = tenant_key
        self.tenant_id = tenant_id
        self.timeout = timeout
        self._session = requests.Session()
        if tenant_key:
            self._session.headers["Authorization"] = f"Bearer {tenant_key}"
        self._session.headers["Content-Type"] = "application/json"

    def _send_event(self, event: dict[str, Any]) -> dict[str, Any]:
        event.setdefault("tenant_id", self.tenant_id)
        event.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        resp = self._session.post(
            f"{self.base_url}/v1/graph/events",
            json=event,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def run_start(
        self,
        graph_run_id: str,
        agent_id: str,
        framework: str = "custom",
        model: str = "",
        node_count: int = 0,
        planned_steps: Optional[list[str]] = None,
        session_id: str = "",
    ) -> dict[str, Any]:
        return self._send_event({
            "type": "run_start",
            "graph_run_id": graph_run_id,
            "agent_id": agent_id,
            "session_id": session_id,
            "run_meta": {
                "framework": framework,
                "model": model,
                "node_count": node_count,
                "planned_steps": planned_steps or [],
            },
        })

    def step_start(
        self,
        graph_run_id: str,
        agent_id: str,
        step_index: int,
        node_id: str,
        node_name: str = "",
        node_type: str = "llm",
        model: str = "",
        cost_so_far: float = 0.0,
    ) -> dict[str, Any]:
        return self._send_event({
            "type": "step_start",
            "graph_run_id": graph_run_id,
            "agent_id": agent_id,
            "step_index": step_index,
            "node_id": node_id,
            "cost": cost_so_far,
            "node_meta": {
                "name": node_name or node_id,
                "type": node_type,
                "model": model,
            },
        })

    def step_end(
        self,
        graph_run_id: str,
        agent_id: str,
        step_index: int,
        status: str = "completed",
        cost: float = 0.0,
        duration_ms: int = 0,
    ) -> dict[str, Any]:
        return self._send_event({
            "type": "step_end",
            "graph_run_id": graph_run_id,
            "agent_id": agent_id,
            "step_index": step_index,
            "result": {
                "status": status,
                "cost": cost,
                "duration_ms": duration_ms,
            },
        })

    def tool_call(
        self,
        graph_run_id: str,
        agent_id: str,
        step_index: int,
        tool_name: str,
        arguments: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return self._send_event({
            "type": "tool_call",
            "graph_run_id": graph_run_id,
            "agent_id": agent_id,
            "step_index": step_index,
            "tool_meta": {
                "name": tool_name,
                "arguments": arguments or {},
            },
        })

    def retry(
        self,
        graph_run_id: str,
        agent_id: str,
        step_index: int,
        node_id: str,
        error_message: str,
        retry_count: int,
        retryable: bool = True,
        cost_so_far: float = 0.0,
    ) -> dict[str, Any]:
        return self._send_event({
            "type": "retry",
            "graph_run_id": graph_run_id,
            "agent_id": agent_id,
            "step_index": step_index,
            "node_id": node_id,
            "cost": cost_so_far,
            "error": {
                "message": error_message,
                "retryable": retryable,
                "retry_count": retry_count,
            },
        })

    def run_end(
        self,
        graph_run_id: str,
        agent_id: str,
        status: str = "completed",
        total_cost: float = 0.0,
        duration_ms: int = 0,
    ) -> dict[str, Any]:
        return self._send_event({
            "type": "run_end",
            "graph_run_id": graph_run_id,
            "agent_id": agent_id,
            "cost": total_cost,
            "result": {
                "status": status,
                "cost": total_cost,
                "duration_ms": duration_ms,
            },
        })

    @staticmethod
    def new_run_id() -> str:
        return f"gr_{uuid.uuid4().hex[:12]}"
