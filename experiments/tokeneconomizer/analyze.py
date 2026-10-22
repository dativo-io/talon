#!/usr/bin/env python3
"""Compare two real Talon audit exports; never infer provider savings from a mock."""
import json
import sys
from collections import Counter
from pathlib import Path


def records(path):
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("records"), list):
        raise SystemExit(f"{path}: expected Talon audit export object containing records[]")
    ids = [r.get("id") for r in data["records"]]
    if not all(ids) or len(set(ids)) != len(ids):
        raise SystemExit(f"{path}: missing or duplicate evidence IDs")
    return data["records"]


def aggregate(items):
    model_calls = [r for r in items if r.get("model_used")]
    return {
        "evidence_records": len(items),
        "model_calls": len(model_calls),
        "models": dict(Counter(r.get("model_used") for r in model_calls)),
        "input_tokens_reported_by_mock": sum(int(r.get("input_tokens") or 0) for r in model_calls),
        "output_tokens_reported_by_mock": sum(int(r.get("output_tokens") or 0) for r in model_calls),
        "cache_read_tokens_reported_by_mock": sum(int(r.get("cache_read_tokens") or 0) for r in model_calls),
        "cost_attributed_from_mock_tokens": round(sum(float(r.get("cost") or 0) for r in model_calls), 8),
        "blocked_records": sum(r.get("allowed") is False for r in items),
        "errors": sum(bool(r.get("has_error")) for r in items),
        "pricing_basis": dict(Counter(r.get("pricing_basis") or "missing" for r in model_calls)),
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: analyze.py baseline.json after.json")
    before = records(sys.argv[1])
    final = records(sys.argv[2])
    ids = {r["id"] for r in before}
    if not ids.issubset({r["id"] for r in final}):
        raise SystemExit("Evidence store lost baseline records between experiments")
    after = [r for r in final if r["id"] not in ids]
    b, a = aggregate(before), aggregate(after)
    if b["model_calls"] < 3 or a["model_calls"] < 3:
        raise SystemExit(f"Did not observe >=3 real routed model calls in each arm: baseline={b['model_calls']} after={a['model_calls']}")
    result = {
        "source": "Talon signed-evidence export, provider is the REPOSITORY MOCK, not a real LLM",
        "experimental_limitations": [
            "The provider reports simulated cache and token usage; no real API billing is measured.",
            "Three sessions per arm are insufficient for TokenEconomizer's five-session tool-pruning learning threshold.",
            "Task quality and actual productivity savings are not measured by canned mock replies.",
            "Savings inferred from simulated token or pricing counters are NOT evidence of production savings.",
        ],
        "baseline": b,
        "token_economizer_installed": a,
        "mock_reported_input_token_delta": a["input_tokens_reported_by_mock"] - b["input_tokens_reported_by_mock"],
        "mock_reported_cost_delta": round(a["cost_attributed_from_mock_tokens"] - b["cost_attributed_from_mock_tokens"], 8),
        "governance_consistency": {
            "baseline_blocked_records": b["blocked_records"],
            "after_blocked_records": a["blocked_records"],
            "baseline_errors": b["errors"],
            "after_errors": a["errors"],
        },
        "actual_provider_cost_savings": None,
        "actual_quality_change": None,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
