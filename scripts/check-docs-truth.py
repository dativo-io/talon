#!/usr/bin/env python3
"""Targeted documentation regressions; not an executable runtime proof."""
from pathlib import Path
import re
root = Path(__file__).resolve().parents[1]
def doc(path):
    return (root / path).read_text()
def require(path, needle):
    assert needle in doc(path), f"{path}: missing {needle}"
def forbid(path, pattern):
    assert not re.search(pattern, doc(path)), f"{path}: obsolete or unsafe {pattern}"
require("docs/tutorials/evidence-integrity-demo.md", "Authorization: Bearer $TALON_USE_CASE_KEY")
require("docs/tutorials/evidence-integrity-demo.md", "audit verify --file tampered-evidence.json")
forbid("docs/tutorials/action-gateway-proof.md", r"implemented on Talon main|MCP/native action convergence")
require("docs/tutorials/action-gateway-proof.md", "share the released")
forbid("docs/guides/cost-governance-by-agent.md", r'talon secrets set support-slack-bot-talon-key "\$AGENT_KEY"')
require("docs/guides/cost-governance-by-agent.md", "two identical requests alone do not guarantee")
require("docs/guides/add-talon-to-existing-app.md", "positive daily/monthly/session budget overrides can replace defaults")
require("docs/reference/object-model.md", "There is no `managed_by` field in this release")
require("docs/guides/incident-response-playbook.md", "native run overrides only")
forbid("docs/explanation/what-talon-does-to-your-request.md", r"\*\*Does not buffer streaming responses\.\*\*|No buffering for streams")
require("docs/explanation/what-talon-does-to-your-request.md", "Preventive `redact` and `block`")
forbid("docs/reference/benchmarks.md", r"not benchmarked until Epic")
print("PASS targeted documentation truth regressions")
