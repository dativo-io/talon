"""Reading `n8n execute` output (#575): the execution document and redacted
diagnostics. Used by check.py; regression-tested by test_n8n_output.py.
"""
import json
import re

# Keys never reach a printed diagnostic: Talon keys, bearer values, provider
# keys and long hex secrets are masked.
SECRET = re.compile(r"talon_uc_[0-9A-Za-z_]+|Bearer\s+\S+|sk-[0-9A-Za-z_-]{6,}|\b[0-9a-fA-F]{32,}\b")


def sanitized_tail(raw, lines=25):
    return "\n".join("      | " + SECRET.sub("[redacted]", l)[:300] for l in raw.splitlines()[-lines:])


def execution_document(raw):
    """n8n's execution document in `n8n execute` output: the first top-level
    JSON object, starting a line, that carries data.resultData. Output before
    and after it (log lines, task-runner messages) is diagnostics, never part
    of the document; None when no such document is present."""
    decoder = json.JSONDecoder()
    for m in re.finditer(r"(?m)^\{", raw):
        try:
            doc, _ = decoder.raw_decode(raw, m.start())
        except ValueError:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("data"), dict) and isinstance(doc["data"].get("resultData"), dict):
            return doc
    return None
