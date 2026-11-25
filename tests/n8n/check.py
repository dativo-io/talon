"""Checks one scripts/n8n-compat.sh run (#575): what each stock n8n workflow
returned, what Talon forwarded to the mock provider, and Talon's own view.
Prints one PASS or FAIL line per check; exits 1 on any FAIL.

Usage: check.py <run-dir>
"""
import json
import os
import sys

from n8n_output import execution_document, sanitized_tail  # noqa: E402


def load(name):
    path = os.path.join(W, name)
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


W = sys.argv[1]
REQUESTS = load("requests.jsonl")
BACKUP = load("requests-backup.jsonl")
failures = 0


def check(ok, what):
    global failures
    print(("PASS " if ok else "FAIL ") + what)
    if not ok:
        failures += 1


def forwarded(name, log=None, prefix="slice"):
    start, end = (int(x) for x in open(os.path.join(W, "%s-%s.txt" % (prefix, name))).read().split())
    return (REQUESTS if log is None else log)[start:end]


def execution(wid):
    """(exit code, last node's first output item or None, raw output). A
    successful exit without a well-formed execution document is a failure
    with the reason printed, never a parse crash."""
    raw = open(os.path.join(W, "out-%s.txt" % wid)).read()
    code = int(open(os.path.join(W, "exit-%s.txt" % wid)).read().strip())
    if code != 0:
        return code, None, raw
    doc = execution_document(raw)
    if doc is None:
        check(False, "%s: n8n printed no execution document\n%s" % (wid, sanitized_tail(raw)))
        return code, None, raw
    rd = doc["data"]["resultData"]
    try:
        output = rd["runData"][rd["lastNodeExecuted"]][0]["data"]["main"][0][0]["json"]
    except (KeyError, IndexError, TypeError):
        check(False, "%s: the execution document has no output for its last node (%r)\n%s" % (wid, rd.get("lastNodeExecuted"), sanitized_tail(raw)))
        return code, None, raw
    return code, output, raw


# --- Executed workflows: stock nodes, the guide's credential -------------
OK_CASES = [
    ("w1chainrespapi01", "Basic LLM Chain, Chat Model v1.3 defaults (Responses API)", {"text": "Hello"}, ["/v1/responses"]),
    ("w2chaincompl0001", "Basic LLM Chain, Responses API off (Chat Completions)", {"text": "Hello"}, ["/v1/chat/completions"]),
    ("w3agenttool00001", "AI Agent v3.1 with a tool, two-step tool round trip", {"output": "The answer is 42."}, ["/v1/responses", "/v1/responses"]),
    ("w4chainjson00001", "JSON response format", {"greeting": "hello", "language": "en"}, ["/v1/chat/completions"]),
    ("w6agentforbid001", "AI Agent with a tool the company forbids", {"output": "Hello"}, ["/v1/responses"]),
]
for wid, what, want, paths in OK_CASES:
    code, output, raw = execution(wid)
    reqs = forwarded(wid)
    ok = code == 0 and output == want
    check(ok, "%s: the workflow returns %s (got exit %d, %s)%s" % (what, json.dumps(want), code, json.dumps(output), "" if ok else "\n" + sanitized_tail(raw)))
    check([r["path"] for r in reqs] == paths, "%s: Talon forwarded %s (got %s)" % (what, paths, [r["path"] for r in reqs]))

reqs = forwarded("w3agenttool00001")
check(len(reqs) == 2 and reqs[0].get("tools") == ["Calculator"] and reqs[1].get("has_tool_output") is True,
      "AI Agent: the tool definition reached the model and the tool's result came back to it")
reqs = forwarded("w4chainjson00001")
check(len(reqs) == 1 and reqs[0].get("json") is True, "JSON response format: the JSON request reached the model")
reqs = forwarded("w6agentforbid001")
check(len(reqs) == 1 and reqs[0].get("tools") == [], "forbidden tool (delete_*): removed from the request before the model saw it")

code, output, raw = execution("w8httpnode000001")
reqs = forwarded("w8httpnode000001")
content = ((output or {}).get("choices") or [{}])[0].get("message", {}).get("content")
check(code == 0 and content == "Hello", "HTTP Request node with Header Auth: answered through Talon (got exit %d, content %r)" % (code, content))
check([r["path"] for r in reqs] == ["/v1/chat/completions"], "HTTP Request node: Talon forwarded /v1/chat/completions")

# --- The company policy denies before any provider call -----------------
for wid, what in (("w5chainpii000001", "Chat Completions"), ("w7chainpiiresp01", "Responses API")):
    code, _, raw = execution(wid)
    check(code != 0, "personal data (%s): the n8n node fails" % what)
    check("PII" in raw, "personal data (%s): Talon's reason reaches n8n's error details" % what)
    check(forwarded(wid) == [], "personal data (%s): nothing reached the provider" % what)

# --- Fallback stays governed --------------------------------------------
# n8n-managed: the agent's primary model is one Talon refuses (unpriced under
# the company cost cap); its fallback model, on the same Talon credential,
# answers. Only the fallback request reached the provider.
code, output, raw = execution("wBn8nfallback001")
reqs = forwarded("wBn8nfallback001")
ok = code == 0 and output == {"output": "Hello"}
check(ok, "n8n fallback model on the Talon credential: the agent answers through its fallback (got exit %d, %s)%s" % (code, json.dumps(output), "" if ok else "\n" + sanitized_tail(raw)))
check([r.get("model") for r in reqs] == ["gpt-4o-mini"],
      "n8n fallback: Talon refused the primary model before any dispatch; only the fallback request reached the provider (got %s)" % [r.get("model") for r in reqs])
# Talon-managed: the upstream answers the model 503; Talon's provider fallback
# chain sends it to the backup provider; n8n sees one answer.
code, output, raw = execution("wCtalonfallback1")
reqs, backup = forwarded("wCtalonfallback1"), forwarded("wCtalonfallback1", BACKUP, "slice-backup")
ok = code == 0 and output == {"text": "Hello"}
check(ok, "Talon provider fallback: the workflow gets the backup provider's answer (got exit %d, %s)%s" % (code, json.dumps(output), "" if ok else "\n" + sanitized_tail(raw)))
check([(r.get("model"), r.get("status")) for r in reqs] == [("gpt-4o", 503)] and [r.get("model") for r in backup] == ["gpt-4o-mini"],
      "Talon provider fallback: the primary failed once (503), the backup provider answered the rewritten model (primary %s, backup %s)"
      % ([(r.get("model"), r.get("status")) for r in reqs], [r.get("model") for r in backup]))

# --- Streaming through a streaming webhook and the AI Agent -------------
for path, upstream in (("talon-stream-responses", "/v1/responses"), ("talon-stream-completions", "/v1/chat/completions")):
    body = open(os.path.join(W, "body-%s.txt" % path)).read()
    events = [json.loads(line) for line in body.replace("}{", "}\n{").splitlines() if line.strip().startswith("{")]
    text = "".join(e.get("content", "") for e in events if e.get("type") == "item")
    reqs = forwarded(path)
    check(text == "Hello" and any(e.get("type") == "end" for e in events),
          "streaming (%s): n8n streamed the answer to its caller (got %r)" % (upstream, text))
    check([r["path"] for r in reqs] == [upstream] and all(r["stream"] for r in reqs),
          "streaming (%s): Talon forwarded a streaming request" % upstream)

# --- Talon's own view of the use case -----------------------------------
show = open(os.path.join(W, "agents-show.txt")).read()
check("Status      Working" in show, "talon agents show: the n8n use case is Working")
check("(signature valid)" in show, "talon agents show: its newest record carries a valid signature")

if failures:
    print("FAIL n8n-compat: %d check(s) failed" % failures)
else:
    print("PASS n8n-compat: every check passed")
sys.exit(1 if failures else 0)
