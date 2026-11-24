"""Checks one scripts/n8n-compat.sh run (#575): what each stock n8n workflow
returned, what Talon forwarded to the mock provider, and Talon's own view.
Prints one PASS or FAIL line per check; exits 1 on any FAIL.

Usage: check.py <run-dir>
"""
import json
import os
import sys

W = sys.argv[1]
REQUESTS = [json.loads(line) for line in open(os.path.join(W, "requests.jsonl"))] if os.path.exists(os.path.join(W, "requests.jsonl")) else []
failures = 0


def check(ok, what):
    global failures
    print(("PASS " if ok else "FAIL ") + what)
    if not ok:
        failures += 1


def forwarded(name):
    start, end = (int(x) for x in open(os.path.join(W, "slice-%s.txt" % name)).read().split())
    return REQUESTS[start:end]


def execution(wid):
    raw = open(os.path.join(W, "out-%s.txt" % wid)).read()
    code = int(open(os.path.join(W, "exit-%s.txt" % wid)).read().strip())
    i = raw.find("\n{\n")
    output = None
    if code == 0 and i >= 0:
        rd = json.loads(raw[i + 1:])["data"]["resultData"]
        output = rd["runData"][rd["lastNodeExecuted"]][0]["data"]["main"][0][0]["json"]
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
    code, output, _ = execution(wid)
    reqs = forwarded(wid)
    check(code == 0 and output == want, "%s: the workflow returns %s (got exit %d, %s)" % (what, json.dumps(want), code, json.dumps(output)))
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
