"""OpenAI-compatible mock provider for the n8n x Talon compatibility harness.

Answers Chat Completions and Responses API requests (streaming and not),
calls the first offered tool once, returns JSON when a JSON format is asked
for, and appends what Talon forwarded to requests.jsonl. Deterministic; no
model, no network.
"""
import http.server
import json
import sys
import time

LOG = sys.argv[2] if len(sys.argv) > 2 else "requests.jsonl"
USAGE_CC = {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}
USAGE_R = {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16}


def tool_names_cc(body):
    return [t.get("function", {}).get("name") for t in body.get("tools") or [] if t.get("type") == "function"]


def tool_names_r(body):
    return [t.get("name") for t in body.get("tools") or [] if t.get("type") == "function"]


def wants_json(body):
    rf = body.get("response_format") or {}
    text = body.get("text") or {}
    fmt = text.get("format") or {}
    return rf.get("type") in ("json_object", "json_schema") or fmt.get("type") in ("json_object", "json_schema")


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send_json(self, obj, status=200):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for name, data in events:
            if name:
                self.wfile.write(("event: %s\n" % name).encode())
            self.wfile.write(("data: %s\n\n" % (data if isinstance(data, str) else json.dumps(data))).encode())
            self.wfile.flush()

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            return self.send_json({"object": "list", "data": [{"id": "gpt-4o-mini", "object": "model", "owned_by": "mock"}]})
        self.send_json({"error": {"message": "not found"}}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        rec = {"t": time.time(), "path": self.path, "model": body.get("model"), "stream": bool(body.get("stream")),
               "keys": sorted(body.keys())}
        if self.path.endswith("/chat/completions"):
            rec["tools"] = tool_names_cc(body)
            rec["json"] = wants_json(body)
            msgs = body.get("messages") or []
            rec["last_role"] = msgs[-1].get("role") if msgs else None
            open(LOG, "a").write(json.dumps(rec) + "\n")
            return self.chat(body, msgs)
        if self.path.endswith("/responses"):
            rec["tools"] = tool_names_r(body)
            rec["json"] = wants_json(body)
            inp = body.get("input")
            rec["has_tool_output"] = isinstance(inp, list) and any(i.get("type") == "function_call_output" for i in inp if isinstance(i, dict))
            open(LOG, "a").write(json.dumps(rec) + "\n")
            return self.responses_api(body, rec["has_tool_output"])
        open(LOG, "a").write(json.dumps(rec) + "\n")
        self.send_json({"error": {"message": "unsupported path " + self.path}}, 404)

    # --- Chat Completions -------------------------------------------------
    def chat(self, body, msgs):
        model = body.get("model", "gpt-4o-mini")
        tools = tool_names_cc(body)
        tool_call = None
        if tools and (not msgs or msgs[-1].get("role") != "tool"):
            tool_call = {"id": "call_1", "type": "function", "function": {"name": tools[0], "arguments": json.dumps({"input": "6 * 7"})}}
        if tool_call:
            message = {"role": "assistant", "content": None, "tool_calls": [tool_call]}
            finish = "tool_calls"
        else:
            content = '{"greeting": "hello", "language": "en"}' if wants_json(body) else ("The answer is 42." if tools else "Hello")
            message = {"role": "assistant", "content": content}
            finish = "stop"
        if body.get("stream"):
            base = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": int(time.time()), "model": model}
            events = [(None, dict(base, choices=[{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]))]
            if tool_call:
                d = {"tool_calls": [dict(tool_call, index=0)]}
                events.append((None, dict(base, choices=[{"index": 0, "delta": d, "finish_reason": None}])))
            else:
                for part in (message["content"][:3], message["content"][3:]):
                    events.append((None, dict(base, choices=[{"index": 0, "delta": {"content": part}, "finish_reason": None}])))
            events.append((None, dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": finish}])))
            events.append((None, dict(base, choices=[], usage=USAGE_CC)))
            events.append((None, "[DONE]"))
            return self.sse(events)
        self.send_json({"id": "chatcmpl-1", "object": "chat.completion", "created": int(time.time()), "model": model,
                        "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": USAGE_CC})

    # --- Responses API ----------------------------------------------------
    def responses_api(self, body, has_tool_output):
        model = body.get("model", "gpt-4o-mini")
        tools = tool_names_r(body)
        if tools and not has_tool_output:
            item = {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": tools[0],
                    "arguments": json.dumps({"input": "6 * 7"}), "status": "completed"}
        else:
            text = '{"greeting": "hello", "language": "en"}' if wants_json(body) else ("The answer is 42." if tools else "Hello")
            item = {"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                    "content": [{"type": "output_text", "text": text, "annotations": []}]}
        resp = {"id": "resp_1", "object": "response", "created_at": int(time.time()), "status": "completed", "model": model,
                "output": [item], "usage": USAGE_R}
        if body.get("stream"):
            created = dict(resp, status="in_progress", output=[], usage=None)
            # OpenAI's documented order: created, in_progress, item added,
            # content part added, text deltas, text done, part done, item done,
            # completed.
            pending = dict(item, status="in_progress")
            if item["type"] == "message":
                pending["content"] = []
            events = [("response.created", {"type": "response.created", "sequence_number": 0, "response": created}),
                      ("response.in_progress", {"type": "response.in_progress", "sequence_number": 1, "response": created}),
                      ("response.output_item.added", {"type": "response.output_item.added", "sequence_number": 2, "output_index": 0, "item": pending})]
            seq = 3
            if item["type"] == "message":
                text = item["content"][0]["text"]
                events.append(("response.content_part.added", {"type": "response.content_part.added", "sequence_number": seq, "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}))
                seq += 1
                for part in (text[:3], text[3:]):
                    events.append(("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": seq, "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": part}))
                    seq += 1
                events.append(("response.output_text.done", {"type": "response.output_text.done", "sequence_number": seq, "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": text}))
                seq += 1
                events.append(("response.content_part.done", {"type": "response.content_part.done", "sequence_number": seq, "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": item["content"][0]}))
                seq += 1
            events.append(("response.output_item.done", {"type": "response.output_item.done", "sequence_number": seq, "output_index": 0, "item": item}))
            events.append(("response.completed", {"type": "response.completed", "sequence_number": seq + 1, "response": resp}))
            return self.sse(events)
        self.send_json(resp)


http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
