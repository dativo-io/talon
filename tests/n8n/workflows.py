"""Writes the n8n credentials and workflows for the n8n x Talon compatibility
harness: stock nodes only, the Talon key as the OpenAI API key, Talon's
OpenAI-compatible base URL. Usage: workflows.py <outdir> <talon_url> <talon_key>
"""
import json
import os
import sys

out, talon, key = sys.argv[1], sys.argv[2].rstrip("/"), sys.argv[3]
base = talon + "/v1/proxy/openai/v1"
os.makedirs(out, exist_ok=True)

creds = [
    {"id": "talonOpenAiCred1", "name": "Talon (OpenAI-compatible)", "type": "openAiApi",
     "data": {"apiKey": key, "url": base}},
    {"id": "talonHeaderCred1", "name": "Talon key header", "type": "httpHeaderAuth",
     "data": {"name": "Authorization", "value": "Bearer " + key}},
]
json.dump(creds, open(os.path.join(out, "credentials.json"), "w"), indent=1)

OPENAI = {"openAiApi": {"id": "talonOpenAiCred1", "name": "Talon (OpenAI-compatible)"}}


def manual():
    return {"id": "n-manual", "name": "Start", "type": "n8n-nodes-base.manualTrigger", "typeVersion": 1, "position": [0, 0], "parameters": {}}


def model(responses=None, response_format=None):
    p = {"model": {"__rl": True, "mode": "id", "value": "gpt-4o-mini"}, "options": {}}
    if responses is not None:
        p["responsesApiEnabled"] = responses
    if response_format:
        p["options"]["responseFormat"] = response_format
    return {"id": "n-model", "name": "OpenAI Chat Model", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1.3,
            "position": [200, 200], "parameters": p, "credentials": OPENAI}


def chain(text):
    return {"id": "n-chain", "name": "Basic LLM Chain", "type": "@n8n/n8n-nodes-langchain.chainLlm", "typeVersion": 1.7,
            "position": [200, 0], "parameters": {"promptType": "define", "text": text}}


def agent(text):
    return {"id": "n-agent", "name": "AI Agent", "type": "@n8n/n8n-nodes-langchain.agent", "typeVersion": 3.1,
            "position": [200, 0], "parameters": {"promptType": "define", "text": text, "options": {}}}


def calculator(name="Calculator"):
    return {"id": "n-tool", "name": name, "type": "@n8n/n8n-nodes-langchain.toolCalculator", "typeVersion": 1,
            "position": [400, 200], "parameters": {}}


def wf(wid, name, nodes, consumer):
    conns = {"Start": {"main": [[{"node": consumer, "type": "main", "index": 0}]]}}
    for n in nodes:
        if n["type"].endswith("lmChatOpenAi"):
            conns[n["name"]] = {"ai_languageModel": [[{"node": consumer, "type": "ai_languageModel", "index": 0}]]}
        if n["type"].endswith("toolCalculator"):
            conns[n["name"]] = {"ai_tool": [[{"node": consumer, "type": "ai_tool", "index": 0}]]}
    doc = {"id": wid, "name": name, "nodes": [manual()] + nodes, "connections": conns, "active": False, "settings": {"executionOrder": "v1"}}
    json.dump(doc, open(os.path.join(out, wid + ".json"), "w"), indent=1)


PII = "Draft a reply to Jane Doe, SSN 123-45-6789, email jane.doe@example.com, about her refund."
wf("w1chainrespapi01", "chain, Chat Model v1.3 defaults (Responses API)", [chain("Say hello in one word."), model()], "Basic LLM Chain")
wf("w2chaincompl0001", "chain, Chat Model v1.3, Responses API off (Chat Completions)", [chain("Say hello in one word."), model(responses=False)], "Basic LLM Chain")
wf("w3agenttool00001", "AI Agent v3.1 + Calculator tool, Chat Model v1.3 defaults", [agent("What is 6 times 7? Use the calculator."), model(), calculator()], "AI Agent")
wf("w4chainjson00001", "chain, JSON response format (Chat Completions)", [chain("Return a JSON greeting."), model(responses=False, response_format="json_object")], "Basic LLM Chain")
wf("w5chainpii000001", "chain, company PII rule (Chat Completions)", [chain(PII), model(responses=False)], "Basic LLM Chain")
wf("w6agentforbid001", "AI Agent with a tool the company forbids (delete_*)", [agent("Remove customer 42."), model(), calculator("delete_customer")], "AI Agent")
wf("w7chainpiiresp01", "chain, company PII rule (Responses API)", [chain(PII), model()], "Basic LLM Chain")

http = {"id": "n-http", "name": "HTTP Request", "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2, "position": [200, 0],
        "parameters": {"method": "POST", "url": base + "/chat/completions", "authentication": "genericCredentialType",
                       "genericAuthType": "httpHeaderAuth", "sendBody": True, "specifyBody": "json",
                       "jsonBody": json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Say hello in one word."}]}),
                       "options": {}},
        "credentials": {"httpHeaderAuth": {"id": "talonHeaderCred1", "name": "Talon key header"}}}
doc = {"id": "w8httpnode000001", "name": "stock HTTP Request node", "nodes": [manual(), http],
       "connections": {"Start": {"main": [[{"node": "HTTP Request", "type": "main", "index": 0}]]}}, "active": False, "settings": {"executionOrder": "v1"}}
json.dump(doc, open(os.path.join(out, "w8httpnode000001.json"), "w"), indent=1)
print("wrote", len(os.listdir(out)), "files to", out)


def streaming(wid, name, path, responses):
    hook = {"id": "n-hook", "name": "Webhook", "type": "n8n-nodes-base.webhook", "typeVersion": 2.1, "position": [0, 0],
            "webhookId": wid + "-hook", "parameters": {"httpMethod": "POST", "path": path, "responseMode": "streaming", "options": {}}}
    ag = agent("Say hello in one word.")
    ag["parameters"]["options"] = {"enableStreaming": True}
    m = model(responses=responses)
    doc = {"id": wid, "name": name, "nodes": [hook, ag, m],
           "connections": {"Webhook": {"main": [[{"node": "AI Agent", "type": "main", "index": 0}]]},
                           "OpenAI Chat Model": {"ai_languageModel": [[{"node": "AI Agent", "type": "ai_languageModel", "index": 0}]]}},
           "active": False, "settings": {"executionOrder": "v1"}}
    json.dump(doc, open(os.path.join(out, wid + ".json"), "w"), indent=1)


streaming("w9streamresp0001", "streaming AI Agent, Responses API (webhook)", "talon-stream-responses", None)
streaming("wAstreamcompl001", "streaming AI Agent, Chat Completions (webhook)", "talon-stream-completions", False)
