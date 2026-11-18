#!/usr/bin/env python3
"""Generate examples/n8n-refund/refund-approval.workflow.json (run from the repo root).

The JSON is generated so that every Talon call, the credential references and
the connections are written once. Edit this generator, not the JSON.
"""
import json
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "examples/n8n-refund/refund-approval.workflow.json"

TALON_CRED = {"httpHeaderAuth": {"id": "talon-refund-bot-key", "name": "Talon refund-bot key"}}
WEBHOOK_CRED = {"httpHeaderAuth": {"id": "refund-webhook-caller", "name": "Refund webhook caller"}}

# The Talon base URL comes from the Config node (edit it after import): n8n
# 2.x blocks $env in expressions by default, so the workflow does not use it.
BASE = "={{ $('Config').first().json.talon_url }}"
# One refund per ticket: an n8n retry resumes the same Talon operation. The
# id is validated before any Talon call and URL-encoded in paths.
OP_ID = "$('Validate request').first().json.operation_id"
OP_PATH = "{{ encodeURIComponent(" + OP_ID + ") }}"


def http(name, pos, method, url, body=None):
    params = {
        "method": method,
        "url": url,
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        # fullResponse + neverError: Talon's 4xx/5xx answers are DATA the
        # workflow branches on (verdicts, refusals). A transport failure
        # (Talon unreachable) still fails the node and stops the workflow.
        "options": {"response": {"response": {"fullResponse": True, "neverError": True}}, "timeout": 35000},
    }
    if body is not None:
        params.update({"sendBody": True, "specifyBody": "json", "jsonBody": body})
    return {"parameters": params, "name": name, "type": "n8n-nodes-base.httpRequest", "typeVersion": 4.2,
            "position": pos, "credentials": TALON_CRED}


def switch(name, pos, value, rules):
    values = []
    for key, equals in rules:
        values.append({
            "outputKey": key, "renameOutput": True,
            "conditions": {
                "options": {"caseSensitive": True, "typeValidation": "strict", "version": 2},
                "combinator": "and",
                "conditions": [{"leftValue": value, "rightValue": equals,
                                "operator": {"type": "string", "operation": "equals"}}],
            },
        })
    return {"parameters": {"rules": {"values": values},
                           "options": {"fallbackOutput": "extra", "renameFallbackOutput": "other"}},
            "name": name, "type": "n8n-nodes-base.switch", "typeVersion": 3.2, "position": pos}


def respond(name, pos, code, body):
    return {"parameters": {"respondWith": "json", "responseBody": body, "options": {"responseCode": code}},
            "name": name, "type": "n8n-nodes-base.respondToWebhook", "typeVersion": 1.1, "position": pos}


nodes = [
    # Authenticated ingress: the caller must present the header credential.
    {"parameters": {"httpMethod": "POST", "path": "talon-refund", "authentication": "headerAuth",
                    "responseMode": "responseNode", "options": {}},
     "name": "Refund request", "type": "n8n-nodes-base.webhook", "typeVersion": 2, "position": [0, 300],
     "webhookId": "talon-refund", "credentials": WEBHOOK_CRED},
    {"parameters": {"assignments": {"assignments": [
        {"id": "talon-url", "name": "talon_url", "type": "string", "value": "http://127.0.0.1:8080"}]},
        "includeOtherFields": True, "options": {}},
     "name": "Config", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [200, 300]},
    # Only a well-formed request reaches Talon: ticket id, exact-decimal
    # amount as a string, currency code.
    {"parameters": {"assignments": {"assignments": [
        {"id": "valid", "name": "valid", "type": "boolean",
         "value": "={{ typeof $json.body === 'object' && $json.body !== null && typeof $json.body.ticket_id === 'string' && /^[A-Z]{1,10}-[0-9]{1,12}$/.test($json.body.ticket_id) && typeof $json.body.amount === 'string' && /^(0|[1-9][0-9]{0,14})(\\.[0-9]{1,2})?$/.test($json.body.amount) && typeof $json.body.currency === 'string' && /^[A-Z]{3}$/.test($json.body.currency) }}"},
        {"id": "opid", "name": "operation_id", "type": "string",
         "value": "={{ 'refund-' + (typeof ($json.body || {}).ticket_id === 'string' ? $json.body.ticket_id : 'invalid') }}"}]},
        "includeOtherFields": True, "options": {}},
     "name": "Validate request", "type": "n8n-nodes-base.set", "typeVersion": 3.4, "position": [400, 300]},
    switch("Request valid", [600, 300], "={{ String($json.valid) }}", [("valid", "true")]),
    http("Talon: establish operation", [820, 300], "POST", BASE + "/v1/action-operations",
         "={{ JSON.stringify({ operation_id: $json.operation_id, action: \"create_refund_request\", arguments: { ticket_id: $json.body.ticket_id, amount: $json.body.amount, currency: $json.body.currency } }) }}"),
    switch("Talon verdict", [1040, 300], "={{ $json.body && $json.body.operation ? String($json.body.operation.verdict) : 'NONE' }}",
           [("allow", "ALLOW"), ("approval", "REQUIRE_APPROVAL"), ("deny", "DENY")]),
    {"parameters": {"amount": 5, "unit": "seconds"}, "name": "Wait for reviewer",
     "type": "n8n-nodes-base.wait", "typeVersion": 1.1, "position": [1260, 420], "webhookId": "talon-refund-wait"},
    http("Talon: read operation", [1480, 420], "GET", BASE + "/v1/action-operations/" + OP_PATH),
    # Keep waiting only while the approval is pending AND not past its
    # expiry: Talon expires an undecided approval at the next claim, so the
    # workflow stops polling by the recorded expires_at.
    switch("Approval state", [1700, 420],
           "={{ !($json.body && $json.body.operation) ? 'NONE' : ($json.body.operation.operation_status !== 'awaiting_approval' ? String($json.body.operation.operation_status) : (($json.body.operation.approval && new Date($json.body.operation.approval.expires_at) > new Date()) ? 'awaiting_approval' : 'expired')) }}",
           [("authorized", "authorized"), ("pending", "awaiting_approval")]),
    http("Talon: claim (Talon dispatches)", [1920, 300], "POST",
         BASE + "/v1/action-operations/" + OP_PATH + "/attempts"),
    # After the claim was sent, anything but a recorded success is NOT proof
    # that no refund happened: unknown and unexpected answers say so.
    switch("Outcome", [2140, 300],
           "={{ $json.body && $json.body.operation ? String($json.body.operation.operation_status) : ($json.body && $json.body.error && $json.body.error.operation ? String($json.body.error.operation.operation_status) : 'NONE') }}",
           [("succeeded", "succeeded"), ("unknown", "unknown")]),
    respond("Respond: refunded", [2360, 200], 200,
            "={{ JSON.stringify({ result: \"refunded\", operation_id: " + OP_ID + ", verify: \"talon audit verify --operation \" + " + OP_ID + " }) }}"),
    respond("Respond: outcome unknown", [2360, 320], 202,
            "={{ JSON.stringify({ result: \"unknown\", operation_id: " + OP_ID + ", note: \"Talon dispatched the refund and could not observe the outcome. It may or may not have happened. Do not retry; reconcile with the refund system.\" }) }}"),
    respond("Respond: claim not completed", [2360, 440], 409,
            "={{ JSON.stringify({ result: \"not_completed\", operation_id: " + OP_ID + ", talon_status: $json.statusCode, talon_code: (($json.body || {}).error || {}).code || null, note: \"Talon did not report a completed refund. Read the operation before assuming that nothing was dispatched.\" }) }}"),
    respond("Respond: denied", [1260, 560], 403,
            "={{ JSON.stringify({ result: \"denied\", operation_id: " + OP_ID + " }) }}"),
    respond("Respond: not approved", [1920, 560], 409,
            "={{ JSON.stringify({ result: \"not_approved\", operation_id: " + OP_ID + ", status: $json.body && $json.body.operation ? $json.body.operation.operation_status : \"unknown\" }) }}"),
    respond("Respond: not authorized by Talon", [1260, 180], 409,
            "={{ JSON.stringify({ result: \"not_authorized\", operation_id: " + OP_ID + ", talon_status: $json.statusCode, talon_code: (($json.body || {}).error || {}).code || null, note: \"Talon returned no verdict (conflict, schema or authentication error). Nothing was dispatched by this run.\" }) }}"),
    respond("Respond: invalid request", [820, 520], 400,
            "={{ JSON.stringify({ result: \"invalid_request\", note: \"ticket_id must look like ABC-123, amount must be a decimal string with at most two fractional digits, currency a three-letter code. Nothing was sent to Talon.\" }) }}"),
]

def conn(*targets):
    return [[{"node": t, "type": "main", "index": 0}] if t else [] for t in targets]


connections = {
    "Refund request": {"main": conn("Config")},
    "Config": {"main": conn("Validate request")},
    "Validate request": {"main": conn("Request valid")},
    "Request valid": {"main": conn("Talon: establish operation", "Respond: invalid request")},
    "Talon: establish operation": {"main": conn("Talon verdict")},
    "Talon verdict": {"main": conn("Talon: claim (Talon dispatches)", "Wait for reviewer", "Respond: denied",
                                   "Respond: not authorized by Talon")},
    "Wait for reviewer": {"main": conn("Talon: read operation")},
    "Talon: read operation": {"main": conn("Approval state")},
    "Approval state": {"main": conn("Talon: claim (Talon dispatches)", "Wait for reviewer", "Respond: not approved")},
    "Talon: claim (Talon dispatches)": {"main": conn("Outcome")},
    "Outcome": {"main": conn("Respond: refunded", "Respond: outcome unknown", "Respond: claim not completed")},
}

workflow = {
    "name": "Talon-governed refund (create_refund_request)",
    "nodes": nodes,
    "connections": connections,
    "settings": {"executionOrder": "v1", "executionTimeout": 3600},
    "pinData": {},
    "meta": {"talon": {
        "contract": "Action Gateway /v1/action-operations (#458, #205)",
        "action": "create_refund_request",
        "generated_by": "examples/n8n-refund/generate-workflow.py",
    }},
}
with open(OUT, "w", encoding="utf-8") as f:
    json.dump(workflow, f, indent=2)
    f.write("\n")
print("wrote", OUT, len(nodes), "nodes")
