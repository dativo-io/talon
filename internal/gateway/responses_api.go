package gateway

import (
	"encoding/json"
	"strings"
)

// isResponsesAPIPath returns true if the path targets the OpenAI Responses API
// (e.g. /v1/responses or /v1/responses/{id}).
func isResponsesAPIPath(path string) bool {
	return strings.HasPrefix(path, "/v1/responses")
}

// ensureResponsesStore sets "store":true in the request body so the Responses API
// persists response items. The API defaults to store:false; proxy clients (e.g.
// OpenClaw) reference previous response IDs in follow-up messages, and those
// IDs 404 unless items were stored. We always force store:true when proxying
// so multi-turn works; any client-sent store:false is overwritten.
func ensureResponsesStore(body []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["store"] = json.RawMessage("true")
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// disableStreaming sets "stream":false in the request body. Used when
// response PII scanning is enabled — we need the full response body to
// scan/redact before returning it to the client. Without this, streaming
// clients (e.g. OpenClaw) send "stream":true and the response bypasses
// PII scanning entirely.
func disableStreaming(body []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["stream"] = json.RawMessage("false")
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}
