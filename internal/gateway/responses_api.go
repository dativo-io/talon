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

// ensureResponsesStore sets "store":true in the request body if it is not
// already explicitly set. The Responses API defaults store to false, which
// means response items are not persisted on OpenAI's servers. Proxy clients
// (like OpenClaw) reference previous response IDs in follow-up messages;
// without store:true those IDs produce 404 errors.
func ensureResponsesStore(body []byte) []byte {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	if _, exists := m["store"]; exists {
		return body
	}
	m["store"] = json.RawMessage("true")
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}
