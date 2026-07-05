package gateway

import (
	"bytes"
	"encoding/json"
	"strings"
)

// isResponsesAPIPath returns true if the path targets the OpenAI Responses API
// (e.g. /v1/responses or /v1/responses/{id}).
func isResponsesAPIPath(path string) bool {
	return strings.HasPrefix(path, "/v1/responses")
}

// Responses API store-mode values (providers.<id>.responses_store_mode).
const (
	// ResponsesStorePreserve forwards the client's store field untouched
	// (absent stays absent — the upstream default applies). This is the
	// gateway default: an explicit client "store": false is a data-retention
	// decision Talon must not silently reverse (#213).
	ResponsesStorePreserve = "preserve"
	// ResponsesStoreForceIfAbsent sets store:true only when the client sent
	// no store field. Opt-in for clients that reference previous_response_id
	// across turns (e.g. OpenClaw) — stored items are required or follow-up
	// turns 404.
	ResponsesStoreForceIfAbsent = "force_if_absent"
	// ResponsesStoreForceTrue always sets store:true, overriding an explicit
	// client "store": false. The override of explicit client intent is
	// recorded in signed evidence (gateway annotation
	// "responses_store_overridden").
	ResponsesStoreForceTrue = "force_true"
)

// applyResponsesStoreMode applies the provider's responses_store_mode to the
// request body. Returns the (possibly rewritten) body and whether an explicit
// client "store": false was overridden — which callers must record in
// evidence. Unparseable bodies pass through unchanged.
func applyResponsesStoreMode(body []byte, mode string) ([]byte, bool) {
	switch mode {
	case "", ResponsesStorePreserve:
		return body, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body, false
	}
	raw, present := m["store"]
	overrode := false
	switch mode {
	case ResponsesStoreForceIfAbsent:
		if present {
			return body, false
		}
		m["store"] = json.RawMessage("true")
	case ResponsesStoreForceTrue:
		if present && bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
			return body, false
		}
		// Explicit non-true (false or null) is client intent being reversed.
		overrode = present
		m["store"] = json.RawMessage("true")
	default:
		return body, false
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body, false
	}
	return out, overrode
}
