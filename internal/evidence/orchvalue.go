package evidence

import "fmt"

// OrchHeaderMaxLen caps client-asserted attribution header values
// (X-Talon-Session-ID and friends).
const OrchHeaderMaxLen = 128

// ValidateOrchValue enforces header hygiene for client-asserted attribution
// values: length-capped and restricted to the RFC 7230 token charset, and
// rejected — never truncated — on violation. This blocks header/HTML
// injection at ingestion so hostile client-asserted strings never reach
// signed evidence or operator dashboards. Shared by the LLM gateway
// (orchestration metadata) and the MCP proxy (#350) so the two ingestion
// surfaces cannot diverge.
func ValidateOrchValue(name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if len(v) > OrchHeaderMaxLen {
		return "", fmt.Errorf("orchestration header %s exceeds %d bytes", name, OrchHeaderMaxLen)
	}
	for i := 0; i < len(v); i++ {
		if !isOrchTokenChar(v[i]) {
			return "", fmt.Errorf("orchestration header %s contains a disallowed character", name)
		}
	}
	return v, nil
}

// isOrchTokenChar reports whether c is an RFC 7230 tchar (the HTTP token charset).
func isOrchTokenChar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
