package gateway

import (
	"fmt"
	"net/http"

	"github.com/dativo-io/talon/internal/evidence"
)

// Provider-neutral orchestration metadata contract (#194, epic #192).
//
// Any client on any provider route can carry coding-orchestration identity via
// the generic X-Talon-* headers. Vendor adapters map a client's native headers
// onto the same neutral contract — they are DATA (a table entry), never code
// branches in the governance core. Generic headers win over a vendor header on
// conflict; both are recorded as evidence only (provenance: client_asserted)
// and never influence policy in v1 — acting on client-asserted identity waits
// for attestation (#149).

// Neutral orchestration headers (canonical; work on every provider route).
const (
	hdrTalonSessionID     = "X-Talon-Session-ID"
	hdrTalonAgentID       = "X-Talon-Agent-ID"
	hdrTalonParentAgentID = "X-Talon-Parent-Agent-ID"
	hdrTalonClient        = "X-Talon-Client"
)

// Session-source provenance: how the request's session_id was obtained. Only
// asserted sources may materialize a session-store row / session budget
// (#198); a synthetic id is evidence-only and must not create session state.
const (
	orchSourceClientAsserted = "client_asserted"
	orchSourceVendorAsserted = "vendor_asserted"
	orchSourceSynthetic      = "synthetic"
)

const orchProvenanceClientAsserted = "client_asserted"

// vendorAdapter maps a client's native request headers onto the neutral
// orchestration contract. Adding a new client is a new entry here — never a
// branch in ServeHTTP.
type vendorAdapter struct {
	client     string // recorded as orchestration.client
	sessionHdr string // client's session-id header (optional)
	agentHdr   string // client's subagent-id header (optional)
	parentHdr  string // client's parent-subagent-id header (optional)
}

// vendorAdapters is evaluated in order; the first adapter with any populated
// header wins. Claude Code and Codex are the two verified clients today.
var vendorAdapters = []vendorAdapter{
	{
		client:     "claude-code",
		sessionHdr: "X-Claude-Code-Session-Id",
		agentHdr:   "X-Claude-Code-Agent-Id",
		parentHdr:  "X-Claude-Code-Parent-Agent-Id",
	},
	{
		client:     "codex",
		sessionHdr: "Session-Id",
		agentHdr:   "X-Openai-Subagent",
	},
}

const orchHeaderMaxLen = 128

// validateOrchValue enforces header hygiene: values are length-capped and
// restricted to the RFC 7230 token charset, and rejected — never truncated —
// on violation. This blocks header/HTML injection at ingestion so hostile
// client-asserted strings never reach signed evidence or operator dashboards.
func validateOrchValue(name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if len(v) > orchHeaderMaxLen {
		return "", fmt.Errorf("orchestration header %s exceeds %d bytes", name, orchHeaderMaxLen)
	}
	for i := 0; i < len(v); i++ {
		if !isTokenChar(v[i]) {
			return "", fmt.Errorf("orchestration header %s contains a disallowed character", name)
		}
	}
	return v, nil
}

// isTokenChar reports whether c is an RFC 7230 tchar (the HTTP token charset).
func isTokenChar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// orchHeaders is the validated raw header set from one request.
type orchHeaders struct {
	genSession, genAgent, genParent, genClient string
	vend                                       vendorAdapter
	vSession, vAgent, vParent                  string
}

func readOrchHeaders(r *http.Request) (orchHeaders, error) {
	var h orchHeaders
	var err error
	if h.genSession, err = validateOrchValue(hdrTalonSessionID, r.Header.Get(hdrTalonSessionID)); err != nil {
		return h, err
	}
	if h.genAgent, err = validateOrchValue(hdrTalonAgentID, r.Header.Get(hdrTalonAgentID)); err != nil {
		return h, err
	}
	if h.genParent, err = validateOrchValue(hdrTalonParentAgentID, r.Header.Get(hdrTalonParentAgentID)); err != nil {
		return h, err
	}
	if h.genClient, err = validateOrchValue(hdrTalonClient, r.Header.Get(hdrTalonClient)); err != nil {
		return h, err
	}
	// Vendor adapter: first with any populated header wins.
	for _, a := range vendorAdapters {
		s, aid, p := hdrOrEmpty(r, a.sessionHdr), hdrOrEmpty(r, a.agentHdr), hdrOrEmpty(r, a.parentHdr)
		if s == "" && aid == "" && p == "" {
			continue
		}
		if h.vSession, err = validateOrchValue(a.sessionHdr, s); err != nil {
			return h, err
		}
		if h.vAgent, err = validateOrchValue(a.agentHdr, aid); err != nil {
			return h, err
		}
		if h.vParent, err = validateOrchValue(a.parentHdr, p); err != nil {
			return h, err
		}
		h.vend = a
		break
	}
	return h, nil
}

// resolveOrchestration reads the neutral and vendor orchestration headers,
// applies hygiene and precedence (generic > vendor > absent), and returns the
// evidence block plus the resolved session id and source. When
// acceptClientMetadata is false, agent/parent/client identity is ignored and
// the session id keeps its pre-epic neutral-header behavior. A hygiene
// violation returns an error; the caller must reject the request (400) so
// invalid values never reach evidence. syntheticSessionID is the
// gateway-derived fallback ("sess_"+correlation) used when no client asserted
// a session id.
func resolveOrchestration(r *http.Request, acceptClientMetadata bool, syntheticSessionID string) (orch *evidence.OrchestrationContext, sessionID, sessionSource string, err error) {
	h, err := readOrchHeaders(r)
	if err != nil {
		return nil, "", "", err
	}

	// Session id + source: generic > vendor > synthetic. The session id is the
	// one correlation spine every request already carries, so it is resolved
	// regardless of acceptClientMetadata (matching pre-epic behavior for the
	// neutral header); only the vendor path is gated by the flag.
	sessionID, sessionSource = syntheticSessionID, orchSourceSynthetic
	switch {
	case h.genSession != "":
		sessionID, sessionSource = h.genSession, orchSourceClientAsserted
	case acceptClientMetadata && h.vSession != "":
		sessionID, sessionSource = h.vSession, orchSourceVendorAsserted
	}

	// Identity (agent/parent/client) is recorded only when the caller accepts
	// client metadata. Generic wins over vendor per field.
	agent, parent, client := "", "", ""
	if acceptClientMetadata {
		agent = firstNonEmpty(h.genAgent, h.vAgent)
		parent = firstNonEmpty(h.genParent, h.vParent)
		client = resolveOrchClient(h, agent, parent, sessionSource)
	}

	// The orchestration block records subagent attribution. A bare session id
	// (client-asserted or synthetic) is already the session_id column, so emit
	// a block only when there is actual identity to attribute. session_source
	// is still returned for the session-lifecycle path (#198) regardless.
	if agent == "" && parent == "" && client == "" {
		return nil, sessionID, sessionSource, nil
	}

	return &evidence.OrchestrationContext{
		SessionID:     sessionID,
		AgentID:       agent,
		ParentAgentID: parent,
		Client:        client,
		SessionSource: sessionSource,
		Provenance:    orchProvenanceClientAsserted,
	}, sessionID, sessionSource, nil
}

// resolveOrchClient picks the recorded client label: explicit generic header,
// else the matched vendor adapter, else "generic" when any identity is present.
func resolveOrchClient(h orchHeaders, agent, parent, source string) string {
	if h.genClient != "" {
		return h.genClient
	}
	if h.vend.client != "" && (h.vSession != "" || h.vAgent != "" || h.vParent != "") {
		return h.vend.client
	}
	if agent != "" || parent != "" || source != orchSourceSynthetic {
		return "generic"
	}
	return ""
}

func hdrOrEmpty(r *http.Request, name string) string {
	if name == "" {
		return ""
	}
	return r.Header.Get(name)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// validGatewayStages is the fixed set of orchestration stages the session
// store reads; any other X-Talon-Stage value is dropped at ingestion so
// unbounded junk stage strings never accumulate session_stage_counts rows.
var validGatewayStages = map[string]struct{}{
	"generation": {},
	"judge":      {},
	"commit":     {},
}

func normalizeStage(v string) string {
	if _, ok := validGatewayStages[v]; ok {
		return v
	}
	return ""
}
