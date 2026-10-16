package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/govcode"
)

// The MCP governance extension (#372). After the protocol gate accepted a
// request and the canonical tool/action is trustworthy, every governance
// outcome on /mcp and /mcp/proxy carries govcode.ExtensionID in the
// JSON-RPC error.data (denials, failures) or in the result _meta (allowed
// calls): the stable code, its retryability, the signed record's actual
// explanation as reasonCode, and the reference to that record. Protocol
// rejections (#447) never reach these helpers and never carry the extension.
//
// Evidence truth, in order of precedence:
//   - a PRE-DISPATCH governed outcome (denial, schema failure, policy
//     evaluation failure, credential unavailable) MUST have its record
//     committed before the response. No attempt, a missing store, or a
//     failed commit all become evidence_commit_failed with no id — and the
//     outcome is still zero dispatch;
//   - a POST-HANDOFF outcome keeps its real code: the effect may already
//     exist and must not be relabelled; a failed commit is committed=false,
//     never a fabricated id.

// evidenceOutcome is what committing a record yields: the in-band reference
// and the record's primary explanation code (the signed reason).
type evidenceOutcome struct {
	ref    *govcode.EvidenceRef
	reason string
}

func (o *evidenceOutcome) committed() bool { return o != nil && o.ref != nil && o.ref.Committed }

// commitEvidence stores one record and reports the outcome truthfully: the
// id and signed reason only when the store accepted the complete signed
// record; committed=false otherwise. A nil store means the route cannot
// commit mandatory evidence at all — reported as not committed, so a
// pre-dispatch governed outcome fails closed (evidence_commit_failed)
// rather than pretending governance ran without proof.
func commitEvidence(ctx context.Context, store *evidence.Store, span trace.Span, ev *evidence.Evidence) *evidenceOutcome {
	if store == nil {
		log.Warn().Str("evidence_id", ev.ID).Msg("mcp_evidence_store_absent")
		return &evidenceOutcome{ref: govcode.NotCommitted()}
	}
	if err := store.Store(ctx, ev); err != nil {
		if span != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.Bool("mcp.evidence_committed", false))
		}
		log.Warn().Err(err).Str("evidence_id", ev.ID).Msg("mcp_evidence_commit_failed")
		return &evidenceOutcome{ref: govcode.NotCommitted()}
	}
	return &evidenceOutcome{ref: govcode.Committed(ev.ID), reason: primaryExplanation(ev)}
}

// primaryExplanation is the signed record's first explanation code.
func primaryExplanation(ev *evidence.Evidence) string {
	if ev == nil || len(ev.Explanations) == 0 {
		return ""
	}
	return ev.Explanations[0].Code
}

// legacyTalonCode maps a canonical code to the deprecated error.data
// talon_code alias (#369), kept for one release so integrators can migrate
// to the versioned extension. Codes introduced by #372 have no alias.
func legacyTalonCode(code string) string {
	switch code {
	case govcode.PolicyDenied:
		return TalonCodePolicyDenied
	case govcode.PIIPolicyViolation:
		return TalonCodePIIBlocked
	case govcode.ScannerUnavailable:
		return TalonCodeScannerUnavailable
	case govcode.UpstreamAuthUnavailable, govcode.UpstreamToolFailed, govcode.UpstreamOutcomeUnknown:
		return TalonCodeUpstreamError
	}
	return ""
}

// governanceData builds error.data: the versioned extension object plus
// the deprecated talon_code alias when one exists. legacy overrides the
// default alias (forbidden_tools keeps TALON_TOOL_FORBIDDEN).
func governanceData(ext govcode.Extension, legacy string) map[string]any {
	data := map[string]any{govcode.ExtensionID: ext}
	if legacy == "" {
		legacy = legacyTalonCode(ext.Code)
	}
	if legacy != "" {
		data["talon_code"] = legacy
	}
	return data
}

// publicEvidenceCommitFailed is the only message a refused-for-evidence
// outcome carries; details stay in logs and spans.
const publicEvidenceCommitFailed = "governance evidence could not be committed; request refused (fail-closed)"

// governedError is the one JSON-RPC error builder for governance outcomes.
// msg must already be a safe, bounded public message (never a raw error).
// For a pre-dispatch outcome whose record did not commit — or was never
// attempted — the outcome becomes evidence_commit_failed with no id. A
// post-handoff outcome keeps its code and reports committed=false. The
// reasonCode is the committed record's signed explanation when one exists.
func governedError(id json.RawMessage, code, msg string, out *evidenceOutcome, legacy string, preDispatch bool) *jsonrpcResponse {
	if preDispatch && !out.committed() {
		code, legacy, msg = govcode.EvidenceCommitFailed, "", publicEvidenceCommitFailed
		out = &evidenceOutcome{ref: govcode.NotCommitted()}
	}
	ext := govcode.Must(code)
	if out != nil {
		ext = ext.WithEvidence(out.ref, out.reason)
	}
	ext.Provenance = provenanceFor(ext, preDispatch)
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: id, Error: &rpcError{Code: codeServerError, Message: govcode.Bounded(msg), Data: governanceData(ext, legacy)}}
}

// provenanceFor states what Talon knows about the effect: nothing was
// dispatched before a pre-dispatch outcome; an unknown-class outcome is
// exactly that; any other post-handoff failure was observed.
func provenanceFor(ext govcode.Extension, preDispatch bool) string {
	switch {
	case preDispatch:
		return "not_dispatched"
	case ext.Decision == govcode.DecisionUnknown:
		return "unknown"
	default:
		return "observed"
	}
}

// withGovernanceMeta attaches the allowed-outcome extension (decision
// allow, signed reason, evidence reference) to a result's _meta, keeping
// every existing _meta key (serverInfo, upstreamServerInfo, vendor keys).
// Results that are not JSON objects are returned unchanged.
func withGovernanceMeta(result any, out *evidenceOutcome) any {
	m, ok := result.(map[string]any)
	if !ok {
		return result
	}
	meta, _ := m["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	ext := govcode.Allowed(nil)
	if out != nil {
		ext = ext.WithEvidence(out.ref, out.reason)
	}
	meta[govcode.ExtensionID] = ext
	m["_meta"] = meta
	return m
}

// discoverCapabilities is what both routes advertise: the tools capability
// (no listChanged: no subscriptions/listen stream exists) and exactly one
// extension, Talon's governance extension, because it is implemented. The
// Tasks extension is not advertised (#448).
func discoverCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}, "extensions": govcode.Advertisement()}
}

// ---- diagnostics that cross a trust boundary ------------------------------

// Public JSON-RPC messages are fixed, bounded strings chosen per outcome;
// raw errors from the policy engine, tools, transport, header generation or
// upstream decoding go to logs and spans only. Evidence is tenant-queryable,
// so free text that reaches a signed record is first passed through
// sanitizeDiagnostic: control characters removed, secret-shaped tokens and
// URL credentials/queries redacted, length bounded.
const (
	publicPolicyEvaluationFailed = "Tool call blocked: policy evaluation failed (fail-closed)"
	publicToolExecutionFailed    = "Tool execution failed"
	publicOutboundRequestInvalid = "Tool call could not be forwarded: outbound request invalid"
	publicUpstreamUnavailable    = "Upstream request failed; the tool outcome is unknown"
	publicUpstreamResponseBad    = "Upstream response invalid; the tool outcome is unknown"
	publicDefinitionsUnavailable = "Upstream tool definitions unavailable"
	publicConfigurationError     = "Service configuration error"
	maxDiagnosticBytes           = 240
)

var (
	// secretShaped covers bearer tokens, API-key style values and
	// key=value / key: value credentials in free text.
	secretShaped = regexp.MustCompile(`(?i)(bearer\s+|sk-[a-z0-9_-]{8,}|(?:api[_-]?key|token|secret|password|passwd|authorization|credential|x-api-key)\s*[:=]\s*)\S+`)
	// urlCredentials strips userinfo and query strings from URLs.
	urlCredentials = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)(?:[^/\s@]+@)?([^\s?#]*)(\?[^\s#]*)?`)
	// fsPath redacts absolute filesystem paths (two or more segments) that
	// are not part of a URL: internal layout is topology, not diagnostics.
	fsPath = regexp.MustCompile(`(^|[\s"'(=:,])((?:/[A-Za-z0-9._-]+){2,})`)
)

// sanitizeDiagnostic makes free-form error text safe for a signed,
// tenant-queryable record or a log line: no control characters or line
// breaks, no secret-shaped tokens, no URL credentials or query strings, no
// absolute filesystem paths, at most maxDiagnosticBytes. It is never used to compose a public message —
// those are fixed constants — only to bound what evidence retains.
func sanitizeDiagnostic(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	s = urlCredentials.ReplaceAllString(s, "${1}${2}")
	s = secretShaped.ReplaceAllString(s, "${1}[redacted]")
	s = fsPath.ReplaceAllString(s, "${1}[path]")
	if len(s) > maxDiagnosticBytes {
		cut := maxDiagnosticBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}
