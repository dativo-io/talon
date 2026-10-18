package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/govcode"
	"github.com/dativo-io/talon/internal/mcp/wire"
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

// writeInvalidParams answers an in-method protocol failure — a tool Talon
// cannot resolve, arguments that violate the trusted schema, malformed
// arguments, an invalid cursor — exactly like the wire gate answers one:
// HTTP 400 with JSON-RPC -32602, no governance extension, no alias, no
// evidence. Nothing trustworthy was evaluated, so nothing is recorded.
// The returned nil tells the route the response is already written.
func writeInvalidParams(w http.ResponseWriter, id json.RawMessage, msg string) *jsonrpcResponse {
	wire.WriteError(w, id, &wire.Error{Status: http.StatusBadRequest, Code: wire.CodeInvalidParams, Reason: wire.ReasonParamsInvalid, Message: govcode.Bounded(msg)})
	return nil
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
// Untrusted text. These strings are controlled by a caller, a policy author
// or a vendor and never reach a public message or a record raw:
//   - policy decision reasons (the rego interpolates argument values);
//   - vendor JSON-RPC error messages and vendor definition errors;
//   - every Go error from the engine, a tool, the transport or decoding.
//
// Public messages are the fixed constants below; records keep a sanitized,
// bounded diagnostic; the vendor's own JSON-RPC error object is relayed to
// the client unchanged as an explicit pass-through (it is the vendor's
// error, not Talon's claim) and never copied into Talon-authored text.
const (
	publicPolicyDenied           = "tool not allowed by policy"
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
	// Secret-shaped text, redacted in three passes so no prefix of a token
	// survives: "Bearer <x>", bare "sk-…" API keys, and key=value /
	// key: value credentials.
	bearerToken  = regexp.MustCompile(`(?i)\b(bearer)\s+\S+`)
	apiKeyToken  = regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{8,}`)
	credentialKV = regexp.MustCompile(`(?i)\b(api[_-]?key|token|secret|password|passwd|authorization|credential|x-api-key)\s*[:=]\s*\S+`)
	// urlCredentials strips userinfo and query strings from URLs.
	urlCredentials = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)(?:[^/\s@]+@)?([^\s?#]*)(\?[^\s#]*)?`)
	// fsPath redacts absolute filesystem paths (two or more segments) that
	// are not part of a URL: internal layout is topology, not diagnostics.
	fsPath = regexp.MustCompile(`(^|[\s"'(=:,])((?:/[A-Za-z0-9._-]+){2,})`)
)

// sanitizeDiagnostic makes free-form error text safe for a LOG LINE, a span
// attribute or a bounded -32602 message that echoes the caller's own input:
// no control or format characters, no secret-shaped tokens, no URL
// credentials or query strings, no absolute filesystem paths, at most
// maxDiagnosticBytes. It is defense in depth, not a storage control: signed
// evidence never receives free text, sanitized or not (see the token
// helpers above).
func sanitizeDiagnostic(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) { // control and format (zero-width, bidi) characters
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	s = urlCredentials.ReplaceAllString(s, "${1}${2}")
	s = credentialKV.ReplaceAllString(s, "${1}=[redacted]")
	s = bearerToken.ReplaceAllString(s, "${1} [redacted]")
	s = apiKeyToken.ReplaceAllString(s, "[redacted]")
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

// ---- evidence reasons are tokens, never free text ---------------------------
//
// Nothing a caller, a policy author or a vendor wrote is stored in a signed,
// tenant-queryable record. Every PolicyDecision.Reason, Execution.Error and
// explanation trigger on the MCP routes is one of the structured tokens
// below: a stable rule or failure identifier plus, at most, a validated
// field name or a numeric policy limit. Raw text goes to logs and spans only.

// opaquePolicyReason is recorded for a denial reason that is not one of
// Talon's known policy-rule templates: free text of unknown provenance is
// never stored, not even sanitized.
const opaquePolicyReason = "policy_rule_denied"

// policyReasonTemplates match Talon's own rego denial messages exactly
// (tool_access.rego, proxy_tool_access.rego) and name the token each maps
// to; a capture group extracts only a validated field name or a policy limit.
var policyReasonTemplates = []struct {
	re    *regexp.Regexp
	token string // %s receives the validated capture when the template has one
}{
	{regexp.MustCompile(`^Tool '[^']*' not in allowed_tools( list)?$`), "tool_not_allowed"},
	{regexp.MustCompile(`^Tool '[^']*' is forbidden by policy$`), "tool_forbidden"},
	{regexp.MustCompile(`^Tool '[^']*' is in allowed_tools but overridden by forbidden_tools$`), "tool_forbidden_override"},
	{regexp.MustCompile(`^Tool '[^']*' matches destructive pattern; requires explicit allowed_tools entry$`), "tool_destructive_pattern"},
	{regexp.MustCompile(`^Admin operation '[^']*' requires explicit allow$`), "admin_operation_requires_allow"},
	{regexp.MustCompile(`^File path matches a forbidden pattern \(capabilities\.forbidden_patterns\)$`), "forbidden_path_pattern"},
	{regexp.MustCompile(`^estimated_row_count exceeds policy limit (\d{1,12}) for tool .+$`), "row_count_exceeded:limit=%s"},
	{regexp.MustCompile(`^dry_run required for .+ when estimated_row_count > (\d{1,12})$`), "dry_run_required:threshold=%s"},
	{regexp.MustCompile(`^argument ([A-Za-z0-9_.-]{1,64}) has a forbidden value for tool .+ \(tool_policies\.forbidden_argument_values\)$`), "forbidden_argument_value:field=%s"},
}

// policyReasonTokens projects policy-engine denial reasons onto structured
// tokens for signed evidence. A reason matching one of Talon's templates
// becomes its token (with the validated field name or limit); anything else
// — including a reason that merely contains familiar words — becomes
// opaquePolicyReason. The tool name is deliberately not repeated: the record
// already carries it in Execution.ToolsCalled.
func policyReasonTokens(reasons []string) []string {
	if len(reasons) == 0 {
		return nil
	}
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		token := opaquePolicyReason
		for _, t := range policyReasonTemplates {
			m := t.re.FindStringSubmatch(r)
			if m == nil {
				continue
			}
			token = t.token
			if len(m) > 1 && strings.Contains(token, "%s") {
				token = strings.Replace(token, "%s", m[1], 1)
			}
			break
		}
		out = append(out, token)
	}
	return out
}

// vendorErrorToken is what a signed record keeps of a vendor JSON-RPC error:
// the numeric code and its JSON-RPC category. The vendor's message and data
// are never stored (they are vendor-authored text of arbitrary content).
func vendorErrorToken(prefix string, code int) string {
	category := "vendor_defined"
	switch {
	case code == -32700:
		category = "parse_error"
	case code == -32600:
		category = "invalid_request"
	case code == -32601:
		category = "method_not_found"
	case code == -32602:
		category = "invalid_params"
	case code == -32603:
		category = "internal_error"
	case code >= -32099 && code <= -32000:
		category = "server_error"
	}
	return fmt.Sprintf("%s: code=%d category=%s", prefix, code, category)
}

// upstreamFailureToken classifies a transport or decoding failure into a
// stable kind without copying the error text (which can embed vendor
// headers, addresses or body fragments).
func upstreamFailureToken(prefix string, err error) string {
	kind := "unclassified"
	switch {
	case errors.Is(err, wire.ErrResultTypeMissing):
		kind = "result_type_missing"
	case errors.Is(err, wire.ErrResultTypeUnsupported):
		kind = "result_type_unsupported"
	case errors.Is(err, wire.ErrRedirectRefused):
		kind = "redirect_refused"
	case errors.Is(err, wire.ErrUpstreamStatus):
		kind = "http_status"
	case errors.Is(err, wire.ErrUpstreamProtocol):
		kind = "protocol_violation"
	case errors.Is(err, wire.ErrListResultInvalid), errors.Is(err, wire.ErrDiscoverResultInvalid), errors.Is(err, wire.ErrListPagination):
		kind = "list_result_invalid"
	case errors.Is(err, context.DeadlineExceeded):
		kind = "timeout"
	case errors.Is(err, errSecretRetrieval):
		kind = "secret_retrieval"
	default:
		var ne net.Error
		if errors.As(err, &ne) {
			kind = "transport"
			if ne.Timeout() {
				kind = "timeout"
			}
		} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			kind = "connection_closed"
		}
	}
	return prefix + ": " + kind
}

// publicVendorError is the only message a vendor-reported JSON-RPC error
// carries to the client: the vendor's numeric code and the request id are
// preserved, the vendor's message and data are not relayed (they may carry
// protected payload, credentials or topology); Talon's signed record keeps
// only the code and its JSON-RPC category (vendorErrorToken).
const publicVendorError = "Upstream tool returned an error; its code and category are recorded in Talon evidence"

// vendorErrorResponse is the ONE boundary for a well-formed upstream
// JSON-RPC error on tools/call and on the definition capture: a trustworthy,
// vendor-reported failure (never relabelled unknown or policy denial),
// answered with the vendor's code, the fixed public message and Talon's
// governance extension. When the record did not commit, committed=false is
// stated and the code stays upstream_tool_failed (the call already ran).
func vendorErrorResponse(id json.RawMessage, vendorCode int, out *evidenceOutcome) *jsonrpcResponse {
	resp := governedError(id, govcode.UpstreamToolFailed, publicVendorError, out, TalonCodeUpstreamError, false)
	if vendorCode != 0 {
		resp.Error.Code = vendorCode
	}
	return resp
}
