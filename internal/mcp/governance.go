package mcp

import (
	"context"
	"encoding/json"

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
// calls): the stable code, its retryability and the reference to the signed
// record that committed. Protocol rejections (#447) never reach these
// helpers and never carry the extension.

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

// governedError is the one JSON-RPC error builder for governance outcomes.
// When the mandatory record of a pre-dispatch outcome did not commit, the
// outcome is reported as evidence_commit_failed with no evidence id (never
// fabricated) — still zero dispatch. A post-dispatch outcome keeps its code
// and states committed=false, because the effect may already have
// happened and must not be relabelled.
func governedError(id json.RawMessage, code, msg string, ref *govcode.EvidenceRef, legacy string, preDispatch bool) *jsonrpcResponse {
	if preDispatch && ref != nil && !ref.Committed {
		code, legacy = govcode.EvidenceCommitFailed, ""
		msg = "governance evidence could not be committed; request refused (fail-closed)"
		ref = govcode.NotCommitted()
	}
	ext := govcode.Must(code)
	ext.Evidence = ref
	return &jsonrpcResponse{JSONRPC: jsonrpcVersion, ID: id, Error: &rpcError{Code: codeServerError, Message: msg, Data: governanceData(ext, legacy)}}
}

// withGovernanceMeta attaches the allowed-outcome extension (decision
// allow + evidence reference) to a result's _meta. Results that are not
// JSON objects are returned unchanged.
func withGovernanceMeta(result any, ref *govcode.EvidenceRef) any {
	m, ok := result.(map[string]any)
	if !ok {
		return result
	}
	meta, _ := m["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[govcode.ExtensionID] = govcode.Allowed(ref)
	m["_meta"] = meta
	return m
}

// commitEvidence stores one record and reports the reference truthfully:
// the id only when the store accepted the complete signed record, an
// explicit committed=false otherwise. A nil store (embedders without
// evidence) yields no reference at all.
func commitEvidence(ctx context.Context, store *evidence.Store, span trace.Span, ev *evidence.Evidence) *govcode.EvidenceRef {
	if store == nil {
		return nil
	}
	if err := store.Store(ctx, ev); err != nil {
		if span != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.Bool("mcp.evidence_committed", false))
		}
		log.Warn().Err(err).Str("evidence_id", ev.ID).Msg("mcp_evidence_commit_failed")
		return govcode.NotCommitted()
	}
	return govcode.Committed(ev.ID)
}

// discoverCapabilities is what both routes advertise: the tools capability
// (no listChanged: no subscriptions/listen stream exists) and exactly one
// extension, Talon's governance extension, because it is implemented. The
// Tasks extension is not advertised (#448).
func discoverCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}, "extensions": govcode.Advertisement()}
}
