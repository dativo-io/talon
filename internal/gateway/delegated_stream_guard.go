package gateway

import (
	"bytes"
	"context"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/classifier"
	"github.com/dativo-io/talon/internal/evidence"
)

// Guarded stream (OpenShell STREAM_BYTES under a preventive response policy).
//
// OpenShell v0.1.3 never offers WHOLE_BODY_BYTES for text/event-stream: its
// eligibility rule treats SSE as open-ended, so the only inspectable mode
// for a streamed model answer is STREAM_BYTES, in which the runtime holds
// each unit until the middleware's result (pass, transform or block) and
// forwards only what the result allows. Before this mode existed Talon
// planned WHOLE_BODY for every preventive policy and, finding it absent,
// failed every streamed response closed (`output_scan_unavailable`) — a
// client that always streams (Claude Code) could never complete one turn
// under `block`/`redact` (#528, PR #531 run 42378512377).
//
// What the guard guarantees: every unit is scanned before it is released,
// and from the first unit found to carry PII (or that cannot be scanned)
// nothing further is released — OpenShell aborts delivery. What it does not
// guarantee: a value split across two units (two SSE deltas, or one frame
// cut by the transport) is complete only in the later unit, so its first
// part was already released when the guard withholds the rest; the guard
// scans a bounded tail of released text with each new unit so that split
// value is still caught at the earliest unit completing it. `redact` is
// honoured as "withhold" here: the v0.1.3 contract forbids retaining input
// bytes across units, so a frame cannot be rewritten in place. Evidence
// records this as enforcement `preventive_per_unit`, never as `preventive`.

// Per-unit scan bounds. The frame carry keeps the trailing incomplete SSE
// frame of a unit so the next unit is parsed whole; the text tail keeps
// enough released text to recognise a value split across units.
const (
	streamGuardFrameCarryLimit = 64 << 10
	streamGuardTextTailLimit   = 256
)

// StreamUnitInspector is what the response hook drives for a guarded
// stream: one Inspect per body unit, in order, then Summary for the
// settlement.
type StreamUnitInspector interface {
	Inspect(ctx context.Context, unit []byte) DelegatedUnitVerdict
	Summary() *StreamGuardSummary
}

// DelegatedUnitVerdict is the result for one unit: release it, or withhold
// it and everything after it.
type DelegatedUnitVerdict struct {
	Block   bool
	Code    string
	Message string
}

// StreamGuardSummary is what the settlement learns from the guard.
type StreamGuardSummary struct {
	Units       int
	Blocked     bool
	BlockedAt   int // 1-based unit sequence of the withheld unit
	Code        string
	PIIDetected bool
	PIITypes    []string
	Tier        int
	// Usage is accumulated from every complete frame the guard parsed,
	// independent of the settlement's bounded capture.
	Usage TokenUsage
}

// DelegatedStreamGuard implements StreamUnitInspector for one exchange.
type DelegatedStreamGuard struct {
	action  string
	scanner classifier.Facade
	frame   []byte
	tail    string
	summary StreamGuardSummary
}

// GuardDelegatedStream prepares the per-unit inspector for an exchange the
// plan put in ResponseModeStreamGuarded. The refusal mirrors the plan's:
// an identity or binding failure blocks delivery.
func (g *Gateway) GuardDelegatedStream(ctx context.Context, pf DelegatedResponsePreflight) (StreamUnitInspector, *DelegatedResponsePlan) {
	rc, refused := g.resolveResponseContext(ctx, pf)
	if refused != nil {
		return nil, refused
	}
	return &DelegatedStreamGuard{action: rc.action, scanner: g.classifier}, nil
}

// Inspect scans one unit before the runtime releases it.
func (sg *DelegatedStreamGuard) Inspect(ctx context.Context, unit []byte) DelegatedUnitVerdict {
	sg.summary.Units++
	if sg.summary.Blocked {
		// The runtime sends no units after a block; a repeat stays withheld.
		return DelegatedUnitVerdict{Block: true, Code: sg.summary.Code, Message: "stream already withheld"}
	}
	complete := sg.completeFrames(unit)
	for _, block := range bytes.Split(complete, []byte("\n\n")) {
		extractUsageFromSSELine(block, &sg.summary.Usage)
	}
	text := accumulateSSEContent(complete)
	if text == "" {
		return DelegatedUnitVerdict{}
	}
	scanText := sg.tail + text
	if sg.scanner == nil {
		return sg.withhold("output_scanner_unavailable", "response PII scanner unavailable; the stream is withheld (fail-closed)")
	}
	cls, err := sg.scanner.Analyze(classifier.WithPIIDirection(ctx, classifier.PIIDirectionResponse), scanText)
	if err != nil {
		log.Warn().Err(err).Msg("delegated_stream_guard_scanner_failed")
		return sg.withhold("output_scanner_unavailable", "response PII scanner failed; the stream is withheld (fail-closed)")
	}
	if cls != nil && cls.HasPII {
		sg.summary.PIIDetected = true
		sg.summary.PIITypes = uniqueSortedEntityTypes(cls.Entities)
		sg.summary.Tier = cls.Tier
		log.Warn().Strs("pii_types", sg.summary.PIITypes).Int("unit", sg.summary.Units).Msg("delegated_stream_unit_withheld")
		return sg.withhold("output_pii_blocked", "response unit carries PII under a preventive policy; the stream is withheld from this unit on")
	}
	if len(scanText) > streamGuardTextTailLimit {
		scanText = scanText[len(scanText)-streamGuardTextTailLimit:]
	}
	sg.tail = scanText
	return DelegatedUnitVerdict{}
}

// completeFrames joins the carried partial frame with the unit and returns
// the complete SSE frames; the trailing partial frame is carried forward
// (bounded, oldest bytes dropped past the bound).
func (sg *DelegatedStreamGuard) completeFrames(unit []byte) []byte {
	data := append(sg.frame, unit...) //nolint:gocritic // the carry is consumed here
	idx := bytes.LastIndex(data, []byte("\n\n"))
	if idx < 0 {
		sg.frame = boundTail(data, streamGuardFrameCarryLimit)
		return nil
	}
	sg.frame = boundTail(append([]byte(nil), data[idx+2:]...), streamGuardFrameCarryLimit)
	return data[:idx+2]
}

func boundTail(b []byte, limit int) []byte {
	if len(b) <= limit {
		return b
	}
	return b[len(b)-limit:]
}

func (sg *DelegatedStreamGuard) withhold(code, message string) DelegatedUnitVerdict {
	sg.summary.Blocked, sg.summary.BlockedAt, sg.summary.Code = true, sg.summary.Units, code
	return DelegatedUnitVerdict{Block: true, Code: code, Message: message}
}

// Summary is the guard's facts for the settlement.
func (sg *DelegatedStreamGuard) Summary() *StreamGuardSummary {
	s := sg.summary
	return &s
}

// guardScanResult projects the guard's facts onto the response_scan
// evidence of the settlement. A guarded settlement without a guard summary
// is a hook defect: it fails closed under the preventive policy it ran for.
func guardScanResult(in DelegatedResponseBody, action string) *ResponsePIIScanResult {
	result := &ResponsePIIScanResult{
		Action: action, Enforcement: evidence.ResponseScanEnforcementPreventivePerUnit, Streamed: true,
		Status: evidence.ResponseScanStatusComplete, BytesObserved: in.BytesSeen, CaptureLimit: in.CaptureCap,
	}
	if in.Guard == nil {
		result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		result.Blocked, result.BlockReason = true, "output_scanner_unavailable"
		return result
	}
	result.PIIDetected, result.PIITypes, result.Tier = in.Guard.PIIDetected, in.Guard.PIITypes, in.Guard.Tier
	if in.Guard.Blocked {
		result.Blocked, result.BlockReason = true, in.Guard.Code
		if in.Guard.Code == "output_scanner_unavailable" {
			result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		}
	}
	return result
}
