package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

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

// Inspect scans one unit before the runtime releases it. Nothing leaves
// uninspected: the complete frames of the unit are parsed and every string
// value of each event is scanned (text, thinking, tool-use input JSON,
// populated content_block_start fields — not only delta.text), and a
// trailing fragment cut mid-frame by the transport is scanned as raw text
// with its JSON escapes decoded, so a value whose frame terminator has not
// arrived yet is still caught before the bytes carrying it are released.
// CR, LF and CRLF line endings are all recognised. A content-bearing frame
// that cannot be parsed, or a carried fragment beyond the bound, withholds
// the stream rather than passing unscanned bytes (PR #531 review, P1).
func (sg *DelegatedStreamGuard) Inspect(ctx context.Context, unit []byte) DelegatedUnitVerdict {
	sg.summary.Units++
	if sg.summary.Blocked {
		// The runtime sends no units after a block; a repeat stays withheld.
		return DelegatedUnitVerdict{Block: true, Code: sg.summary.Code, Message: "stream already withheld"}
	}
	complete, partial, overflow := sg.frames(unit)
	if overflow {
		return sg.withhold(CodeResponseScanIncomplete, "a frame carried across units exceeds the inspection bound; the stream is withheld (fail-closed)")
	}
	for _, block := range bytes.Split(complete, []byte("\n\n")) {
		extractUsageFromSSELine(block, &sg.summary.Usage)
	}
	text, unparseable := sseEventText(complete)
	if unparseable {
		return sg.withhold(CodeResponseContentUnsupported, "a content-bearing frame could not be parsed; the stream is withheld (fail-closed)")
	}
	if len(partial) > 0 {
		// The string still open at the cut continues the preceding text;
		// the whole raw fragment is scanned as well.
		text += openStringTail(partial) + "\n" + fragmentText(partial)
	}
	if strings.TrimSpace(text) == "" {
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

// frames joins the carried partial frame with the unit (line endings
// normalised to LF for inspection only; the unit itself is never rewritten)
// and returns the complete SSE frames, the trailing partial frame, and
// whether the carry exceeded its bound. The partial frame is carried into
// the next unit so it is parsed whole once its terminator arrives; it is
// never dropped — past the bound the caller withholds the stream.
func (sg *DelegatedStreamGuard) frames(unit []byte) (complete, partial []byte, overflow bool) {
	data := append(sg.frame, normalizeLineEndings(unit)...) //nolint:gocritic // the carry is consumed here
	idx := bytes.LastIndex(data, []byte("\n\n"))
	if idx < 0 {
		sg.frame = data
		return nil, data, len(data) > streamGuardFrameCarryLimit
	}
	sg.frame = append([]byte(nil), data[idx+2:]...)
	return data[:idx+2], sg.frame, len(sg.frame) > streamGuardFrameCarryLimit
}

func normalizeLineEndings(b []byte) []byte {
	if !bytes.ContainsRune(b, '\r') {
		return b
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
}

// sseEventText returns the scannable text of complete SSE frames: for each
// frame the data lines (joined per the SSE grammar) parsed as JSON and every
// string value in the document collected. Protocol metadata is excluded by
// its LOCATION in the provider envelope, never by key name alone: a field
// named id or model inside a tool input is model output and is scanned.
// Consecutive streamed fragments (text, partial_json, thinking, content,
// arguments, Responses delta) are joined as one string, so a value split
// across two events that the runtime coalesced into one unit is still
// recognised. A data payload that is neither JSON nor the OpenAI "[DONE]"
// sentinel is content Talon cannot inspect: unparseable is true and the
// caller fails closed. Comment lines, event-only frames and empty data carry
// nothing.
func sseEventText(frames []byte) (text string, unparseable bool) {
	var b scanTextBuilder
	for _, frame := range bytes.Split(frames, []byte("\n\n")) {
		var data [][]byte
		for _, line := range bytes.Split(frame, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("data:")) {
				data = append(data, bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:"))))
			}
		}
		if len(data) == 0 {
			continue
		}
		payload := bytes.Join(data, []byte("\n"))
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var doc any
		if err := json.Unmarshal(payload, &doc); err != nil {
			return "", true
		}
		collectStrings(doc, "", true, &b)
	}
	return b.sb.String(), false
}

// sseStructuralKeys are identifiers and enumerations of the provider
// envelope, never model output — excluded only at envelope positions.
var sseStructuralKeys = map[string]struct{}{
	"type": {}, "id": {}, "model": {}, "role": {}, "stop_reason": {}, "stop_sequence": {}, "signature": {},
	"object": {}, "service_tier": {}, "finish_reason": {}, "system_fingerprint": {}, "event": {},
}

// sseEnvelopeContainers are the envelope objects whose DIRECT members may
// be structural; the event root is one implicitly. A path that leaves this
// set (content_block.input, message.content, choices[].delta.tool_calls, …)
// is model output and is scanned whole.
var sseEnvelopeContainers = map[string]struct{}{
	"message": {}, "delta": {}, "content_block": {}, "usage": {}, "choices": {}, "response": {}, "error": {},
}

// sseFragmentKeys name the streamed pieces of one logical string.
var sseFragmentKeys = map[string]struct{}{
	"text": {}, "partial_json": {}, "thinking": {}, "content": {}, "arguments": {}, "delta": {},
}

// scanTextBuilder assembles the classifier input: fragments of one logical
// string are concatenated directly, other values are separated.
type scanTextBuilder struct {
	sb           strings.Builder
	lastFragment bool
}

func (b *scanTextBuilder) add(key, s string) {
	_, fragment := sseFragmentKeys[key]
	if b.sb.Len() > 0 && (!fragment || !b.lastFragment) {
		b.sb.WriteByte('\n')
	}
	b.sb.WriteString(s)
	b.lastFragment = fragment
}

// collectStrings appends every string value of a decoded JSON document in
// key order. envelope is true while the path has stayed within the
// envelope containers from the root; only there are structural keys
// skipped.
func collectStrings(v any, key string, envelope bool, b *scanTextBuilder) {
	switch x := v.(type) {
	case string:
		b.add(key, x)
	case []any:
		for _, e := range x {
			collectStrings(e, key, envelope, b)
		}
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if _, structural := sseStructuralKeys[k]; structural && envelope {
				continue
			}
			_, container := sseEnvelopeContainers[k]
			collectStrings(x[k], k, envelope && container, b)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// openStringTail is the part of a transport-cut fragment after its last
// `":"` — the string value that was still open when the transport cut the
// frame — so it continues the preceding event's text with no separator.
func openStringTail(fragment []byte) string {
	i := bytes.LastIndex(fragment, []byte(`":"`))
	if i < 0 {
		return ""
	}
	return fragmentText(fragment[i+3:])
}

// fragmentText is the raw text of a frame cut mid-way by the transport,
// with the JSON escapes a cut string may contain decoded (\uXXXX, \", \\,
// \/ and the whitespace escapes), so a value split from its terminator
// is scanned as the reader would see it. Field names and punctuation
// around it are harmless to the scanner.
func fragmentText(fragment []byte) string {
	s := string(fragment)
	if !strings.Contains(s, "\\") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'u':
			if i+6 <= len(s) {
				if decoded, err := strconv.Unquote(`"\u` + s[i+2:i+6] + `"`); err == nil {
					sb.WriteString(decoded)
					i += 5
					continue
				}
			}
			sb.WriteByte(s[i])
		case '"', '\\', '/':
			sb.WriteByte(s[i+1])
			i++
		case 'n', 't', 'r', 'b', 'f':
			sb.WriteByte(' ')
			i++
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
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
		// A withhold for anything but a positive finding means the guard
		// could not inspect: the scan did not cover the response and the
		// signed status says so (same mapping as the held-whole path).
		switch in.Guard.Code {
		case "output_scanner_unavailable", CodeResponseContentUnsupported:
			result.markIncomplete(evidence.ResponseScanIncompleteScannerUnavailable)
		case CodeResponseScanIncomplete:
			result.markIncomplete(evidence.ResponseScanIncompleteCaptureLimitExceeded)
		}
	}
	return result
}
