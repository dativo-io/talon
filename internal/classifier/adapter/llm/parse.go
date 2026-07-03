package llm

import (
	"encoding/json"
	"errors"
	"strings"
)

// Detection is one entity the model reported: a type label and the verbatim
// value it claims appears in the text. Offsets are never accepted from the
// model — relocation computes them.
type Detection struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// rawDetection defers value decoding: small models emit "value" as a string
// (the prompted shape) or as an array of strings (observed from llama3.2:1b:
// {"type":"EMAIL_ADDRESS","value":["[EMAIL]"]}). Any other shape is a
// fail-closed decode error.
type rawDetection struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type nerResponse struct {
	Entities []rawDetection `json:"entities"`
}

// expandDetections normalizes raw detections into the canonical one-value-per-
// detection form. Missing/empty values are skipped (nothing to relocate);
// non-string value shapes reject the whole reply (fail-closed).
func expandDetections(raw []rawDetection) ([]Detection, error) {
	out := make([]Detection, 0, len(raw))
	for _, r := range raw {
		if len(r.Value) == 0 || string(r.Value) == "null" {
			continue
		}
		var s string
		if err := json.Unmarshal(r.Value, &s); err == nil {
			out = append(out, Detection{Type: r.Type, Value: s})
			continue
		}
		var arr []string
		if err := json.Unmarshal(r.Value, &arr); err == nil {
			for _, v := range arr {
				out = append(out, Detection{Type: r.Type, Value: v})
			}
			continue
		}
		return nil, errNotNERJSON
	}
	return out, nil
}

// maxDetections bounds how many reported entities are processed per scan —
// a runaway/adversarial model must not amplify work (untrusted input).
const maxDetections = 256

var errNotNERJSON = errors.New("model response is not the expected entities JSON object")

// ParseDetections extracts the model's detections from its reply. The prompt
// demands {"entities":[...]}, but small models under JSON mode degenerate in
// known structured ways that are still unambiguous detections — a bare
// top-level array ([] or [{"type":...}], observed deterministically from
// llama3.2:1b on placeholder-only verify re-scans) — so both shapes are
// accepted. Code fences and surrounding prose are tolerated. Anything without
// a parseable JSON value is an error — fail-closed, never "no PII found".
func ParseDetections(content string) ([]Detection, error) {
	payload := extractJSONValue(content)
	if payload == "" {
		return nil, errNotNERJSON
	}
	var raw []rawDetection
	if strings.HasPrefix(payload, "[") {
		if err := json.Unmarshal([]byte(payload), &raw); err != nil {
			return nil, errNotNERJSON
		}
	} else {
		var resp nerResponse
		if err := json.Unmarshal([]byte(payload), &resp); err != nil {
			return nil, errNotNERJSON
		}
		raw = resp.Entities
	}
	if len(raw) > maxDetections {
		raw = raw[:maxDetections]
	}
	dets, err := expandDetections(raw)
	if err != nil {
		return nil, err
	}
	if len(dets) > maxDetections {
		dets = dets[:maxDetections]
	}
	return dets, nil
}

// extractJSONValue returns the first top-level {...} object or [...] array in
// s, stripping markdown code fences. Small models drift in known ways; the
// fourth field-observed shape was a complete entities array whose outer
// object brace never arrived — the model wandered into whitespace and hit
// EOS ({"entities":[{...}\n\n]\n\n \n\n …). When the input ends with open
// delimiters, only whitespace after the last token, not inside a string, and
// not mid-structure (after , : { [), the missing closers are appended.
// json.Unmarshal remains the gate afterwards, so repair can only complete an
// envelope — never fabricate or alter detections; anything murkier stays a
// fail-closed decode error.
//
//nolint:gocyclo // string-aware delimiter scan: the states are inherent to JSON
func extractJSONValue(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return ""
	}
	var stack []byte
	inString := false
	escaped := false
	lastToken := -1
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
		case c == '{' || c == '[':
			stack = append(stack, c)
		case c == '}' || c == ']':
			if len(stack) == 0 {
				return ""
			}
			open := stack[len(stack)-1]
			if (c == '}' && open != '{') || (c == ']' && open != '[') {
				return "" // mismatched close: refuse
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return s[start : i+1]
			}
		}
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			lastToken = i
		}
	}
	// Input exhausted with open delimiters: conservative envelope repair.
	const maxRepairDepth = 8
	if len(stack) == 0 || len(stack) > maxRepairDepth || inString || lastToken < start {
		return ""
	}
	switch s[lastToken] {
	case '{', '[', ',', ':':
		return "" // stopped mid-structure: cannot know what was coming
	}
	closers := make([]byte, len(stack))
	for i := range stack {
		if stack[len(stack)-1-i] == '{' {
			closers[i] = '}'
		} else {
			closers[i] = ']'
		}
	}
	return s[start:lastToken+1] + string(closers)
}
