// Data-flow tracking: records which data was sent to which destination
// (LLM provider, MCP tool, client output, cache) within one governed request.
// Every governed request records at least its primary egress flow; classified
// data additionally carries entity types and value digests — never raw values.
// Supports evidence for GDPR Art. 30 (records of processing, incl. recipients)
// and EU AI Act Art. 13.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/dativo-io/talon/internal/classifier"
)

// Data-flow source kinds: where the classified data appeared.
const (
	FlowSourcePrompt     = "prompt"
	FlowSourceAttachment = "attachment"
	FlowSourceToolArgs   = "tool_args"
	FlowSourceToolResult = "tool_result"
	FlowSourceResponse   = "response"
)

// Data-flow destination kinds: where the data went.
const (
	FlowDestLLMProvider = "llm_provider"
	FlowDestMCPTool     = "mcp_tool"
	FlowDestClient      = "client"
	FlowDestCache       = "cache"
)

// Data-flow dispositions: what happened to the data on the way to the destination.
const (
	FlowDispositionForwarded = "forwarded"
	FlowDispositionRedacted  = "redacted"
	FlowDispositionBlocked   = "blocked"
	FlowDispositionSurfaced  = "surfaced"
)

// FlowRegionUnknown is used when no region/jurisdiction could be resolved
// from configuration or provider metadata. Talon never guesses a region.
const FlowRegionUnknown = "unknown"

// DataFlow records movement of classified data for one governed request.
// It is an optional, signed section of the evidence record.
type DataFlow struct {
	// Detector identifies the analysis engine that produced the
	// classifications (e.g. "talon-regex"; future: "presidio").
	Detector string         `json:"detector,omitempty"`
	Items    []DataFlowItem `json:"items"`
}

// DataFlowItem links one classified data source to one destination.
type DataFlowItem struct {
	Source       string   `json:"source"`                  // prompt | attachment | tool_args | tool_result | response
	SourceDetail string   `json:"source_detail,omitempty"` // attachment filename, tool name
	Tier         int      `json:"tier"`                    // 0-2
	EntityTypes  []string `json:"entity_types,omitempty"`  // deduped, sorted canonical types: ["email","iban"]
	EntityCount  int      `json:"entity_count,omitempty"`  // merged (non-overlapping) entity spans
	ValueDigests []string `json:"value_digests,omitempty"` // per-request salted SHA-256 prefixes; never raw values
	// EntityAttributions provide compact, additive span attribution for evidence
	// (field path + byte range), never raw values.
	EntityAttributions []FlowEntityAttribution `json:"entity_attributions,omitempty"`
	Disposition        string                  `json:"disposition"` // forwarded | redacted | blocked | surfaced
	Destination        FlowDestination         `json:"destination"`
}

// FlowEntityAttribution carries compact per-entity attribution details used for
// auditability and targeted remediation. It intentionally excludes raw values.
type FlowEntityAttribution struct {
	Type       string            `json:"type"`
	FieldPath  string            `json:"field_path,omitempty"`
	Start      *int              `json:"start,omitempty"` // byte offset
	End        *int              `json:"end,omitempty"`   // byte offset
	Attributes map[string]string `json:"attributes,omitempty"`
}

// FlowDestination identifies where classified data was sent.
type FlowDestination struct {
	Kind     string `json:"kind"` // llm_provider | mcp_tool | client | cache
	Name     string `json:"name"` // "openai", upstream vendor, caller name, cache entry ID
	Model    string `json:"model,omitempty"`
	Endpoint string `json:"endpoint,omitempty"` // upstream host only (no path/query/credentials)
	Region   string `json:"region,omitempty"`   // jurisdiction: "EU" | "US" | "LOCAL" | "unknown"
}

// flowDigestSeparator is an ASCII unit separator preventing ambiguity between
// the concatenated digest inputs (tenant, correlation, type, value).
const flowDigestSeparator = "\x1f"

// FlowDigest returns a short, per-request salted digest of a classified value.
// The salt (tenant_id + correlation_id) deliberately prevents cross-request
// linkage while letting the same value in input and output of one request
// produce the same digest ("classified item X surfaced in output Z").
// The value is canonicalized (NFC + per-entity-type normalization) first so
// formatting differences ("DE89 3704..." vs "DE893704...") do not break the trail.
// Never returns or stores the raw value.
func FlowDigest(tenantID, correlationID, entityType, value string) string {
	canonical := CanonicalizeEntityValue(entityType, value)
	h := sha256.Sum256([]byte(
		tenantID + flowDigestSeparator +
			correlationID + flowDigestSeparator +
			entityType + flowDigestSeparator +
			canonical))
	return hex.EncodeToString(h[:])[:16]
}

// CanonicalizeEntityValue normalizes a matched entity value so that the same
// logical value always produces the same digest regardless of formatting:
// Unicode NFC normalization plus per-entity-type rules (separator stripping
// for structured identifiers, lowercasing for emails, etc.).
func CanonicalizeEntityValue(entityType, value string) string {
	v := norm.NFC.String(value)
	switch entityType {
	case "iban", "credit_card", "national_id", "ssn", "tax_id", "vat_id", "passport":
		// Structured identifiers: strip separators, uppercase.
		return strings.ToUpper(stripFlowSeparators(v))
	case "email":
		return strings.ToLower(strings.TrimSpace(v))
	case "phone":
		// Keep leading + and digits; strip spaces, hyphens, dots, parentheses.
		return stripFlowSeparators(v)
	default:
		return strings.TrimSpace(v)
	}
}

// stripFlowSeparators removes common formatting separators from identifier values.
func stripFlowSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '-', '.', '(', ')', '\t':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NewDataFlowItem builds a flow item from merged (non-overlapping) entity
// spans. Entity types and value digests are deduped and sorted so the signed
// canonical JSON is deterministic. Callers must pass entities through
// classifier.MergeEntitySpans first so counts are not inflated by
// overlapping recognizers.
func NewDataFlowItem(tenantID, correlationID, source, sourceDetail string, tier int, entities []classifier.PIIEntity, disposition string, dest FlowDestination) DataFlowItem {
	typeSet := make(map[string]struct{}, len(entities))
	digestSet := make(map[string]struct{}, len(entities))
	for _, e := range entities {
		typeSet[e.Type] = struct{}{}
		if e.Value != "" {
			digestSet[FlowDigest(tenantID, correlationID, e.Type, e.Value)] = struct{}{}
		}
	}
	return DataFlowItem{
		Source:             source,
		SourceDetail:       sourceDetail,
		Tier:               tier,
		EntityTypes:        sortedSetKeys(typeSet),
		EntityCount:        len(entities),
		ValueDigests:       sortedSetKeys(digestSet),
		EntityAttributions: compactEntityAttributions(source, entities),
		Disposition:        disposition,
		Destination:        dest,
	}
}

// NewDataFlowItemFromTypes builds a flow item when only entity types are
// available (e.g. attachment scans, which do not retain values or positions).
// No value digests are produced.
func NewDataFlowItemFromTypes(source, sourceDetail string, tier int, entityTypes []string, disposition string, dest FlowDestination) DataFlowItem {
	typeSet := make(map[string]struct{}, len(entityTypes))
	for _, t := range entityTypes {
		typeSet[t] = struct{}{}
	}
	return DataFlowItem{
		Source:       source,
		SourceDetail: sourceDetail,
		Tier:         tier,
		EntityTypes:  sortedSetKeys(typeSet),
		EntityCount:  len(typeSet),
		Disposition:  disposition,
		Destination:  dest,
	}
}

func sortedSetKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func compactEntityAttributions(source string, entities []classifier.PIIEntity) []FlowEntityAttribution {
	if len(entities) == 0 {
		return nil
	}

	out := make([]FlowEntityAttribution, 0, len(entities))
	seen := make(map[string]struct{}, len(entities))
	defaultPath := defaultFieldPathForSource(source)

	for _, e := range entities {
		if e.Type == "" {
			continue
		}
		fieldPath := strings.TrimSpace(e.FieldPath)
		if fieldPath == "" {
			fieldPath = defaultPath
		}
		start := e.Position
		end := e.Position + len(e.Value)
		att := FlowEntityAttribution{
			Type:      e.Type,
			FieldPath: fieldPath,
		}
		if e.Position >= 0 {
			att.Start = &start
		}
		if end >= 0 {
			att.End = &end
		}
		key := att.Type + "|" + att.FieldPath + "|" + ptrIntKey(att.Start) + "|" + ptrIntKey(att.End)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, att)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].FieldPath != out[j].FieldPath {
			return out[i].FieldPath < out[j].FieldPath
		}
		li, ri := ptrIntValue(out[i].Start), ptrIntValue(out[j].Start)
		if li != ri {
			return li < ri
		}
		return ptrIntValue(out[i].End) < ptrIntValue(out[j].End)
	})

	return out
}

func defaultFieldPathForSource(source string) string {
	switch source {
	case FlowSourcePrompt:
		return "messages[].content"
	case FlowSourceResponse:
		return "response.content"
	case FlowSourceToolArgs:
		return "arguments"
	case FlowSourceToolResult:
		return "result"
	case FlowSourceAttachment:
		return "attachment.text"
	default:
		return ""
	}
}

func ptrIntKey(v *int) string {
	if v == nil {
		return "_"
	}
	return strconv.Itoa(*v)
}

func ptrIntValue(v *int) int {
	if v == nil {
		return -1
	}
	return *v
}
