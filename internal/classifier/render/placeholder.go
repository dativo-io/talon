package render

import (
	"sort"
	"strings"

	"github.com/dativo-io/talon/internal/classifier/entity"
)

// AllowedAttrs returns which attributes may be emitted for an entity (by id).
// If nil or id not present, no extra attributes are emitted.
type AllowedAttrs func(entityID int) []string

// RedactOptions configures placeholder rendering.
type RedactOptions struct {
	UseEnriched bool         // if true, render XML-style with attributes when allowed
	Allowed     AllowedAttrs // which attributes to emit per entity (used when UseEnriched)
}

// RedactWithPlaceholders replaces spans in text with placeholders. When UseEnriched is false,
// uses legacy format [TYPE]. When true, uses <PII type="TYPE" id="N" .../> with deterministic
// attribute order (type, id, then allowed attributes in sorted order).
// Entities must be sorted by start offset and non-overlapping (caller responsibility).
func RedactWithPlaceholders(text string, entities []*entity.CanonicalEntity, opts *RedactOptions) string {
	if len(entities) == 0 {
		return text
	}
	useEnriched := opts != nil && opts.UseEnriched
	allowed := opts.Allowed

	// Build replacements from end to start to preserve indices
	type repl struct {
		start int
		end   int
		s     string
	}
	var repls []repl
	for _, e := range entities {
		if e == nil || e.Start < 0 || e.End > len(text) {
			continue
		}
		var placeholder string
		if useEnriched && allowed != nil {
			placeholder = formatEnriched(e, allowed(e.Id))
		} else {
			placeholder = formatLegacy(e.Type)
		}
		repls = append(repls, repl{start: e.Start, end: e.End, s: placeholder})
	}
	// Sort by start descending so we can replace from end
	sort.Slice(repls, func(i, j int) bool { return repls[i].start > repls[j].start })
	result := []byte(text)
	for _, r := range repls {
		result = append(result[:r.start], append([]byte(r.s), result[r.end:]...)...)
	}
	return string(result)
}

func formatLegacy(entityType string) string {
	return "[" + strings.ToUpper(entityType) + "]"
}

// formatEnriched produces <PII type="TYPE" id="N" attr1="v1" .../> with deterministic order.
// allowed lists attribute names that may be emitted (e.g. ["gender", "scope"]).
func formatEnriched(e *entity.CanonicalEntity, allowed []string) string {
	// Deterministic order: type, id, then allowed attributes sorted
	allowedSet := make(map[string]bool)
	for _, a := range allowed {
		allowedSet[a] = true
	}
	var attrs []string
	for k := range e.Attributes {
		if allowedSet[k] {
			attrs = append(attrs, k)
		}
	}
	sort.Strings(attrs)
	var sb strings.Builder
	sb.WriteString(`<PII type="`)
	sb.WriteString(e.Type)
	sb.WriteString(`" id="`)
	sb.WriteString(intToString(e.Id))
	sb.WriteString(`"`)
	for _, k := range attrs {
		if v, ok := e.Attributes[k]; ok && v != "" {
			sb.WriteString(` `)
			sb.WriteString(k)
			sb.WriteString(`="`)
			sb.WriteString(escapeXMLAttr(v))
			sb.WriteString(`"`)
		}
	}
	sb.WriteString(`/>`)
	return sb.String()
}

func intToString(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [20]byte
	i := len(b) - 1
	for n > 0 {
		b[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(b[i+1:])
}

func escapeXMLAttr(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString("&quot;")
		case '\'':
			sb.WriteString("&apos;")
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '&':
			sb.WriteString("&amp;")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
