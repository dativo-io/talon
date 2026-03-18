package render

import (
	"testing"

	"github.com/dativo-io/talon/internal/classifier/entity"
	"github.com/stretchr/testify/assert"
)

func TestRedactWithPlaceholders_Legacy(t *testing.T) {
	text := "Hello Mrs Smith in Berlin."
	entities := []*entity.CanonicalEntity{
		{Id: 1, Type: "person", Raw: "Mrs Smith", Start: 6, End: 15},
		{Id: 2, Type: "location", Raw: "Berlin", Start: 19, End: 25},
	}
	opts := &RedactOptions{UseEnriched: false}
	out := RedactWithPlaceholders(text, entities, opts)
	assert.Equal(t, "Hello [PERSON] in [LOCATION].", out)
}

func TestRedactWithPlaceholders_Enriched(t *testing.T) {
	text := "Hello Mrs Smith in Berlin."
	entities := []*entity.CanonicalEntity{
		{Id: 1, Type: "person", Raw: "Mrs Smith", Start: 6, End: 15, Attributes: map[string]string{"gender": "female"}},
		{Id: 2, Type: "location", Raw: "Berlin", Start: 19, End: 25, Attributes: map[string]string{"scope": "city"}},
	}
	allowedMap := map[int][]string{1: {"gender"}, 2: {"scope"}}
	opts := &RedactOptions{
		UseEnriched: true,
		Allowed:     func(id int) []string { return allowedMap[id] },
	}
	out := RedactWithPlaceholders(text, entities, opts)
	assert.Contains(t, out, `<PII type="person" id="1" gender="female"/>`)
	assert.Contains(t, out, `<PII type="location" id="2" scope="city"/>`)
	assert.Equal(t, "Hello <PII type=\"person\" id=\"1\" gender=\"female\"/> in <PII type=\"location\" id=\"2\" scope=\"city\"/>.", out)
}

func TestRedactWithPlaceholders_DeterministicOrder(t *testing.T) {
	// Attributes should appear in sorted order (gender before scope)
	ent := &entity.CanonicalEntity{
		Id: 1, Type: "person", Raw: "x", Start: 0, End: 1,
		Attributes: map[string]string{"scope": "city", "gender": "female"},
	}
	opts := &RedactOptions{
		UseEnriched: true,
		Allowed:     func(int) []string { return []string{"gender", "scope"} },
	}
	out := RedactWithPlaceholders("x", []*entity.CanonicalEntity{ent}, opts)
	// Order: type, id, then sorted attrs -> gender, scope
	assert.Equal(t, `<PII type="person" id="1" gender="female" scope="city"/>`, out)
}

func TestRedactWithPlaceholders_EmptyEntities(t *testing.T) {
	out := RedactWithPlaceholders("hello", nil, nil)
	assert.Equal(t, "hello", out)
	out = RedactWithPlaceholders("hello", []*entity.CanonicalEntity{}, &RedactOptions{})
	assert.Equal(t, "hello", out)
}

func TestFormatLegacy(t *testing.T) {
	assert.Equal(t, "[EMAIL]", formatLegacy("email"))
	assert.Equal(t, "[PERSON]", formatLegacy("person"))
}

func TestEscapeXMLAttr(t *testing.T) {
	assert.Equal(t, "a&amp;b", escapeXMLAttr("a&b"))
	assert.Equal(t, "&lt;tag&gt;", escapeXMLAttr("<tag>"))
	assert.Equal(t, "&quot;x&quot;", escapeXMLAttr("\"x\""))
}
