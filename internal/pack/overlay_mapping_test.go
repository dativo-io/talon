package pack

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/compliance"
)

// supportsLine matches structured overlay annotations of the form:
//
//	# supports: <framework> <article> — <source> (<control>)
var supportsLine = regexp.MustCompile(`#\s*supports:\s*([a-z0-9-]+)\s+(.+?)\s+—\s+(\S+)\s+\((.+)\)`)

// TestComplianceOverlays_AnnotationsLinkToMappings enforces link integrity
// (claims discipline): every "supports:" annotation in a compliance overlay must
// reference a Framework + Article that exists in compliance.DefaultMappings(),
// with the source file matching the mapping entry. Overlays must never annotate
// articles Talon has no shipping control for.
func TestComplianceOverlays_AnnotationsLinkToMappings(t *testing.T) {
	type key struct{ framework, article string }
	mappings := make(map[key]compliance.ControlMapping)
	for _, m := range compliance.DefaultMappings() {
		mappings[key{m.Framework, m.Article}] = m
	}

	for _, name := range ComplianceOverlayNames() {
		t.Run(name, func(t *testing.T) {
			content, err := ReadComplianceOverlay(name)
			require.NoError(t, err)

			matches := supportsLine.FindAllStringSubmatch(string(content), -1)
			require.NotEmpty(t, matches, "overlay %q must annotate at least one supported article", name)

			for _, m := range matches {
				framework, article, source := m[1], strings.TrimSpace(m[2]), m[3]
				entry, ok := mappings[key{framework, article}]
				assert.True(t, ok,
					"overlay %q annotates %s %s which has no entry in compliance.DefaultMappings() — remove the annotation or add a real control mapping",
					name, framework, article)
				if ok {
					assert.Equal(t, entry.Source, source,
						"overlay %q annotation for %s %s points at %s but the mapping entry says %s",
						name, framework, article, source, entry.Source)
				}
			}
		})
	}
}

// TestComplianceOverlays_OwnFrameworkAnnotated verifies each overlay annotates at
// least one article of the framework it is named after.
func TestComplianceOverlays_OwnFrameworkAnnotated(t *testing.T) {
	for _, name := range ComplianceOverlayNames() {
		content, err := ReadComplianceOverlay(name)
		require.NoError(t, err)
		assert.Contains(t, string(content), fmt.Sprintf("supports: %s ", name),
			"overlay %q should annotate at least one %s article", name, name)
	}
}

// TestComplianceOverlays_ClaimsDiscipline ensures the overlays never claim
// compliance outright (proof bar area 4: "supporting evidence", never "compliant").
func TestComplianceOverlays_ClaimsDiscipline(t *testing.T) {
	for _, name := range ComplianceOverlayNames() {
		content, err := ReadComplianceOverlay(name)
		require.NoError(t, err)
		text := strings.ToLower(string(content))
		assert.Contains(t, text, "supporting controls",
			"overlay %q should state it provides supporting controls", name)
		assert.Contains(t, text, "do not, by themselves, make you compliant",
			"overlay %q must carry the claims-discipline disclaimer", name)
	}
}
