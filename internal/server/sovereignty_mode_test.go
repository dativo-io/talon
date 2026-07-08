package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestWithSovereigntyMode_SetsField guards the server-side half of the
// sovereignty-propagation fix (#261): the configured data-sovereignty mode is
// stored on the Server so both agent-run handlers can thread it into
// RunRequest.SovereigntyMode. Without this the HTTP runner path silently
// skipped compliance routing that the `talon run` CLI applied. The routing
// behavior itself is covered by
// TestResolveProvider_SovereigntyRoutes_USRejectedLocalSelected
// (internal/agent); here we pin that the option reaches the field the handlers
// read (handlers.go copies s.sovereigntyMode into every RunRequest).
func TestWithSovereigntyMode_SetsField(t *testing.T) {
	var s Server
	WithSovereigntyMode("eu_strict")(&s)
	assert.Equal(t, "eu_strict", s.sovereigntyMode)

	// Empty is a valid "disabled" value and must be preserved (no default).
	var s2 Server
	WithSovereigntyMode("")(&s2)
	assert.Equal(t, "", s2.sovereigntyMode)
}
