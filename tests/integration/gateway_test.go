//go:build integration

package integration

import (
	"testing"

	"github.com/dativo-io/talon/internal/testutil"
)

func TestGateway_OpenAI_NonStreaming(t *testing.T) {
	mock := testutil.NewOpenAICompatibleServer("Hello from mock", 10, 12)
	defer mock.Close()

	// Start Talon with gateway pointing to mock.
	// (Implementation: build binary, write config with mock URL, start serve)
	// This test verifies: request round-trips, evidence generated, PII scanned.
	t.Skip("Implement after gateway is built — placeholder for Prompt 08 integration test")
}

func TestGateway_OpenAI_Streaming(t *testing.T) {
	mock := testutil.NewOpenAICompatibleServer("streaming", 10, 4)
	defer mock.Close()

	// Verify SSE chunks pass through byte-identical
	t.Skip("Implement after gateway is built — placeholder for Prompt 08 integration test")
}

func TestGateway_PolicyDeny_ReturnsProviderError(t *testing.T) {
	// Verify that when policy denies, Talon returns error in OpenAI format
	// {"error": {"message": "...", "type": "...", "code": N}}
	t.Skip("Implement after gateway is built — placeholder for Prompt 08 integration test")
}
