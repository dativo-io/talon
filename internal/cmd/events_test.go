package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/events"
)

func TestPrintOperationalEvent_Text(t *testing.T) {
	eventsJSON = false
	var out bytes.Buffer
	printOperationalEvent(&out, events.OperationalEvent{
		Timestamp:     time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC),
		TenantID:      "acme",
		Caller:        "hr-service",
		Decision:      "blocked",
		ReasonCode:    "POLICY_DENIED",
		ReasonText:    "Request blocked by policy.",
		CostEUR:       0.0,
		Model:         "gpt-4o",
		EvidenceID:    "ev-123",
		CorrelationID: "corr-123",
	})
	text := out.String()
	assert.Contains(t, text, "tenant=acme")
	assert.Contains(t, text, "decision=blocked")
	assert.Contains(t, text, "reason_code=POLICY_DENIED")
	assert.Contains(t, text, "reason_text=Request blocked by policy.")
	assert.Contains(t, text, "evidence=ev-123")
	assert.Contains(t, text, "correlation=corr-123")
}

func TestPrintOperationalEvent_JSON(t *testing.T) {
	eventsJSON = true
	t.Cleanup(func() { eventsJSON = false })

	var out bytes.Buffer
	printOperationalEvent(&out, events.OperationalEvent{
		EventID:    "1-ev-1",
		EvidenceID: "ev-1",
		Decision:   "allowed",
	})
	var got events.OperationalEvent
	assert.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, "ev-1", got.EvidenceID)
	assert.Equal(t, "allowed", got.Decision)
}
