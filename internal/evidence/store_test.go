package evidence

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/dativo-io/talon/internal/explanation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSigningKey = "test-signing-key-1234567890123456"

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "evidence.db"), testSigningKey)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStoreAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	gen := NewGenerator(store)
	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_test123",
		TenantID:       "acme",
		AgentID:        "sales-analyst",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{
			Allowed:       true,
			Action:        "allow",
			PolicyVersion: "1.0.0:sha256:abc12345",
		},
		Classification: Classification{
			InputTier:   0,
			PIIDetected: []string{},
		},
		ModelUsed:      "gpt-4",
		Cost:           0.0018,
		Tokens:         TokenUsage{Input: 100, Output: 50},
		DurationMS:     250,
		InputPrompt:    "Hello world",
		OutputResponse: "Hi there",
		Compliance: Compliance{
			Frameworks:   []string{"gdpr", "iso-27001"},
			DataLocation: "eu-west-1",
		},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ev.ID)
	assert.NotEmpty(t, ev.Signature)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, ev.ID, retrieved.ID)
	assert.Equal(t, "acme", retrieved.TenantID)
	assert.Equal(t, "sales-analyst", retrieved.AgentID)
	assert.Equal(t, "gpt-4", retrieved.Execution.ModelUsed)
}

func TestStoreEvidence_WithRoutingDecision(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	rd := &RoutingDecision{
		SelectedProvider: "openai",
		SelectedModel:    "gpt-4",
		RejectedCandidates: []RejectedCandidate{
			{ProviderID: "anthropic", Reason: "jurisdiction not allowed"},
		},
	}
	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:   "corr_routing",
		TenantID:        "acme",
		AgentID:         "agent",
		InvocationType:  "manual",
		PolicyDecision:  PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:       "gpt-4",
		Cost:            0.001,
		RoutingDecision: rd,
	})
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved.RoutingDecision)
	assert.Equal(t, "openai", retrieved.RoutingDecision.SelectedProvider)
	assert.Equal(t, "gpt-4", retrieved.RoutingDecision.SelectedModel)
	require.Len(t, retrieved.RoutingDecision.RejectedCandidates, 1)
	assert.Equal(t, "anthropic", retrieved.RoutingDecision.RejectedCandidates[0].ProviderID)
	assert.Equal(t, "jurisdiction not allowed", retrieved.RoutingDecision.RejectedCandidates[0].Reason)
}

func TestStoreEvidence_WithoutRoutingDecision(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_no_routing",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4",
		Cost:           0.001,
		// RoutingDecision intentionally nil (backward compat)
	})
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Nil(t, retrieved.RoutingDecision, "existing evidence without routing_decision should remain nil")
}

func TestGenerateAddsMandatoryExplanations(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_explanations",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "1.2.3:sha256:abc12345"},
		ModelUsed:      "gpt-4o-mini",
	})
	require.NoError(t, err)
	require.NotEmpty(t, ev.Explanations)
	assert.NotEmpty(t, ev.Explanations[0].Code)
	assert.NotEmpty(t, ev.Explanations[0].Reason)
	assert.Equal(t, "1.2.3:sha256:abc12345", ev.Explanations[0].VersionIdentity)
}

func TestIndexIncludesPrimaryExplanationFields(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)
	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_idx_expl",
		TenantID:       "default",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{
			Allowed:       false,
			Action:        "deny",
			Reasons:       []string{"daily budget exceeded"},
			PolicyVersion: "1.0.0:sha256:deadbeef",
		},
	})
	require.NoError(t, err)

	index, err := store.ListIndex(ctx, "default", "", time.Time{}, time.Time{}, 10, "", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, index)
	assert.NotEmpty(t, index[0].PrimaryExplanationCode)
	assert.NotEmpty(t, index[0].PrimaryExplanationReason)
}

func TestGenerate_InputHashDeterministic(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	params := GenerateParams{
		CorrelationID:  "corr_hash1",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "Summarize this document",
		OutputResponse: "Summary here",
	}
	ev1, err := gen.Generate(ctx, params)
	require.NoError(t, err)
	params.CorrelationID = "corr_hash2"
	params.OutputResponse = "Different response"
	ev2, err := gen.Generate(ctx, params)
	require.NoError(t, err)

	assert.NotEmpty(t, ev1.AuditTrail.InputHash, "InputHash should be set")
	assert.Equal(t, ev1.AuditTrail.InputHash, ev2.AuditTrail.InputHash,
		"same InputPrompt should yield same InputHash (for memory dedup)")

	params.InputPrompt = "Different prompt"
	params.CorrelationID = "corr_hash3"
	ev3, err := gen.Generate(ctx, params)
	require.NoError(t, err)
	assert.NotEqual(t, ev1.AuditTrail.InputHash, ev3.AuditTrail.InputHash,
		"different InputPrompt should yield different InputHash")
}

func TestInputHashWithAttachmentHashes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	params := GenerateParams{
		CorrelationID:    "corr_att1",
		TenantID:         "acme",
		AgentID:          "agent",
		InvocationType:   "manual",
		PolicyDecision:   PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:      "Summarize the document",
		OutputResponse:   "Summary",
		AttachmentHashes: []string{"aa", "bb"},
	}
	ev1, err := gen.Generate(ctx, params)
	require.NoError(t, err)

	params.CorrelationID = "corr_att2"
	params.AttachmentHashes = []string{"aa", "bb"}
	ev2, err := gen.Generate(ctx, params)
	require.NoError(t, err)
	assert.Equal(t, ev1.AuditTrail.InputHash, ev2.AuditTrail.InputHash,
		"same prompt + same attachment hashes → same InputHash")

	params.CorrelationID = "corr_att3"
	params.AttachmentHashes = []string{"aa", "cc"}
	ev3, err := gen.Generate(ctx, params)
	require.NoError(t, err)
	assert.NotEqual(t, ev1.AuditTrail.InputHash, ev3.AuditTrail.InputHash,
		"different attachment hashes → different InputHash")
}

func TestVerifySignature(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	gen := NewGenerator(store)
	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_verify",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	valid, err := store.Verify(ctx, ev.ID)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestListWithFilters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	// Create records for two tenants
	for _, tenant := range []string{"acme", "globex"} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_" + tenant,
			TenantID:       tenant,
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
	}

	// List for acme only
	results, err := store.List(ctx, "acme", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "acme", results[0].TenantID)

	// List all
	all, err := store.List(ctx, "", "", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestListIndex(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_idx",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4",
		Cost:           0.005,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	index, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "", "")
	require.NoError(t, err)
	assert.Len(t, index, 1)
	assert.True(t, index[0].Allowed)
	assert.Equal(t, "gpt-4", index[0].ModelUsed)
}

func TestTimeline(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	var middleID string
	for i := 0; i < 5; i++ {
		ev, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_tl",
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
		if i == 2 {
			middleID = ev.ID
		}
		// Small sleep to ensure timestamp ordering
		time.Sleep(5 * time.Millisecond)
	}

	timeline, err := store.Timeline(ctx, middleID, 2, 2)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(timeline), 3) // at least: 2 before + target + some after
}

func TestGetNonexistent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_, err := store.Get(ctx, "ev_does_not_exist")
	assert.Error(t, err)
}

func TestGenerateWithError(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_err",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4",
		DurationMS:     100,
		Error:          "connection timeout",
		InputPrompt:    "test",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ev.ID)
	assert.NotEmpty(t, ev.Execution.Error)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, "connection timeout", retrieved.Execution.Error)
}

func TestGenerate_NoDuplicateExecutionFailureWhenExplanationFactsAlreadySet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_exec_dedup",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow", PolicyVersion: "1.0.0:sha256:abc"},
		ModelUsed:      "gpt-4",
		Error:          "provider unavailable",
		ExplanationFacts: []explanation.Fact{{
			Code:            explanation.CodeExecutionFailed,
			Decision:        explanation.DecisionFailure,
			Stage:           "execution",
			Trigger:         "provider unavailable",
			PolicyRef:       "policy:1.0.0:sha256:abc",
			VersionIdentity: "1.0.0:sha256:abc",
		}},
	})
	require.NoError(t, err)

	nExec := 0
	for _, ex := range ev.Explanations {
		if ex.Code == explanation.CodeExecutionFailed {
			nExec++
		}
	}
	assert.Equal(t, 1, nExec, "params.Error must not add a second execution failure when ExplanationFacts already includes one")
}

func TestGenerateWithAttachmentScan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_att",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		AttachmentScan: &AttachmentScan{
			FilesProcessed:     2,
			InjectionsDetected: 1,
			ActionTaken:        "blocked",
			BlockedFiles:       []string{"malicious.pdf"},
		},
		InputPrompt: "test",
	})
	require.NoError(t, err)
	assert.NotNil(t, ev.AttachmentScan)
	assert.Equal(t, 1, ev.AttachmentScan.InjectionsDetected)
}

func TestGenerateWithAttachmentScanPIIFields(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_att_pii",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		AttachmentScan: &AttachmentScan{
			FilesProcessed:           1,
			InjectionsDetected:       0,
			ActionTaken:              "sandboxed",
			PIIDetectedInAttachments: []string{"email", "iban"},
			AttachmentTier:           2,
		},
		InputPrompt: "summarize",
	})
	require.NoError(t, err)
	require.NotNil(t, ev.AttachmentScan)
	assert.Equal(t, []string{"email", "iban"}, ev.AttachmentScan.PIIDetectedInAttachments)
	assert.Equal(t, 2, ev.AttachmentScan.AttachmentTier)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"email", "iban"}, retrieved.AttachmentScan.PIIDetectedInAttachments)
	assert.Equal(t, 2, retrieved.AttachmentScan.AttachmentTier)
}

func TestVerifyTamperedData(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_tamper",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "test",
	})
	require.NoError(t, err)

	// Tamper with the stored data
	_, err = store.db.ExecContext(ctx,
		`UPDATE evidence SET evidence_json = REPLACE(evidence_json, '"acme"', '"tampered"') WHERE id = ?`, ev.ID)
	require.NoError(t, err)

	valid, err := store.Verify(ctx, ev.ID)
	require.NoError(t, err)
	assert.False(t, valid, "tampered evidence should fail verification")
}

func TestListIndexWithTimeFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	for i := 0; i < 3; i++ {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_tf",
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
		})
		require.NoError(t, err)
	}

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	index, err := store.ListIndex(ctx, "acme", "agent", from, to, 10, "", "", "")
	require.NoError(t, err)
	assert.Len(t, index, 3)

	futureFrom := time.Now().Add(1 * time.Hour)
	futureTo := time.Now().Add(2 * time.Hour)
	empty, err := store.ListIndex(ctx, "acme", "agent", futureFrom, futureTo, 10, "", "", "")
	require.NoError(t, err)
	assert.Len(t, empty, 0)
}

// TestListIndexByInvocationType ensures limit is applied after filtering by invocation_type,
// so e.g. trigger history returns the N most recent webhook entries, not N overall then filtered.
func TestListIndexByInvocationType(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	// Mix of types: 3 webhook:zendesk, 2 manual, 2 cron (7 total)
	for _, inv := range []string{"webhook:zendesk", "webhook:zendesk", "manual", "cron", "webhook:zendesk", "manual", "cron"} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_inv",
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: inv,
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
		})
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	// Without filter: limit 50 returns up to 50 (we have 7)
	all, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 50, "", "", "")
	require.NoError(t, err)
	assert.Len(t, all, 7)

	// With invocationType filter: limit applies *after* filter, so we get all 3 webhook:zendesk
	webhook, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 50, "webhook:zendesk", "", "")
	require.NoError(t, err)
	assert.Len(t, webhook, 3, "should return all webhook:zendesk entries when limit is 50")
	for i := range webhook {
		assert.Equal(t, "webhook:zendesk", webhook[i].InvocationType)
	}

	// Limit 2 with filter returns 2 most recent webhook:zendesk only
	webhook2, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 2, "webhook:zendesk", "", "")
	require.NoError(t, err)
	assert.Len(t, webhook2, 2)
	for i := range webhook2 {
		assert.Equal(t, "webhook:zendesk", webhook2[i].InvocationType)
	}
}

func TestListIndexAllowedAndModelFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	// One allowed gpt-4, one denied gpt-4, one allowed claude
	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID: "corr_a1", TenantID: "acme", AgentID: "a",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4", InputPrompt: "p", OutputResponse: "r",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID: "corr_a2", TenantID: "acme", AgentID: "a",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		ModelUsed:      "gpt-4", InputPrompt: "p",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID: "corr_a3", TenantID: "acme", AgentID: "a",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "claude-3", InputPrompt: "p", OutputResponse: "r",
	})
	require.NoError(t, err)

	all, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "", "")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	allowedOnly, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "true", "")
	require.NoError(t, err)
	assert.Len(t, allowedOnly, 2)
	for i := range allowedOnly {
		assert.True(t, allowedOnly[i].Allowed)
	}

	deniedOnly, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "false", "")
	require.NoError(t, err)
	assert.Len(t, deniedOnly, 1)
	assert.False(t, deniedOnly[0].Allowed)

	modelGpt4, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "", "gpt-4")
	require.NoError(t, err)
	assert.Len(t, modelGpt4, 2)
	for i := range modelGpt4 {
		assert.Equal(t, "gpt-4", modelGpt4[i].ModelUsed)
	}

	modelClaude, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "", "claude-3")
	require.NoError(t, err)
	assert.Len(t, modelClaude, 1)
	assert.Equal(t, "claude-3", modelClaude[0].ModelUsed)

	allowedAndModel, err := store.ListIndex(ctx, "acme", "", time.Time{}, time.Time{}, 10, "", "true", "gpt-4")
	require.NoError(t, err)
	assert.Len(t, allowedAndModel, 1)
	assert.True(t, allowedAndModel[0].Allowed)
	assert.Equal(t, "gpt-4", allowedAndModel[0].ModelUsed)
}

func TestDenialsByReason(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	total, byReason, err := store.DenialsByReason(ctx, "acme", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.NotNil(t, byReason)

	gen := NewGenerator(store)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID: "corr_dr1", TenantID: "acme", AgentID: "a",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		InputPrompt:    "p",
	})
	require.NoError(t, err)
	total, byReason, err = store.DenialsByReason(ctx, "acme", time.Time{}, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.GreaterOrEqual(t, byReason["policy_deny"], 0)
}

func TestListWithAgentFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	for _, agent := range []string{"sales", "support", "sales"} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_af",
			TenantID:       "acme",
			AgentID:        agent,
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			InputPrompt:    "test",
		})
		require.NoError(t, err)
	}

	salesOnly, err := store.List(ctx, "acme", "sales", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, salesOnly, 2)

	supportOnly, err := store.List(ctx, "", "support", time.Time{}, time.Time{}, 10)
	require.NoError(t, err)
	assert.Len(t, supportOnly, 1)
}

func TestListWithTimeRange(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_tr",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		InputPrompt:    "test",
	})
	require.NoError(t, err)

	from := time.Now().Add(-1 * time.Hour)
	to := time.Now().Add(1 * time.Hour)
	results, err := store.List(ctx, "", "", from, to, 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)

	// Future range returns empty
	futureFrom := time.Now().Add(1 * time.Hour)
	futureTo := time.Now().Add(2 * time.Hour)
	empty, err := store.List(ctx, "", "", futureFrom, futureTo, 10)
	require.NoError(t, err)
	assert.Len(t, empty, 0)
}

func TestGenerateWithSecretsAndMemory(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:   "corr_sm",
		TenantID:        "acme",
		AgentID:         "agent",
		InvocationType:  "manual",
		PolicyDecision:  PolicyDecision{Allowed: true, Action: "allow"},
		SecretsAccessed: []string{"openai-api-key", "db-password"},
		MemoryWrites: []MemoryWrite{
			{Category: "factual_corrections", EntryID: "mem_001"},
		},
		InputPrompt:    "test",
		OutputResponse: "response",
		ToolsCalled:    []string{"search", "email"},
	})
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"openai-api-key", "db-password"}, retrieved.SecretsAccessed)
	assert.Len(t, retrieved.MemoryWrites, 1)
	assert.Equal(t, []string{"search", "email"}, retrieved.Execution.ToolsCalled)
}

func TestAvgTTFTAndAvgTPOT(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	from := now.Add(-1 * time.Hour)
	to := now.Add(1 * time.Hour)

	// Store two evidence records with streaming metrics
	for i, ttft := range []int64{100, 200} {
		tpot := 0.5 + float64(i)*0.5 // 0.5 and 1.0
		ev := &Evidence{
			ID:             fmt.Sprintf("ev-ttft-%d", i),
			CorrelationID:  "corr",
			Timestamp:      now,
			TenantID:       "default",
			AgentID:        "caller-1",
			InvocationType: "gateway",
			PolicyDecision: PolicyDecision{Allowed: true},
			Classification: Classification{},
			Execution: Execution{
				ModelUsed:  "gpt-4o",
				Cost:       0.01,
				Tokens:     TokenUsage{Input: 10, Output: 20},
				DurationMS: 500,
				TTFTMS:     ttft,
				TPOTMS:     tpot,
			},
			AuditTrail: AuditTrail{},
			Compliance: Compliance{},
		}
		err := store.Store(ctx, ev)
		require.NoError(t, err)
	}

	avgTTFT, err := store.AvgTTFT(ctx, "default", "", from, to)
	require.NoError(t, err)
	assert.InDelta(t, 150.0, avgTTFT, 0.1, "avg of 100 and 200")

	avgTPOT, err := store.AvgTPOT(ctx, "default", "", from, to)
	require.NoError(t, err)
	assert.InDelta(t, 0.75, avgTPOT, 0.01, "avg of 0.5 and 1.0")
}

func TestVerifyNonexistentEvidence(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.Verify(ctx, "ev_nonexistent")
	assert.Error(t, err)
}

func TestNewStoreInvalidSigningKey(t *testing.T) {
	dir := t.TempDir()
	_, err := NewStore(filepath.Join(dir, "ev.db"), "short-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signer")
}

func TestSignerKeyTooShort(t *testing.T) {
	_, err := NewSigner("short")
	assert.Error(t, err)
}

func TestSignAndVerify(t *testing.T) {
	signer, err := NewSigner(testSigningKey)
	require.NoError(t, err)

	data := []byte(`{"test": "data"}`)

	sig, err := signer.Sign(data)
	require.NoError(t, err)
	assert.True(t, signer.Verify(data, sig))
	assert.False(t, signer.Verify([]byte("tampered"), sig))
}

func TestSignerWithHexKey(t *testing.T) {
	// 64 hex chars → 32 bytes (full HMAC key strength); recommended: openssl rand -hex 32
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signer, err := NewSigner(hexKey)
	require.NoError(t, err)
	data := []byte("payload")
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	assert.True(t, signer.Verify(data, sig))
}

func TestCostTotal(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	// Agent A: 0.01 + 0.02
	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_c1",
		TenantID:       "acme",
		AgentID:        "agent-a",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.01,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_c2",
		TenantID:       "acme",
		AgentID:        "agent-a",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.02,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)
	// Agent B: 0.03
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_c3",
		TenantID:       "acme",
		AgentID:        "agent-b",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.03,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	totalAll, err := store.CostTotal(ctx, "acme", "", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.06, totalAll, 0.0001)

	totalA, err := store.CostTotal(ctx, "acme", "agent-a", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.03, totalA, 0.0001)

	totalB, err := store.CostTotal(ctx, "acme", "agent-b", dayStart, dayEnd)
	require.NoError(t, err)
	assert.InDelta(t, 0.03, totalB, 0.0001)
}

func TestCostByAgent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	for _, p := range []struct {
		agent string
		cost  float64
	}{
		{"sales-analyst", 1.5},
		{"support-bot", 0.5},
		{"sales-analyst", 2.0},
	} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_cba",
			TenantID:       "tenant1",
			AgentID:        p.agent,
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			Cost:           p.cost,
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
	}

	byAgent, err := store.CostByAgent(ctx, "tenant1", dayStart, dayEnd)
	require.NoError(t, err)
	assert.Len(t, byAgent, 2)
	assert.InDelta(t, 3.5, byAgent["sales-analyst"], 0.0001)
	assert.InDelta(t, 0.5, byAgent["support-bot"], 0.0001)
}

func TestGenerateWithDegradation(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	ev, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr_deg",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		ModelUsed:      "gpt-4o-mini",
		OriginalModel:  "gpt-4o",
		Degraded:       true,
		Cost:           0.001,
		InputPrompt:    "test",
		OutputResponse: "response",
	})
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, ev.ID)
	require.NoError(t, err)
	assert.True(t, retrieved.Execution.Degraded)
	assert.Equal(t, "gpt-4o", retrieved.Execution.OriginalModel)
	assert.Equal(t, "gpt-4o-mini", retrieved.Execution.ModelUsed)
}

func BenchmarkEvidenceStore(b *testing.B) {
	dir := b.TempDir()
	store, err := NewStore(filepath.Join(dir, "evidence.db"), testSigningKey)
	require.NoError(b, err)
	defer store.Close()
	gen := NewGenerator(store)
	ctx := context.Background()
	params := GenerateParams{
		CorrelationID:  "corr_bench",
		TenantID:       "acme",
		AgentID:        "agent",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.001,
		InputPrompt:    "bench",
		OutputResponse: "bench",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gen.Generate(ctx, params)
	}
}

func TestStoreStepAndListSteps(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	corrID := "corr_step_test"
	_, err := gen.GenerateStep(ctx, StepParams{
		CorrelationID: corrID, TenantID: "acme", AgentID: "agent",
		StepIndex: 0, Type: "llm_call",
		OutputSummary: "model response summary",
		DurationMS:    100, Cost: 0.002,
	})
	require.NoError(t, err)

	_, err = gen.GenerateStep(ctx, StepParams{
		CorrelationID: corrID, TenantID: "acme", AgentID: "agent",
		StepIndex: 1, Type: "tool_call", ToolName: "search",
		OutputSummary: "tool result",
		DurationMS:    5, Cost: 0,
	})
	require.NoError(t, err)

	steps, err := store.ListStepsByCorrelationID(ctx, corrID)
	require.NoError(t, err)
	require.Len(t, steps, 2)
	assert.Equal(t, 0, steps[0].StepIndex)
	assert.Equal(t, "llm_call", steps[0].Type)
	assert.Equal(t, int64(100), steps[0].DurationMS)
	assert.Equal(t, 1, steps[1].StepIndex)
	assert.Equal(t, "tool_call", steps[1].Type)
	assert.Equal(t, "search", steps[1].ToolName)
	assert.NotEmpty(t, steps[0].Signature)
	assert.NotEmpty(t, steps[1].Signature)
}

func TestStepEvidence_ValidationErrorAndSessionFields(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	step, err := gen.GenerateStep(ctx, StepParams{
		CorrelationID:   "corr_val",
		SessionID:       "sess_abc123",
		TenantID:        "acme",
		AgentID:         "agent",
		StepIndex:       0,
		Type:            "tool_call",
		ToolName:        "search",
		OutputSummary:   "result",
		DurationMS:      10,
		Cost:            0,
		ValidationError: "schema validation failed: query: invalid type. Expected: string, given: integer",
		Stage:           "generation",
		CandidateIndex:  1,
		JudgeScore:      0.85,
		Selected:        false,
	})
	require.NoError(t, err)
	require.NotEmpty(t, step.ID)

	steps, err := store.ListStepsByCorrelationID(ctx, "corr_val")
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "sess_abc123", steps[0].SessionID)
	assert.Equal(t, "generation", steps[0].Stage)
	assert.Equal(t, 1, steps[0].CandidateIndex)
	assert.Equal(t, 0.85, steps[0].JudgeScore)
	assert.False(t, steps[0].Selected)
	assert.Contains(t, steps[0].ValidationError, "schema validation failed")
}

func TestEvidence_SessionIDStageCandidateAndListBySessionID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)

	sessionID := "sess_ruler_001"
	for i := 0; i < 3; i++ {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr_sess_" + fmt.Sprint(i),
			SessionID:      sessionID,
			Stage:          "generation",
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			ModelUsed:      "gpt-4",
			Cost:           0.001 * float64(i+1),
			CandidateIndex: i,
			JudgeScore:     0.5 + float64(i)*0.1,
			Selected:       i == 1,
			InputPrompt:    "test",
			OutputResponse: "response",
		})
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
	}

	list, err := store.ListBySessionID(ctx, sessionID)
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, sessionID, list[0].SessionID)
	assert.Equal(t, "generation", list[0].Stage)
	var foundSelected bool
	for _, ev := range list {
		if ev.Selected {
			foundSelected = true
			assert.Equal(t, 1, ev.CandidateIndex)
			assert.Equal(t, 0.6, ev.JudgeScore)
		}
	}
	assert.True(t, foundSelected)

	empty, err := store.ListBySessionID(ctx, "sess_nonexistent")
	require.NoError(t, err)
	assert.Len(t, empty, 0)
}

func TestListTenantIDs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	for _, tt := range []struct{ tenant, agent string }{
		{"acme", "agent1"},
		{"acme", "agent2"},
		{"beta", "agent1"},
	} {
		_, err := gen.Generate(ctx, GenerateParams{
			CorrelationID:  "corr-" + tt.tenant + "-" + tt.agent,
			TenantID:       tt.tenant,
			AgentID:        tt.agent,
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			Cost:           0.001,
			InputPrompt:    "x",
			OutputResponse: "y",
		})
		require.NoError(t, err)
	}

	ids, err := store.ListTenantIDs(ctx, dayStart, dayEnd)
	require.NoError(t, err)
	assert.Len(t, ids, 2) // acme, beta
	assert.Contains(t, ids, "acme")
	assert.Contains(t, ids, "beta")
}

func TestCountDeniedInRange(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr-allowed",
		TenantID:       "acme",
		AgentID:        "a1",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.001,
		InputPrompt:    "x",
		OutputResponse: "y",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "corr-denied",
		TenantID:       "acme",
		AgentID:        "a1",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		Cost:           0,
		InputPrompt:    "x",
		OutputResponse: "",
	})
	require.NoError(t, err)

	n, err := store.CountDeniedInRange(ctx, "acme", "", dayStart, dayEnd)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestTenantsSummary(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthEnd := monthStart.AddDate(0, 1, 0)

	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "c1",
		TenantID:       "acme",
		AgentID:        "a1",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.5,
		InputPrompt:    "x",
		OutputResponse: "y",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "c2",
		TenantID:       "beta",
		AgentID:        "a1",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		Cost:           0,
		InputPrompt:    "x",
		OutputResponse: "",
	})
	require.NoError(t, err)

	summary, err := store.TenantsSummary(ctx, dayStart, dayEnd, monthStart, monthEnd, "")
	require.NoError(t, err)
	require.Len(t, summary, 2)
	var acme, beta *TenantSummary
	for i := range summary {
		switch summary[i].TenantID {
		case "acme":
			acme = &summary[i]
		case "beta":
			beta = &summary[i]
		}
	}
	require.NotNil(t, acme)
	require.NotNil(t, beta)
	assert.Equal(t, 1, acme.RequestVolume)
	assert.InDelta(t, 0.5, acme.SpendToday, 1e-6)
	assert.Equal(t, 0, acme.Denials)
	assert.Equal(t, 1, beta.RequestVolume)
	assert.Equal(t, 1, beta.Denials) // one denied request for beta
}

func TestAgentsSummary(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	gen := NewGenerator(store)
	_, err := gen.Generate(ctx, GenerateParams{
		CorrelationID:  "c1",
		TenantID:       "acme",
		AgentID:        "agent-x",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
		Cost:           0.1,
		InputPrompt:    "x",
		OutputResponse: "y",
	})
	require.NoError(t, err)
	_, err = gen.Generate(ctx, GenerateParams{
		CorrelationID:  "c2",
		TenantID:       "acme",
		AgentID:        "agent-y",
		InvocationType: "manual",
		PolicyDecision: PolicyDecision{Allowed: false, Action: "deny"},
		Cost:           0,
		InputPrompt:    "x",
		OutputResponse: "",
	})
	require.NoError(t, err)

	// No time filter to avoid SQLite timestamp format sensitivity; get all-time agent summary.
	agents, err := store.AgentsSummary(ctx, time.Time{}, time.Time{}, "")
	require.NoError(t, err)
	require.Len(t, agents, 2)
	var ax, ay *AgentSummary
	for i := range agents {
		switch agents[i].AgentID {
		case "agent-x":
			ax = &agents[i]
		case "agent-y":
			ay = &agents[i]
		}
	}
	require.NotNil(t, ax)
	require.NotNil(t, ay)
	assert.Equal(t, "acme", ax.TenantID)
	assert.Equal(t, 1, ax.Requests)
	assert.InDelta(t, 0.1, ax.CostEUR, 1e-6)
	assert.Equal(t, 0, ax.Blocked)
	assert.Equal(t, "acme", ay.TenantID)
	assert.Equal(t, 1, ay.Blocked)
}

func BenchmarkCostTotal(b *testing.B) {
	dir := b.TempDir()
	store, err := NewStore(filepath.Join(dir, "evidence.db"), testSigningKey)
	require.NoError(b, err)
	defer store.Close()
	gen := NewGenerator(store)
	ctx := context.Background()
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)
	for i := 0; i < 100; i++ {
		_, _ = gen.Generate(ctx, GenerateParams{
			CorrelationID:  fmt.Sprintf("corr_%d", i),
			TenantID:       "acme",
			AgentID:        "agent",
			InvocationType: "manual",
			PolicyDecision: PolicyDecision{Allowed: true, Action: "allow"},
			Cost:           0.001 * float64(i+1),
			InputPrompt:    "bench",
			OutputResponse: "bench",
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.CostTotal(ctx, "acme", "", dayStart, dayEnd)
	}
}
