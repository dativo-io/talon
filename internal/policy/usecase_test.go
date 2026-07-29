package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Operating-record contract (#382): optional use_case block — parsing,
// validation rules, and backward compatibility.

const useCaseAgentYAML = `
agent:
  name: support-bot
  version: "1.0.0"
  use_case:
    purpose: "Answer tier-1 customer questions"
    department: "Customer Support"
    criticality: important
    owners:
      business: "Sofia Marino <s.marino@acme.example>"
      technical: "support-platform@acme.example"
      budget: "cs-finops@acme.example"
      risk: "privacy-office@acme.example"
    references:
      - "AIGOV-101"
policies:
  cost_limits:
    daily: 10.0
`

func writeUseCasePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.talon.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadPolicy_UseCaseParsed(t *testing.T) {
	path := writeUseCasePolicy(t, useCaseAgentYAML)
	pol, err := LoadPolicy(context.Background(), path, false, filepath.Dir(path))
	require.NoError(t, err)
	uc := pol.Agent.UseCase
	require.NotNil(t, uc)
	assert.Equal(t, "Answer tier-1 customer questions", uc.Purpose)
	assert.Equal(t, "Customer Support", uc.Department)
	assert.Equal(t, "important", uc.Criticality)
	require.NotNil(t, uc.Owners)
	assert.Equal(t, "Sofia Marino <s.marino@acme.example>", uc.Owners.Business)
	assert.Equal(t, "privacy-office@acme.example", uc.Owners.Risk)
	assert.Equal(t, []string{"AIGOV-101"}, uc.References)
}

// Existing configs without the block stay valid, parse to nil, and keep their
// canonical digest unchanged — the record is purely additive.
func TestLoadPolicy_UseCaseAbsentBackCompat(t *testing.T) {
	without := "agent:\n  name: support-bot\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 10.0\n"
	path := writeUseCasePolicy(t, without)
	pol, err := LoadPolicy(context.Background(), path, false, filepath.Dir(path))
	require.NoError(t, err)
	assert.Nil(t, pol.Agent.UseCase)
	require.NotEmpty(t, pol.Hash)

	// Adding the block changes the digest (it is part of the config's
	// identity); removing it restores the original — no hidden state.
	withPath := writeUseCasePolicy(t, useCaseAgentYAML)
	withPol, err := LoadPolicy(context.Background(), withPath, false, filepath.Dir(withPath))
	require.NoError(t, err)
	assert.NotEqual(t, pol.Hash, withPol.Hash)
}

func TestLoadPolicy_UseCaseCriticalityClosedVocabulary(t *testing.T) {
	bad := strings.Replace(useCaseAgentYAML, "criticality: important", "criticality: sev1", 1)
	path := writeUseCasePolicy(t, bad)
	_, err := LoadPolicy(context.Background(), path, false, filepath.Dir(path))
	require.Error(t, err, "free-form criticality must be rejected, not become a private risk taxonomy")
	assert.Contains(t, err.Error(), "criticality")
}

func TestValidateUseCase_Bounds(t *testing.T) {
	assert.NoError(t, ValidateUseCase(nil), "record is optional")
	assert.NoError(t, ValidateUseCase(&UseCaseConfig{}), "empty record is valid")
	assert.NoError(t, ValidateUseCase(&UseCaseConfig{Criticality: "critical"}))

	assert.Error(t, ValidateUseCase(&UseCaseConfig{Criticality: "high"}))
	assert.Error(t, ValidateUseCase(&UseCaseConfig{Purpose: strings.Repeat("x", useCasePurposeMaxLen+1)}))
	assert.Error(t, ValidateUseCase(&UseCaseConfig{Department: strings.Repeat("x", useCaseFieldMaxLen+1)}))
	assert.Error(t, ValidateUseCase(&UseCaseConfig{Owners: &UseCaseOwners{Budget: strings.Repeat("x", useCaseFieldMaxLen+1)}}))
	assert.Error(t, ValidateUseCase(&UseCaseConfig{References: make([]string, useCaseMaxReferences+1)}))
	assert.Error(t, ValidateUseCase(&UseCaseConfig{References: []string{strings.Repeat("x", useCaseReferenceMaxLen+1)}}))
}
