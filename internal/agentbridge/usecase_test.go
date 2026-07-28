package agentbridge

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/policy"
)

// FleetUseCase is the ONE policy → fleet mapping (#382): the server fleet
// endpoint and the CLI offline path both call it, so the projections cannot
// drift — this test pins the field-by-field contract.
func TestFleetUseCase(t *testing.T) {
	pol := &policy.Policy{Agent: policy.AgentConfig{
		Name: "support-bot",
		UseCase: &policy.UseCaseConfig{
			Purpose:     "Answer tier-1 customer questions",
			Department:  "Customer Support",
			Criticality: "important",
			Owners: &policy.UseCaseOwners{
				Business:  "Sofia Marino <s.marino@acme.example>",
				Technical: "support-platform@acme.example",
				Budget:    "cs-finops@acme.example",
				Risk:      "privacy-office@acme.example",
			},
			References: []string{"AIGOV-101"},
		},
	}}

	got := FleetUseCase(pol)
	assert.Equal(t, &fleet.UseCase{
		Purpose:        "Answer tier-1 customer questions",
		Department:     "Customer Support",
		Criticality:    "important",
		OwnerBusiness:  "Sofia Marino <s.marino@acme.example>",
		OwnerTechnical: "support-platform@acme.example",
		OwnerBudget:    "cs-finops@acme.example",
		OwnerRisk:      "privacy-office@acme.example",
		References:     []string{"AIGOV-101"},
	}, got)

	// Owners block absent: the flat fields stay empty, record still projects.
	pol.Agent.UseCase.Owners = nil
	partial := FleetUseCase(pol)
	assert.Empty(t, partial.OwnerBusiness)
	assert.Equal(t, "Customer Support", partial.Department)

	// Nil-safety at both levels: no policy, no record.
	assert.Nil(t, FleetUseCase(nil))
	assert.Nil(t, FleetUseCase(&policy.Policy{}), "agent without use_case projects no record")
}
