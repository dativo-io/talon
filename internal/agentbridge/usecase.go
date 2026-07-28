package agentbridge

import (
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/policy"
)

// FleetUseCase maps the agent config's operating record onto the fleet
// projection (#382). It lives here — next to the policy → gateway identity
// adapter — so the server fleet endpoint and the CLI offline path project the
// IDENTICAL representation instead of each re-reading YAML shapes; fleet
// itself stays a leaf read model with no policy import. Nil in, nil out: an
// agent without a use_case block projects no record.
func FleetUseCase(pol *policy.Policy) *fleet.UseCase {
	if pol == nil || pol.Agent.UseCase == nil {
		return nil
	}
	uc := pol.Agent.UseCase
	out := &fleet.UseCase{
		Purpose:     uc.Purpose,
		Department:  uc.Department,
		Criticality: uc.Criticality,
		References:  append([]string(nil), uc.References...),
	}
	if uc.Owners != nil {
		out.OwnerBusiness = uc.Owners.Business
		out.OwnerTechnical = uc.Owners.Technical
		out.OwnerBudget = uc.Owners.Budget
		out.OwnerRisk = uc.Owners.Risk
	}
	return out
}
