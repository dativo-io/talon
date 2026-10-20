package gateway

import (
	"context"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/workload"
)

// WorkloadHopRequest is a sandbox request whose destination is Talon's own
// HTTP API (the Action Gateway), presented at an external runtime's egress
// hop with the runtime-verified principal (#457/#482).
type WorkloadHopRequest struct {
	Runtime         string
	Principal       *workload.Principal
	IdentityFailure string
	Host, Method    string
	Path            string
}

// WorkloadHopDecision is the hop outcome: the use case the verified
// principal is bound to, or a stable refusal code. It carries no evidence
// id: the Action Gateway evidences the operation itself with the identity
// facts the hop verified.
type WorkloadHopDecision struct {
	Allowed bool
	Status  int
	Code    string
	Message string
	Agent   string
	Tenant  string
	Team    string
}

// ResolveWorkloadHop binds the runtime-verified principal to its configured
// use case for a request addressed to Talon itself. It is the same trust
// resolution the model path uses (resolveDelegatedAgent) plus the
// operational kill switch; no policy is evaluated here because the request
// has not reached the Action Gateway yet — it only becomes attributable.
func (g *Gateway) ResolveWorkloadHop(ctx context.Context, req WorkloadHopRequest) WorkloadHopDecision {
	agent, refused := g.resolveDelegatedAgent(ctx, DelegatedRequest{
		Runtime: req.Runtime, Principal: req.Principal, IdentityFailure: req.IdentityFailure, Host: req.Host,
	})
	if refused != nil {
		return WorkloadHopDecision{Status: refused.Status, Code: refused.Code, Message: refused.Message}
	}
	if !agent.Enabled {
		RecordGatewayError(ctx, CodeAgentDisabled)
		log.Warn().Str("runtime", req.Runtime).Str("agent", agent.Name).Msg("delegated_hop_agent_disabled")
		return WorkloadHopDecision{
			Status: http.StatusForbidden, Code: CodeAgentDisabled,
			Message: CodeAgentDisabled + ": agent \"" + agent.Name + "\" is disabled by its Talon agent config (enabled: false)",
			Agent:   agent.Name, Tenant: agent.TenantID,
		}
	}
	return WorkloadHopDecision{Allowed: true, Status: http.StatusOK, Agent: agent.Name, Tenant: agent.TenantID, Team: agent.Team}
}
