package console

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// EffectivePolicyDTO is the effective-policy report of one AI use case
// (#305): effective.Build, the projection `talon agents show <name>
// --effective --json` prints.
type EffectivePolicyDTO struct {
	Meta         Meta              `json:"meta"`
	Availability Availability      `json:"availability"`
	Report       *effective.Report `json:"report,omitempty"`
}

// EffectivePolicy builds the report for one use case from the console's
// configuration sources, its read-only store and its installation's
// runtime records.
func (s *Service) EffectivePolicy(ctx context.Context, tenant, name string) (*EffectivePolicyDTO, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: use case name is required", ErrInvalidArgument)
	}
	src := s.cfg.ConfigSources
	in := effective.Inputs{
		AgentsDir: src.AgentsDir, DefaultPolicy: src.DefaultPolicy, GatewayConfig: src.GatewayConfig, ProxyConfig: src.ProxyConfig,
		Name: name, Tenant: tenant, Evidence: s.cfg.Evidence, Now: s.now(),
	}
	rt := s.runtime()
	if rt.Availability.State == StateOK || rt.Availability.State == StateUnavailable {
		view := runtimestatus.View{Processes: rt.Processes}
		in.Runtime, in.RuntimeReadable = &view, rt.Availability.State == StateOK
	}
	out := &EffectivePolicyDTO{Meta: s.meta(tenant)}
	r, err := effective.Build(ctx, in)
	switch {
	case errors.Is(err, effective.ErrUnknownUseCase):
		return nil, fmt.Errorf("%w: %v", ErrNotFound, err)
	case err != nil:
		out.Availability = unavailable(SourceConfigFiles, err)
		return out, nil
	}
	out.Report = r
	out.Meta = s.meta(r.TenantID)
	out.Availability = ok(SourceConfigFiles, s.now())
	if !r.Effective.ProvenActive {
		out.Availability.State = StatePartial
		out.Availability.Unavailable = []string{"report.effective.proven_active"}
		out.Availability.Note = "compiled from the current files; " + r.Loaded.Reason
	}
	return out, nil
}
