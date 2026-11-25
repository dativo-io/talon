package console

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
	in := s.effectiveInputs(s.runtime())
	in.Name, in.Tenant = name, tenant
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
	// Each enforcement boundary is proved on its own; what is not proved is
	// named, never inferred from the other boundary.
	var notes []string
	if !r.Effective.ProvenActive {
		out.Availability.Unavailable = append(out.Availability.Unavailable, "report.effective.proven_active")
		notes = append(notes, "gateway policy compiled from the current files, not proven active: "+r.Effective.Proof.Reason)
	}
	if b := r.ActionBoundary; b != nil && !b.ProvenActive {
		out.Availability.Unavailable = append(out.Availability.Unavailable, "report.action_boundary.proven_active")
		notes = append(notes, "action policy compiled from the current files, not proven active: "+b.Proof.Reason)
	}
	if len(notes) > 0 {
		out.Availability.State = StatePartial
		out.Availability.Note = strings.Join(notes, "; ")
	}
	return out, nil
}

// effectiveInputs are what every effective report of this console reads:
// its configuration files, its read-only store, the vault's metadata and the
// runtime records rt was assessed from. The effective-policy route and the
// use-case status (#575) both start from here, so they read alike; Name and
// Tenant are the caller's.
func (s *Service) effectiveInputs(rt Runtime) effective.Inputs {
	src := s.cfg.ConfigSources
	in := effective.Inputs{
		AgentsDir: src.AgentsDir, DefaultPolicy: src.DefaultPolicy, GatewayConfig: src.GatewayConfig,
		Evidence: s.cfg.Evidence, Now: s.now(),
	}
	if s.cfg.DataDir != "" {
		// The vault's METADATA only, through a read-only connection and
		// without a decryption key: when the use case's credential was last
		// written. The console never reads a secret's value.
		in.SecretsDB = filepath.Join(s.cfg.DataDir, "secrets.db")
	}
	if rt.Availability.State == StateOK || rt.Availability.State == StateUnavailable {
		// ReadAt is part of the view, as in the CLI: whether the runtime
		// records still cover the moment an older record was written depends
		// on it (effective.servedByCurrent).
		view := runtimestatus.View{ReadAt: rt.ReadAt, Processes: rt.Processes}
		in.Runtime, in.RuntimeReadable = &view, rt.Availability.State == StateOK
	}
	return in
}
