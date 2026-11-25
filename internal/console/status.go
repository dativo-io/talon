package console

import (
	"context"
	"strings"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/fleet"
)

// UseCaseStatus is one AI use case's status (#575): effective.StatusOf over
// its fleet row and its effective report, the function `talon agents show
// <name>` prints its Status and Next with. It is kept apart from the fleet
// row: fleet health is not redefined, and a use case nothing serves, or that
// no authenticated request has reached, is not presented as working because
// its health is healthy.
type UseCaseStatus struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// Code, Headline, Next and Also are effective.StatusOf's.
	effective.Status
	// Reading is the connection and verification reading the status rests
	// on (effective.Verification.Reading); absent when not determined.
	Reading *effective.Reading `json:"reading,omitempty"`
	// Error says why the status is not determined (the report's build error).
	Error string `json:"error,omitempty"`
}

// UseCaseStatuses are the statuses of the use cases a page lists, one per
// fleet row, in the rows' order.
type UseCaseStatuses struct {
	Availability Availability    `json:"availability"`
	Items        []UseCaseStatus `json:"items"`
}

// useCaseStatuses derives each row's status from the same effective report
// the CLI builds, over the runtime records rt was assessed from and the agent
// scan the rows were projected from (scan; nil scans the files once).
//
// Cost: no agent scan when the rows' scan is given and one read of the
// gateway config for all rows, then per row a fixed number of indexed
// evidence lookups (the newest record of each qualifying invocation type and
// lifecycle event, plus the newest registration), the signature check of the
// records presented (at most five), and one read-only query of the vault's
// metadata. No per-row directory scan and no evidence range scan.
func (s *Service) useCaseStatuses(ctx context.Context, rows []fleet.AgentRow, rt Runtime, scan *agentcatalog.ScanResult) *UseCaseStatuses {
	out := &UseCaseStatuses{Items: []UseCaseStatus{}}
	src := s.cfg.ConfigSources
	var shared *effective.Shared
	if scan != nil {
		shared = effective.SharedFromScan(scan, src.GatewayConfig)
	} else {
		var err error
		if shared, err = effective.ReadShared(ctx, src.AgentsDir, src.DefaultPolicy, src.GatewayConfig); err != nil {
			out.Availability = unavailable(SourceConfigFiles, err)
			return out
		}
	}
	base := s.effectiveInputs(rt)
	base.Shared = shared
	var undetermined []string
	for i := range rows {
		if err := ctx.Err(); err != nil {
			return &UseCaseStatuses{Items: []UseCaseStatus{}, Availability: unavailable(SourceConfigFiles, err)}
		}
		row := &rows[i]
		in := base
		in.Name, in.Tenant = row.Name, row.TenantID
		item := UseCaseStatus{TenantID: row.TenantID, Name: row.Name}
		var v *effective.Verification
		switch r, err := effective.Build(ctx, in); {
		case err != nil:
			item.Error = err.Error()
			undetermined = append(undetermined, row.Name)
		case r.Verification != nil:
			v = r.Verification
			reading := v.Reading
			item.Reading = &reading
		}
		item.Status = effective.StatusOf(row, v)
		out.Items = append(out.Items, item)
	}
	out.Availability = ok(SourceConfigFiles, s.now())
	switch {
	case len(rows) == 0:
		out.Availability.State = StateEmpty
	case len(undetermined) > 0:
		out.Availability.State = StatePartial
		out.Availability.Unavailable = []string{"items.status"}
		out.Availability.Note = "the status of " + strings.Join(undetermined, ", ") + " is not determined: its effective report could not be built (see the item's error)"
	}
	return out
}
