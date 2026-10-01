package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/server"
)

// actionGateway is the serve-time composition of ActionGovernance (#458):
// one repository in the evidence database (state + evidence commit in one
// transaction), one trusted HTTP dispatcher, and one immutable Service per
// AI use case that declares an action catalog, built from the runtime
// generation active at startup. Catalog/approval-rule reload is not part
// of this slice: a changed agent file takes effect at the next start (the
// live generation keeps serving the catalog it was built with).
type actionGateway struct {
	services  map[string]*action.Service // tenant\x00agent
	repo      *action.Repository
	approvers *approver.Store
}

func buildActionGateway(ctx context.Context, snap *agentcatalog.RuntimeSnapshot, evStore *evidence.Store, approverDBPath, vaultKey string) (*actionGateway, error) {
	withCatalog := agentsWithCatalog(snap)
	if len(withCatalog) == 0 {
		return nil, nil
	}
	repo, err := action.NewRepository(ctx, evStore.DB())
	if err != nil {
		return nil, err
	}
	dispatcher := action.NewHTTPDispatcher(&http.Client{Timeout: 35 * time.Second})
	// Active payloads are sealed under a key derived from the vault key
	// (explicit version); without it no operation can be established.
	cryptor, err := action.NewPayloadCryptor(vaultKey)
	if err != nil {
		return nil, fmt.Errorf("action payload encryption: %w", err)
	}
	ag := &actionGateway{services: map[string]*action.Service{}, repo: repo}
	for _, ra := range withCatalog {
		tenant, svc, err := buildActionService(ctx, ra, repo, evStore, dispatcher, cryptor)
		if err != nil {
			return nil, err
		}
		ag.services[tenant+"\x00"+ra.Name] = svc
	}
	store, err := approver.NewStore(approverDBPath)
	if err != nil {
		return nil, fmt.Errorf("opening approver store: %w", err)
	}
	ag.approvers = store
	return ag, nil
}

// agentsWithCatalog lists the runtime agents that declare an action catalog.
func agentsWithCatalog(snap *agentcatalog.RuntimeSnapshot) []*agentcatalog.RuntimeAgent {
	if snap == nil {
		return nil
	}
	var out []*agentcatalog.RuntimeAgent
	for _, ra := range snap.List() {
		if ra.Policy != nil && ra.Policy.Actions != nil && len(ra.Policy.Actions.Definitions) > 0 {
			out = append(out, ra)
		}
	}
	return out
}

// buildActionService compiles one agent's catalog and approval policy and
// recovers attempts interrupted by a previous crash.
func buildActionService(ctx context.Context, ra *agentcatalog.RuntimeAgent, repo *action.Repository, evStore *evidence.Store, dispatcher action.Dispatcher, cryptor *action.PayloadCryptor) (string, *action.Service, error) {
	cat, err := action.CompileCatalog(ra.Policy.Actions)
	if err != nil {
		return "", nil, fmt.Errorf("agent %q (%s): %w", ra.Name, ra.Path, err)
	}
	ap, err := action.CompileApprovalPolicy(ra.Policy)
	if err != nil {
		return "", nil, fmt.Errorf("agent %q (%s): %w", ra.Name, ra.Path, err)
	}
	tenant := strings.TrimSpace(ra.TenantID)
	if tenant == "" {
		tenant = "default"
	}
	svc, err := action.NewService(tenant, ra.Name, cat, ap, repo, evStore, dispatcher, cryptor)
	if err != nil {
		return "", nil, err
	}
	if n, err := svc.RecoverInterrupted(ctx); err != nil {
		return "", nil, fmt.Errorf("agent %q: recovering interrupted attempts: %w", ra.Name, err)
	} else if n > 0 {
		log.Warn().Str("agent", ra.Name).Int("attempts", n).Msg("action_attempts_recovered_after_restart")
	}
	log.Info().Str("agent", ra.Name).Str("tenant", tenant).Strs("actions", cat.Names()).Msg("action_catalog_active")
	return tenant, svc, nil
}

func (ag *actionGateway) resolver() server.ActionServiceResolver {
	return func(tenantID, agentID string) (*action.Service, bool) {
		if tenantID == "" {
			tenantID = "default"
		}
		svc, ok := ag.services[tenantID+"\x00"+agentID]
		return svc, ok
	}
}

func (ag *actionGateway) ownerResolver() server.ApprovalOwnerResolver {
	return func(ctx context.Context, tenantScope, approvalID string) (*action.Service, bool) {
		tenant, agent, ok, err := ag.repo.OwnerOfApproval(ctx, tenantScope, approvalID)
		if err != nil || !ok {
			return nil, false
		}
		return ag.resolver()(tenant, agent)
	}
}
