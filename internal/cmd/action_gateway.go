package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/approver"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/server"
)

// actionGateway is the serve-time composition of ActionGovernance (#458):
// one repository in the evidence database (state + evidence commit in one
// transaction), one trusted HTTP dispatcher, one approver store, and one
// immutable Service per AI use case AND runtime generation. The catalog and
// approval policy a Service governs with are the ones compiled INTO the
// generation (#427): a request resolves its Service from the generation it
// captured, so a reload can never change the catalog under an in-flight
// operation, and a new generation is served as soon as it is active.
type actionGateway struct {
	holder     *agentcatalog.RuntimeHolder
	repo       *action.Repository
	evStore    *evidence.Store
	dispatcher action.Dispatcher
	cryptor    *action.PayloadCryptor
	approvers  *approver.Store

	mu         sync.Mutex
	generation string
	services   map[string]*action.Service // tenant\x00agent, for `generation`
}

// buildActionGateway composes the gateway over the runtime holder. Without
// a usable payload key no operation can ever be established: that is a
// startup error when some agent already declares a catalog, and "no action
// gateway" otherwise. Attempts interrupted by a previous crash are
// recovered for every agent of the boot generation that declares a catalog.
func buildActionGateway(ctx context.Context, holder *agentcatalog.RuntimeHolder, evStore *evidence.Store, approverDBPath, vaultKey string) (*actionGateway, error) {
	snap := holder.Current()
	withCatalog := agentsWithCatalog(snap)
	cryptor, err := action.NewPayloadCryptor(vaultKey)
	if err != nil {
		if len(withCatalog) == 0 {
			log.Debug().Err(err).Msg("action_gateway_disabled_no_payload_key")
			return nil, nil
		}
		return nil, fmt.Errorf("action payload encryption: %w", err)
	}
	repo, err := action.NewRepository(ctx, evStore.DB())
	if err != nil {
		return nil, err
	}
	store, err := approver.NewStore(approverDBPath)
	if err != nil {
		return nil, fmt.Errorf("opening approver store: %w", err)
	}
	ag := &actionGateway{
		holder: holder, repo: repo, evStore: evStore, cryptor: cryptor, approvers: store,
		dispatcher: action.NewHTTPDispatcher(&http.Client{Timeout: 35 * time.Second}),
		services:   map[string]*action.Service{},
	}
	for _, ra := range withCatalog {
		svc, err := ag.serviceFor(snap, ra)
		if err != nil {
			return nil, err
		}
		if n, err := svc.RecoverInterrupted(ctx); err != nil {
			return nil, fmt.Errorf("agent %q: recovering interrupted attempts: %w", ra.Name, err)
		} else if n > 0 {
			log.Warn().Str("agent", ra.Name).Int("attempts", n).Msg("action_attempts_recovered_after_restart")
		}
		log.Info().Str("agent", ra.Name).Str("tenant", normalizedTenant(ra.TenantID)).Strs("actions", ra.Actions.Names()).Int("sources", len(ra.Actions.Sources())).Str("catalog", shortGeneration(ra.Actions.Digest)).Msg("action_catalog_active")
	}
	return ag, nil
}

// agentsWithCatalog lists the runtime agents whose generation carries a
// compiled action catalog.
func agentsWithCatalog(snap *agentcatalog.RuntimeSnapshot) []*agentcatalog.RuntimeAgent {
	if snap == nil {
		return nil
	}
	var out []*agentcatalog.RuntimeAgent
	for _, ra := range snap.List() {
		if ra.Actions != nil {
			out = append(out, ra)
		}
	}
	return out
}

// serviceFor returns the Service of one agent for one generation. Services
// are cached per generation; a generation change drops the previous set
// (a Service is cheap — the catalog and policy were compiled by the
// generation build).
func (ag *actionGateway) serviceFor(snap *agentcatalog.RuntimeSnapshot, ra *agentcatalog.RuntimeAgent) (*action.Service, error) {
	if ra.Actions == nil || ra.Approvals == nil {
		return nil, fmt.Errorf("agent %q: generation carries no compiled action catalog", ra.Name)
	}
	tenant := normalizedTenant(ra.TenantID)
	key := tenant + "\x00" + ra.Name
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if ag.generation != snap.Generation {
		ag.generation = snap.Generation
		ag.services = map[string]*action.Service{}
	}
	if svc, ok := ag.services[key]; ok {
		return svc, nil
	}
	svc, err := action.NewService(tenant, ra.Name, ra.Actions, ra.Approvals, ag.repo, ag.evStore, ag.dispatcher, ag.cryptor)
	if err != nil {
		return nil, err
	}
	ag.services[key] = svc
	return svc, nil
}

// resolver resolves the authenticated AI use case's Service from the
// generation its key authenticated against: the CURRENT generation must be
// that one (#267 — one request, one generation), otherwise the request is
// refused with generation_changed before any domain call. The resolved
// Service is bound to its immutable generation, so a reload that activates
// after resolution never changes the catalog under the request.
func (ag *actionGateway) resolver() server.ActionServiceResolver {
	return func(id requestctx.AgentIdentity) (*action.Service, error) {
		snap := ag.holder.Current()
		if id.Generation != "" && snap.Generation != id.Generation {
			return nil, &server.ActionServiceError{
				Code:    server.CodeGenerationChanged,
				Message: fmt.Sprintf("runtime generation changed between authentication and action resolution (authenticated %s, current %s); re-authenticate and retry", shortGeneration(id.Generation), shortGeneration(snap.Generation)),
			}
		}
		return ag.serviceIn(snap, id.TenantID, id.AgentID)
	}
}

// serviceIn resolves one agent's Service within one generation.
func (ag *actionGateway) serviceIn(snap *agentcatalog.RuntimeSnapshot, tenantID, agentID string) (*action.Service, error) {
	ra, ok := snap.Get(agentID)
	if !ok || ra.Actions == nil || normalizedTenant(ra.TenantID) != normalizedTenant(tenantID) {
		return nil, &server.ActionServiceError{Code: action.CodeActionNotFound, Message: "this AI use case declares no action catalog (agent.talon.yaml actions.definitions)"}
	}
	return ag.serviceFor(snap, ra)
}

// ownerResolver resolves the Service owning an approval for a REVIEWER
// decision. Reviewer credentials are tenant-scoped, not generation-bound,
// so the current generation is used; the domain revalidates the trusted
// definition/policy binding before it commits any decision or claim.
func (ag *actionGateway) ownerResolver() server.ApprovalOwnerResolver {
	return func(ctx context.Context, tenantScope, approvalID string) (*action.Service, bool) {
		tenant, agent, ok, err := ag.repo.OwnerOfApproval(ctx, tenantScope, approvalID)
		if err != nil || !ok {
			return nil, false
		}
		svc, err := ag.serviceIn(ag.holder.Current(), strings.TrimSpace(tenant), agent)
		if err != nil {
			return nil, false
		}
		return svc, true
	}
}
