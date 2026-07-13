package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/secrets"
	"github.com/dativo-io/talon/internal/server"
)

// LoadedAgentFromPolicy is the shared policy → gateway adapter (#266). It
// lives in internal/agentbridge so `talon doctor` and `talon enforce enable`
// construct the IDENTICAL identity serve startup does — see that package's
// doc comment. This alias keeps cmd-internal call sites short.
func LoadedAgentFromPolicy(pol *policy.Policy, path string) gateway.LoadedAgent {
	return agentbridge.LoadedAgentFromPolicy(pol, path)
}

// buildServeIdentityRegistry applies the serve-time registry mode matrix
// (#266; regression-tested since the #279 review):
//
//	--gateway:           registry REQUIRED — a broken binding fails startup
//	                     (a gateway with no resolvable agent would reject
//	                     every request; the ≥1-keyed-agent gate runs later).
//	--proxy-quickstart:  registry SKIPPED — quickstart is zero-setup by
//	                     design and uses only the synthetic identity; its
//	                     tenant surface stays unmounted (see
//	                     docs/reference/proxy-quickstart.md).
//	plain serve:         registry BEST-EFFORT — a scaffolded-but-unminted
//	                     key must not break `talon init && talon serve` for
//	                     native-only use; tenant APIs simply reject agent
//	                     keys until the secret is set. EXCEPTION: an agent
//	                     key colliding with TALON_ADMIN_KEY is a security
//	                     misconfiguration, not an onboarding gap — terminal
//	                     in every mode that loads agent keys.
func buildServeIdentityRegistry(ctx context.Context, pol *policy.Policy, policyPath string, vault *secrets.SecretStore, adminKey string, gatewayMode, quickstart bool) (*gateway.IdentityRegistry, error) {
	if pol.Agent.Key == nil || pol.Agent.Key.SecretName == "" || quickstart {
		return nil, nil
	}
	// A gateway-bound agent's policy must not contain silently-ignored keys:
	// a typo like `montly:` or `allowed_provider:` would drop a budget or a
	// restriction. Fail startup instead (#266 review round 4). Gateway mode is
	// terminal; plain serve degrades like other registry-build problems.
	if unknownErr := policy.ValidateNoUnknownFields(policyPath); unknownErr != nil {
		if gatewayMode {
			return nil, unknownErr
		}
		log.Warn().Err(unknownErr).Msg("agent policy has unknown keys; tenant-scoped APIs may enforce less than intended")
	}
	registry, err := gateway.BuildIdentityRegistry(ctx, []gateway.LoadedAgent{
		agentbridge.LoadedAgentFromPolicy(pol, policyPath),
	}, vault, adminKey)
	if err != nil {
		if gatewayMode || errors.Is(err, gateway.ErrAdminKeyCollision) {
			return nil, fmt.Errorf("building agent identity registry: %w", err)
		}
		// Registry unavailable (unminted key). With no agent keys AND no
		// TALON_ADMIN_KEY, the tenant-scoped APIs are UNAUTHENTICATED (the
		// dev-mode open rule, #280) — say so plainly, not merely that agent
		// keys are rejected (#266 review round 4).
		if os.Getenv("TALON_ADMIN_KEY") == "" {
			log.Warn().Err(err).Msgf("agent identity registry unavailable and TALON_ADMIN_KEY unset — tenant-scoped APIs are UNAUTHENTICATED (dev mode). Set TALON_ADMIN_KEY and run `talon secrets set %s <key>` before exposing this server.", pol.Agent.Key.SecretName)
		} else {
			log.Warn().Err(err).Msgf("agent identity registry unavailable; tenant-scoped APIs accept the admin key only and reject agent keys until you run: talon secrets set %s <key>", pol.Agent.Key.SecretName)
		}
		return nil, nil
	}
	return registry, nil
}

// buildServeIdentityRegistryFromDir builds the registry from an agents_dir
// scan (#267): every agent.talon.yaml under the directory is one AI use case,
// and every one must validate and bind a minted key. Errors are ALWAYS
// terminal at startup, in gateway AND plain serve: agents_dir is deliberate
// fleet configuration, so the single-file "unminted key degrades to a nil
// registry" onboarding affordance does not apply. (During reload, #269, a
// failed scan keeps last-known-good instead.) The ScanResult travels back so
// the caller can log the generation and seed the reloader.
func buildServeIdentityRegistryFromDir(ctx context.Context, dir string, vault *secrets.SecretStore, adminKey string) (*gateway.IdentityRegistry, *agentcatalog.ScanResult, error) {
	scan, err := agentcatalog.DiscoverAgents(ctx, dir)
	if err != nil {
		return nil, scan, err
	}
	registry, err := gateway.BuildIdentityRegistry(ctx, scan.LoadedAgents(), vault, adminKey)
	if err != nil {
		return nil, scan, fmt.Errorf("building agent identity registry from agents_dir %s: %w", dir, err)
	}
	return registry, scan, nil
}

// shortGeneration abbreviates a scan digest for logs (full digests live in
// evidence, #269).
func shortGeneration(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// holderKeyResolver adapts the ONE runtime holder into the server's
// AgentKeyResolver (#289/#267): every auth check resolves against the
// CURRENT generation, so a reload swap (#269) propagates to the tenant-API
// surface without middleware rebuilds. Resolution reuses the registry's own
// constant-time key matching.
//
// Current() is read EXACTLY ONCE per authentication (#291 review, P1): the
// key-count fact (dev-open signal), the resolution, AND the generation token
// must come from the same snapshot — two separate reads could straddle a
// swap. The generation travels into the request identity so execution can
// fail closed when the fleet changed between authentication and run
// resolution (#267 review round 2).
type holderKeyResolver struct {
	holder *agentcatalog.RuntimeHolder
}

func (r holderKeyResolver) AuthenticateAgentKey(key string) server.AgentKeyAuth {
	snap := r.holder.Current() // the ONE generation this decision is made on
	var reg *gateway.IdentityRegistry
	var generation string
	if snap != nil {
		reg = snap.Registry
		generation = snap.Generation
	}
	auth := server.AgentKeyAuth{KeysConfigured: reg.Len() > 0}
	if id, ok := reg.ResolveKey(key); ok {
		auth.Found = true
		auth.Identity = requestctx.AgentIdentity{
			AgentID: id.Name, TenantID: id.TenantID, Team: id.Team,
			Generation: generation,
		}
	}
	return auth
}

// resolveRunTenant decides the tenant a native run attributes to (#266):
// agent.tenant_id is authoritative — the same agent file yields the same
// tenant on the gateway and the runner. An explicit --tenant flag may only
// confirm it; a mismatch errors. When the file omits tenant_id, the flag
// value applies (default "default").
func resolveRunTenant(pol *policy.Policy, flagTenant string, flagSet bool) (string, error) {
	fileTenant := pol.Agent.TenantID
	if fileTenant == "" {
		return flagTenant, nil
	}
	if flagSet && flagTenant != fileTenant {
		return "", fmt.Errorf("--tenant %q conflicts with agent.tenant_id %q in the agent policy — the agent file is authoritative (#266); drop the flag or fix the file", flagTenant, fileTenant)
	}
	return fileTenant, nil
}
