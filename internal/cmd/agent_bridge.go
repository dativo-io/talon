package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/requestctx"
	"github.com/dativo-io/talon/internal/secrets"
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

// holderKeyResolver adapts the shared registry holder into the server's
// AgentKeyResolver (#289): every auth check resolves against the CURRENT
// registry snapshot, so a reload swap (#269) propagates to the tenant-API
// surface without middleware rebuilds. Resolution reuses the registry's own
// constant-time key matching.
type holderKeyResolver struct {
	holder *gateway.RegistryHolder
}

func (r holderKeyResolver) ResolveAgentKey(key string) (requestctx.AgentIdentity, bool) {
	id, ok := r.holder.Current().ResolveKey(key)
	if !ok {
		return requestctx.AgentIdentity{}, false
	}
	return requestctx.AgentIdentity{AgentID: id.Name, TenantID: id.TenantID, Team: id.Team}, true
}

func (r holderKeyResolver) HasAgentKeys() bool {
	return r.holder.Current().Len() > 0
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
