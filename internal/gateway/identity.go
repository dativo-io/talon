package gateway

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sort"
	"strings"

	"github.com/dativo-io/talon/internal/secrets"
)

// Agent identity model (#266): one agent.talon.yaml = one AI use case = one
// Talon traffic identity = one active vault-bound key.
//
//	[]LoadedAgent ──► BuildIdentityRegistry(agents, vault) ──► immutable IdentityRegistry
//	                                                                 │
//	                                       presented key ──► ResolveKey ──► *ResolvedIdentity
//
// A presented key resolves to exactly one agent or the request is rejected;
// the only non-key identity is the explicit quickstart synthetic identity.
// tenant_id is derived key → agent → tenant_id — the only tenant derivation.

// LoadedAgent is one agent config as loaded from an agent.talon.yaml, mapped
// to gateway-native types by the serve-time bridge (the gateway package stays
// free of the policy loader). #266 loads the single default agent policy;
// #267 plugs agents_dir discovery into the same slice.
type LoadedAgent struct {
	// Path is the config file the agent was loaded from (surfaced by the
	// fleet view, #270).
	Path string
	// Name is the agent's operational identity, unique per installation.
	Name string
	// TenantID the agent belongs to. Empty means "default".
	TenantID string
	// KeySecretName is the vault secret holding the agent's one active Talon
	// key. Required for every agent loaded into the gateway registry.
	KeySecretName string
	// Team attributes spend/evidence to a team (evidence.Team, CostByTeam).
	Team string
	// Tags classify telemetry (e.g. "copaw" drives OTel/dashboard views).
	Tags []string
	// AllowedProviders restricts reachable gateway providers. Empty = all.
	AllowedProviders []string
	// AcceptClientMetadata gates recording of client-asserted orchestration
	// identity (#194). nil = true.
	AcceptClientMetadata *bool
	// Override is the agent's explicit policy override — exactly one override
	// layer over the organization baseline.
	Override *PolicyOverride
}

// PolicyOverride is the canonical per-agent policy override. It is the ONLY
// override vocabulary the gateway consumes; the bridge adapts the agent-file
// fields (cost_limits, session_limits, capabilities, data_classification,
// models, egress) into it. Zero/empty fields inherit the organization
// baseline — see ResolveEffectivePolicy for the per-field contract.
type PolicyOverride struct {
	MaxDailyCost   float64 // replace baseline when > 0
	MaxMonthlyCost float64 // replace baseline when > 0
	// MaxSessionCost is a soft cap on accumulated spend per coding session
	// (#198): a new request is denied once session spend + the pre-request
	// estimate exceeds it. Applies to client/vendor-asserted sessions.
	MaxSessionCost float64 // set when > 0

	PIIAction         string // block | redact | warn | allow; empty inherits
	ResponsePIIAction string // block | redact | warn | allow; empty inherits

	AllowedModels []string // replace baseline when non-empty
	BlockedModels []string // replace baseline when non-empty
	MaxDataTier   *TierLevel

	AllowedTools     []string // most-specific non-empty list wins
	ForbiddenTools   []string // union with baseline + provider
	ToolPolicyAction string   // filter | block; most-specific wins

	// Egress replaces the organization baseline egress policy wholesale when set.
	Egress *EgressPolicyConfig
}

// ResolvedIdentity is the runtime identity of one AI use case, produced by
// the registry from a presented key (or synthesized for quickstart mode).
// #268 adds Enabled; the struct is the seam for the fleet issues (#267–#270).
type ResolvedIdentity struct {
	Name       string
	TenantID   string
	Team       string
	ConfigPath string
	Tags       []string

	AllowedProviders     []string
	AcceptClientMetadata *bool
	Override             *PolicyOverride

	// key is the resolved traffic key material. Unexported: it exists only
	// for constant-time matching inside the registry and is never persisted
	// or logged.
	key []byte
}

// AcceptsClientMetadata reports whether client-asserted orchestration
// identity is recorded for this agent. Default true when unset (#194).
func (id *ResolvedIdentity) AcceptsClientMetadata() bool {
	return id == nil || id.AcceptClientMetadata == nil || *id.AcceptClientMetadata
}

// HasTag reports whether the identity carries the given telemetry tag.
func (id *ResolvedIdentity) HasTag(tag string) bool {
	if id == nil {
		return false
	}
	for _, t := range id.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// NewQuickstartIdentity returns the synthetic identity for --proxy-quickstart
// mode — the ONLY identity not backed by a vault key. It is injected via
// request context by the quickstart facade and cannot be reached through
// normal key resolution, so it is impossible to confuse with production
// authentication. Its budget caps come from the quickstart organization
// baseline (QuickstartConfig), not from an override.
func NewQuickstartIdentity() *ResolvedIdentity {
	return &ResolvedIdentity{
		Name:             quickstartAgentName,
		TenantID:         quickstartTenantID,
		Tags:             []string{"quickstart"},
		AllowedProviders: []string{"openai"},
	}
}

// IdentityRegistry is the immutable key → agent registry, built once after
// the vault is available and shared by the gateway data plane, server
// tenant-API auth, and metrics/cache tenant scoping. Periodic reload (#269)
// swaps whole registries atomically; nothing mutates one in place.
type IdentityRegistry struct {
	identities []*ResolvedIdentity
}

// BuildIdentityRegistry resolves every agent's key binding through the vault
// and validates the set fail-closed. Errors name the offending agents so an
// operator can fix config without guessing:
//   - duplicate agent name
//   - missing key binding (gateway-loaded agents must be keyed)
//   - missing / ACL-denied secret (vault access is audit-logged either way)
//   - empty resolved key material
//   - two agents resolving to the same key
func BuildIdentityRegistry(ctx context.Context, agents []LoadedAgent, vault *secrets.SecretStore) (*IdentityRegistry, error) {
	reg := &IdentityRegistry{identities: make([]*ResolvedIdentity, 0, len(agents))}
	byName := make(map[string]string, len(agents))   // name → path
	byKey := make(map[string]string, len(agents))    // raw key → agent name (build-time dup check only)
	bySecret := make(map[string]string, len(agents)) // secret name → agent name

	for i := range agents {
		a := &agents[i]
		if strings.TrimSpace(a.Name) == "" {
			return nil, fmt.Errorf("agent config %s: agent.name is required", a.Path)
		}
		if prev, dup := byName[a.Name]; dup {
			return nil, fmt.Errorf("duplicate agent name %q: defined in both %s and %s — agent names are unique per installation", a.Name, prev, a.Path)
		}
		byName[a.Name] = a.Path

		if a.KeySecretName == "" {
			return nil, fmt.Errorf("agent %q (%s): agent.key.secret_name is required for gateway-loaded agents — bind the traffic key via `talon secrets set <name> <key>` and reference it, or run the agent natively only", a.Name, a.Path)
		}
		if prev, dup := bySecret[a.KeySecretName]; dup {
			return nil, fmt.Errorf("agents %q and %q both bind vault secret %q — one active key per agent, one agent per key", prev, a.Name, a.KeySecretName)
		}
		bySecret[a.KeySecretName] = a.Name

		tenantID := strings.TrimSpace(a.TenantID)
		if tenantID == "" {
			tenantID = "default"
		}

		if err := a.Override.finalize("agent " + a.Name); err != nil {
			return nil, fmt.Errorf("agent %q (%s): %w", a.Name, a.Path, err)
		}

		secret, err := vault.Get(ctx, a.KeySecretName, tenantID, a.Name)
		if err != nil {
			return nil, fmt.Errorf("agent %q (%s): resolving key secret %q: %w", a.Name, a.Path, a.KeySecretName, err)
		}
		keyMaterial := strings.TrimSpace(string(secret.Value))
		if keyMaterial == "" {
			return nil, fmt.Errorf("agent %q (%s): key secret %q resolved to an empty value — set it via `talon secrets set %s <key>`", a.Name, a.Path, a.KeySecretName, a.KeySecretName)
		}
		if prev, dup := byKey[keyMaterial]; dup {
			return nil, fmt.Errorf("agents %q and %q resolve to the same key material — a key identifies exactly one AI use case", prev, a.Name)
		}
		byKey[keyMaterial] = a.Name

		reg.identities = append(reg.identities, &ResolvedIdentity{
			Name:                 a.Name,
			TenantID:             tenantID,
			Team:                 a.Team,
			ConfigPath:           a.Path,
			Tags:                 append([]string(nil), a.Tags...),
			AllowedProviders:     append([]string(nil), a.AllowedProviders...),
			AcceptClientMetadata: a.AcceptClientMetadata,
			Override:             a.Override.clone(),
			key:                  []byte(keyMaterial),
		})
	}
	return reg, nil
}

// ResolveKey matches a presented key against the registry in constant time
// per identity. Returns (nil, false) for unknown keys — the agent rejects.
func (r *IdentityRegistry) ResolveKey(presented string) (*ResolvedIdentity, bool) {
	if r == nil || presented == "" {
		return nil, false
	}
	presentedBytes := []byte(presented)
	var match *ResolvedIdentity
	for _, id := range r.identities {
		if subtle.ConstantTimeCompare(id.key, presentedBytes) == 1 {
			match = id
		}
	}
	if match == nil {
		return nil, false
	}
	return match, true
}

// Len reports how many traffic-bound agents the registry holds.
func (r *IdentityRegistry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.identities)
}

// TenantIDs returns the sorted distinct tenant IDs across all agents — the
// source for metrics tenant scoping and cache tenant canonicalization.
func (r *IdentityRegistry) TenantIDs() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.identities))
	for _, id := range r.identities {
		seen[id.TenantID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// MetricsTenantScope returns the tenant_id filter for dashboard SQL
// aggregates: single-tenant installations scope to that tenant, multi-tenant
// ones use "" (all tenants).
func (r *IdentityRegistry) MetricsTenantScope() string {
	ids := r.TenantIDs()
	if len(ids) == 1 {
		return ids[0]
	}
	return ""
}

// AuthKeyTenantProjection projects the registry into the key → tenant_id map
// consumed by the server tenant-API middleware. The registry is the single
// source; this is a projection, kept only because the middleware wants a
// plain map. Auth openness is governed by the admin-key dev rule, never by
// this map being empty.
func (r *IdentityRegistry) AuthKeyTenantProjection() map[string]string {
	m := make(map[string]string)
	if r == nil {
		return m
	}
	for _, id := range r.identities {
		m[string(id.key)] = id.TenantID
	}
	return m
}

// Identities returns the resolved identities (for fleet views and preflight
// checks). The slice is a copy; identities themselves are shared and must be
// treated as immutable.
func (r *IdentityRegistry) Identities() []*ResolvedIdentity {
	if r == nil {
		return nil
	}
	return append([]*ResolvedIdentity(nil), r.identities...)
}

// finalize normalizes the override in place and validates its semantic
// constraints. It runs for every agent at registry build, regardless of how
// the LoadedAgent was produced (serve bridge, #267 scanner, tests).
func (o *PolicyOverride) finalize(scope string) error {
	if o == nil {
		return nil
	}
	switch o.PIIAction {
	case "", "block", "redact", "warn", "allow":
	default:
		return fmt.Errorf("%s: pii action must be block, redact, warn, or allow, got %q", scope, o.PIIAction)
	}
	switch o.ResponsePIIAction {
	case "", "block", "redact", "warn", "allow":
	default:
		return fmt.Errorf("%s: response pii action must be block, redact, warn, or allow, got %q", scope, o.ResponsePIIAction)
	}
	switch o.ToolPolicyAction {
	case "", "filter", "block":
	default:
		return fmt.Errorf("%s: tool_policy_action must be filter or block, got %q", scope, o.ToolPolicyAction)
	}
	if o.MaxDataTier != nil && (*o.MaxDataTier < 0 || *o.MaxDataTier > 2) {
		return fmt.Errorf("%s: max_data_tier must be 0, 1, or 2, got %d", scope, int(*o.MaxDataTier))
	}
	if o.MaxDailyCost < 0 || o.MaxMonthlyCost < 0 || o.MaxSessionCost < 0 {
		return fmt.Errorf("%s: cost caps must not be negative", scope)
	}
	o.Egress.applyDefaults()
	return validateEgressPolicy(scope, o.Egress)
}

// clone deep-copies the override so registry identities never alias the
// loader's structs (reload snapshot safety, #269).
func (o *PolicyOverride) clone() *PolicyOverride {
	if o == nil {
		return nil
	}
	c := *o
	c.AllowedModels = append([]string(nil), o.AllowedModels...)
	c.BlockedModels = append([]string(nil), o.BlockedModels...)
	c.AllowedTools = append([]string(nil), o.AllowedTools...)
	c.ForbiddenTools = append([]string(nil), o.ForbiddenTools...)
	if o.MaxDataTier != nil {
		t := *o.MaxDataTier
		c.MaxDataTier = &t
	}
	c.Egress = cloneEgressPolicy(o.Egress)
	return &c
}

// cloneEgressPolicy deep-copies an egress policy (rules, tiers, lists).
func cloneEgressPolicy(p *EgressPolicyConfig) *EgressPolicyConfig {
	if p == nil {
		return nil
	}
	c := &EgressPolicyConfig{DefaultAction: p.DefaultAction}
	if len(p.Rules) > 0 {
		c.Rules = make([]EgressRule, len(p.Rules))
		for i := range p.Rules {
			r := p.Rules[i]
			cr := EgressRule{
				AllowedProviders: append([]string(nil), r.AllowedProviders...),
				AllowedRegions:   append([]string(nil), r.AllowedRegions...),
			}
			if r.Tier != nil {
				t := *r.Tier
				cr.Tier = &t
			}
			c.Rules[i] = cr
		}
	}
	return c
}
