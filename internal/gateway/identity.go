package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/dativo-io/talon/internal/secrets"
)

// ErrAdminKeyCollision marks an agent key resolving to the same value as the
// admin key — a config error that must fail startup in every serve mode that
// loads agent keys (gateway and plain serve; --proxy-quickstart never builds
// the registry, so no agent key is loaded there at all). It would grant a
// workload operator authority, unlike an unminted secret which is tolerable
// for native-only runs.
var ErrAdminKeyCollision = errors.New("agent key collides with admin key")

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
	// PolicyDigest is the agent policy's canonical content hash (policy.Hash),
	// recorded in signed evidence so a decision names the exact agent-policy
	// version it was made against (#266 review round 4).
	PolicyDigest string
	// Tags classify telemetry (e.g. "copaw" drives OTel/dashboard views).
	Tags []string
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

	AllowedModels []string // replace baseline when non-empty (org lists stay hard constraints)
	BlockedModels []string // replace baseline when non-empty (org lists stay hard constraints)
	MaxDataTier   *TierLevel

	// AllowedProviders restricts which gateway providers this agent may
	// reach. Empty = all; the organization's allowed_providers list remains
	// a hard constraint either way (see EffectivePolicy.ProviderAllowed).
	AllowedProviders []string

	AllowedTools     []string // most-specific non-empty list wins
	ForbiddenTools   []string // union with baseline + provider
	ToolPolicyAction string   // filter | block; most-specific wins

	// Egress is a second boundary evaluated ALONGSIDE the organization egress:
	// a destination must pass BOTH (logical intersection) — the agent narrows
	// within the org boundary, never widens or replaces it (#266 review r5).
	Egress *EgressPolicyConfig
}

// ResolvedIdentity is the runtime identity of one AI use case, produced by
// the registry from a presented key (or synthesized for quickstart mode).
// #268 adds Enabled; the struct is the seam for the fleet issues (#267–#270).
type ResolvedIdentity struct {
	Name         string
	TenantID     string
	Team         string
	ConfigPath   string
	PolicyDigest string // agent policy canonical content hash (#266 review r4)
	Tags         []string

	AcceptClientMetadata *bool
	Override             *PolicyOverride

	// key is the resolved traffic key material. Unexported: it exists only
	// so projections can hand the server middleware a key → identity map; it
	// is never persisted or logged. keyDigest is the SHA-256 of key, used for
	// fixed-length constant-time matching (#266 review round 4).
	key       []byte
	keyDigest [sha256.Size]byte
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
// baseline (QuickstartConfig); the openai-only restriction rides the same
// override channel every real agent uses.
func NewQuickstartIdentity() *ResolvedIdentity {
	return &ResolvedIdentity{
		Name:     quickstartAgentName,
		TenantID: quickstartTenantID,
		Tags:     []string{"quickstart"},
		Override: &PolicyOverride{AllowedProviders: []string{"openai"}},
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
//   - an agent key colliding with the admin key (adminKey; "" = none
//     configured). The server's tenant-or-admin middleware checks the admin
//     bearer first, so a collision would silently elevate that agent's
//     traffic to operator authority — fail startup instead.
func BuildIdentityRegistry(ctx context.Context, agents []LoadedAgent, vault *secrets.SecretStore, adminKey string) (*IdentityRegistry, error) {
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

		if adminKey != "" && subtle.ConstantTimeCompare([]byte(keyMaterial), []byte(adminKey)) == 1 {
			return nil, fmt.Errorf("agent %q (%s): key secret %q resolves to the same value as TALON_ADMIN_KEY — an agent key must never carry admin authority; rotate one of them (`talon secrets set %s <new key>`): %w", a.Name, a.Path, a.KeySecretName, a.KeySecretName, ErrAdminKeyCollision)
		}

		reg.identities = append(reg.identities, &ResolvedIdentity{
			Name:                 a.Name,
			TenantID:             tenantID,
			Team:                 a.Team,
			ConfigPath:           a.Path,
			PolicyDigest:         a.PolicyDigest,
			Tags:                 append([]string(nil), a.Tags...),
			AcceptClientMetadata: cloneBoolPtr(a.AcceptClientMetadata),
			Override:             a.Override.clone(),
			key:                  []byte(keyMaterial),
			keyDigest:            sha256.Sum256([]byte(keyMaterial)),
		})
	}
	return reg, nil
}

// cloneBoolPtr deep-copies a *bool so registry identities never alias the
// loader's structs (reload snapshot safety, #269).
func cloneBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// ResolveKey matches a presented key against the registry. Both sides are
// SHA-256 digested to a fixed 32-byte length before the constant-time
// compare, so the comparison time does not vary with key length
// (subtle.ConstantTimeCompare short-circuits on a length mismatch, #266
// review round 4). Returns (nil, false) for unknown keys.
func (r *IdentityRegistry) ResolveKey(presented string) (*ResolvedIdentity, bool) {
	if r == nil || presented == "" {
		return nil, false
	}
	presentedDigest := sha256.Sum256([]byte(presented))
	var match *ResolvedIdentity
	for _, id := range r.identities {
		if subtle.ConstantTimeCompare(id.keyDigest[:], presentedDigest[:]) == 1 {
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

// CanonicalTenantID returns the registry's own string for a tenant it knows
// (so cache-key scope always originates from config, never from request
// data) and reports whether the tenant is registered. Allocation-free — it
// runs on the per-request cache path (#289).
func (r *IdentityRegistry) CanonicalTenantID(tenantID string) (string, bool) {
	if r == nil {
		return "", false
	}
	for _, id := range r.identities {
		if id.TenantID == tenantID {
			return id.TenantID, true
		}
	}
	return "", false
}

// AuthPrincipal is the identity a presented agent key resolves to on the
// tenant-API surface (#266): the agent name, its derived tenant, and team.
// It is the value type of AuthKeyIdentityProjection — an immutable snapshot,
// never a pointer into the registry, so consumers cannot mutate an identity.
type AuthPrincipal struct {
	AgentID  string
	TenantID string
	Team     string
}

// AuthKeyIdentityProjection projects the registry into the key → AuthPrincipal
// map consumed by the server tenant-API middleware. The registry is the
// single source; this is a projection, kept only because the middleware wants
// a plain map. The full identity (not just tenant) travels through so native
// handlers can bind attribution to the AUTHENTICATED agent instead of a
// client-asserted name (#266 review round 4). Auth openness is governed by
// the admin-key dev rule, never by this map being empty.
func (r *IdentityRegistry) AuthKeyIdentityProjection() map[string]AuthPrincipal {
	m := make(map[string]AuthPrincipal)
	if r == nil {
		return m
	}
	for _, id := range r.identities {
		m[string(id.key)] = AuthPrincipal{AgentID: id.Name, TenantID: id.TenantID, Team: id.Team}
	}
	return m
}

// AuthKeyTenantProjection projects the registry into the key → tenant_id map.
// Retained for callers that need only the tenant; new code should prefer
// AuthKeyIdentityProjection.
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

// Identities returns DEEP COPIES of the resolved identities (for fleet views
// and preflight checks). Copies — not shared pointers — so a consumer cannot
// mutate an identity, its override, or nested slices out from under the
// registry (#266 review round 4: structural immutability, not by convention).
func (r *IdentityRegistry) Identities() []*ResolvedIdentity {
	if r == nil {
		return nil
	}
	out := make([]*ResolvedIdentity, len(r.identities))
	for i, id := range r.identities {
		out[i] = id.clone()
	}
	return out
}

// clone deep-copies a resolved identity, including its override, tags, and
// metadata pointer. The traffic key material is intentionally NOT copied out
// (it stays unexported inside the registry).
func (id *ResolvedIdentity) clone() *ResolvedIdentity {
	if id == nil {
		return nil
	}
	c := *id
	c.Tags = append([]string(nil), id.Tags...)
	c.AcceptClientMetadata = cloneBoolPtr(id.AcceptClientMetadata)
	c.Override = id.Override.clone()
	c.key = append([]byte(nil), id.key...)
	return &c
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
	// ALLOW lists match literally, so "*" would deny every concrete value
	// rather than allow all — the same fail-closed footgun as the org/provider
	// model lists (#266 review round 5). An empty list already means
	// unrestricted. Blocked lists are exempt: blocked_models: ["*"] is the
	// supported deny-all.
	if err := rejectWildcardInAllowList(scope, "policies.models.allowed", o.AllowedModels); err != nil {
		return err
	}
	if err := rejectWildcardInAllowList(scope, "policies.allowed_providers", o.AllowedProviders); err != nil {
		return err
	}
	// Agent tool allowlists match by exact name in EvaluateToolPolicy —
	// the same literal-membership footgun (#291 review). Forbidden lists
	// stay exempt: they are glob patterns and "*" is the supported deny-all.
	if err := rejectWildcardInAllowList(scope, "capabilities.allowed_tools", o.AllowedTools); err != nil {
		return err
	}
	o.Egress.applyDefaults()
	return validateEgressPolicy(scope, o.Egress)
}

// rejectWildcardInAllowList fails when an agent ALLOW list contains "*":
// matching is literal, so the wildcard silently denies everything.
func rejectWildcardInAllowList(scope, field string, values []string) error {
	for _, v := range values {
		if strings.TrimSpace(v) == "*" {
			return fmt.Errorf("%s: %s must not contain \"*\": an allow list matches literally, so \"*\" denies every value — leave the list empty to allow all", scope, field)
		}
	}
	return nil
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
	c.AllowedProviders = append([]string(nil), o.AllowedProviders...)
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
