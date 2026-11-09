// Package effective builds the effective-policy report for one AI use case
// (#305): the CLI (`talon agents show <name> --effective`) and the console
// (`GET /console/v1/use-cases/{name}/effective-policy`) print this one
// projection. It keeps four facts apart and never substitutes one for
// another:
//
//  1. current files: what the agent, gateway and MCP proxy files say now;
//  2. loaded: whether a running process proves it loaded the current agent
//     file (runtimestatus.ProveLoaded) — otherwise unknown;
//  3. effective: the policy the canonical resolver
//     (gateway.ExplainEffectivePolicy over gateway.ResolveEffectivePolicy)
//     compiles from the current files, with each selected rule's winning
//     layer, plus the MCP proxy's own pre-dispatch decision per tool
//     (mcp.EvaluateToolAccess);
//  4. last decision: the newest signed evidence record of the use case, with
//     the policy identity it recorded, compared to the current files only by
//     recorded digests — never assumed to have run under the current file.
package effective

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/mcp"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// ErrUnknownUseCase is returned when no agent file defines the use case.
var ErrUnknownUseCase = errors.New("unknown AI use case")

// maxTools bounds the tool decisions listed for the MCP boundary.
const maxTools = 50

// Inputs are the files and stores the report reads.
type Inputs struct {
	AgentsDir     string
	DefaultPolicy string
	GatewayConfig string
	ProxyConfig   string
	Name          string
	Tenant        string // "" = the agent file's tenant
	Evidence      *evidence.Store
	// Runtime is the assessed runtime view of this installation; nil when the
	// caller has none (the "loaded" layer is then unknown).
	Runtime         *runtimestatus.View
	RuntimeReadable bool
	Now             time.Time
}

// Report is the effective-policy report.
type Report struct {
	UseCase      string               `json:"use_case"`
	TenantID     string               `json:"tenant_id"`
	GeneratedAt  time.Time            `json:"generated_at"`
	CurrentFiles CurrentFiles         `json:"current_files"`
	Loaded       runtimestatus.Loaded `json:"loaded"`
	Effective    Effective            `json:"effective"`
	MCPBoundary  *MCPBoundary         `json:"mcp_boundary,omitempty"`
	LastDecision *LastDecision        `json:"last_decision,omitempty"`
	Notes        []string             `json:"notes,omitempty"`
}

// CurrentFiles are the files as they read now.
type CurrentFiles struct {
	AgentFile     string `json:"agent_file"`
	PolicyDigest  string `json:"policy_digest"`
	GatewayConfig *File  `json:"gateway_config,omitempty"`
	ProxyConfig   *File  `json:"proxy_config,omitempty"`
}

// File is one configuration file: present, its digest, or why not.
type File struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Digest  string `json:"digest,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Effective is the compiled policy of the current files.
type Effective struct {
	// Basis says what the values are computed from and whether they are
	// proven active (only when Loaded is loaded_matches_file).
	Basis           string `json:"basis"`
	ProvenActive    bool   `json:"proven_active"`
	BaselinePresent bool   `json:"organization_baseline_present"`

	DailyCap          float64  `json:"daily_cap,omitempty"`
	MonthlyCap        float64  `json:"monthly_cap,omitempty"`
	SessionCap        float64  `json:"session_cap,omitempty"`
	PIIAction         string   `json:"pii_action,omitempty"`
	ResponsePIIAction string   `json:"response_pii_action,omitempty"`
	AllowedModels     []string `json:"allowed_models,omitempty"`
	OrgAllowedModels  []string `json:"organization_allowed_models,omitempty"`
	AllowedProviders  []string `json:"allowed_providers,omitempty"`
	ForbiddenTools    []string `json:"forbidden_tools,omitempty"`
	ToolPolicyAction  string   `json:"tool_policy_action,omitempty"`

	Rules     []gateway.RuleProvenance `json:"rules"`
	Providers []ProviderEffective      `json:"providers,omitempty"`
}

// ProviderEffective is the effective policy toward one configured provider:
// its own constraints and the digest the gateway would sign for it.
type ProviderEffective struct {
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	EffectiveDigest string   `json:"effective_digest"`
	ForbiddenTools  []string `json:"forbidden_tools,omitempty"`
	AllowedModels   []string `json:"allowed_models,omitempty"`
}

// MCPBoundary is the MCP proxy's pre-dispatch decision for each tool the
// configuration names.
type MCPBoundary struct {
	Proxy string           `json:"proxy"`
	File  string           `json:"file"`
	Scope string           `json:"scope"`
	Tools []mcp.ToolAccess `json:"tools"`
	Error string           `json:"error,omitempty"`
}

// LastDecision points at the newest evidence record of the use case.
type LastDecision struct {
	EvidenceID        string           `json:"evidence_id"`
	Timestamp         time.Time        `json:"timestamp"`
	InvocationType    string           `json:"invocation_type"`
	SessionID         string           `json:"session_id,omitempty"`
	Outcome           evidence.Outcome `json:"outcome"`
	PrimaryCode       string           `json:"primary_explanation_code,omitempty"`
	PrimaryReason     string           `json:"primary_explanation_reason,omitempty"`
	RecordedAgent     string           `json:"recorded_agent_policy_digest,omitempty"`
	RecordedEffective string           `json:"recorded_effective_digest,omitempty"`
	// AgentFile: same | different | not_recorded — the recorded agent policy
	// digest against the current file's.
	AgentFile string `json:"agent_file"`
	// EffectivePolicy: matches_current:<provider> | differs_from_current |
	// not_recorded — the recorded effective digest against the current
	// effective policy toward each configured provider.
	EffectivePolicy string `json:"effective_policy"`
	Note            string `json:"note"`
}

// findAgent scans the agent files and returns the named use case in the
// requested tenant ("" = any), or ErrUnknownUseCase listing what exists.
func findAgent(ctx context.Context, in Inputs) (agent *policy.Policy, path, digest, tenant string, err error) {
	scan, err := fleetview.Scan(ctx, in.AgentsDir, in.DefaultPolicy)
	if err != nil {
		return nil, "", "", "", err
	}
	var names []string
	for i := range scan.Agents {
		a := scan.Agents[i]
		names = append(names, a.Name)
		t := a.TenantID
		if t == "" {
			t = "default"
		}
		if a.Name == in.Name && (in.Tenant == "" || in.Tenant == t) {
			agent, path, digest, tenant = a.Policy, a.Path, a.PolicyDigest, t
		}
	}
	if agent == nil {
		sort.Strings(names)
		return nil, "", "", "", fmt.Errorf("%w %q: defined use cases: %s", ErrUnknownUseCase, in.Name, strings.Join(names, ", "))
	}
	return agent, path, digest, tenant, nil
}

// Build assembles the report.
func Build(ctx context.Context, in Inputs) (*Report, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	agent, path, digest, tenant, err := findAgent(ctx, in)
	if err != nil {
		return nil, err
	}
	r := &Report{UseCase: in.Name, TenantID: tenant, GeneratedAt: now, CurrentFiles: CurrentFiles{AgentFile: path, PolicyDigest: digest}}

	// 2. loaded
	if in.Runtime != nil {
		r.Loaded = runtimestatus.ProveLoaded(*in.Runtime, in.RuntimeReadable, in.Name, tenant, digest)
	} else {
		r.Loaded = runtimestatus.Loaded{State: runtimestatus.LoadedUnknown, Reason: "no runtime records were read: whether this file is loaded cannot be proved"}
	}

	// 3. effective (gateway layers)
	baseline, providers := r.organization(in.GatewayConfig)
	override := agentbridge.LoadedAgentFromPolicy(agent, path).Override
	eff, rules := gateway.ExplainEffectivePolicy(baseline, gateway.ProviderConfig{}, "", override)
	r.Effective = Effective{
		BaselinePresent:   r.CurrentFiles.GatewayConfig != nil && r.CurrentFiles.GatewayConfig.Present && r.CurrentFiles.GatewayConfig.Error == "",
		DailyCap:          eff.BindingDailyCap(),
		MonthlyCap:        eff.BindingMonthlyCap(),
		SessionCap:        eff.BindingSessionCap(),
		PIIAction:         eff.PIIAction,
		ResponsePIIAction: eff.ResponsePIIAction,
		AllowedModels:     eff.AllowedModels,
		OrgAllowedModels:  eff.OrgAllowedModels,
		AllowedProviders:  eff.AllowedProviders,
		ForbiddenTools:    eff.ForbiddenTools,
		ToolPolicyAction:  eff.ToolPolicyAction,
		Rules:             rules,
	}
	for _, name := range sortedKeys(providers) {
		p := providers[name]
		r.Effective.Providers = append(r.Effective.Providers, ProviderEffective{
			Name: name, Enabled: p.Enabled, EffectiveDigest: gateway.EffectivePolicyDigest(baseline, p, override),
			ForbiddenTools: p.ForbiddenTools, AllowedModels: p.AllowedModels,
		})
	}
	r.Effective.ProvenActive = r.Loaded.State == runtimestatus.LoadedMatchesFile
	switch {
	case r.Effective.ProvenActive:
		r.Effective.Basis = "compiled by gateway.ResolveEffectivePolicy from the current files; a running process proves it loaded this agent file"
	default:
		r.Effective.Basis = "compiled by gateway.ResolveEffectivePolicy from the current files; not proven to be what a running process enforces (" + r.Loaded.Reason + ")"
	}
	if !r.Effective.BaselinePresent {
		r.Notes = append(r.Notes, "no organization baseline was read (no or invalid gateway config): the effective values are the use case's own")
	}

	// 3b. MCP boundary
	r.MCPBoundary = mcpBoundary(ctx, in.ProxyConfig, agent, &r.CurrentFiles)

	// 4. last decision
	if in.Evidence != nil {
		ld, err := lastDecision(ctx, in.Evidence, tenant, in.Name, digest, r.Effective.Providers)
		switch {
		case err != nil:
			r.Notes = append(r.Notes, "last decision unavailable: "+err.Error())
		case ld == nil:
			r.Notes = append(r.Notes, "no evidence recorded for this use case yet")
		default:
			r.LastDecision = ld
		}
	}
	return r, nil
}

func (r *Report) organization(path string) (baseline gateway.OrganizationPolicy, providers map[string]gateway.ProviderConfig) {
	if path == "" {
		return gateway.OrganizationPolicy{}, nil
	}
	f := &File{Path: path, Digest: fileDigest(path)}
	r.CurrentFiles.GatewayConfig = f
	gw, err := gateway.LoadGatewayConfig(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return gateway.OrganizationPolicy{}, nil
	case err != nil:
		f.Present, f.Error = true, err.Error()
		return gateway.OrganizationPolicy{}, nil
	}
	f.Present = true
	return gw.OrganizationPolicy, gw.Providers
}

func mcpBoundary(ctx context.Context, path string, agent *policy.Policy, files *CurrentFiles) *MCPBoundary {
	if path == "" {
		return nil
	}
	f := &File{Path: path, Digest: fileDigest(path)}
	files.ProxyConfig = f
	b := &MCPBoundary{File: path, Tools: []mcp.ToolAccess{}}
	cfg, err := mcp.LoadProxyConfig(ctx, path)
	if err != nil {
		f.Present = !errors.Is(err, os.ErrNotExist)
		f.Error, b.Error = err.Error(), err.Error()
		return b
	}
	f.Present = true
	b.Proxy = cfg.Agent.Name
	b.Scope = "calls made through this MCP proxy; tools reached any other way are not governed here"
	engine, err := policy.NewProxyEngine(ctx, cfg)
	if err != nil {
		b.Error = err.Error()
		return b
	}
	seen := map[string]bool{}
	var tools []string
	add := func(t string) {
		if t != "" && !strings.HasSuffix(t, "*") && !seen[t] && len(tools) < maxTools {
			seen[t] = true
			tools = append(tools, t)
		}
	}
	for _, t := range cfg.Proxy.AllowedTools {
		add(t.Name)
	}
	for _, t := range cfg.Proxy.ForbiddenTools {
		add(t)
	}
	if c := agent.Capabilities; c != nil {
		for _, t := range c.AllowedTools {
			add(t)
		}
		for _, t := range c.ForbiddenTools {
			add(t)
		}
	}
	sort.Strings(tools)
	for _, t := range tools {
		d, err := mcp.EvaluateToolAccess(ctx, cfg, engine, t)
		if err != nil {
			b.Error = err.Error()
			return b
		}
		b.Tools = append(b.Tools, d)
	}
	return b
}

func lastDecision(ctx context.Context, store *evidence.Store, tenant, name, fileDigest string, providers []ProviderEffective) (*LastDecision, error) {
	recs, err := store.List(ctx, tenant, name, time.Time{}, time.Time{}, 1)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	ev := &recs[0]
	ld := &LastDecision{
		EvidenceID: ev.ID, Timestamp: ev.Timestamp, InvocationType: ev.InvocationType, SessionID: ev.SessionID,
		Outcome: evidence.OutcomeOf(ev), AgentFile: "not_recorded", EffectivePolicy: "not_recorded",
		Note: "a historical decision: the policy recorded on this signed record applied to it; the current files are compared only by recorded digests",
	}
	if p, ok := explanation.Primary(ev.Explanations); ok {
		ld.PrimaryCode, ld.PrimaryReason = p.Code, p.Reason
	}
	if d := ev.PolicyDecision.PolicyDigests; d != nil {
		ld.RecordedAgent, ld.RecordedEffective = d.Agent, d.Effective
		if d.Agent != "" {
			ld.AgentFile = "different"
			if d.Agent == fileDigest {
				ld.AgentFile = "same"
			}
		}
		if d.Effective != "" {
			ld.EffectivePolicy = "differs_from_current"
			for _, p := range providers {
				if p.EffectiveDigest == d.Effective {
					ld.EffectivePolicy = "matches_current:" + p.Name
					break
				}
			}
		}
	}
	return ld, nil
}

func sortedKeys(m map[string]gateway.ProviderConfig) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fileDigest(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // G304: a configuration path the operator gave the command
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
