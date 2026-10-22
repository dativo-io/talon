package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
	"github.com/dativo-io/talon/internal/pricing"
)

// `talon openshell prepare` (#482 showcase): the idempotent configuration
// overlay for the OpenShell composition. It edits the operator's gateway
// config and the use case's agent file THROUGH the YAML tree and the real
// loaders — never by splicing text — adding exactly the OpenShell surface
// (gateway.openshell, a provider the sandbox dials, the sandboxed use case
// with its verified identity binding, tool governance, trusted action
// catalog and approval rule) and leaving every other setting, provider and
// agent untouched. Every write is validated with the same loaders `talon
// serve` and `talon validate` use, then replaces the file atomically.
//
// Restart boundary: gateway.openshell is read at startup (listener, TLS,
// trust anchors), so a changed block needs a Talon restart; the agent file
// (bindings, catalog, tools) is picked up by the agent reload.
var openshellCmd = &cobra.Command{
	Use:   "openshell",
	Short: "OpenShell composition tooling (#482): configuration overlay for the showcase",
}

type openshellPrepareOptions struct {
	configPath, agentsDir, agentFile string
	agent, tenant                    string
	subjects                         []string
	listen, tlsCert, tlsKey          string
	issuer, audience, jwksFile       string
	selfHosts                        []string
	providerName, providerBaseURL    string
	providerSecret, providerPricing  string
	protectedBaseURL                 string
	maxCaptureBytes                  int64
	settlementTimeout                string
	responseGovernance               bool
	summaryPath                      string
}

var openshellPrepareOpts openshellPrepareOptions

var openshellPrepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "Idempotently add the OpenShell surface to a gateway config and an agent directory (validated, atomic)",
	Long: `Adds gateway.openshell (listener, TLS, identity trust anchors, self destination, response
governance), the provider the sandbox dials, and the sandboxed use case (verified identity
binding, allowed/forbidden tools, trusted action catalog, refund approval rule) to EXISTING
configuration. Other providers, agents and settings are preserved. Re-running with the same
inputs changes nothing; re-running with a new --sandbox-subject adds the binding.

The gateway.openshell block is read at startup: Talon must be restarted after the first
prepare (or when listener/TLS/identity settings change). Agent-file changes are hot-reloaded.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		summary, err := runOpenshellPrepare(cmd.Context(), openshellPrepareOpts)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(summary, "", "  ")
		if openshellPrepareOpts.summaryPath != "" {
			if err := os.WriteFile(openshellPrepareOpts.summaryPath, append(b, '\n'), 0o600); err != nil {
				return err
			}
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return nil
	},
}

func init() {
	f := openshellPrepareCmd.Flags()
	f.StringVar(&openshellPrepareOpts.configPath, "config", "talon.config.yaml", "gateway config file to overlay (must exist)")
	f.StringVar(&openshellPrepareOpts.agentsDir, "agents-dir", "", "agents directory (the use case is written as <dir>/<agent>/agent.talon.yaml, the layout discovery expects); mutually exclusive with --agent-file")
	f.StringVar(&openshellPrepareOpts.agentFile, "agent-file", "", "single agent file to overlay (for single-policy deployments)")
	f.StringVar(&openshellPrepareOpts.agent, "agent", "sandboxed-support", "name of the sandboxed AI use case")
	f.StringVar(&openshellPrepareOpts.tenant, "tenant", "default", "tenant of the use case (approver groups are tenant-scoped)")
	f.StringArrayVar(&openshellPrepareOpts.subjects, "sandbox-subject", nil, "verified sandbox subject to bind, e.g. spiffe://openshell/sandbox/<id> (repeatable; added, never replaced)")
	f.StringVar(&openshellPrepareOpts.listen, "listen", "", "Talon's OpenShell middleware listener (host:port reachable by the gateway and supervisors)")
	f.StringVar(&openshellPrepareOpts.tlsCert, "tls-cert", "", "server certificate for the middleware listener (PEM, signed by the CA the gateway trusts)")
	f.StringVar(&openshellPrepareOpts.tlsKey, "tls-key", "", "server key for the middleware listener (PEM)")
	f.StringVar(&openshellPrepareOpts.issuer, "issuer", "", "gateway token issuer, openshell-gateway:<gateway_id>")
	f.StringVar(&openshellPrepareOpts.audience, "audience", "urn:openshell:extension:middleware:talon", "expected token audience (must equal the registration's audience)")
	f.StringVar(&openshellPrepareOpts.jwksFile, "jwks-file", "", "JWKS file with the gateway's signing public key(s)")
	f.StringArrayVar(&openshellPrepareOpts.selfHosts, "self-host", nil, "host[:port] under which sandboxes reach Talon's own HTTP API (self_destination.hosts; repeatable)")
	f.StringVar(&openshellPrepareOpts.providerName, "provider-name", "openshell-mock", "provider entry the sandbox's model traffic maps to (by the host of --provider-base-url)")
	f.StringVar(&openshellPrepareOpts.providerBaseURL, "provider-base-url", "", "the provider's base URL as the sandbox dials it (host selects the provider); empty keeps existing providers")
	f.StringVar(&openshellPrepareOpts.providerSecret, "provider-secret-name", "openshell-mock-provider-key", "vault secret name of the provider entry (used only on /v1/proxy, never on the delegated path)")
	f.StringVar(&openshellPrepareOpts.providerPricing, "provider-pricing", "openai", "pricing catalog entry the provider is priced as (`inherit` in pricing/models.yaml; the showcase mock serves OpenAI models): a provider absent from the table is denied pricing_unavailable under the agent's spending cap")
	f.StringVar(&openshellPrepareOpts.protectedBaseURL, "protected-base-url", "", "base URL of the protected business service Talon dispatches actions to (Talon-side; the sandbox has no route to it)")
	f.Int64Var(&openshellPrepareOpts.maxCaptureBytes, "max-capture-bytes", gateway.DefaultOpenShellMaxCaptureBytes, "response inspection bound (preventive policies block larger bodies)")
	f.StringVar(&openshellPrepareOpts.settlementTimeout, "settlement-timeout", "60s", "response settlement timeout")
	f.BoolVar(&openshellPrepareOpts.responseGovernance, "response-governance", true, "advertise and serve HTTP_RESPONSE/PRE_RETURN")
	f.StringVar(&openshellPrepareOpts.summaryPath, "summary", "", "write the JSON summary to this file as well")
	openshellCmd.AddCommand(openshellPrepareCmd)
	rootCmd.AddCommand(openshellCmd)
}

// openshellPrepareSummary is what the runner and operators read back.
type openshellPrepareSummary struct {
	ConfigPath      string   `json:"config_path"`
	ConfigChanged   bool     `json:"config_changed"`
	RestartRequired bool     `json:"restart_required"`
	AgentFile       string   `json:"agent_file"`
	AgentChanged    bool     `json:"agent_changed"`
	AgentCreated    bool     `json:"agent_created"`
	Bindings        []string `json:"bindings"`
	Provider        string   `json:"provider,omitempty"`
	ProviderSecret  string   `json:"provider_secret_name,omitempty"`
	ProviderPricing string   `json:"provider_pricing,omitempty"`
	PricingFile     string   `json:"pricing_file,omitempty"`
	PricingChanged  bool     `json:"pricing_changed,omitempty"`
	AgentKeySecret  string   `json:"agent_key_secret_name"`
	ApproverGroup   string   `json:"approver_group"`
	Actions         []string `json:"actions"`
	ForbiddenTools  []string `json:"forbidden_tools"`
	AllowedTools    []string `json:"allowed_tools"`
	Notes           []string `json:"notes"`
	PreparedAt      string   `json:"prepared_at"`
	ResponseGovern  bool     `json:"response_governance"`
	MaxCaptureBytes int64    `json:"max_capture_bytes"`
}

const (
	openshellApproverGroup = "support-leads"
	openshellRefundRule    = "refund-request"
)

// validateOpenshellPrepareOptions checks the flags and derives the agent
// location from the config when neither --agents-dir nor --agent-file is
// given (agents_dir relative to the config, else default_policy).
func validateOpenshellPrepareOptions(o *openshellPrepareOptions) error {
	if o.configPath == "" {
		return fmt.Errorf("--config is required")
	}
	if o.agentsDir != "" && o.agentFile != "" {
		return fmt.Errorf("--agents-dir and --agent-file are mutually exclusive")
	}
	if o.agentsDir == "" && o.agentFile == "" {
		dir, file, err := agentLocationFromConfig(o.configPath)
		if err != nil {
			return err
		}
		o.agentsDir, o.agentFile = dir, file
	}
	for flag, v := range map[string]string{"--listen": o.listen, "--tls-cert": o.tlsCert, "--tls-key": o.tlsKey, "--issuer": o.issuer, "--jwks-file": o.jwksFile, "--protected-base-url": o.protectedBaseURL} {
		if v == "" {
			return fmt.Errorf("%s is required", flag)
		}
	}
	if len(o.selfHosts) == 0 {
		return fmt.Errorf("--self-host is required")
	}
	for _, s := range o.subjects {
		if !strings.HasPrefix(s, "spiffe://openshell/sandbox/") {
			return fmt.Errorf("--sandbox-subject %q is not an OpenShell sandbox subject (spiffe://openshell/sandbox/<id>)", s)
		}
	}
	return nil
}

// prepareNotes are the operator's next steps and restart boundary.
func prepareNotes(o openshellPrepareOptions, configChanged, agentChanged bool, agentKeySecret string) []string {
	var notes []string
	if configChanged {
		notes = append(notes, "gateway.openshell changed: restart `talon serve` (the middleware listener, TLS identity and trust anchors are read at startup)")
	}
	if agentChanged {
		notes = append(notes, "agent file changed: picked up by the agent reload, no restart needed")
	}
	notes = append(notes,
		fmt.Sprintf("the use case needs its traffic key in the vault: talon secrets set %s <value>", agentKeySecret),
		fmt.Sprintf("a reviewer in group %s decides refunds: talon approver add --name <who> --tenant %s --groups %s", openshellApproverGroup, o.tenant, openshellApproverGroup))
	if o.providerBaseURL != "" {
		notes = append(notes, fmt.Sprintf("provider %s needs a vault entry for /v1/proxy only (any value; the delegated path never reads it): talon secrets set %s <value>", o.providerName, o.providerSecret))
		notes = append(notes, fmt.Sprintf("provider %s is priced as %s (pricing/models.yaml `inherit`): the agent's spending cap applies to its requests at those rates", o.providerName, o.providerPricing))
	}
	return notes
}

func runOpenshellPrepare(ctx context.Context, o openshellPrepareOptions) (*openshellPrepareSummary, error) {
	if err := validateOpenshellPrepareOptions(&o); err != nil {
		return nil, err
	}
	summary := &openshellPrepareSummary{
		ConfigPath: o.configPath, AgentKeySecret: o.agent + "-talon-key", ApproverGroup: openshellApproverGroup,
		Actions: []string{"lookup_ticket", "create_refund_request", "delete_customer"}, ForbiddenTools: []string{"delete_customer"},
		AllowedTools: []string{"lookup_ticket", "create_refund_request"}, PreparedAt: time.Now().UTC().Format(time.RFC3339),
		ResponseGovern: o.responseGovernance, MaxCaptureBytes: o.maxCaptureBytes,
	}

	// ---- gateway config
	configChanged, err := overlayGatewayConfig(o)
	if err != nil {
		return nil, err
	}
	summary.ConfigChanged, summary.RestartRequired = configChanged, configChanged
	if o.providerBaseURL != "" {
		summary.Provider, summary.ProviderSecret = o.providerName, o.providerSecret
		// ---- pricing: the provider must be priceable or every capped request
		// to it is denied pricing_unavailable (the table is read at startup).
		pricingPath, pricingChanged, err := ensureProviderPricing(o)
		if err != nil {
			return nil, err
		}
		summary.ProviderPricing, summary.PricingFile, summary.PricingChanged = o.providerPricing, pricingPath, pricingChanged
		summary.RestartRequired = summary.RestartRequired || pricingChanged
	}

	// ---- agent file
	// Discovery matches agent.talon.yaml exactly: one directory per use case.
	agentPath := o.agentFile
	if o.agentsDir != "" {
		agentPath = filepath.Join(o.agentsDir, o.agent, agentcatalog.AgentConfigFilename)
	}
	created, changed, bindings, err := overlayAgentFile(ctx, agentPath, o)
	if err != nil {
		return nil, err
	}
	summary.AgentFile, summary.AgentCreated, summary.AgentChanged, summary.Bindings = agentPath, created, changed, bindings
	summary.Notes = prepareNotes(o, configChanged, changed, summary.AgentKeySecret)
	return summary, nil
}

// agentLocationFromConfig reads agents_dir / default_policy from the
// operator config (relative paths resolve against the config's directory).
func agentLocationFromConfig(configPath string) (dir, file string, err error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", fmt.Errorf("reading %s: %w", configPath, err)
	}
	var top struct {
		AgentsDir     string `yaml:"agents_dir"`
		DefaultPolicy string `yaml:"default_policy"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return "", "", fmt.Errorf("parsing %s: %w", configPath, err)
	}
	base := filepath.Dir(configPath)
	resolve := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	switch {
	case top.AgentsDir != "":
		return resolve(top.AgentsDir), "", nil
	case top.DefaultPolicy != "":
		return "", resolve(top.DefaultPolicy), nil
	default:
		return "", filepath.Join(base, "agent.talon.yaml"), nil
	}
}

// overlayGatewayConfig sets gateway.openshell (replacing the block: it is
// Talon's OpenShell surface) and, when asked, one provider entry; nothing
// else in the file is touched. Returns whether the file changed.
func overlayGatewayConfig(o openshellPrepareOptions) (bool, error) {
	raw, err := os.ReadFile(o.configPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", o.configPath, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("parsing %s: %w", o.configPath, err)
	}
	root := documentRoot(&doc)
	gw := ensureMap(root, "gateway")
	setScalar(gw, "enabled", "true", "!!bool")
	if v := mapValue(gw, "listen_prefix"); v == nil {
		setScalar(gw, "listen_prefix", "/v1/proxy", "!!str")
	}
	if o.providerBaseURL != "" {
		providers := ensureMap(gw, "providers")
		prov := ensureMap(providers, o.providerName)
		setScalar(prov, "enabled", "true", "!!bool")
		setScalar(prov, "secret_name", o.providerSecret, "!!str")
		setScalar(prov, "base_url", o.providerBaseURL, "!!str")
	}
	osBlock := map[string]any{
		"enabled": true, "listen": o.listen,
		"tls":             map[string]any{"cert_file": o.tlsCert, "key_file": o.tlsKey},
		"middleware_name": "talon", "max_payload_bytes": 1048576, "request_timeout": "10s",
		"identity":            map[string]any{"issuer": o.issuer, "audience": o.audience, "jwks_file": o.jwksFile},
		"self_destination":    map[string]any{"hosts": o.selfHosts, "assertion_ttl": "60s"},
		"response_governance": map[string]any{"enabled": o.responseGovernance, "settlement_timeout": o.settlementTimeout, "max_capture_bytes": o.maxCaptureBytes},
	}
	var osNode yaml.Node
	if err := osNode.Encode(osBlock); err != nil {
		return false, err
	}
	osNode.HeadComment = "OpenShell composition (#482): written by `talon openshell prepare`; read at startup."
	setNode(gw, "openshell", &osNode)

	out, err := marshalYAML(&doc)
	if err != nil {
		return false, err
	}
	if bytes.Equal(out, raw) {
		return false, nil
	}
	// Validate exactly what talon serve will load, before replacing the file.
	tmp, err := writeTemp(o.configPath, out)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	cfg, err := gateway.LoadGatewayConfig(tmp)
	if err != nil {
		return false, fmt.Errorf("the prepared gateway config does not load: %w", err)
	}
	if err := cfg.ApplyDefaults(); err != nil {
		return false, fmt.Errorf("the prepared gateway config does not apply defaults: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return false, fmt.Errorf("the prepared gateway config does not validate: %w", err)
	}
	return true, replaceFile(o.configPath, tmp)
}

// ensureProviderPricing makes the sandbox's provider priceable: the pricing
// table `talon serve` will read (llm.pricing_file from the config, else
// pricing/models.yaml beside it — serve runs from the config directory)
// gains `<provider>: {inherit: <catalog>}` unless the operator already
// priced the provider. A missing table is created from the embedded default
// first, so the operator's catalog starts complete. Returns the path and
// whether the file changed.
func ensureProviderPricing(o openshellPrepareOptions) (path string, changed bool, err error) {
	if o.providerPricing == "" {
		return "", false, fmt.Errorf("--provider-pricing is required with --provider-base-url: a provider absent from pricing/models.yaml cannot be priced and is denied under the agent's spending cap")
	}
	path, err = pricingPathFromConfig(o.configPath)
	if err != nil {
		return "", false, err
	}
	raw, doc, created, err := loadPricingDoc(path)
	if err != nil {
		return "", false, err
	}
	providers := ensureMap(documentRoot(doc), "providers")
	if mapValue(providers, o.providerPricing) == nil {
		return "", false, fmt.Errorf("--provider-pricing %q is not a provider in %s", o.providerPricing, path)
	}
	if existing := mapValue(providers, o.providerName); existing != nil {
		if !created {
			return path, false, nil // the operator priced it; theirs wins
		}
	} else {
		entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setScalar(entry, "inherit", o.providerPricing, "!!str")
		entry.HeadComment = fmt.Sprintf("written by `talon openshell prepare`: the sandbox's provider %s is priced as %s", o.providerName, o.providerPricing)
		setNode(providers, o.providerName, entry)
	}
	out, err := marshalYAML(doc)
	if err != nil {
		return "", false, err
	}
	if !created && bytes.Equal(out, raw) {
		return path, false, nil
	}
	changed, err = writePricingDoc(path, out, o.providerName)
	return path, changed, err
}

// loadPricingDoc reads the pricing table as a YAML node tree (comments
// preserved); a missing file starts from the embedded catalog.
func loadPricingDoc(path string) (raw []byte, doc *yaml.Node, created bool, err error) {
	raw, err = os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		raw, created = pricing.DefaultModelsYAML(), true
	case err != nil:
		return nil, nil, false, fmt.Errorf("reading %s: %w", path, err)
	}
	doc = &yaml.Node{}
	if err := yaml.Unmarshal(raw, doc); err != nil {
		return nil, nil, false, fmt.Errorf("parsing %s: %w", path, err)
	}
	return raw, doc, created, nil
}

// writePricingDoc validates the prepared table with the pricing loader —
// and that it actually prices the provider — before replacing the file.
func writePricingDoc(path string, out []byte, providerName string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, err
	}
	tmp, err := writeTemp(path, out)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	table, err := pricing.Load(tmp)
	if err != nil {
		return false, fmt.Errorf("the prepared pricing table does not load: %w", err)
	}
	if _, known, _ := table.EstimateCached(providerName, "gpt-4o-mini", 1, 0, 0, 1); !known {
		return false, fmt.Errorf("the prepared pricing table still cannot price provider %s", providerName)
	}
	return true, replaceFile(path, tmp)
}

// pricingPathFromConfig resolves the table `talon serve` reads: the config's
// llm.pricing_file (relative to the config directory, which is serve's
// working directory in the showcase and the Full Demo), else the default
// pricing/models.yaml beside the config.
func pricingPathFromConfig(configPath string) (string, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", configPath, err)
	}
	var top struct {
		LLM struct {
			PricingFile string `yaml:"pricing_file"`
		} `yaml:"llm"`
	}
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return "", fmt.Errorf("parsing %s: %w", configPath, err)
	}
	p := top.LLM.PricingFile
	if p == "" {
		p = config.DefaultPricingFile
	}
	if filepath.IsAbs(p) {
		return p, nil
	}
	return filepath.Join(filepath.Dir(configPath), p), nil
}

// overlayAgentFile creates or updates the sandboxed use case: identity
// bindings (added), tool governance, the trusted catalog and the approval
// rule (set to the showcase contract); every other key is preserved.
func overlayAgentFile(ctx context.Context, path string, o openshellPrepareOptions) (created, changed bool, bindings []string, err error) {
	raw, doc, created, err := loadOrNewAgentDoc(path, o)
	if err != nil {
		return false, false, nil, err
	}
	root := documentRoot(doc)
	agent := ensureMap(root, "agent")
	if name := mapValue(agent, "name"); name != nil && name.Value != o.agent {
		return false, false, nil, fmt.Errorf("%s belongs to agent %q, not %q", path, name.Value, o.agent)
	}
	setScalar(agent, "name", o.agent, "!!str")
	key := ensureMap(agent, "key")
	if v := mapValue(key, "secret_name"); v == nil || v.Value == "" {
		setScalar(key, "secret_name", o.agent+"-talon-key", "!!str")
	}
	bindings = mergeBindings(agent, o.subjects)
	if err := applyShowcaseContract(root, o); err != nil {
		return false, false, nil, err
	}
	out, err := marshalYAML(doc)
	if err != nil {
		return false, false, nil, err
	}
	if raw != nil && bytes.Equal(out, raw) {
		return false, false, bindings, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, false, nil, err
	}
	tmp, err := writeTemp(path, out)
	if err != nil {
		return false, false, nil, err
	}
	defer os.Remove(tmp)
	if _, err := policy.LoadPolicy(ctx, filepath.Base(tmp), true, filepath.Dir(tmp)); err != nil {
		return false, false, nil, fmt.Errorf("the prepared agent file does not validate: %w", err)
	}
	return created, true, bindings, replaceFile(path, tmp)
}

// loadOrNewAgentDoc parses the existing agent file (raw != nil) or builds
// a minimal new use case (raw == nil, created == true).
func loadOrNewAgentDoc(path string, o openshellPrepareOptions) (raw []byte, doc *yaml.Node, created bool, err error) {
	raw, readErr := os.ReadFile(path)
	doc = &yaml.Node{}
	switch {
	case readErr == nil:
		if err := yaml.Unmarshal(raw, doc); err != nil {
			return nil, nil, false, fmt.Errorf("parsing %s: %w", path, err)
		}
		return raw, doc, false, nil
	case os.IsNotExist(readErr):
		base := map[string]any{
			"agent": map[string]any{
				"name": o.agent, "description": "Sandboxed customer-support agent (OpenShell contains it; Talon governs it)", "version": "1.0.0", "model_tier": 0,
				"key":      map[string]any{"secret_name": o.agent + "-talon-key"},
				"use_case": map[string]any{"purpose": "Customer-support assistant running inside an OpenShell sandbox", "department": "support", "criticality": "standard"},
			},
			"policies": map[string]any{
				"cost_limits":   map[string]any{"per_request": 1.0, "daily": 50.0, "monthly": 500.0},
				"model_routing": map[string]any{"tier_0": map[string]any{"primary": "gpt-4o-mini", "location": "any"}, "tier_1": map[string]any{"primary": "gpt-4o-mini", "location": "any"}, "tier_2": map[string]any{"primary": "gpt-4o-mini", "location": "any"}},
			},
			"audit":      map[string]any{"log_level": "detailed", "retention_days": 2555},
			"compliance": map[string]any{"frameworks": []string{"gdpr"}, "data_residency": "eu"},
		}
		var m yaml.Node
		if err := m.Encode(base); err != nil {
			return nil, nil, false, err
		}
		// Encode yields the mapping node directly; wrap it as a document.
		return nil, &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{&m}}, true, nil
	default:
		return nil, nil, false, fmt.Errorf("reading %s: %w", path, readErr)
	}
}

// mergeBindings adds the requested subjects to the use case's identity
// bindings, keeping existing ones. The schema requires at least one binding
// when the block exists, so before the first sandbox is known the block is
// absent (every delegated request is then workload_identity_unbound).
func mergeBindings(agent *yaml.Node, subjects []string) (bindings []string) {
	existing := map[string]bool{}
	var bindingsNode *yaml.Node
	if wi := mapValue(agent, "workload_identity"); wi != nil && wi.Kind == yaml.MappingNode {
		if bn := mapValue(wi, "bindings"); bn != nil && bn.Kind == yaml.SequenceNode {
			bindingsNode = bn
			for _, b := range bn.Content {
				if subj := mapValue(b, "subject"); subj != nil {
					existing[subj.Value] = true
					bindings = append(bindings, subj.Value)
				}
			}
		}
	}
	for _, s := range subjects {
		if existing[s] {
			continue
		}
		if bindingsNode == nil {
			bindingsNode = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			setNode(ensureMap(agent, "workload_identity"), "bindings", bindingsNode)
		}
		var b yaml.Node
		_ = b.Encode(map[string]string{"runtime": "openshell", "subject": s})
		bindingsNode.Content = append(bindingsNode.Content, &b)
		bindings = append(bindings, s)
	}
	sort.Strings(bindings)
	return bindings
}

// applyShowcaseContract sets tool governance, the trusted catalog and the
// refund approval rule (the showcase contract); other keys are preserved.
func applyShowcaseContract(root *yaml.Node, o openshellPrepareOptions) error {
	caps := ensureMap(root, "capabilities")
	setNode(caps, "allowed_tools", seqOfStrings([]string{"lookup_ticket", "create_refund_request"}))
	setNode(caps, "forbidden_tools", seqOfStrings([]string{"delete_customer"}))
	var actions yaml.Node
	if err := actions.Encode(openshellActionCatalog(o.protectedBaseURL)); err != nil {
		return err
	}
	setNode(root, "actions", &actions)
	policies := ensureMap(root, "policies")
	approvals := ensureMap(policies, "approvals")
	setScalar(approvals, "expires_after", "30m", "!!str")
	rules := ensureMap(approvals, "rules")
	var rule yaml.Node
	_ = rule.Encode(map[string]any{"actions": []string{"create_refund_request"}, "approver_groups": []string{openshellApproverGroup}})
	setNode(rules, openshellRefundRule, &rule)
	return nil
}

// openshellActionCatalog is the use case's trusted catalog: a read, a
// consequential refund with a reviewer projection, and a forbidden
// deletion. Destinations are Talon-side; the sandbox has no route to them.
func openshellActionCatalog(protected string) map[string]any {
	protected = strings.TrimRight(protected, "/")
	schema := func(required []string, props map[string]any) map[string]any {
		m := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	return map[string]any{"definitions": map[string]any{
		"lookup_ticket": map[string]any{
			"description":  "Read one support ticket",
			"input_schema": schema([]string{"ticket_id"}, map[string]any{"ticket_id": map[string]any{"type": "string"}}),
			"destination":  map[string]any{"type": "http", "url": protected + "/tickets", "method": "POST", "success": map[string]any{"status_codes": []int{200}}},
		},
		"create_refund_request": map[string]any{
			"description": "Create a refund request for a support ticket",
			"input_schema": schema([]string{"ticket_id", "amount", "currency"}, map[string]any{
				"ticket_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"},
				"currency": map[string]any{"type": "string", "enum": []string{"EUR", "USD"}},
			}),
			"review":      map[string]any{"fields": []string{"ticket_id", "amount", "currency"}},
			"destination": map[string]any{"type": "http", "url": protected + "/refunds", "method": "POST", "success": map[string]any{"status_codes": []int{201}}},
		},
		"delete_customer": map[string]any{
			"input_schema": schema(nil, map[string]any{"customer_id": map[string]any{"type": "string"}}),
			"destination":  map[string]any{"type": "http", "url": protected + "/customers"},
		},
	}}
}

// ---- yaml.Node helpers -------------------------------------------------

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		*doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{m}}
		return m
	}
	return doc
}

func setNode(m *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = value
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func setScalar(m *yaml.Node, key, value, tag string) {
	setNode(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value})
}

func ensureMap(m *yaml.Node, key string) *yaml.Node {
	if v := mapValue(m, key); v != nil && v.Kind == yaml.MappingNode {
		return v
	}
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setNode(m, key, n)
	return n
}

func seqOfStrings(xs []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, x := range xs {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: x})
	}
	return n
}

func marshalYAML(doc *yaml.Node) ([]byte, error) {
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func writeTemp(target string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".prepare-*.yaml")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}

func replaceFile(target, tmp string) error {
	if st, err := os.Stat(target); err == nil {
		_ = os.Chmod(tmp, st.Mode().Perm())
	}
	return os.Rename(tmp, target)
}
