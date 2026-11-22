package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/trigger"
)

// The company action policy (#425) lives in the operator-owned gateway config
// (gateway.organization_policy.constraints: forbidden_tools, action_approvals)
// and is compiled into every runtime generation. One resolution for every
// surface that needs it: serve (both serving modes), validate and the
// `talon actions` inspection — so no surface can see a different company
// policy than the server applies.

// gatewayConfigPath is the gateway config file offline commands and the
// native-only serve read: TALON_GATEWAY_CONFIG, else the given default
// (serve's --gateway-config value, or talon.config.yaml).
func gatewayConfigPath(fallback string) string {
	if p := strings.TrimSpace(os.Getenv("TALON_GATEWAY_CONFIG")); p != "" {
		return p
	}
	if fallback == "" {
		return "talon.config.yaml"
	}
	return fallback
}

// serveOrganizationPolicy resolves the company baseline
// (gateway.organization_policy) a serve process applies, in EVERY serve
// mode: the company action policy (#425) and the PII baseline of the
// governed MCP route (#431) both come from it, so a native (MCP-only) serve
// cannot run with a weaker company policy than a gateway serve of the same
// installation. Gateway mode uses the gateway config it already loaded.
// Native-only serve reads the gateway config file when one exists; a
// PRESENT but invalid file is a startup error — a failed company-policy load
// is never treated as "no company policy". Absent file: nil (no company
// baseline). Quickstart serves no company policy (it accepts no gateway
// config). The source names the file for evidence and logs.
func serveOrganizationPolicy(gatewayMode, quickstart bool, path string, preloaded *gateway.GatewayConfig, preloadedDigest string) (servedOrgPolicy, error) {
	if quickstart {
		return servedOrgPolicy{}, nil
	}
	if gatewayMode {
		if preloaded == nil {
			return servedOrgPolicy{}, errors.New("company policy: gateway mode without a loaded gateway config")
		}
		o := preloaded.OrganizationPolicy
		return servedOrgPolicy{Policy: &o, Path: path, Digest: preloadedDigest}, nil
	}
	path = gatewayConfigPath(path)
	cfg, digest, err := gateway.LoadGatewayConfigWithDigest(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return servedOrgPolicy{}, nil
		}
		return servedOrgPolicy{}, fmt.Errorf("company policy: gateway config %s is present but invalid (a company policy that fails to load is never ignored): %w", path, err)
	}
	o := cfg.OrganizationPolicy
	return servedOrgPolicy{Policy: &o, Path: path, Digest: digest}, nil
}

// servedOrgPolicy is the company baseline a serve process read: the policy
// (nil without one), the file and the digest of the exact bytes parsed —
// what the process's runtime record publishes, so the console can prove
// which company policy a running process applies in every serve mode.
type servedOrgPolicy struct {
	Policy *gateway.OrganizationPolicy
	Path   string
	Digest string
}

// companyActionPolicy is the company action policy of the baseline (nil
// without one).
func (o servedOrgPolicy) companyActionPolicy() *action.CompanyActionPolicy {
	if o.Policy == nil {
		return nil
	}
	return o.Policy.CompanyActionPolicy(o.Path + ":gateway.organization_policy")
}

// offlineServeContext is what the offline commands learn from the gateway
// config about how serve would run: the trigger definition rules (#479) and
// the company action policy (#425). An absent file means native-only rules
// and no company policy. A PRESENT but invalid file is an error, exactly as
// for serve: validating or inspecting "without" the company policy
// production would refuse to load is a misleading result, never a success
// (PR #526 review P2).
type offlineServeContext struct {
	Triggers trigger.ServeRules
	Company  *action.CompanyActionPolicy
}

func offlineServeContextFromGateway() (offlineServeContext, error) {
	path := gatewayConfigPath("")
	gwCfg, err := gateway.LoadGatewayConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return offlineServeContext{}, nil
		}
		return offlineServeContext{}, fmt.Errorf("gateway config %s is present but invalid: %w — fix it (serve refuses to start on this file); a company action policy that fails to load is never ignored", path, err)
	}
	return offlineServeContext{
		Triggers: trigger.ServeRules{GatewayServed: gwCfg.Enabled},
		Company:  gwCfg.OrganizationPolicy.CompanyActionPolicy(path + ":gateway.organization_policy"),
	}, nil
}
