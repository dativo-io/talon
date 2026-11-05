package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

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

// serveCompanyActionPolicy resolves the company action policy for a serve
// mode. Gateway mode uses the gateway config it already loaded. Native-only
// serve reads the gateway config file when one exists so the company policy
// is authoritative on that path too; a PRESENT but invalid file is a startup
// error — a failed company-policy load is never treated as "no company
// policy". Quickstart serves no company policy (it accepts no gateway
// config). nil means no company action policy is configured.
func serveCompanyActionPolicy(gatewayMode, quickstart bool, path string, preloaded *gateway.GatewayConfig) (*action.CompanyActionPolicy, error) {
	if quickstart {
		return nil, nil
	}
	if gatewayMode {
		if preloaded == nil {
			return nil, errors.New("company action policy: gateway mode without a loaded gateway config")
		}
		return preloaded.OrganizationPolicy.CompanyActionPolicy(path + ":gateway.organization_policy"), nil
	}
	path = gatewayConfigPath(path)
	cfg, err := gateway.LoadGatewayConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("company action policy: gateway config %s is present but invalid (a company policy that fails to load is never ignored): %w", path, err)
	}
	return cfg.OrganizationPolicy.CompanyActionPolicy(path + ":gateway.organization_policy"), nil
}

// offlineServeContext is what the offline commands learn from the gateway
// config about how serve would run: the trigger definition rules (#479) and
// the company action policy (#425). An absent file means native-only rules
// and no company policy; a present but invalid file is doctor's finding —
// the offline command warns and proceeds without it.
type offlineServeContext struct {
	Triggers trigger.ServeRules
	Company  *action.CompanyActionPolicy
}

func offlineServeContextFromGateway() offlineServeContext {
	path := gatewayConfigPath("")
	gwCfg, err := gateway.LoadGatewayConfig(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Warn().Err(err).Str("path", path).Msg("gateway config present but invalid; validating with native-only trigger rules and WITHOUT the company action policy (run 'talon doctor'; serve refuses to start on this file)")
		}
		return offlineServeContext{}
	}
	return offlineServeContext{
		Triggers: trigger.ServeRules{GatewayServed: gwCfg.Enabled},
		Company:  gwCfg.OrganizationPolicy.CompanyActionPolicy(path + ":gateway.organization_policy"),
	}
}
