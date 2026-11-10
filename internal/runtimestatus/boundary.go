package runtimestatus

import (
	"fmt"
	"strings"
)

// Boundary proof states (#305, #555 review). Loaded answers "is this agent
// file loaded by some process"; a boundary proof answers "does a running
// process of the enforcing role run exactly the inputs this policy was
// computed from". Each enforcement boundary is proved on its own: a running
// MCP proxy proves nothing about the gateway policy, and the reverse.
const (
	BoundaryProven     = "proven_active"
	BoundaryDiffers    = "loaded_differs_from_files"
	BoundaryNotRunning = "no_running_process"
	BoundaryUnknown    = "unknown"
)

// ProveGateway proves the gateway-effective policy: every running process
// with the gateway role must report the use case (name, tenant) with
// agentDigest and must have loaded the gateway config whose current digest is
// gatewayConfigDigest ("" when the report has no gateway config file).
func ProveGateway(v View, readable bool, name, tenant, agentDigest, gatewayConfigDigest string) Loaded {
	return prove(v, readable, RoleGateway, "gateway", func(p *Process) (bool, string) {
		if p.Catalog == nil {
			return false, "reports no agent catalog"
		}
		found := false
		for _, a := range p.Catalog.Agents {
			if a.Name != name || tenantOf(a.TenantID) != tenantOf(tenant) {
				continue
			}
			found = true
			if a.PolicyDigest != agentDigest || agentDigest == "" {
				return false, "loaded a different version of the agent file"
			}
		}
		if !found {
			return false, "does not have this use case in its active generation"
		}
		return configMatches(p.GatewayConfig, gatewayConfigDigest, "gateway config")
	})
}

// ProveProxy proves the MCP proxy's tool decisions: every running process
// with the MCP proxy role must have loaded the proxy config whose current
// digest is proxyConfigDigest.
func ProveProxy(v View, readable bool, proxyConfigDigest string) Loaded {
	return prove(v, readable, RoleMCPProxy, "MCP proxy", func(p *Process) (bool, string) {
		return configMatches(p.ProxyConfig, proxyConfigDigest, "proxy config")
	})
}

// ProveGatewayConfig proves the installation-level gateway configuration:
// every running gateway loaded the gateway config whose current digest is
// gatewayConfigDigest. Per-use-case proof (agent file digests) is
// ProveGateway.
func ProveGatewayConfig(v View, readable bool, gatewayConfigDigest string) Loaded {
	return prove(v, readable, RoleGateway, "gateway", func(p *Process) (bool, string) {
		return configMatches(p.GatewayConfig, gatewayConfigDigest, "gateway config")
	})
}

// errUnreported marks a running process that did not report what it loaded:
// nothing can be compared, so the proof is unknown rather than different.
const errUnreported = "did not report the digest of the "

func configMatches(ref *ConfigRef, current, label string) (ok bool, why string) {
	switch {
	case ref == nil && current == "":
		return true, ""
	case ref == nil || ref.Digest == "":
		return false, errUnreported + label + " it loaded"
	case current == "":
		return false, "loaded a " + label + " that no longer exists on disk"
	case ref.Digest != current:
		return false, "loaded a different version of the " + label + " (edited since the process started)"
	}
	return true, ""
}

// prove requires every running process of role to satisfy match. Stale and
// offline processes prove nothing.
func prove(v View, readable bool, role, label string, match func(*Process) (bool, string)) Loaded {
	if !readable {
		return Loaded{State: BoundaryUnknown, Reason: "runtime records unavailable: whether a running " + label + " enforces these files cannot be proved"}
	}
	var ids []string
	for i := range v.Processes {
		p := &v.Processes[i]
		if p.Assessed != Running || !hasRole(p.Roles, role) {
			continue
		}
		ids = append(ids, p.InstanceID)
		if ok, why := match(p); !ok {
			state := BoundaryDiffers
			if strings.HasPrefix(why, errUnreported) {
				state = BoundaryUnknown
			}
			return Loaded{State: state, Reason: fmt.Sprintf("the running %s %s %s", label, p.InstanceID, why), InstanceIDs: ids}
		}
	}
	if len(ids) == 0 {
		return Loaded{State: BoundaryNotRunning, Reason: "no " + label + " of this installation is running: nothing enforces these files now"}
	}
	return Loaded{State: BoundaryProven, Reason: "every running " + label + " loaded exactly these files", InstanceIDs: ids}
}
