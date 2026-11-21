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

// ProveGatewayConfig proves the installation-level gateway configuration:
// every running gateway loaded the gateway config whose current digest is
// gatewayConfigDigest. Per-use-case proof (agent file digests) is
// ProveGateway.
func ProveGatewayConfig(v View, readable bool, gatewayConfigDigest string) Loaded {
	return prove(v, readable, RoleGateway, "gateway", func(p *Process) (bool, string) {
		return configMatches(p.GatewayConfig, gatewayConfigDigest, "gateway config")
	})
}

// ProveActionPolicy proves the Action Gateway's effective action policy for
// one use case. The Action Gateway is served by EVERY `talon serve` process,
// whatever its role, and each compiles the action policy from two inputs: the
// agent file of its active generation and the company action policy of the
// gateway config it read at start. So every running serve process (a process
// that reports an agent catalog) must report the use case with agentDigest
// AND the digest of the gateway config it loaded, equal to
// gatewayConfigDigest. A process that serves the Action Gateway but does not
// report which gateway config it read (a serve without --gateway reads the
// company policy from the file without reporting its digest) leaves the proof
// unknown: its company action policy cannot be compared, and is never assumed.
func ProveActionPolicy(v View, readable bool, name, tenant, agentDigest, gatewayConfigDigest string) Loaded {
	const label = "talon serve"
	if !readable {
		return Loaded{State: BoundaryUnknown, Reason: "runtime records unavailable: whether a running " + label + " enforces this action policy cannot be proved"}
	}
	var ids []string
	for i := range v.Processes {
		p := &v.Processes[i]
		if p.Assessed != Running {
			continue
		}
		if p.Catalog == nil {
			// A process reporting the governed MCP role is a talon serve
			// (#431): one that does not report its active generation is
			// unverifiable, never "not running".
			if hasRole(p.Roles, RoleMCP) {
				ids = append(ids, p.InstanceID)
				return Loaded{State: BoundaryUnknown, Reason: fmt.Sprintf("the running %s %s does not report its active generation, so which agent files it enforces cannot be compared", label, p.InstanceID), InstanceIDs: ids}
			}
			continue
		}
		ids = append(ids, p.InstanceID)
		fail := func(state, why string) Loaded {
			return Loaded{State: state, Reason: fmt.Sprintf("the running %s %s %s", label, p.InstanceID, why), InstanceIDs: ids}
		}
		found := false
		for _, a := range p.Catalog.Agents {
			if a.Name != name || tenantOf(a.TenantID) != tenantOf(tenant) {
				continue
			}
			found = true
			if a.PolicyDigest != agentDigest || agentDigest == "" {
				return fail(BoundaryDiffers, "loaded a different version of the agent file")
			}
		}
		if !found {
			return fail(BoundaryDiffers, "does not have this use case in its active generation")
		}
		if state, why := companyConfigProof(p, gatewayConfigDigest); state != "" {
			return fail(state, why)
		}
	}
	if len(ids) == 0 {
		return Loaded{State: BoundaryNotRunning, Reason: "no " + label + " of this installation is running: nothing enforces this action policy now"}
	}
	return Loaded{State: BoundaryProven, Reason: "every running " + label + " loaded this agent file and read the company action policy from this gateway config at start", InstanceIDs: ids}
}

// errUnreported marks a running process that did not report what it loaded:
// nothing can be compared, so the proof is unknown rather than different.
const errUnreported = "did not report the digest of the "

// companyConfigProof compares the company config a serve process read at
// start with the one on disk now: "" when they agree, else the boundary
// state and why.
func companyConfigProof(p *Process, current string) (state, why string) {
	if p.GatewayConfig == nil || p.GatewayConfig.Digest == "" {
		// A process that reports the governed MCP role (#431) records the
		// company config whenever it read one: reporting none while none
		// exists on disk proves "no company policy".
		if p.GatewayConfig == nil && current == "" && hasRole(p.Roles, RoleMCP) {
			return "", ""
		}
		return BoundaryUnknown, "serves the Action Gateway but does not report which gateway config it read, so its company action policy cannot be compared"
	}
	if ok, why := configMatches(p.GatewayConfig, current, "gateway config"); !ok {
		return BoundaryDiffers, why + "; the company action policy is read at process start"
	}
	return "", ""
}

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
