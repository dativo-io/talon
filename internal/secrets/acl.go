package secrets

import (
	"path/filepath"
	"strings"
)

// ACL defines who can access a secret.
type ACL struct {
	Agents          []string `json:"agents"`           // Allowed agents (glob patterns)
	Tenants         []string `json:"tenants"`          // Allowed tenants (glob patterns)
	ForbiddenAgents []string `json:"forbidden_agents"` // Explicitly denied agents
}

// CheckAccess verifies if a tenant+agent combination can access the secret.
// Forbidden list is checked first (explicit deny). Empty allow lists mean allow-all.
func (a ACL) CheckAccess(tenantID, agentID string) bool {
	for _, pattern := range a.ForbiddenAgents {
		if matchGlob(pattern, agentID) {
			return false
		}
	}

	tenantAllowed := len(a.Tenants) == 0
	for _, pattern := range a.Tenants {
		if matchGlob(pattern, tenantID) {
			tenantAllowed = true
			break
		}
	}
	if !tenantAllowed {
		return false
	}

	agentAllowed := len(a.Agents) == 0
	for _, pattern := range a.Agents {
		if matchGlob(pattern, agentID) {
			agentAllowed = true
			break
		}
	}

	return agentAllowed
}

// matchGlob performs simple glob matching using filepath.Match.
func matchGlob(pattern, str string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == str
	}
	matched, _ := filepath.Match(pattern, str)
	return matched
}
