// Package agentcatalog is the ONE agent catalog every execution surface
// resolves against (Fleet Operations v1, #267): gateway identity, native
// runs, the run API, trigger dispatch, doctor, validate, and the fleet view.
// It discovers agent configs (one agent.talon.yaml per AI use case, either a
// single file or a recursive agents_dir scan), and publishes them as ONE
// immutable RuntimeSnapshot behind ONE atomic holder — the generation a
// request or run captures at entry and uses through evidence (#269).
//
// Layering: this package imports policy (loader), agentbridge (the one
// policy→gateway adapter) and gateway (registry types). The gateway package
// stays free of the policy loader; the policy package stays free of gateway
// types.
package agentcatalog

import (
	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/policy"
)

// CatalogAgent is one discovered AI use case: the parsed policy plus the
// identity facts every surface needs. The Policy pointer is treated as
// immutable after discovery — snapshots share it, never mutate it.
type CatalogAgent struct {
	// Name is the agent's operational identity, unique per installation.
	Name string
	// TenantID as declared in the file. Empty means "default" (normalized at
	// registry build, not here — the file's declaration stays inspectable).
	TenantID string
	// Path is the config file the agent was loaded from.
	Path string
	// PolicyDigest is the policy's canonical content hash (policy.Hash) —
	// the version signed evidence names.
	PolicyDigest string
	// Enabled is the operational on/off switch (#268). Always true until the
	// agent schema carries `agent.enabled`; the field exists so snapshots and
	// consumers are already shaped for it.
	Enabled bool
	// Policy is the fully loaded and validated agent policy.
	Policy *policy.Policy
}

// LoadedAgent adapts this agent for gateway registry construction via the
// shared bridge — the IDENTICAL identity serve, doctor and enforce build.
func (a *CatalogAgent) LoadedAgent() gateway.LoadedAgent {
	return agentbridge.LoadedAgentFromPolicy(a.Policy, a.Path)
}

// Fleet-issue statuses. A FleetIssue is a configuration problem reported by
// PATH — never a synthesized agent identity: a file that has never validated
// has no trustworthy agent name, so no identity is invented from it.
const (
	IssueInvalidConfig = "invalid_config"
	IssueDuplicateName = "duplicate_name"
)

// FleetIssue is one rejected config file, addressed by path. Agent is the
// last-known-good name when one is reliably attributable, otherwise empty
// ("unknown") — malformed YAML is never raw-parsed for a name.
type FleetIssue struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Agent  string `json:"agent,omitempty"`
}
