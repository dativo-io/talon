package fleet

// Membership is one agent's identity + config-validity facts, as read from the
// runtime snapshot (server path) or a local scan (offline path). It is the input
// to AssembleStatuses, which pairs it with effective caps to produce the
// AgentStatus that Project consumes. Keeping this a plain struct — rather than
// importing agentcatalog — keeps internal/fleet a leaf read model.
type Membership struct {
	Name         string
	TenantID     string
	Enabled      bool
	ConfigPath   string
	PolicyDigest string
	// ConfigRejected — this agent's current on-disk config was rejected by the
	// last reload/scan; last-known-good is still serving (#269). The caller
	// derives it from the reload state (by FleetIssue agent-name or path).
	ConfigRejected bool
	ConfigError    string
	// PolicyDenyAll — the ACTIVE policy denies all new work agent-wide (BLOCKED).
	PolicyDenyAll bool
}

// CapLookup returns an agent's effective daily/monthly cost caps (0 = uncapped),
// ok=false when the agent has no resolvable caps. Both surfaces pass the SAME
// resolver shape used by GET /v1/costs/budget (gateway.ResolveEffectivePolicy →
// BindingDailyCap/BindingMonthlyCap), so the COST denominators and budget health
// match `talon costs` exactly.
type CapLookup func(tenantID, agentID string) (daily, monthly float64, ok bool)

// AssembleStatuses turns membership + effective caps into the []AgentStatus that
// Project consumes. It is the shared step both the server handler and the CLI
// run before Project, so neither surface re-derives caps or config-validity
// independently. caps may be nil (no org caps in native serve) → uncapped.
func AssembleStatuses(members []Membership, caps CapLookup, currency string) []AgentStatus {
	out := make([]AgentStatus, 0, len(members))
	for i := range members {
		m := &members[i]
		var daily, monthly float64
		if caps != nil {
			if d, mo, ok := caps(m.TenantID, m.Name); ok {
				daily, monthly = d, mo
			}
		}
		out = append(out, AgentStatus{
			Name:           m.Name,
			TenantID:       m.TenantID,
			Enabled:        m.Enabled,
			ConfigPath:     m.ConfigPath,
			PolicyDigest:   m.PolicyDigest,
			ConfigRejected: m.ConfigRejected,
			ConfigError:    m.ConfigError,
			PolicyDenyAll:  m.PolicyDenyAll,
			DailyCap:       daily,
			MonthlyCap:     monthly,
			Currency:       currency,
		})
	}
	return out
}
