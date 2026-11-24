package evidence

import (
	"sort"
	"strings"
)

// InstallationTenantID is the reserved namespace under which Talon records
// its own installation-level operational events (#593):
//   - configuration reload activation/rejection by `talon serve`;
//   - the recovery-hold resume by `talon backup resume`;
//   - in stores written before #442, `talon enforce` mode changes.
//
// It is the tenant_id these signed records have always carried, so nothing
// historical is rewritten. It is not a customer tenant: an installation
// event belongs to the installation, not to any tenant's AI use cases.
const InstallationTenantID = "system"

// Invocation types of installation events written today.
const (
	InvocationTypeConfigReload    = "config_reload"
	InvocationTypeRecoveryResumed = "recovery_resumed"
)

// installationEventType is the closed registry of invocation types Talon
// writes under InstallationTenantID. A record is an installation event only
// when BOTH hold: its tenant_id is InstallationTenantID AND its
// invocation_type is registered here. So a customer tenant that is itself
// named "system" keeps every record of its own traffic, actions and
// operator changes; only Talon's installation bookkeeping is set apart.
var installationEventType = map[string]struct{}{
	InvocationTypeConfigReload:    {},
	InvocationTypeRecoveryResumed: {},
	// LEGACY (#442): written under "system" by the removed `talon enforce`;
	// historical rows stay installation events.
	"mode_change": {},
}

// IsInstallationEvent reports whether a record with this tenant and
// invocation type is an installation-level operational event rather than
// activity of a tenant.
func IsInstallationEvent(tenantID, invocationType string) bool {
	if tenantID != InstallationTenantID {
		return false
	}
	_, ok := installationEventType[invocationType]
	return ok
}

// installationEventSQL is the SQL predicate matching installation events,
// with its arguments in a stable order. It reads only the tenant_id and
// invocation_type columns (both covered by idx_evidence_tenant_agent_type_ts),
// never the signed JSON.
func installationEventSQL() (pred string, args []interface{}) {
	types := make([]string, 0, len(installationEventType))
	for t := range installationEventType {
		types = append(types, t)
	}
	sort.Strings(types)
	args = make([]interface{}, 0, len(types)+1)
	args = append(args, InstallationTenantID)
	for _, t := range types {
		args = append(args, t)
	}
	return "(tenant_id = ? AND invocation_type IN (?" + strings.Repeat(",?", len(types)-1) + "))", args
}
