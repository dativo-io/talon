package runtimestatus

// Loaded states whether a use case's current file is what a running process
// of this installation loaded, proved by the policy digest the process
// reports for that use case (#538, #305).
type Loaded struct {
	State              string   `json:"state"` // loaded_matches_file | loaded_differs_from_file | not_in_active_generation | unknown
	Reason             string   `json:"reason"`
	ActivePolicyDigest string   `json:"active_policy_digest,omitempty"`
	InstanceIDs        []string `json:"instance_ids,omitempty"`
}

// Loaded states.
const (
	LoadedMatchesFile     = "loaded_matches_file"
	LoadedDiffersFromFile = "loaded_differs_from_file"
	NotInActiveGeneration = "not_in_active_generation"
	LoadedUnknown         = "unknown"
)

// ProveLoaded compares fileDigest (the policy digest of the current agent
// file) with what the current running processes in v report for the use case
// (name, tenant; an empty tenant means "default"). readable is false when the
// runtime records could not be read at all.
func ProveLoaded(v View, readable bool, name, tenant, fileDigest string) Loaded {
	if !readable {
		return Loaded{State: LoadedUnknown, Reason: "runtime records unavailable: whether this file is loaded cannot be proved"}
	}
	ids, digest, seen, conflict := reported(v, name, tenant)
	switch {
	case !seen:
		return Loaded{State: LoadedUnknown, Reason: "no running process reports an agent catalog: whether this file is loaded cannot be proved"}
	case conflict:
		return Loaded{State: LoadedUnknown, Reason: "running processes report different policy digests for this use case", InstanceIDs: ids}
	case len(ids) == 0:
		return Loaded{State: NotInActiveGeneration, Reason: "no running process has this use case in its active generation (added since activation, or rejected)"}
	case fileDigest == "" || digest == "":
		return Loaded{State: LoadedUnknown, Reason: "a policy digest is missing, so the file cannot be compared", ActivePolicyDigest: digest, InstanceIDs: ids}
	case fileDigest == digest:
		return Loaded{State: LoadedMatchesFile, Reason: "the running process reports the policy digest of the current file", ActivePolicyDigest: digest, InstanceIDs: ids}
	default:
		return Loaded{State: LoadedDiffersFromFile, Reason: "the running process loaded a different version of this file (edited since activation, or the reload was rejected)", ActivePolicyDigest: digest, InstanceIDs: ids}
	}
}

// reported collects what the current running processes report for the use
// case: the instances, the policy digest, whether any process reports a
// catalog at all, and whether processes disagree on the digest.
func reported(v View, name, tenant string) (ids []string, digest string, seen, conflict bool) {
	for i := range v.Processes {
		p := &v.Processes[i]
		if !p.Current || p.Assessed != Running || p.Catalog == nil {
			continue
		}
		seen = true
		for _, a := range p.Catalog.Agents {
			if a.Name != name || tenantOf(a.TenantID) != tenantOf(tenant) {
				continue
			}
			ids = append(ids, p.InstanceID)
			switch {
			case digest == "":
				digest = a.PolicyDigest
			case digest != a.PolicyDigest:
				conflict = true
			}
		}
	}
	return ids, digest, seen, conflict
}

func tenantOf(t string) string {
	if t == "" {
		return "default"
	}
	return t
}
