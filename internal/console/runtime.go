package console

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"

	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// SourceRuntimeRecords is the runtime status records each `talon serve`
// process publishes into the installation's data directory (#538).
const SourceRuntimeRecords = "runtime_records"

// runtime assesses the data-plane processes of this installation from their
// published records. Without a data directory or an installation
// fingerprint the console cannot match records to its installation, so the
// runtime stays unknown rather than guessed.
func (s *Service) runtime() Runtime {
	if s.cfg.DataDir == "" || s.cfg.InstallationFingerprint == "" {
		return Runtime{Availability: Availability{
			State: StateUnknown, Source: SourceNone,
			Note: "the console was started without its installation's data directory and signing key, so runtime records cannot be matched to it",
		}}
	}
	expected, configErrs := s.expectedRoles()
	v := s.runtimeReader.Assess(s.cfg.DataDir, s.cfg.InstallationFingerprint, expected, s.now())
	// A role whose configuration cannot be read is not "not configured":
	// whether it should run is unknown (#554 review).
	for i := range v.Roles {
		if e, bad := configErrs[v.Roles[i].Role]; bad && v.Roles[i].State == runtimestatus.NotConfigured {
			v.Roles[i].State, v.Roles[i].Reason = runtimestatus.Unknown, e
		}
	}
	out := Runtime{Roles: v.Roles, Processes: v.Processes, Rejected: v.Rejected, ReadAt: v.ReadAt}
	if out.Processes == nil {
		out.Processes = []runtimestatus.Process{}
	}
	if v.Err != "" {
		out.Availability = Availability{State: StateUnavailable, Source: SourceRuntimeRecords, AsOf: v.ReadAt, Error: v.Err}
		return out
	}
	out.Availability = Availability{
		State: StateOK, Source: SourceRuntimeRecords, AsOf: v.ReadAt,
		Note: "liveness is each process's own heartbeat in the data directory; history in the evidence store does not depend on it",
	}
	// The active generation is stated only when every running process with a
	// catalog agrees on it; otherwise the per-process values are in Processes.
	gen := ""
	agree := true
	for i := range v.Processes {
		p := &v.Processes[i]
		if !p.Current || p.Assessed != runtimestatus.Running || p.Catalog == nil {
			continue
		}
		switch {
		case gen == "":
			gen = p.Catalog.ActiveGeneration
			t := p.Catalog.ActivatedAt
			out.ActivatedAt = &t
		case gen != p.Catalog.ActiveGeneration:
			agree = false
		}
	}
	if agree {
		out.ActiveGeneration = gen
	} else {
		out.ActivatedAt = nil
		out.Availability.Note = "running processes report different active generations; see each process"
	}
	return out
}

// expectedRoles are the roles this installation's configuration (as given
// to the console) says should run: the MCP proxy when a proxy config is set,
// the gateway when the gateway config enables it. configErrs names roles
// whose configuration exists but cannot be used, so the caller never reports
// them as intentionally absent. A gateway config path that does not exist is
// no gateway.
func (s *Service) expectedRoles() (exp map[string]bool, configErrs map[string]string) {
	exp, configErrs = map[string]bool{}, map[string]string{}
	if s.cfg.ConfigSources.ProxyConfig != "" {
		exp[runtimestatus.RoleMCPProxy] = true
	}
	if p := s.cfg.ConfigSources.GatewayConfig; p != "" {
		gw, err := gateway.LoadGatewayConfig(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			configErrs[runtimestatus.RoleGateway] = "the gateway config cannot be parsed, so whether a gateway should run is unknown: " + err.Error()
		case gw.Enabled:
			exp[runtimestatus.RoleGateway] = true
		}
	}
	return exp, configErrs
}

// fileDigest is the sha256 of a file's current bytes ("" when unreadable).
func fileDigest(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // G304: a configuration path the operator gave the console process
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
