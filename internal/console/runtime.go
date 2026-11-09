package console

import (
	"crypto/sha256"
	"encoding/hex"
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
	v := s.runtimeReader.Assess(s.cfg.DataDir, s.cfg.InstallationFingerprint, s.expectedRoles(), s.now())
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
// the gateway when the gateway config enables it.
func (s *Service) expectedRoles() map[string]bool {
	exp := map[string]bool{}
	if s.cfg.ConfigSources.ProxyConfig != "" {
		exp[runtimestatus.RoleMCPProxy] = true
	}
	if p := s.cfg.ConfigSources.GatewayConfig; p != "" {
		if gw, err := gateway.LoadGatewayConfig(p); err == nil && gw.Enabled {
			exp[runtimestatus.RoleGateway] = true
		}
	}
	return exp
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
