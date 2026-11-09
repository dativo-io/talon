package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// startRuntimeStatus publishes this process's runtime record into the data
// directory (#538) so the separate console process can tell which data-plane
// processes run, with which active catalog generation and reload state,
// without any network path to them. It returns a stop function that writes
// the final "stopped" record; a process killed without it simply stops
// heartbeating and is reported stale, then offline.
func startRuntimeStatus(ctx context.Context, cfg *config.Config, fleetView func() agentcatalog.FleetView, reloadEnabled bool) func() {
	var roles []string
	if serveGateway {
		roles = append(roles, runtimestatus.RoleGateway)
	}
	if serveProxyConfig != "" {
		roles = append(roles, runtimestatus.RoleMCPProxy)
	}
	if len(roles) == 0 {
		roles = append(roles, runtimestatus.RoleNative)
	}
	store, _ := filepath.Abs(cfg.EvidenceDBPath())
	base := runtimestatus.Record{
		Installation: runtimestatus.Installation{KeyFingerprint: runtimestatus.Fingerprint(cfg.SigningKey), StorePath: store},
		Roles:        roles,
		Version:      resolvedVersion(),
		Commit:       Commit,
		StartedAt:    time.Now().UTC(),
	}
	if serveProxyConfig != "" {
		base.ProxyConfig = configRef(serveProxyConfig)
	}
	if serveGateway {
		base.GatewayConfig = configRef(serveGatewayConfig)
	}
	snapshot := func(r *runtimestatus.Record) {
		if fleetView == nil {
			return
		}
		v := fleetView()
		if v.Snapshot == nil {
			return
		}
		c := &runtimestatus.Catalog{
			ActiveGeneration: v.Snapshot.Generation,
			ScanDigest:       v.Snapshot.ScanDigest,
			ActivatedAt:      v.Snapshot.BuiltAt,
			ReloadEnabled:    reloadEnabled,
			ReloadRejected:   v.Reload.Rejected,
			RejectedDigest:   v.Reload.RejectedDigest,
			RejectedCauses:   v.Reload.RejectedCauses,
			Agents:           []runtimestatus.Agent{},
		}
		if !v.Reload.ActivatedAt.IsZero() {
			c.ActivatedAt = v.Reload.ActivatedAt
		}
		if v.Reload.Rejected && !v.Reload.RejectedAt.IsZero() {
			t := v.Reload.RejectedAt
			c.RejectedAt = &t
		}
		for _, a := range v.Snapshot.List() {
			c.Agents = append(c.Agents, runtimestatus.Agent{Name: a.Name, TenantID: a.TenantID, Enabled: a.Enabled, PolicyDigest: a.PolicyDigest})
		}
		r.Catalog = c
	}
	pub, err := runtimestatus.NewPublisher(cfg.DataDir, runtimestatus.DefaultInterval, base, snapshot)
	if err != nil {
		log.Warn().Err(err).Msg("runtime_status_disabled")
		return func() {}
	}
	pubCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := pub.Run(pubCtx); err != nil {
			log.Warn().Err(err).Msg("runtime_status_write_failed")
		}
	}()
	log.Info().Str("instance_id", pub.InstanceID()).Strs("roles", roles).Msg("runtime_status_publishing")
	return func() {
		cancel()
		<-done
	}
}

// configRef records a loaded configuration file and the digest of its
// current bytes. It is called once at start-up, right after the file was
// loaded, so the digest describes what the process runs.
func configRef(path string) *runtimestatus.ConfigRef {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	ref := &runtimestatus.ConfigRef{Path: abs, LoadedAt: time.Now().UTC()}
	if data, err := os.ReadFile(abs); err == nil { //nolint:gosec // G304: the operator's own --proxy-config / --gateway-config path
		sum := sha256.Sum256(data)
		ref.Digest = hex.EncodeToString(sum[:])
	}
	return ref
}
