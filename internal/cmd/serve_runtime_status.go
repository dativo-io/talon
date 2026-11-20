package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
)

// errNoKeyedAgents marks gateway mode started without any keyed agent.
var errNoKeyedAgents = errors.New("gateway mode requires at least one keyed agent")

// startRuntimeStatus publishes this process's runtime record into the data
// directory (#538) so the separate console process can tell which data-plane
// processes run, with which active catalog generation and reload state,
// without any network path to them. It returns a stop function that writes
// the final "stopped" record; a process killed without it simply stops
// heartbeating and is reported stale, then offline.
func startRuntimeStatus(ctx context.Context, cfg *config.Config, fleetView func() agentcatalog.FleetView, reloadEnabled bool) func() {
	base := runtimeBase(cfg)
	roles := base.Roles
	snapshot := func(r *runtimestatus.Record) {
		if fleetView == nil {
			return
		}
		v := fleetView()
		if v.Snapshot == nil {
			return
		}
		r.Catalog = catalogOf(v, reloadEnabled)
		r.AgentKeys = agentKeysOf(v.Snapshot)
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

// serveStartedAt is the start time `talon serve` reports in its runtime
// record. It is taken at one precise point: after the vault is open and
// before the process reads its first agent key. Readers rely on both sides
// (effective.Verification attributes traffic to the credential stored now
// on that basis):
//
//   - a process whose record says it started at or after a moment T read
//     its agent keys after T. Taking the time when the record is first
//     written, after the keys were read, would not give that;
//   - a process that opened an older vault, and thereby made it record
//     value versions, reports a start time after that moment, so it counts
//     as "started after the vault began to record versions".
var serveStartedAt time.Time

// runtimeBase is the static part of this process's record: installation,
// roles from the serve flags, version, loaded config files.
func runtimeBase(cfg *config.Config) runtimestatus.Record {
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
		StartedAt:    serveStartedAt,
	}
	if base.StartedAt.IsZero() {
		base.StartedAt = time.Now().UTC()
	}
	if serveProxyConfig != "" {
		base.ProxyConfig = configRef(serveProxyConfig)
	}
	if serveGateway {
		base.GatewayConfig = loadedConfigRef(serveGatewayConfig, loadedGatewayConfigDigest)
	}
	return base
}

// loadedGatewayConfigDigest is the SHA-256 of the bytes this process parsed
// its gateway config from (gateway.LoadGatewayConfigWithDigest), set when
// serve loads it. Empty until then.
var loadedGatewayConfigDigest string

// loadedConfigRef records a configuration file with the digest of the bytes
// the process parsed it from. The console compares that digest with the
// current file before it calls a policy "confirmed by the runtime", so it
// must name what the process compiled: a digest taken with a second read of
// the file would name other bytes when the file changed in between (#565
// review). A process that has not loaded the file runs nothing of it (a
// start-up that failed earlier): only then is the file as found recorded.
func loadedConfigRef(path, loadedDigest string) *runtimestatus.ConfigRef {
	if loadedDigest == "" {
		return configRef(path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return &runtimestatus.ConfigRef{Path: abs, Digest: loadedDigest, LoadedAt: time.Now().UTC()}
}

func catalogOf(v agentcatalog.FleetView, reloadEnabled bool) *runtimestatus.Catalog {
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
	return c
}

// agentKeysOf counts, for the active generation, the use cases that declare
// an agent key and those whose key the identity registry holds. A single-file
// plain serve whose key is unminted or undecryptable runs with no registry
// (#266 degrade): that is exactly the case this makes visible. Only names
// and counts leave the process.
func agentKeysOf(snap *agentcatalog.RuntimeSnapshot) *runtimestatus.AgentKeys {
	held := map[string]bool{}
	if snap.Registry != nil {
		for _, id := range snap.Registry.Identities() {
			held[id.Name] = true
		}
	}
	k := &runtimestatus.AgentKeys{}
	for _, a := range snap.List() {
		if a.Policy == nil || a.Policy.Agent.Key == nil || a.Policy.Agent.Key.SecretName == "" {
			continue
		}
		k.Declared++
		if held[a.Name] {
			k.Loaded++
		} else if len(k.Unloaded) < runtimestatus.MaxUnloadedNames {
			k.Unloaded = append(k.Unloaded, a.Name)
		}
	}
	return k
}

// recordServeStartupFailure leaves a "failed to start" record for the roles
// this serve invocation would have served, so the console reports the cause
// category instead of a role that never reported. Best effort: a failure to
// write is logged, the start-up error stays the process's exit reason.
func recordServeStartupFailure(cfg *config.Config, startErr error) {
	if cfg == nil || cfg.DataDir == "" || cfg.SigningKey == "" {
		return
	}
	if err := runtimestatus.WriteStartupFailure(cfg.DataDir, runtimeBase(cfg), classifyStartupFailure(startErr), time.Now()); err != nil {
		log.Warn().Err(err).Msg("runtime_status_startup_failure_not_recorded")
	}
}

// classifyStartupFailure maps a start-up error to a fixed code and sentence.
// The raw error is never copied into the record: it can quote configuration.
func classifyStartupFailure(err error) runtimestatus.StartupFailure {
	switch {
	case errors.Is(err, secrets.ErrSecretUndecryptable):
		return runtimestatus.StartupFailure{
			Code:   runtimestatus.FailureAgentKeyUnavailable,
			Reason: "a declared agent key cannot be decrypted with the configured secrets key (TALON_SECRETS_KEY changed since the key was stored?); agent authentication cannot work",
		}
	case errors.Is(err, secrets.ErrSecretNotFound), errors.Is(err, secrets.ErrSecretAccessDenied):
		return runtimestatus.StartupFailure{
			Code:   runtimestatus.FailureAgentKeyUnavailable,
			Reason: "a declared agent key is not in the vault or not readable by its use case; run talon secrets set for it",
		}
	case errors.Is(err, secrets.ErrInvalidEncryptionKey):
		return runtimestatus.StartupFailure{
			Code:   runtimestatus.FailureSecretsStore,
			Reason: "the secrets store cannot be opened with the configured secrets key",
		}
	case errors.Is(err, errNoKeyedAgents):
		return runtimestatus.StartupFailure{
			Code:   runtimestatus.FailureNoKeyedAgents,
			Reason: "gateway mode requires at least one use case with an agent key",
		}
	}
	return runtimestatus.StartupFailure{
		Code:   runtimestatus.FailureConfiguration,
		Reason: "start-up failed; the process log has the error",
	}
}

// configRef records a configuration file and the digest of its bytes as the
// file is found now. Where the process knows the bytes it parsed, use
// loadedConfigRef instead.
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
