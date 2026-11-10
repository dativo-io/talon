// Package runtimestatus lets each running Talon data-plane process (`talon
// serve`: MCP proxy, LLM gateway, or both) publish a small, read-only status
// record into the installation's own data directory, and lets the console
// process read those records without any network path to the data plane
// (#538). It is not a registry or coordinator: a record is one JSON file per
// process instance under <data_dir>/runtime/, written atomically by that
// process alone, and the console only reads.
//
// A record states what the writing process knows about itself (version,
// roles, active catalog generation, reload rejection, loaded config digests)
// and when it last said so. Liveness is derived from that heartbeat's age by
// Assess, never from the existence of the evidence store or from evidence.
// Records from another installation (different evidence signing key) are
// rejected, so unrelated runtimes are never combined.
package runtimestatus

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SchemaVersion is the record format. Readers reject other versions.
const SchemaVersion = 1

// Roles a process can serve.
const (
	RoleMCPProxy = "mcp_proxy"
	RoleGateway  = "gateway"
	RoleNative   = "native" // native agent execution routes (talon serve without --gateway)
)

// Record states written by the process.
const (
	StateRunning = "running"
	StateStopped = "stopped" // written on graceful shutdown
	// StateFailed is written once by a process that failed during start-up
	// and never served (see WriteStartupFailure).
	StateFailed = "failed"
)

// DirName is the subdirectory of the data directory holding records.
const DirName = "runtime"

// Record is one process instance's self-report.
type Record struct {
	Schema       int          `json:"schema"`
	InstanceID   string       `json:"instance_id"`
	Installation Installation `json:"installation"`
	Roles        []string     `json:"roles"`
	Version      string       `json:"version"`
	Commit       string       `json:"commit,omitempty"`
	PID          int          `json:"pid"`
	Host         string       `json:"host,omitempty"`
	StartedAt    time.Time    `json:"started_at"`
	WrittenAt    time.Time    `json:"written_at"`
	// Sequence increases with every write of this instance; a reader never
	// replaces a newer record with an older one (out-of-order reads).
	Sequence uint64 `json:"sequence"`
	// IntervalSeconds is the heartbeat period; Assess derives staleness from it.
	IntervalSeconds int        `json:"interval_seconds"`
	State           string     `json:"state"`
	StoppedAt       *time.Time `json:"stopped_at,omitempty"`

	Catalog       *Catalog   `json:"catalog,omitempty"`
	ProxyConfig   *ConfigRef `json:"proxy_config,omitempty"`
	GatewayConfig *ConfigRef `json:"gateway_config,omitempty"`

	// AgentKeys is what the process holds for agent-key authentication in
	// its active generation (absent from records written before it existed:
	// readers then report authentication readiness as unverified).
	AgentKeys *AgentKeys `json:"agent_keys,omitempty"`
	// StartupFailure is set only on a StateFailed record.
	StartupFailure *StartupFailure `json:"startup_failure,omitempty"`
}

// AgentKeys counts the AI use cases of the active generation that declare an
// agent key (agent.key.secret_name) and those whose key material the process
// resolved into its identity registry. It carries names and counts only,
// never a key, a digest of a key or a secret value. Loaded keys mean the
// process can match a presented key; they do not prove that any client holds
// the right one.
type AgentKeys struct {
	Declared int `json:"declared"`
	Loaded   int `json:"loaded"`
	// Unloaded names the use cases that declare a key the process does not
	// hold (unminted, not readable, not decryptable), bounded.
	Unloaded []string `json:"unloaded,omitempty"`
}

// MaxUnloadedNames bounds AgentKeys.Unloaded.
const MaxUnloadedNames = 20

// StartupFailure is why a process stopped before serving: a fixed category
// and a fixed sentence chosen by the process, never the raw error text
// (which can carry configuration content). The process log has the detail.
type StartupFailure struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// Startup failure codes.
const (
	FailureAgentKeyUnavailable = "agent_key_unavailable" // a declared agent key is not in the vault, not readable or not decryptable
	FailureNoKeyedAgents       = "no_keyed_agents"       // gateway mode with no keyed agent
	FailureSecretsStore        = "secrets_store"         // the secrets store cannot be opened with the configured key
	FailureConfiguration       = "configuration"         // any other start-up error
)

// Installation identifies the installation a record belongs to without
// revealing any key: KeyFingerprint is an HMAC of a fixed label under the
// evidence signing key, so two processes match only when they sign evidence
// with the same key. StorePath is informational (mount points can differ
// between containers).
type Installation struct {
	KeyFingerprint string `json:"key_fingerprint"`
	StorePath      string `json:"store_path"`
}

// Catalog is the process's ACTIVE agent catalog generation and reload state,
// copied from its reloader (agentcatalog.ReloadState / RuntimeSnapshot).
type Catalog struct {
	ActiveGeneration string     `json:"active_generation"`
	ScanDigest       string     `json:"scan_digest"`
	ActivatedAt      time.Time  `json:"activated_at"`
	ReloadEnabled    bool       `json:"reload_enabled"`
	ReloadRejected   bool       `json:"reload_rejected"`
	RejectedDigest   string     `json:"rejected_digest,omitempty"`
	RejectedAt       *time.Time `json:"rejected_at,omitempty"`
	RejectedCauses   []string   `json:"rejected_causes,omitempty"`
	Agents           []Agent    `json:"agents"`
}

// Agent is one AI use case in the active generation.
type Agent struct {
	Name         string `json:"name"`
	TenantID     string `json:"tenant_id"`
	Enabled      bool   `json:"enabled"`
	PolicyDigest string `json:"policy_digest"`
}

// ConfigRef names a configuration file the process loaded and the digest of
// the bytes it loaded (sha256), so a reader can tell whether the file on
// disk is still what the process runs.
type ConfigRef struct {
	Path     string    `json:"path"`
	Digest   string    `json:"digest"`
	LoadedAt time.Time `json:"loaded_at"`
}

// Fingerprint derives the installation fingerprint from the evidence signing
// key (never the key itself).
func Fingerprint(signingKey string) string {
	m := hmac.New(sha256.New, []byte(signingKey))
	m.Write([]byte("talon-installation-fingerprint-v1"))
	return hex.EncodeToString(m.Sum(nil))[:32]
}
