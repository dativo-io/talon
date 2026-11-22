package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/gateway"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// #565 review, finding 5 (the running process's side). The gateway config
// digest a process publishes in its runtime record is what the console
// compares the current file with before it calls a policy "confirmed by the
// runtime". It must be the digest of the bytes the process parsed and
// compiled, not of whatever the file holds when the record is written.
func TestRuntimeRecord_GatewayConfigDigestIsOfTheLoadedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "talon.config.yaml")
	loaded := "gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: openai-api-key\n  organization_policy:\n    constraints:\n      forbidden_tools: [\"delete_*\"]\n"
	later := loaded + "      # edited after the process started\n"
	require.NoError(t, os.WriteFile(path, []byte(loaded), 0o600))
	cfg, digest, err := gateway.LoadGatewayConfigWithDigest(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, sha(loaded), digest, "the loader digests the bytes it parsed")
	// The file changes between the load and the first runtime record.
	require.NoError(t, os.WriteFile(path, []byte(later), 0o600))

	ref := loadedConfigRef(path, digest)
	require.Equal(t, sha(loaded), ref.Digest, "the record must name the bytes the process runs, not the bytes now on disk (%s)", sha(later)[:12])
	require.True(t, filepath.IsAbs(ref.Path))

	// What serve publishes: runtimeBase reads the digest serve recorded at
	// load, whatever the file holds when the record is written.
	oldGateway, oldPath, oldDigest, oldLoaded := serveGateway, serveGatewayConfig, loadedGatewayConfigDigest, loadedGatewayConfigPath
	t.Cleanup(func() {
		serveGateway, serveGatewayConfig, loadedGatewayConfigDigest, loadedGatewayConfigPath = oldGateway, oldPath, oldDigest, oldLoaded
	})
	serveGateway, serveGatewayConfig, loadedGatewayConfigDigest, loadedGatewayConfigPath = true, path, digest, path
	base := runtimeBase(&config.Config{DataDir: t.TempDir(), SigningKey: "runtime-record-digest-test-key-0001"})
	require.NotNil(t, base.GatewayConfig)
	require.Equal(t, sha(loaded), base.GatewayConfig.Digest)

	// A native (MCP-only) serve that read a company config records it too
	// (#431): its organization policy applies, so it must be provable.
	serveGateway = false
	base = runtimeBase(&config.Config{DataDir: t.TempDir(), SigningKey: "runtime-record-digest-test-key-0001"})
	require.NotNil(t, base.GatewayConfig, "native serve names the company config it read")
	require.Equal(t, sha(loaded), base.GatewayConfig.Digest)
	// One that read none records none.
	loadedGatewayConfigPath, loadedGatewayConfigDigest = "", ""
	base = runtimeBase(&config.Config{DataDir: t.TempDir(), SigningKey: "runtime-record-digest-test-key-0001"})
	require.Nil(t, base.GatewayConfig)

	// A start-up that failed before the load: nothing was parsed, the file
	// as found is recorded.
	require.Equal(t, sha(later), loadedConfigRef(path, "").Digest)
}

// The runtime record's start time is when `talon serve` began, before it
// read any agent key, not when the record was first written: a reader that
// sees "started after T" may conclude that the keys were read after T
// (#567 review, credential attribution).
func TestRuntimeBase_StartedAtIsWhenServeBeganNotWhenTheRecordIsWritten(t *testing.T) {
	old := serveStartedAt
	t.Cleanup(func() { serveStartedAt = old })
	began := time.Now().UTC().Add(-90 * time.Second)
	serveStartedAt = began
	base := runtimeBase(&config.Config{DataDir: t.TempDir(), SigningKey: "runtime-record-start-time-0000001"})
	if !base.StartedAt.Equal(began) {
		t.Fatalf("StartedAt = %s, want the moment serve began (%s)", base.StartedAt, began)
	}
	// Outside `talon serve` (no start recorded) the record still has a time.
	serveStartedAt = time.Time{}
	if runtimeBase(&config.Config{DataDir: t.TempDir(), SigningKey: "runtime-record-start-time-0000001"}).StartedAt.IsZero() {
		t.Fatal("StartedAt must never be zero")
	}
}
