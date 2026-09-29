package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyPostureSigningKey matches internal/testutil.TestSigningKey; the
// evidence package cannot import testutil (cycle), so the literal is repeated.
const legacyPostureSigningKey = "test-signing-key-1234567890123456"

// loadLegacyPostureFixtures returns the signed records captured under the
// removed live postures (gateway shadow/log_only, MCP proxy passthrough,
// native audit.observation_only, talon enforce mode_change) before #442
// deleted their writers. They are the compatibility contract for
// ObservationModeOverride / ShadowViolations / mode_change /
// proxy_shadow_violation: those fields and record types no longer get
// written, but every historical record must still round-trip losslessly and
// verify. Deleting, renaming, retagging or MOVING one of those struct fields
// breaks this test — and would break every operator's historical audit trail.
func loadLegacyPostureFixtures(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "legacy_posture", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, paths, "legacy posture fixtures missing")
	sort.Strings(paths)
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		out[filepath.Base(p)] = bytes.TrimSpace(b)
	}
	return out
}

func TestLegacyPostureFixtures_RoundTripAndVerify(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), legacyPostureSigningKey)
	require.NoError(t, err)
	defer store.Close()

	for name, raw := range loadLegacyPostureFixtures(t) {
		t.Run(name, func(t *testing.T) {
			var ev Evidence
			require.NoError(t, json.Unmarshal(raw, &ev))
			require.NotEmpty(t, ev.Signature)

			// Lossless: re-marshalling the struct must reproduce the stored
			// bytes exactly, which is what the verifier depends on.
			again, err := json.Marshal(&ev)
			require.NoError(t, err)
			assert.JSONEq(t, string(raw), string(again))
			assert.Equal(t, string(raw), string(again), "canonical bytes drifted: a legacy signed field was removed or moved")

			assert.True(t, store.VerifyRecord(&ev), "historical record must still verify")
		})
	}
}

func TestLegacyPostureFixtures_SignedExportVerifies(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "e.db"), legacyPostureSigningKey)
	require.NoError(t, err)
	defer store.Close()

	var ndjson bytes.Buffer
	fixtures := loadLegacyPostureFixtures(t)
	for _, raw := range fixtures {
		ndjson.Write(raw)
		ndjson.WriteByte('\n')
	}
	report, err := store.VerifyExport(ndjson.Bytes())
	require.NoError(t, err)
	assert.Equal(t, len(fixtures), report.Valid)
	assert.Zero(t, report.Invalid)
	assert.Zero(t, report.Unsupported)
}

func TestLegacyPostureFixtures_ClassificationAndShape(t *testing.T) {
	fixtures := loadLegacyPostureFixtures(t)
	seen := map[string]bool{}
	for name, raw := range fixtures {
		var ev Evidence
		require.NoError(t, json.Unmarshal(raw, &ev))
		seen[ev.InvocationType] = true
		switch ev.InvocationType {
		case "mode_change":
			assert.Equal(t, ClassOperatorEvent, RecordClassOf(ev.InvocationType), name)
			assert.False(t, IsRequestClass(ev.InvocationType), name)
		case "proxy_shadow_violation":
			assert.Equal(t, ClassProviderAttempt, RecordClassOf(ev.InvocationType), name)
			assert.False(t, IsRequestClass(ev.InvocationType), name)
			assert.True(t, ev.ObservationModeOverride, name)
			assert.NotEmpty(t, ev.ShadowViolations, name)
		default:
			// gateway shadow/log_only and native observation_only records are
			// ordinary request-class records that carried the override flag.
			assert.True(t, IsRequestClass(ev.InvocationType), name)
			assert.True(t, ev.ObservationModeOverride, name)
		}
	}
	for _, want := range []string{"mode_change", "proxy_shadow_violation", "gateway", "manual"} {
		assert.True(t, seen[want], "fixture set must cover %s", want)
	}
}
