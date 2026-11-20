package effective

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/runtimestatus"
	"github.com/dativo-io/talon/internal/secrets"
)

// loadedBy makes p report the use case with the current agent policy digest
// and the current gateway config digest, so a process of the gateway role
// that reports it "serves" the use case.
func loadedBy(t *testing.T, k *keyed, p runtimestatus.Process) runtimestatus.Process {
	t.Helper()
	first, err := Build(context.Background(), k.inputs())
	require.NoError(t, err)
	p.Catalog.Agents = []runtimestatus.Agent{{Name: uc, PolicyDigest: first.CurrentFiles.PolicyDigest}}
	p.GatewayConfig = &runtimestatus.ConfigRef{Digest: first.CurrentFiles.GatewayConfig.Digest}
	return p
}

// neverCurrent asserts the invariant for one report: the LLM gateway record
// is not attributed to the credential stored now, and the next step is not
// "nothing to do".
func neverCurrent(t *testing.T, r *Report, when string) TrafficObservation {
	t.Helper()
	g := observation(t, r, BoundaryLLMGateway)
	assert.NotEqual(t, CredentialCurrent, g.Credential, "%s: a request made with an earlier key is reported as the current credential (%s)", when, g.CredentialNote)
	assert.NotEqual(t, NextNone, r.Verification.Next.Code, "%s: %s", when, r.Verification.Next.Text)
	return g
}

// #567 review (independent pass). Evidence records neither the key a request
// presented nor the process that served it. The attribution to the
// credential stored now is therefore sound only while the runtime records
// still say which processes can have served the request. Every case below
// is a request made with an EARLIER key that an earlier version of the rule
// reported as the current credential.
func TestVerification_AnEarlierKeyIsNeverReportedAsCurrent(t *testing.T) {
	ctx := context.Background()

	t.Run("the serving process's record is gone or ended before the request; another process covers the moment", func(t *testing.T) {
		t1 := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Second)
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		gateway1 := process("gateway-1", w1.Add(time.Second), w1.Add(time.Second), true) // read key A when it started
		w2 := k.replace("key-B", t1.Add(time.Hour))                                      // gateway-1 is not restarted
		// Another Talon process of the installation, MCP proxy role only,
		// starts after the replacement and keeps running.
		mcp := process("mcp-1", w2.Add(time.Minute), w2.Add(time.Minute), true)
		mcp.Roles = []string{runtimestatus.RoleMCPProxy}
		ts := w2.Add(10 * time.Minute)
		k.request("req-with-key-A", ts) // the application still presents key A; gateway-1 accepts it

		r, err := Build(ctx, withRuntime(k.inputs(), gateway1, mcp))
		require.NoError(t, err)
		assert.Equal(t, CredentialNotEstablished, neverCurrent(t, r, "both processes on record").Credential)

		// gateway-1 is restarted: gateway-2 holds key B. The application
		// (key A) now gets 401, which leaves no record: the request above
		// stays the newest.
		at := ts.Add(10 * time.Minute)
		gateway2 := loadedBy(t, k, process("gateway-2", at.Add(time.Second), at.Add(time.Second), true))

		// Its record was removed (records that are no longer written are
		// kept for runtimestatus.Retention). The MCP proxy process covers
		// the moment, but it serves no LLM gateway request.
		r, err = Build(ctx, withRuntime(k.inputs(), mcp, gateway2))
		require.NoError(t, err)
		g := neverCurrent(t, r, "the serving process's record was removed")
		assert.Equal(t, CredentialNotEstablished, g.Credential)
		assert.Contains(t, g.CredentialNote, "no runtime record covers that moment for a process that serves the LLM gateway")

		// It was killed: no stop record, and its last report was three
		// seconds before the request. A process that stopped reporting may
		// have served for a while longer.
		killed := gateway1
		killed.Assessed, killed.WrittenAt = runtimestatus.Offline, ts.Add(-3*time.Second)
		r, err = Build(ctx, withRuntime(k.inputs(), killed, mcp, gateway2))
		require.NoError(t, err)
		g = neverCurrent(t, r, "the serving process was killed after its last report")
		assert.Equal(t, CredentialNotEstablished, g.Credential)
		assert.Contains(t, g.CredentialNote, "gateway-1")

		// A process that reports late (stale) may still be serving with the
		// key it holds: the running processes do not "hold the current one".
		late := gateway1
		late.Assessed = runtimestatus.Stale
		r, err = Build(ctx, withRuntime(k.inputs(), late, gateway2))
		require.NoError(t, err)
		assert.NotEqual(t, RuntimeHoldsCurrent, r.Verification.Credential.Runtime)

		// Beyond what the runtime records cover, the processes still listed
		// are not all that can have served the request: a gateway process
		// that started after the write and "covers" the moment proves
		// nothing about a record older than the retention.
		gateway3 := loadedBy(t, k, process("gateway-3", w2.Add(time.Minute), w2.Add(time.Minute), true))
		old := withRuntime(k.inputs(), gateway3)
		old.Runtime.ReadAt = time.Now().UTC()
		r, err = Build(ctx, old)
		require.NoError(t, err)
		g = neverCurrent(t, r, "the record is older than the runtime records are kept")
		assert.Contains(t, g.CredentialNote, "may be gone")
	})

	t.Run("the vault file was recreated under a running process", func(t *testing.T) {
		t1 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Second)
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		serve1 := loadedBy(t, k, process("serve1", w1.Add(time.Second), w1.Add(time.Second), true)) // holds key A in memory
		require.NoError(t, os.Remove(k.vault))
		// A new vault file: created, then the key stored. It records
		// versions from its creation, so its one value reads as the only
		// one ever stored under the name.
		k.store(func(*secrets.SecretStore) {})
		created := t1.Add(59 * time.Minute)
		k.exec(`UPDATE vault_meta SET value = ? WHERE key = 'value_versions_since'`, created.Format(time.RFC3339Nano))
		w2 := k.issue("key-B", t1.Add(time.Hour))
		k.request("req-with-key-A", w2.Add(time.Minute)) // serve1 still accepts key A

		r, err := Build(ctx, withRuntime(k.inputs(), serve1))
		require.NoError(t, err)
		require.Equal(t, HistoryOnlyValue, r.Verification.Credential.History, "the new vault file knows one value only")
		g := neverCurrent(t, r, "vault recreated, process not restarted")
		assert.Equal(t, CredentialNotEstablished, g.Credential)
		assert.Contains(t, g.CredentialNote, "had started before this vault file was created")
		assert.NotEqual(t, RuntimeHoldsCurrent, r.Verification.Credential.Runtime, "a process older than the vault file may hold a key that never was in it")
		assert.Equal(t, NextRestartRuntime, r.Verification.Next.Code)

		// A process started after the new vault file exists can hold only
		// what is in it: its request is the current credential's.
		restart := w2.Add(2 * time.Minute)
		serve2 := loadedBy(t, k, process("serve2", restart, restart, true))
		k.request("req-with-key-B", restart.Add(time.Minute))
		r, err = Build(ctx, withRuntime(k.inputs(), serve2))
		require.NoError(t, err)
		assert.Equal(t, CredentialCurrent, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Equal(t, NextNone, r.Verification.Next.Code)
	})

	t.Run("the agent file was pointed at another secret by hand", func(t *testing.T) {
		t1 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Second)
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		serve1 := process("serve1", w1.Add(time.Second), w1.Add(time.Second), true)
		// The operator stores a replacement under a NEW name. That name has
		// only ever held one value.
		const v2 = "hr-analytics-assistant-talon-key-v2"
		k.store(func(s *secrets.SecretStore) { require.NoError(t, s.Set(ctx, v2, []byte("key-B"), secrets.ACL{})) })
		k.exec(`UPDATE secret_value_versions SET written_at = ? WHERE name = ?`, t1.Add(30*time.Minute).UTC().Format("2006-01-02T15:04:05.000Z"), v2)
		k.request("req-with-key-A", t1.Add(time.Hour)) // the binding is still the old name
		// The operator switches the binding in the agent file.
		file := filepath.Join(k.agents, uc, "agent.talon.yaml")
		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(file, []byte(strings.Replace(string(raw), "secret_name: "+keySecret, "secret_name: "+v2, 1)), 0o600))

		r, err := Build(ctx, withRuntime(k.inputs(), loadedBy(t, k, serve1)))
		require.NoError(t, err)
		require.Equal(t, v2, r.Verification.Credential.SecretName)
		g := neverCurrent(t, r, "after re-binding")
		assert.Equal(t, CredentialUnknown, g.Credential, "the record does not say which secret authenticated it")
		assert.Contains(t, g.CredentialNote, "which secret the use case was bound to then is not recorded")
		assert.NotEqual(t, ReadingTrafficMatches, r.Verification.Reading.Code)
	})
}

// #567 review (independent pass). "Nothing to do" needs more than a verified
// record and a Talon process that read the file: a process that SERVES the
// use case's requests, and credential facts that do not contradict it.
func TestVerification_NothingToDoNeedsAServingProcessAndTheCredentialFacts(t *testing.T) {
	ctx := context.Background()
	t1 := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Second)

	t.Run("only a process of another role runs: the gateway is down", func(t *testing.T) {
		k := newKeyed(t)
		w := k.issue("key-A", t1)
		k.request("req-1", w.Add(time.Minute))
		first, err := Build(ctx, k.inputs())
		require.NoError(t, err)
		px := runningRecord("px", []string{runtimestatus.RoleMCPProxy}, first.CurrentFiles.PolicyDigest, "", first.CurrentFiles.ProxyConfig.Digest)
		px.StartedAt = t1.Add(time.Hour)
		r, err := Build(ctx, withRuntime(k.inputs(), px))
		require.NoError(t, err)
		require.Equal(t, runtimestatus.LoadedMatchesFile, r.Loaded.State, "a Talon process has read the file")
		assert.Equal(t, runtimestatus.RoleGateway, r.Verification.Serving.Role)
		assert.NotEqual(t, runtimestatus.LoadedMatchesFile, r.Verification.Serving.State, "but none that serves the LLM gateway")
		assert.Equal(t, NextStartRuntime, r.Verification.Next.Code)
		assert.Contains(t, r.Verification.Next.Text, "none that serves the LLM gateway")

		// With a gateway process that loaded it, it is served.
		gw := loadedBy(t, k, process("gw", w.Add(time.Second), w.Add(time.Second), true))
		r, err = Build(ctx, withRuntime(k.inputs(), gw, px))
		require.NoError(t, err)
		assert.Equal(t, runtimestatus.LoadedMatchesFile, r.Verification.Serving.State)
		assert.Equal(t, NextNone, r.Verification.Next.Code)
	})

	t.Run("the newest record is a workload identity's; the running process holds an earlier key", func(t *testing.T) {
		k := newKeyed(t)
		w1 := k.issue("key-A", t1)
		serve1 := loadedBy(t, k, process("serve1", w1.Add(time.Second), w1.Add(time.Second), true))
		w2 := k.replace("key-B", t1.Add(time.Hour)) // serve1 is not restarted
		agent, eff := k.currentDigests(t)
		k.put(t, "delegated", "gateway", w2.Add(time.Minute), func(ev *evidence.Evidence) {
			ev.WorkloadIdentity = &evidence.WorkloadIdentity{Status: "verified", Runtime: "openshell", AuthMethod: "hop_assertion"}
			ev.PolicyDecision.PolicyDigests = &evidence.PolicyDigests{Agent: agent, Effective: eff}
		})
		r, err := Build(ctx, withRuntime(k.inputs(), serve1))
		require.NoError(t, err)
		require.Equal(t, ReadingTrafficMatches, r.Verification.Reading.Code)
		require.Equal(t, RuntimePredatesCurrent, r.Verification.Credential.Runtime)
		assert.Equal(t, NextRestartRuntime, r.Verification.Next.Code, r.Verification.Next.Text)
	})

	t.Run("a vault without a version record: said, not guessed", func(t *testing.T) {
		k := newKeyed(t)
		w := k.issue("key-A", t1)
		k.request("req-1", w.Add(time.Minute))
		k.asOlderVault(t1.Add(time.Hour))
		serve := loadedBy(t, k, process("serve1", t1.Add(2*time.Hour), t1.Add(2*time.Hour), true))
		r, err := Build(ctx, withRuntime(k.inputs(), serve))
		require.NoError(t, err)
		assert.Equal(t, CredentialUnknown, observation(t, r, BoundaryLLMGateway).Credential)
		assert.Contains(t, r.Verification.Reading.Text, "which credential it was authenticated with is not established")
		assert.Equal(t, NextNone, r.Verification.Next.Code)
		assert.Contains(t, r.Verification.Next.Text, "Not established here: which key that request used", "the step states what it does not rest on")
	})

	t.Run("the newest authenticated record decides, whichever boundary recorded it", func(t *testing.T) {
		older, newer := t1, t1.Add(time.Hour)
		v := &Verification{Configured: "enabled", Credential: &Credential{State: CredentialKnown, Since: &older}, Traffic: []TrafficObservation{
			{Boundary: BoundaryLLMGateway, State: TrafficObserved, IdentityProven: true, Timestamp: &older, EvidenceID: "gw_1", Verification: "valid", Credential: CredentialCurrent, Policy: PolicyMatchesCurrent},
			{Boundary: BoundaryActionGateway, State: TrafficObserved, IdentityProven: true, Timestamp: &newer, EvidenceID: "act_1", Verification: "valid", Credential: CredentialNotEstablished, CredentialNote: "served by a process that was already running", Policy: PolicyMatchesCurrent},
		}}
		got := readingOf(v, runtimestatus.Loaded{State: runtimestatus.LoadedMatchesFile})
		assert.Equal(t, ReadingTrafficCredentialUnproven, got.Code, "an older record with the current credential does not outvote a newer one without it")
		assert.Contains(t, got.Text, "act_1")
	})
}
