package effective

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

const actionAgentYAML = `agent:
  name: refund-bot
  version: "1.0.0"
actions:
  definitions:
    create_refund_request:
      description: "Refund a customer payment"
      input_schema:
        type: object
        additionalProperties: false
        required: [ticket_id, amount, currency]
        properties:
          ticket_id: {type: string}
          amount: {type: number, minimum: 0}
          currency: {type: string, enum: [EUR]}
      review:
        fields: [ticket_id, amount, currency]
      destination: {type: http, url: "http://127.0.0.1:9/refunds", method: POST, success: {status_codes: [201]}}
policies:
  cost_limits:
    monthly: 20
  approvals:
    expires_after: 30m
    argument_rules:
      refund-needs-approval: {actions: [create_refund_request], argument: amount, type: decimal, operator: gt, value: "50.00", effect: require_approval, approver_groups: [support-leads]}
`

func actionGateway(forbidden string) string {
	return "gateway:\n  enabled: true\n  providers:\n    openai:\n      enabled: true\n      base_url: \"https://api.openai.com\"\n      secret_name: openai-api-key\n" +
		"  organization_policy:\n    constraints:\n      forbidden_tools: [" + forbidden + "]\n"
}

type actionConfigFixture struct {
	t      *testing.T
	in     Inputs
	gwPath string
	agent  string // the agent's policy digest
}

func newActionConfigFixture(t *testing.T) *actionConfigFixture {
	t.Helper()
	dir := t.TempDir()
	agents := filepath.Join(dir, "agents")
	require.NoError(t, os.MkdirAll(filepath.Join(agents, "refund-bot"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(agents, "refund-bot", "agent.talon.yaml"), []byte(actionAgentYAML), 0o600))
	f := &actionConfigFixture{t: t, gwPath: filepath.Join(dir, "talon.config.yaml")}
	f.in = Inputs{AgentsDir: agents, GatewayConfig: f.gwPath, Now: time.Now().UTC()}
	scan, err := fleetview.Scan(context.Background(), agents, "")
	require.NoError(t, err)
	require.Len(t, scan.Agents, 1)
	f.agent = scan.Agents[0].PolicyDigest
	return f
}

func (f *actionConfigFixture) write(content string) {
	f.t.Helper()
	// Replace the file as an editor or a deploy does: write a sibling, rename.
	tmp := f.gwPath + ".new"
	require.NoError(f.t, os.WriteFile(tmp, []byte(content), 0o600))
	require.NoError(f.t, os.Rename(tmp, f.gwPath))
}

// policyOf is the action policy digest the files compile to when nothing
// else touches them.
func (f *actionConfigFixture) policyOf(content string) string {
	f.t.Helper()
	f.write(content)
	in := f.in
	in.Runtime = nil
	cfg := BuildActionConfigs(context.Background(), in).For("default", "refund-bot")
	require.Empty(f.t, cfg.Unavailable)
	require.NotNil(f.t, cfg.Policy)
	return cfg.Policy.Digest
}

// runningWith is a running `talon serve` that loaded the agent file and a
// gateway config with these bytes.
func (f *actionConfigFixture) runningWith(gatewayBytes string) *runtimestatus.View {
	sum := sha256.Sum256([]byte(gatewayBytes))
	rec := runtimestatus.Record{
		InstanceID: "serve1", Roles: []string{runtimestatus.RoleGateway},
		Catalog:       &runtimestatus.Catalog{Agents: []runtimestatus.Agent{{Name: "refund-bot", PolicyDigest: f.agent}}},
		GatewayConfig: &runtimestatus.ConfigRef{Digest: hex.EncodeToString(sum[:])},
	}
	return &runtimestatus.View{Processes: []runtimestatus.Process{{Record: rec, Assessed: runtimestatus.Running, Current: true}}}
}

// #565 review, finding 5. "Confirmed by the runtime" compares the digest of
// the gateway config with the digest a running process reports. The policy
// that is called confirmed must be compiled from the very bytes that were
// digested: when the file is replaced between the read that compiles and a
// second read that digests, a policy compiled from the OLD bytes would be
// confirmed against a process that runs the NEW ones.
func TestBuildActionConfigs_ConfirmationBindsTheBytesItCompiled(t *testing.T) {
	ctx := context.Background()
	f := newActionConfigFixture(t)
	oldBytes, newBytes := actionGateway(`"delete_*"`), actionGateway(`"delete_*", "export_*"`)
	oldPolicy, newPolicy := f.policyOf(oldBytes), f.policyOf(newBytes)
	require.NotEqual(t, oldPolicy, newPolicy, "the two company policies compile to different action policies")

	// The running process loaded the NEW bytes. The reader starts on the
	// OLD file, which is replaced right after it was read for compilation.
	f.in.Runtime, f.in.RuntimeReadable = f.runningWith(newBytes), true
	f.write(oldBytes)
	afterGatewayConfigRead = func() { f.write(newBytes) }
	t.Cleanup(func() { afterGatewayConfigRead = nil })
	cfg := BuildActionConfigs(ctx, f.in).For("default", "refund-bot")
	require.Empty(t, cfg.Unavailable)
	require.Equal(t, oldPolicy, cfg.Policy.Digest, "the policy was compiled from the bytes that were read first")
	require.Equal(t, action.CurrentFiles, cfg.Basis, "a policy compiled from other bytes than the process loaded is never 'confirmed by the runtime'")

	// Nothing changes underneath: the same files are confirmed.
	afterGatewayConfigRead = nil
	cfg = BuildActionConfigs(ctx, f.in).For("default", "refund-bot")
	require.Equal(t, newPolicy, cfg.Policy.Digest)
	require.Equal(t, action.CurrentFilesConfirmed, cfg.Basis)
}

// The same invariant while the file is being replaced concurrently: every
// answer pairs a compiled policy with the proof for the bytes that policy
// was compiled from. A policy compiled from the old bytes is never called
// confirmed against the process that runs the new ones, and the other way
// round.
func TestBuildActionConfigs_ConfirmationUnderConcurrentFileChanges(t *testing.T) {
	ctx := context.Background()
	f := newActionConfigFixture(t)
	oldBytes, newBytes := actionGateway(`"delete_*"`), actionGateway(`"delete_*", "export_*"`)
	oldPolicy, newPolicy := f.policyOf(oldBytes), f.policyOf(newBytes)
	f.in.Runtime, f.in.RuntimeReadable = f.runningWith(newBytes), true

	start, stop, flipped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(flipped)
		<-start
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			content := oldBytes
			if i%2 == 0 {
				content = newBytes
			}
			tmp := f.gwPath + ".flip"
			if os.WriteFile(tmp, []byte(content), 0o600) != nil || os.Rename(tmp, f.gwPath) != nil {
				return
			}
		}
	}()
	close(start)
	confirmed, unconfirmed := 0, 0
	for i := 0; i < 150; i++ {
		cfg := BuildActionConfigs(ctx, f.in).For("default", "refund-bot")
		require.Empty(t, cfg.Unavailable)
		switch cfg.Policy.Digest {
		case newPolicy:
			require.Equal(t, action.CurrentFilesConfirmed, cfg.Basis, "compiled from the bytes the process loaded")
			confirmed++
		case oldPolicy:
			require.Equal(t, action.CurrentFiles, cfg.Basis, "compiled from other bytes than the process loaded: never confirmed")
			unconfirmed++
		default:
			t.Fatalf("a policy that neither version of the file compiles to: %s", cfg.Policy.Digest)
		}
	}
	close(stop)
	<-flipped
	t.Logf("%d answers confirmed, %d not confirmed", confirmed, unconfirmed)
}
