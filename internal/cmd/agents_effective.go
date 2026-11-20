package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/action"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

var (
	agentsShowEffective   bool
	agentsShowProxyConfig string
)

func init() {
	agentsShowCmd.Flags().BoolVar(&agentsShowEffective, "effective", false, "Show the effective policy: current files, whether a running process loaded them, the compiled policy with rule provenance, the MCP proxy's tool decisions and the last recorded decision (#305)")
	agentsShowCmd.Flags().StringVar(&agentsShowProxyConfig, "proxy-config", "", "MCP proxy config to include in --effective (the file talon serve --proxy-config uses)")
}

// runAgentShowEffective prints effective.Build for one use case: the same
// report the console serves at /console/v1/use-cases/{name}/effective-policy.
// It reads the files, the installation's runtime records and the evidence
// store read-only; it never contacts a server.
func runAgentShowEffective(ctx context.Context, cmd *cobra.Command, cfg *config.Config, name string) error {
	in := effective.Inputs{
		AgentsDir: cfg.AgentsDir, DefaultPolicy: cfg.DefaultPolicy,
		GatewayConfig: offlineGatewayConfigPath(), ProxyConfig: strings.TrimSpace(agentsShowProxyConfig),
		Name: name, Tenant: agentsQueueTenant, Now: time.Now().UTC(),
		// Vault METADATA only (read-only, no key): when the use case's
		// credential was last written.
		SecretsDB: cfg.SecretsDBPath(),
	}
	if _, err := os.Stat(cfg.EvidenceDBPath()); err == nil {
		store, err := evidence.OpenReadOnly(cfg.EvidenceDBPath(), cfg.SigningKey)
		if err != nil {
			return fmt.Errorf("opening evidence store read-only: %w", err)
		}
		defer store.Close()
		in.Evidence = store
	}
	view := runtimestatus.NewReader().Assess(cfg.DataDir, runtimestatus.Fingerprint(cfg.SigningKey), nil, in.Now)
	in.Runtime, in.RuntimeReadable = &view, view.Err == ""
	r, err := effective.Build(ctx, in)
	if err != nil {
		return err
	}
	if agentsQueueJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(r)
	}
	renderEffective(cmd.OutOrStdout(), r)
	return nil
}

// offlineGatewayConfigPath is the gateway config the offline views read:
// $TALON_GATEWAY_CONFIG or ./talon.config.yaml.
func offlineGatewayConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("TALON_GATEWAY_CONFIG")); p != "" {
		return p
	}
	return "talon.config.yaml"
}

func renderEffective(w io.Writer, r *effective.Report) {
	fmt.Fprintf(w, "AI use case %s (tenant %s)\n\n", r.UseCase, r.TenantID)
	fmt.Fprintln(w, "1. Current files")
	fmt.Fprintf(w, "   agent file:     %s (policy digest %s)\n", r.CurrentFiles.AgentFile, short(r.CurrentFiles.PolicyDigest))
	printFile(w, "gateway config", r.CurrentFiles.GatewayConfig)
	printFile(w, "MCP proxy config", r.CurrentFiles.ProxyConfig)
	fmt.Fprintln(w, "\n2. Loaded by a running process")
	fmt.Fprintf(w, "   %s — %s\n", r.Loaded.State, r.Loaded.Reason)
	fmt.Fprintln(w, "\n3. Effective policy")
	fmt.Fprintf(w, "   gateway boundary: %s — %s\n", r.Effective.Proof.State, r.Effective.Proof.Reason)
	fmt.Fprintf(w, "   basis: %s\n", r.Effective.Basis)
	renderEffectiveRules(w, r, "   ")
	if b := r.MCPBoundary; b != nil {
		fmt.Fprintf(w, "\n   MCP proxy %s (%s)\n", b.Proxy, b.Scope)
		fmt.Fprintf(w, "   MCP boundary: %s — %s\n", b.Proof.State, b.Proof.Reason)
		if b.Error != "" {
			fmt.Fprintf(w, "   unavailable: %s\n", b.Error)
		}
		for _, d := range b.Tools {
			verdict := "allowed"
			if !d.Allowed {
				verdict = "denied before dispatch at " + d.Stage
				if d.Matched != "" {
					verdict += " (" + d.Matched + ")"
				}
			}
			fmt.Fprintf(w, "   tool %-24s %s\n", d.Tool, verdict)
		}
	}
	renderActionBoundary(w, r.ActionBoundary)
	fmt.Fprintln(w, "\n4. Last recorded decision (the newest request decision recorded for this use case at any boundary)")
	if d := r.LastDecision; d != nil {
		if d.Verification != "valid" {
			fmt.Fprintf(w, "   %s: SIGNATURE INVALID — changed after signing; not authenticated\n", d.EvidenceID)
		}
		fmt.Fprintf(w, "   %s at %s: %s, dispatch %s (%s), signature %s\n", d.EvidenceID, d.Timestamp.UTC().Format(time.RFC3339), d.Outcome.Decision, d.Outcome.Dispatch, d.InvocationType, d.Verification)
		if d.SessionID != "" {
			fmt.Fprintf(w, "   session: %s\n", d.SessionID)
		}
		if d.PrimaryCode != "" {
			fmt.Fprintf(w, "   %s: %s\n", d.PrimaryCode, d.PrimaryReason)
		}
		fmt.Fprintf(w, "   recorded agent policy vs current file: %s; recorded effective policy: %s\n", d.AgentFile, d.EffectivePolicy)
		fmt.Fprintf(w, "   %s\n", d.Note)
	} else {
		fmt.Fprintln(w, "   none")
	}
	renderVerification(w, r.Verification)
	for _, n := range r.Notes {
		fmt.Fprintf(w, "\nnote: %s\n", n)
	}
}

// renderCredential prints what is known about the credential the use case
// presents now: observed traffic is attributed against it.
func renderCredential(w io.Writer, c *effective.Credential) {
	if c == nil {
		return
	}
	switch c.State {
	case effective.CredentialKnown:
		fmt.Fprintf(w, "   credential: vault secret %s, current value stored %s; %s\n", c.SecretName, c.Since.UTC().Format(time.RFC3339), c.Note)
	default:
		fmt.Fprintf(w, "   credential: %s — %s\n", c.State, c.Note)
	}
	if r := c.Registration; r != nil {
		fmt.Fprintf(w, "               registered %s (%s, signature %s)\n", r.At.UTC().Format(time.RFC3339), r.EvidenceID, r.Verification)
	} else {
		fmt.Fprintln(w, "               no 'talon agents add' record for this use case (configured by hand)")
	}
	fmt.Fprintf(w, "               running process: %s — %s\n", c.Runtime, c.RuntimeNote)
}

// renderVerification prints the independent observations of
// effective.Verification: configured state, observed authenticated traffic
// per boundary with its policy comparison, the one-line reading and what is
// not established. The wording is the projection's; nothing is decided here.
func renderVerification(w io.Writer, v *effective.Verification) {
	fmt.Fprintln(w, "\n5. Connection and verification")
	if v == nil {
		fmt.Fprintln(w, "   not available")
		return
	}
	fmt.Fprintf(w, "   %s\n", v.Reading.Text)
	fmt.Fprintf(w, "   configured: %s\n", v.Configured)
	renderCredential(w, v.Credential)
	for i := range v.Traffic {
		o := &v.Traffic[i]
		switch o.State {
		case effective.TrafficObserved:
			observed := "observed"
			if !o.IdentityProven {
				observed = "observed, caller's identity not established,"
			}
			line := fmt.Sprintf("%s %s (%s", observed, o.Timestamp.UTC().Format(time.RFC3339), o.EvidenceID)
			if o.Event != "" {
				line += ", " + o.Event
			}
			if o.SessionID != "" {
				line += ", session " + o.SessionID
			}
			line += ")"
			if o.Outcome != nil {
				line += fmt.Sprintf(": Talon %s, dispatch %s", o.Outcome.Decision, o.Outcome.Dispatch)
			}
			fmt.Fprintf(w, "   %-15s %s\n", o.Boundary+":", line)
			fmt.Fprintf(w, "   %-15s signature %s; policy %s — %s\n", "", o.Verification, o.Policy, o.PolicyNote)
			fmt.Fprintf(w, "   %-15s identity: %s\n", "", o.Identity)
			if o.Credential != "" {
				fmt.Fprintf(w, "   %-15s credential: %s — %s\n", "", o.Credential, o.CredentialNote)
			}
			if d := o.LastDispatch; d != nil {
				fmt.Fprintf(w, "   %-15s last dispatch %s (%s): dispatch %s, destination %s, signature %s\n", "", d.Timestamp.UTC().Format(time.RFC3339), d.EvidenceID, d.Outcome.Dispatch, d.Outcome.Downstream, d.Verification)
			}
		case effective.TrafficUnavailable:
			fmt.Fprintf(w, "   %-15s unavailable — %s\n", o.Boundary+":", o.Error)
		default:
			fmt.Fprintf(w, "   %-15s no request of this use case recorded\n", o.Boundary+":")
		}
	}
	fmt.Fprintln(w, "   not established by the above:")
	for _, n := range v.NotEstablished {
		fmt.Fprintf(w, "     - %s\n", n)
	}
}

func printFile(w io.Writer, label string, f *effective.File) {
	switch {
	case f == nil:
		fmt.Fprintf(w, "   %-15s not given\n", label+":")
	case f.Error != "":
		fmt.Fprintf(w, "   %-15s %s (unusable: %s)\n", label+":", f.Path, f.Error)
	case !f.Present:
		fmt.Fprintf(w, "   %-15s %s (absent)\n", label+":", f.Path)
	default:
		fmt.Fprintf(w, "   %-15s %s (sha256 %s)\n", label+":", f.Path, short(f.Digest))
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// renderActionBoundary prints the effective action policy: each action's
// baseline verdict (marked when a call's arguments can make it stricter)
// and every rule with the layer that declared it.
func renderActionBoundary(w io.Writer, b *effective.ActionBoundary) {
	if b == nil {
		return
	}
	fmt.Fprintln(w, "\n   Action Gateway")
	fmt.Fprintf(w, "   action boundary: %s — %s\n", b.Proof.State, b.Proof.Reason)
	fmt.Fprintf(w, "   basis: %s\n", b.Basis)
	if b.Error != "" {
		fmt.Fprintf(w, "   unavailable: %s\n", b.Error)
		return
	}
	for i := range b.Actions {
		d := &b.Actions[i]
		verdict := d.Verdict
		if d.VerdictSource != "" {
			verdict += " (" + d.VerdictSource + ")"
		}
		if d.DecisionBasis == action.DecisionByArguments {
			verdict = "BY ARGUMENTS — " + verdict + " by name; a call can be stricter"
		}
		fmt.Fprintf(w, "   action %-22s %s\n", d.Action, verdict)
	}
	for _, r := range b.ApprovalRules {
		fmt.Fprintf(w, "   approval rule %s (%s): %s → require approval (groups: %s)\n", r.ID, r.Source, strings.Join(r.Actions, ", "), strings.Join(r.ApproverGroups, ", "))
	}
	for i := range b.ArgumentRules {
		r := &b.ArgumentRules[i]
		effect := "deny"
		if r.Effect == action.EffectRequireApproval {
			effect = "require approval (groups: " + strings.Join(r.ApproverGroups, ", ") + ")"
		}
		fmt.Fprintf(w, "   argument rule %s (%s): %s when %s [%s] → %s\n", r.ID, r.Source, strings.Join(r.Actions, ", "), r.Condition, r.Type, effect)
	}
	for _, n := range b.Notes {
		fmt.Fprintf(w, "   note: %s\n", n)
	}
}
