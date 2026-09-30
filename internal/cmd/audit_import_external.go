package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/openshell"
)

var (
	importExternalRuntime string
	importExternalFile    string
	importExternalIssuer  string
	importExternalDryRun  bool
)

// auditImportExternalCmd imports containment facts an external runtime
// enforced on its own (#482 VERIFY): today, OpenShell OCSF network/HTTP
// denials. Each denial becomes ONE signed external_runtime_event record
// attributed through the same agent binding the delegated model path uses
// (agent.workload_identity.bindings), labelled external_asserted /
// receipt unverified. Talon never claims it saw or verified the block.
var auditImportExternalCmd = &cobra.Command{
	Use:   "import-external",
	Short: "Import external-runtime containment denials (OpenShell OCSF export) as signed external_runtime_event records",
	Long: `Import containment facts an external runtime enforced without Talon.

Supported runtime: openshell — an OCSF JSONL export (/var/log/openshell-ocsf-*.log,
or 'openshell logs <sandbox> --source sandbox' output) whose Network Activity
(4001) / HTTP Activity (4002) DENIED events become signed Talon records.

Attribution uses the sandbox id in the event (container.uid) resolved through
agent.workload_identity.bindings — the same trusted binding the delegated model
path uses. Events for unbound sandboxes are reported and skipped.

Every imported record says: enforcement=external_asserted,
mechanism=verify, receipt.verified=false. A valid Talon
signature on it proves Talon recorded the import, not that OpenShell enforced.`,
	RunE: runAuditImportExternal,
}

func init() {
	auditImportExternalCmd.Flags().StringVar(&importExternalRuntime, "runtime", "openshell", "External runtime type (openshell)")
	auditImportExternalCmd.Flags().StringVar(&importExternalFile, "file", "", "OCSF JSONL export to import (required)")
	auditImportExternalCmd.Flags().StringVar(&importExternalIssuer, "runtime-id", "", "Stable runtime identity recorded in evidence (default: gateway.openshell.identity.issuer from --gateway-config, else 'openshell')")
	auditImportExternalCmd.Flags().BoolVar(&importExternalDryRun, "dry-run", false, "Parse and attribute without writing records")
	auditCmd.AddCommand(auditImportExternalCmd)
}

func runAuditImportExternal(cmd *cobra.Command, _ []string) error {
	if importExternalRuntime != openshell.RuntimeType {
		return fmt.Errorf("unsupported runtime %q (supported: openshell)", importExternalRuntime)
	}
	if importExternalFile == "" {
		return fmt.Errorf("--file is required")
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	bindings, err := loadWorkloadBindings(ctx, cfg)
	if err != nil {
		return err
	}
	f, err := os.Open(importExternalFile) //nolint:gosec // operator-supplied export path
	if err != nil {
		return fmt.Errorf("opening export: %w", err)
	}
	defer f.Close()
	events, skipped, err := openshell.ReadOCSFDenials(f, 10000)
	if err != nil {
		return fmt.Errorf("reading export: %w", err)
	}
	issuer := importExternalIssuer
	if issuer == "" {
		issuer = openshell.RuntimeType
	}
	var store *evidence.Store
	if !importExternalDryRun {
		store, err = evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
		if err != nil {
			return fmt.Errorf("opening evidence store: %w", err)
		}
		defer store.Close()
	}
	written, unbound := 0, 0
	out := cmd.OutOrStdout()
	for _, ev := range events {
		agent, ok := bindings[openshell.RuntimeType+"\x00"+"spiffe://openshell/sandbox/"+ev.SandboxID]
		if !ok || ev.SandboxID == "" {
			unbound++
			fmt.Fprintf(out, "  skip  sandbox=%q dst=%s:%d (no agent binds this sandbox)\n", ev.SandboxID, ev.DstHost, ev.DstPort)
			continue
		}
		rec := openshell.ContainmentRecord(ev, agent, issuer, operatorID(), time.Now())
		if importExternalDryRun {
			fmt.Fprintf(out, "  would-import  agent=%s tenant=%s dst=%s:%d process=%s\n", agent.Name, agent.TenantID, ev.DstHost, ev.DstPort, ev.ProcessName)
			continue
		}
		if err := store.Store(ctx, rec); err != nil {
			return fmt.Errorf("storing record: %w", err)
		}
		written++
		fmt.Fprintf(out, "  imported  %s  agent=%s dst=%s:%d  enforcement=external_asserted receipt=unverified\n", rec.ID, agent.Name, ev.DstHost, ev.DstPort)
	}
	fmt.Fprintf(out, "External runtime import (%s): %d denial(s) in export, %d imported, %d unbound, %d non-denial line(s) skipped\n",
		importExternalRuntime, len(events), written, unbound, skipped)
	return nil
}

// loadWorkloadBindings indexes (runtime, subject) → agent from the SAME
// fleet source serve uses (agents_dir or the default policy file), so an
// import attributes exactly as the live delegated path would.
func loadWorkloadBindings(ctx context.Context, cfg *config.Config) (map[string]openshell.ImportedAgent, error) {
	var scan *agentcatalog.ScanResult
	var err error
	if cfg.AgentsDir != "" {
		scan, err = agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
	} else {
		scan, err = agentcatalog.Source{File: cfg.DefaultPolicy}.Scan(ctx)
	}
	if err != nil && (scan == nil || len(scan.Agents) == 0) {
		return nil, fmt.Errorf("loading agents: %w", err)
	}
	out := make(map[string]openshell.ImportedAgent)
	for i := range scan.Agents {
		a := &scan.Agents[i]
		if a.Policy == nil || a.Policy.Agent.WorkloadIdentity == nil {
			continue
		}
		team := ""
		if a.Policy.Metadata != nil {
			team = a.Policy.Metadata.Team
		}
		for _, b := range a.Policy.Agent.WorkloadIdentity.Bindings {
			key := strings.TrimSpace(b.Runtime) + "\x00" + strings.TrimSpace(b.Subject)
			if prev, dup := out[key]; dup && prev.Name != a.Name {
				return nil, fmt.Errorf("agents %q and %q both bind %s subject %q", prev.Name, a.Name, b.Runtime, b.Subject)
			}
			out[key] = openshell.ImportedAgent{Name: a.Name, TenantID: a.Policy.Agent.TenantID, Team: team}
		}
	}
	return out, nil
}
