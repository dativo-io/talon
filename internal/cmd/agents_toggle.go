package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/policy"
)

// talon agents enable/disable (#268): the config-backed operational on/off
// switch. HOST-LOCAL by design — the command edits the agent's YAML on THIS
// machine (remote administration is out of scope); a running `talon serve`
// picks the change up within its reload interval (#269) or on restart.
// YAML stays the source of truth: the CLI edits config, config drives state.

var agentsEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Enable an agent (config-backed; new work resumes on the next reload)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAgentToggle(cmd, args[0], true)
	},
}

var agentsDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Disable an agent (config-backed kill switch; in-flight work finishes)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAgentToggle(cmd, args[0], false)
	},
}

func init() {
	agentsCmd.AddCommand(agentsEnableCmd)
	agentsCmd.AddCommand(agentsDisableCmd)
}

func runAgentToggle(cmd *cobra.Command, name string, enable bool) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ra, scanIssues, err := locateToggleAgent(ctx, cfg, name)
	if err != nil {
		return err
	}

	verb := "disabled"
	if enable {
		verb = "enabled"
	}
	if ra.Policy.Agent.IsEnabled() == enable {
		fmt.Fprintf(cmd.OutOrStdout(), "agent %q is already %s (no change; config: %s)\n", ra.Name, verb, ra.Path)
		return nil
	}

	original, err := os.ReadFile(ra.Path)
	if err != nil {
		return fmt.Errorf("reading agent config: %w", err)
	}
	edited, err := setAgentEnabledYAML(original, ra.Name, enable)
	if err != nil {
		return fmt.Errorf("could not safely rewrite %s: %w — set agent.enabled manually", ra.Path, err)
	}

	evStore, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("opening evidence store: %w", err)
	}
	defer evStore.Close()

	tenant := ra.TenantID
	if tenant == "" {
		tenant = "default"
	}
	prior := ra.Policy.Agent.IsEnabled()

	// Intent → atomic rename → completion (#268): the signed trail records
	// the operator's decision before AND after the state change; a failed
	// completion record rolls the FILE back so recorded state and actual
	// state can never silently diverge.
	if _, err := recordAgentLifecycle(ctx, evStore, tenant, ra.Name, ra.Path, intentType(enable), prior, enable); err != nil {
		return fmt.Errorf("recording intent evidence: %w (no change was made)", err)
	}
	if err := atomicWriteFile(ra.Path, edited); err != nil {
		return fmt.Errorf("writing agent config: %w", err)
	}
	completionID, err := recordAgentLifecycle(ctx, evStore, tenant, ra.Name, ra.Path, completionType(enable), prior, enable)
	if err != nil {
		// Roll the file back: an unrecorded state change is worse than no
		// change — the operator retries with a working evidence store.
		if restoreErr := atomicWriteFile(ra.Path, original); restoreErr != nil {
			return fmt.Errorf("CRITICAL: completion evidence failed (%v) AND restoring %s failed (%v) — the agent is %s on disk but the change is NOT recorded; fix the evidence store and re-run", err, ra.Path, restoreErr, verb)
		}
		return fmt.Errorf("completion evidence failed: %w — the config change was rolled back; fix the evidence store and re-run", err)
	}

	out := cmd.OutOrStdout()
	was := "enabled"
	if !prior {
		was = "disabled"
	}
	fmt.Fprintf(out, "agent %q %s (was %s)\n", ra.Name, verb, was)
	fmt.Fprintf(out, "config:   %s\n", ra.Path)
	fmt.Fprintf(out, "evidence: %s (signed)\n", completionID)
	fmt.Fprintf(out, "note: a running `talon serve` applies this within its reload interval (agents_reload_interval, default %s), or on restart.\n", config.DefaultAgentsReloadInterval)
	if len(scanIssues) > 0 {
		fmt.Fprintf(out, "warning: %d other config file(s) under the fleet source are invalid — the running fleet keeps last-known-good until they are fixed.\n", len(scanIssues))
	}
	return nil
}

func intentType(enable bool) string {
	if enable {
		return "agent_enable_intent"
	}
	return "agent_disable_intent"
}

func completionType(enable bool) string {
	if enable {
		return "agent_enabled"
	}
	return "agent_disabled"
}

// locateToggleAgent resolves the agent among the VALID files of the fleet
// source. A broken sibling never blocks toggling a valid agent, but a
// never-valid file is a fleet problem addressed by PATH — no identity is
// raw-parsed out of malformed YAML, so it cannot be toggled by name.
func locateToggleAgent(ctx context.Context, cfg *config.Config, name string) (*agentcatalog.CatalogAgent, []agentcatalog.FleetIssue, error) {
	var scan *agentcatalog.ScanResult
	var scanErr error
	if cfg.AgentsDir != "" {
		scan, scanErr = agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
	} else {
		scan, scanErr = agentcatalog.Source{File: cfg.DefaultPolicy}.Scan(ctx)
	}
	// scanErr alone is not terminal: valid agents in scan.Agents stay
	// toggleable even when a sibling file is broken.
	for i := range scan.Agents {
		if scan.Agents[i].Name == name {
			return &scan.Agents[i], scan.Issues, nil
		}
	}
	if scanErr != nil && len(scan.Issues) > 0 {
		return nil, nil, fmt.Errorf("agent %q not found among the valid configs (discovered: %s); %d file(s) are invalid and can only be fixed by path — first: %s: %s",
			name, scanAgentNames(scan), len(scan.Issues), scan.Issues[0].Path, scan.Issues[0].Reason)
	}
	return nil, nil, fmt.Errorf("unknown agent %q: discovered agents: %s", name, scanAgentNames(scan))
}

// setAgentEnabledYAML structurally edits the `agent:` mapping via yaml.Node —
// comments and key order survive (indentation normalizes to two spaces). The
// edit is verified by re-parse before it is ever written.
func setAgentEnabledYAML(doc []byte, agentName string, enable bool) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected document shape")
	}
	agentNode := mapValue(root.Content[0], "agent")
	if agentNode == nil || agentNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("no agent: mapping found")
	}

	value := "false"
	if enable {
		value = "true"
	}
	if v := mapValue(agentNode, "enabled"); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = "!!bool"
		v.Value = value
		v.Style = 0
	} else {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"}
		valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: value}
		// Insert right after the name pair when present, else append.
		insertAt := len(agentNode.Content)
		for i := 0; i+1 < len(agentNode.Content); i += 2 {
			if agentNode.Content[i].Value == "name" {
				insertAt = i + 2
				break
			}
		}
		agentNode.Content = append(agentNode.Content[:insertAt],
			append([]*yaml.Node{keyNode, valNode}, agentNode.Content[insertAt:]...)...)
	}

	out, err := marshalYAMLDoc(&root)
	if err != nil {
		return nil, err
	}
	// Verify before commit: the edited bytes must parse back to the SAME
	// agent with the TARGET state — anchors or unusual layouts abort cleanly.
	var probe policy.Policy
	if err := yaml.Unmarshal(out, &probe); err != nil {
		return nil, fmt.Errorf("verification re-parse failed: %w", err)
	}
	if probe.Agent.Name != agentName {
		return nil, fmt.Errorf("verification failed: edited file declares agent %q, expected %q", probe.Agent.Name, agentName)
	}
	if probe.Agent.IsEnabled() != enable {
		return nil, fmt.Errorf("verification failed: edited file does not carry the target enabled state")
	}
	return out, nil
}

func mapValue(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func marshalYAMLDoc(root *yaml.Node) ([]byte, error) {
	var buf []byte
	w := &yamlBuf{buf: &buf}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}

type yamlBuf struct{ buf *[]byte }

func (b *yamlBuf) Write(p []byte) (int, error) {
	*b.buf = append(*b.buf, p...)
	return len(p), nil
}

// atomicWriteFile writes via temp file + fsync + rename in the same
// directory (atomic on POSIX): the reload loop (#269) sees old bytes or new
// bytes, never a torn file. The original file's mode is preserved.
func atomicWriteFile(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".talon-agent-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, info.Mode()); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// recordAgentLifecycle writes one signed operational record for an
// enable/disable step, attributed to the AGENT's tenant so it appears in
// that tenant's audit trail.
func recordAgentLifecycle(ctx context.Context, store *evidence.Store, tenantID, agentName, path, invocationType string, prior, target bool) (string, error) {
	id := "al_" + uuid.New().String()[:12]
	ev := &evidence.Evidence{
		ID:              id,
		CorrelationID:   id,
		Timestamp:       time.Now().UTC(),
		TenantID:        tenantID,
		AgentID:         agentName,
		InvocationType:  invocationType,
		RequestSourceID: operatorID(),
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  invocationType,
			Reasons: []string{
				fmt.Sprintf("enabled: %t -> %t", prior, target),
				"config: " + path,
			},
		},
	}
	if err := store.Store(ctx, ev); err != nil {
		return "", err
	}
	return id, nil
}

// operatorID names the operator in lifecycle evidence: TALON_OPERATOR wins,
// then the OS user, then a generic marker.
func operatorID() string {
	if op := os.Getenv("TALON_OPERATOR"); op != "" {
		return op
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "cli"
}
