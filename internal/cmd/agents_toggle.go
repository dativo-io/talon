package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// toggleTarget is the validated, locked edit target for one enable/disable.
type toggleTarget struct {
	path     string
	original []byte
	edited   []byte
	tenant   string
	prior    bool
	unlock   func()
}

func runAgentToggle(cmd *cobra.Command, name string, enable bool) error {
	ctx := cmd.Context()
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	verb := map[bool]string{true: "enabled", false: "disabled"}[enable]

	// Locate the target's config PATH (unambiguous name) from a first scan.
	located, scanIssues, err := locateToggleAgent(ctx, cfg, name)
	if err != nil {
		return err
	}

	tgt, noop, err := prepareToggle(ctx, cmd, located.Path, name, enable)
	if err != nil || noop {
		return err
	}
	defer tgt.unlock()

	evStore, err := openEvidenceStore()
	if err != nil {
		return fmt.Errorf("opening evidence store: %w", err)
	}
	defer evStore.Close()

	completionID, warn, err := applyToggle(ctx, evStore, tgt, name, verb, enable)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	was := map[bool]string{true: "enabled", false: "disabled"}[tgt.prior]
	fmt.Fprintf(out, "agent %q %s (was %s)\n", name, verb, was)
	fmt.Fprintf(out, "config:   %s\n", tgt.path)
	fmt.Fprintf(out, "evidence: %s (signed)\n", completionID)
	if warn != "" {
		fmt.Fprintf(out, "warning:  %s (the change and its evidence are recorded; verify after any crash)\n", warn)
	}
	fmt.Fprintf(out, "note: a running `talon serve` applies this within its reload interval (agents_reload_interval, default %s), or on restart.\n", config.DefaultAgentsReloadInterval)
	if len(scanIssues) > 0 {
		fmt.Fprintf(out, "warning: %d other config file(s) under the fleet source are invalid — the running fleet keeps last-known-good until they are fixed.\n", len(scanIssues))
	}
	return nil
}

// prepareToggle takes the advisory lock, re-reads and strictly validates the
// EXACT current bytes, derives tenant + prior state from them, and computes
// the edited bytes. Returns noop=true (and prints) when already in the target
// state. The caller owns tgt.unlock on success.
func prepareToggle(ctx context.Context, cmd *cobra.Command, path, name string, enable bool) (toggleTarget, bool, error) {
	// Hold an advisory lock for the whole operation so a concurrent `talon
	// agents` command cannot interleave between the read and the write (#268
	// review). Everything below re-reads and re-validates the EXACT current
	// bytes — the earlier scan only resolved the path and rejected ambiguity.
	unlock, err := lockAgentFile(path)
	if err != nil {
		return toggleTarget{}, false, err
	}
	ok := false
	defer func() {
		if !ok {
			unlock()
		}
	}()

	original, err := os.ReadFile(path)
	if err != nil {
		return toggleTarget{}, false, fmt.Errorf("reading agent config: %w", err)
	}
	pol, err := policy.LoadPolicy(ctx, filepath.Base(path), false, filepath.Dir(path))
	if err != nil {
		return toggleTarget{}, false, fmt.Errorf("agent config %s failed validation, not toggling: %w", path, err)
	}
	if err := policy.ValidateNoUnknownFields(path); err != nil {
		return toggleTarget{}, false, fmt.Errorf("agent config %s has unknown keys, not toggling: %w", path, err)
	}
	if pol.Agent.Name != name {
		return toggleTarget{}, false, fmt.Errorf("agent config %s now declares agent %q, not %q — another process changed it; re-run", path, pol.Agent.Name, name)
	}

	prior := pol.Agent.IsEnabled()
	if prior == enable {
		verb := map[bool]string{true: "enabled", false: "disabled"}[enable]
		fmt.Fprintf(cmd.OutOrStdout(), "agent %q is already %s (no change; config: %s)\n", name, verb, path)
		return toggleTarget{}, true, nil
	}
	edited, err := setAgentEnabledYAML(original, name, enable)
	if err != nil {
		return toggleTarget{}, false, fmt.Errorf("could not safely rewrite %s: %w — set agent.enabled manually", path, err)
	}

	tenant := pol.Agent.TenantID
	if tenant == "" {
		tenant = "default"
	}
	ok = true
	return toggleTarget{path: path, original: original, edited: edited, tenant: tenant, prior: prior, unlock: unlock}, false, nil
}

// applyToggle records intent, atomically replaces the file, and records
// completion under ONE correlation ID. It ALWAYS writes a terminal record that
// matches the on-disk state — completion when the change went live, a
// rolled-back record when it did not — so intent evidence never dangles and
// recorded state and actual state can never silently diverge (#268 / #300
// review round 5, blocker 4). The returned warn string is a non-fatal
// durability caveat (the change and its completion are recorded, but the
// parent-dir fsync did not confirm); it is surfaced to the operator.
func applyToggle(ctx context.Context, evStore *evidence.Store, tgt toggleTarget, name, verb string, enable bool) (completionID, warn string, err error) {
	correlationID := "al_" + uuid.New().String()[:12]
	if _, err := recordAgentLifecycle(ctx, evStore, correlationID, tgt.tenant, name, tgt.path, intentType(enable), tgt.prior, enable); err != nil {
		return "", "", fmt.Errorf("recording intent evidence: %w (no change was made)", err)
	}
	renamed, replaceErr := atomicReplaceFile(tgt.path, tgt.edited, tgt.original)
	if !renamed {
		// Nothing changed on disk. Close the intent with a terminal rolled-back
		// record (state unchanged) so the operation never leaves a dangling
		// intent, then report the failure.
		_, _ = recordAgentLifecycle(ctx, evStore, correlationID, tgt.tenant, name, tgt.path, "agent_toggle_rolled_back", tgt.prior, tgt.prior)
		return "", "", fmt.Errorf("writing agent config: %w (no change was made)", replaceErr)
	}
	// The change is LIVE on disk. A non-nil replaceErr here is a durability
	// warning only — record completion (matching disk) with the caveat; never
	// leave a live change unrecorded.
	var extra []string
	if replaceErr != nil {
		warn = replaceErr.Error()
		extra = append(extra, "durability_warning: "+warn)
	}
	completionID, cerr := recordAgentLifecycle(ctx, evStore, correlationID, tgt.tenant, name, tgt.path, completionType(enable), tgt.prior, enable, extra...)
	if cerr != nil {
		rolledBack, restoreErr := atomicReplaceFile(tgt.path, tgt.original, tgt.edited)
		if !rolledBack {
			return "", "", fmt.Errorf("CRITICAL: completion evidence failed (%v) AND restoring %s failed (%v) — the agent is %s on disk but the change is NOT recorded; fix the evidence store and re-run", cerr, tgt.path, restoreErr, verb)
		}
		_, _ = recordAgentLifecycle(ctx, evStore, correlationID, tgt.tenant, name, tgt.path, "agent_toggle_rolled_back", tgt.prior, tgt.prior)
		return "", "", fmt.Errorf("completion evidence failed: %w — the config change was rolled back; fix the evidence store and re-run", cerr)
	}
	return completionID, warn, nil
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
	// A name involved in a duplicate-name issue is AMBIGUOUS (fail closed):
	// it is not a valid identity and must not be toggled to whichever file
	// sorted first — the operator resolves the conflict by path (#267 review).
	for _, issue := range scan.Issues {
		if issue.Status == agentcatalog.IssueDuplicateName && issue.Reason != "" &&
			strings.Contains(issue.Reason, "\""+name+"\"") {
			return nil, nil, fmt.Errorf("agent %q is ambiguous: multiple config files declare it — %s. Resolve the duplicate by path before toggling; no change was made", name, issue.Reason)
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

// atomicReplaceFile writes data via temp file + fsync + rename in the same
// directory (atomic on POSIX): the reload loop (#269) sees old bytes or new
// bytes, never a torn file. The original file's mode is preserved. Concurrency:
// if expectCurrent is non-nil, the on-disk bytes are re-read immediately before
// the rename and MUST still equal expectCurrent — otherwise another process
// changed the file since our read and we fail rather than clobber that edit
// (#268 review).
//
// It returns renamed=true the instant os.Rename has swapped the new file into
// place — EVEN IF a subsequent durability sync fails (#300 review round 5,
// blocker 4). The caller must branch on renamed, not on err, to record a
// terminal outcome that matches the ACTUAL on-disk state:
//   - renamed=false: nothing changed on disk (prep/recheck/rename failed) — the
//     operation may be aborted safely with no completion.
//   - renamed=true: the change is LIVE — it must be recorded (completion) or
//     explicitly rolled back; a non-nil err alongside is a DURABILITY WARNING
//     (the parent-dir fsync did not confirm), never a signal that nothing
//     changed.
func atomicReplaceFile(path string, data, expectCurrent []byte) (renamed bool, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(path)

	// Prepare the temp file FIRST (write, fsync, chmod) so the target is
	// touched only by the final rename — the concurrency recheck then happens
	// as close to the rename as possible.
	tmp, err := os.CreateTemp(dir, ".talon-agent-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return false, err
	}
	if err := os.Chmod(tmpName, info.Mode()); err != nil {
		cleanup()
		return false, err
	}

	// Recheck the target IMMEDIATELY before the rename: fail rather than
	// clobber a change made since expectCurrent was read. Under the advisory
	// lock this is airtight against other Talon processes; it also narrows
	// the window against an external editor to microseconds.
	if expectCurrent != nil {
		current, err := os.ReadFile(path)
		if err != nil {
			cleanup()
			return false, err
		}
		if !bytes.Equal(current, expectCurrent) {
			cleanup()
			return false, fmt.Errorf("%s was modified by another writer — not overwriting; re-run", path)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return false, err
	}
	// Past this point the change is LIVE (renamed=true). fsync the directory so
	// the rename is durable across a crash, but surface any failure as a
	// durability WARNING alongside renamed=true — never as "nothing changed".
	d, err := os.Open(dir)
	if err != nil {
		return true, fmt.Errorf("rewrote %s but could not open its directory to fsync (change may not survive a crash): %w", path, err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return true, fmt.Errorf("rewrote %s but directory fsync failed (change may not survive a crash): %w", path, syncErr)
	}
	if closeErr != nil {
		return true, fmt.Errorf("rewrote %s but directory close failed: %w", path, closeErr)
	}
	return true, nil
}

// recordAgentLifecycle writes one signed operational record for an
// enable/disable step, attributed to the AGENT's tenant so it appears in that
// tenant's audit trail. correlationID ties the intent, completion, and any
// rollback of one operation together.
func recordAgentLifecycle(ctx context.Context, store *evidence.Store, correlationID, tenantID, agentName, path, invocationType string, prior, target bool, extraReasons ...string) (string, error) {
	id := "al_" + uuid.New().String()[:12]
	reasons := []string{
		fmt.Sprintf("enabled: %t -> %t", prior, target),
		"config: " + path,
	}
	reasons = append(reasons, extraReasons...)
	ev := &evidence.Evidence{
		ID:              id,
		CorrelationID:   correlationID,
		Timestamp:       time.Now().UTC(),
		TenantID:        tenantID,
		AgentID:         agentName,
		InvocationType:  invocationType,
		RequestSourceID: operatorID(),
		PolicyDecision: evidence.PolicyDecision{
			Allowed: true,
			Action:  invocationType,
			Reasons: reasons,
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
