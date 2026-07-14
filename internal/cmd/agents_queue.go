package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agentbridge"
	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/gateway"
	talonsession "github.com/dativo-io/talon/internal/session"
)

// `talon agents` is the operator ATTENTION QUEUE (#270): every discovered agent
// with STATE (configured enabled/stopped) and HEALTH (evaluated), plus COST and
// WHY. It is server-first — the RUNNING gateway is the source of truth — with an
// honestly-labeled offline config view when no Talon server is reachable. The
// health/budget/session math is fleet.Project, the SAME code path the server
// uses, so the CLI and dashboard can never disagree (#270 parity).

var (
	agentsQueueURL    string
	agentsQueueTenant string
	agentsQueueJSON   bool
)

const offlineFleetLabel = "OFFLINE — CONFIG VIEW (no running gateway found; runtime state may differ)"

func init() {
	agentsCmd.Args = cobra.NoArgs
	agentsCmd.RunE = runAgentsList
	bindAgentsQueueFlags(agentsCmd)

	agentsCmd.AddCommand(agentsShowCmd)
	bindAgentsQueueFlags(agentsShowCmd)
}

func bindAgentsQueueFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&agentsQueueURL, "url", "http://localhost:8080", "Talon server URL (explicit value is authoritative — no offline fallback)")
	cmd.Flags().StringVar(&agentsQueueTenant, "tenant", "", "Filter to one tenant (default: all discovered agents)")
	cmd.Flags().BoolVar(&agentsQueueJSON, "json", false, "Emit the typed rows as JSON")
}

var agentsShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show one agent's operational summary (state, health, cost vs caps, signals)",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentShow,
}

// fleetResponse decodes GET /v1/agents/fleet (fleet.AgentRow and
// agentcatalog.FleetIssue are exported, so the CLI decodes the rows directly).
type fleetResponse struct {
	Generation  string                    `json:"generation"`
	Source      string                    `json:"source"`
	Agents      []fleet.AgentRow          `json:"agents"`
	FleetIssues []agentcatalog.FleetIssue `json:"fleet_issues"`
}

func runAgentsList(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	rows, issues, label, err := resolveFleet(ctx, cmd, cfg, agentsQueueTenant)
	if err != nil {
		return err
	}
	if agentsQueueJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"offline": label != "", "agents": rows, "fleet_issues": issues,
		})
	}
	renderAgentsTable(cmd.OutOrStdout(), rows, issues, label)
	return nil
}

func runAgentShow(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	name := args[0]
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	rows, _, label, err := resolveFleet(ctx, cmd, cfg, agentsQueueTenant)
	if err != nil {
		return err
	}
	for i := range rows {
		if rows[i].Name == name {
			if agentsQueueJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows[i])
			}
			renderAgentShow(cmd.OutOrStdout(), rows[i], label)
			return nil
		}
	}
	return fmt.Errorf("unknown agent %q: discovered agents: %s", name, strings.Join(agentRowNames(rows), ", "))
}

// resolveFleet returns the attention-queue rows + fleet issues, server-first:
//   - an EXPLICIT --url is authoritative — a reachable-but-failing server is a
//     hard error, never a silent fall back to a possibly-divergent local view;
//   - otherwise an implicitly-detected localhost Talon server (the #293 /health
//     marker) is authoritative when reachable;
//   - otherwise the local config is projected offline, prominently labeled.
func resolveFleet(ctx context.Context, cmd *cobra.Command, cfg *config.Config, tenant string) (rows []fleet.AgentRow, issues []agentcatalog.FleetIssue, label string, err error) {
	explicit := cmd.Flags().Changed("url")
	if explicit {
		fr, ferr := fetchServerFleet(ctx, agentsQueueURL, tenant)
		if ferr != nil {
			return nil, nil, "", fmt.Errorf("querying %s: %w (an explicit --url is authoritative; not falling back to a local config view)", agentsQueueURL, ferr)
		}
		return fr.Agents, fr.FleetIssues, "", nil
	}
	if isTalonServer(ctx, agentsQueueURL) {
		if fr, ferr := fetchServerFleet(ctx, agentsQueueURL, tenant); ferr == nil {
			return fr.Agents, fr.FleetIssues, "", nil
		}
		// A Talon server was detected but the fleet read failed: fall through to
		// the offline view rather than error, since --url was not explicit.
	}
	rows, issues, err = offlineFleet(ctx, cfg, tenant)
	if err != nil {
		return nil, nil, "", err
	}
	return rows, issues, offlineFleetLabel, nil
}

func fetchServerFleet(ctx context.Context, baseURL, tenant string) (*fleetResponse, error) {
	u := strings.TrimRight(baseURL, "/") + "/v1/agents/fleet"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if k := os.Getenv("TALON_ADMIN_KEY"); k != "" {
		req.Header.Set("X-Talon-Admin-Key", k)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var fr fleetResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		return nil, fmt.Errorf("decoding fleet response: %w", err)
	}
	if tenant != "" {
		fr.Agents = filterRowsByTenant(fr.Agents, tenant)
	}
	return &fr, nil
}

// offlineFleet projects the LOCAL config (no running server): scan the fleet
// source, resolve each agent's effective caps from its own policy + the gateway
// org baseline, and run the SAME fleet.Project over the local evidence/session
// stores. Runtime state (active generation, last-known-good divergence) is
// unavailable offline — the caller labels the output accordingly.
func offlineFleet(ctx context.Context, cfg *config.Config, tenant string) ([]fleet.AgentRow, []agentcatalog.FleetIssue, error) {
	var scan *agentcatalog.ScanResult
	if cfg.AgentsDir != "" {
		scan, _ = agentcatalog.DiscoverAgents(ctx, cfg.AgentsDir)
	} else {
		scan, _ = agentcatalog.Source{File: cfg.DefaultPolicy}.Scan(ctx)
	}
	if scan == nil {
		return nil, nil, fmt.Errorf("no agent config found (set agents_dir or %s)", cfg.DefaultPolicy)
	}

	members := make([]fleet.Membership, 0, len(scan.Agents))
	for i := range scan.Agents {
		a := &scan.Agents[i]
		t := a.TenantID
		if t == "" {
			t = "default"
		}
		if tenant != "" && t != tenant {
			continue
		}
		members = append(members, fleet.Membership{
			Name: a.Name, TenantID: t, Enabled: a.Enabled,
			ConfigPath: a.Path, PolicyDigest: a.PolicyDigest,
		})
	}

	caps := offlineCapsLookup(scan)
	currency := loadPricingTable(cfg, "").CurrencyCode()
	statuses := fleet.AssembleStatuses(members, caps, currency)

	ev, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("opening evidence store: %w", err)
	}
	defer ev.Close()
	ss, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return nil, nil, fmt.Errorf("opening session store: %w", err)
	}
	defer ss.Close()

	rows, err := fleet.Project(ctx, ev, ss, statuses, fleet.DefaultThresholds(), time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	return rows, append([]agentcatalog.FleetIssue(nil), scan.Issues...), nil
}

// offlineCapsLookup resolves each scanned agent's effective daily/monthly caps
// from its OWN policy override tightened against the gateway org baseline — the
// same ResolveEffectivePolicy the server uses. A missing gateway config yields a
// zero org baseline (caps come from the agent override alone).
func offlineCapsLookup(scan *agentcatalog.ScanResult) fleet.CapLookup {
	org := gateway.OrganizationPolicy{}
	gwPath := strings.TrimSpace(os.Getenv("TALON_GATEWAY_CONFIG"))
	if gwPath == "" {
		gwPath = "talon.config.yaml"
	}
	if gwCfg, err := gateway.LoadGatewayConfig(gwPath); err == nil {
		org = gwCfg.OrganizationPolicy
	}
	type cap struct{ daily, monthly float64 }
	byName := make(map[string]cap, len(scan.Agents))
	for i := range scan.Agents {
		a := &scan.Agents[i]
		la := agentbridge.LoadedAgentFromPolicy(a.Policy, a.Path)
		eff := gateway.ResolveEffectivePolicy(org, gateway.ProviderConfig{}, la.Override)
		byName[a.Name] = cap{eff.BindingDailyCap(), eff.BindingMonthlyCap()}
	}
	return func(_, agentID string) (float64, float64, bool) {
		c, ok := byName[agentID]
		return c.daily, c.monthly, ok && (c.daily > 0 || c.monthly > 0)
	}
}

func filterRowsByTenant(rows []fleet.AgentRow, tenant string) []fleet.AgentRow {
	out := rows[:0]
	for i := range rows {
		if rows[i].TenantID == tenant {
			out = append(out, rows[i])
		}
	}
	return out
}

func agentRowNames(rows []fleet.AgentRow) []string {
	names := make([]string, len(rows))
	for i := range rows {
		names[i] = rows[i].Name
	}
	return names
}

func renderAgentsTable(w io.Writer, rows []fleet.AgentRow, issues []agentcatalog.FleetIssue, label string) {
	if label != "" {
		fmt.Fprintln(w, label)
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%-22s %-9s %-16s %-24s %s\n", "AGENT", "STATE", "HEALTH", "COST", "WHY")
	fmt.Fprintf(w, "%-22s %-9s %-16s %-24s %s\n", "-----", "-----", "------", "----", "---")
	for i := range rows {
		r := &rows[i]
		fmt.Fprintf(w, "%-22s %-9s %-16s %-24s %s\n", r.Name, r.State, r.Health, r.CostString(), r.Why)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no agents discovered)")
	}
	if len(issues) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "fleet issues (%d) — fix or remove by path; never-valid files are not agents:\n", len(issues))
		for _, iss := range issues {
			fmt.Fprintf(w, "  %s: %s\n", iss.Path, iss.Reason)
		}
	}
}

func renderAgentShow(w io.Writer, r fleet.AgentRow, label string) {
	if label != "" {
		fmt.Fprintln(w, label)
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Agent:  %s  (tenant %s)\n", r.Name, r.TenantID)
	fmt.Fprintf(w, "State:  %s\n", r.State)
	fmt.Fprintf(w, "Health: %s\n", r.Health)
	fmt.Fprintf(w, "Why:    %s\n", r.Why)
	for _, c := range r.Causes {
		fmt.Fprintf(w, "  - %s: %s\n", c.Kind, c.Detail)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Cost (month-to-date): %s\n", monthCostLine(r))
	fmt.Fprintf(w, "Cost (today):         %s\n", dayCostLine(r))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Signals (rolling windows):")
	fmt.Fprintf(w, "  requests (1h):         %d (%d denied)\n", r.Requests, r.Denied)
	fmt.Fprintf(w, "  fallbacks (1h):        %d\n", r.Fallbacks)
	fmt.Fprintf(w, "  failed sessions (24h): %d\n", r.FailedSessions)
	if !r.LastRun.IsZero() {
		fmt.Fprintf(w, "Last run: %s\n", r.LastRun.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(w, "Config:   %s\n", r.ConfigPath)
	if r.PolicyDigest != "" {
		fmt.Fprintf(w, "Digest:   %s\n", r.PolicyDigest)
	}
	if r.ConfigError != "" {
		fmt.Fprintf(w, "Config rejected: %s (last-known-good is serving)\n", r.ConfigError)
	}
}

func monthCostLine(r fleet.AgentRow) string {
	if r.MonthlyCap > 0 {
		return fleet.FormatMoney(r.Currency, r.SpendMonth) + " / " + fleet.FormatMoney(r.Currency, r.MonthlyCap)
	}
	return fleet.FormatMoney(r.Currency, r.SpendMonth) + " / (no monthly cap)"
}

func dayCostLine(r fleet.AgentRow) string {
	if r.DailyCap > 0 {
		return fleet.FormatMoney(r.Currency, r.SpendDay) + " / " + fleet.FormatMoney(r.Currency, r.DailyCap)
	}
	return fleet.FormatMoney(r.Currency, r.SpendDay) + " / (no daily cap)"
}
