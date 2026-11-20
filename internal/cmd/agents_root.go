package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/fleetview"
	"github.com/dativo-io/talon/internal/gateway"
	"github.com/dativo-io/talon/internal/runtimestatus"
	talonsession "github.com/dativo-io/talon/internal/session"
)

// `talon agents` is the operator ATTENTION QUEUE (#270): every discovered agent
// with STATE (configured enabled/stopped) and HEALTH (evaluated), plus COST and
// WHY. It is server-first — the RUNNING gateway is the source of truth — with an
// honestly-labeled offline config view when no Talon server is reachable. The
// health/budget/session math is fleet.Project, the SAME code path the server
// uses, so the CLI and the API can never disagree (#270 parity).

var (
	agentsQueueURL    string
	agentsQueueTenant string
	agentsQueueJSON   bool
)

// offlineFleetLabel marks rows that were projected from the local files and
// stores because no Talon server answered (the `offline` field of --json).
// The human views word it from what the installation's own runtime records
// say (localViewNote): "no server answered here" is not "nothing runs".
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
	Short: "Show one AI use case: what is happening with it and what to do next (--effective: the full report)",
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
	quietOperatorLogs(cmd)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	rows, issues, label, origin, err := resolveFleetOrigin(ctx, cmd, cfg, agentsQueueTenant)
	if err != nil {
		return err
	}
	if agentsQueueJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"offline": label != "", "agents": rows, "fleet_issues": issues,
		})
	}
	if why := foreignServerSettled(cfg, origin); why != "" {
		// Another installation's rows: this machine's runtime records say
		// nothing about them, so the RUNTIME column is not filled from them.
		renderAgentsOverview(cmd.OutOrStdout(), rows, issues, serverViewNote(origin.serverURL, why), nil, false, time.Now().UTC())
		return nil
	}
	now := time.Now().UTC()
	view, readable := installationRuntime(cfg, now)
	renderAgentsOverview(cmd.OutOrStdout(), rows, issues, localViewNote(label, agentsQueueURL, &view, readable), &view, readable, now)
	return nil
}

func runAgentShow(cmd *cobra.Command, args []string) error {
	quietOperatorLogs(cmd)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	name := args[0]
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if agentsShowEffective {
		return runAgentShowEffective(ctx, cmd, cfg, name)
	}
	return showUseCase(ctx, cmd, cfg, name)
}

// showUseCase is `talon agents show <name>` for a loaded configuration.
func showUseCase(ctx context.Context, cmd *cobra.Command, cfg *config.Config, name string) error {
	rows, _, _, origin, err := resolveFleetOrigin(ctx, cmd, cfg, agentsQueueTenant)
	if err != nil {
		return err
	}
	for i := range rows {
		if rows[i].Name == name {
			if agentsQueueJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows[i])
			}
			now := time.Now().UTC()
			// A row a server reported is shown with this machine's policy,
			// evidence and runtime records only when that server is a
			// process of this installation. Otherwise the row is shown as
			// what it is, and nothing local is put next to it.
			if why := foreignServerSettled(cfg, origin); why != "" {
				renderServerUseCase(cmd.OutOrStdout(), &rows[i], origin.serverURL, why, now)
				return nil
			}
			// The human view adds what the fleet row does not hold: whether a
			// running process loaded the use case, the newest request and
			// the next step, from the report `--effective` prints in full.
			report, rerr := buildUseCaseReport(ctx, cfg, name, agentsQueueTenant, agentsShowProxyConfig)
			renderUseCase(cmd.OutOrStdout(), &rows[i], report, rerr, now)
			return nil
		}
	}
	return fmt.Errorf("unknown agent %q: discovered agents: %s", name, strings.Join(agentRowNames(rows), ", "))
}

// resolveFleet returns the attention-queue rows + fleet issues, server-first,
// under the SAME authority contract as `talon costs` (#288/#293) — a running
// Talon server's answer, or its refusal, is authoritative; the offline config
// view is used ONLY when no Talon server is actually there:
//   - an EXPLICIT --url is authoritative — a reachable-but-failing server is a
//     hard error, never a silent fall back to a possibly-divergent local view
//     (--url "" forces the offline view);
//   - an implicitly-detected localhost Talon server (the #293 /health marker) is
//     likewise authoritative: if it is present but the fleet query fails (401,
//     403, 500, malformed), that is a HARD ERROR carrying the original reason —
//     NOT a silent offline view under a "no server found" banner (#270 review
//     round 1, P1);
//   - only when NO Talon server is reachable (unreachable, or a non-Talon port
//     occupant) does the local config project offline, prominently labeled.
func resolveFleet(ctx context.Context, cmd *cobra.Command, cfg *config.Config, tenant string) (rows []fleet.AgentRow, issues []agentcatalog.FleetIssue, label string, err error) {
	rows, issues, label, _, err = resolveFleetOrigin(ctx, cmd, cfg, tenant)
	return rows, issues, label, err
}

// fleetOrigin says where a command's fleet rows came from: a Talon server
// that answered (its URL and the fleet generation it serves), or the local
// projection (serverURL == "").
type fleetOrigin struct {
	serverURL  string
	generation string
}

// foreignServer reports why the server that answered is NOT established to
// be a process of this installation, the one whose configuration, evidence
// and runtime records this command can read ("" when it is, or when the
// rows are the local projection).
//
// A server's fleet facts and this machine's stores describe the same
// installation only when the server is a process of it. That is established
// from existing contracts alone: the server is on this machine, and a
// running process of this installation reports, in its own runtime record,
// the fleet generation the server serves (GET /v1/agents/fleet). Anything
// else is another installation as far as this command can tell, and its
// rows are never shown next to this machine's evidence (#567 review).
func foreignServer(o fleetOrigin, view *runtimestatus.View, readable bool) string {
	if o.serverURL == "" {
		return ""
	}
	if !isLoopbackURL(o.serverURL) {
		return "it is on another host"
	}
	if view == nil || !readable {
		return "this installation's runtime records could not be read"
	}
	running := false
	for i := range view.Processes {
		p := &view.Processes[i]
		if p.Assessed != runtimestatus.Running || p.Catalog == nil {
			continue
		}
		running = true
		if o.generation != "" && p.Catalog.ActiveGeneration == o.generation {
			return ""
		}
	}
	if running {
		return "no running Talon process of this installation reports the fleet generation that server serves"
	}
	return "no Talon process of this installation is running, so that server belongs to another installation"
}

// fleetSettle is how long, and how often, a command waits for this
// installation's own process to report the fleet generation a server on
// this machine serves. A process writes its record within a fraction of a
// second of activating a generation; a command that asks in that moment
// would otherwise treat its own server as another installation's.
var fleetSettle = struct {
	delay time.Duration
	tries int
}{300 * time.Millisecond, 3}

// foreignServerSettled is foreignServer with that bounded wait. It waits
// only when the single obstacle can be the record being a moment behind: a
// server on this machine and a running process of this installation.
func foreignServerSettled(cfg *config.Config, o fleetOrigin) string {
	view, readable := installationRuntime(cfg, time.Now().UTC())
	why := foreignServer(o, &view, readable)
	for i := 0; i < fleetSettle.tries && why != "" && isLoopbackURL(o.serverURL) && readable && anyRunning(&view); i++ {
		time.Sleep(fleetSettle.delay)
		view, readable = installationRuntime(cfg, time.Now().UTC())
		why = foreignServer(o, &view, readable)
	}
	return why
}

// isLoopbackURL reports whether the URL's host is this machine.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// resolveFleetOrigin is resolveFleet with the origin of the rows.
func resolveFleetOrigin(ctx context.Context, cmd *cobra.Command, cfg *config.Config, tenant string) (rows []fleet.AgentRow, issues []agentcatalog.FleetIssue, label string, origin fleetOrigin, err error) {
	explicit := cmd.Flags().Changed("url")
	// Explicit --url "" forces the offline config view (skip the server path
	// entirely), matching `talon costs`.
	if explicit && strings.TrimSpace(agentsQueueURL) == "" {
		rows, issues, label, err = offlineWithLabel(ctx, cfg, tenant)
		return rows, issues, label, origin, err
	}
	if explicit {
		fr, ferr := fetchServerFleet(ctx, agentsQueueURL, tenant)
		if ferr != nil {
			return nil, nil, "", origin, fmt.Errorf("querying %s: %w (an explicit --url is authoritative; not falling back to a local config view — pass --url \"\" to force the offline view)", agentsQueueURL, ferr)
		}
		return fr.Agents, fr.FleetIssues, "", fleetOrigin{serverURL: agentsQueueURL, generation: fr.Generation}, nil
	}
	if isTalonServer(ctx, agentsQueueURL) {
		fr, ferr := fetchServerFleet(ctx, agentsQueueURL, tenant)
		if ferr != nil {
			// A Talon server IS running here but the fleet query failed: its
			// refusal is authoritative — never present a possibly-divergent local
			// view under a "no running gateway found" banner (the #293 defect).
			return nil, nil, "", origin, fmt.Errorf("a Talon server at %s rejected the fleet query: %w (set TALON_ADMIN_KEY or fix the server; not falling back to a local config view — pass --url \"\" to force it)", agentsQueueURL, ferr)
		}
		return fr.Agents, fr.FleetIssues, "", fleetOrigin{serverURL: agentsQueueURL, generation: fr.Generation}, nil
	}
	// No Talon server reachable (unreachable or a non-Talon port occupant).
	rows, issues, label, err = offlineWithLabel(ctx, cfg, tenant)
	return rows, issues, label, origin, err
}

// offlineWithLabel projects the local config and attaches the offline banner.
func offlineWithLabel(ctx context.Context, cfg *config.Config, tenant string) ([]fleet.AgentRow, []agentcatalog.FleetIssue, string, error) {
	rows, issues, err := offlineFleet(ctx, cfg, tenant)
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
// offlineFleet is the config-file view of the attention queue: the shared
// fleetview.ProjectOffline over the local scan, gateway baseline and stores
// (#535) — the same function the operations console uses, so `talon agents`
// offline and the console cannot disagree.
func offlineFleet(ctx context.Context, cfg *config.Config, tenant string) ([]fleet.AgentRow, []agentcatalog.FleetIssue, error) {
	scan, err := fleetview.Scan(ctx, cfg.AgentsDir, cfg.DefaultPolicy)
	if err != nil {
		return nil, nil, err
	}
	org, providers, err := loadOfflineGatewayContext()
	if err != nil {
		return nil, nil, err
	}
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

	res, err := fleetview.ProjectOffline(ctx, fleetview.Inputs{
		Scan: scan, Org: org, Providers: providers, Tenant: tenant,
		Currency: loadPricingTable(cfg, "").CurrencyCode(),
		Evidence: ev, Sessions: ss, Now: time.Now().UTC(),
	})
	if err != nil {
		return nil, nil, err
	}
	return res.Rows, res.Issues, nil
}

func loadOfflineGatewayContext() (org gateway.OrganizationPolicy, providers map[string]gateway.ProviderConfig, err error) {
	path := offlineGatewayConfigPath()
	gwCfg, loadErr := gateway.LoadGatewayConfig(path)
	if loadErr != nil {
		if errors.Is(loadErr, os.ErrNotExist) {
			return gateway.OrganizationPolicy{}, nil, nil // no gateway config: agent-only view
		}
		return gateway.OrganizationPolicy{}, nil, fmt.Errorf("gateway config %s is present but invalid: %w — fix it, or unset TALON_GATEWAY_CONFIG for a config-only view without an org baseline", path, loadErr)
	}
	return gwCfg.OrganizationPolicy, gwCfg.Providers, nil
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

// notComparable is the cost text when the row says the period's spend is
// not a measurement (priced records in another currency, #553 review).
func notComparable(r fleet.AgentRow, field string) bool {
	for _, f := range r.UnavailableFields {
		if f == field {
			return true
		}
	}
	return false
}

func monthCostLine(r fleet.AgentRow) string {
	if notComparable(r, "spend_month") {
		return "n/a (currencies differ) / " + fleet.FormatMoney(r.Currency, r.MonthlyCap)
	}
	if r.MonthlyCap > 0 {
		return fleet.FormatMoney(r.Currency, r.SpendMonth) + " / " + fleet.FormatMoney(r.Currency, r.MonthlyCap)
	}
	return fleet.FormatMoney(r.Currency, r.SpendMonth) + " / (no monthly cap)"
}

func dayCostLine(r fleet.AgentRow) string {
	if notComparable(r, "spend_day") {
		return "n/a (currencies differ) / " + fleet.FormatMoney(r.Currency, r.DailyCap)
	}
	if r.DailyCap > 0 {
		return fleet.FormatMoney(r.Currency, r.SpendDay) + " / " + fleet.FormatMoney(r.Currency, r.DailyCap)
	}
	return fleet.FormatMoney(r.Currency, r.SpendDay) + " / (no daily cap)"
}
