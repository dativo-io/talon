package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/agentcatalog"
	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/effective"
	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/fleet"
	"github.com/dativo-io/talon/internal/runtimestatus"
)

// The default (human) views of `talon agents` and `talon agents show`.
//
// They are presentations of projections that exist: the fleet rows
// (fleet.AgentRow, the same rows `--json` prints and the console shows),
// the processes' runtime records, and for one use case the effective report
// (effective.Report, what `--effective` prints in full). Nothing is decided
// or stored here. The machine contracts are `--json` and `--effective
// --json`; they do not change with these views.
//
// What the views keep apart, because a listing that says "healthy" for an
// application nobody has connected is how operators get misled: configured
// (the file), runtime (a running process has loaded it), traffic (a request
// was observed) and attention (health). None is derived from another, and a
// missing observation is shown as missing.

// quietOperatorLogs keeps informational log lines (for example which pricing
// table is in use) out of an operator view. An explicit --log-level or
// --verbose is respected.
func quietOperatorLogs(cmd *cobra.Command) {
	flags := cmd.Root().PersistentFlags()
	if flags.Changed("log-level") || flags.Changed("verbose") {
		return
	}
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
}

// installationRuntime reads the runtime records of this installation.
func installationRuntime(cfg *config.Config, now time.Time) (view runtimestatus.View, readable bool) {
	view = runtimestatus.NewReader().Assess(cfg.DataDir, runtimestatus.Fingerprint(cfg.SigningKey), nil, now)
	return view, view.Err == ""
}

func anyRunning(view *runtimestatus.View) bool {
	for i := range view.Processes {
		if view.Processes[i].Assessed == runtimestatus.Running {
			return true
		}
	}
	return false
}

// localViewNote says, when no server answered at the URL the command asked,
// what the reader is looking at. It does not claim that nothing is running
// when the installation's own records say that something is.
func localViewNote(label, url string, view *runtimestatus.View, readable bool) string {
	if label == "" {
		return ""
	}
	switch {
	case readable && anyRunning(view):
		return fmt.Sprintf("Local view: no Talon server answered at %s. A Talon process of this installation is running elsewhere (RUNTIME is from its own records); pass --url <its address> for its view.", url)
	case readable:
		return fmt.Sprintf("Local view: no Talon process of this installation is running (none answered at %s).", url)
	}
	return fmt.Sprintf("Local view: no Talon server answered at %s, and this installation's runtime records could not be read.", url)
}

// runtimeWord is one row's runtime state in a word. It comes from the
// processes' own records, compared by policy digest; it is not inferred
// from the file's existence.
func runtimeWord(view *runtimestatus.View, readable bool, r *fleet.AgentRow) string {
	if !readable {
		return "unknown"
	}
	if !anyRunning(view) {
		return "not running"
	}
	switch runtimestatus.ProveLoaded(*view, readable, r.Name, r.TenantID, r.PolicyDigest).State {
	case runtimestatus.LoadedMatchesFile:
		return "loaded"
	case runtimestatus.LoadedDiffersFromFile:
		return "other version"
	case runtimestatus.NotInActiveGeneration:
		return "not loaded"
	}
	return "unknown"
}

// ago words how long ago t was, coarsely.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < 0:
		return t.UTC().Format(time.RFC3339)
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func attention(r *fleet.AgentRow) string {
	if r.ConfigError != "" {
		return "config rejected: " + r.ConfigError
	}
	if r.Health == fleet.HealthHealthy {
		return "—"
	}
	if r.Why == "" || r.Why == "—" {
		return string(r.Health)
	}
	return string(r.Health) + ": " + r.Why
}

// renderAgentsOverview is the default `talon agents` listing: one line per
// use case, with what an operator scans for first.
func renderAgentsOverview(w io.Writer, rows []fleet.AgentRow, issues []agentcatalog.FleetIssue, note string, view *runtimestatus.View, readable bool, now time.Time) {
	if note != "" {
		fmt.Fprintln(w, note)
		fmt.Fprintln(w)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "No AI use case is registered. Register one: talon agents add <name> --owner <team>")
	} else {
		const format = "%-22s %-9s %-14s %-14s %-22s %s\n"
		fmt.Fprintf(w, format, "USE CASE", "STATE", "RUNTIME", "LAST REQUEST", "COST THIS MONTH", "ATTENTION")
		for i := range rows {
			r := &rows[i]
			last := "none observed"
			if !r.LastRun.IsZero() {
				last = ago(now, r.LastRun)
			}
			fmt.Fprintf(w, format, r.Name, r.State, runtimeWord(view, readable, r), last, r.CostString(), attention(r))
		}
		fmt.Fprintf(w, "\nSTATE: the file · RUNTIME: loaded by a running Talon process · LAST REQUEST: observed traffic\nInspect one: talon agents show <name>\n")
	}
	if len(issues) > 0 {
		fmt.Fprintf(w, "\nFleet issues (%d): these files are not valid use cases; fix or remove them by path.\n", len(issues))
		for _, iss := range issues {
			fmt.Fprintf(w, "  %s: %s\n", iss.Path, iss.Reason)
		}
	}
}

// buildUseCaseReport builds the effective report of one use case from the
// local files, stores and runtime records: the projection `--effective`
// prints and the console shows.
func buildUseCaseReport(ctx context.Context, cfg *config.Config, name, tenant, proxyConfig string) (*effective.Report, error) {
	in := effective.Inputs{
		AgentsDir: cfg.AgentsDir, DefaultPolicy: cfg.DefaultPolicy,
		GatewayConfig: offlineGatewayConfigPath(), ProxyConfig: strings.TrimSpace(proxyConfig),
		Name: name, Tenant: tenant, Now: time.Now().UTC(),
		// Vault METADATA only (read-only, no key): the version record of the
		// use case's credential.
		SecretsDB: cfg.SecretsDBPath(),
	}
	if _, err := os.Stat(cfg.EvidenceDBPath()); err == nil {
		store, err := evidence.OpenReadOnly(cfg.EvidenceDBPath(), cfg.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("opening evidence store read-only: %w", err)
		}
		defer store.Close()
		in.Evidence = store
	}
	view, readable := installationRuntime(cfg, in.Now)
	in.Runtime, in.RuntimeReadable = &view, readable
	return effective.Build(ctx, in)
}

// statusHeadline is the first thing the single view says. It is the next
// step's code in two or three words; the sentence is under "Next".
func statusHeadline(next effective.NextStep) string {
	switch next.Code {
	case effective.NextNone:
		return "Working"
	case effective.NextEnable:
		return "Disabled"
	case effective.NextStartRuntime, effective.NextFixReload, effective.NextWaitReload:
		return "Not active"
	case effective.NextCheckRuntime:
		return "Runtime not confirmed"
	case effective.NextSendRequest:
		return "Waiting for its first request"
	}
	return "Needs attention"
}

func runtimeLine(r *effective.Report) string {
	if r.Verification != nil && r.Verification.Next.Code == effective.NextStartRuntime {
		return "not running: no Talon process of this installation is running"
	}
	switch r.Loaded.State {
	case runtimestatus.LoadedMatchesFile:
		return "loaded by the running Talon process"
	case runtimestatus.LoadedDiffersFromFile:
		return fmt.Sprintf("the running Talon process reports ANOTHER version of this file (it refreshes its report every %s)", runtimestatus.DefaultInterval)
	case runtimestatus.NotInActiveGeneration:
		return "not loaded: a Talon process is running without this use case"
	}
	return "not confirmed: " + r.Loaded.Reason
}

// policyLine is the policy in one line: the controls that have a value, and
// whether the newest authenticated request was evaluated under them.
func policyLine(r *effective.Report) (controls, verified string) {
	var items []string
	for i := range r.Effective.Rules {
		rule := &r.Effective.Rules[i]
		if strings.TrimSpace(rule.Effective) != "" && !strings.HasPrefix(rule.Winner, "built_in") {
			items = append(items, rule.Rule+" "+rule.Effective)
		}
	}
	controls = strings.Join(items, " · ")
	switch {
	case !r.Effective.BaselinePresent && controls == "":
		controls = "no company policy is configured, and the use case sets none"
	case !r.Effective.BaselinePresent:
		controls += " (no company policy is configured)"
	case controls == "":
		controls = "the company policy sets no budget, PII or tool rule"
	}
	verified = "no authenticated request to compare with yet"
	if v := r.Verification; v != nil {
		for i := range v.Traffic {
			o := &v.Traffic[i]
			if o.State != effective.TrafficObserved || !o.IdentityProven {
				continue
			}
			switch o.Policy {
			case effective.PolicyMatchesCurrent:
				verified = "the newest authenticated request was evaluated under this policy"
			case effective.PolicyDiffers:
				verified = "the newest authenticated request was evaluated under ANOTHER policy"
			default:
				verified = "the policy of the newest authenticated request is not recorded on its record"
			}
			break
		}
	}
	return controls, verified
}

func outcomeWords(o *evidence.Outcome) string {
	decision := map[string]string{"allowed": "allowed by Talon", "denied": "denied by Talon", "approval_required": "waits for approval"}[o.Decision]
	if decision == "" {
		decision = o.Decision
	}
	return decision + ", " + strings.ReplaceAll(o.Dispatch, "_", " ")
}

// boundaryOf names the boundary a request-class record was made at.
func boundaryOf(invocationType string) string {
	switch {
	case invocationType == "gateway":
		return "LLM gateway"
	case strings.HasPrefix(invocationType, "proxy_"):
		return "MCP proxy"
	case invocationType == evidence.InvocationTypeActionLifecycle:
		return "Action Gateway"
	}
	return invocationType
}

func stateWord(s fleet.State) string {
	if s == fleet.StateStopped {
		return "disabled (agent.enabled: false)"
	}
	return string(s)
}

// renderUseCase is the default `talon agents show <name>` view: what is
// happening with this application, and whether to do something. report may
// be nil when the effective report could not be built; the view then says
// so and shows what the fleet row holds.
func renderUseCase(w io.Writer, row *fleet.AgentRow, report *effective.Report, reportErr error, now time.Time) {
	renderUseCaseIdentity(w, row)
	var next *effective.NextStep
	if report != nil && report.Verification != nil {
		next = &report.Verification.Next
	}
	renderUseCaseFacts(w, row, report, next, reportErr, now)
	if report != nil && report.LastDecision != nil {
		renderLastRequest(w, report.LastDecision)
	}
	if hasOperatingRecord(row.UseCase) {
		fmt.Fprintln(w)
		renderAgentUseCase(w, row.UseCase)
	}
	if next != nil {
		fmt.Fprintf(w, "\nNext\n  %s\n", next.Text)
		for _, c := range next.Commands {
			fmt.Fprintf(w, "    %s\n", c)
		}
	}
	fmt.Fprintf(w, "\nFull report: talon agents show %s --effective\n", row.Name)
}

// renderUseCaseIdentity prints the name, what the use case is for, and who
// operates it (declared in its file; attribution, not authentication).
func renderUseCaseIdentity(w io.Writer, row *fleet.AgentRow) {
	title, owner := row.Name, "not declared"
	if uc := row.UseCase; uc != nil {
		if uc.Purpose != "" {
			title += " — " + uc.Purpose
		}
		for _, o := range []string{uc.OwnerTechnical, uc.OwnerBusiness} {
			if o != "" {
				owner = o
				break
			}
		}
	}
	fmt.Fprintf(w, "%s\ntenant %s · owner %s · %s\n\n", title, row.TenantID, owner, row.ConfigPath)
}

// renderUseCaseFacts prints the facts side by side, each from its own
// source: the file, the runtime records, observed traffic, the policy, the
// spend and the health signals.
func renderUseCaseFacts(w io.Writer, row *fleet.AgentRow, report *effective.Report, next *effective.NextStep, reportErr error, now time.Time) {
	line := func(k, v string) { fmt.Fprintf(w, "  %-11s %s\n", k, v) }
	if next != nil {
		line("Status", statusHeadline(*next))
	} else {
		line("Status", "Not determined: the full report could not be built ("+errText(reportErr)+")")
	}
	line("Configured", stateWord(row.State))
	if report != nil {
		line("Runtime", runtimeLine(report))
	}
	traffic := "no request observed"
	if !row.LastRun.IsZero() {
		traffic = fmt.Sprintf("last request %s · %d in the last hour (%d denied)", ago(now, row.LastRun), row.Requests, row.Denied)
	}
	line("Traffic", traffic)
	if report != nil {
		controls, verified := policyLine(report)
		line("Policy", controls)
		line("", verified)
	}
	line("Cost", monthCostLine(*row)+" this month · "+dayCostLine(*row)+" today")
	line("Health", attentionOrHealthy(row))
	for _, c := range row.Causes {
		if c.Kind != "" {
			line("", string(c.Kind)+": "+c.Detail)
		}
	}
}

// renderLastRequest prints the newest request decision with its evidence.
func renderLastRequest(w io.Writer, d *effective.LastDecision) {
	fmt.Fprintf(w, "\nLast request\n  %s · %s · %s\n", d.Timestamp.UTC().Format("2006-01-02 15:04:05Z"), boundaryOf(d.InvocationType), outcomeWords(&d.Outcome))
	switch {
	case d.PrimaryCode == explanation.CodeLegacyReasonUnmigrated:
		// The record states its reason in its own words but carries no
		// reason code (for example a request to a disabled use case). The
		// placeholder text explains nothing: point at the record.
		fmt.Fprintf(w, "  reason recorded without a reason code; read it with: talon audit show %s\n", d.EvidenceID)
	case d.PrimaryCode != "":
		fmt.Fprintf(w, "  %s: %s\n", d.PrimaryCode, d.PrimaryReason)
	}
	sig := "signature valid"
	if d.Verification != "valid" {
		sig = "SIGNATURE INVALID: nothing on this record is established"
	}
	ref := fmt.Sprintf("  evidence %s (%s)", d.EvidenceID, sig)
	if d.SessionID != "" {
		ref += " · session " + d.SessionID
	}
	fmt.Fprintln(w, ref)
}

func attentionOrHealthy(r *fleet.AgentRow) string {
	if a := attention(r); a != "—" {
		return a
	}
	return "no budget, denial or failure signal"
}

func errText(err error) string {
	if err == nil {
		return "no detail"
	}
	return err.Error()
}

// renderAgentUseCase prints the operating record declared in the agent's
// config (#382). Purely declared metadata — no health/budget/policy
// computation happens here; owners are attribution for the reader, never
// authentication of the named people.
func renderAgentUseCase(w io.Writer, uc *fleet.UseCase) {
	if uc == nil {
		return
	}
	fmt.Fprintln(w, "Use case (declared in config):")
	if uc.Purpose != "" {
		fmt.Fprintf(w, "  Purpose:     %s\n", uc.Purpose)
	}
	if uc.Department != "" {
		fmt.Fprintf(w, "  Department:  %s\n", uc.Department)
	}
	if uc.Criticality != "" {
		fmt.Fprintf(w, "  Criticality: %s\n", uc.Criticality)
	}
	owners := [][2]string{
		{"business", uc.OwnerBusiness},
		{"technical", uc.OwnerTechnical},
		{"budget", uc.OwnerBudget},
		{"risk", uc.OwnerRisk},
	}
	for _, o := range owners {
		if o[1] != "" {
			fmt.Fprintf(w, "  Owner (%s): %s\n", o[0], o[1])
		}
	}
	for _, ref := range uc.References {
		fmt.Fprintf(w, "  Reference:   %s\n", ref)
	}
	fmt.Fprintln(w)
}

// hasOperatingRecord reports whether the declared record says more than the
// title line of the view already shows (purpose and the operating owner).
func hasOperatingRecord(uc *fleet.UseCase) bool {
	return uc != nil && (uc.Department != "" || uc.Criticality != "" || uc.OwnerBusiness != "" || uc.OwnerBudget != "" || uc.OwnerRisk != "" || len(uc.References) > 0)
}
