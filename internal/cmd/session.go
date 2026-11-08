package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/config"
	"github.com/dativo-io/talon/internal/evidence"
	talonsession "github.com/dativo-io/talon/internal/session"
)

var (
	sessTenant     string
	sessStatus     string
	sessListJSON   bool
	sessListLimit  int
	sessListObs    bool
	sessShowTenant string
	sessShowAgent  string
	sessShowJSON   bool
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage sessions (workflow grouping)",
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sessions",
	RunE:  sessionList,
}

var sessionShowCmd = &cobra.Command{
	Use:   "show [session-id]",
	Short: "Show the session summary (status, cost, reliability, interventions, tool calls)",
	Long: `Show the operational summary of a session: status, duration, cost, request
count, retries/fallbacks/denials, intercepted tool calls, the provider path
that served it, key policy interventions, and a failure explanation when the
session failed.

Accepts the internal id (sess_...) or the external client/vendor-asserted
session id. The summary covers only traffic Talon intercepted — local actions
that bypass Talon are invisible and are not part of this account.`,
	Args: cobra.ExactArgs(1),
	RunE: sessionShow,
}

func init() {
	sessionListCmd.Flags().StringVar(&sessTenant, "tenant", "default", "Tenant ID")
	sessionListCmd.Flags().StringVar(&sessStatus, "status", "", "Filter by status")
	sessionListCmd.Flags().BoolVar(&sessListJSON, "json", false, "Emit the session rows as JSON")
	sessionListCmd.Flags().IntVar(&sessListLimit, "limit", 0, "Return at most N sessions, newest first (0 = all)")
	sessionListCmd.Flags().BoolVar(&sessListObs, "observed", false, "List session ids seen in evidence that have no session row (for example asserted on the MCP proxy path): agents, record count, first/last seen; --limit bounds the page (default 50)")
	sessionShowCmd.Flags().StringVar(&sessShowTenant, "tenant", "", "Scope to a tenant (default: unscoped operator read)")
	sessionShowCmd.Flags().BoolVar(&sessShowJSON, "json", false, "Emit the session detail as JSON")
	sessionShowCmd.Flags().StringVar(&sessShowAgent, "agent", "", "Scope to one agent's share of the session (the (session, agent) pair `session list --observed` shows); an external id shared by several agents resolves to that agent's row")
	sessionCmd.AddCommand(sessionListCmd, sessionShowCmd)
	rootCmd.AddCommand(sessionCmd)
}

func sessionList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	store, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("opening session store: %w", err)
	}
	defer store.Close()

	if sessListObs {
		return sessionListObserved(cmd, cfg, store)
	}
	// Operator CLI on the local DB: tenant-wide view (no agent scope). Only
	// real asserted/talon sessions have rows — synthetic request-level ids
	// never reach this store, so they cannot appear here (#271 boundary).
	var sessions []*talonsession.Session
	if sessListLimit > 0 {
		sessions, err = store.ListRecent(context.Background(), sessTenant, "", talonsession.Status(sessStatus), talonsession.Cursor{}, sessListLimit)
	} else {
		sessions, err = store.ListByTenant(context.Background(), sessTenant, "", talonsession.Status(sessStatus))
	}
	if err != nil {
		return fmt.Errorf("listing sessions: %w", err)
	}

	if sessListJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(sessions)
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSESSION\tSOURCE\tSTATUS\tAGENT\tCOST\tTOKENS\tCREATED")
	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%.4f\t%d\t%s\n",
			s.ID, valueOrDash(s.ExternalSessionID), valueOrDash(s.Source), s.Status, s.AgentID,
			s.TotalCost, s.TotalTokens, s.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	return tw.Flush()
}

// sessionListObserved is `session list --observed`: the evidence-observed
// session ids without a session-store row, the same rows the console lists
// (evidence.Store.ListObservedSessions filtered by session.Store).
func sessionListObserved(cmd *cobra.Command, cfg *config.Config, store *talonsession.Store) error {
	ctx := cmd.Context()
	evStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("opening evidence store: %w", err)
	}
	defer evStore.Close()
	limit := sessListLimit
	if limit <= 0 {
		limit = 50
	}
	if limit > evidence.MaxObservedPage {
		limit = evidence.MaxObservedPage
	}
	observed, err := evStore.ListObservedSessions(ctx, sessTenant, "", evidence.ObservedCursor{}, limit)
	if err != nil {
		return fmt.Errorf("listing observed sessions: %w", err)
	}
	ids := make([]string, 0, len(observed))
	for i := range observed {
		ids = append(ids, observed[i].SessionID)
	}
	owners, err := store.OwnersOf(ctx, sessTenant, ids)
	if err != nil {
		return fmt.Errorf("resolving session owners: %w", err)
	}
	rows := make([]evidence.ObservedSession, 0, len(observed))
	for i := range observed {
		if owners[observed[i].SessionID][observed[i].AgentID] {
			continue // that agent's share has a row: `talon session list` shows it
		}
		rows = append(rows, observed[i])
	}
	if sessListJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tAGENT\tRECORDS\tFIRST SEEN\tLAST SEEN\tSOURCE")
	for i := range rows {
		o := &rows[i]
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", o.SessionID, o.AgentID, o.RecordCount,
			o.FirstSeen.Format("2006-01-02 15:04:05"), o.LastSeen.Format("2006-01-02 15:04:05"), o.Source)
	}
	return tw.Flush()
}

// sessionDetail is the `session show` contract: the shared session.Detail
// (#271, #535), built by session.LoadDetail for the CLI and the console alike.
type sessionDetail = talonsession.Detail

func sessionShow(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	store, err := talonsession.NewStore(cfg.EvidenceDBPath())
	if err != nil {
		return fmt.Errorf("opening session store: %w", err)
	}
	defer store.Close()
	evStore, err := evidence.NewStore(cfg.EvidenceDBPath(), cfg.SigningKey)
	if err != nil {
		return fmt.Errorf("opening evidence store: %w", err)
	}
	defer evStore.Close()

	detail, err := talonsession.LoadDetailFor(cmd.Context(), store, evStore, args[0], sessShowTenant, sessShowAgent)
	if err != nil {
		return err
	}
	if sessShowJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(detail)
	}
	renderSessionDetail(cmd.OutOrStdout(), args[0], detail)
	if len(detail.Ambiguous) > 0 {
		return fmt.Errorf("external session id %q matches %d sessions; re-run with an internal id", args[0], len(detail.Ambiguous))
	}
	return nil
}

// renderSessionDetail prints the one-screen session summary: the store row's
// lifecycle facts, then the shared evidence rollup.
func renderSessionDetail(w io.Writer, requested string, detail *sessionDetail) {
	if len(detail.Ambiguous) > 0 {
		fmt.Fprintf(w, "External session id %s matches %d sessions:\n", requested, len(detail.Ambiguous))
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTENANT\tAGENT\tSTATUS\tCREATED")
		for _, s := range detail.Ambiguous {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.TenantID, s.AgentID, s.Status, s.CreatedAt.Format("2006-01-02 15:04:05"))
		}
		tw.Flush()
		return
	}

	sum := detail.Summary
	sess := detail.Session
	header := sum.SessionID
	if sess != nil {
		header = sess.ID
		if sess.ExternalSessionID != "" {
			header += " (external: " + sess.ExternalSessionID + ")"
		}
	}
	fmt.Fprintf(w, "Session %s\n", header)
	renderSessionRow(w, sess)
	if sum.RecordCount == 0 {
		fmt.Fprintln(w, "  (no evidence records)")
		return
	}
	renderSessionSummaryBody(w, sum)
}

// renderSessionRow prints the lifecycle facts held by the session store. A
// missing row is stated plainly: the session was observed in evidence only.
func renderSessionRow(w io.Writer, sess *talonsession.Session) {
	if sess == nil {
		fmt.Fprintln(w, "  Status:    (no session row — observed in evidence only)")
		return
	}
	status := fmt.Sprintf("  Status:    %s — created %s", sess.Status, sess.CreatedAt.Format(time.RFC3339))
	if sess.CompletedAt != nil {
		status += ", completed " + sess.CompletedAt.Format(time.RFC3339)
	} else if !sess.UpdatedAt.Equal(sess.CreatedAt) {
		status += ", last activity " + sess.UpdatedAt.Format(time.RFC3339)
	}
	fmt.Fprintln(w, status)
	if sess.Source != "" {
		fmt.Fprintf(w, "  Asserted:  %s\n", sess.Source)
	}
	if sess.MaxCost > 0 {
		fmt.Fprintf(w, "  Budget:    session cap %s, tracked spend %s\n",
			formatMoney("", sess.MaxCost), formatMoney("", sess.TotalCost))
	}
}
