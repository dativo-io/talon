package cmd

import (
	"context"
	"encoding/json"
	"errors"
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
	sessShowTenant string
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
	sessionShowCmd.Flags().StringVar(&sessShowTenant, "tenant", "", "Scope to a tenant (default: unscoped operator read)")
	sessionShowCmd.Flags().BoolVar(&sessShowJSON, "json", false, "Emit the session detail as JSON")
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

	// Operator CLI on the local DB: tenant-wide view (no agent scope). Only
	// real asserted/talon sessions have rows — synthetic request-level ids
	// never reach this store, so they cannot appear here (#271 boundary).
	sessions, err := store.ListByTenant(context.Background(), sessTenant, "", talonsession.Status(sessStatus))
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

// sessionDetail is the `session show` contract: the session-store row (when
// one exists) plus the evidence-derived summary. The summary is built by
// evidence.BuildSessionSummary — the same pure function behind the dashboard
// session drill-down, so the two views cannot disagree (#271).
type sessionDetail struct {
	Session   *talonsession.Session   `json:"session,omitempty"`
	Ambiguous []*talonsession.Session `json:"ambiguous_sessions,omitempty"`
	Summary   evidence.SessionSummary `json:"summary"`
}

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

	detail, err := loadSessionDetail(cmd.Context(), store, evStore, args[0], sessShowTenant)
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

// loadSessionDetail resolves the argument against both id namespaces (internal
// sess_... primary key, then external asserted id) and joins the row with the
// session's evidence records. A session with evidence but no row (e.g. one
// asserted only on the MCP proxy path) still gets a summary.
func loadSessionDetail(ctx context.Context, store *talonsession.Store, evStore *evidence.Store, idOrExternal, tenant string) (*sessionDetail, error) {
	detail := &sessionDetail{}
	sess, err := store.Get(ctx, idOrExternal, tenant)
	switch {
	case err == nil:
		detail.Session = sess
	case errors.Is(err, talonsession.ErrSessionNotFound):
		matches, listErr := store.ListByExternalID(ctx, idOrExternal, tenant)
		if listErr != nil {
			return nil, listErr
		}
		switch len(matches) {
		case 0: // evidence-only session, or unknown id — decided below
		case 1:
			detail.Session = matches[0]
		default:
			detail.Ambiguous = matches
			return detail, nil
		}
	default:
		return nil, fmt.Errorf("getting session %s: %w", idOrExternal, err)
	}

	// Evidence keys sessions by the EXTERNAL id when one was asserted; runner
	// lifecycle sessions use the internal id itself.
	evidenceKey := idOrExternal
	if detail.Session != nil {
		evidenceKey = detail.Session.ID
		if detail.Session.ExternalSessionID != "" {
			evidenceKey = detail.Session.ExternalSessionID
		}
	}
	records, err := fetchSessionRecords(ctx, evStore, evidenceKey, tenant, "")
	if err != nil {
		return nil, err
	}
	if detail.Session == nil && len(records) == 0 {
		return nil, fmt.Errorf("session %s not found (no session row, no evidence records)", idOrExternal)
	}
	detail.Summary = evidence.BuildSessionSummary(evidenceKey, records)
	return detail, nil
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
