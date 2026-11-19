package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dativo-io/talon/internal/action"
)

// Local reviewer path (#433): an authenticated approver lists the pending
// approvals of their tenant and groups, reads exactly what they approve
// (action, material arguments as the reviewer projection, policy rule,
// target) and decides. The command is a thin client of the running
// server's reviewer routes; the approver credential is read from the
// TALON_APPROVER_KEY environment variable only — never a flag, so it does
// not land in shell history or process listings.

const approverKeyEnv = "TALON_APPROVER_KEY"

var (
	approvalsURL    string
	approvalsJSON   bool
	approvalsReason string
	// approvalsAll lists every unresolved approval, also the ones that can
	// no longer be decided; approvalsDecided lists history.
	approvalsAll     bool
	approvalsDecided bool
	approvalsAfter   string
	approvalsLimit   int
	// approvalsTechnical adds identifiers, digests and timestamps to show.
	approvalsTechnical bool
	// approvalsAllowPlaintext permits plain http to a non-loopback host.
	approvalsAllowPlaintext bool
)

var approvalsCmd = &cobra.Command{
	Use:   "approvals",
	Short: "Review and decide pending action approvals as an approver (credential from TALON_APPROVER_KEY)",
	Long: `Review and decide pending Action Gateway approvals against a running Talon server.

The approver credential (talon_appr_..., issued by 'talon approver add') is read
from the TALON_APPROVER_KEY environment variable; it is never accepted as a flag.
Only approvals of the credential's tenant that one of its groups may decide are
listed or shown. A decision dispatches nothing: the AI use case's runtime claims
the approved operation afterwards.`,
}

var approvalsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the approvals that need a decision (oldest first); --all adds the ones that can no longer be decided, --decided shows history",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if approvalsAll && approvalsDecided {
			return fmt.Errorf("--all and --decided are separate listings; pass one of them")
		}
		state := action.SelectAttention
		switch {
		case approvalsAll:
			state = action.SelectUnresolved
		case approvalsDecided:
			state = action.SelectDecided
		}
		q := url.Values{"state": {state}}
		if approvalsAfter != "" {
			q.Set("after", approvalsAfter)
		}
		if approvalsLimit > 0 {
			q.Set("limit", fmt.Sprint(approvalsLimit))
		}
		var out approvalsListResponse
		raw, err := approvalsRequest(cmd.Context(), http.MethodGet, "/v1/reviews?"+q.Encode(), nil, &out)
		if err != nil {
			return err
		}
		if approvalsJSON {
			_, err = cmd.OutOrStdout().Write(append(raw, '\n'))
			return err
		}
		printApprovalList(cmd.OutOrStdout(), &out, time.Now().UTC())
		return nil
	},
}

type approvalsListResponse struct {
	Tenant    string                   `json:"tenant"`
	State     string                   `json:"state"`
	Approvals []action.ApprovalSummary `json:"approvals"`
	Next      string                   `json:"next"`
}

// printApprovalList is the compact listing: one line per approval, no
// argument name or value (talon approvals show prints those).
func printApprovalList(w io.Writer, out *approvalsListResponse, now time.Time) {
	what := map[string]string{
		action.SelectAttention:  "Approvals of your groups that need a decision",
		action.SelectUnresolved: "Unresolved approvals of your groups (including ones that can no longer be decided)",
		action.SelectDecided:    "Decided and closed approvals of your groups (newest first)",
	}[out.State]
	if len(out.Approvals) == 0 {
		fmt.Fprintf(w, "%s in tenant %s: none.\n", what, out.Tenant)
	} else {
		fmt.Fprintf(w, "%s in tenant %s:\n\n", what, out.Tenant)
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		if out.State == action.SelectDecided {
			fmt.Fprintln(tw, "APPROVAL\tACTION\tUSE CASE\tOUTCOME\tDECIDED\tBY")
		} else {
			fmt.Fprintln(tw, "APPROVAL\tACTION\tUSE CASE\tSTATE\tEXPIRES\tGROUPS")
		}
		for i := range out.Approvals {
			a := &out.Approvals[i]
			if out.State == action.SelectDecided {
				decided := "-"
				if a.DecidedAt != nil {
					decided = a.DecidedAt.UTC().Format("2006-01-02 15:04Z")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ApprovalID, a.Action, a.UseCase, a.Status, decided, orDash(a.DecidedBy))
				continue
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ApprovalID, a.Action, a.UseCase, listState(a.Eligibility), expiresIn(a.ExpiresAt, now), strings.Join(a.ApproverGroups, ","))
		}
		_ = tw.Flush()
	}
	fmt.Fprintln(w)
	if out.Next != "" {
		fmt.Fprintf(w, "More exist. Next page: talon approvals list%s --after %s\n", listFlag(out.State), out.Next)
	}
	switch out.State {
	case action.SelectAttention:
		fmt.Fprintln(w, "Expired or stale requests: talon approvals list --all    History: talon approvals list --decided")
	case action.SelectUnresolved:
		fmt.Fprintln(w, "Only \"can be decided\" rows accept a decision. History: talon approvals list --decided")
	}
	if len(out.Approvals) > 0 {
		fmt.Fprintln(w, "Exact arguments and the reason approval is required: talon approvals show <approval>")
	}
}

func listFlag(state string) string {
	switch state {
	case action.SelectUnresolved:
		return " --all"
	case action.SelectDecided:
		return " --decided"
	}
	return ""
}

func listState(e action.Eligibility) string {
	if e.Decidable() {
		return "can be decided"
	}
	return strings.ReplaceAll(e.State, "_", " ")
}

// expiresIn is a coarse remaining lifetime, or "expired".
func expiresIn(at, now time.Time) string {
	d := at.Sub(now)
	switch {
	case d <= 0:
		return "expired"
	case d < time.Minute:
		return "in <1m"
	case d < time.Hour:
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()))
	}
	return fmt.Sprintf("in %dd", int(d.Hours()/24))
}

var approvalsShowCmd = &cobra.Command{
	Use:   "show <approval-id>",
	Short: "Show exactly what an approval authorizes, why it is required and what happened to it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var v action.ApprovalView
		raw, err := approvalsRequest(cmd.Context(), http.MethodGet, "/v1/reviews/"+url.PathEscape(args[0]), nil, &v)
		if err != nil {
			return err
		}
		if approvalsJSON {
			_, err = cmd.OutOrStdout().Write(append(raw, '\n'))
			return err
		}
		printReview(cmd.OutOrStdout(), &v, time.Now().UTC(), approvalsTechnical)
		return nil
	},
}

func decideCmd(verb string, approve bool) *cobra.Command {
	return &cobra.Command{
		Use:   verb + " <approval-id> --reason <text>",
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " a pending approval (dispatches nothing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The CLI asks for a reason for BOTH decisions: it is recorded in
			// the signed approval evidence, and an approval without a stated
			// reason is not something an operator should produce by default.
			// The decision API keeps its published v1.16.1 validation (a
			// reason is required for a rejection only, at most 1024
			// characters) so existing API clients keep working.
			if strings.TrimSpace(approvalsReason) == "" {
				return fmt.Errorf("--reason is required: it is recorded in the signed approval evidence")
			}
			decision := "reject"
			if approve {
				decision = "approve"
			}
			body, _ := json.Marshal(map[string]string{"decision": decision, "reason": approvalsReason})
			var out struct {
				Operation struct {
					OperationID string `json:"operation_id"`
					Status      string `json:"operation_status"`
				} `json:"operation"`
				Approval struct {
					ID           string `json:"id"`
					Status       string `json:"status"`
					DecidedBy    string `json:"decided_by"`
					DecidedGroup string `json:"decided_group"`
				} `json:"approval"`
			}
			raw, err := approvalsRequest(cmd.Context(), http.MethodPost, "/v1/approvals/"+url.PathEscape(args[0])+"/decisions", body, &out)
			if err != nil {
				return err
			}
			if approvalsJSON {
				_, err = cmd.OutOrStdout().Write(append(raw, '\n'))
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Approval %s: %s by %s (%s). Operation %s is now %s; nothing was dispatched by this decision.\n",
				out.Approval.ID, out.Approval.Status, out.Approval.DecidedBy, out.Approval.DecidedGroup, out.Operation.OperationID, out.Operation.Status)
			return nil
		},
	}
}

// printReview answers, in this order, what an operator who has never seen
// the request needs: what is asked, by whom, can it still be decided, with
// which exact arguments, where it would go, why approval is required,
// whether the configuration it was established under is still the current
// one, what was decided and what happened afterwards, and how to decide.
// Identifiers, digests and timestamps are printed with --technical. Facts
// bound at establish are never mixed with today's configuration.
func printReview(w io.Writer, v *action.ApprovalView, now time.Time, technical bool) {
	title := v.Action
	if v.ActionDescription != "" {
		title = v.ActionDescription + "  (" + v.Action + ")"
	}
	fmt.Fprintf(w, "%s\n\n", title)
	row := func(label, text string) { fmt.Fprintf(w, "%-14s %s\n", label, text) }
	row("Requested by", fmt.Sprintf("AI use case %s (tenant %s)", v.UseCase, v.Tenant))
	row("Status", reviewStatus(v, now))
	fmt.Fprintf(w, "%-14s %s\n", "", v.Eligibility.Explanation)
	if len(v.Arguments) == 0 {
		row("Arguments", "none declared for review")
	}
	for i, a := range v.Arguments {
		label := ""
		if i == 0 {
			label = "Arguments"
		}
		row(label, fmt.Sprintf("%-16s %s", a.Name, string(a.Value)))
	}
	row("Destination", v.Bound.Destination+"  (bound when the operation was established)")
	row("Why", reviewWhy(v))
	row("Still current", reviewCurrent(v))
	row("Decision", reviewDecision(v))
	row("Outcome", reviewOutcome(v))
	if v.Eligibility.Decidable() {
		row("Approve", fmt.Sprintf("talon approvals approve %s --reason \"...\"", v.ApprovalID))
		row("Reject", fmt.Sprintf("talon approvals reject %s --reason \"...\"", v.ApprovalID))
	}
	row("After approval", v.AfterApproval)
	if !technical {
		row("Technical", fmt.Sprintf("talon approvals show %s --technical   (identifiers, digests, timestamps)", v.ApprovalID))
		return
	}
	fmt.Fprintf(w, "\nTechnical details\n")
	trow := func(label, text string) { fmt.Fprintf(w, "  %-20s %s\n", label, text) }
	trow("Approval", v.ApprovalID)
	trow("Approver groups", strings.Join(v.ApproverGroups, ","))
	trow("Operation", fmt.Sprintf("%s (ref %s), status %s, verdict %s", v.Operation.OperationID, v.Operation.OperationRef, v.Operation.Status, v.Operation.Verdict))
	trow("Established", v.Bound.EstablishedAt.UTC().Format(time.RFC3339))
	trow("Expires", v.ExpiresAt.UTC().Format(time.RFC3339))
	trow("Rule", fmt.Sprintf("%s (%s policy)", v.Bound.RuleID, v.Bound.RuleSource))
	trow("Arguments digest", v.Bound.ArgumentsDigest)
	trow("Policy digest", v.Bound.PolicyDigest)
	trow("Definition digest", v.Bound.DefinitionDigest)
	trow("Compared with", fmt.Sprintf("%s (policy %s, action definition %s)", v.Current.Basis, v.Eligibility.Policy, v.Eligibility.Definition))
	if at := v.Operation.LatestAttempt; at != nil {
		trow("Latest attempt", fmt.Sprintf("#%d %s, request written %t, response observed %t, HTTP %d, %s", at.Ordinal, at.Status, at.RequestWritten, at.ResponseObserved, at.HTTPStatus, at.ResultProvenance))
	}
	trow("Lifecycle evidence", "talon audit verify --operation "+v.Operation.OperationID)
}

func reviewStatus(v *action.ApprovalView, now time.Time) string {
	switch {
	case v.Eligibility.Decidable():
		return fmt.Sprintf("CAN BE DECIDED NOW, expires %s (%s)", v.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"), expiresIn(v.ExpiresAt, now))
	case v.Unresolved:
		return "CANNOT BE DECIDED (" + strings.ReplaceAll(v.Eligibility.State, "_", " ") + "); still unresolved in the store"
	}
	return strings.ToUpper(v.Status)
}

func reviewWhy(v *action.ApprovalView) string {
	layer := v.Bound.RuleSource
	if layer == "" {
		layer = "unknown"
	}
	bound := fmt.Sprintf("rule %s of the %s policy required approval by %s", v.Bound.RuleID, strings.ReplaceAll(layer, "_", " "), strings.Join(v.ApproverGroups, " or "))
	switch {
	case v.Eligibility.Policy == action.BindingUnchanged && v.Current.RulePresent:
		return bound + ". The rule: " + v.Current.Rule
	case v.Current.RulePresent:
		return bound + ". The rule as it reads TODAY (not necessarily as it read then): " + v.Current.Rule
	}
	return bound + ". Its text at that time is not recorded"
}

func reviewCurrent(v *action.ApprovalView) string {
	word := map[string]string{action.BindingUnchanged: "unchanged", action.BindingChanged: "CHANGED since establish", action.BindingUnknown: "unknown"}
	out := fmt.Sprintf("policy %s, action definition %s", word[v.Eligibility.Policy], word[v.Eligibility.Definition])
	if v.Eligibility.Definition == action.BindingChanged && v.Current.Destination != "" {
		out += "; destination today: " + v.Current.Destination
	}
	if v.Current.Note != "" {
		out += " (" + v.Current.Note + ")"
	}
	return out
}

func reviewDecision(v *action.ApprovalView) string {
	d := v.Decision
	if d == nil {
		return "none yet"
	}
	when := ""
	if d.DecidedAt != nil {
		when = " at " + d.DecidedAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	who := d.DecidedBy
	if d.DecidedGroup != "" {
		who += " (group " + d.DecidedGroup + ")"
	}
	out := fmt.Sprintf("%s by %s%s", d.Status, orDash(who), when)
	if d.Reason != "" {
		out += fmt.Sprintf(". Reason: %q", d.Reason)
	}
	return out
}

// reviewOutcome says what happened to the operation. It claims a
// downstream effect only from recorded dispatch facts.
func reviewOutcome(v *action.ApprovalView) string {
	op := v.Operation
	out := "operation " + op.Status
	switch {
	case op.AttemptCount == 0:
		out += "; nothing was dispatched"
	case op.LatestAttempt != nil:
		at := op.LatestAttempt
		out += fmt.Sprintf("; %d dispatch attempt(s), latest %s", op.AttemptCount, at.Status)
		if at.HTTPStatus != 0 {
			out += fmt.Sprintf(", destination answered HTTP %d", at.HTTPStatus)
		}
		if at.ResultProvenance != "" {
			out += " (" + at.ResultProvenance + ")"
		}
	}
	if op.OutcomeCode != "" {
		out += ", outcome " + op.OutcomeCode
	}
	return out
}

// approvalsRequest calls the reviewer API with the approver credential from
// the environment and decodes a 2xx JSON answer into out. A non-2xx answer
// is returned as an error carrying the server's code and message.
func approvalsRequest(ctx context.Context, method, path string, body []byte, out any) ([]byte, error) {
	key := strings.TrimSpace(os.Getenv(approverKeyEnv))
	if key == "" {
		return nil, fmt.Errorf("%s is not set: export the approver credential printed by 'talon approver add' (never pass it as a flag)", approverKeyEnv)
	}
	if !strings.HasPrefix(key, "talon_appr_") {
		return nil, fmt.Errorf("%s does not hold an approver credential (talon_appr_...); admin and agent keys carry no approval authority", approverKeyEnv)
	}
	if err := refusePlaintextRemote(approvalsURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(approvalsURL, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := approvalsHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching the Talon server at %s: %w", approvalsURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return nil, fmt.Errorf("the server at %s answered with a redirect (HTTP %d); the approver credential is sent only to the URL you gave, so the redirect was not followed. Pass the final URL with --url", approvalsURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, approvalsServerError(resp.StatusCode, path, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("decoding the server answer: %w", err)
	}
	return raw, nil
}

// approvalsServerError renders a non-2xx answer with the server's code and
// message when it sent them.
func approvalsServerError(status int, path string, raw []byte) error {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
		return fmt.Errorf("%s (HTTP %d): %s", e.Error.Code, status, e.Error.Message)
	}
	return fmt.Errorf("HTTP %d from %s", status, path)
}

// approvalsHTTPClient never follows a redirect (#565 review). The request
// carries the approver credential; a redirect could name another host, or
// the same host over plain http, and the credential must reach only the
// URL the operator gave (which refusePlaintextRemote has already checked).
var approvalsHTTPClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// refusePlaintextRemote keeps the approver credential off the network in
// clear text: plain http is accepted for loopback only, unless the operator
// states that the path is protected (a private link or a TLS-terminating
// proxy on the same host) with --allow-plaintext.
func refusePlaintextRemote(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("--url %q is not a valid URL", raw)
	}
	if u.Scheme == "https" || approvalsAllowPlaintext {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing to send the approver credential over plain http to %s: use an https URL, or pass --allow-plaintext when the network path is protected", u.Host)
}

func init() {
	approvalsCmd.PersistentFlags().BoolVar(&approvalsAllowPlaintext, "allow-plaintext", false, "send the credential over plain http to a non-loopback host (only on a protected network path)")
	approvalsCmd.PersistentFlags().StringVar(&approvalsURL, "url", "http://localhost:8080", "base URL of the running Talon server")
	approvalsCmd.PersistentFlags().BoolVar(&approvalsJSON, "json", false, "print the server's JSON answer")
	approve := decideCmd("approve", true)
	reject := decideCmd("reject", false)
	for _, c := range []*cobra.Command{approve, reject} {
		c.Flags().StringVar(&approvalsReason, "reason", "", "why (recorded in the signed approval evidence; required)")
	}
	approvalsListCmd.Flags().BoolVar(&approvalsAll, "all", false, "also list pending approvals that can no longer be decided (expired, or bound to a changed policy or action definition)")
	approvalsListCmd.Flags().BoolVar(&approvalsDecided, "decided", false, "list decided and closed approvals (approved, rejected, expired, invalidated), newest first")
	approvalsListCmd.Flags().StringVar(&approvalsAfter, "after", "", "continue after the cursor a previous listing printed")
	approvalsListCmd.Flags().IntVar(&approvalsLimit, "limit", 0, "rows per page (1..100; default 100)")
	approvalsShowCmd.Flags().BoolVar(&approvalsTechnical, "technical", false, "also print identifiers, digests and timestamps")
	approvalsCmd.AddCommand(approvalsListCmd, approvalsShowCmd, approve, reject)
	rootCmd.AddCommand(approvalsCmd)
}
