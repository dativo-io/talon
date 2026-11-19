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
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
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
	// approvalsAll also lists pending approvals that can no longer be decided.
	approvalsAll bool
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
	Short: "List the approvals you can decide now (oldest first); --all adds expired and stale ones",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var out struct {
			Tenant  string           `json:"tenant"`
			Reviews []reviewResponse `json:"reviews"`
			More    bool             `json:"more"`
		}
		path := "/v1/reviews"
		if approvalsAll {
			path += "?state=all"
		}
		raw, err := approvalsRequest(cmd.Context(), http.MethodGet, path, nil, &out)
		if err != nil {
			return err
		}
		if approvalsJSON {
			_, err = cmd.OutOrStdout().Write(append(raw, '\n'))
			return err
		}
		w := cmd.OutOrStdout()
		if len(out.Reviews) == 0 {
			if approvalsAll {
				fmt.Fprintf(w, "No pending approvals of your groups in tenant %s.\n", out.Tenant)
			} else {
				fmt.Fprintf(w, "No approvals you can decide now in tenant %s. ('talon approvals list --all' also shows expired and stale requests.)\n", out.Tenant)
			}
			return nil
		}
		if approvalsAll {
			fmt.Fprintf(w, "Pending approvals of your groups in tenant %s (those you can decide first, oldest first):\n\n", out.Tenant)
		} else {
			fmt.Fprintf(w, "Approvals you can decide now in tenant %s (oldest first):\n\n", out.Tenant)
		}
		for i := range out.Reviews {
			r := &out.Reviews[i]
			fmt.Fprintf(w, "  %s  %-16s  %s  %s  op %s  expires %s  %s\n", r.Operation.Approval.ID, r.Actionability, r.UseCase, r.Operation.Action, r.Operation.OperationID,
				r.Operation.Approval.ExpiresAt.UTC().Format(time.RFC3339), compactReview(r.Operation.Review))
		}
		if out.More {
			fmt.Fprintf(w, "\nMORE exist beyond these %d (the oldest are shown first). Decide these, then list again.\n", len(out.Reviews))
		}
		fmt.Fprintf(w, "\nShow one with: talon approvals show <approval-id>\n")
		return nil
	},
}

var approvalsShowCmd = &cobra.Command{
	Use:   "show <approval-id>",
	Short: "Show exactly what an approval would authorize",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var r reviewResponse
		raw, err := approvalsRequest(cmd.Context(), http.MethodGet, "/v1/reviews/"+args[0], nil, &r)
		if err != nil {
			return err
		}
		if approvalsJSON {
			_, err = cmd.OutOrStdout().Write(append(raw, '\n'))
			return err
		}
		printReview(cmd.OutOrStdout(), &r)
		return nil
	},
}

func decideCmd(verb string, approve bool) *cobra.Command {
	return &cobra.Command{
		Use:   verb + " <approval-id> --reason <text>",
		Short: strings.ToUpper(verb[:1]) + verb[1:] + " a pending approval (dispatches nothing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(approvalsReason) == "" {
				return fmt.Errorf("--reason is required: it is recorded in the signed approval evidence")
			}
			decision := "reject"
			if approve {
				decision = "approve"
			}
			body, _ := json.Marshal(map[string]string{"decision": decision, "reason": approvalsReason})
			var out struct {
				Operation reviewOperation `json:"operation"`
				Approval  reviewApproval  `json:"approval"`
			}
			raw, err := approvalsRequest(cmd.Context(), http.MethodPost, "/v1/approvals/"+args[0]+"/decisions", body, &out)
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

type reviewApproval struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"`
	RuleID       string    `json:"rule_id"`
	Groups       []string  `json:"approver_groups"`
	ExpiresAt    time.Time `json:"expires_at"`
	DecidedBy    string    `json:"decided_by"`
	DecidedGroup string    `json:"decided_group"`
}

type reviewOperation struct {
	OperationID       string                     `json:"operation_id"`
	Action            string                     `json:"action"`
	Status            string                     `json:"operation_status"`
	Verdict           string                     `json:"verdict"`
	MatchedRuleID     string                     `json:"matched_rule_id"`
	MatchedRuleSource string                     `json:"matched_rule_source"`
	Digest            string                     `json:"digest"`
	Review            map[string]json.RawMessage `json:"review"`
	Approval          *reviewApproval            `json:"approval"`
}

type reviewResponse struct {
	Operation     reviewOperation `json:"operation"`
	UseCase       string          `json:"use_case"`
	Tenant        string          `json:"tenant"`
	Actionable    bool            `json:"actionable"`
	Actionability string          `json:"actionability"`
	Explanation   string          `json:"explanation"`
	AfterApproval string          `json:"after_approval"`
	Bound         struct {
		RuleID           string    `json:"rule_id"`
		RuleSource       string    `json:"rule_source"`
		Destination      string    `json:"destination"`
		ArgumentsDigest  string    `json:"arguments_digest"`
		DefinitionDigest string    `json:"definition_digest"`
		PolicyDigest     string    `json:"policy_digest"`
		EstablishedAt    time.Time `json:"established_at"`
	} `json:"bound"`
	Current struct {
		PolicyUnchanged     bool   `json:"policy_unchanged"`
		DefinitionUnchanged bool   `json:"definition_unchanged"`
		Rule                string `json:"rule"`
		RulePresent         bool   `json:"rule_present"`
		Destination         string `json:"destination"`
		ActionDescription   string `json:"action_description"`
	} `json:"current"`
}

func compactReview(review map[string]json.RawMessage) string {
	keys := make([]string, 0, len(review))
	for k := range review {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+string(review[k]))
	}
	return strings.Join(parts, " ")
}

// printReview answers, in this order, what an unfamiliar reviewer needs:
// can I still decide, who asks for what, with which exact arguments, where
// it would go, why approval is required, and what an approval does. Facts
// bound when the operation was established are kept apart from the
// configuration enforced now; today's configuration is never printed as if
// it were the operation's history.
func printReview(w io.Writer, r *reviewResponse) {
	op := &r.Operation
	status := "CAN BE DECIDED NOW"
	if !r.Actionable {
		status = "CANNOT BE DECIDED (" + r.Actionability + ")"
	}
	fmt.Fprintf(w, "Status:            %s: %s\n", status, r.Explanation)
	if a := op.Approval; a != nil {
		fmt.Fprintf(w, "Approval:          %s, %s, groups %s, expires %s\n", a.ID, a.Status, strings.Join(a.Groups, ","), a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(w, "\nRequested by:      AI use case %s (tenant %s)\n", r.UseCase, r.Tenant)
	fmt.Fprintf(w, "Action:            %s\n", op.Action)
	if r.Current.ActionDescription != "" {
		fmt.Fprintf(w, "                   %s (description from the current catalog)\n", r.Current.ActionDescription)
	}
	fmt.Fprintf(w, "Operation:         %s (%s), established %s\n", op.OperationID, op.Status, r.Bound.EstablishedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Arguments you approve (exact values; the digest binds them):\n")
	keys := make([]string, 0, len(op.Review))
	for k := range op.Review {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "  %-16s %s\n", k, string(op.Review[k]))
	}
	fmt.Fprintf(w, "Arguments digest:  %s\n", r.Bound.ArgumentsDigest)

	fmt.Fprintf(w, "\nBound when the operation was established (from its record):\n")
	fmt.Fprintf(w, "  Destination:     %s\n", r.Bound.Destination)
	fmt.Fprintf(w, "  Required by:     rule %s (%s policy), verdict %s\n", r.Bound.RuleID, r.Bound.RuleSource, op.Verdict)
	fmt.Fprintf(w, "  Policy digest:   %s\n", r.Bound.PolicyDigest)
	fmt.Fprintf(w, "  Definition:      %s\n", r.Bound.DefinitionDigest)

	fmt.Fprintf(w, "\nConfiguration enforced now:\n")
	switch {
	case r.Current.PolicyUnchanged && r.Current.RulePresent:
		fmt.Fprintf(w, "  Policy:          unchanged since establish. The rule: %s\n", r.Current.Rule)
	case r.Current.RulePresent:
		fmt.Fprintf(w, "  Policy:          CHANGED since establish. Rule %s as it reads TODAY (not necessarily as it read then): %s\n", r.Bound.RuleID, r.Current.Rule)
	case r.Current.PolicyUnchanged:
		fmt.Fprintf(w, "  Policy:          unchanged since establish.\n")
	default:
		fmt.Fprintf(w, "  Policy:          CHANGED since establish. The current policy has no rule %s; its original text is not recorded.\n", r.Bound.RuleID)
	}
	switch {
	case r.Current.DefinitionUnchanged:
		fmt.Fprintf(w, "  Action definition: unchanged since establish (destination as bound).\n")
	case r.Current.Destination != "":
		fmt.Fprintf(w, "  Action definition: CHANGED since establish. Destination today: %s\n", r.Current.Destination)
	default:
		fmt.Fprintf(w, "  Action definition: CHANGED since establish. The action is no longer catalogued.\n")
	}
	fmt.Fprintf(w, "\nAfter approval:    %s\n", r.AfterApproval)
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching the Talon server at %s: %w", approvalsURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
			return nil, fmt.Errorf("%s (HTTP %d): %s", e.Error.Code, resp.StatusCode, e.Error.Message)
		}
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("decoding the server answer: %w", err)
	}
	return raw, nil
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
	approvalsCmd.AddCommand(approvalsListCmd, approvalsShowCmd, approve, reject)
	rootCmd.AddCommand(approvalsCmd)
}
