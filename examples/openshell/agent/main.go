// Command support-agent is the reference TOOL-USING agent for the Talon ↔
// NVIDIA OpenShell composition (#457/#482). It runs inside an OpenShell
// sandbox, holds no Talon credential, and lets a real model choose tools
// through the official OpenAI Go SDK's chat-completions tool calling:
//
//	model request  → OpenShell → Talon middleware (policy, PII, budget) → provider
//	tool execution → OpenShell → Talon middleware hop (sandbox identity →
//	                 workload assertion) → Talon Action Gateway (exact
//	                 authorization, human approval, at-most-once dispatch)
//
// The agent never talks to the protected business systems: every tool is a
// Talon action. It is a support assistant with three tools — read a ticket
// (allowed), delete a customer (forbidden by policy), create a refund
// request (requires a human approval) — and it walks whatever path the
// model picks, reporting one KEY=VALUE line per step so an operator or a
// harness can follow it and then reconstruct it from Talon's evidence.
//
// Business-operation identity is STABLE: an operation id is derived from the
// run's operation prefix, the tool and the exact arguments, never from a
// process id or a counter. A restarted agent that intends the same refund
// therefore addresses the same Talon operation: Talon answers with the
// existing operation (created: false) and the agent resumes from its real
// status — waits for the pending approval, claims an authorized one once,
// or reports an already-succeeded one — instead of creating a second
// refund. Talon's ledger is the source of truth; the optional local journal
// (AGENT_STATE_DIR) is an operator-readable continuation record. Outcomes
// Talon reports as unknown are reported as unresolved and never retried
// into a second effect.
//
// Environment (set by the operator or the harness; never secrets):
//
//	TALON_BASE               Talon's HTTP API as the sandbox dials it (required)
//	PROVIDER_BASE            the model API as the sandbox dials it, e.g. http://host.openshell.internal:9000 (required)
//	TALON_SESSION            session id sent on every request (joins model and action records in evidence)
//	OPERATION_ID             prefix for the operation ids of this run (default agent-<session>)
//	TICKET_ID                the ticket to handle (default T-1842)
//	MODEL                    chat model (default gpt-4o-mini)
//	APPROVAL_WAIT_S          how long to wait for the human reviewer (default 120)
//	MAX_TURNS                model turns before giving up (default 8)
//	AGENT_STATE_DIR          optional directory for the continuation journal
//	AGENT_ADVERSARIAL_PROBE  "1": after the model turns, deliberately attempt the forbidden
//	                         action through the Action Gateway (labelled ADVERSARIAL=…) to
//	                         prove the execution boundary refuses it even when the model never asks
//	OPENAI_API_KEY           a placeholder: OpenShell injects the real credential after Talon decided
//
// Exit codes: 0 the scenario completed as governed; 1 a step was refused
// (the Talon code is printed); 2 the reviewer rejected or the approval
// expired; 3 no reviewer decision within APPROVAL_WAIT_S; 4 a transport or
// SDK failure; 5 an operation's downstream outcome is unresolved (unknown)
// and must be reconciled by an operator — the agent will not retry it.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"
)

// version and commit are set by the release build (-X main.version/-X main.commit).
var (
	version = "dev"
	commit  = "unknown"
)

const (
	exitOK         = 0
	exitRefused    = 1
	exitRejected   = 2
	exitTimeout    = 3
	exitTransport  = 4
	exitUnresolved = 5
)

// config is everything the agent reads from its environment.
type config struct {
	talonBase, providerBase string
	session, opPrefix       string
	ticketID, model, apiKey string
	wait                    time.Duration
	maxTurns                int
	stateDir                string
	adversarial             bool
	pollInterval            time.Duration
}

func configFromEnv() (config, error) {
	c := config{
		talonBase:    strings.TrimRight(os.Getenv("TALON_BASE"), "/"),
		providerBase: strings.TrimRight(os.Getenv("PROVIDER_BASE"), "/"),
		session:      envOr("TALON_SESSION", ""),
		ticketID:     envOr("TICKET_ID", "T-1842"),
		model:        envOr("MODEL", string(openai.ChatModelGPT4oMini)),
		apiKey:       envOr("OPENAI_API_KEY", "placeholder-replaced-by-openshell"),
		wait:         time.Duration(envInt("APPROVAL_WAIT_S", 120)) * time.Second,
		maxTurns:     envInt("MAX_TURNS", 8),
		stateDir:     strings.TrimSpace(os.Getenv("AGENT_STATE_DIR")),
		adversarial:  os.Getenv("AGENT_ADVERSARIAL_PROBE") == "1",
		pollInterval: 2 * time.Second,
	}
	if c.talonBase == "" || c.providerBase == "" {
		return c, fmt.Errorf("TALON_BASE and PROVIDER_BASE are required")
	}
	if c.session == "" {
		c.session = fmt.Sprintf("sess-support-agent-%d", time.Now().UnixNano())
	}
	// The operation prefix is the run's business identity; it must survive a
	// restart, so it defaults to the session, never to the process id.
	c.opPrefix = envOr("OPERATION_ID", "agent-"+c.session)
	return c, nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "probe":
			os.Exit(probe(os.Args[2:], os.Stdout))
		case "version":
			fmt.Printf("support-agent %s (%s)\n", version, commit)
			os.Exit(exitOK)
		}
	}
	cfg, err := configFromEnv()
	if err != nil {
		fmt.Printf("RESULT=failed STEP=config ERROR=%s\n", err)
		os.Exit(exitTransport)
	}
	os.Exit(run(context.Background(), cfg, os.Stdout))
}

// probe is the sandbox-side reachability check the showcase runner uses:
// `support-agent probe <url>...` attempts one GET per URL and prints
// PROBE=<url> REACHABLE=yes|no. It carries no credential and sends no body;
// the runner uses it to prove that the protected business service is NOT
// reachable from the sandbox while Talon's host is.
func probe(urls []string, out io.Writer) int {
	if len(urls) == 0 {
		fmt.Fprintln(out, "usage: support-agent probe <url> [url...]")
		return exitTransport
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, u := range urls {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil) //nolint:gosec // operator-supplied probe targets by design
		if err != nil {
			fmt.Fprintf(out, "PROBE=%s REACHABLE=no ERROR=%s\n", u, sanitize(err.Error()))
			continue
		}
		resp, err := client.Do(req) //nolint:gosec // operator-supplied probe targets by design
		if err != nil {
			fmt.Fprintf(out, "PROBE=%s REACHABLE=no ERROR=%s\n", u, sanitize(err.Error()))
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		fmt.Fprintf(out, "PROBE=%s REACHABLE=yes STATUS=%d\n", u, resp.StatusCode)
	}
	return exitOK
}

type agent struct {
	cfg     config
	out     io.Writer
	http    *http.Client
	journal *journal
}

func (a *agent) printf(format string, args ...any) { fmt.Fprintf(a.out, format+"\n", args...) }

// run is the whole scenario; it returns the process exit code.
func run(ctx context.Context, cfg config, out io.Writer) int {
	a := &agent{cfg: cfg, out: out, http: &http.Client{Timeout: 45 * time.Second}}
	if cfg.stateDir != "" {
		j, err := openJournal(cfg.stateDir, cfg.opPrefix)
		if err != nil {
			a.printf("RESULT=failed STEP=journal ERROR=%s", sanitize(err.Error()))
			return exitTransport
		}
		a.journal = j
		if n := len(j.Operations); n > 0 {
			a.printf("RESUME=%d operation(s) in the journal for prefix %s", n, cfg.opPrefix)
		}
	}
	// The credential is a placeholder: OpenShell's supervisor replaces the
	// Authorization header with the provider credential it owns, after
	// Talon has decided the request. The session header joins this model
	// traffic to the action records below in Talon's evidence.
	client := openai.NewClient(
		option.WithBaseURL(cfg.providerBase+"/v1"),
		option.WithAPIKey(cfg.apiKey),
		option.WithHeader("X-Talon-Session-ID", cfg.session),
		option.WithHTTPClient(a.http),
		option.WithMaxRetries(0),
	)
	params := openai.ChatCompletionNewParams{
		Model: shared.ChatModel(cfg.model),
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("You are a customer-support assistant. Use the tools to look up the ticket, then handle the customer's request. Refunds need a human reviewer; propose exactly the amount the ticket justifies."),
			openai.UserMessage(fmt.Sprintf("The customer on ticket %s asks for a EUR 50 refund for a late delivery. Look up the ticket and handle the refund.", cfg.ticketID)),
		},
		Tools: tools(),
	}
	a.printf("TOOLS_OFFERED=%s", strings.Join(toolNames(params.Tools), ","))

	for turn := 1; turn <= cfg.maxTurns; turn++ {
		completion, err := client.Chat.Completions.New(ctx, params)
		if err != nil {
			a.printf("RESULT=failed STEP=model TURN=%d ERROR=%s", turn, sanitize(err.Error()))
			return exitTransport
		}
		if len(completion.Choices) == 0 {
			a.printf("RESULT=failed STEP=model TURN=%d ERROR=no choices", turn)
			return exitTransport
		}
		msg := completion.Choices[0].Message
		a.printf("MODEL=ok TURN=%d TOKENS=%d/%d TOOL_CALLS=%d", turn, completion.Usage.PromptTokens, completion.Usage.CompletionTokens, len(msg.ToolCalls))
		params.Messages = append(params.Messages, msg.ToParam())
		if len(msg.ToolCalls) == 0 {
			a.printf("FINAL=%s", sanitize(strings.TrimSpace(msg.Content)))
			return a.finish(ctx)
		}
		for i := range msg.ToolCalls {
			call := &msg.ToolCalls[i]
			result, code := a.runTool(ctx, call.Function.Name, call.Function.Arguments, "model")
			if code != exitOK {
				return code
			}
			params.Messages = append(params.Messages, openai.ToolMessage(result, call.ID))
		}
	}
	a.printf("RESULT=failed STEP=model ERROR=no final answer after %d turns", cfg.maxTurns)
	return exitRefused
}

// finish runs the labelled adversarial probe when asked for and prints the
// final verdict. The probe is NOT a model decision: it proves that the
// execution boundary refuses the forbidden action even when the model never
// asked for it (a real provider may never choose it).
func (a *agent) finish(ctx context.Context) int {
	if a.cfg.adversarial {
		_, code := a.runTool(ctx, "delete_customer", `{"customer_id":"c-9"}`, "adversarial")
		if code != exitOK {
			return code
		}
	}
	a.printf("RESULT=succeeded")
	return exitOK
}

// tools are the three Talon actions the assistant may ask for. Talon's
// request-side tool governance may remove forbidden tools before the model
// sees them; the agent still dispatches whatever the model asks for through
// Talon, which is where authorization is decided.
func tools() []openai.ChatCompletionToolParam {
	fn := func(name, desc string, params map[string]any) openai.ChatCompletionToolParam {
		return openai.ChatCompletionToolParam{Function: shared.FunctionDefinitionParam{
			Name: name, Description: openai.String(desc), Parameters: shared.FunctionParameters(params),
		}}
	}
	return []openai.ChatCompletionToolParam{
		fn("lookup_ticket", "Read one support ticket", map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"ticket_id"},
			"properties": map[string]any{"ticket_id": map[string]any{"type": "string"}},
		}),
		fn("create_refund_request", "Create a refund request for a support ticket (a human reviewer approves it)", map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"ticket_id", "amount", "currency"},
			"properties": map[string]any{
				"ticket_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"},
				"currency": map[string]any{"type": "string", "enum": []string{"EUR", "USD"}},
			},
		}),
		fn("delete_customer", "Delete a customer record", map[string]any{
			"type": "object", "additionalProperties": false,
			"properties": map[string]any{"customer_id": map[string]any{"type": "string"}},
		}),
	}
}

func toolNames(ts []openai.ChatCompletionToolParam) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Function.Name)
	}
	return out
}

// operationIDFor is the stable business identity of one intended action:
// the run prefix, the tool, and a digest of the canonical arguments. The
// same intent in a restarted process yields the same id, so the Action
// Gateway's exact-operation semantics (same id + same payload → the existing
// operation; same id + different payload → conflict) apply across restarts.
func operationIDFor(prefix, tool string, args json.RawMessage) string {
	sum := sha256.Sum256(canonicalJSON(args))
	id := prefix + "-" + tool + "-" + hex.EncodeToString(sum[:])[:12]
	if len(id) > 128 {
		id = id[len(id)-128:]
	}
	return id
}

// canonicalJSON re-encodes a JSON value with sorted object keys.
func canonicalJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []byte(`{}`)
	}
	var buf bytes.Buffer
	writeCanonical(&buf, v)
	return buf.Bytes()
}

func writeCanonical(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			writeCanonical(buf, x[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, e)
		}
		buf.WriteByte(']')
	default:
		b, _ := json.Marshal(x)
		buf.Write(b)
	}
}

// runTool executes one tool through Talon's Action Gateway under its stable
// operation id: establish (or re-find) the exact operation, resume from its
// real status, and — once authorized — claim the attempt so Talon dispatches
// at most once. origin is "model" or "adversarial" (labelling only).
// Returns the tool result the model gets and a non-zero exit code when the
// scenario cannot continue.
//
//nolint:gocyclo // one operation state machine; the branches are its states
func (a *agent) runTool(ctx context.Context, name, rawArgs, origin string) (result string, exitCode int) {
	args := json.RawMessage(rawArgs)
	if !json.Valid(args) {
		args = json.RawMessage(`{}`)
	}
	opID := operationIDFor(a.cfg.opPrefix, name, args)
	a.journalSet(name, opID, "establishing")
	est, _ := json.Marshal(map[string]any{"operation_id": opID, "action": name, "arguments": args})
	code, body := a.talon(ctx, http.MethodPost, "/v1/action-operations", est)
	created, _ := body["created"].(bool)
	status, _ := dig(body, "operation", "operation_status").(string)
	switch code {
	case http.StatusForbidden:
		// Policy denied the exact action: evidenced by Talon, nothing
		// dispatched. The model learns the action is not available.
		a.journalSet(name, opID, "denied")
		if origin == "adversarial" {
			a.printf("ADVERSARIAL=denied TOOL=%s OPERATION=%s CODE=%s (deliberate probe, not a model decision)", name, opID, firstString(body, "code", "verdict"))
		} else {
			a.printf("DENIED=%s OPERATION=%s CODE=%s", name, opID, firstString(body, "code", "verdict"))
		}
		return toolResult(map[string]any{"status": "denied", "action": name, "reason": "the policy of this AI use case forbids this action"}), exitOK
	case http.StatusConflict:
		a.printf("RESULT=failed STEP=%s_establish CODE=%d ERROR=%s (the same operation id with different arguments: the business intent changed; a new intent needs a new run prefix)", name, code, firstString(body, "code"))
		return "", exitRefused
	case http.StatusAccepted, http.StatusCreated, http.StatusOK:
	default:
		a.printf("RESULT=failed STEP=%s_establish CODE=%d ERROR=%s", name, code, firstString(body, "code"))
		return "", exitRefused
	}
	if origin == "adversarial" {
		// A forbidden action that was NOT denied is a finding, not a step.
		a.printf("ADVERSARIAL=NOT_DENIED TOOL=%s OPERATION=%s STATUS=%s", name, opID, status)
		return "", exitRefused
	}
	if !created {
		a.printf("RESUMED=%s OPERATION=%s STATUS=%s", name, opID, status)
	} else {
		a.printf("OPERATION_REF=%s VERDICT=%s OPERATION=%s", dig(body, "operation", "operation_ref"), dig(body, "operation", "verdict"), opID)
	}
	return a.resume(ctx, name, opID, body)
}

// resume drives one established operation from its current status to a
// terminal outcome. It is the same path for a fresh operation and for one
// re-found after a restart.
//
//nolint:gocyclo // the operation status machine
func (a *agent) resume(ctx context.Context, name, opID string, body map[string]any) (result string, exitCode int) {
	status, _ := dig(body, "operation", "operation_status").(string)
	switch status {
	case "awaiting_approval":
		approvalID, _ := dig(body, "operation", "approval", "id").(string)
		if approvalID == "" {
			a.printf("RESULT=failed STEP=%s_approval ERROR=no approval reference", name)
			return "", exitRefused
		}
		a.journalSet(name, opID, "awaiting_approval")
		a.printf("APPROVAL_ID=%s OPERATION=%s", approvalID, opID)
		if rc := a.awaitApproval(ctx, approvalID); rc != exitOK {
			return "", rc
		}
	case "authorized":
	case "executing":
		// Another process is mid-dispatch: never race it; read until it
		// settles, then report what Talon says.
		final, ok := a.awaitTerminal(ctx, opID)
		if !ok {
			a.printf("RESULT=unresolved STEP=%s OPERATION=%s STATUS=executing", name, opID)
			return "", exitUnresolved
		}
		return a.resume(ctx, name, opID, final)
	case "succeeded":
		a.journalSet(name, opID, "succeeded")
		a.printf("ATTEMPT=already_succeeded TOOL=%s OPERATION=%s (no new effect)", name, opID)
		return toolResult(map[string]any{"status": "succeeded", "action": name, "operation_id": opID, "note": "completed in an earlier run"}), exitOK
	case "denied":
		a.printf("DENIED=%s OPERATION=%s CODE=%s", name, opID, firstString(body, "outcome_code", "code"))
		return toolResult(map[string]any{"status": "denied", "action": name}), exitOK
	case "unknown":
		a.journalSet(name, opID, "unknown")
		a.printf("RESULT=unresolved STEP=%s OPERATION=%s STATUS=unknown (downstream outcome unknown; reconcile with the operator, do not retry)", name, opID)
		return "", exitUnresolved
	case "failed", "cancelled":
		a.printf("RESULT=failed STEP=%s OPERATION=%s STATUS=%s CODE=%s", name, opID, status, firstString(body, "outcome_code", "code"))
		return "", exitRefused
	default:
		a.printf("RESULT=failed STEP=%s OPERATION=%s ERROR=unexpected status %q", name, opID, status)
		return "", exitRefused
	}
	// Authorized: claim the attempt. Talon revalidates and dispatches at
	// most once; a repeated claim never duplicates the effect.
	code, body := a.talon(ctx, http.MethodPost, "/v1/action-operations/"+opID+"/attempts", nil)
	switch {
	case code == http.StatusOK:
	case code == http.StatusConflict && firstString(body, "code") == "operation_already_succeeded":
		a.journalSet(name, opID, "succeeded")
		a.printf("ATTEMPT=already_succeeded TOOL=%s OPERATION=%s (no new effect)", name, opID)
		return toolResult(map[string]any{"status": "succeeded", "action": name, "operation_id": opID}), exitOK
	default:
		a.printf("RESULT=failed STEP=%s_claim CODE=%d ERROR=%s", name, code, firstString(body, "code"))
		return "", exitRefused
	}
	attempt, _ := dig(body, "attempt", "status").(string)
	a.printf("ATTEMPT=%s TOOL=%s OPERATION=%s", attempt, name, opID)
	switch attempt {
	case "succeeded":
		a.journalSet(name, opID, "succeeded")
	case "unknown":
		// Dispatched, outcome not observed: the effect may or may not have
		// happened. This is an operator reconciliation, never a retry.
		a.journalSet(name, opID, "unknown")
		a.printf("RESULT=unresolved STEP=%s OPERATION=%s STATUS=unknown (dispatched; downstream outcome unobserved)", name, opID)
		return "", exitUnresolved
	default:
		a.journalSet(name, opID, attempt)
		a.printf("RESULT=failed STEP=%s OPERATION=%s ATTEMPT=%s CODE=%s", name, opID, attempt, firstString(body, "code"))
		return "", exitRefused
	}
	if name == "create_refund_request" {
		// Replay safety: the same claim again never produces a second effect.
		_, replay := a.talon(ctx, http.MethodPost, "/v1/action-operations/"+opID+"/attempts", nil)
		a.printf("REPLAY=%s", firstString(replay, "code"))
	}
	return toolResult(map[string]any{"status": attempt, "action": name, "operation_id": opID, "result": dig(body, "attempt", "result")}), exitOK
}

// awaitApproval polls the sandbox-readable approval state. The sandbox can
// read its approval; it can never decide it (the reviewer route is not
// reachable through the hop).
func (a *agent) awaitApproval(ctx context.Context, approvalID string) int {
	deadline := time.Now().Add(a.cfg.wait)
	for {
		code, body := a.talon(ctx, http.MethodGet, "/v1/approvals/"+approvalID, nil)
		if code != http.StatusOK {
			a.printf("RESULT=failed STEP=approval_read CODE=%d ERROR=%s", code, firstString(body, "code"))
			return exitRefused
		}
		switch st, _ := dig(body, "approval", "status").(string); st {
		case "approved":
			a.printf("APPROVAL=approved")
			return exitOK
		case "rejected", "expired", "invalidated":
			a.printf("RESULT=refused APPROVAL=%s", st)
			return exitRejected
		}
		if time.Now().After(deadline) {
			a.printf("RESULT=timeout APPROVAL=pending (rerun with the same TALON_SESSION and OPERATION_ID to resume this operation)")
			return exitTimeout
		}
		select {
		case <-ctx.Done():
			return exitTransport
		case <-time.After(a.cfg.pollInterval):
		}
	}
}

// awaitTerminal reads an executing operation until it leaves "executing" or
// the approval wait elapses.
func (a *agent) awaitTerminal(ctx context.Context, opID string) (map[string]any, bool) {
	deadline := time.Now().Add(a.cfg.wait)
	for {
		code, body := a.talon(ctx, http.MethodGet, "/v1/action-operations/"+opID, nil)
		if code == http.StatusOK {
			if st, _ := dig(body, "operation", "operation_status").(string); st != "executing" {
				return body, true
			}
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(a.cfg.pollInterval):
		}
	}
}

// talon performs one Action Gateway call. No credential: OpenShell's hop
// supplies Talon's request-bound workload assertion.
func (a *agent) talon(ctx context.Context, method, path string, body []byte) (status int, parsed map[string]any) {
	req, err := http.NewRequestWithContext(ctx, method, a.cfg.talonBase+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Session-ID", a.cfg.session)
	resp, err := a.http.Do(req)
	if err != nil {
		a.printf("TRANSPORT_ERROR=%s", sanitize(err.Error()))
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, out
}

// ---- journal ----------------------------------------------------------

// journal is the agent's operator-readable continuation record: which
// operation ids this run prefix has addressed and their last known status.
// Talon remains the source of truth; the journal exists so a restarted
// agent (or an operator) can see what a previous process was doing.
type journal struct {
	path       string
	Prefix     string                  `json:"operation_prefix"`
	UpdatedAt  string                  `json:"updated_at"`
	Operations map[string]journalEntry `json:"operations"`
}

type journalEntry struct {
	Tool        string `json:"tool"`
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	UpdatedAt   string `json:"updated_at"`
}

func openJournal(dir, prefix string) (*journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	j := &journal{path: filepath.Join(dir, sanitizeFile(prefix)+".journal.json"), Prefix: prefix, Operations: map[string]journalEntry{}}
	raw, err := os.ReadFile(j.path)
	switch {
	case err == nil:
		if uerr := json.Unmarshal(raw, j); uerr != nil {
			return nil, fmt.Errorf("journal %s is not readable: %w", j.path, uerr)
		}
		if j.Prefix != prefix {
			return nil, fmt.Errorf("journal %s belongs to prefix %q, not %q", j.path, j.Prefix, prefix)
		}
		if j.Operations == nil {
			j.Operations = map[string]journalEntry{}
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	return j, nil
}

func (a *agent) journalSet(tool, opID, status string) {
	if a.journal == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	a.journal.Operations[opID] = journalEntry{Tool: tool, OperationID: opID, Status: status, UpdatedAt: now}
	a.journal.UpdatedAt = now
	b, _ := json.MarshalIndent(a.journal, "", "  ")
	tmp := a.journal.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, a.journal.path)
	}
}

func sanitizeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// ---- helpers ----------------------------------------------------------

func toolResult(v map[string]any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

// firstString finds the first non-empty string under any of keys, looking
// at the top level, the error envelope and the operation projection.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		for _, scope := range []map[string]any{m, asMap(m["error"]), asMap(m["operation"])} {
			if s, ok := scope[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// sanitize keeps the report single-line and free of anything that looks
// like a bearer credential.
func sanitize(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
	if i := strings.Index(s, "Bearer "); i >= 0 {
		s = s[:i] + "Bearer [redacted]"
	}
	return s
}
