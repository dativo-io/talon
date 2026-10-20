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
// Environment (set by the operator or the harness; never secrets):
//
//	TALON_BASE       Talon's HTTP API as the sandbox dials it (required)
//	PROVIDER_BASE    the model API as the sandbox dials it, e.g. http://host.openshell.internal:9000 (required)
//	TALON_SESSION    session id sent on every request (joins model and action records in evidence)
//	OPERATION_ID     prefix for the operation ids of this run (default agent-<pid>)
//	TICKET_ID        the ticket to handle (default T-1842)
//	MODEL            chat model (default gpt-4o-mini)
//	APPROVAL_WAIT_S  how long to wait for the human reviewer (default 120)
//	MAX_TURNS        model turns before giving up (default 8)
//	OPENAI_API_KEY   a placeholder: OpenShell injects the real credential after Talon decided
//
// Exit codes: 0 the scenario completed as governed; 1 a step was refused
// (the Talon code is printed); 2 the reviewer rejected or the approval
// expired; 3 no reviewer decision within APPROVAL_WAIT_S; 4 a transport or
// SDK failure.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"
)

type agent struct {
	talonBase string
	session   string
	opPrefix  string
	ticketID  string
	wait      time.Duration
	http      *http.Client
	toolSeq   int
}

func main() {
	os.Exit(run())
}

func run() int {
	talonBase := os.Getenv("TALON_BASE")
	providerBase := os.Getenv("PROVIDER_BASE")
	if talonBase == "" || providerBase == "" {
		fmt.Println("RESULT=failed STEP=config ERROR=TALON_BASE and PROVIDER_BASE are required")
		return 4
	}
	a := &agent{
		talonBase: strings.TrimRight(talonBase, "/"),
		session:   envOr("TALON_SESSION", fmt.Sprintf("sess-support-agent-%d", os.Getpid())),
		opPrefix:  envOr("OPERATION_ID", fmt.Sprintf("agent-%d", os.Getpid())),
		ticketID:  envOr("TICKET_ID", "T-1842"),
		wait:      time.Duration(envInt("APPROVAL_WAIT_S", 120)) * time.Second,
		http:      &http.Client{Timeout: 45 * time.Second},
	}
	model := envOr("MODEL", string(openai.ChatModelGPT4oMini))
	maxTurns := envInt("MAX_TURNS", 8)

	// The credential is a placeholder: OpenShell's supervisor replaces the
	// Authorization header with the provider credential it owns, after
	// Talon has decided the request. The session header joins this model
	// traffic to the action records below in Talon's evidence.
	client := openai.NewClient(
		option.WithBaseURL(strings.TrimRight(providerBase, "/")+"/v1"),
		option.WithAPIKey(envOr("OPENAI_API_KEY", "placeholder-replaced-by-openshell")),
		option.WithHeader("X-Talon-Session-ID", a.session),
		option.WithHTTPClient(a.http),
		option.WithMaxRetries(0),
	)
	params := openai.ChatCompletionNewParams{
		Model: shared.ChatModel(model),
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("You are a customer-support assistant. Use the tools to look up the ticket, then handle the customer's request. Refunds need a human reviewer; propose exactly the amount the ticket justifies."),
			openai.UserMessage(fmt.Sprintf("The customer on ticket %s asks for a EUR 50 refund for a late delivery. Look up the ticket and handle the refund.", a.ticketID)),
		},
		Tools: tools(),
	}
	fmt.Printf("TOOLS_OFFERED=%s\n", strings.Join(toolNames(params.Tools), ","))

	ctx := context.Background()
	for turn := 1; turn <= maxTurns; turn++ {
		completion, err := client.Chat.Completions.New(ctx, params)
		if err != nil {
			fmt.Printf("RESULT=failed STEP=model TURN=%d ERROR=%s\n", turn, sanitize(err.Error()))
			return 4
		}
		if len(completion.Choices) == 0 {
			fmt.Printf("RESULT=failed STEP=model TURN=%d ERROR=no choices\n", turn)
			return 4
		}
		msg := completion.Choices[0].Message
		fmt.Printf("MODEL=ok TURN=%d TOKENS=%d/%d TOOL_CALLS=%d\n", turn, completion.Usage.PromptTokens, completion.Usage.CompletionTokens, len(msg.ToolCalls))
		params.Messages = append(params.Messages, msg.ToParam())
		if len(msg.ToolCalls) == 0 {
			fmt.Printf("FINAL=%s\n", sanitize(strings.TrimSpace(msg.Content)))
			fmt.Println("RESULT=succeeded")
			return 0
		}
		for i := range msg.ToolCalls {
			call := &msg.ToolCalls[i]
			result, code := a.runTool(ctx, call.Function.Name, call.Function.Arguments)
			if code != 0 {
				return code
			}
			params.Messages = append(params.Messages, openai.ToolMessage(result, call.ID))
		}
	}
	fmt.Printf("RESULT=failed STEP=model ERROR=no final answer after %d turns\n", maxTurns)
	return 1
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

// runTool executes one model-chosen tool through Talon's Action Gateway:
// establish the exact operation, then — once authorized — claim the
// attempt so Talon dispatches at most once. Returns the tool result the
// model gets and a non-zero exit code when the scenario cannot continue.
func (a *agent) runTool(ctx context.Context, name, rawArgs string) (result string, exitCode int) {
	a.toolSeq++
	opID := fmt.Sprintf("%s-%s-%d", a.opPrefix, name, a.toolSeq)
	args := json.RawMessage(rawArgs)
	if !json.Valid(args) {
		args = json.RawMessage(`{}`)
	}
	est, _ := json.Marshal(map[string]any{"operation_id": opID, "action": name, "arguments": args})
	code, body := a.talon(ctx, http.MethodPost, "/v1/action-operations", est)
	switch code {
	case http.StatusForbidden:
		// Policy denied the exact action: evidenced by Talon, nothing
		// dispatched. The model learns the action is not available.
		fmt.Printf("DENIED=%s OPERATION=%s CODE=%s\n", name, opID, firstString(body, "code", "verdict"))
		return toolResult(map[string]any{"status": "denied", "action": name, "reason": "the policy of this AI use case forbids this action"}), 0
	case http.StatusAccepted:
		fmt.Printf("OPERATION_REF=%s\n", dig(body, "operation", "operation_ref"))
		approvalID, _ := dig(body, "operation", "approval", "id").(string)
		if approvalID == "" {
			fmt.Printf("RESULT=failed STEP=%s_approval CODE=%d ERROR=no approval reference\n", name, code)
			return "", 1
		}
		fmt.Printf("APPROVAL_ID=%s\n", approvalID)
		if rc := a.awaitApproval(ctx, approvalID); rc != 0 {
			return "", rc
		}
	case http.StatusCreated, http.StatusOK:
		fmt.Printf("OPERATION_REF=%s VERDICT=%s\n", dig(body, "operation", "operation_ref"), dig(body, "operation", "verdict"))
	default:
		fmt.Printf("RESULT=failed STEP=%s_establish CODE=%d ERROR=%s\n", name, code, firstString(body, "code"))
		return "", 1
	}
	// Authorized: claim the attempt. Talon revalidates and dispatches at
	// most once; a repeated claim never duplicates the effect.
	code, body = a.talon(ctx, http.MethodPost, "/v1/action-operations/"+opID+"/attempts", nil)
	if code != http.StatusOK {
		fmt.Printf("RESULT=failed STEP=%s_claim CODE=%d ERROR=%s\n", name, code, firstString(body, "code"))
		return "", 1
	}
	status, _ := dig(body, "attempt", "status").(string)
	fmt.Printf("ATTEMPT=%s TOOL=%s OPERATION=%s\n", status, name, opID)
	if name == "create_refund_request" {
		_, replay := a.talon(ctx, http.MethodPost, "/v1/action-operations/"+opID+"/attempts", nil)
		fmt.Printf("REPLAY=%s\n", firstString(replay, "code"))
	}
	return toolResult(map[string]any{"status": status, "action": name, "operation_id": opID, "result": dig(body, "attempt", "result")}), 0
}

// awaitApproval polls the sandbox-readable approval state. The sandbox can
// read its approval; it can never decide it (the reviewer route is not
// reachable through the hop).
func (a *agent) awaitApproval(ctx context.Context, approvalID string) int {
	deadline := time.Now().Add(a.wait)
	for {
		code, body := a.talon(ctx, http.MethodGet, "/v1/approvals/"+approvalID, nil)
		if code != http.StatusOK {
			fmt.Printf("RESULT=failed STEP=approval_read CODE=%d ERROR=%s\n", code, firstString(body, "code"))
			return 1
		}
		switch st, _ := dig(body, "approval", "status").(string); st {
		case "approved":
			fmt.Println("APPROVAL=approved")
			return 0
		case "rejected", "expired", "invalidated":
			fmt.Printf("RESULT=refused APPROVAL=%s\n", st)
			return 2
		}
		if time.Now().After(deadline) {
			fmt.Println("RESULT=timeout APPROVAL=pending")
			return 3
		}
		select {
		case <-ctx.Done():
			return 4
		case <-time.After(2 * time.Second):
		}
	}
}

// talon performs one Action Gateway call. No credential: OpenShell's hop
// supplies Talon's request-bound workload assertion.
func (a *agent) talon(ctx context.Context, method, path string, body []byte) (status int, parsed map[string]any) {
	req, err := http.NewRequestWithContext(ctx, method, a.talonBase+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Talon-Session-ID", a.session)
	resp, err := a.http.Do(req)
	if err != nil {
		fmt.Printf("TRANSPORT_ERROR=%s\n", sanitize(err.Error()))
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
