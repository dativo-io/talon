// Command seed writes a People Analytics–shaped Talon installation for the
// console's browser tests (#539–#545): agent, gateway and MCP proxy files and
// an evidence store filled through the production write path (records are
// HMAC-signed by evidence.Store exactly as the gateway and MCP proxy sign
// them), plus one managed session row and one deliberately tampered record.
// It prints the fixture's expectations as JSON so the browser tests assert
// against the same facts the seed wrote, not against copies.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/dativo-io/talon/internal/evidence"
	"github.com/dativo-io/talon/internal/explanation"
	"github.com/dativo-io/talon/internal/session"
)

type expectations struct {
	Dir             string `json:"dir"`
	UseCase         string `json:"use_case"`
	DisabledUseCase string `json:"disabled_use_case"`
	Session         string `json:"session"`
	ManagedSession  string `json:"managed_session"`
	SharedExternal  string `json:"shared_external"`
	AllowedID       string `json:"allowed_evidence"`
	ExportDeniedID  string `json:"export_denied_evidence"`
	HRRejectedID    string `json:"hr_rejected_evidence"`
	LLMID           string `json:"llm_evidence"`
	StandaloneID    string `json:"standalone_evidence"`
	TamperedID      string `json:"tampered_evidence"`
	CacheHitID      string `json:"cache_hit_evidence"`
	LongSession     string `json:"long_session"`
	ForeignUseCase  string `json:"foreign_currency_use_case"`
	Records         int    `json:"records"`
	Correlation     string `json:"correlation"`
	LLMCost         string `json:"llm_cost"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func write(path, body string) {
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, []byte(body), 0o600))
}

func main() {
	dir := flag.String("dir", "", "installation directory to create")
	key := flag.String("signing-key", "", "evidence signing key (the console must use the same)")
	flag.Parse()
	if *dir == "" || *key == "" {
		must(fmt.Errorf("-dir and -signing-key are required"))
	}
	ctx := context.Background()
	write(filepath.Join(*dir, "agents/hr-analytics-assistant/agent.talon.yaml"), `agent:
  name: hr-analytics-assistant
  description: People Analytics copilot over aggregated workforce data
  version: "1.0.0"
  key:
    secret_name: hr-analytics-assistant-talon-key
  use_case:
    purpose: Answer workforce questions from aggregates only
    department: People
    owners:
      technical: platform-team
capabilities:
  allowed_tools: ["hr_aggregate_sql"]
  forbidden_tools: ["hr_employee_export"]
policies:
  cost_limits:
    daily: 5
    monthly: 50
  data_classification:
    input_scan: true
    output_scan: true
`)
	write(filepath.Join(*dir, "agents/support-bot/agent.talon.yaml"), `agent:
  name: support-bot
  version: "1.0.0"
  enabled: false
policies:
  cost_limits:
    monthly: 20
`)
	write(filepath.Join(*dir, "agents/eu-reports/agent.talon.yaml"), `agent:
  name: eu-reports
  version: "1.0.0"
policies:
  cost_limits:
    daily: 1
    monthly: 10
`)
	write(filepath.Join(*dir, "talon.config.yaml"), `gateway:
  enabled: true
  providers:
    openai:
      enabled: true
      base_url: "https://api.openai.com"
      secret_name: openai-api-key
      allowed_models: ["gpt-4o-mini"]
  organization_policy:
    defaults:
      pii_action: redact
      daily_cost: 100
    constraints:
      forbidden_tools: ["admin_*"]
`)
	write(filepath.Join(*dir, "proxy.talon.yaml"), `agent:
  name: hr-mcp-proxy
  type: mcp_proxy
proxy:
  upstream:
    vendor: hr-backend
    url: "http://hr-upstream:9000/mcp"
  allowed_tools:
    - name: hr_aggregate_sql
  forbidden_tools: ["hr_employee_export"]
`)

	dbPath := filepath.Join(*dir, "evidence.db")
	store, err := evidence.NewStore(dbPath, *key)
	must(err)
	defer store.Close()
	sessions, err := session.NewStore(dbPath)
	must(err)
	defer sessions.Close()

	now := time.Now().UTC().Add(-90 * time.Minute)
	if now.Day() != time.Now().UTC().Day() {
		now = time.Now().UTC().Add(-2 * time.Minute) // keep the fixture inside today's UTC day
	}
	at := func(m int) time.Time { return now.Add(time.Duration(m) * time.Second * 20) }
	const agent, sess, corr = "hr-analytics-assistant", "pa-session-1", "corr-pa-aggregate"
	allow := evidence.PolicyDecision{Allowed: true, Action: "allow"}
	deny := evidence.PolicyDecision{Allowed: false, Action: "deny", Reasons: []string{"forbidden_tools"}}
	put := func(ev *evidence.Evidence) {
		if ev.TenantID == "" {
			ev.TenantID = "default"
		}
		must(store.Store(ctx, ev))
	}
	put(&evidence.Evidence{
		ID: "pa-allowed-aggregate", CorrelationID: corr, SessionID: sess, AgentID: agent, Timestamp: at(0),
		InvocationType: "proxy_tool_call", RequestSourceID: "hr-backend", PolicyDecision: allow,
		Execution:    evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}, DurationMS: 84},
		Explanations: []explanation.Item{{Code: "POLICY_ALLOWED", Decision: "allow", Stage: "tool_execution", Reason: "Request allowed by policy.", Trigger: "hr_aggregate_sql"}},
	})
	put(&evidence.Evidence{
		ID: "pa-export-denied", CorrelationID: "corr-pa-export", SessionID: sess, AgentID: agent, Timestamp: at(1),
		InvocationType: "proxy_tool_blocked", RequestSourceID: "hr-backend", PolicyDecision: deny,
		Execution:    evidence.Execution{ToolsCalled: []string{"hr_employee_export"}, Error: "forbidden_tools"},
		Explanations: []explanation.Item{{Code: "POLICY_DENIED_TOOL", Decision: "deny", Stage: "tool_execution", Reason: "Request blocked by tool access policy.", Trigger: "hr_employee_export", Fix: "Use allowed tool or extend allowlist."}},
	})
	put(&evidence.Evidence{
		ID: "pa-hr-rejected", CorrelationID: "corr-pa-badsql", SessionID: sess, AgentID: agent, Timestamp: at(2),
		InvocationType: "proxy_upstream_error", RequestSourceID: "hr-backend", PolicyDecision: allow,
		Status: evidence.StatusFailed, FailureReason: "upstream_error",
		Execution:    evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}, Error: "upstream_jsonrpc_error:invalid_params"},
		Explanations: []explanation.Item{{Code: "EXECUTION_FAILED", Decision: "failure", Stage: "tool_execution", Reason: "Request failed during execution.", Trigger: "upstream_jsonrpc_error:invalid_params"}},
	})
	put(&evidence.Evidence{
		ID: "pa-llm-answer", CorrelationID: "corr-pa-llm", SessionID: sess, AgentID: agent, Timestamp: at(3),
		InvocationType: "gateway", PolicyDecision: allow,
		Execution:    evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.0123, Currency: "USD", PricingKnown: true, DurationMS: 640, Tokens: evidence.TokenUsage{Input: 820, Output: 140}},
		Explanations: []explanation.Item{{Code: "POLICY_ALLOWED", Decision: "allow", Stage: "policy_evaluation", Reason: "Request allowed by policy."}},
	})
	put(&evidence.Evidence{
		ID: "pa-standalone", CorrelationID: "corr-pa-standalone", AgentID: agent, Timestamp: at(4),
		InvocationType: "gateway", PolicyDecision: allow,
		Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.001, Currency: "USD", PricingKnown: true, DurationMS: 210},
	})
	// Two AI use cases asserting the same external session id stay separate.
	put(&evidence.Evidence{ID: "shared-a", CorrelationID: "corr-shared-a", SessionID: "shared-ext", AgentID: agent, Timestamp: at(5), InvocationType: "proxy_tool_call", PolicyDecision: allow, Execution: evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}}})
	put(&evidence.Evidence{ID: "shared-b", CorrelationID: "corr-shared-b", SessionID: "shared-ext", AgentID: "support-bot", Timestamp: at(6), InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini"}})
	put(&evidence.Evidence{ID: "pa-tampered", CorrelationID: "corr-pa-tampered", AgentID: agent, Timestamp: at(7), InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.002, Currency: "USD", PricingKnown: true}})

	// A cache hit as the gateway writes it: allowed, cache_hit, no provider call.
	put(&evidence.Evidence{
		ID: "pa-cache-hit", CorrelationID: "corr-pa-cache", SessionID: sess, AgentID: agent, Timestamp: at(9),
		InvocationType: "gateway", PolicyDecision: allow, CacheHit: true, CacheEntryID: "cache-entry-1", CostSaved: 0.0123,
		Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Currency: "USD"},
	})
	// Spend recorded in EUR while the pricing table is USD: not comparable with the caps.
	put(&evidence.Evidence{
		ID: "eu-spend", CorrelationID: "corr-eu", AgentID: "eu-reports", Timestamp: at(10), InvocationType: "gateway", PolicyDecision: allow,
		Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 2.5, Currency: "EUR", PricingKnown: true},
	})
	// A long session (60 records) for timeline paging.
	for i := 0; i < 60; i++ {
		put(&evidence.Evidence{
			ID: fmt.Sprintf("long-%02d", i), CorrelationID: fmt.Sprintf("corr-long-%02d", i), SessionID: "pa-long", AgentID: agent,
			Timestamp: at(20 + i), InvocationType: "proxy_tool_call", PolicyDecision: allow, Execution: evidence.Execution{ToolsCalled: []string{"hr_aggregate_sql"}},
		})
	}

	managed, err := sessions.Create(ctx, "default", agent, "guided people analytics run", 1.0)
	must(err)
	put(&evidence.Evidence{ID: "pa-managed-call", CorrelationID: "corr-pa-managed", SessionID: managed.ID, AgentID: agent, Timestamp: at(8), InvocationType: "gateway", PolicyDecision: allow, Execution: evidence.Execution{ModelUsed: "gpt-4o-mini", Cost: 0.004, Currency: "USD", PricingKnown: true}})
	must(sessions.Complete(ctx, managed.ID, "default", agent, 0.004, 120))

	// Tamper: change the stored record after signing, as an attacker with
	// file access would. Verification must report invalid.
	raw, err := sql.Open("sqlite3", dbPath)
	must(err)
	_, err = raw.ExecContext(ctx, `UPDATE evidence SET evidence_json = replace(evidence_json, '"cost":0.002', '"cost":0.000') WHERE id = 'pa-tampered'`)
	must(err)
	must(raw.Close())

	count, _, err := store.Stats(ctx)
	must(err)
	out := expectations{
		Dir: *dir, UseCase: agent, DisabledUseCase: "support-bot", Session: sess, ManagedSession: managed.ID, SharedExternal: "shared-ext",
		AllowedID: "pa-allowed-aggregate", ExportDeniedID: "pa-export-denied", HRRejectedID: "pa-hr-rejected", LLMID: "pa-llm-answer",
		StandaloneID: "pa-standalone", TamperedID: "pa-tampered", Correlation: corr, LLMCost: "$0.0123",
		CacheHitID: "pa-cache-hit", LongSession: "pa-long", ForeignUseCase: "eu-reports", Records: count,
	}
	must(json.NewEncoder(os.Stdout).Encode(out))
}
