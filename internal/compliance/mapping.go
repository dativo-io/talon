package compliance

// ControlMapping links Talon controls to compliance framework articles.
type ControlMapping struct {
	Framework string `json:"framework"`
	Article   string `json:"article"`
	Control   string `json:"control"`
	Source    string `json:"source"`
}

// DefaultMappings returns built-in article-level mappings used in reports.
func DefaultMappings() []ControlMapping {
	return []ControlMapping{
		{Framework: "gdpr", Article: "Art. 30", Control: "Processing records via signed evidence export", Source: "internal/evidence/store.go"},
		{Framework: "gdpr", Article: "Art. 32", Control: "PII detection and model/data-tier routing", Source: "internal/classifier/pii.go"},
		{Framework: "gdpr", Article: "Art. 44-50", Control: "EU data residency routing controls", Source: "internal/policy/rego/routing.rego"},
		{Framework: "eu-ai-act", Article: "Art. 11", Control: "Technical documentation through execution plans and evidence", Source: "internal/agent/plan.go"},
		{Framework: "eu-ai-act", Article: "Art. 13", Control: "Transparency via execution/model/cost traceability", Source: "internal/evidence/store.go"},
		{Framework: "eu-ai-act", Article: "Art. 14", Control: "Human oversight via plan review gate", Source: "internal/agent/plan_review.go"},
		{Framework: "nis2", Article: "Art. 21", Control: "Risk controls, policy enforcement, and monitoring", Source: "internal/policy/engine.go"},
		{Framework: "dora", Article: "Art. 11", Control: "ICT incident traceability with signed audit trail", Source: "internal/evidence/store.go"},
		{Framework: "iso-27001", Article: "A.8.15", Control: "Cryptographic integrity of logs (HMAC)", Source: "internal/evidence/signature.go"},
		{Framework: "iso-27001", Article: "A.8.16", Control: "Monitoring and governance metrics", Source: "internal/gateway/metrics.go"},
	}
}
