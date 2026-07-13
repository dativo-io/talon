package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dativo-io/talon/internal/compliance"
)

// Policy represents a complete .talon.yaml configuration (v2.0 schema).
type Policy struct {
	Agent              AgentConfig                      `yaml:"agent" json:"agent"`
	Capabilities       *CapabilitiesConfig              `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Triggers           *TriggersConfig                  `yaml:"triggers,omitempty" json:"triggers,omitempty"`
	Secrets            *SecretsConfig                   `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Memory             *MemoryConfig                    `yaml:"memory,omitempty" json:"memory,omitempty"`
	Context            *ContextConfig                   `yaml:"context,omitempty" json:"context,omitempty"`
	AttachmentHandling *AttachmentHandlingConfig        `yaml:"attachment_handling,omitempty" json:"attachment_handling,omitempty"`
	Policies           PoliciesConfig                   `yaml:"policies" json:"policies"`
	ToolPolicies       map[string]ToolPIIPolicy         `yaml:"tool_policies,omitempty" json:"tool_policies,omitempty"`
	ToolGovernance     map[string]ToolIdempotencyConfig `yaml:"tool_governance,omitempty" json:"tool_governance,omitempty"`
	Audit              *AuditConfig                     `yaml:"audit,omitempty" json:"audit,omitempty"`
	Compliance         *ComplianceConfig                `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	Metadata           *MetadataConfig                  `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	Copaw              *CopawConfig                     `yaml:"copaw,omitempty" json:"copaw,omitempty"` // CoPaw skill governance (when using CoPaw integration)

	// Computed fields (not serialized from YAML)
	Hash       string `yaml:"-" json:"-"`
	VersionTag string `yaml:"-" json:"-"`
}

// AgentConfig holds the agent identity. One agent.talon.yaml = one AI use
// case = one Talon traffic identity (#266).
type AgentConfig struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string `yaml:"version" json:"version"`
	ModelTier   int    `yaml:"model_tier,omitempty" json:"model_tier,omitempty"`
	// TenantID is the tenant this AI use case belongs to. An agent belongs to
	// exactly one tenant; key → agent → tenant_id is the only tenant
	// derivation, authoritative for gateway traffic AND native runs (#266).
	// Empty means "default".
	TenantID string `yaml:"tenant_id,omitempty" json:"tenant_id,omitempty"`
	// Enabled is the operational on/off switch (#268): false denies NEW work
	// for this agent (gateway requests, native runs, scheduled triggers) with
	// an explicit reason; in-flight work finishes. Pointer so absence is
	// distinguishable (nil = true, mirroring AcceptClientMetadata) and the
	// canonical digest only changes when an operator actually sets it.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Key binds this agent's one active Talon traffic key. Required for every
	// agent loaded into the gateway identity registry (a missing binding fails
	// startup); optional for native-only, non-traffic-bound runs.
	Key *AgentKeyBinding `yaml:"key,omitempty" json:"key,omitempty"`
	// AcceptClientMetadata controls whether client-asserted orchestration
	// identity (x-claude-code-* / Codex / generic X-Talon-* headers) is
	// recorded in evidence for this agent's gateway traffic. nil = true
	// (default). Recording only — never a policy input in v1 (#194).
	AcceptClientMetadata *bool `yaml:"accept_client_metadata,omitempty" json:"accept_client_metadata,omitempty"`
}

// IsEnabled reports the agent's operational state (#268). nil (unset) = true.
func (a *AgentConfig) IsEnabled() bool {
	return a == nil || a.Enabled == nil || *a.Enabled
}

// AgentKeyBinding references the agent's one active Talon key in the encrypted
// vault. Policy files are committed to Git, so the binding is a vault secret
// NAME — never raw key material (the schema rejects any other field here).
// Rotation = `talon secrets set <secret_name> <new>` + restart; one active key
// per agent, structurally.
type AgentKeyBinding struct {
	SecretName string `yaml:"secret_name" json:"secret_name"`
}

// CapabilitiesConfig defines what the agent is allowed to do.
type CapabilitiesConfig struct {
	AllowedTools        []string `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`
	AllowedDataSources  []string `yaml:"allowed_data_sources,omitempty" json:"allowed_data_sources,omitempty"`
	ForbiddenPatterns   []string `yaml:"forbidden_patterns,omitempty" json:"forbidden_patterns,omitempty"`
	DestructivePatterns []string `yaml:"destructive_patterns,omitempty" json:"destructive_patterns,omitempty"`
	// ForbiddenTools lists tool NAMES denied for this agent's gateway traffic
	// (unioned with the organization baseline and provider restrictions).
	// Distinct from ForbiddenPatterns, which are command/content patterns for
	// the native runner (#266).
	ForbiddenTools []string `yaml:"forbidden_tools,omitempty" json:"forbidden_tools,omitempty"`
	// ToolPolicyAction is the gateway enforcement mode when a request declares
	// disallowed tools: "filter" strips them from the request, "block" rejects
	// the request. Empty inherits the organization baseline.
	ToolPolicyAction string `yaml:"tool_policy_action,omitempty" json:"tool_policy_action,omitempty"`
}

// TriggersConfig defines automatic execution triggers.
type TriggersConfig struct {
	Schedule []ScheduleTrigger `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	Webhooks []WebhookTrigger  `yaml:"webhooks,omitempty" json:"webhooks,omitempty"`
}

// ScheduleTrigger is a cron-based agent trigger.
type ScheduleTrigger struct {
	Cron        string `yaml:"cron" json:"cron"`
	Prompt      string `yaml:"prompt" json:"prompt"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// WebhookTrigger is an HTTP-webhook-based agent trigger.
type WebhookTrigger struct {
	Name            string `yaml:"name" json:"name"`
	Source          string `yaml:"source" json:"source"`
	PromptTemplate  string `yaml:"prompt_template" json:"prompt_template"`
	RequireApproval bool   `yaml:"require_approval,omitempty" json:"require_approval,omitempty"`
}

// SecretsConfig defines which vault entries the agent can access.
type SecretsConfig struct {
	Allowed   []SecretACL `yaml:"allowed,omitempty" json:"allowed,omitempty"`
	Forbidden []SecretACL `yaml:"forbidden,omitempty" json:"forbidden,omitempty"`
}

// SecretACL is a single secret access control entry.
type SecretACL struct {
	Name    string `yaml:"name" json:"name"`
	Purpose string `yaml:"purpose,omitempty" json:"purpose,omitempty"`
}

// MemoryConfig governs the agent's self-improvement memory.
type MemoryConfig struct {
	Enabled             bool                    `yaml:"enabled" json:"enabled"`
	Mode                string                  `yaml:"mode,omitempty" json:"mode,omitempty"` // "active" (default), "shadow", "disabled"
	MaxEntries          int                     `yaml:"max_entries,omitempty" json:"max_entries,omitempty"`
	MaxEntrySizeKB      int                     `yaml:"max_entry_size_kb,omitempty" json:"max_entry_size_kb,omitempty"`
	MaxPromptTokens     int                     `yaml:"max_prompt_tokens,omitempty" json:"max_prompt_tokens,omitempty"` // cap memory tokens injected into prompts
	RetentionDays       int                     `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	ReviewMode          string                  `yaml:"review_mode,omitempty" json:"review_mode,omitempty"`
	AllowedCategories   []string                `yaml:"allowed_categories,omitempty" json:"allowed_categories,omitempty"`
	ForbiddenCategories []string                `yaml:"forbidden_categories,omitempty" json:"forbidden_categories,omitempty"`
	PromptCategories    []string                `yaml:"prompt_categories,omitempty" json:"prompt_categories,omitempty"` // categories to include in LLM prompt (empty = all)
	Audit               bool                    `yaml:"audit,omitempty" json:"audit,omitempty"`
	Governance          *MemoryGovernanceConfig `yaml:"governance,omitempty" json:"governance,omitempty"`
}

// MemoryGovernanceConfig controls memory conflict detection, trust scoring, and deduplication.
type MemoryGovernanceConfig struct {
	ConflictResolution          string  `yaml:"conflict_resolution,omitempty" json:"conflict_resolution,omitempty"`
	ConflictSimilarityThreshold float64 `yaml:"conflict_similarity_threshold,omitempty" json:"conflict_similarity_threshold,omitempty"`
	TrustScoreOverrides         bool    `yaml:"trust_score_overrides,omitempty" json:"trust_score_overrides,omitempty"`
	DedupWindowMinutes          int     `yaml:"dedup_window_minutes,omitempty" json:"dedup_window_minutes,omitempty"` // Skip memory write if same input_hash within window (0 = disabled)
}

// ContextConfig defines shared enterprise context mounts.
type ContextConfig struct {
	SharedMounts []SharedMount `yaml:"shared_mounts,omitempty" json:"shared_mounts,omitempty"`
}

// SharedMount is a read-only enterprise knowledge mount.
type SharedMount struct {
	Name           string `yaml:"name" json:"name"`
	Path           string `yaml:"path" json:"path"`
	Description    string `yaml:"description,omitempty" json:"description,omitempty"`
	Classification string `yaml:"classification" json:"classification"`
}

// AttachmentHandlingConfig controls prompt injection prevention.
type AttachmentHandlingConfig struct {
	Mode                string            `yaml:"mode,omitempty" json:"mode,omitempty"`
	RequireUserApproval []string          `yaml:"require_user_approval,omitempty" json:"require_user_approval,omitempty"`
	AutoAllow           []string          `yaml:"auto_allow,omitempty" json:"auto_allow,omitempty"`
	Scanning            *ScanningConfig   `yaml:"scanning,omitempty" json:"scanning,omitempty"`
	Sandboxing          *SandboxingConfig `yaml:"sandboxing,omitempty" json:"sandboxing,omitempty"`
}

// ScanningConfig controls attachment instruction detection.
type ScanningConfig struct {
	DetectInstructions bool   `yaml:"detect_instructions" json:"detect_instructions"`
	ActionOnDetection  string `yaml:"action_on_detection,omitempty" json:"action_on_detection,omitempty"`
}

// SandboxingConfig controls attachment content isolation.
type SandboxingConfig struct {
	WrapContent bool `yaml:"wrap_content" json:"wrap_content"`
}

// SessionLimitsConfig sets per-session budget and candidate/judge caps for RULER-style evaluation.
type SessionLimitsConfig struct {
	MaxCost       float64 `yaml:"max_cost,omitempty" json:"max_cost,omitempty"`
	MaxCandidates int     `yaml:"max_candidates,omitempty" json:"max_candidates,omitempty"`
	MaxJudgeCalls int     `yaml:"max_judge_calls,omitempty" json:"max_judge_calls,omitempty"`
}

// PoliciesConfig is the main governance section.
type PoliciesConfig struct {
	CostLimits         *CostLimitsConfig         `yaml:"cost_limits" json:"cost_limits"`
	ResourceLimits     *ResourceLimitsConfig     `yaml:"resource_limits,omitempty" json:"resource_limits,omitempty"`
	RateLimits         *RateLimitsConfig         `yaml:"rate_limits,omitempty" json:"rate_limits,omitempty"`
	DataClassification *DataClassificationConfig `yaml:"data_classification,omitempty" json:"data_classification,omitempty"`
	SemanticEnrichment *SemanticEnrichmentConfig `yaml:"semantic_enrichment,omitempty" json:"semantic_enrichment,omitempty"`
	ModelRouting       *ModelRoutingConfig       `yaml:"model_routing,omitempty" json:"model_routing,omitempty"`
	TimeRestrictions   *TimeRestrictionsConfig   `yaml:"time_restrictions,omitempty" json:"time_restrictions,omitempty"`
	SessionLimits      *SessionLimitsConfig      `yaml:"session_limits,omitempty" json:"session_limits,omitempty"`
	// Models are flat allow/block lists for this agent's gateway traffic.
	// Distinct from ModelRouting, which is the runner-side tier-based routing
	// preference — Models decides what MAY be called, ModelRouting decides
	// what the runner PREFERS to call (#266).
	Models *ModelsConfig `yaml:"models,omitempty" json:"models,omitempty"`
	// AllowedProviders restricts which gateway providers this agent may reach.
	// Empty = all enabled providers.
	AllowedProviders []string `yaml:"allowed_providers,omitempty" json:"allowed_providers,omitempty"`
	// Egress is a second boundary evaluated alongside the organization egress
	// for this agent's gateway traffic: a destination must pass BOTH (logical
	// intersection); the agent narrows within the org boundary, never widens
	// or replaces it (#266).
	Egress *EgressConfig `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// ModelsConfig is the agent's flat model allow/block list for gateway traffic.
type ModelsConfig struct {
	Allowed []string `yaml:"allowed,omitempty" json:"allowed,omitempty"`
	Blocked []string `yaml:"blocked,omitempty" json:"blocked,omitempty"`
}

// EgressConfig mirrors the gateway egress policy YAML shape (which
// destinations each data tier may egress to). It is a pure data mirror — the
// serve-time bridge converts it to the gateway's egress policy type, where
// semantic validation lives. Kept here so the policy package does not import
// the gateway package.
type EgressConfig struct {
	DefaultAction string             `yaml:"default_action,omitempty" json:"default_action,omitempty"` // allow (default) | deny
	Rules         []EgressRuleConfig `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// EgressRuleConfig permits destinations for a single data tier.
type EgressRuleConfig struct {
	Tier             *TierValue `yaml:"tier" json:"tier"`
	AllowedProviders []string   `yaml:"allowed_providers,omitempty" json:"allowed_providers,omitempty"`
	AllowedRegions   []string   `yaml:"allowed_regions,omitempty" json:"allowed_regions,omitempty"`
}

// SemanticEnrichmentConfig controls PII placeholder semantic attributes (e.g. gender, scope).
// Mode: off = no enrichment; shadow = compute and log only; enforce = emit attributes when allowed by policy.
type SemanticEnrichmentConfig struct {
	Enabled               bool     `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Mode                  string   `yaml:"mode,omitempty" json:"mode,omitempty"` // off | shadow | enforce
	ConfidenceThreshold   float64  `yaml:"confidence_threshold,omitempty" json:"confidence_threshold,omitempty"`
	EmitUnknownAttributes bool     `yaml:"emit_unknown_attributes,omitempty" json:"emit_unknown_attributes,omitempty"`
	DefaultPersonGender   string   `yaml:"default_person_gender,omitempty" json:"default_person_gender,omitempty"`
	DefaultLocationScope  string   `yaml:"default_location_scope,omitempty" json:"default_location_scope,omitempty"`
	PreserveTitles        bool     `yaml:"preserve_titles,omitempty" json:"preserve_titles,omitempty"`
	LocaleHintSource      string   `yaml:"locale_hint_source,omitempty" json:"locale_hint_source,omitempty"`
	AllowedAttributes     []string `yaml:"allowed_attributes,omitempty" json:"allowed_attributes,omitempty"` // e.g. ["gender", "scope"]
}

// CostLimitsConfig sets per-request, daily, and monthly cost budgets.
type CostLimitsConfig struct {
	PerRequest         float64            `yaml:"per_request,omitempty" json:"per_request,omitempty"`
	Daily              float64            `yaml:"daily,omitempty" json:"daily,omitempty"`
	Monthly            float64            `yaml:"monthly,omitempty" json:"monthly,omitempty"`
	Degradation        *DegradationConfig `yaml:"degradation,omitempty" json:"degradation,omitempty"`
	BudgetAlertWebhook string             `yaml:"budget_alert_webhook,omitempty" json:"budget_alert_webhook,omitempty"` // Optional URL; POST when usage >= 80% of daily or monthly
}

// DegradationConfig enables graceful model downgrade when budget threshold is reached.
// When enabled and daily budget used >= threshold_percent, router uses fallback_model instead of primary.
type DegradationConfig struct {
	Enabled          bool    `yaml:"enabled" json:"enabled"`
	ThresholdPercent float64 `yaml:"threshold_percent" json:"threshold_percent"`
	FallbackModel    string  `yaml:"fallback_model" json:"fallback_model"`
	Notify           bool    `yaml:"notify,omitempty" json:"notify,omitempty"`
}

// ResourceLimitsConfig sets compute resource constraints.
type ResourceLimitsConfig struct {
	CPU                string         `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory             string         `yaml:"memory,omitempty" json:"memory,omitempty"`
	EphemeralStorage   string         `yaml:"ephemeral_storage,omitempty" json:"ephemeral_storage,omitempty"`
	MaxIterations      int            `yaml:"max_iterations,omitempty" json:"max_iterations,omitempty"`                 // agentic loop cap; 0 or 1 = single LLM call
	MaxToolCallsPerRun int            `yaml:"max_tool_calls_per_run,omitempty" json:"max_tool_calls_per_run,omitempty"` // cap tool invocations per run; 0 = no limit
	MaxCostPerRun      float64        `yaml:"max_cost_per_run,omitempty" json:"max_cost_per_run,omitempty"`             // cap cost per run (EUR); 0 = no limit
	MaxRetriesPerNode  int            `yaml:"max_retries_per_node,omitempty" json:"max_retries_per_node,omitempty"`     // cap retries per graph node; 0 = use Rego default (3)
	RequireApproval    []string       `yaml:"require_approval,omitempty" json:"require_approval,omitempty"`             // tools requiring human approval before execution
	Timeout            *TimeoutConfig `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// TimeoutConfig sets operation timeouts.
type TimeoutConfig struct {
	Operation     string `yaml:"operation,omitempty" json:"operation,omitempty"`
	ToolExecution string `yaml:"tool_execution,omitempty" json:"tool_execution,omitempty"`
	AgentTotal    string `yaml:"agent_total,omitempty" json:"agent_total,omitempty"`
}

// RateLimitsConfig constrains request throughput.
type RateLimitsConfig struct {
	RequestsPerMinute         int    `yaml:"requests_per_minute,omitempty" json:"requests_per_minute,omitempty"`
	ConcurrentExecutions      int    `yaml:"concurrent_executions,omitempty" json:"concurrent_executions,omitempty"`
	PerAgentRequestsPerMinute int    `yaml:"per_agent_requests_per_minute,omitempty" json:"per_agent_requests_per_minute,omitempty"`
	CircuitBreakerThreshold   int    `yaml:"circuit_breaker_threshold,omitempty" json:"circuit_breaker_threshold,omitempty"`
	CircuitBreakerWindow      string `yaml:"circuit_breaker_window,omitempty" json:"circuit_breaker_window,omitempty"`
	ToolFailureThreshold      int    `yaml:"tool_failure_threshold,omitempty" json:"tool_failure_threshold,omitempty"` // Gap T4: separate from circuit breaker
	ToolFailureWindow         string `yaml:"tool_failure_window,omitempty" json:"tool_failure_window,omitempty"`       // Gap T4: e.g. "5m"
}

// DataClassificationConfig controls PII scanning and redaction.
type DataClassificationConfig struct {
	InputScan  bool `yaml:"input_scan,omitempty" json:"input_scan,omitempty"`
	OutputScan bool `yaml:"output_scan,omitempty" json:"output_scan,omitempty"`
	// RedactPII is a backward-compatible shorthand: when set it enables both input and output redaction.
	// Use RedactInput / RedactOutput for granular control; explicit values override RedactPII.
	RedactPII    bool  `yaml:"redact_pii,omitempty" json:"redact_pii,omitempty"`
	RedactInput  *bool `yaml:"redact_input,omitempty" json:"redact_input,omitempty"`
	RedactOutput *bool `yaml:"redact_output,omitempty" json:"redact_output,omitempty"`
	// BlockOnPII when true denies the run when input (prompt or attachments) contains PII.
	BlockOnPII bool `yaml:"block_on_pii,omitempty" json:"block_on_pii,omitempty"`

	// EnabledEntities whitelists specific Presidio entity types (e.g. "EMAIL_ADDRESS").
	// When non-empty, only recognizers matching these entities will be active.
	EnabledEntities []string `yaml:"enabled_entities,omitempty" json:"enabled_entities,omitempty"`

	// DisabledEntities blacklists specific entity types from scanning.
	DisabledEntities []string `yaml:"disabled_entities,omitempty" json:"disabled_entities,omitempty"`

	// CustomRecognizers defines per-agent PII recognizers in Presidio-compatible format.
	CustomRecognizers []CustomRecognizerConfig `yaml:"custom_recognizers,omitempty" json:"custom_recognizers,omitempty"`

	// MaxDataTier caps the data classification tier this agent's gateway
	// traffic may carry (0/public, 1/internal, 2/confidential). nil = no cap
	// beyond the organization baseline (#266).
	MaxDataTier *TierValue `yaml:"max_data_tier,omitempty" json:"max_data_tier,omitempty"`
}

// TierValue is a data classification tier written either as a number (0, 1,
// 2) or a named alias (public, internal, confidential) — the same convention
// as the gateway config. Pure YAML mirror; range validation lives with the
// consumer so error messages carry config context.
type TierValue int

var tierValueNames = map[string]TierValue{
	"public":       0,
	"internal":     1,
	"confidential": 2,
}

// UnmarshalYAML accepts `tier: 2` and `tier: confidential` interchangeably.
func (t *TierValue) UnmarshalYAML(value *yaml.Node) error {
	var n int
	if err := value.Decode(&n); err == nil {
		*t = TierValue(n)
		return nil
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid tier value: %w", err)
	}
	name := strings.ToLower(strings.TrimSpace(s))
	if v, ok := tierValueNames[name]; ok {
		*t = v
		return nil
	}
	if n, err := strconv.Atoi(name); err == nil {
		*t = TierValue(n)
		return nil
	}
	return fmt.Errorf("invalid tier %q: must be 0-2 or one of public, internal, confidential", s)
}

// ShouldRedactInput returns true when input (prompt) PII should be redacted before the LLM.
// Falls back to RedactPII when RedactInput is not explicitly set.
func (dc *DataClassificationConfig) ShouldRedactInput() bool {
	if dc.RedactInput != nil {
		return *dc.RedactInput
	}
	return dc.RedactPII
}

// ShouldRedactOutput returns true when output (LLM response) PII should be redacted.
// Falls back to RedactPII when RedactOutput is not explicitly set.
func (dc *DataClassificationConfig) ShouldRedactOutput() bool {
	if dc.RedactOutput != nil {
		return *dc.RedactOutput
	}
	return dc.RedactPII
}

// CustomRecognizerConfig is the per-agent YAML representation of a custom PII
// recognizer. Uses Presidio-compatible field names.
type CustomRecognizerConfig struct {
	Name            string                `yaml:"name" json:"name"`
	SupportedEntity string                `yaml:"supported_entity" json:"supported_entity"`
	Patterns        []CustomPatternConfig `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	Sensitivity     int                   `yaml:"sensitivity,omitempty" json:"sensitivity,omitempty"`
}

// CustomPatternConfig is a single regex pattern in a custom recognizer.
type CustomPatternConfig struct {
	Name  string  `yaml:"name" json:"name"`
	Regex string  `yaml:"regex" json:"regex"`
	Score float64 `yaml:"score,omitempty" json:"score,omitempty"`
}

// PIIAction controls how PII is handled for a specific tool argument or result.
type PIIAction string

const (
	PIIActionAllow  PIIAction = "allow"
	PIIActionRedact PIIAction = "redact"
	PIIActionAudit  PIIAction = "audit"
	PIIActionBlock  PIIAction = "block"
)

// ToolPIIPolicy defines per-tool PII handling, safety guards, and argument restrictions.
// When a tool has no explicit policy in tool_policies, the _default entry applies.
// When tool_policies is entirely absent, the global pii_action from data_classification applies.
type ToolPIIPolicy struct {
	Arguments       map[string]PIIAction `yaml:"arguments,omitempty" json:"arguments,omitempty"`
	ArgumentDefault PIIAction            `yaml:"argument_default,omitempty" json:"argument_default,omitempty"`
	Result          PIIAction            `yaml:"result,omitempty" json:"result,omitempty"`
	Timeout         string               `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Row count guard (Gap T7): limit bulk operations and require dry_run above threshold.
	MaxRowCount     int  `yaml:"max_row_count,omitempty" json:"max_row_count,omitempty"`         // 0 = no limit
	RequireDryRun   bool `yaml:"require_dry_run,omitempty" json:"require_dry_run,omitempty"`     // require dry_run=true when rows exceed DryRunThreshold
	DryRunThreshold int  `yaml:"dry_run_threshold,omitempty" json:"dry_run_threshold,omitempty"` // rows above which dry_run is required

	// Argument value policy (Gap T9): block specific argument values by name.
	ForbiddenArgumentValues map[string][]string `yaml:"forbidden_argument_values,omitempty" json:"forbidden_argument_values,omitempty"`

	SchemaValidation string `yaml:"schema_validation,omitempty" json:"schema_validation,omitempty"` // "enforce" (default), "shadow", or "disabled"
}

// ToolIdempotencyConfig defines per-tool idempotency for side-effecting tools (e.g. send email, charge card).
// When present under tool_governance.<tool_name>, the runner deduplicates repeated calls with the same key.
// idempotency_key: "request_id" uses correlation_id (per run); "session_id" uses session_id (cross-run dedupe).
type ToolIdempotencyConfig struct {
	IdempotencyKey string `yaml:"idempotency_key,omitempty" json:"idempotency_key,omitempty"` // "request_id" (default) or "session_id"
	CacheTTL       string `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`             // e.g. "24h"; 0 or empty = no TTL
	OnDuplicate    string `yaml:"on_duplicate,omitempty" json:"on_duplicate,omitempty"`       // "return_cached" (default) or "fail"
	StrictMode     bool   `yaml:"strict_mode,omitempty" json:"strict_mode,omitempty"`         // if true, fail tool call when idempotency check errors
}

// CopawConfig holds CoPaw integration policy (skill governance when using CoPaw with Talon).
type CopawConfig struct {
	Skills *CopawSkillsConfig `yaml:"skills,omitempty" json:"skills,omitempty"`
	Memory *CopawMemoryConfig `yaml:"memory,omitempty" json:"memory,omitempty"`
}

// CopawMemoryConfig holds memory governance settings (forbidden phrases for Constitutional AI).
type CopawMemoryConfig struct {
	ForbiddenPhrases []string `yaml:"forbidden_phrases,omitempty" json:"forbidden_phrases,omitempty"`
}

// CopawSkillsConfig defines allow/deny and allowlist for CoPaw skill categories.
// Used by internal/policy/rego/copaw_skills.rego.
type CopawSkillsConfig struct {
	WebSearch   string            `yaml:"web_search,omitempty" json:"web_search,omitempty"` // allow | deny
	FileRead    string            `yaml:"file_read,omitempty" json:"file_read,omitempty"`   // allow | deny
	FileWrite   string            `yaml:"file_write,omitempty" json:"file_write,omitempty"` // allow | deny | deny_sensitive_paths
	ExternalAPI *CopawExternalAPI `yaml:"external_api,omitempty" json:"external_api,omitempty"`
	DigestSend  *CopawDigestSend  `yaml:"digest_send,omitempty" json:"digest_send,omitempty"`
}

// CopawExternalAPI restricts which hosts external_api skills may call.
type CopawExternalAPI struct {
	Allowlist []string `yaml:"allowlist,omitempty" json:"allowlist,omitempty"`
}

// CopawDigestSend controls digest/newsletter skill (PII scan, approval).
type CopawDigestSend struct {
	PIIScan         bool   `yaml:"pii_scan,omitempty" json:"pii_scan,omitempty"`
	RequireApproval string `yaml:"require_approval,omitempty" json:"require_approval,omitempty"` // tier_1 | tier_2 | none
}

// DefaultDestructivePatterns is the compiled-in default for destructive operation detection.
var DefaultDestructivePatterns = []string{"delete", "drop", "remove", "bulk_", "truncate", "purge", "wipe", "destroy"}

// ModelRoutingConfig defines per-tier LLM routing.
type ModelRoutingConfig struct {
	Tier0 *TierConfig `yaml:"tier_0,omitempty" json:"tier_0,omitempty"`
	Tier1 *TierConfig `yaml:"tier_1,omitempty" json:"tier_1,omitempty"`
	Tier2 *TierConfig `yaml:"tier_2,omitempty" json:"tier_2,omitempty"`
}

// TierConfig defines the model routing for a single data tier.
//
// Location is declarative documentation of the intended region; it is NOT
// enforced by the router. Region/jurisdiction enforcement comes from the
// provider registry metadata combined with llm.routing.data_sovereignty_mode
// (routing.rego) and, at the gateway, egress rules.
type TierConfig struct {
	Primary  string `yaml:"primary" json:"primary"`
	Fallback string `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	// FallbackChain is the ordered error-driven fallback chain for this tier:
	// on a transient provider failure (timeout / connection / 429 / 5xx) the
	// runner retries the request against each model in order, subject to the
	// same compliance/sovereignty routing checks as the primary. When set it
	// supersedes the single legacy Fallback entry for error-driven failover
	// (Fallback still applies to provider-unavailable-at-route-time).
	FallbackChain []string `yaml:"fallback_chain,omitempty" json:"fallback_chain,omitempty"`
	Location      string   `yaml:"location,omitempty" json:"location,omitempty"`
	BedrockOnly   bool     `yaml:"bedrock_only,omitempty" json:"bedrock_only,omitempty"`
}

// TimeRestrictionsConfig limits when the agent can run.
type TimeRestrictionsConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	AllowedHours string `yaml:"allowed_hours,omitempty" json:"allowed_hours,omitempty"`
	Timezone     string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Weekends     bool   `yaml:"weekends,omitempty" json:"weekends,omitempty"`
}

// AuditConfig controls evidence logging detail.
// When ObservationOnly is true, policy denials are logged but not enforced (shadow mode for governance visibility).
type AuditConfig struct {
	LogLevel         string `yaml:"log_level,omitempty" json:"log_level,omitempty"`
	RetentionDays    int    `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	IncludePrompts   bool   `yaml:"include_prompts,omitempty" json:"include_prompts,omitempty"`
	IncludeResponses bool   `yaml:"include_responses,omitempty" json:"include_responses,omitempty"`
	ObservationOnly  bool   `yaml:"observation_only,omitempty" json:"observation_only,omitempty"` // If true, never deny; record would-have-denied in evidence
	// IncludeOriginalPrompts controls whether the prompt version store persists the
	// original (pre-redaction) prompt text.  Default false: when input PII redaction
	// is active, the redacted prompt is stored instead — aligning with GDPR Art. 5(1)(c)
	// data minimization.  Set to true only when forensic reconstruction of original
	// input is required (e.g. internal audit under legal hold).
	IncludeOriginalPrompts bool `yaml:"include_original_prompts,omitempty" json:"include_original_prompts,omitempty"`
}

// PlanReviewConfig configures when execution plans require human review (EU AI Act Art. 14).
// The agent package owns plan review runtime logic (internal/agent/plan_review.go);
// this struct is the YAML-facing shape and must stay in sync with it.
type PlanReviewConfig struct {
	RequireForTools bool            `yaml:"require_for_tools" json:"require_for_tools"`
	RequireForTier  string          `yaml:"require_for_tier" json:"require_for_tier"`
	CostThreshold   float64         `yaml:"cost_threshold" json:"cost_threshold"`
	TimeoutMinutes  int             `yaml:"timeout_minutes" json:"timeout_minutes"`
	NotifyWebhook   string          `yaml:"notify_webhook" json:"notify_webhook"`
	VolumeThreshold int             `yaml:"volume_threshold,omitempty" json:"volume_threshold,omitempty"`
	Mode            string          `yaml:"mode,omitempty" json:"mode,omitempty"`
	ApprovalChain   []ApprovalLevel `yaml:"approval_chain,omitempty" json:"approval_chain,omitempty"`
}

type ApprovalLevel struct {
	Role              string `yaml:"role" json:"role"`
	TimeoutMinutes    int    `yaml:"timeout_minutes,omitempty" json:"timeout_minutes,omitempty"`
	EscalateOnTimeout bool   `yaml:"escalate_on_timeout,omitempty" json:"escalate_on_timeout,omitempty"`
}

// ComplianceConfig declares regulatory framework alignment.
type ComplianceConfig struct {
	Frameworks     []string          `yaml:"frameworks,omitempty" json:"frameworks,omitempty"`
	DataResidency  string            `yaml:"data_residency,omitempty" json:"data_residency,omitempty"`
	AIActRiskLevel string            `yaml:"ai_act_risk_level,omitempty" json:"ai_act_risk_level,omitempty"`
	HumanOversight string            `yaml:"human_oversight,omitempty" json:"human_oversight,omitempty"`
	PlanReview     *PlanReviewConfig `yaml:"plan_review,omitempty" json:"plan_review,omitempty"`
	// Declarations are per-agent declared facts (processing purposes,
	// retention, system description) used to populate auditor exports
	// (GDPR Art. 30 RoPA, EU AI Act Annex IV). Declared facts only —
	// runtime facts come from the signed evidence store.
	Declarations *compliance.AgentDeclarations `yaml:"declarations,omitempty" json:"declarations,omitempty"`
}

// MetadataConfig holds optional organizational metadata.
type MetadataConfig struct {
	// Team attributes this agent's spend and evidence to a team
	// (evidence.Team / cost-by-team reporting) (#266).
	Team       string    `yaml:"team,omitempty" json:"team,omitempty"`
	Department string    `yaml:"department,omitempty" json:"department,omitempty"`
	Owner      string    `yaml:"owner,omitempty" json:"owner,omitempty"`
	CreatedAt  time.Time `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	Tags       []string  `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// ComputeHash generates SHA-256 hash of policy content and sets
// the VersionTag to "{agent.version}:sha256:{first8chars}".
func (p *Policy) ComputeHash(content []byte) {
	hash := sha256.Sum256(content)
	p.Hash = hex.EncodeToString(hash[:])
	p.VersionTag = fmt.Sprintf("%s:sha256:%s", p.Agent.Version, p.Hash[:8])
}

// ComputeCanonicalIdentity computes policy identity from a canonical serialized
// policy representation (post-defaults), making identity insensitive to YAML
// formatting, comment changes, or map insertion order.
func (p *Policy) ComputeCanonicalIdentity() error {
	canonicalJSON, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshaling canonical policy: %w", err)
	}
	hash := sha256.Sum256(canonicalJSON)
	p.Hash = hex.EncodeToString(hash[:])
	declaredVersion := strings.TrimSpace(p.Agent.Version)
	if declaredVersion == "" {
		declaredVersion = "0.0.0"
	}
	p.VersionTag = fmt.Sprintf("%s:sha256:%s", declaredVersion, p.Hash[:8])
	return nil
}

// RoutingWarning describes a potential misconfiguration in model routing.
type RoutingWarning struct {
	Tier    string
	Message string
}

// ValidateRouting checks model routing configuration for sovereignty
// misconfigurations. Returns warnings for configs that are technically valid
// but likely incorrect (e.g., bedrock_only with a non-Bedrock model name).
// Returns errors for configs that are logically contradictory.
func ValidateRouting(routing *ModelRoutingConfig) (warnings []RoutingWarning, err error) {
	if routing == nil {
		return nil, nil
	}

	tiers := map[string]*TierConfig{
		"tier_0": routing.Tier0,
		"tier_1": routing.Tier1,
		"tier_2": routing.Tier2,
	}

	for name, tier := range tiers {
		if tier == nil {
			continue
		}
		w, e := validateTierRouting(name, tier)
		warnings = append(warnings, w...)
		if e != nil {
			return warnings, e
		}
	}

	return warnings, nil
}

// validateTierRouting checks a single tier config for routing issues.
func validateTierRouting(tierName string, tier *TierConfig) (warnings []RoutingWarning, err error) {
	if !tier.BedrockOnly {
		return nil, nil
	}

	// BedrockOnly is set — validate that primary looks like a Bedrock model
	if !isBedrockModelName(tier.Primary) {
		warnings = append(warnings, RoutingWarning{
			Tier: tierName,
			Message: fmt.Sprintf(
				"bedrock_only is true but primary model %q does not use Bedrock naming (vendor.model, e.g. anthropic.*, amazon.*, meta.*, cohere.*, ai21.*, stability.*, mistral.*); "+
					"the router will force Bedrock provider — ensure this model is available via Bedrock in your region",
				tier.Primary),
		})
	}

	// Fallback with bedrock_only: warn if fallback also doesn't look like Bedrock
	if tier.Fallback != "" && !isBedrockModelName(tier.Fallback) {
		warnings = append(warnings, RoutingWarning{
			Tier: tierName,
			Message: fmt.Sprintf(
				"bedrock_only is true but fallback model %q does not use Bedrock naming; "+
					"fallback will also be forced through Bedrock provider",
				tier.Fallback),
		})
	}

	for i, m := range tier.FallbackChain {
		if !isBedrockModelName(m) {
			warnings = append(warnings, RoutingWarning{
				Tier: tierName,
				Message: fmt.Sprintf(
					"bedrock_only is true but fallback_chain[%d] model %q does not use Bedrock naming; "+
						"it will also be forced through Bedrock provider",
					i, m),
			})
		}
	}

	return warnings, nil
}

// bedrockModelPrefixes lists the vendor prefixes used by AWS Bedrock model IDs.
// Bedrock model names follow the pattern "vendor.model-name-version", e.g.
// "anthropic.claude-3-sonnet-20240229-v1:0" or "meta.llama3-1-70b-instruct-v1:0".
var bedrockModelPrefixes = []string{
	"anthropic.",
	"amazon.",
	"meta.",
	"cohere.",
	"ai21.",
	"stability.",
	"mistral.",
}

// BedrockModelPrefixes returns the set of known Bedrock vendor prefixes.
// Used by the LLM router to distinguish Bedrock model IDs from local/other names.
func BedrockModelPrefixes() []string {
	out := make([]string, len(bedrockModelPrefixes))
	copy(out, bedrockModelPrefixes)
	return out
}

// isBedrockModelName returns true if the model name follows Bedrock conventions
// (i.e., starts with a known vendor prefix like "anthropic.", "meta.", etc.).
func isBedrockModelName(model string) bool {
	for _, prefix := range bedrockModelPrefixes {
		if strings.HasPrefix(model, prefix) {
			return true
		}
	}
	return false
}
