package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Policy represents a complete .talon.yaml configuration (v2.0 schema).
type Policy struct {
	Agent              AgentConfig               `yaml:"agent" json:"agent"`
	Capabilities       *CapabilitiesConfig       `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Triggers           *TriggersConfig           `yaml:"triggers,omitempty" json:"triggers,omitempty"`
	Secrets            *SecretsConfig            `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Memory             *MemoryConfig             `yaml:"memory,omitempty" json:"memory,omitempty"`
	Context            *ContextConfig            `yaml:"context,omitempty" json:"context,omitempty"`
	AttachmentHandling *AttachmentHandlingConfig `yaml:"attachment_handling,omitempty" json:"attachment_handling,omitempty"`
	Policies           PoliciesConfig            `yaml:"policies" json:"policies"`
	Audit              *AuditConfig              `yaml:"audit,omitempty" json:"audit,omitempty"`
	Compliance         *ComplianceConfig         `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	Metadata           *MetadataConfig           `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// Computed fields (not serialized from YAML)
	Hash       string `yaml:"-" json:"-"`
	VersionTag string `yaml:"-" json:"-"`
}

// AgentConfig holds the agent identity.
type AgentConfig struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string `yaml:"version" json:"version"`
	ModelTier   int    `yaml:"model_tier,omitempty" json:"model_tier,omitempty"`
}

// CapabilitiesConfig defines what the agent is allowed to do.
type CapabilitiesConfig struct {
	AllowedTools       []string `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`
	AllowedDataSources []string `yaml:"allowed_data_sources,omitempty" json:"allowed_data_sources,omitempty"`
	ForbiddenPatterns  []string `yaml:"forbidden_patterns,omitempty" json:"forbidden_patterns,omitempty"`
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
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	MaxEntries          int      `yaml:"max_entries,omitempty" json:"max_entries,omitempty"`
	MaxEntrySizeKB      int      `yaml:"max_entry_size_kb,omitempty" json:"max_entry_size_kb,omitempty"`
	RetentionDays       int      `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	ReviewMode          string   `yaml:"review_mode,omitempty" json:"review_mode,omitempty"`
	AllowedCategories   []string `yaml:"allowed_categories,omitempty" json:"allowed_categories,omitempty"`
	ForbiddenCategories []string `yaml:"forbidden_categories,omitempty" json:"forbidden_categories,omitempty"`
	Audit               bool     `yaml:"audit,omitempty" json:"audit,omitempty"`
}

// ContextConfig defines shared enterprise context mounts.
type ContextConfig struct {
	SharedMounts []SharedMount `yaml:"shared_mounts,omitempty" json:"shared_mounts,omitempty"`
}

// SharedMount is a read-only enterprise knowledge mount.
type SharedMount struct {
	Name           string `yaml:"name" json:"name"`
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

// PoliciesConfig is the main governance section.
type PoliciesConfig struct {
	CostLimits         *CostLimitsConfig         `yaml:"cost_limits" json:"cost_limits"`
	ResourceLimits     *ResourceLimitsConfig     `yaml:"resource_limits,omitempty" json:"resource_limits,omitempty"`
	RateLimits         *RateLimitsConfig         `yaml:"rate_limits,omitempty" json:"rate_limits,omitempty"`
	DataClassification *DataClassificationConfig `yaml:"data_classification,omitempty" json:"data_classification,omitempty"`
	ModelRouting       *ModelRoutingConfig       `yaml:"model_routing,omitempty" json:"model_routing,omitempty"`
	TimeRestrictions   *TimeRestrictionsConfig   `yaml:"time_restrictions,omitempty" json:"time_restrictions,omitempty"`
}

// CostLimitsConfig sets per-request, daily, and monthly cost budgets.
type CostLimitsConfig struct {
	PerRequest float64 `yaml:"per_request,omitempty" json:"per_request,omitempty"`
	Daily      float64 `yaml:"daily,omitempty" json:"daily,omitempty"`
	Monthly    float64 `yaml:"monthly,omitempty" json:"monthly,omitempty"`
}

// ResourceLimitsConfig sets compute resource constraints.
type ResourceLimitsConfig struct {
	CPU              string         `yaml:"cpu,omitempty" json:"cpu,omitempty"`
	Memory           string         `yaml:"memory,omitempty" json:"memory,omitempty"`
	EphemeralStorage string         `yaml:"ephemeral_storage,omitempty" json:"ephemeral_storage,omitempty"`
	Timeout          *TimeoutConfig `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// TimeoutConfig sets operation timeouts.
type TimeoutConfig struct {
	Operation     string `yaml:"operation,omitempty" json:"operation,omitempty"`
	ToolExecution string `yaml:"tool_execution,omitempty" json:"tool_execution,omitempty"`
	AgentTotal    string `yaml:"agent_total,omitempty" json:"agent_total,omitempty"`
}

// RateLimitsConfig constrains request throughput.
type RateLimitsConfig struct {
	RequestsPerMinute    int `yaml:"requests_per_minute,omitempty" json:"requests_per_minute,omitempty"`
	ConcurrentExecutions int `yaml:"concurrent_executions,omitempty" json:"concurrent_executions,omitempty"`
}

// DataClassificationConfig controls PII scanning and redaction.
type DataClassificationConfig struct {
	InputScan  bool `yaml:"input_scan,omitempty" json:"input_scan,omitempty"`
	OutputScan bool `yaml:"output_scan,omitempty" json:"output_scan,omitempty"`
	RedactPII  bool `yaml:"redact_pii,omitempty" json:"redact_pii,omitempty"`
}

// ModelRoutingConfig defines per-tier LLM routing.
type ModelRoutingConfig struct {
	Tier0 *TierConfig `yaml:"tier_0,omitempty" json:"tier_0,omitempty"`
	Tier1 *TierConfig `yaml:"tier_1,omitempty" json:"tier_1,omitempty"`
	Tier2 *TierConfig `yaml:"tier_2,omitempty" json:"tier_2,omitempty"`
}

// TierConfig defines the model routing for a single data tier.
type TierConfig struct {
	Primary     string `yaml:"primary" json:"primary"`
	Fallback    string `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	Location    string `yaml:"location,omitempty" json:"location,omitempty"`
	BedrockOnly bool   `yaml:"bedrock_only,omitempty" json:"bedrock_only,omitempty"`
}

// TimeRestrictionsConfig limits when the agent can run.
type TimeRestrictionsConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	AllowedHours string `yaml:"allowed_hours,omitempty" json:"allowed_hours,omitempty"`
	Timezone     string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	Weekends     bool   `yaml:"weekends,omitempty" json:"weekends,omitempty"`
}

// AuditConfig controls evidence logging detail.
type AuditConfig struct {
	LogLevel         string `yaml:"log_level,omitempty" json:"log_level,omitempty"`
	RetentionDays    int    `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	IncludePrompts   bool   `yaml:"include_prompts,omitempty" json:"include_prompts,omitempty"`
	IncludeResponses bool   `yaml:"include_responses,omitempty" json:"include_responses,omitempty"`
}

// ComplianceConfig declares regulatory framework alignment.
type ComplianceConfig struct {
	Frameworks     []string `yaml:"frameworks,omitempty" json:"frameworks,omitempty"`
	DataResidency  string   `yaml:"data_residency,omitempty" json:"data_residency,omitempty"`
	AIActRiskLevel string   `yaml:"ai_act_risk_level,omitempty" json:"ai_act_risk_level,omitempty"`
	HumanOversight string   `yaml:"human_oversight,omitempty" json:"human_oversight,omitempty"`
}

// MetadataConfig holds optional organizational metadata.
type MetadataConfig struct {
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
				"bedrock_only is true but primary model %q does not use Bedrock naming (anthropic.* or amazon.*); "+
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

	return warnings, nil
}

// isBedrockModelName returns true if the model name follows Bedrock conventions.
func isBedrockModelName(model string) bool {
	return strings.HasPrefix(model, "anthropic.") || strings.HasPrefix(model, "amazon.")
}
