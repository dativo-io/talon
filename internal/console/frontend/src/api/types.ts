// Types of the /console/v1 JSON contract, mirrored from the Go DTOs in
// internal/console (dto.go, configuration.go, search.go) and the shared
// projections they embed (fleet.AgentRow, costs.Report, session.*,
// evidence.*). Field names are the Go json tags; nothing here adds meaning.

export type AvailabilityState = "ok" | "partial" | "unavailable" | "unknown" | "empty";

export interface Availability {
  state: AvailabilityState;
  source: string;
  as_of?: string;
  error?: string;
  note?: string;
  unavailable?: string[];
}

export interface Meta {
  contract_version: string;
  generated_at: string;
  tenant_scope: "tenant" | "all_tenants";
  tenant_id?: string;
}

export type RuntimeState = "running" | "stale" | "offline" | "not_configured" | "unknown";

export interface RoleStatus {
  role: string; // mcp_proxy | gateway | native
  expected: boolean;
  state: RuntimeState;
  reason: string;
  instance_id?: string;
  last_seen?: string;
}

export interface RuntimeCatalog {
  active_generation: string;
  scan_digest: string;
  activated_at: string;
  reload_enabled: boolean;
  reload_rejected: boolean;
  rejected_digest?: string;
  rejected_at?: string;
  rejected_causes?: string[];
  agents: { name: string; tenant_id: string; enabled: boolean; policy_digest: string }[];
}

export interface RuntimeProcess {
  instance_id: string;
  roles: string[];
  version: string;
  commit?: string;
  pid: number;
  host?: string;
  started_at: string;
  written_at: string;
  sequence: number;
  interval_seconds: number;
  state: "running" | "stopped";
  stopped_at?: string;
  catalog?: RuntimeCatalog;
  proxy_config?: { path: string; digest: string; loaded_at: string };
  gateway_config?: { path: string; digest: string; loaded_at: string };
  assessed_state: RuntimeState;
  reason: string;
  age_seconds: number;
  current: boolean;
}

export interface Runtime {
  availability: Availability;
  active_generation?: string;
  activated_at?: string;
  read_at?: string;
  roles: RoleStatus[] | null;
  processes: RuntimeProcess[] | null;
  rejected?: { file: string; reason: string }[];
}

export type Health = "healthy" | "needs-attention" | "stopped" | "blocked";

export interface Cause {
  kind: string;
  detail: string;
}

export interface UseCaseRecordRow {
  purpose?: string;
  department?: string;
  criticality?: string;
  owner_business?: string;
  owner_technical?: string;
  owner_budget?: string;
  owner_risk?: string;
  references?: string[];
}

export interface AgentRow {
  name: string;
  tenant_id: string;
  state: "enabled" | "stopped";
  health: Health;
  why: string;
  causes?: Cause[];
  spend_month: number;
  monthly_cap: number;
  spend_day: number;
  daily_cap: number;
  currency: string;
  requests: number;
  denied: number;
  fallbacks: number;
  failed_sessions: number;
  last_run?: string;
  config_path: string;
  policy_digest: string;
  config_error?: string;
  // spend_day / spend_month when that period's priced records are not all in
  // `currency`: the retained number is not a measurement.
  unavailable_fields?: string[];
  use_case?: UseCaseRecordRow;
}

export interface FleetIssue {
  path: string;
  status: string;
  reason: string;
  agent?: string;
}

export interface UseCases {
  availability: Availability;
  health_basis: "projected_from_store" | "runtime";
  rows: AgentRow[] | null;
  issues: FleetIssue[] | null;
  attention: AgentRow[] | null;
  runtime: Runtime;
  counter_windows: { requests_denied: string; fallbacks: string; failed_sessions: string };
}

export interface WindowBounds {
  day_start: string;
  day_end: string;
  month_start: string;
  month_end: string;
  week_start: string;
  week_end: string;
}

export interface Today {
  availability: Availability;
  tenant_scope: string;
  window: WindowBounds;
  requests: number;
  denied: number;
  cost: number;
  currency: string;
  scope: string;
}

export interface OperationalEvent {
  event_id: string;
  evidence_id: string;
  correlation_id?: string;
  timestamp: string;
  tenant_id: string;
  agent?: string;
  agent_id?: string;
  invocation_type?: string;
  decision: string;
  allowed: boolean;
  reason_code?: string;
  reason_text?: string;
  reasons?: string[];
  suggested_fix?: string;
  cost_eur: number;
  model?: string;
  duration_ms: number;
  has_error: boolean;
  primary_explanation_code?: string;
  primary_explanation_reason?: string;
}

export interface RecentEvents {
  availability: Availability;
  tenant_scope: string;
  events: OperationalEvent[] | null;
  cursor?: string;
  limit: number;
}

export interface Overview {
  meta: Meta;
  use_cases: UseCases;
  today: Today;
  recent_events: RecentEvents;
}

export interface BudgetUsage {
  used_eur: number;
  limit_eur: number;
  percent: number;
  source: string;
  status: string;
}

export interface CacheUsage {
  hits: number;
  saved_eur: number;
  hit_rate_percent: number;
  total_seen: number;
}

export interface CostReport {
  tenant_id: string;
  agent_id?: string;
  currency: string;
  window: WindowBounds;
  today_eur: number;
  month_eur: number;
  seven_days_eur: number;
  by_agent_eur?: Record<string, number>;
  by_agent_month_eur?: Record<string, number>;
  by_model_eur?: Record<string, number>;
  by_model_month_eur?: Record<string, number>;
  by_provider_eur?: Record<string, number>;
  by_provider_month_eur?: Record<string, number>;
  by_team_eur?: Record<string, number>;
  by_team_month_eur?: Record<string, number>;
  daily_budget?: BudgetUsage;
  monthly_budget?: BudgetUsage;
  cache_7d?: CacheUsage;
  cache_30d?: CacheUsage;
  currencies?: Record<string, Record<string, number>>;
  unpriced_records: number;
  warnings?: string[];
  unavailable_fields?: string[];
}

export interface Costs {
  meta: Meta;
  availability: Availability;
  report?: CostReport;
  budget_note?: string;
}

export interface ActivityBucket {
  start: string;
  requests: number;
  denied: number;
  errors: number;
  cost: number;
}

export interface ActivitySeries {
  tenant_id: string;
  agent_id?: string;
  from: string;
  to: string;
  bucket: "5m" | "1h" | "24h";
  scope: string;
  buckets: ActivityBucket[] | null;
}

export interface Activity {
  meta: Meta;
  availability: Availability;
  series?: ActivitySeries;
}

export interface SessionRow {
  id: string;
  tenant_id: string;
  agent_id: string;
  status: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  total_cost: number;
  total_tokens: number;
  reserved_cost?: number;
  max_cost?: number;
  reasoning?: string;
  external_session_id?: string;
  source?: string;
}

export interface SessionCursor {
  created_at: string;
  id: string;
}

export interface ObservedSession {
  session_id: string;
  tenant_id: string;
  agent_id: string;
  record_count: number;
  first_seen: string;
  last_seen: string;
  source: string;
}

export interface ObservedCursor {
  last_seen: string;
  session_id: string;
  agent_id: string;
}

export interface SessionList {
  meta: Meta;
  availability: Availability;
  sessions: SessionRow[] | null;
  limit: number;
  next_cursor?: SessionCursor;
  observed_availability: Availability;
  observed: ObservedSession[] | null;
  observed_next_cursor?: ObservedCursor;
}

export interface SessionFailure {
  at: string;
  code: string;
  detail?: string;
}

export interface SessionSummary {
  session_id: string;
  tenant_id: string;
  session_source?: string;
  client?: string;
  agents?: string[];
  providers?: string[];
  models?: string[];
  record_count: number;
  allowed: number;
  denied: number;
  errors: number;
  total_cost: number;
  currency?: string;
  currencies?: Record<string, number>;
  cost_comparable: boolean;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
  first_seen: string;
  last_seen: string;
  requests: number;
  duration_ms?: number;
  retries?: number;
  failed_attempts?: number;
  fallbacks?: number;
  fail_closed?: number;
  denied_by_reason?: Record<string, number>;
  provider_path?: string[];
  tool_calls?: number;
  tool_calls_denied?: number;
  tool_calls_failed?: number;
  tool_names?: string[];
  tools_filtered?: string[];
  pii_redactions?: number;
  pii_types?: string[];
  last_failure?: SessionFailure;
}

export interface SessionDetailInner {
  session?: SessionRow;
  ambiguous_sessions?: SessionRow[];
  summary: SessionSummary;
}

export type Dispatch = "not_dispatched" | "dispatched" | "unknown" | "not_recorded";
export type Downstream = "none" | "completed" | "rejected" | "failed" | "unknown" | "not_recorded" | "cache";

export interface Outcome {
  decision: "allowed" | "denied";
  dispatch: Dispatch;
  downstream: Downstream;
  response_withheld?: boolean;
  tool?: string;
  basis: string;
}

export interface EvidenceIndex {
  id: string;
  correlation_id?: string;
  session_id?: string;
  timestamp: string;
  tenant_id: string;
  agent_id: string;
  invocation_type: string;
  allowed: boolean;
  cost: number;
  currency?: string;
  model_used: string;
  duration_ms: number;
  has_error: boolean;
  primary_explanation_code?: string;
  primary_explanation_reason?: string;
  outcome?: Outcome;
}

export interface TimelineCursor {
  timestamp: string;
  id: string;
}

export interface Timeline {
  summary: SessionSummary;
  records: EvidenceIndex[] | null;
  total: number;
  limit?: number;
  next_cursor?: TimelineCursor;
}

export interface SessionDetail {
  meta: Meta;
  availability: Availability;
  detail?: SessionDetailInner;
  timeline?: Timeline;
}

export interface ExplanationItem {
  code: string;
  decision: string;
  stage: string;
  reason: string;
  trigger?: string;
  fix?: string;
  policy_ref?: string;
  version_identity?: string;
}

// The signed record is shown as stored (its own redaction applies); only
// the fields the page lays out are typed.
export interface EvidenceRecord {
  id: string;
  correlation_id: string;
  session_id?: string;
  stage?: string;
  timestamp: string;
  tenant_id: string;
  agent_id: string;
  invocation_type: string;
  request_source_id?: string;
  policy_decision: { allowed: boolean; action: string; reasons?: string[]; policy_version: string };
  execution: {
    model_used: string;
    tools_called?: string[];
    cost: number;
    currency?: string;
    duration_ms: number;
    error?: string;
    pricing_known?: boolean;
    tokens?: { input?: number; output?: number };
  };
  status?: string;
  failure_reason?: string;
  explanations?: ExplanationItem[];
  failover?: { role: string; provider: string; model?: string; error_class?: string; chain_position: number };
  enforcement?: { mechanism: string; boundary: string; decision_authority: string; provenance: string };
  orchestration?: Record<string, unknown>;
  signature: string;
  [key: string]: unknown;
}

export interface Verification {
  state: "valid" | "invalid";
  checked_at: string;
}

export interface EvidenceDetail {
  meta: Meta;
  availability: Availability;
  detail?: { record: EvidenceRecord; verification: Verification; outcome: Outcome };
}

export interface StoreHealth {
  availability: Availability;
  path: string;
  read_only: boolean;
  size_bytes: number;
  record_count: number;
  newest_record?: string;
}

export interface SystemInfo {
  meta: Meta;
  console: { version: string; commit?: string; started_at: string; currency: string };
  store: StoreHealth;
  runtime: Runtime;
}

export interface Retry {
  max_attempts: number;
  initial_backoff?: string;
  max_backoff?: string;
}

export interface ProviderView {
  name: string;
  enabled: boolean;
  endpoint?: string;
  region?: string;
  secret_name?: string;
  upstream_auth_mode?: string;
  allowed_models?: string[];
  blocked_models?: string[];
  forbidden_tools?: string[];
  tool_policy_action?: string;
  fallback?: string[];
}

export interface OrganizationConfig {
  availability: Availability;
  source_path?: string;
  pii_action?: string;
  response_pii_action?: string;
  daily_cost?: number;
  monthly_cost?: number;
  session_cost?: number;
  tool_policy_action?: string;
  retry?: Retry;
  allowed_providers?: string[];
  allowed_models?: string[];
  blocked_models?: string[];
  allowed_tools?: string[];
  forbidden_tools?: string[];
  max_daily_cost?: number;
  max_monthly_cost?: number;
  max_session_cost?: number;
  log_prompts: boolean;
  log_responses: boolean;
  cost_webhook_configured: boolean;
  providers?: ProviderView[];
}

export interface TierRoute {
  tier: number;
  primary?: string;
  fallback?: string;
  fallback_chain?: string[];
  location?: string;
}

export interface UseCaseConfig {
  name: string;
  tenant_id: string;
  description?: string;
  version?: string;
  enabled: boolean;
  source_path: string;
  policy_digest?: string;
  key_secret_name?: string;
  model_tier: number;
  allowed_providers?: string[];
  allowed_models?: string[];
  blocked_models?: string[];
  model_routing?: TierRoute[];
  retry?: Retry;
  cost_per_request?: number;
  cost_daily?: number;
  cost_monthly?: number;
  session_max_cost?: number;
  budget_alert_webhook_configured: boolean;
  requests_per_minute?: number;
  concurrent_executions?: number;
  allowed_tools?: string[];
  forbidden_tools?: string[];
  tool_policy_action?: string;
  input_scan: boolean;
  output_scan: boolean;
  redact_pii: boolean;
  block_on_pii: boolean;
  audit_log_level?: string;
  audit_retention_days?: number;
  audit_include_prompts: boolean;
  audit_include_responses: boolean;
  use_case?: UseCaseRecordRow;
  active: ActiveStatus;
}

export interface ProxyConfigView {
  availability: Availability;
  source_path?: string;
  name?: string;
  vendor?: string;
  endpoint?: string;
  region?: string;
  auth_secret_name?: string;
  allowed_tools?: string[];
  forbidden_tools?: string[];
  requests_per_minute?: number;
}

export interface Configuration {
  meta: Meta;
  read_at: string;
  organization: OrganizationConfig;
  use_cases: { availability: Availability; source?: string; items: UseCaseConfig[] };
  mcp_proxy: ProxyConfigView;
  effective_policy: Availability;
  active_generation: Availability;
  active: ActiveProcessConfig[];
  issues?: { path: string; status: string; reason: string }[];
}

export interface ActiveFile {
  loaded_path: string;
  loaded_digest: string;
  loaded_at: string;
  current_digest?: string;
  matches: boolean | null;
}

export interface ActiveProcessConfig {
  instance_id: string;
  roles: string[];
  state: RuntimeState;
  active_generation?: string;
  activated_at?: string;
  agent_files_match: boolean | null;
  reload_enabled: boolean;
  reload_rejected: boolean;
  rejected_at?: string;
  rejected_causes?: string[];
  proxy_config?: ActiveFile;
  gateway_config?: ActiveFile;
}

export interface ActiveStatus {
  state: "loaded_matches_file" | "loaded_differs_from_file" | "not_in_active_generation" | "unknown";
  reason: string;
  active_policy_digest?: string;
  instance_ids?: string[];
}

export interface UseCaseDetail {
  meta: Meta;
  row: AgentRow | null;
  availability: Availability;
  health_basis: string;
  counter_windows: { requests_denied: string; fallbacks: string; failed_sessions: string };
  runtime: Runtime;
  recent_sessions: SessionList;
  costs: Costs;
  activity: Activity;
  effective_policy: Availability;
}

export interface SearchResults {
  meta: Meta;
  query: string;
  availability: Availability;
  use_cases: { name: string; tenant_id: string; health: string }[];
  sessions: { session_id: string; tenant_id: string; managed: boolean; record_count: number }[];
  evidence: EvidenceIndex[];
  unsupported: string[];
  notes?: string[];
}

export interface AuthSession {
  paired: boolean;
  expires_at?: string;
}
