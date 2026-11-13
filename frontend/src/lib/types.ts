/** Types mirroring the API contract. */

export type ObservableType = 'ip' | 'domain' | 'url' | 'hash' | 'file' | 'generic';
export type JobStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'SUCCESS'
  | 'PARTIAL_FAILURE'
  | 'FAILED'
  | 'KILLED';
export type ReportStatus = 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'KILLED';
/** Where a plugin sits in the job lifecycle. */
export type PluginType = 'analyzer' | 'connector' | 'pivot';
export type Verdict = 'unknown' | 'clean' | 'suspicious' | 'malicious';
/** Traffic Light Protocol v2.0, as the API serialises it. */
export type Tlp = 'clear' | 'green' | 'amber' | 'red';
export type ScanMode = 'reuse_recent' | 'force_new';
export type Role = 'analyst' | 'admin';
export type AuthSource = 'local' | 'oidc' | 'proxy';

export interface CurrentUser {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  role: Role;
  auth_source: AuthSource;
  must_change_password: boolean;
  mfa_enabled: boolean;
  mfa_required: boolean;
  mfa_requirement_reason: string | null;
  groups: string[];
  permissions: string[];
  default_playbook: string | null;
}

/**
 * The outcome of the first sign-in step.
 *
 * An account with an authenticator gets no session here: the challenge token
 * has to be posted back with a code, and `user` is null until it is.
 */
export interface LoginResult {
  mfa_required: boolean;
  challenge_token: string | null;
  user: CurrentUser | null;
}

export interface MfaStatus {
  enabled: boolean;
  required: boolean;
  requirement_reason: string | null;
  confirmed_at: string | null;
  recovery_codes_remaining: number;
}

export interface MfaEnrolment {
  secret: string;
  otpauth_uri: string;
}

export interface AuthMethods {
  local_enabled: boolean;
  oidc_enabled: boolean;
  proxy_enabled: boolean;
}

export interface PluginSummaryData {
  verdict: Verdict;
  score: number | null;
  tags: string[];
  open_ports: number[];
  country: string | null;
  asn: string | null;
  organisation: string | null;
  hostnames: string[];
  cves: string[];
  detection_ratio: string | null;
  headline: string | null;
  /** A page capture the source took, fetched back through the API. */
  screenshot_url?: string | null;
  links: { label: string; url: string }[];
  extra: Record<string, unknown>;
}

export interface DerivedObservable {
  value: string;
  reason: string;
}

export interface PluginReport {
  id: string;
  plugin_name: string;
  plugin_type: PluginType;
  status: ReportStatus;
  summary_data: Partial<PluginSummaryData>;
  errors: string | null;
  execution_time_ms: number | null;
  from_cache: boolean;
  /** Observables a pivot derived, and the child jobs they produced. */
  derived_observables: DerivedObservable[];
  spawned_job_ids: string[];
  created_at: string;
  finished_at: string | null;
}

export interface PluginReportDetail extends PluginReport {
  raw_output: Record<string, unknown> | null;
}

export interface JobSummary {
  id: string;
  observable_value: string;
  observable_type: ObservableType;
  status: JobStatus;
  verdict: Verdict;
  tags: string[];
  playbook_name: string | null;
  requested_by_name: string;
  created_at: string;
  finished_at: string | null;
  analyzer_count: number;
  tlp: Tlp;
  /** Set when a pivot derived this job from another one. */
  parent_job_id: string | null;
  pivot_name: string | null;
  depth: number;
}

export interface JobDetail extends JobSummary {
  /** Present when the job was submitted as a file rather than a value. */
  file_name: string | null;
  file_size: number | null;
  requested_analyzers: string[];
  requested_connectors: string[];
  requested_pivots: string[];
  force_rescan: boolean;
  summary: {
    tags?: string[];
    open_ports?: number[];
    cves?: string[];
    hostnames?: string[];
    countries?: string[];
    organisations?: string[];
    asns?: string[];
    detection_ratios?: Record<string, string>;
    scores?: Record<string, number>;
    analyzers_succeeded?: number;
    analyzers_failed?: number;
    analyzers_skipped?: number;
    analyzers_from_cache?: number;
    connectors_succeeded?: number;
    connectors_failed?: number;
    connectors_skipped?: number;
    pivots_succeeded?: number;
    pivots_failed?: number;
    pivots_skipped?: number;
    spawned_job_ids?: string[];
    skipped_plugins?: { name: string; type: PluginType; reason: string }[];
  };
  started_at: string | null;
  reports: PluginReport[];
}

export interface ObservablePreview {
  value: string;
  type: ObservableType;
  hash_algorithm: string | null;
  is_private: boolean;
  refanged: boolean;
  tlp: Tlp;
  default_scan_mode: ScanMode;
  compatible_analyzers: string[];
  compatible_connectors: string[];
  compatible_pivots: string[];
  compatible_playbooks: string[];
  unavailable_analyzers: { name: string; type: PluginType; reason: string }[];
  unavailable_plugins: { name: string; type: PluginType; reason: string }[];
  auto_select: boolean;
}

/** Who serves a plugin, and what configuring it requires. */
export interface ProviderInfo {
  name: string;
  url: string;
  /** The endpoint XenoProxy calls. Read-only: it is not a setting. */
  api_base_url: string;
  credential_url: string;
  free_tier: string;
  rate_limit: string;
  notes: string;
  /** The operator runs the service, so the address is theirs to give. */
  self_hosted: boolean;
}

export interface SecretSpec {
  name: string;
  label: string;
  required: boolean;
  help_text: string;
  /** What the value looks like, used as the input's placeholder. */
  placeholder: string;
  /** An analyst may set this one for themselves, in Settings. */
  user_overridable: boolean;
}

export interface OptionSpec {
  type?: string;
  default?: unknown;
  label?: string;
  enum?: string[];
  user_overridable?: boolean;
}

export interface Plugin {
  name: string;
  label: string;
  description: string;
  plugin_type: PluginType;
  supported_types: ObservableType[];
  secrets: SecretSpec[];
  options_schema: Record<string, OptionSpec>;
  documentation_url: string;
  free_tier: boolean;
  requires_network: boolean;
  provider: ProviderInfo;
  is_custom: boolean;
  plugin_version: string;
  max_tlp: Tlp;
  /** Connector and pivot declarations; absent on an analyzer. */
  run_on_verdicts?: Verdict[];
  run_on_partial_failure?: boolean | null;
  child_playbook?: string | null;
  max_children?: number | null;
  enabled: boolean;
  configured: boolean;
  missing_secrets: string[];
  secret_hints: Record<string, string>;
  options: Record<string, unknown>;
  timeout_seconds: number;
  cache_ttl_seconds: number;
  health_ok?: boolean | null;
  health_detail?: string | null;
  health_checked_at?: string | null;
  updated_at: string | null;
  updated_by: string | null;
}

export interface PluginManifest {
  name: string;
  version: string;
  api_version: number;
  entrypoint: string;
  label: string;
  description: string;
  author: string;
  homepage: string;
}

export interface InstalledPlugin {
  name: string;
  loaded: boolean;
  error: string | null;
  plugin_name: string | null;
  manifest: PluginManifest | null;
  plugin?: Plugin;
}

export interface PluginState {
  enabled: boolean;
  upload_enabled: boolean;
  directory: string;
  max_archive_bytes: number;
  plugins: InstalledPlugin[];
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  observable_types: ObservableType[];
  analyzers: string[];
  connectors: string[];
  pivots: string[];
  is_builtin: boolean;
  enabled: boolean;
  updated_at: string;
}

export interface GroupRecord {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  require_mfa: boolean;
  /** Names this group answers to in the identity provider or the directory. */
  external_names: string[];
  grants_admin: boolean;
  /** The provider that last signed somebody in through this group. */
  matched_source: string | null;
  matched_at: string | null;
  member_count: number;
  members: string[];
  created_at: string;
}

export interface UserDetail {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  role: Role;
  auth_source: AuthSource;
  is_active: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  groups: string[];
  group_ids: string[];
  created_at: string;
  last_login_at: string | null;
}

/** Returned once, on creation or on a reset: the password is never shown again. */
export interface UserCreated extends UserDetail {
  initial_password: string;
}

export interface UserRecord {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  role: Role;
  auth_source: AuthSource;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AuditEvent {
  seq: number;
  occurred_at: string;
  action: string;
  outcome: string;
  actor: string;
  target: string | null;
  ip_address: string | null;
  request_id: string | null;
  details: Record<string, unknown>;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked: boolean;
}

export interface ApiKeyCreated extends ApiKey {
  token: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface JobStats {
  jobs_by_verdict: Record<string, number>;
  jobs_by_status: Record<string, number>;
  reports_total: number;
  reports_from_cache: number;
  cache_hit_ratio: number;
}

/** What this analyst may configure for themselves, and what they already have. */
export interface MyPluginConfig {
  overridable: Record<
    string,
    { label: string; plugin_type: PluginType; options: string[]; secrets: string[] }
  >;
  options: Record<string, Record<string, unknown>>;
  secret_hints: Record<string, Record<string, string>>;
}

export interface HealthCheckResult {
  plugin_name: string;
  healthy: boolean;
  detail: string;
  checked_at: string;
}

// --- Instance settings -------------------------------------------------------

export type SettingType = 'boolean' | 'integer' | 'string' | 'choice';

/** One scalar switch or threshold, with its declaration. */
export interface SettingSpec {
  key: string;
  label: string;
  help_text: string;
  type: SettingType;
  default: unknown;
  section: string;
  choices: string[];
  minimum: number | null;
  maximum: number | null;
  value: unknown;
  managed_by_environment: boolean;
  environment_variable: string | null;
  updated_at: string | null;
  updated_by: string | null;
}

/** A JSON Schema property, as the backend derives it from the section model. */
export interface SchemaProperty {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  enum?: string[];
  anyOf?: { type?: string; enum?: string[] }[];
  items?: { type?: string };
  minimum?: number;
  maximum?: number;
  maxLength?: number;
}

export interface SectionSchema {
  title?: string;
  description?: string;
  properties: Record<string, SchemaProperty>;
  required?: string[];
}

/** A section's stored values. Sealed fields read as '' plus `<field>_set`. */
export type SectionValues = Record<string, unknown>;

export interface SettingsDocument {
  settings: SettingSpec[];
  scalar_sections: string[];
  sections: Record<string, SectionValues>;
  section_schemas: Record<string, SectionSchema>;
  managed_by_environment: Record<string, string[]>;
  outbound_route: string;
  assistant_default_prompt: string;
  tlp_levels: { value: string; description: string }[];
  scan_modes: { value: string; description: string }[];
}

export interface ProbeResult {
  ok: boolean;
  detail: string;
  elapsed_ms: number;
  route?: string;
  status?: number;
  models?: string[];
  found?: Record<string, unknown> | null;
}

// --- Assistant ---------------------------------------------------------------

export interface AssistantStatus {
  available: boolean;
  reason: string;
  enabled: boolean;
  configured: boolean;
  model: string;
  provider: 'ollama' | 'openai';
  agent_enabled: boolean;
  allow_writes: boolean;
  max_steps: number;
  effective_parameters: Record<string, unknown>;
}

export interface AgentStep {
  step: number;
  tool: string;
  arguments: Record<string, unknown>;
  ok: boolean;
  result: unknown;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  steps: AgentStep[];
  created_at: string;
}

/** One observable a conversation's tools actually returned. */
export interface TouchedObservable {
  value: string;
  type?: string;
  verdict?: string;
  status?: string;
  job_id?: string;
}

export interface Conversation {
  id: string;
  title: string;
  job_id: string | null;
  created_at: string;
  updated_at: string;
  messages?: ChatMessage[];
  /** Present when the conversation is read in full. */
  observables?: TouchedObservable[];
}

/** A saved connection to an inference server. Secrets are never returned. */
export interface AssistantProfile {
  id: string;
  name: string;
  provider: 'ollama' | 'openai';
  base_url: string;
  model: string;
  timeout: number;
  temperature: number;
  top_p: number;
  max_tokens: number;
  context_tokens: number;
  is_active: boolean;
  api_key_set: boolean;
  header_names: string[];
  updated_at: string | null;
  updated_by: string | null;
}

export interface AssistantProfileWrite {
  name: string;
  provider: 'ollama' | 'openai';
  base_url: string;
  model: string;
  timeout: number;
  temperature: number;
  top_p: number;
  max_tokens: number;
  context_tokens: number;
  /** Empty keeps the stored key, so the browser never has to hold it. */
  api_key: string;
  headers?: Record<string, string>;
}
