export type SourceHealth = {
  source: string;
  status: "working" | "delayed" | "unavailable" | "not_checked" | "needs_configuration";
  last_checked_at: string | null;
  last_success_at: string | null;
  latest_record_at: string | null;
  records_received: number;
  message: string;
};

export type Client = {
  id: string;
  canonical_name: string;
  primary_domain: string;
  description: string;
  country: string;
  industry: string;
  countries: string[];
  cities: string[];
  industries: string[];
  related_entities: RelatedEntity[];
  priority: "standard" | "high" | "critical";
  aliases: string[];
  keywords: string[];
  created_at: string;
};

export type RelatedEntity = {
  name: string;
  domain: string;
  relationship: "subsidiary" | "third_party";
};

export type Claim = {
  id: string;
  source: string;
  source_url: string;
  threat_actor: string;
  title: string;
  description: string;
  published_at: string | null;
  discovered_at: string | null;
  received_at: string;
  country: string;
  industry: string;
  domains: string[];
  status: "alleged" | "confirmed";
  publication_status: string;
  leak_size: string;
  ai_industry: string;
  ai_country: string;
  ai_description: string;
  ai_organization_type: string;
  ai_rationale: string;
  ai_sources: string[];
  ai_confidence: number | null;
  ai_provider: string;
  ai_enriched_at: string | null;
};

export type ActorAIAnalysis = {
  actor: string;
  period_days: number;
  claim_count: number;
  growth: GrowthItem;
  top_countries: CountItem[];
  top_industries: CountItem[];
  country_coverage: number;
  industry_coverage: number;
  recent_victims: { name: string; country: string; industry: string; published_at: string | null }[];
  summary: string;
  patterns: string[];
  risk_observations: string[];
  caveats: string[];
  confidence: number;
  provider: string;
  model: string;
  generated_at: string;
};

export type ThreatActorProfile = {
  actor: string;
  summary: string;
  claim_count: number;
  current_count: number;
  previous_count: number;
  change: number;
  growth_percent: number | null;
  trend_basis_days: number;
  first_observed_at: string;
  last_observed_at: string;
  top_countries: CountItem[];
  top_industries: CountItem[];
  sources: CountItem[];
  possible_aliases: string[];
  confidence: "low" | "moderate" | "high";
  caveat: string;
};

export type IntelligenceAnalysisScope = "overall" | "actor" | "region" | "industry";

export type IntelligenceAIAnalysis = Omit<ActorAIAnalysis, "actor"> & {
  scope: IntelligenceAnalysisScope;
  scope_value: string;
  label: string;
  top_groups: CountItem[];
  monthly_trend: { month: string; count: number }[];
};

export type Alert = {
  id: string;
  claim_id: string;
  client_id: string;
  severity: "critical" | "high" | "review";
  score: number;
  reason: string;
  evidence: string;
  status: AlertStatus;
  note: string;
  updated_at: string | null;
  notified_at: string | null;
  created_at: string;
  claim_title: string;
  threat_actor: string;
  source: string;
  source_url: string;
  published_at: string | null;
  discovered_at: string | null;
  received_at: string;
  client_name: string;
  primary_domain: string;
};

export type AlertStatus = "new" | "investigating" | "client_notified" | "monitoring" | "resolved" | "dismissed";

export type NotificationDraft = {
  alert_id: string;
  subject: string;
  body: string;
  scenario: string;
  generated_by: string;
  client_name_sanitized: boolean;
  disclaimer: string;
};

export type AlertIntelligenceContext = {
  alert: Alert;
  claim: Claim;
  client: Client;
  scenario: string;
  actor_profile: ThreatActorProfile | null;
  published_at: string | null;
  ingested_at: string;
};

export type DashboardSummary = {
  urgent_alerts: number;
  awaiting_review: number;
  claims_today: number;
  monitored_clients: number;
  new_alerts: Alert[];
  recent_claims: Claim[];
  sources: SourceHealth[];
  generated_at: string;
};

export type NewClient = {
  canonical_name: string;
  primary_domain: string;
  description: string;
  countries: string[];
  cities: string[];
  industries: string[];
  related_entities: RelatedEntity[];
  priority: "standard" | "high" | "critical";
  aliases: string[];
  keywords: string[];
};

export type CountItem = { name: string; count: number; is_monitored?: boolean };
export type GrowthItem = {
  name: string;
  current_count: number;
  previous_count: number;
  change: number;
  growth_percent: number | null;
};
export type RegionGrowthItem = GrowthItem & { count: number };

export type IntelligenceResponse = {
  period_days: number;
  total: number;
  daily_average: number;
  countries_affected: number;
  active_groups: number;
  growth_basis_days: number;
  overall_growth: Omit<GrowthItem, "name">;
  group_growth: GrowthItem[];
  monitored_geographies: string[];
  monitored_region_growth: RegionGrowthItem[];
  top_groups: CountItem[];
  top_countries: CountItem[];
  top_industries: CountItem[];
  sources: CountItem[];
  monthly_trend: { month: string; count: number }[];
  facets: {
    actors: string[];
    countries: string[];
    industries: string[];
    statuses: string[];
  };
  page: number;
  page_size: number;
  pages: number;
  victims: Claim[];
  generated_at: string;
};

export type DlsTarget = {
  id: string;
  group_name: string;
  description: string;
  fqdn: string;
  address_hint: string;
  location_type: string;
  title: string;
  enabled: boolean;
  available: boolean;
  source: string;
  capture_enabled: boolean;
  first_seen_at: string;
  last_catalog_sync_at: string;
  last_capture_at: string | null;
  last_capture_status: string;
};

export type CaptureJob = {
  id: string;
  target_id: string;
  group_name: string;
  address_hint: string;
  status: string;
  requested_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string;
};

export type DirectSitesOverview = {
  worker_configured: boolean;
  catalog_total: number;
  available: number;
  capture_enabled: number;
  targets: DlsTarget[];
  jobs: CaptureJob[];
};

export type OperatingMode = "off" | "passive" | "active";

export type RuntimeSettings = {
  operating_mode: OperatingMode;
  scheduling_enabled: boolean;
  public_interval_minutes: number;
  catalog_interval_hours: number;
  active_interval_minutes: number;
  ai_enabled: boolean;
  ai_provider: string;
  ai_model: string;
  ai_base_url: string;
  focus_regions: string[];
  victim_digest_enabled: boolean;
  victim_digest_interval_hours: number;
  victim_digest_recipients: string[];
  smtp_host: string;
  smtp_port: number;
  smtp_security: "starttls" | "ssl";
  smtp_username: string;
  smtp_from: string;
  smtp_password_configured: boolean;
  last_public_run_at: string | null;
  last_catalog_run_at: string | null;
  last_active_run_at: string | null;
  last_victim_digest_at: string | null;
  last_victim_digest_run_at: string | null;
  scheduler_process_enabled: boolean;
  worker_configured: boolean;
};

export type RuntimeSettingsUpdate = Pick<RuntimeSettings,
  "operating_mode" | "scheduling_enabled" | "public_interval_minutes" |
  "catalog_interval_hours" | "active_interval_minutes" | "ai_enabled" |
  "ai_provider" | "ai_model" | "ai_base_url" | "focus_regions" |
  "victim_digest_enabled" | "victim_digest_interval_hours" | "victim_digest_recipients" |
  "smtp_host" | "smtp_port" | "smtp_security" | "smtp_username" | "smtp_from"
>;

export type BulkEnrichmentResult = {
  requested: number;
  enriched: number;
  failed: number;
  remaining: number;
  errors: string[];
};

export type VictimDigestResult = {
  status: "sent" | "no_new_victims";
  count: number;
  recipients: string[];
  summary_source?: "ai" | "deterministic" | "deterministic_fallback";
  sent_at?: string;
};

export type AIProvider = {
  id: string;
  name: string;
  region: string;
  base_url: string;
  models: string[];
  api_key_env: string;
  note: string;
  credential_configured: boolean;
  credential_source: "not_required" | "environment" | "local_store" | "none";
};

export type AIConnectionTest = {
  status: "verified";
  provider: string;
  model: string;
  upstream_model: string;
  latency_ms: number;
  response_id: string;
  response_preview: string;
  endpoint_host: string;
  challenge_verified: boolean;
  json_verified: boolean;
  available_models: string[];
  checks: { id: string; label: string; status: "passed" }[];
  checked_at: string;
  credential_source: AIProvider["credential_source"];
};
