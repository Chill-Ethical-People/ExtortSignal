export type SourceHealth = {
  source: string;
  status:
    | "working"
    | "delayed"
    | "unavailable"
    | "not_checked"
    | "needs_configuration";
  last_checked_at: string | null;
  last_success_at: string | null;
  latest_record_at: string | null;
  records_received: number;
  observations_stored: number;
  observation_versions_stored: number;
  oldest_observation_at: string | null;
  newest_observation_at: string | null;
  coverage_status: "complete" | "partial" | "failed" | "not_checked";
  coverage_message: string;
  coverage_checked_at: string | null;
  coverage_gaps: string[];
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
  attack_date: string | null;
  received_at: string;
  country: string;
  industry: string;
  domains: string[];
  status: "alleged" | "confirmed";
  publication_status: string;
  leak_size: string;
  leak_size_bytes: number | null;
  leak_size_source: string;
  source_screenshot_url: string;
  source_tags: string[];
  detail_checked_at: string | null;
  detail_status: string;
  ai_industry: string;
  ai_country: string;
  ai_description: string;
  ai_organization_type: string;
  ai_rationale: string;
  ai_sources: string[];
  ai_past_incidents: PastIncident[];
  ai_osint_status: string;
  ai_osint_checked_at: string | null;
  ai_confidence: number | null;
  ai_provider: string;
  ai_enriched_at: string | null;
  is_focus_region?: boolean;
  is_new_today?: boolean;
  matched_focus_regions?: string[];
  organization_profile?: OrganizationProfile | null;
};

export type OrganizationProfile = {
  id: string;
  canonical_name: string;
  primary_domain: string;
  aliases: string[];
  domains: string[];
  description: string;
  industry: string;
  country: string;
  organization_type: string;
  confidence: number;
  provenance: {
    claim_id: string;
    provider: string;
    source_refs: string[];
    observed_at: string;
  }[];
  analyst_reviewed: boolean;
  created_at: string;
  updated_at: string;
};

export type PastIncident = {
  published_at: string;
  incident_type: string;
  summary: string;
  source_url: string;
  source_name?: string;
  threat_actor?: string;
  evidence_type: "local_claim" | "news_report" | string;
  confidence: number;
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
  recent_victims: {
    name: string;
    country: string;
    industry: string;
    published_at: string | null;
  }[];
  summary: string;
  patterns: string[];
  risk_observations: string[];
  caveats: string[];
  confidence: number;
  provider: string;
  model: string;
  generated_at: string;
};

export type ThreatActorProfessionalProfile = {
  profile_schema: string;
  profile_status: "sourced_profile" | "catalogue_context_only" | "label_only";
  actor_class: string;
  distribution: string;
  summary: string;
  motivation: string;
  targeting: string;
  capabilities: string;
  campaign_history: string;
  source_kind:
    | "ai_refreshed"
    | "mitre_attack"
    | "ransomware_live_catalog"
    | "actor_registry"
    | "static_local_curated"
    | "static_local_framework"
    | "static_local_catalog"
    | "static_local_label";
  sources: string[];
  source_references: { name: string; url: string }[];
  source_confidence: "low" | "moderate" | "high";
  analytic_confidence: number | null;
  generated_at: string | null;
  reviewed_at: string | null;
  caveats: string[];
  identity: {
    attack_id: string;
    canonical_name: string;
    aliases: string[];
    resolution_basis: string;
    related_but_distinct: { name: string; relationship: string }[];
  };
  technique_count: number;
  software_count: number;
  campaign_count: number;
  field_evidence: Record<string, string[]>;
  osint_evidence_count: number;
  independent_source_count: number;
  osint_researched_at: string | null;
  ai_overlay_status: "applied" | "insufficient_evidence" | "not_requested";
  top_techniques: { id: string; name: string; tactics: string[]; url: string }[];
  priority_actions: string[];
  hunt_hypotheses: string[];
  detection_coverage: {
    status: "not_assessed";
    documented_technique_count: number;
    message: string;
  };
  key_judgments: string[];
};

export type ThreatActorOsintEvidence = {
  id: string;
  actor: string;
  source_name: string;
  source_tier: string;
  title: string;
  source_url: string;
  published_at: string | null;
  retrieved_at: string;
  excerpt: string;
  evidence_type: string;
  content_sha256: string;
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
  cti_profile: null | {
    attack_id: string;
    canonical_name: string;
    aliases: string[];
    description: string;
    created: string | null;
    modified: string | null;
    attack_url: string;
    match_confidence: "moderate" | "high";
    match_basis: "canonical_name" | "associated_name";
    refreshed_at: string;
    source_note: string;
    techniques: {
      id: string;
      name: string;
      tactics: string[];
      relationship: string;
      url: string;
      references?: { source: string; title: string; url: string }[];
    }[];
    software: {
      id: string;
      name: string;
      type: string;
      description: string;
      url: string;
      references?: { source: string; title: string; url: string }[];
    }[];
    campaigns: {
      id: string;
      name: string;
      description: string;
      first_seen: string | null;
      last_seen: string | null;
      url: string;
      references?: { source: string; title: string; url: string }[];
    }[];
    references: { source: string; title: string; url: string }[];
  };
  catalog_profile: null | { name: string; description: string; source: string };
  baseline_profile: {
    summary: string;
    source: string;
    confidence: "low" | "moderate" | "high";
    source_kind?: string;
    reviewed_at?: string;
  };
  professional_profile?: ThreatActorProfessionalProfile;
  osint_evidence: ThreatActorOsintEvidence[];
  ai_profile_refresh: null | {
    actor: string;
    summary: string;
    motivation: string;
    targeting: string;
    capabilities: string;
    campaign_history: string;
    confidence: number;
    caveats: string[];
    sources: string[];
    provider: string;
    model: string;
    generated_at: string;
    field_evidence?: Record<string, string[]>;
    osint_evidence_count?: number;
    independent_source_count?: number;
    osint_researched_at?: string;
    research_warnings?: string[];
    profile_schema?: string;
    prompt_version?: string;
    key_judgments?: string[];
    priority_actions?: string[];
    hunt_hypotheses?: string[];
    overlay_status?: "applied" | "insufficient_evidence";
  };
};

export type ThreatActorProfileIndexItem = {
  actor: string;
  claim_count: number;
  first_observed_at: string;
  last_observed_at: string;
};

export type ActivityResponse = {
  items: Claim[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  actors: string[];
  countries: string[];
  focus_regions: string[];
  daily_focus_count: number;
};

export type ClaimSourceEvidence = {
  claim_id: string;
  source: string;
  source_record_id: string;
  source_url: string;
  description: string;
  archived_record: Record<string, unknown>;
  observations: {
    id: string;
    source: string;
    source_record_id: string;
    source_url: string;
    published_at: string | null;
    received_at: string;
    content_sha256: string;
    parser_version: string;
  }[];
};

export type IntelligenceAnalysisScope =
  | "overall"
  | "actor"
  | "region"
  | "industry";

export type IntelligenceAIAnalysis = Omit<ActorAIAnalysis, "actor"> & {
  id: string;
  scope: IntelligenceAnalysisScope;
  scope_value: string;
  label: string;
  top_groups: CountItem[];
  monthly_trend: { month: string; count: number }[];
  monthly_attack_trend: { month: string; count: number }[];
  attack_date_coverage: number;
  counting_method: string;
  threat_actor_context?: {
    actor: string;
    professional_profile: ThreatActorProfessionalProfile;
    local_observations: {
      claim_count: number;
      observation_window_days: number;
      top_countries: CountItem[];
      top_industries: CountItem[];
      caveat: string;
    };
  }[];
  fresh_osint_safety_net?: {
    actor: string;
    status: string;
    researched_at: string;
    independent_source_count: number;
    warnings: string[];
    evidence: {
      id: string;
      source_name: string;
      source_tier: string;
      title: string;
      source_url: string;
      published_at: string;
      excerpt: string;
      evidence_type: string;
    }[];
  }[];
};

export type AIJobType =
  | "intelligence_analysis"
  | "actor_analysis"
  | "actor_profile_refresh"
  | "victim_enrichment"
  | "bulk_victim_enrichment"
  | "alert_assessment"
  | "bulk_alert_assessment"
  | "alert_notification_draft"
  | "claim_awareness_draft"
  | "provider_test"
  | "victim_digest";

export type AIJob = {
  id: string;
  job_type: AIJobType;
  title: string;
  status: "queued" | "running" | "completed" | "failed";
  payload: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error: string;
  destination: "home" | "intelligence" | "activity" | "alerts" | "settings";
  target_id: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  seen_at: string | null;
};

export type AIJobHistoryResponse = {
  items: AIJob[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
  status_counts: Partial<Record<AIJob["status"], number>>;
  job_types: AIJobType[];
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
  claim_country: string;
  claim_industry: string;
};

export type AlertStatus =
  | "new"
  | "investigating"
  | "client_notified"
  | "monitoring"
  | "resolved"
  | "dismissed";

export type NotificationDraft = {
  id: string;
  alert_id: string;
  client_id: string;
  subject: string;
  body: string;
  scenario: string;
  generated_by: string;
  client_name_sanitized: boolean;
  disclaimer: string;
  created_at: string;
  updated_at: string;
};

export type FalsePositivePrecedent = {
  feedback_id: string;
  category: string;
  analyst_note: string;
  similarity: number;
  created_at: string;
  retrieval_basis: string;
};

export type AlertAIAssessment = {
  id: string;
  alert_id: string;
  claim_id: string;
  executive_summary: string;
  named_victim_profile: string;
  alert_relevance: string;
  analytic_assessment: string;
  recommended_actions: string[];
  evidence_gaps: string[];
  confidence: number;
  victim_details: {
    name: string;
    description: string;
    industry: string;
    geography: string;
    organization_type: string;
    enrichment_confidence: number | null;
    past_incidents: PastIncident[];
    source_urls: string[];
    enriched_at: string | null;
  };
  scenario: string;
  deterministic_match_score: number;
  deterministic_severity: Alert["severity"];
  disclaimer: string;
  provider: string;
  model: string;
  generated_at: string;
};

export type AlertIntelligenceContext = {
  alert: Alert;
  claim: Claim;
  client: Client;
  scenario: string;
  actor_profile: ThreatActorProfile | null;
  published_at: string | null;
  ingested_at: string;
  saved_drafts: NotificationDraft[];
  ai_assessments: AlertAIAssessment[];
  false_positive_precedents: FalsePositivePrecedent[];
  capture_jobs: CaptureJob[];
};

export type BulkAlertUpdateResult = {
  requested: number;
  updated: number;
  missing: number;
  missing_alert_ids: string[];
  status: AlertStatus;
  updated_at: string;
};

export type ClientDeletionResult = {
  deleted_client: { id: string; canonical_name: string };
  deleted_alerts: number;
  deleted_drafts: number;
  deleted_feedback: number;
  deleted_assessments: number;
};

export type BulkFalsePositiveResult = {
  requested: number;
  recorded: number;
  failed: number;
  recorded_alert_ids: string[];
  failures: { alert_id: string; error: string }[];
  status: "dismissed";
  category: string;
  updated_at: string;
};

export type DashboardSummary = {
  urgent_alerts: number;
  awaiting_review: number;
  claims_today: number;
  monitored_clients: number;
  new_alerts: Alert[];
  recent_claims: Claim[];
  sources: SourceHealth[];
  focus_regions: string[];
  daily_focus_count: number;
  daily_focus_victims: Claim[];
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
  raw_source_records: number;
  duplicates_collapsed: number;
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
  monthly_attack_trend: { month: string; count: number }[];
  attack_date_coverage: number;
  counting_method: string;
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
  screenshot_path: string;
  screenshot_paths: string[];
  segment_count: number;
  css_blur_element_count: number;
  text_path: string;
  content_sha256: string;
  text_sha256: string;
  extraction_method: string;
  duplicate_of_job_id: string;
  detected_statuses: string[];
  status_changed: boolean;
  added_line_count: number;
  removed_line_count: number;
  scroll_count: number;
  page_height: number;
  capture_truncated: boolean;
  coverage_status:
    | "stable"
    | "scroll_limit"
    | "height_limit"
    | "interaction_limit"
    | "previous_anchor_found"
    | "victim_found"
    | "not_measured";
  anchor_lines: string[];
  continuity_status: "no_baseline" | "matched" | "missing" | "ocr_unavailable";
  continuity_anchor: string;
  continuity_page: number;
  pagination_detected: boolean;
  more_content_suspected: boolean;
  opsec_status: "passed" | "failed" | "not_checked";
  tor_preflight_passed: boolean;
  blocked_request_count: number;
  blocked_popup_count: number;
  blocked_download_count: number;
  opsec_controls: string[];
  alert_id: string;
  claim_id: string;
  victim_name: string;
  capture_scope: "site_overview" | "flagged_victim" | string;
  victim_match_found: boolean;
  evidence_readiness: "ready" | "review" | "not_ready" | "not_assessed";
  readiness_reason: string;
  victim_candidates: Array<{
    name: string;
    domain: string;
    published_at: string;
    source:
      | "retained_claim_match"
      | "capture_label"
      | "capture_domain"
      | string;
    confidence: "high" | "medium" | "low" | string;
  }>;
};

export type DirectSitesOverview = {
  worker_configured: boolean;
  worker_online: boolean;
  ocr_configured: boolean;
  evidence_directory: string;
  catalog_total: number;
  available: number;
  capture_enabled: number;
  job_status_counts: Record<string, number>;
  targets: DlsTarget[];
  jobs: CaptureJob[];
};

export type CaptureJobCleanupResult = {
  statuses: Array<"queued" | "failed">;
  deleted: number;
  deleted_by_status: Record<string, number>;
};

export type OperatingMode = "off" | "passive" | "active";

export type RuntimeSettings = {
  operating_mode: OperatingMode;
  scheduling_enabled: boolean;
  public_interval_minutes: number;
  catalog_interval_hours: number;
  active_interval_minutes: number;
  capture_max_scrolls: number;
  capture_stable_passes: number;
  capture_scroll_delay_ms: number;
  capture_max_page_height: number;
  capture_segment_height: number;
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
  worker_online: boolean;
};

export type RuntimeSettingsUpdate = Pick<
  RuntimeSettings,
  | "operating_mode"
  | "scheduling_enabled"
  | "public_interval_minutes"
  | "catalog_interval_hours"
  | "active_interval_minutes"
  | "capture_max_scrolls"
  | "capture_stable_passes"
  | "capture_scroll_delay_ms"
  | "capture_max_page_height"
  | "capture_segment_height"
  | "ai_enabled"
  | "ai_provider"
  | "ai_model"
  | "ai_base_url"
  | "focus_regions"
  | "victim_digest_enabled"
  | "victim_digest_interval_hours"
  | "victim_digest_recipients"
  | "smtp_host"
  | "smtp_port"
  | "smtp_security"
  | "smtp_username"
  | "smtp_from"
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
  focus_region_count?: number;
  focus_regions?: string[];
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
