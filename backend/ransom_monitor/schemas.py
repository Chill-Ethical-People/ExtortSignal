from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

from .source_metadata import normalize_leak_size


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def clean_domain_value(value: str, *, required: bool = True) -> str:
    domain = value.strip().lower()
    if not domain and not required:
        return ""
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split("/", 1)[0].removeprefix("www.").rstrip(".")
    if "." not in domain or " " in domain:
        raise ValueError("Enter a domain such as company.example")
    return domain


class RelatedEntity(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    domain: str = Field(default="", max_length=253)
    relationship: Literal["subsidiary", "third_party"]

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return " ".join(value.split())

    @field_validator("domain")
    @classmethod
    def clean_optional_domain(cls, value: str) -> str:
        return clean_domain_value(value, required=False)


class ClientCreate(BaseModel):
    canonical_name: str = Field(min_length=2, max_length=200)
    primary_domain: str = Field(min_length=3, max_length=253)
    description: str = Field(default="", max_length=2000)
    country: str = Field(default="", max_length=80)
    industry: str = Field(default="", max_length=120)
    countries: list[str] = Field(default_factory=list, max_length=30)
    cities: list[str] = Field(default_factory=list, max_length=50)
    industries: list[str] = Field(default_factory=list, max_length=30)
    related_entities: list[RelatedEntity] = Field(default_factory=list, max_length=100)
    priority: Literal["standard", "high", "critical"] = "standard"
    aliases: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("primary_domain")
    @classmethod
    def clean_domain(cls, value: str) -> str:
        return clean_domain_value(value)

    @field_validator("canonical_name", "country", "industry", "description")
    @classmethod
    def clean_text(cls, value: str) -> str:
        return " ".join(value.split())

    @field_validator("countries", "cities", "industries", "keywords")
    @classmethod
    def clean_text_list(cls, values: list[str]) -> list[str]:
        cleaned = [" ".join(value.split()) for value in values if value.strip()]
        return list(dict.fromkeys(cleaned))

    @model_validator(mode="after")
    def sync_legacy_fields(self):
        if self.country and not self.countries:
            self.countries = [self.country]
        elif self.countries and not self.country:
            self.country = self.countries[0]
        if self.industry and not self.industries:
            self.industries = [self.industry]
        elif self.industries and not self.industry:
            self.industry = self.industries[0]
        return self


class Client(ClientCreate):
    id: str
    created_at: datetime


class ClaimInput(BaseModel):
    source: str
    source_record_id: str
    source_url: str = ""
    threat_actor: str
    title: str
    description: str = ""
    published_at: datetime | None = None
    discovered_at: datetime | None = None
    attack_date: datetime | None = None
    country: str = ""
    industry: str = ""
    domains: list[str] = Field(default_factory=list)
    publication_status: str = Field(default="claimed", max_length=40)
    leak_size: str = Field(default="", max_length=120)
    leak_size_bytes: int | None = Field(default=None, ge=0)
    leak_size_source: str = Field(default="", max_length=80)
    source_screenshot_url: str = Field(default="", max_length=2000)
    source_tags: list[str] = Field(default_factory=list, max_length=30)
    detail_checked_at: datetime | None = None
    detail_status: str = Field(default="not_checked", max_length=40)
    raw: dict = Field(default_factory=dict)

    @field_validator("source_url", "source_screenshot_url")
    @classmethod
    def clean_source_url(cls, value: str) -> str:
        candidate = value.strip()[:2000]
        if not candidate:
            return ""
        parsed = urlsplit(candidate)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            return ""
        return candidate

    @field_validator("source_tags")
    @classmethod
    def clean_source_tags(cls, values: list[str]) -> list[str]:
        cleaned = [" ".join(str(value).split())[:80] for value in values if str(value).strip()]
        return list(dict.fromkeys(cleaned))

    @model_validator(mode="after")
    def normalize_source_metadata(self):
        parsed = normalize_leak_size(self.leak_size, source=self.leak_size_source)
        if parsed is not None:
            self.leak_size = parsed.raw
            if self.leak_size_bytes is None:
                self.leak_size_bytes = parsed.bytes
        if not self.leak_size:
            self.leak_size_bytes = None
            self.leak_size_source = ""
        return self


class Claim(ClaimInput):
    id: str
    fingerprint: str
    received_at: datetime
    status: Literal["alleged", "confirmed"] = "alleged"


class Alert(BaseModel):
    id: str
    claim_id: str
    client_id: str
    severity: Literal["critical", "high", "review"]
    score: int
    reason: str
    evidence: str
    status: Literal[
        "new", "investigating", "client_notified", "monitoring", "resolved", "dismissed"
    ] = "new"
    created_at: datetime


class SourceHealth(BaseModel):
    source: str
    status: Literal["working", "delayed", "unavailable", "not_checked", "needs_configuration"]
    last_checked_at: datetime | None = None
    last_success_at: datetime | None = None
    latest_record_at: datetime | None = None
    records_received: int = 0
    message: str = "Waiting for the first check"


class DashboardSummary(BaseModel):
    urgent_alerts: int
    awaiting_review: int
    claims_today: int
    monitored_clients: int
    new_alerts: list[dict]
    recent_claims: list[dict]
    sources: list[SourceHealth]
    focus_regions: list[str] = Field(default_factory=list)
    daily_focus_count: int = 0
    daily_focus_victims: list[dict] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)


class AlertUpdate(BaseModel):
    status: Literal[
        "new", "investigating", "client_notified", "monitoring", "resolved", "dismissed"
    ]
    note: str = Field(default="", max_length=500)


class BulkAlertUpdate(BaseModel):
    alert_ids: list[str] = Field(min_length=1, max_length=1000)
    status: Literal[
        "new", "investigating", "client_notified", "monitoring", "resolved", "dismissed"
    ]
    note: str = Field(default="", max_length=500)

    @field_validator("alert_ids")
    @classmethod
    def clean_alert_ids(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not cleaned:
            raise ValueError("Select at least one alert")
        return cleaned


class NotificationDraftUpdate(BaseModel):
    subject: str = Field(min_length=1, max_length=300)
    body: str = Field(min_length=1, max_length=20_000)

    @field_validator("subject", "body")
    @classmethod
    def clean_draft_text(cls, value: str) -> str:
        return value.strip()


class FalsePositiveFeedbackCreate(BaseModel):
    category: Literal[
        "unrelated_organization",
        "ambiguous_name",
        "stale_or_duplicate",
        "incorrect_context",
        "other",
    ] = "unrelated_organization"
    analyst_note: str = Field(default="", max_length=2000)

    @field_validator("analyst_note")
    @classmethod
    def clean_feedback_note(cls, value: str) -> str:
        return " ".join(value.split())


class BulkFalsePositiveFeedbackCreate(FalsePositiveFeedbackCreate):
    alert_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("alert_ids")
    @classmethod
    def clean_alert_ids(cls, values: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not cleaned:
            raise ValueError("Select at least one alert")
        return cleaned


class DlsLocationInput(BaseModel):
    group_name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    fqdn: str = Field(min_length=10, max_length=255)
    location_type: str = Field(default="DLS", max_length=40)
    title: str = Field(default="", max_length=240)
    enabled: bool = True
    available: bool = False
    source: str = Field(default="ransomware_live", max_length=80)


class DlsTargetUpdate(BaseModel):
    capture_enabled: bool


class DlsBulkTargetUpdate(BaseModel):
    target_ids: list[str] = Field(min_length=1, max_length=500)
    capture_enabled: bool

    @field_validator("target_ids")
    @classmethod
    def clean_target_ids(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values if value.strip()]
        return list(dict.fromkeys(cleaned))


class CaptureJobCleanupRequest(BaseModel):
    statuses: list[Literal["queued", "failed"]] = Field(min_length=1, max_length=2)

    @field_validator("statuses")
    @classmethod
    def clean_statuses(
        cls, values: list[Literal["queued", "failed"]]
    ) -> list[Literal["queued", "failed"]]:
        return list(dict.fromkeys(values))


class CaptureWorkerCompletion(BaseModel):
    screenshot_path: str = Field(min_length=1, max_length=500)
    screenshot_paths: list[str] = Field(min_length=1, max_length=200)
    text_path: str = Field(default="", max_length=500)
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    text_sha256: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")
    extraction_method: str = Field(default="", max_length=40)
    duplicate_of_job_id: str = Field(default="", max_length=80)
    detected_statuses: list[str] = Field(default_factory=list, max_length=20)
    status_changed: bool = False
    added_line_count: int = Field(default=0, ge=0, le=1_000_000)
    removed_line_count: int = Field(default=0, ge=0, le=1_000_000)
    scroll_count: int = Field(default=0, ge=0, le=10_000)
    page_height: int = Field(default=0, ge=0, le=1_000_000)
    capture_truncated: bool = False
    coverage_status: str = Field(default="not_measured", max_length=40)
    anchor_lines: list[str] = Field(default_factory=list, max_length=100)
    continuity_status: str = Field(default="no_baseline", max_length=40)
    continuity_anchor: str = Field(default="", max_length=240)
    continuity_page: int = Field(default=0, ge=0, le=1_000)
    pagination_detected: bool = False
    more_content_suspected: bool = False
    css_blur_element_count: int = Field(default=0, ge=0, le=100_000)
    victim_match_found: bool = False
    opsec_status: Literal["passed", "failed", "not_checked"] = "not_checked"
    tor_preflight_passed: bool = False
    blocked_request_count: int = Field(default=0, ge=0, le=1_000_000)
    blocked_popup_count: int = Field(default=0, ge=0, le=100_000)
    blocked_download_count: int = Field(default=0, ge=0, le=100_000)
    opsec_controls: list[str] = Field(default_factory=list, max_length=50)

    @field_validator(
        "screenshot_path",
        "text_path",
        "extraction_method",
        "coverage_status",
        "continuity_status",
        "continuity_anchor",
        "duplicate_of_job_id",
    )
    @classmethod
    def clean_capture_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("screenshot_paths", "detected_statuses", "anchor_lines", "opsec_controls")
    @classmethod
    def clean_capture_lists(cls, values: list[str]) -> list[str]:
        cleaned = [" ".join(value.split()) for value in values if value.strip()]
        return list(dict.fromkeys(cleaned))


class CaptureWorkerFailure(BaseModel):
    error: str = Field(min_length=1, max_length=500)
    opsec_status: Literal["passed", "failed", "not_checked"] = "not_checked"
    tor_preflight_passed: bool = False
    blocked_request_count: int = Field(default=0, ge=0, le=1_000_000)
    blocked_popup_count: int = Field(default=0, ge=0, le=100_000)
    blocked_download_count: int = Field(default=0, ge=0, le=100_000)
    opsec_controls: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("error")
    @classmethod
    def clean_error(cls, value: str) -> str:
        return " ".join(value.split())


class AIProviderCredentialUpdate(BaseModel):
    api_key: SecretStr

    @model_validator(mode="after")
    def validate_key(self):
        if len(self.api_key.get_secret_value().strip()) < 8:
            raise ValueError("API key must contain at least 8 characters")
        return self


class SMTPPasswordUpdate(BaseModel):
    password: SecretStr

    @model_validator(mode="after")
    def validate_password(self):
        if len(self.password.get_secret_value()) < 1:
            raise ValueError("SMTP password cannot be empty")
        return self


class BulkVictimEnrichmentRequest(BaseModel):
    limit: int = Field(default=25, ge=1, le=100)
    claim_ids: list[str] = Field(default_factory=list, max_length=100)


class AIJobRequest(BaseModel):
    job_type: Literal[
        "intelligence_analysis",
        "actor_analysis",
        "actor_profile_refresh",
        "victim_enrichment",
        "bulk_victim_enrichment",
        "alert_assessment",
        "bulk_alert_assessment",
        "alert_notification_draft",
        "claim_awareness_draft",
        "provider_test",
        "victim_digest",
    ]
    payload: dict = Field(default_factory=dict)


class RuntimeSettingsUpdate(BaseModel):
    operating_mode: Literal["off", "passive", "active"]
    scheduling_enabled: bool = True
    public_interval_minutes: int = Field(default=2, ge=1, le=1440)
    catalog_interval_hours: int = Field(default=6, ge=1, le=168)
    active_interval_minutes: int = Field(default=30, ge=5, le=1440)
    capture_max_scrolls: int = Field(default=60, ge=10, le=200)
    capture_stable_passes: int = Field(default=3, ge=2, le=8)
    capture_scroll_delay_ms: int = Field(default=1000, ge=250, le=5000)
    capture_max_page_height: int = Field(default=50000, ge=5000, le=100000)
    capture_segment_height: int = Field(default=1400, ge=800, le=2400)
    ai_enabled: bool = False
    ai_provider: str = Field(default="ollama", min_length=2, max_length=80)
    ai_model: str = Field(default="qwen3:4b", max_length=160)
    ai_base_url: str = Field(default="http://127.0.0.1:11434/v1", max_length=500)
    focus_regions: list[str] = Field(default_factory=list, max_length=50)
    victim_digest_enabled: bool = False
    victim_digest_interval_hours: int = Field(default=24, ge=1, le=168)
    victim_digest_recipients: list[str] = Field(default_factory=list, max_length=20)
    smtp_host: str = Field(default="", max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: Literal["starttls", "ssl"] = "starttls"
    smtp_username: str = Field(default="", max_length=320)
    smtp_from: str = Field(default="", max_length=320)

    @field_validator(
        "ai_provider", "ai_model", "ai_base_url", "smtp_host", "smtp_username", "smtp_from"
    )
    @classmethod
    def clean_runtime_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("focus_regions")
    @classmethod
    def clean_focus_regions(cls, values: list[str]) -> list[str]:
        cleaned = [" ".join(value.split()) for value in values if value.strip()]
        return list(dict.fromkeys(cleaned))

    @field_validator("victim_digest_recipients")
    @classmethod
    def clean_digest_recipients(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip().lower() for value in values if value.strip()]
        for value in cleaned:
            if "@" not in value or value.startswith("@") or value.endswith("@"):
                raise ValueError(f"Invalid digest recipient: {value}")
        return list(dict.fromkeys(cleaned))
