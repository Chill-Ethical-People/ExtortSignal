from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator


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
    country: str = ""
    industry: str = ""
    domains: list[str] = Field(default_factory=list)
    publication_status: str = Field(default="claimed", max_length=40)
    leak_size: str = Field(default="", max_length=120)
    raw: dict = Field(default_factory=dict)


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
    status: Literal[
        "working", "delayed", "unavailable", "not_checked", "needs_configuration"
    ]
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
    generated_at: datetime = Field(default_factory=utc_now)


class AlertUpdate(BaseModel):
    status: Literal[
        "new", "investigating", "client_notified", "monitoring", "resolved", "dismissed"
    ]
    note: str = Field(default="", max_length=500)


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


class RuntimeSettingsUpdate(BaseModel):
    operating_mode: Literal["off", "passive", "active"]
    scheduling_enabled: bool = True
    public_interval_minutes: int = Field(default=2, ge=1, le=1440)
    catalog_interval_hours: int = Field(default=6, ge=1, le=168)
    active_interval_minutes: int = Field(default=30, ge=5, le=1440)
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

    @field_validator("ai_provider", "ai_model", "ai_base_url", "smtp_host", "smtp_username", "smtp_from")
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
