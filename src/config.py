"""Load and validate application settings from environment variables."""

from functools import lru_cache
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


SMTP_SUBMISSION_PORT = 587


class Settings(BaseSettings):
    """Typed configuration shared by the scheduler, clients, and processor."""

    defectdojo_base_url: str = Field(..., alias="DEFECTDOJO_BASE_URL")
    defectdojo_api_token: str = Field(..., alias="DEFECTDOJO_API_TOKEN")
    defectdojo_findings_limit: int = Field(100, alias="DEFECTDOJO_FINDINGS_LIMIT")
    defectdojo_request_timeout_seconds: int = Field(
        60, alias="DEFECTDOJO_REQUEST_TIMEOUT_SECONDS"
    )

    project_email_mapping_json: str | None = Field(
        None, alias="PROJECT_EMAIL_MAPPING_JSON"
    )
    project_email_mapping_file: str | None = Field(
        None, alias="PROJECT_EMAIL_MAPPING_FILE"
    )

    database_url: str = Field(..., alias="DATABASE_URL")

    smtp_host: str = Field(..., alias="SMTP_HOST")
    smtp_port: int = Field(SMTP_SUBMISSION_PORT, alias="SMTP_PORT")
    smtp_username: str | None = Field(None, alias="SMTP_USERNAME")
    smtp_password: str | None = Field(None, alias="SMTP_PASSWORD")
    smtp_from_email: str = Field(..., alias="SMTP_FROM_EMAIL")
    smtp_use_tls: bool = Field(True, alias="SMTP_USE_TLS")
    smtp_timeout_seconds: int = Field(30, alias="SMTP_TIMEOUT_SECONDS")
    scheduler_interval_seconds: int = Field(300, alias="SCHEDULER_INTERVAL_SECONDS")
    notification_lease_ttl_seconds: int = Field(
        1800, alias="NOTIFICATION_LEASE_TTL_SECONDS"
    )

    smtp_max_emails_per_minute: int = Field(30, alias="SMTP_MAX_EMAILS_PER_MINUTE")
    smtp_max_emails_per_hour: int = Field(500, alias="SMTP_MAX_EMAILS_PER_HOUR")

    smtp_max_attempts: int = Field(3, alias="SMTP_MAX_ATTEMPTS")
    smtp_retry_delay_seconds: int = Field(60, alias="SMTP_RETRY_DELAY_SECONDS")
    smtp_retry_backoff_multiplier: int = Field(
        2, alias="SMTP_RETRY_BACKOFF_MULTIPLIER"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    @field_validator("defectdojo_base_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        """Normalize the DefectDojo base URL for safe URL joining."""
        return value.rstrip("/")

    @field_validator("project_email_mapping_json", mode="before")
    @classmethod
    def empty_string_to_none(cls, value: Any) -> Any:
        """Treat an empty inline mapping value as an unset configuration."""
        if value == "":
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    """Return one cached Settings instance for the running process."""
    return Settings()
