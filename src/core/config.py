"""Typed configuration from environment variables, a local env file or Docker secrets (docs/11 §2, D-042).

Secrets are `SecretStr` so they never appear in `repr`, logs or API responses (SEG-20, SEG-21).
Required values fail closed at startup; an empty optional secret counts as "not configured", never as a
valid empty key (prototype conflict C5).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DOCKER_SECRETS_DIR = Path("/run/secrets")
MIN_CURSOR_KEY_LENGTH = 32
DEFAULT_LLM_BASE_URL = "https://api.deepseek.com/beta"  # strict tool mode (JUE-03) ⚠️ verified in F0.5

_OPTIONAL_FIELDS = (
    "itop_url",
    "itop_token",
    "itop_system_user",
    "nvd_api_key",
    "deepseek_api_key",
    "llm_base_url_analysts",
    "abusech_auth_key",
    "ransomwarelive_api_key",
    "firebase_credentials_file",
)


class Settings(BaseSettings):
    """Backend settings. Field names map to the variables of docs/11 §2 (upper case)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=DOCKER_SECRETS_DIR if DOCKER_SECRETS_DIR.is_dir() else None,
        extra="ignore",
        frozen=True,
        # Validation errors must not echo inputs: a bad URL may contain credentials (SEG-21).
        hide_input_in_errors=True,
        # A blank variable (e.g. exported empty by compose) must not shadow a Docker secret file.
        env_ignore_empty=True,
    )

    # Connections required to start
    database_url: SecretStr = Field(description="PostgreSQL connection URL; the password may come from PGPASSWORD")
    # libpq/psycopg read PGPASSWORD when the URL has none, so passwords never need URL encoding (compose.yaml)
    pgpassword: SecretStr | None = None
    firebase_project_id: str = Field(min_length=1, description="Firebase project that issues the ID tokens")
    # HMAC key that signs pagination cursors (API-02); a secret, also readable from a Docker secret file
    cursor_signing_key: SecretStr = Field(description="Key that signs pagination cursors (at least 32 characters)")

    # Firebase Admin SDK service account: the most sensitive secret (SEG-20)
    firebase_credentials_file: Path | None = None

    # iTop REST API (D-003, D-037)
    itop_url: HttpUrl | None = None
    itop_token: SecretStr | None = None
    itop_system_user: str | None = None

    # Vulnerability and threat sources
    nvd_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    ransomwarelive_api_key: SecretStr | None = None

    # Swagger UI, ReDoc and /openapi.json: off unless explicitly enabled for development (API-01, docs/14 §10.4)
    api_docs_enabled: bool = False

    # LLM endpoints (OpenAI-compatible API, D-029)
    deepseek_api_key: SecretStr | None = None
    llm_base_url_judge: HttpUrl = HttpUrl(DEFAULT_LLM_BASE_URL)
    llm_base_url_analysts: HttpUrl | None = None

    @field_validator("database_url")
    @classmethod
    def _database_url_not_blank(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("DATABASE_URL is empty")
        return value

    @field_validator("cursor_signing_key")
    @classmethod
    def _cursor_key_strong_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().strip()) < MIN_CURSOR_KEY_LENGTH:
            raise ValueError(f"CURSOR_SIGNING_KEY must have at least {MIN_CURSOR_KEY_LENGTH} characters")
        return value

    @field_validator("firebase_project_id", mode="before")
    @classmethod
    def _project_id_stripped(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator(*_OPTIONAL_FIELDS, "pgpassword", mode="before")
    @classmethod
    def _blank_means_unset(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("llm_base_url_judge", mode="before")
    @classmethod
    def _blank_judge_url_means_default(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return DEFAULT_LLM_BASE_URL
        return value

    @model_validator(mode="after")
    def _analysts_default_to_judge(self) -> Self:
        if self.llm_base_url_analysts is None:
            object.__setattr__(self, "llm_base_url_analysts", self.llm_base_url_judge)
        return self

    def secret_values(self) -> list[str]:
        """Every configured secret value, for the log masking filter (SEG-24)."""
        secrets: list[str] = []
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                raw = value.get_secret_value()
                if raw:
                    secrets.append(raw)
        return secrets

    def missing(self) -> list[str]:
        """Optional connections that are not configured, as variable names (setup wizard, D-042)."""
        return [name.upper() for name in _OPTIONAL_FIELDS if getattr(self, name) is None]
