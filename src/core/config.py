"""Typed configuration from environment variables, a local env file or Docker secrets (docs/11 §2, D-042).

Secrets are `SecretStr` so they never appear in `repr`, logs or API responses (SEG-20, SEG-21).
Required values fail closed at startup; an empty optional secret counts as "not configured", never as a
valid empty key (prototype conflict C5).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DOCKER_SECRETS_DIR = Path("/run/secrets")
MIN_CURSOR_KEY_LENGTH = 32
DEFAULT_LLM_BASE_URL = "https://api.deepseek.com/beta"  # strict tool mode (JUE-03) ⚠️ verified in F0.5
# A Claude Code model alias or name (opus, sonnet, claude-opus-5-5, sonnet[1m]): it reaches the CLI as the value of
# --model, so it can never start with "-" and be read as another flag (D-084).
CLAUDE_MODEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:\[\]-]{0,99}$"
# Effort levels of `claude --effort` (checked against `claude --help` 2.1.330)
ClaudeEffort = Literal["low", "medium", "high", "xhigh", "max"]


def read_secret(name: str, secrets_dir: Path = DOCKER_SECRETS_DIR) -> str | None:
    """A credential from the environment (upper-case name) or from a mounted Docker secret file (lower-case name).

    Used where Settings is not available (provisioning, Alembic). A blank value counts as not configured;
    otherwise the value is kept as is (leading and trailing spaces are part of a password).
    """
    value = os.environ.get(name.upper(), "")
    if value.strip():
        return value
    path = secrets_dir / name.lower()
    if path.is_file():
        # Keep the credential as written; drop only a final line break (the postgres image does the same).
        content = path.read_text(encoding="utf-8").removesuffix("\n").removesuffix("\r")
        return content if content.strip() else None
    return None


_OPTIONAL_FIELDS = (
    "itop_url",
    "itop_token",
    "itop_system_user",
    "itop_webhook_token",
    "itop_org_id",
    "itop_caller_id",
    "nvd_api_key",
    "deepseek_api_key",
    "llm_base_url_analysts",
    "abusech_auth_key",
    "ransomwarelive_api_key",
    "firebase_credentials_file",
    "embeddings_url",
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
    # The iTop console people open from the links of the front and the notifications; unset = itop_url. Set it when
    # the backend reaches iTop by a name the browser cannot (ITOP_URL=http://itop:8080 on the shared network, F16.1).
    itop_console_url: HttpUrl | None = None
    itop_token: SecretStr | None = None
    itop_system_user: str | None = None
    # Shared secret iTop sends as `Authorization: Bearer` to the webhook doorbell (ARQ-02); unset = webhook off
    itop_webhook_token: SecretStr | None = None
    # Who files tickets (D-036, prototype C7): organization, the system person as caller, the service; ids in iTop
    itop_org_id: str | None = None
    itop_caller_id: str | None = None
    itop_service_id: str | None = None

    # Scheduled simulated scan every N hours (docs/03 §2); 0 = only on demand (POST /api/scans)
    scan_interval_hours: int = Field(default=0, ge=0, le=24 * 30)

    # Embeddings service on the internal network (docker/embeddings, ING-07); unset = the news cycle is off
    embeddings_url: HttpUrl | None = None

    # Vulnerability and threat sources
    nvd_api_key: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    ransomwarelive_api_key: SecretStr | None = None

    # Swagger UI, ReDoc and /openapi.json: off unless explicitly enabled for development (API-01, docs/14 §10.4)
    api_docs_enabled: bool = False

    # HSTS (ASVS V3.4.1): one year always; `includeSubDomains` only when the API has its own host name, because it
    # makes browsers require HTTPS on every subdomain of that host for a year (README §7). Off by default.
    hsts_include_subdomains: bool = False

    # Password e-mails (D-105) each admin can have Firebase send per hour from this API process: a stolen admin session
    # cannot use the project to spam addresses. The test stacks raise it (compose.ci.yaml), as Schemathesis creates
    # many accounts before the Bruno step.
    password_emails_per_hour: int = Field(default=20, ge=1, le=100_000)

    # Browser origins allowed to call the API cross-origin (the React front on another origin), comma-separated
    # exact origins such as "https://hermes-front.example.com". Empty (default) = same origin only, e.g. front and
    # API behind one reverse proxy. A wildcard is refused: the API carries bearer tokens.
    cors_allowed_origins: str = ""

    @property
    def itop_link_url(self) -> str | None:
        """Base of the iTop links shown to people: the console URL when set, else the REST base URL."""
        url = self.itop_console_url or self.itop_url
        return str(url) if url is not None else None

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip().rstrip("/") for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @field_validator("cors_allowed_origins")
    @classmethod
    def _cors_origins_are_exact(cls, value: str) -> str:
        for origin in (o.strip().rstrip("/") for o in value.split(",") if o.strip()):
            if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?", origin):
                raise ValueError("CORS_ALLOWED_ORIGINS must list exact origins like https://front.example.com")
        return value

    # LLM endpoints (OpenAI-compatible API, D-029)
    deepseek_api_key: SecretStr | None = None
    llm_base_url_judge: HttpUrl = HttpUrl(DEFAULT_LLM_BASE_URL)
    llm_base_url_analysts: HttpUrl | None = None

    # LLM provider (D-084): "deepseek" (the OpenAI-compatible API above) or "claude-code" (the Claude Code CLI with the
    # operator's Claude subscription). claude-code works only for a worker run on the host (make worker-host): the CLI
    # and its login are not in the images, so a container fails closed (analysts and judge off).
    llm_provider: Literal["deepseek", "claude-code"] = "deepseek"
    # Claude Code model of each role (an alias such as opus or sonnet, or a full model name), effort and the timeout
    # of one CLI call in seconds
    claude_code_model_judge: str = Field(default="opus", pattern=CLAUDE_MODEL_PATTERN)
    claude_code_model_analysts: str = Field(default="sonnet", pattern=CLAUDE_MODEL_PATTERN)
    claude_code_effort: ClaudeEffort = "medium"
    claude_code_timeout_seconds: int = Field(default=300, ge=30, le=3600)

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

    @field_validator(*_OPTIONAL_FIELDS, "pgpassword", "itop_console_url", mode="before")
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
