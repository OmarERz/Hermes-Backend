"""Settings: required values fail closed, blank secrets count as unset, secrets never leak."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from core.config import DEFAULT_LLM_BASE_URL, Settings

REQUIRED = {"DATABASE_URL": "postgresql://app:s3cret-pw@db:5432/hermes", "FIREBASE_PROJECT_ID": "demo-hermes"}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [
        *REQUIRED,
        "ITOP_TOKEN",
        "ITOP_URL",
        "NVD_API_KEY",
        "DEEPSEEK_API_KEY",
        "LLM_BASE_URL_JUDGE",
        "LLM_BASE_URL_ANALYSTS",
        "ABUSECH_AUTH_KEY",
        "RANSOMWARELIVE_API_KEY",
        "ITOP_SYSTEM_USER",
        "FIREBASE_CREDENTIALS_FILE",
    ]:
        monkeypatch.delenv(name, raising=False)


def load(monkeypatch: pytest.MonkeyPatch, env: dict[str, str] | None = None) -> Settings:
    for name, value in {**REQUIRED, **(env or {})}.items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.mark.parametrize("missing", list(REQUIRED))
def test_required_values_fail_closed(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    for name, value in REQUIRED.items():
        if name != missing:
            monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.mark.parametrize("name", list(REQUIRED))
def test_blank_required_value_rejected(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    with pytest.raises(ValidationError):
        load(monkeypatch, {name: "  "})


def test_blank_optional_secret_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"ITOP_TOKEN": "", "NVD_API_KEY": "   "})
    assert settings.itop_token is None
    assert settings.nvd_api_key is None
    assert "ITOP_TOKEN" in settings.missing()
    assert "NVD_API_KEY" in settings.missing()


def test_secrets_do_not_leak_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"ITOP_TOKEN": "itop-token-value", "DEEPSEEK_API_KEY": "sk-abc123"})
    text = repr(settings) + str(settings) + settings.model_dump_json()
    for secret in ("s3cret-pw", "itop-token-value", "sk-abc123"):
        assert secret not in text


def test_secret_values_lists_only_configured_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"ITOP_TOKEN": "itop-token-value"})
    assert sorted(settings.secret_values()) == sorted([REQUIRED["DATABASE_URL"], "itop-token-value"])


def test_llm_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch)
    assert str(settings.llm_base_url_judge) == DEFAULT_LLM_BASE_URL
    assert settings.llm_base_url_analysts == settings.llm_base_url_judge


def test_analysts_url_can_point_to_local_model(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"LLM_BASE_URL_ANALYSTS": "http://localhost:11434/v1"})
    assert str(settings.llm_base_url_analysts) == "http://localhost:11434/v1"


def test_invalid_url_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        load(monkeypatch, {"ITOP_URL": "not a url"})


def test_settings_are_immutable(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch)
    with pytest.raises(ValidationError):
        settings.firebase_project_id = "other"  # type: ignore[misc]


def test_missing_reports_unconfigured_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"ITOP_URL": "https://itop.example.test/", "ITOP_TOKEN": "t"})
    missing = settings.missing()
    assert "ITOP_URL" not in missing
    assert "ITOP_TOKEN" not in missing
    assert "DEEPSEEK_API_KEY" in missing
    assert "LLM_BASE_URL_ANALYSTS" not in missing  # defaults to the judge URL


def test_example_env_file_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped example file starts as-is: blank values fall back to defaults or 'not configured'."""
    example = Path(__file__).resolve().parents[2] / ".env.example"
    settings = Settings(_env_file=example)  # type: ignore[call-arg]
    assert str(settings.llm_base_url_judge) == DEFAULT_LLM_BASE_URL
    assert settings.itop_token is None


def test_blank_judge_url_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert str(load(monkeypatch, {"LLM_BASE_URL_JUDGE": ""}).llm_base_url_judge) == DEFAULT_LLM_BASE_URL


def test_pgpassword_is_a_masked_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"PGPASSWORD": "pw/with@reserved:chars"})
    assert "pw/with@reserved:chars" in settings.secret_values()
    assert "pw/with@reserved:chars" not in repr(settings)
