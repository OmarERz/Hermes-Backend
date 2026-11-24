"""Settings: required values fail closed, blank secrets count as unset, secrets never leak."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.config import DEFAULT_LLM_BASE_URL, Settings, read_secret

REQUIRED = {
    "DATABASE_URL": "postgresql://app:s3cret-pw@db:5432/hermes",
    "FIREBASE_PROJECT_ID": "demo-hermes",
    "CURSOR_SIGNING_KEY": "k" * 40,
}


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
        "LLM_PROVIDER",
        "CLAUDE_CODE_MODEL_JUDGE",
        "CLAUDE_CODE_MODEL_ANALYSTS",
        "CLAUDE_CODE_EFFORT",
        "CLAUDE_CODE_TIMEOUT_SECONDS",
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
    assert sorted(settings.secret_values()) == sorted(
        [REQUIRED["DATABASE_URL"], REQUIRED["CURSOR_SIGNING_KEY"], "itop-token-value"]
    )


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


def test_itop_links_use_the_console_url_when_it_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    # On the shared Docker network the backend reaches http://itop:8080, which a browser cannot resolve (F16.1).
    internal = {"ITOP_URL": "http://itop:8080/", "ITOP_TOKEN": "t"}
    assert load(monkeypatch, internal).itop_link_url == "http://itop:8080/"
    assert load(monkeypatch, {**internal, "ITOP_CONSOLE_URL": ""}).itop_link_url == "http://itop:8080/"
    console = load(monkeypatch, {**internal, "ITOP_CONSOLE_URL": "http://127.0.0.1:8080"})
    assert console.itop_link_url == "http://127.0.0.1:8080/"
    assert str(console.itop_url) == "http://itop:8080/"  # REST still goes to the internal name
    assert "ITOP_CONSOLE_URL" not in console.missing()  # optional, never reported as an unconfigured connection
    monkeypatch.delenv("ITOP_URL")
    assert load(monkeypatch).itop_link_url == "http://127.0.0.1:8080/"
    monkeypatch.delenv("ITOP_CONSOLE_URL")
    assert load(monkeypatch).itop_link_url is None


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
    assert settings.llm_provider == "deepseek"  # blank LLM_PROVIDER and CLAUDE_CODE_* fall back to the defaults
    assert (settings.claude_code_model_judge, settings.claude_code_effort) == ("opus", "medium")


def test_blank_judge_url_uses_default(monkeypatch: pytest.MonkeyPatch) -> None:
    assert str(load(monkeypatch, {"LLM_BASE_URL_JUDGE": ""}).llm_base_url_judge) == DEFAULT_LLM_BASE_URL


def test_pgpassword_is_a_masked_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load(monkeypatch, {"PGPASSWORD": "pw/with@reserved:chars"})
    assert "pw/with@reserved:chars" in settings.secret_values()
    assert "pw/with@reserved:chars" not in repr(settings)


def test_validation_error_hides_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """SEG-21: a rejected value with credentials must not appear in the error text."""
    with pytest.raises(ValidationError) as error:
        load(monkeypatch, {"ITOP_URL": "not a url with s3cret-in-it"})
    assert "s3cret-in-it" not in str(error.value)


def test_blank_env_var_does_not_shadow_secret_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """D-042: compose exports blank variables; the Docker secret file must still win."""
    (tmp_path / "itop_token").write_text("from-secret-file")
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("ITOP_TOKEN", "")
    settings = Settings(_env_file=None, _secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert settings.itop_token is not None
    assert settings.itop_token.get_secret_value() == "from-secret-file"


def test_cursor_signing_key_must_be_long_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError) as error:
        load(monkeypatch, {"CURSOR_SIGNING_KEY": "short-key"})
    assert "short-key" not in str(error.value)


def test_cursor_signing_key_can_come_from_a_secret_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "cursor_signing_key").write_text("s" * 40)
    for name, value in REQUIRED.items():
        if name != "CURSOR_SIGNING_KEY":
            monkeypatch.setenv(name, value)
    settings = Settings(_env_file=None, _secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert settings.cursor_signing_key.get_secret_value() == "s" * 40


def test_read_secret_keeps_spaces_and_drops_final_newline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SAMPLE_SECRET", raising=False)
    (tmp_path / "sample_secret").write_text("  padded value \n", encoding="utf-8")
    assert read_secret("sample_secret", tmp_path) == "  padded value "
    (tmp_path / "blank_secret").write_text("   \n", encoding="utf-8")
    assert read_secret("blank_secret", tmp_path) is None


# Read outside Settings (os.environ or compose interpolation) but still documented in .env.example.
EXAMPLE_EXTRAS = {
    "POSTGRES_PASSWORD",  # compose secrets (make compose-secrets)
    "MIGRATOR_DB_PASSWORD",
    "APP_DB_PASSWORD",
    "RETENTION_DB_PASSWORD",
    "FIREBASE_AUTH_EMULATOR_HOST",  # read by firebase-admin and core.devtools.emulator
    "ADVISORY_DOMAINS",  # core.analysts.cve
    "API_PORT",  # compose interpolation
    "DB_PORT",
    "AUTH_EMULATOR_PORT",
    "COMPOSE_SECRETS_DIR",
    "EMBEDDINGS_PORT",  # compose.host.yaml and make worker-host
    "MIGRATION_DATABASE_URL",  # core.devtools.admin (make seed)
    "FORWARDED_ALLOW_IPS",  # read by uvicorn (trusted proxies for X-Forwarded-For)
    "ITOP_PORT",  # compose.itop.yaml interpolation (persistent iTop)
    "ITOP_WEBHOOK_URL",
    "COMPOSE_FILE",  # read by docker compose itself (compose.itop-link.yaml, compose.firebase.yaml)
    "FIREBASE_SERVICE_ACCOUNT_FILE",  # compose.firebase.yaml: host path of the service account secret (D-087)
}
NOT_IN_EXAMPLE = {"PGPASSWORD"}  # the app role's password reaches Settings as the pgpassword secret file only


def test_the_example_env_file_lists_every_setting_and_only_settings() -> None:
    example = (Path(__file__).resolve().parents[2] / ".env.example").read_text(encoding="utf-8")
    listed = set(re.findall(r"^#? ?([A-Z][A-Z0-9_]+)=", example, re.MULTILINE))
    fields = {name.upper() for name in Settings.model_fields} - NOT_IN_EXAMPLE
    assert fields <= listed, f"settings missing from .env.example: {sorted(fields - listed)}"
    assert listed <= fields | EXAMPLE_EXTRAS, (
        f".env.example lists unread variables: {sorted(listed - fields - EXAMPLE_EXTRAS)}"
    )
