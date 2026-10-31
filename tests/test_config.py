from __future__ import annotations

from pathlib import Path

import pytest

from netledger.config import ConfigError, interpolate, load_settings, parse_env_file, settings_from_dict


def test_interpolation_env_default_file_and_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NL_USER", "admin")
    (tmp_path / "secret.txt").write_text("s3cret\n", encoding="utf-8")
    data = {
        "a": "${NL_USER}",
        "b": "${NL_MISSING:-fallback}",
        "c": "${file:secret.txt}",
        "d": "price $$5 for ${env:NL_USER}",
        "e": ["${NL_USER}-x", {"f": "${NL_EMPTY:-}"}],
        "n": 5,
    }
    out = interpolate(data, tmp_path)
    assert out == {"a": "admin", "b": "fallback", "c": "s3cret", "d": "price $5 for admin", "e": ["admin-x", {"f": ""}], "n": 5}


def test_interpolation_missing_variable_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"credentials.default.password: environment variable NOPE_NOT_SET is not set"):
        interpolate({"credentials": {"default": {"password": "${NOPE_NOT_SET}"}}}, tmp_path)
    with pytest.raises(ConfigError, match="needed for git"):
        interpolate({"x": "${NOPE_NOT_SET:?needed for git}"}, tmp_path)


def test_env_file_parsing() -> None:
    text = """
    # comment
    export A=1
    B = "two words"
    C='single $NOT_EXPANDED'
    D=value # trailing comment
    E="line\\nbreak"
    not a pair
    """
    assert parse_env_file(text) == {"A": "1", "B": "two words", "C": "single $NOT_EXPANDED", "D": "value", "E": "line\nbreak"}


def test_env_file_is_loaded_next_to_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NL_TOKEN", raising=False)
    (tmp_path / "netledger.env").write_text("NL_TOKEN=abc123\n", encoding="utf-8")
    (tmp_path / "netledger.yaml").write_text(
        "git:\n  backend: github\n  repo: acme/configs\n  token: ${NL_TOKEN}\n", encoding="utf-8"
    )
    settings = load_settings(tmp_path / "netledger.yaml")
    assert settings.git.token == "abc123"
    assert settings.data_path == tmp_path / "data"
    monkeypatch.delenv("NL_TOKEN", raising=False)


def test_unknown_keys_are_reported(tmp_path: Path) -> None:
    (tmp_path / "netledger.yaml").write_text("backup:\n  wokers: 5\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"backup.wokers: unknown setting"):
        load_settings(tmp_path / "netledger.yaml")


def test_git_backend_validation() -> None:
    with pytest.raises(ConfigError, match="git.url is required"):
        settings_from_dict({"git": {"backend": "git"}})
    with pytest.raises(ConfigError, match="needs git.token or git.github_app"):
        settings_from_dict({"git": {"backend": "github", "repo": "a/b"}})
    with pytest.raises(ConfigError, match="unknown placeholder"):
        settings_from_dict({"git": {"backend": "local", "path": "{name}/{nope}"}})
    settings = settings_from_dict({"git": {"backend": "local", "path": "{site}/{vendor}/{name}"}})
    assert settings.git.path == "{site}/{vendor}/{name}"


def test_notifier_and_compliance_validation() -> None:
    with pytest.raises(ConfigError, match="slack notifier needs a 'url'"):
        settings_from_dict({"notifications": [{"type": "slack"}]})
    with pytest.raises(ConfigError, match="unknown event type"):
        settings_from_dict({"notifications": [{"type": "slack", "url": "https://x", "events": ["nope"]}]})
    with pytest.raises(ConfigError, match="needs must_match and/or must_not_match"):
        settings_from_dict({"compliance": [{"name": "empty"}]})
    with pytest.raises(ConfigError, match="invalid regex"):
        settings_from_dict({"compliance": [{"name": "bad", "must_match": "("}]})
    settings = settings_from_dict({"notifications": [{"type": "teams", "url": "https://x", "events": ["all"]}]})
    assert "config_changed" in settings.notifications[0].events


def test_default_credentials_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = settings_from_dict({})
    assert settings.credential_set("default") is None
    monkeypatch.setenv("NETLEDGER_USERNAME", "bob")
    monkeypatch.setenv("NETLEDGER_PASSWORD", "pw")
    cred = settings.credential_set("default")
    assert cred is not None and cred.username == "bob" and cred.password == "pw"


def test_hmac_requires_key() -> None:
    with pytest.raises(ConfigError, match="secret_key is required"):
        settings_from_dict({"normalize": {"secrets": "hmac"}})
