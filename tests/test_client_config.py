"""Tests for ``TamgaConfig`` and base URL construction."""

from __future__ import annotations

from tamga.client import TamgaConfig
from tamga.transport import DEFAULT_TIMEOUT_SECONDS, LicenseAuth, build_base_url


def test_tamga_config_requires_account_id_and_host() -> None:
    config = TamgaConfig(account_id="acct_123", host="api.tamga.sh")
    assert config.account_id == "acct_123"
    assert config.host == "api.tamga.sh"


def test_tamga_config_defaults() -> None:
    config = TamgaConfig(account_id="acct_123", host="api.tamga.sh")
    assert config.api_version == "1"
    assert config.default_auth is None
    assert config.timeout_seconds == DEFAULT_TIMEOUT_SECONDS
    assert config.user_agent is None


def test_tamga_config_accepts_overrides() -> None:
    auth = LicenseAuth(key="lic-abc")
    config = TamgaConfig(
        account_id="acct_123",
        host="api.tamga.sh",
        api_version="2",
        default_auth=auth,
        timeout_seconds=5.0,
        user_agent="tamga-python/0.1.0",
    )
    assert config.api_version == "2"
    assert config.default_auth == auth
    assert config.timeout_seconds == 5.0
    assert config.user_agent == "tamga-python/0.1.0"


def test_build_base_url_singleplayer_and_multiplayer_both_require_account_id() -> None:
    url = build_base_url("api.tamga.sh", "acct_123")
    assert url == "https://api.tamga.sh/v1/accounts/acct_123"


def test_build_base_url_strips_scheme_and_trailing_slash() -> None:
    assert build_base_url("https://api.tamga.sh/", "acct_123") == (
        "https://api.tamga.sh/v1/accounts/acct_123"
    )
    assert build_base_url("api.tamga.sh", "acct_123") == (
        "https://api.tamga.sh/v1/accounts/acct_123"
    )


def test_build_base_url_preserves_an_explicit_http_scheme() -> None:
    # A self-hosted or local deployment may legitimately serve plain HTTP —
    # the server's TLS cert/key paths are optional and it allows localhost.
    # Silently rewriting http:// to https:// made those hosts unreachable with
    # no diagnostic beyond a TLS error.
    assert build_base_url("http://localhost:8080", "acct_123") == (
        "http://localhost:8080/v1/accounts/acct_123"
    )
    assert build_base_url("http://127.0.0.1:8080/", "acct_123") == (
        "http://127.0.0.1:8080/v1/accounts/acct_123"
    )


def test_default_timeout_outlives_the_servers_own_request_timeout() -> None:
    # The server times a request out at 30s and answers 504 *with* an
    # X-Request-Id. At an equal 30s the client raced it and usually surfaced a
    # local timeout carrying no correlation id at all.
    assert DEFAULT_TIMEOUT_SECONDS > 30.0
