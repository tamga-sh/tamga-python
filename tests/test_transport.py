"""Tests for the 5 auth transports, header handling, and response parsing."""

from __future__ import annotations

import base64

import httpx
import pytest

from tamga.errors import NotFoundError
from tamga.transport import (
    BasicAuth,
    BearerAuth,
    LicenseAuth,
    QueryParamAuth,
    apply_auth,
    parse_response,
    sanitize_tamga_version,
)


def test_bearer_auth_sets_authorization_header() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, BearerAuth(token="tok-abc123"))
    assert headers["Authorization"] == "Bearer tok-abc123"
    assert params == {}


def test_license_auth_sets_authorization_header() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, LicenseAuth(key="lic-xyz789"))
    assert headers["Authorization"] == "License lic-xyz789"


def test_query_param_auth_sets_param_not_header() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, QueryParamAuth(value="tok-abc123"))
    assert "Authorization" not in headers
    assert params == {"token": "tok-abc123"}


def test_query_param_auth_custom_param_name() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, QueryParamAuth(value="tok-abc123", param_name="auth"))
    assert params == {"auth": "tok-abc123"}


def test_basic_auth_email_password_sub_form() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, BasicAuth(email="user@example.com", password="hunter2"))
    expected = base64.b64encode(b"user@example.com:hunter2").decode("ascii")
    assert headers["Authorization"] == f"Basic {expected}"


def test_basic_auth_token_sub_form_uses_empty_password() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, BasicAuth(token="tok-abc123"))
    expected = base64.b64encode(b"tok-abc123:").decode("ascii")
    assert headers["Authorization"] == f"Basic {expected}"


def test_basic_auth_license_key_sub_form_prefixes_license_literal() -> None:
    headers: dict[str, str] = {}
    params: dict[str, str] = {}
    apply_auth(headers, params, BasicAuth(license_key="lic-xyz789"))
    expected = base64.b64encode(b"license:lic-xyz789").decode("ascii")
    assert headers["Authorization"] == f"Basic {expected}"


def test_sanitize_tamga_version_keeps_allowed_characters() -> None:
    assert sanitize_tamga_version("1.8") == "1.8"
    assert sanitize_tamga_version("v1.0-beta") == "v1.0-beta"


def test_sanitize_tamga_version_strips_disallowed_characters() -> None:
    assert sanitize_tamga_version("1.8; DROP TABLE") == "1.8DROPTABLE"
    assert sanitize_tamga_version("a/b c") == "abc"


def test_sanitize_tamga_version_truncates_to_32_chars() -> None:
    long_version = "a" * 50
    sanitized = sanitize_tamga_version(long_version)
    assert len(sanitized) == 32
    assert sanitized == "a" * 32


def test_sanitize_tamga_version_raises_on_empty_result() -> None:
    with pytest.raises(ValueError, match="sanitizes to an empty string"):
        sanitize_tamga_version("!!!")


def test_parse_response_unwraps_json_api_data_envelope() -> None:
    response = httpx.Response(
        200,
        json={"data": {"id": "abc", "type": "licenses", "attributes": {}}},
        headers={"Content-Type": "application/vnd.api+json"},
    )
    parsed = parse_response(response)
    assert parsed.data == {"id": "abc", "type": "licenses", "attributes": {}}


def test_parse_response_quick_validate_special_case_no_data_envelope() -> None:
    response = httpx.Response(
        200,
        json={"ts": "2024-01-01T00:00:00Z", "valid": True, "detail": "ok", "code": "VALID"},
        headers={"Content-Type": "application/json"},
    )
    parsed = parse_response(response, is_quick_validate=True)
    assert parsed.data["valid"] is True
    assert parsed.data["code"] == "VALID"


def test_parse_response_reads_known_response_headers() -> None:
    response = httpx.Response(
        200,
        json={"data": {}},
        headers={
            "Tamga-Version": "1.8",
            "Tamga-Edition": "CE",
            "Tamga-Mode": "multiplayer",
            "X-Request-Id": "req-123",
        },
    )
    parsed = parse_response(response)
    assert parsed.tamga_version == "1.8"
    assert parsed.tamga_edition == "CE"
    assert parsed.tamga_mode == "multiplayer"
    assert parsed.request_id == "req-123"


def test_parse_response_missing_headers_default_to_none() -> None:
    response = httpx.Response(200, json={"data": {}})
    parsed = parse_response(response)
    assert parsed.tamga_version is None
    assert parsed.tamga_edition is None
    assert parsed.tamga_mode is None
    assert parsed.request_id is None


def test_parse_response_raises_typed_error_on_error_status(json_api_error_body: dict) -> None:
    response = httpx.Response(404, json=json_api_error_body)
    with pytest.raises(NotFoundError) as exc_info:
        parse_response(response)
    assert exc_info.value.code == "NOT_FOUND"
    assert exc_info.value.status == 404
