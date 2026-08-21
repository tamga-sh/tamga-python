"""Tests for `GET /v1/health` — the one route outside the account prefix."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from tamga.client import TamgaClient, TamgaConfig
from tamga.errors import TamgaError
from tamga.transport import LicenseAuth, build_root_url

HEALTH_BODY = {"status": "ok", "version": "0.9.3", "uptime_secs": 4321}


def test_health_is_requested_outside_the_account_prefix(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/health"
        assert "/accounts/" not in str(request.url)
        assert request.url.host == "api.tamga.sh"
        return httpx.Response(200, json=HEALTH_BODY)

    client = make_client(handler)
    health = client.health()
    assert health.status == "ok"
    assert health.version == "0.9.3"
    assert health.uptime_seconds == 4321


def test_health_decodes_a_flat_body_not_a_json_api_envelope(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The handler returns a bare object; routing it through the envelope parser would
    silently hand back the whole body as `data`."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = httpx.Response(200, json=HEALTH_BODY).json()
        assert "data" not in body
        return httpx.Response(200, json=body)

    client = make_client(handler)
    assert client.health().uptime_seconds == 4321


def test_health_still_sends_the_configured_credential(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(200, json=HEALTH_BODY)

    config = TamgaConfig(
        account_id="018f2f3a-0000-7000-8000-000000000001",
        host="api.tamga.sh",
        default_auth=LicenseAuth(key="KEY-123"),
    )
    client = TamgaClient(config, transport=httpx.MockTransport(handler))
    client.health()
    assert captured["authorization"] == "License KEY-123"
    assert captured["tamga-version"] == "1"


def test_health_surfaces_a_non_2xx_as_a_typed_error(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="<html>upstream down</html>")

    client = make_client(handler)
    with pytest.raises(TamgaError) as excinfo:
        client.health()
    # A non-JSON:API body must not crash the parser.
    assert excinfo.value.code == "UNKNOWN"
    assert excinfo.value.status == 503


def test_health_missing_fields_do_not_raise(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    client = make_client(handler)
    health = client.health()
    assert health.status == ""
    assert health.uptime_seconds == 0


def test_build_root_url_keeps_an_explicit_http_scheme() -> None:
    assert build_root_url("http://localhost:8080") == "http://localhost:8080"
    assert build_root_url("api.tamga.sh") == "https://api.tamga.sh"
    assert build_root_url("https://api.tamga.sh/") == "https://api.tamga.sh"
    assert build_root_url("  api.tamga.sh  ") == "https://api.tamga.sh"


def test_health_on_a_plain_http_host_stays_on_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://localhost:8080/v1/health"
        return httpx.Response(200, json=HEALTH_BODY)

    config = TamgaConfig(
        account_id="018f2f3a-0000-7000-8000-000000000001", host="http://localhost:8080"
    )
    client = TamgaClient(config, transport=httpx.MockTransport(handler))
    assert client.health().status == "ok"
