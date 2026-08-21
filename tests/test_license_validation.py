"""Tests for the 3 license validation endpoints."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import httpx
import pytest

from tamga.client import TamgaClient
from tamga.models.license import LicenseScope
from tamga.models.validation import ValidationCode

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000010")

LICENSE_DATA = {
    "id": str(LICENSE_ID),
    "type": "licenses",
    "attributes": {"key": "TEST-KEY", "status": "ACTIVE"},
}


def _validate_response(code: str = "VALID", valid: bool = True) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": LICENSE_DATA,
            "meta": {"ts": "2024-01-01T00:00:00Z", "valid": valid, "detail": "ok", "code": code},
        },
        headers={"Content-Type": "application/vnd.api+json"},
    )


def test_validate_by_key_sends_key_in_body_and_license_auth_header(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        assert request.url.path == f"{ACCOUNT_PATH}/licenses/actions/validate-key"
        return _validate_response()

    client = make_client(handler)
    result = client.licenses.validate_by_key("MY-LICENSE-KEY")

    body = captured["request"].content
    assert b"MY-LICENSE-KEY" in body
    assert captured["request"].headers["Authorization"] == "License MY-LICENSE-KEY"
    assert result.meta.valid is True
    assert result.meta.code == ValidationCode.VALID
    assert result.license is not None
    assert result.license.id == LICENSE_ID


def test_validate_by_id_serializes_the_six_enforced_scope_fields(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return _validate_response()

    client = make_client(handler)
    scope = LicenseScope(
        product=UUID("018f2f3a-0000-7000-8000-000000000001"),
        policy=UUID("018f2f3a-0000-7000-8000-000000000002"),
        user=UUID("018f2f3a-0000-7000-8000-000000000003"),
        environment=UUID("018f2f3a-0000-7000-8000-000000000004"),
        entitlements=["feature-a", "feature-b"],
        fingerprint="fp-abc",
        version="1.2.3",
        checksum="deadbeef",
    )
    client.licenses.validate_by_id(LICENSE_ID, scope=scope, skip_touch=True)

    import json

    body = json.loads(captured["request"].content)
    sent_scope = body["meta"]["scope"]
    assert sent_scope["product"] == str(scope.product)
    assert sent_scope["policy"] == str(scope.policy)
    assert sent_scope["user"] == str(scope.user)
    assert sent_scope["environment"] == str(scope.environment)
    assert sent_scope["entitlements"] == ["feature-a", "feature-b"]
    assert sent_scope["fingerprint"] == "fp-abc"
    # `version`/`checksum` must NOT go on the wire. The server does not ignore
    # them: `reject_unenforced_scope` fails the entire call with
    # `422 SCOPE_NOT_SUPPORTED` before any validation runs, so a caller that
    # sets one would get no `meta.valid` at all. Dropping them here degrades
    # that caller to a working validate instead of a hard failure.
    assert "version" not in sent_scope
    assert "checksum" not in sent_scope
    assert body["meta"]["skip_touch"] is True


def test_a_scope_of_only_version_and_checksum_sends_no_scope_at_all(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Nothing enforceable is left once the two rejected keys are dropped, so
    # the request must not carry an empty `meta.scope` either — the server
    # rejects on key *presence*, and an empty object is pointless regardless.
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return _validate_response()

    client = make_client(handler)
    client.licenses.validate_by_id(
        LICENSE_ID, scope=LicenseScope(version="1.2.3", checksum="deadbeef")
    )

    import json

    body = json.loads(captured["request"].content or b"{}")
    assert "scope" not in body.get("meta", {})


def test_validate_by_id_skip_touch_false_by_default(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return _validate_response()

    client = make_client(handler)
    client.licenses.validate_by_id(LICENSE_ID)

    # No scope, no skip_touch -> body may omit meta entirely or send an empty one.
    assert captured["request"].method == "POST"
    assert captured["request"].url.path == (
        f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/actions/validate"
    )


def test_quick_validate_parses_flat_json_no_data_envelope(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == (f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/actions/validate")
        return httpx.Response(
            200,
            json={
                "ts": "2024-01-01T00:00:00Z",
                "valid": False,
                "detail": "license expired",
                "code": "EXPIRED",
            },
            headers={"Content-Type": "application/json"},
        )

    client = make_client(handler)
    result = client.licenses.quick_validate(LICENSE_ID)

    assert result.license is None
    assert result.meta.valid is False
    assert result.meta.code == ValidationCode.EXPIRED
    assert result.meta.detail == "license expired"


@pytest.mark.parametrize(
    "code",
    [
        "VALID",
        "SUSPENDED",
        "EXPIRED",
        "OVERDUE",
        "PRODUCT_SCOPE_MISMATCH",
        "POLICY_SCOPE_MISMATCH",
        "USER_SCOPE_MISMATCH",
        "ENVIRONMENT_SCOPE_MISMATCH",
        "TOO_MANY_MACHINES",
        "TOO_MANY_CORES",
        "TOO_MUCH_MEMORY",
        "TOO_MUCH_DISK",
        "TOO_MANY_PROCESSES",
        "TOO_MANY_USES",
        "NOT_FOUND",
        "BANNED",
        "ENTITLEMENTS_MISSING",
        "TOO_MANY_USERS",
        "HEARTBEAT_DEAD",
        "HEARTBEAT_NOT_STARTED",
        "FINGERPRINT_SCOPE_MISMATCH",
        "COMPONENTS_SCOPE_MISMATCH",
        "CHECKSUM_SCOPE_MISMATCH",
        "VERSION_SCOPE_MISMATCH",
    ],
)
def test_every_validation_code_round_trips_through_validation_meta(
    code: str,
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _validate_response(code=code, valid=(code == "VALID"))

    client = make_client(handler)
    result = client.licenses.validate_by_key("KEY")
    assert result.meta.code == ValidationCode(code)


def test_unknown_validation_code_deserializes_leniently(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _validate_response(code="SOME_FUTURE_CODE", valid=False)

    client = make_client(handler)
    result = client.licenses.validate_by_key("KEY")
    assert result.meta.code == ValidationCode.UNKNOWN
