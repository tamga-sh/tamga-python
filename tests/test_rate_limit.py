"""The server rate-limits; the SDK has to cope.

Credential-accepting endpoints run on a tight per-IP budget (5 requests/second
by default), and the calls a licensing client makes on a timer — validate,
heartbeat ping, check-in — are exactly the ones inside it. Without backoff, a
retry loop turns one throttled request into a sustained burst that keeps the
bucket empty, and the client never recovers on its own.
"""

from __future__ import annotations

import json
from uuid import UUID

import httpx
import pytest

from tamga.client import (
    TamgaClient,
    TamgaConfig,
    _is_retryable,
    _retry_delay,
)
from tamga.errors import RateLimitedError
from tamga.transport import LicenseAuth

ACCOUNT = "acc-123"
MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")


def _rate_limited_body() -> bytes:
    return json.dumps(
        {
            "errors": [
                {
                    "id": "e1",
                    "status": "429",
                    "code": "TOO_MANY_REQUESTS",
                    "title": "Too Many Requests",
                    "detail": "rate limit exceeded",
                }
            ]
        }
    ).encode("utf-8")


def _validation_body() -> bytes:
    return json.dumps(
        {
            "data": {
                "id": "018f2f3a-0000-7000-8000-000000000030",
                "type": "licenses",
                "attributes": {"key": "K", "status": "ACTIVE"},
            },
            "meta": {
                "ts": "2026-01-01T00:00:00Z",
                "valid": True,
                "detail": "is valid",
                "code": "VALID",
            },
        }
    ).encode("utf-8")


def _client(handler, *, max_retries: int = 3) -> TamgaClient:
    config = TamgaConfig(
        account_id=ACCOUNT,
        host="api.example.test",
        default_auth=LicenseAuth("lic-abc"),
        max_retries=max_retries,
    )
    return TamgaClient(config, transport=httpx.MockTransport(handler))


def test_a_throttled_validation_retries_and_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, content=_rate_limited_body(), headers={"Retry-After": "0"})
        return httpx.Response(200, content=_validation_body())

    result = _client(handler).licenses.validate_by_key("K")

    assert result.meta.valid is True
    assert calls["n"] == 2, "the SDK must have retried exactly once"


def test_a_persistently_throttled_call_surfaces_retry_after() -> None:
    # Once the budget is spent the caller must be told why and for how long.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=_rate_limited_body(), headers={"Retry-After": "42"})

    with pytest.raises(RateLimitedError) as excinfo:
        _client(handler, max_retries=0).licenses.validate_by_key("K")

    assert excinfo.value.retry_after == 42


def test_retries_can_be_turned_off() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, content=_rate_limited_body())

    with pytest.raises(RateLimitedError):
        _client(handler, max_retries=0).licenses.validate_by_key("K")

    assert calls["n"] == 1


def test_a_create_is_never_auto_retried() -> None:
    # Repeating a create is not safe: the first attempt may well have succeeded
    # server-side, and a second activation burns a second seat.
    assert _is_retryable("POST", "/v1/accounts/acc/machines") is False
    assert _is_retryable("POST", "/v1/accounts/acc/licenses") is False


def test_idempotent_calls_are_retryable() -> None:
    assert _is_retryable("GET", "/v1/accounts/acc/licenses") is True
    assert _is_retryable("POST", "/v1/accounts/acc/licenses/actions/validate") is True
    assert _is_retryable("POST", "/v1/accounts/acc/processes/x/actions/ping") is True


def test_the_machine_heartbeat_is_retryable() -> None:
    # `/actions/ping-heartbeat` does not end with `/actions/ping` — that suffix
    # only matches the *process* ping route — so the machine heartbeat was
    # excluded from backoff. It is the one call a machine makes on a timer, and
    # the limiter buckets per route pattern with every caller sharing a bucket,
    # so a throttled heartbeat was dropped silently and the machine drifted
    # toward being culled. Both heartbeat writes are bare idempotent UPDATEs.
    assert _is_retryable("POST", "/v1/accounts/acc/machines/m-1/actions/ping-heartbeat") is True
    assert _is_retryable("POST", "/v1/accounts/acc/machines/m-1/actions/reset-heartbeat") is True


def test_a_throttled_heartbeat_is_actually_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, content=_rate_limited_body(), headers={"Retry-After": "0"})
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(MACHINE_ID),
                    "type": "machines",
                    "attributes": {"fingerprint": "fp", "heartbeat_status": "ALIVE"},
                }
            },
        )

    machine = _client(handler).machines.ping_heartbeat(MACHINE_ID)

    assert machine.heartbeat_status.value == "ALIVE"
    assert calls["n"] == 2, "the throttled heartbeat must have been retried"


def test_an_absurd_retry_after_is_capped() -> None:
    # A misconfigured — or hostile — proxy must not be able to park the caller
    # for a day on a single header.
    assert _retry_delay(0, 5) == 5
    assert _retry_delay(0, 86_400) <= 60


def test_backoff_grows_when_the_server_says_nothing() -> None:
    # Guessing the same short delay every time is just the original burst again.
    assert _retry_delay(2, None) > _retry_delay(0, None)
