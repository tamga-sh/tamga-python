"""Tests for machine management: create/delete/activate/heartbeat (plan Section G)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import httpx
import pytest

from tamga.client import HeartbeatScheduler, TamgaClient
from tamga.errors import FingerprintTakenError
from tamga.models.machine import HeartbeatStatus

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000050")
MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")


def _machine_data(heartbeat_status: str = "NOT_STARTED") -> dict:
    return {
        "id": str(MACHINE_ID),
        "type": "machines",
        "attributes": {"fingerprint": "fp-abc", "heartbeat_status": heartbeat_status},
    }


def test_create_machine_happy_path(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/machines"
        body = json.loads(request.content)
        assert body["data"]["attributes"]["fingerprint"] == "fp-abc"
        assert body["data"]["relationships"]["license"]["data"]["id"] == str(LICENSE_ID)
        return httpx.Response(201, json={"data": _machine_data()})

    client = make_client(handler)
    machine = client.machines.create(LICENSE_ID, "fp-abc")
    assert machine.id == MACHINE_ID
    assert machine.fingerprint == "fp-abc"
    assert machine.heartbeat_status == HeartbeatStatus.NOT_STARTED


def test_create_machine_duplicate_fingerprint_raises_typed_error(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "409",
                        "code": "FINGERPRINT_TAKEN",
                        "title": "Conflict",
                        "detail": "fingerprint already exists",
                        "source": None,
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(FingerprintTakenError):
        client.machines.create(LICENSE_ID, "fp-abc")


def test_activate_machine_rollback_on_too_many_machines(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == f"{ACCOUNT_PATH}/machines" and request.method == "POST":
            return httpx.Response(201, json={"data": _machine_data()})
        if "actions/validate" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": _machine_data(),
                    "meta": {
                        "ts": "2024-01-01T00:00:00Z",
                        "valid": False,
                        "detail": "too many machines",
                        "code": "TOO_MANY_MACHINES",
                    },
                },
            )
        if request.method == "DELETE":
            return httpx.Response(204)
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)
    with pytest.raises(ValueError, match="TOO_MANY_MACHINES"):
        client.machines.activate_machine(LICENSE_ID, "fp-abc")

    assert any(c.startswith("DELETE") for c in calls), "machine should have been rolled back"


def test_ping_heartbeat_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (f"{ACCOUNT_PATH}/machines/{MACHINE_ID}/actions/ping-heartbeat")
        return httpx.Response(200, json={"data": _machine_data("ALIVE")})

    client = make_client(handler)
    machine = client.machines.ping_heartbeat(MACHINE_ID)
    assert machine.heartbeat_status == HeartbeatStatus.ALIVE


def test_reset_heartbeat_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (f"{ACCOUNT_PATH}/machines/{MACHINE_ID}/actions/reset-heartbeat")
        return httpx.Response(200, json={"data": _machine_data("NOT_STARTED")})

    client = make_client(handler)
    machine = client.machines.reset_heartbeat(MACHINE_ID)
    assert machine.heartbeat_status == HeartbeatStatus.NOT_STARTED


def test_heartbeat_scheduler_default_interval_is_200_seconds(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data()}))
    scheduler = HeartbeatScheduler(machines=client.machines, machine_id=MACHINE_ID)
    assert scheduler.interval == timedelta(seconds=200)


def test_heartbeat_scheduler_stops_on_dead_status(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ping_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        ping_count["n"] += 1
        return httpx.Response(200, json={"data": _machine_data("DEAD")})

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(seconds=0)
    )
    monkeypatch.setattr("tamga.client.time.sleep", lambda _seconds: None)
    scheduler.run_forever()
    # Loop must stop after the first DEAD response rather than pinging forever.
    assert ping_count["n"] == 1
