"""Tests for machine management: create/delete/activate/heartbeat."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
import pytest

from tamga.client import HeartbeatScheduler, TamgaClient
from tamga.errors import (
    CoreLimitExceededError,
    FingerprintTakenError,
    MachineLimitExceededError,
    NotFoundError,
)
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


def test_machine_timestamps_are_parsed(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Every timestamp the server sends used to be dropped on the floor, which
    # left a Python caller with no way to build the liveness logic the module
    # docs describe: `heartbeat_status` alone cannot say *when* the last ping
    # was, and `memory`/`disk` are megabytes, not bytes.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(MACHINE_ID),
                    "type": "machines",
                    "attributes": {
                        "fingerprint": "fp-abc",
                        "heartbeat_status": "ALIVE",
                        "memory": 16384,
                        "disk": 512000,
                        "last_heartbeat_at": "2024-01-01T00:05:00Z",
                        "next_heartbeat_at": "2024-01-01T00:15:00Z",
                        "last_check_out_at": "2024-01-01T00:00:30Z",
                        "created": "2024-01-01T00:00:00Z",
                        "updated": "2024-01-01T00:05:00Z",
                    },
                }
            },
        )

    client = make_client(handler)
    machine = client.machines.ping_heartbeat(MACHINE_ID)

    assert machine.last_heartbeat_at == datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc)
    assert machine.next_heartbeat_at == datetime(2024, 1, 1, 0, 15, tzinfo=timezone.utc)
    assert machine.last_check_out_at == datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
    assert machine.created == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert machine.updated == datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc)
    # Megabytes on the wire — 16 GB of RAM is 16384, not 17179869184.
    assert machine.memory == 16384


def test_machine_timestamps_default_to_none_when_absent(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data("ALIVE")}))
    machine = client.machines.ping_heartbeat(MACHINE_ID)
    assert machine.last_heartbeat_at is None
    assert machine.created is None


def test_create_machine_over_limit_raises_the_typed_limit_error(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Creation is not limit-free: the server checks the policy's machine limit
    # before inserting the row. `status` is the string "422" on the wire.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "422",
                        "code": "MACHINE_LIMIT_EXCEEDED",
                        "title": "Unprocessable Entity",
                        "detail": "machine limit exceeded for this license",
                        "source": {"pointer": "/data/relationships/license"},
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(MachineLimitExceededError) as excinfo:
        client.machines.create(LICENSE_ID, "fp-abc")

    assert excinfo.value.status == 422
    assert excinfo.value.code == "MACHINE_LIMIT_EXCEEDED"
    assert excinfo.value.pointer == "/data/relationships/license"


def test_activate_machine_create_time_422_does_not_delete(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Under a strict overage strategy the limit stops the create itself, so no
    # row exists. Issuing the rollback DELETE anyway would target a machine id
    # this client never received.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST" and request.url.path == f"{ACCOUNT_PATH}/machines":
            return httpx.Response(
                422,
                json={
                    "errors": [
                        {
                            "id": "e1",
                            "status": "422",
                            "code": "CORE_LIMIT_EXCEEDED",
                            "title": "Unprocessable Entity",
                            "detail": "core limit exceeded",
                        }
                    ]
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)
    with pytest.raises(ValueError, match="TOO_MANY_CORES") as excinfo:
        client.machines.activate_machine(LICENSE_ID, "fp-abc", cores=64)

    # The create-time code is normalized to its ValidationCode equivalent, and
    # the original typed error stays attached as the cause.
    assert "CORE_LIMIT_EXCEEDED" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, CoreLimitExceededError)
    assert calls == [f"POST {ACCOUNT_PATH}/machines"]
    assert not any(c.startswith("DELETE") for c in calls), "nothing was created to roll back"


def test_activate_machine_under_overage_still_rolls_back_at_validate(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # The create-time limit check runs through the policy's overage strategy,
    # so under ALLOW_ACCESS / ALLOW_1_25X_OVERAGE the create succeeds and the
    # limit only shows up in the validate response. The row exists here, so the
    # rollback DELETE must still run.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST" and request.url.path == f"{ACCOUNT_PATH}/machines":
            return httpx.Response(201, json={"data": _machine_data()})
        if "actions/validate" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": {"id": str(LICENSE_ID), "type": "licenses", "attributes": {}},
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
    with pytest.raises(ValueError, match="rolled back"):
        client.machines.activate_machine(LICENSE_ID, "fp-abc")

    assert calls[0] == f"POST {ACCOUNT_PATH}/machines"
    assert calls[-1] == f"DELETE {ACCOUNT_PATH}/machines/{MACHINE_ID}"


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


def test_heartbeat_scheduler_keeps_pinging_after_a_dead_observation(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A defensive test, deliberately mocking a response the real server cannot
    # send. A ping writes `last_heartbeat_at = NOW()` and derives the status
    # from that same timestamp, so it always answers ALIVE or RESURRECTED —
    # DEAD is only reachable from a machine read this SDK does not expose. The
    # loop used to `break` on DEAD anyway: unreachable in practice, and
    # permanent if it ever fired, since nothing restarted it. So the rule under
    # test is the general one — no status ends the loop — and feeding it the
    # one status that used to be fatal is the sharpest way to hold that.
    ping_count = {"n": 0}
    scheduler_box: dict[str, HeartbeatScheduler] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        ping_count["n"] += 1
        if ping_count["n"] >= 3:
            scheduler_box["scheduler"].stop()
        # Every ping reports DEAD; the loop must not read the status at all.
        return httpx.Response(200, json={"data": _machine_data("DEAD")})

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(seconds=0)
    )
    scheduler_box["scheduler"] = scheduler
    monkeypatch.setattr("tamga.client.time.sleep", lambda _seconds: None)
    scheduler.run_forever()

    assert ping_count["n"] == 3, "no heartbeat status may end the loop"


def test_heartbeat_scheduler_surfaces_a_404_from_the_ping(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A 404 on the ping is the *only* signal that the machine row is really
    # gone, and it is what a caller keys re-activation off. It must reach them.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "404",
                        "code": "NOT_FOUND",
                        "title": "Not Found",
                        "detail": "machine not found",
                    }
                ]
            },
        )

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(seconds=0)
    )
    monkeypatch.setattr("tamga.client.time.sleep", lambda _seconds: None)
    with pytest.raises(NotFoundError):
        scheduler.run_forever()
