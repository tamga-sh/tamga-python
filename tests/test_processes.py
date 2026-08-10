"""Tests for process creation and heartbeat pinging (plan Section I)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import httpx
import pytest

from tamga.client import ProcessHeartbeatScheduler, TamgaClient
from tamga.errors import PidTakenError

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000070")
PROCESS_ID = UUID("018f2f3a-0000-7000-8000-000000000071")


def _process_data() -> dict:
    return {
        "id": str(PROCESS_ID),
        "type": "processes",
        "attributes": {"pid": "12345", "machine_id": str(MACHINE_ID)},
    }


def test_create_process_with_string_pid(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/processes"
        body = json.loads(request.content)
        assert body["data"]["attributes"]["pid"] == "12345"
        assert isinstance(body["data"]["attributes"]["pid"], str)
        return httpx.Response(201, json={"data": _process_data()})

    client = make_client(handler)
    process = client.processes.create(MACHINE_ID, "12345")
    assert process.pid == "12345"
    assert isinstance(process.pid, str)


def test_create_process_rejects_non_string_pid(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda r: httpx.Response(201, json={"data": _process_data()}))
    with pytest.raises(TypeError, match="pid must be a str"):
        client.processes.create(MACHINE_ID, 12345)  # type: ignore[arg-type]


def test_create_process_duplicate_pid_conflict(
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
                        "code": "PID_TAKEN",
                        "title": "Conflict",
                        "detail": "duplicate pid",
                        "source": None,
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(PidTakenError):
        client.processes.create(MACHINE_ID, "12345")


def test_ping_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/processes/{PROCESS_ID}/actions/ping"
        return httpx.Response(200, json={"data": _process_data()})

    client = make_client(handler)
    process = client.processes.ping(PROCESS_ID)
    assert process.id == PROCESS_ID


def test_process_heartbeat_scheduler_default_interval_is_10_seconds(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda r: httpx.Response(200, json={"data": _process_data()}))
    scheduler = ProcessHeartbeatScheduler(processes=client.processes, process_id=PROCESS_ID)
    assert scheduler.interval == timedelta(seconds=10)


def test_process_heartbeat_scheduler_stops_when_signalled(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ping_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        ping_count["n"] += 1
        return httpx.Response(200, json={"data": _process_data()})

    client = make_client(handler)
    scheduler = ProcessHeartbeatScheduler(
        processes=client.processes, process_id=PROCESS_ID, interval=timedelta(seconds=0)
    )

    def fake_sleep(_seconds: float) -> None:
        if ping_count["n"] >= 3:
            scheduler.stop()

    monkeypatch.setattr("tamga.client.time.sleep", fake_sleep)
    scheduler.run_forever()
    assert ping_count["n"] == 3
