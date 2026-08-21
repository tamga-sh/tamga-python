"""Tests for process creation and heartbeat pinging."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
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


def test_create_process_sends_a_flat_body_with_a_string_pid(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The handler takes `CreateProcessBody { machine_id, pid, metadata }`.

    Asserted as whole-body equality rather than field-by-field lookups. The
    previous version read `body["data"]["attributes"]["pid"]`, which passed
    against an enveloped body the server rejects with 422 — the test pinned the
    bug instead of catching it. An exact match cannot do that.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/processes"
        body = json.loads(request.content)
        assert body == {"machine_id": str(MACHINE_ID), "pid": "12345"}
        # The pid stays a string on the wire, at the top level.
        assert isinstance(body["pid"], str)
        return httpx.Response(201, json={"data": _process_data()})

    client = make_client(handler)
    process = client.processes.create(MACHINE_ID, "12345")
    assert process.pid == "12345"
    assert isinstance(process.pid, str)


def test_create_process_never_nests_fields_under_a_data_key(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """`machine_id` and `pid` have no serde default, so an envelope 422s."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert "data" not in body, "re-enveloped: every create would 422"
        assert "attributes" not in body
        return httpx.Response(201, json={"data": _process_data()})

    client = make_client(handler)
    client.processes.create(MACHINE_ID, "12345")


def test_create_process_forwards_metadata_at_the_top_level(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content) == {
            "machine_id": str(MACHINE_ID),
            "pid": "12345",
            "metadata": {"role": "worker"},
        }
        return httpx.Response(201, json={"data": _process_data()})

    client = make_client(handler)
    client.processes.create(MACHINE_ID, "12345", metadata={"role": "worker"})


def test_create_process_response_is_still_enveloped(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Flat request, enveloped response. Matching the two directions up breaks one."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert "data" not in json.loads(request.content)
        return httpx.Response(201, json={"data": _process_data()})

    client = make_client(handler)
    process = client.processes.create(MACHINE_ID, "12345")
    # Parsed out of `data`: a flat decode would leave these empty/zeroed.
    assert process.id == PROCESS_ID
    assert process.pid == "12345"
    assert process.machine_id == MACHINE_ID


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


def test_process_timestamps_are_parsed(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # `last_heartbeat_at` is NOT NULL server-side (a process is ALIVE from
    # creation) and was dropped entirely by the parser.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(PROCESS_ID),
                    "type": "processes",
                    "attributes": {
                        "pid": "12345",
                        "machine_id": str(MACHINE_ID),
                        "last_heartbeat_at": "2024-01-01T00:00:10Z",
                        "created": "2024-01-01T00:00:00Z",
                        "updated": "2024-01-01T00:00:10Z",
                    },
                }
            },
        )

    client = make_client(handler)
    process = client.processes.ping(PROCESS_ID)

    assert process.last_heartbeat_at == datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
    assert process.created == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert process.updated == datetime(2024, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
