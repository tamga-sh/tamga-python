"""One table pinning the request-body shape of every endpoint that sends one.

Whether a request is a JSON:API envelope or a flat object is a **per-endpoint**
fact on this server, not a protocol-wide rule. `POST /machines` and
`PATCH /machines/{id}` deserialize into structs with a `data` member;
`POST /components` and `POST /processes` deserialize into plain structs whose
fields sit at the top level. Responses are enveloped throughout, in every case.

This file exists because the fact is exactly the kind that gets inverted
wholesale. tamga-python sent the envelope to both flat endpoints — failing
deserialization on their required fields, so every component and process create
returned 422 — and the per-endpoint tests asserted
`body["data"]["attributes"][...]`, which pinned the broken shape rather than
catching it. tamga-dotnet had the mirror image on the response axis for the same
two endpoints, hidden the same way.

Asserting both shapes side by side is what makes "normalize them to match" fail
loudly instead of looking like a tidy-up.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import UUID

import httpx

from tamga.client import TamgaClient

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000050")
MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")

Client = Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient]


def _capture(make_client: Client, resource_type: str) -> tuple[dict, Callable[[], dict]]:
    """Return a handler that records the request body and answers plausibly."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(
            201,
            json={
                "data": {
                    "id": "018f2f3a-0000-7000-8000-0000000000ff",
                    "type": resource_type,
                    "attributes": {
                        "fingerprint": "fp",
                        "name": "n",
                        "pid": "1",
                        "machine_id": str(MACHINE_ID),
                    },
                }
            },
        )

    return captured, handler  # type: ignore[return-value]


def test_machine_create_is_enveloped(make_client: Client) -> None:
    captured, handler = _capture(make_client, "machines")
    make_client(handler).machines.create(LICENSE_ID, "fp")

    assert set(captured) == {"data"}
    assert captured["data"]["type"] == "machines"
    assert captured["data"]["attributes"]["fingerprint"] == "fp"
    assert captured["data"]["relationships"]["license"]["data"]["id"] == str(LICENSE_ID)


def test_machine_update_is_enveloped(make_client: Client) -> None:
    captured, handler = _capture(make_client, "machines")
    make_client(handler).machines.update(MACHINE_ID, name="box")

    assert set(captured) == {"data"}
    assert captured["data"]["type"] == "machines"
    assert captured["data"]["attributes"] == {"name": "box"}


def test_component_create_is_flat(make_client: Client) -> None:
    captured, handler = _capture(make_client, "components")
    make_client(handler).components.create(MACHINE_ID, "fp", "CPU")

    # Exactly the server struct's fields, at the top level.
    assert set(captured) == {"machine_id", "fingerprint", "name"}
    assert "data" not in captured


def test_process_create_is_flat(make_client: Client) -> None:
    captured, handler = _capture(make_client, "processes")
    make_client(handler).processes.create(MACHINE_ID, "1")

    assert set(captured) == {"machine_id", "pid"}
    assert "data" not in captured


def test_the_two_shapes_are_genuinely_different(make_client: Client) -> None:
    """The contrast itself, in one assertion, so neither side can drift to the other."""
    machine, machine_handler = _capture(make_client, "machines")
    make_client(machine_handler).machines.create(LICENSE_ID, "fp")

    component, component_handler = _capture(make_client, "components")
    make_client(component_handler).components.create(MACHINE_ID, "fp", "CPU")

    process, process_handler = _capture(make_client, "processes")
    make_client(process_handler).processes.create(MACHINE_ID, "1")

    assert "data" in machine, "POST /machines takes an envelope"
    assert "data" not in component, "POST /components takes a flat body"
    assert "data" not in process, "POST /processes takes a flat body"
