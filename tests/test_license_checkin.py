"""Tests for license check-in (plan Section D)."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import httpx
import pytest

from tamga.client import TamgaClient
from tamga.errors import CheckInNotRequiredError

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000020")


def test_check_in_success_bumps_and_returns_license_resource(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/actions/check-in"
        assert request.content == b"" or request.content is None
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(LICENSE_ID),
                    "type": "licenses",
                    "attributes": {"last_check_in_at": "2024-01-01T00:00:00Z"},
                }
            },
            headers={"Content-Type": "application/vnd.api+json"},
        )

    client = make_client(handler)
    license_resource = client.licenses.check_in(LICENSE_ID)
    assert license_resource.id == LICENSE_ID
    assert license_resource.attributes["last_check_in_at"] == "2024-01-01T00:00:00Z"


def test_check_in_not_required_raises_typed_error(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "errors": [
                    {
                        "id": "err-1",
                        "status": "422",
                        "code": "CHECK_IN_NOT_REQUIRED",
                        "title": "Unprocessable Entity",
                        "detail": "this license's policy does not require check-in",
                        "source": None,
                    }
                ]
            },
            headers={"Content-Type": "application/vnd.api+json"},
        )

    client = make_client(handler)
    with pytest.raises(CheckInNotRequiredError) as exc_info:
        client.licenses.check_in(LICENSE_ID)
    assert exc_info.value.code == "CHECK_IN_NOT_REQUIRED"
    assert exc_info.value.status == 422
