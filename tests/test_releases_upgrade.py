"""Tests for the auto-update check.

The endpoint answers `204 No Content` for two different situations on purpose,
and the SDK must not collapse them into "you are up to date".
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import httpx
import pytest

from tamga.client import TamgaClient
from tamga.errors import ForbiddenError, NotFoundError, UnauthorizedError

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

PRODUCT_ID = UUID("018f2f3a-0000-7000-8000-000000000070")
RELEASE_ID = UUID("018f2f3a-0000-7000-8000-000000000090")


def _release_data(**extra: object) -> dict:
    attributes: dict = {
        "product_id": str(PRODUCT_ID),
        "name": "1.4.0",
        "version": "1.4.0",
        "channel": "stable",
        "status": "PUBLISHED",
        "metadata": {"notes": "faster"},
        "created": "2026-01-02T03:04:05Z",
        "updated": "2026-01-02T03:04:05Z",
    }
    attributes.update(extra)
    return {"id": str(RELEASE_ID), "type": "releases", "attributes": attributes}


def _check(client: TamgaClient) -> object:
    return client.releases.check_for_upgrade(
        product_id=PRODUCT_ID, platform="darwin-arm64", filetype="dmg", version="1.3.0"
    )


def test_upgrade_check_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"{ACCOUNT_PATH}/releases/actions/upgrade"
        assert request.url.params["product"] == str(PRODUCT_ID)
        assert request.url.params["platform"] == "darwin-arm64"
        # The server spells this `filetype`, one word.
        assert request.url.params["filetype"] == "dmg"
        assert request.url.params["version"] == "1.3.0"
        assert "channel" not in request.url.params
        assert "constraint" not in request.url.params
        return httpx.Response(200, json={"data": _release_data()})

    client = make_client(handler)
    release = _check(client)
    assert release is not None
    assert release.id == RELEASE_ID
    assert release.product_id == PRODUCT_ID
    assert release.version == "1.4.0"
    assert release.channel == "stable"
    assert release.tag is None
    assert release.metadata == {"notes": "faster"}
    assert release.created is not None


def test_upgrade_check_forwards_the_optional_narrowing_params(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["channel"] == "beta"
        assert request.url.params["constraint"] == "1.x"
        return httpx.Response(200, json={"data": _release_data(tag="rc1")})

    client = make_client(handler)
    release = client.releases.check_for_upgrade(
        product_id=PRODUCT_ID,
        platform="linux-x86_64",
        filetype="tar.gz",
        version="1.3.0",
        channel="beta",
        constraint="1.x",
    )
    assert release is not None
    assert release.tag == "rc1"


def test_204_means_no_update_is_available_to_you_not_that_you_are_current(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Both the already-current case and the not-entitled case return this."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204)

    client = make_client(handler)
    assert _check(client) is None


def test_a_suspended_license_is_a_403_not_an_ambiguous_204(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"errors": [{"code": "FORBIDDEN", "detail": "The license is suspended"}]},
        )

    client = make_client(handler)
    with pytest.raises(ForbiddenError):
        _check(client)


def test_a_licensed_product_without_a_credential_is_a_401(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"errors": [{"code": "UNAUTHORIZED", "detail": "a license is required"}]},
        )

    client = make_client(handler)
    with pytest.raises(UnauthorizedError):
        _check(client)


def test_an_unknown_product_is_a_404(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": [{"code": "NOT_FOUND", "detail": "no product"}]})

    client = make_client(handler)
    with pytest.raises(NotFoundError):
        _check(client)
