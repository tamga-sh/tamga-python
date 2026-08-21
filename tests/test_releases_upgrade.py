"""Tests for the auto-update check.

The endpoint answers `204 No Content` for two different situations on purpose,
and the SDK must not collapse them into "you are up to date".
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

import httpx
import pytest

from tamga.client import TamgaClient
from tamga.errors import ForbiddenError, NotFoundError, UnauthorizedError

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

PRODUCT_ID = UUID("018f2f3a-0000-7000-8000-000000000070")
RELEASE_ID = UUID("018f2f3a-0000-7000-8000-000000000090")

#: A real upgrade-check response body, keyed exactly as the server emits it.
#:
#: The keys were derived mechanically from `ReleaseAttributes` in the server's
#: own serializer, **not** transcribed from this SDK's `ReleaseResource`. That
#: distinction is the whole point: the previous inline fixture spelled the
#: owning product `product_id` because that is what the dataclass field is
#: called, so it agreed with the parser and disagreed with the server. The test
#: passed and `check_for_upgrade` raised `KeyError` against every real response.
#: See the file's own `_provenance` block.
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "releases" / "upgrade_response.json"
_FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _release_data(**extra: object) -> dict:
    """The server-shaped `data` object, optionally overridden per test."""
    data = json.loads(json.dumps(_FIXTURE["data"]))
    data["attributes"].update(extra)
    return data


def _check(client: TamgaClient) -> object:
    return client.releases.check_for_upgrade(
        product_id=PRODUCT_ID, platform="darwin-arm64", filetype="dmg", version="1.3.0"
    )


def test_release_attributes_are_camel_cased_on_the_wire(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """`releases` is one of the few resources the server serializes camelCase.

    The owning product arrives as `productId`. Reading `product_id` — the
    spelling every *other* resource this SDK parses uses — raises `KeyError`
    against a real response, which is what this SDK did until now.
    """
    attributes = _FIXTURE["data"]["attributes"]
    assert "productId" in attributes
    assert "product_id" not in attributes

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": _FIXTURE["data"]})

    client = make_client(handler)
    release = _check(client)
    assert release is not None
    assert release.product_id == PRODUCT_ID


def test_created_and_updated_are_not_camel_cased(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The exception inside the exception, pinned so it cannot be "fixed".

    The struct fields are `created_at`/`updated_at`, so `rename_all =
    "camelCase"` would make them `createdAt`/`updatedAt` — but each carries an
    explicit `#[serde(rename)]`, and an explicit rename wins. Camel-casing these
    two while fixing `productId` would break two fields that are already right.
    """
    attributes = _FIXTURE["data"]["attributes"]
    assert "created" in attributes and "updated" in attributes
    assert "createdAt" not in attributes and "updatedAt" not in attributes

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": _FIXTURE["data"]})

    client = make_client(handler)
    release = _check(client)
    assert release is not None
    assert release.created is not None
    assert release.updated is not None
    assert release.created.year == 2026


def test_camel_cased_timestamps_are_ignored_rather_than_guessed(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A body carrying `createdAt`/`updatedAt` is not the server's shape.

    If the parser ever started reading those, this would silently start passing
    and the real `created`/`updated` would be dropped. Asserting `None` keeps
    the two spellings distinguishable.
    """
    attributes = dict(_FIXTURE["data"]["attributes"])
    attributes.pop("created")
    attributes.pop("updated")
    attributes["createdAt"] = "2026-01-02T03:04:05Z"
    attributes["updatedAt"] = "2026-01-02T03:04:05Z"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {**_FIXTURE["data"], "attributes": attributes}})

    client = make_client(handler)
    release = _check(client)
    assert release is not None
    assert release.created is None
    assert release.updated is None


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
