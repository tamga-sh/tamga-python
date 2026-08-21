"""``GET /signing-keys`` — the account's published key set, and what it parses into.

The wire shape is pinned by ``tests/fixtures/signing_keys/list_response.json``, whose keys
were derived from the server's ``SigningKeyResource``/``SigningKeyAttributes`` structs
rather than from this SDK's field names. That distinction has already cost this repo once:
the release resource's ``productId`` was read as ``product_id`` and every real response
raised ``KeyError``, because the fixture proving it was written from the dataclass.
"""

from __future__ import annotations

import base64
import datetime
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from tamga.checkout.key_set import SigningKeySet
from tamga.checkout.license_file import ALG_PLAIN, PEM_FOOTER, PEM_HEADER, LicenseFile
from tamga.client import TamgaClient
from tamga.crypto.ed25519 import key_id
from tamga.errors import ForbiddenError
from tamga.models.signing_key import ACTIVE_STATUS, ED25519_ALGORITHM, RETIRED_STATUS

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"
SIGNING_KEYS_PATH = f"{ACCOUNT_PATH}/signing-keys"

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "signing_keys" / "list_response.json").read_text()
)

MakeClient = Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient]


def _responder(
    body: dict[str, Any], status: int = 200
) -> Callable[[httpx.Request], httpx.Response]:
    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == SIGNING_KEYS_PATH
        return httpx.Response(status, json=body)

    return _handler


def test_list_signing_keys_parses_the_servers_own_response_shape(
    make_client: MakeClient,
) -> None:
    with make_client(_responder(FIXTURE)) as client:
        keys = client.accounts.list_signing_keys()

    assert len(keys) == 3
    expected = FIXTURE["data"]
    for key, resource in zip(keys, expected):
        attributes = resource["attributes"]
        # The resource `id` IS the kid (accounts/serializer.rs:119-123).
        assert key.kid == resource["id"]
        assert key.public_key == attributes["publicKey"]
        assert key.algorithm == ED25519_ALGORITHM
        # Every fixture id is the real key_id of the key beside it, so a parser
        # that read the wrong attribute could not still look self-consistent.
        assert key.kid_is_self_consistent
        assert key.public_key_bytes is not None


def test_retired_keys_are_returned_and_marked(make_client: MakeClient) -> None:
    """The whole point of the endpoint: a client needs the key that signed an old file."""
    with make_client(_responder(FIXTURE)) as client:
        keys = client.accounts.list_signing_keys()

    assert keys[0].status == ACTIVE_STATUS
    assert not keys[0].is_retired
    assert [key.status for key in keys[1:]] == [RETIRED_STATUS, RETIRED_STATUS]
    assert all(key.is_retired for key in keys[1:])


def test_timestamps_parse_and_an_omitted_retired_stays_none(make_client: MakeClient) -> None:
    """The server omits `retired` entirely rather than sending null (`skip_serializing_if`)."""
    assert "retired" not in FIXTURE["data"][0]["attributes"]

    with make_client(_responder(FIXTURE)) as client:
        keys = client.accounts.list_signing_keys()

    assert keys[0].retired is None
    assert keys[0].created == datetime.datetime(2026, 8, 1, 9, 15, tzinfo=datetime.timezone.utc)
    assert keys[1].retired == datetime.datetime(2026, 8, 1, 9, 15, tzinfo=datetime.timezone.utc)


def test_the_public_key_attribute_is_camel_case(make_client: MakeClient) -> None:
    """`publicKey` is the one camelCase field in an otherwise snake_case attribute bag
    (`accounts/serializer.rs:108-117`). A parser reading `public_key` finds nothing —
    which is exactly the `productId` bug this repo already shipped once."""
    snake_cased = json.loads(json.dumps(FIXTURE))
    attributes = snake_cased["data"][0]["attributes"]
    attributes["public_key"] = attributes.pop("publicKey")

    with make_client(_responder(snake_cased)) as client:
        keys = client.accounts.list_signing_keys()

    assert keys[0].public_key == ""
    assert keys[0].public_key_bytes is None


def test_an_empty_key_set_is_normal_not_an_error(make_client: MakeClient) -> None:
    """`account_signing_keys` is only written by a rotation, so an account that has never
    rotated has no rows at all."""
    with make_client(_responder({"data": []})) as client:
        assert client.accounts.list_signing_keys() == []
        assert len(client.accounts.signing_key_set()) == 0


def test_one_unusable_row_does_not_strand_the_others(make_client: MakeClient) -> None:
    body = json.loads(json.dumps(FIXTURE))
    body["data"][1]["attributes"]["algorithm"] = "rsa2048"
    body["data"][2]["attributes"]["publicKey"] = "not base64!!"

    with make_client(_responder(body)) as client:
        key_set = client.accounts.signing_key_set()

    assert len(key_set) == 3
    assert len(key_set.usable_keys) == 1


def test_signing_key_set_wraps_the_same_keys(make_client: MakeClient) -> None:
    with make_client(_responder(FIXTURE)) as client:
        key_set = client.accounts.signing_key_set()

    assert isinstance(key_set, SigningKeySet)
    assert list(key_set.kids) == [resource["id"] for resource in FIXTURE["data"]]
    assert key_set.inconsistent_keys == ()


def test_a_license_key_credential_gets_forbidden(make_client: MakeClient) -> None:
    """The route needs `account.read`, which `Role::LicenseToken` does not hold
    (`shared/authz/mod.rs:241-267`), and there is no license-scoped alternative route.
    Documented rather than worked around — pin keys instead."""
    body = {"errors": [{"status": "403", "code": "FORBIDDEN", "title": "Forbidden"}]}

    with make_client(_responder(body, status=403)) as client, pytest.raises(ForbiddenError):
        client.accounts.list_signing_keys()


def test_a_fetched_key_set_verifies_a_file_signed_before_the_rotation(
    make_client: MakeClient,
) -> None:
    """End to end: fetch the published set, then open a file signed by the retired key."""
    retired_private = ed25519.Ed25519PrivateKey.generate()
    active_private = ed25519.Ed25519PrivateKey.generate()

    def _publish(private: ed25519.Ed25519PrivateKey, status: str) -> dict[str, Any]:
        public_key = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
        return {
            "type": "signing-keys",
            "id": key_id(public_key),
            "attributes": {
                "algorithm": "ed25519",
                "publicKey": public_key,
                "status": status,
                "created": "2026-08-01T09:15:00Z",
            },
        }

    body = {"data": [_publish(active_private, "active"), _publish(retired_private, "retired")]}
    payload = {
        "data": {"id": "018f2f3a-0000-7000-8000-000000000030", "type": "licenses"},
        "meta": {"iat": 1767225600, "jti": "j", "kid": body["data"][1]["id"]},
    }
    enc = base64.b64encode(json.dumps(payload).encode()).decode("ascii")
    certificate = base64.b64encode(
        json.dumps(
            {
                "enc": enc,
                "sig": base64.b64encode(retired_private.sign(enc.encode("ascii"))).decode(),
                "alg": ALG_PLAIN,
            }
        ).encode()
    ).decode("ascii")

    with make_client(_responder(body)) as client:
        key_set = client.accounts.signing_key_set()

    verified = LicenseFile.parse(f"{PEM_HEADER}\n{certificate}\n{PEM_FOOTER}").verify_with_key_set(
        key_set
    )

    assert verified.key.is_retired
    assert verified.key.kid == body["data"][1]["id"]
