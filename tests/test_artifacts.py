"""Artifact read and download.

The three things these tests exist to stop, in order of how much they would
cost if they regressed:

1. **The licence key reaching the storage host.** The download route answers
   ``303`` to a presigned URL on a third-party host by default, so any client
   that follows redirects with ``Authorization`` still attached leaks the
   credential. Pinned from two independent directions — the SDK always sends
   ``redirect=false``, *and* the HTTP client does not follow redirects — so
   losing either one alone still fails a test.
2. **``created``/``updated`` camel-cased into oblivion.** ``ArtifactAttributes``
   is ``rename_all = "camelCase"`` but those two fields carry explicit
   ``#[serde(rename)]``s that override it. Applying camelCase uniformly gives
   two silently-null timestamps rather than an error. This SDK shipped the
   mirror-image bug on ``productId`` once already.
3. **``redirectUrl`` absence treated as malformed.** It is skipped, not nulled,
   on list and show.

Response shapes come from ``tests/fixtures/artifacts/``, whose keys were
derived from the Rust struct rather than from this SDK's dataclass — see the
``_provenance`` block in each file.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest

from tamga.client import (
    MAX_PRESIGN_TTL_SECONDS,
    MIN_PRESIGN_TTL_SECONDS,
    TamgaClient,
    TamgaConfig,
)
from tamga.errors import ArtifactDownloadError, ForbiddenError, StorageUnavailableError
from tamga.transport import LicenseAuth

FIXTURES = Path(__file__).parent / "fixtures" / "artifacts"
ARTIFACT_ID = UUID("018f2f3a-0000-7000-8000-0000000000a1")
RELEASE_ID = UUID("018f2f3a-0000-7000-8000-000000000090")
LICENSE_KEY = "SECRET-LICENCE-KEY-DO-NOT-LEAK"


def _fixture(name: str) -> dict[str, Any]:
    body: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    # `_provenance` documents where the keys came from; it is not wire data.
    return {k: v for k, v in body.items() if not k.startswith("_")}


@pytest.fixture
def licensed_client() -> Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient]:
    """A client carrying a licence key, so a leaked credential is detectable."""

    def _make(handler: Callable[[httpx.Request], httpx.Response]) -> TamgaClient:
        config = TamgaConfig(
            account_id="018f2f3a-0000-7000-8000-000000000001",
            host="api.tamga.sh",
            default_auth=LicenseAuth(key=LICENSE_KEY),
        )
        return TamgaClient(config, transport=httpx.MockTransport(handler))

    return _make


# --------------------------------------------------------------------------
# 1. Credential containment
# --------------------------------------------------------------------------


def test_download_never_sends_the_licence_key_to_the_storage_host(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The storage fetch must carry no ``Authorization`` header at all.

    Not "a different header" and not "a stripped one" — the SDK reaches the
    storage host by simply never applying auth on that request. Asserted on the
    real recorded request, so an ``apply_auth`` call sneaking onto this path
    fails here.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.tamga.sh":
            return httpx.Response(200, json=_fixture("download_response.json"))
        return httpx.Response(200, content=b"MZ\x90\x00binary-payload")

    with licensed_client(handler) as client:
        assert client.artifacts.download(ARTIFACT_ID) == b"MZ\x90\x00binary-payload"

    api_request, storage_request = seen
    assert api_request.url.host == "api.tamga.sh"
    assert "License" in api_request.headers["Authorization"]

    assert storage_request.url.host == "storage.example.com"
    assert "authorization" not in storage_request.headers
    # Belt and braces: the key must not appear anywhere in the outbound request.
    assert LICENSE_KEY not in str(storage_request.url)
    assert not any(LICENSE_KEY in v for v in storage_request.headers.values())


def test_the_http_client_does_not_follow_redirects(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The backstop behind ``redirect=false``, pinned independently of it.

    httpx defaults ``follow_redirects`` to ``False`` and ``TamgaClient`` does
    not override it. If a future change turned it on, a ``303`` from the
    download route would be chased to the storage host **with the request's
    own headers**, which is the leak. This asserts the property directly so it
    fails even if the ``redirect=false`` parameter is still being sent.
    """
    with licensed_client(lambda r: httpx.Response(200, json={"data": None})) as client:
        assert client._http.follow_redirects is False


def test_a_303_is_surfaced_rather_than_chased(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """If the server ever answers ``303`` anyway, nothing follows it.

    Proves the two protections compose: the SDK asks for ``redirect=false``,
    and a server that ignores that still cannot induce a second, credentialed
    request. The 303 is a non-2xx-free response with no body, so it parses to
    no artifact — the point is that only ONE request happened.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            303, headers={"Location": "https://storage.example.com/leak"}, content=b""
        )

    with licensed_client(handler) as client, pytest.raises(ArtifactDownloadError):
        client.artifacts.download(ARTIFACT_ID)

    assert len(seen) == 1
    assert seen[0].url.host == "api.tamga.sh"


def test_get_download_url_always_asks_for_redirect_false(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``redirect=false`` is unconditional — there is no caller-facing switch."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client:
        client.artifacts.get_download_url(ARTIFACT_ID)

    assert seen[0].url.params["redirect"] == "false"
    assert seen[0].url.path.endswith(f"/artifacts/{ARTIFACT_ID}/actions/download")


# --------------------------------------------------------------------------
# 2. Wire casing
# --------------------------------------------------------------------------


def test_created_and_updated_are_not_camel_cased(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``created``/``updated``, never ``createdAt``/``updatedAt``.

    The explicit ``#[serde(rename)]`` beats the struct's ``rename_all``. An
    implementation reading ``createdAt`` gets ``None`` here rather than an
    error, so this asserts the parsed values, not merely that parsing survived.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client:
        artifact = client.artifacts.get_download_url(ARTIFACT_ID)

    assert artifact.created is not None
    assert artifact.updated is not None
    assert artifact.created.year == 2026
    assert artifact.created.tzinfo == timezone.utc
    assert artifact.updated.hour == 4


def test_the_fixture_really_uses_the_server_spellings() -> None:
    """Guards the guard: pins the fixture's own key spellings.

    If a future refresh of the fixture "tidied" ``created`` to ``createdAt``,
    the parser test above would go on passing against a wrong file. These
    spellings are what ``serializer.rs`` emits.
    """
    attrs = _fixture("download_response.json")["data"]["attributes"]
    assert "created" in attrs and "createdAt" not in attrs
    assert "updated" in attrs and "updatedAt" not in attrs
    assert "redirectUrl" in attrs and "redirect_url" not in attrs


def test_redirect_url_is_camel_cased(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``redirectUrl`` — the one multi-word field the camelCase rule does reach."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client:
        artifact = client.artifacts.get_download_url(ARTIFACT_ID)

    assert artifact.redirect_url is not None
    assert artifact.redirect_url.startswith("https://storage.example.com/")


def test_all_scalar_attributes_round_trip(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Every modelled field reads back, so a missed key cannot hide behind a default."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client:
        artifact = client.artifacts.get_download_url(ARTIFACT_ID)

    assert artifact.id == ARTIFACT_ID
    assert artifact.filename == "tamga-app-1.4.0-darwin-arm64.dmg"
    assert artifact.filetype == "dmg"
    assert artifact.filesize == 48210944
    assert artifact.checksum is not None and len(artifact.checksum) == 64
    assert artifact.platform == "darwin-arm64"
    assert artifact.arch == "arm64"
    assert artifact.signature is not None
    assert artifact.status == "UPLOADED"
    assert artifact.metadata == {"notarized": True}


# --------------------------------------------------------------------------
# 3. List and show
# --------------------------------------------------------------------------


def test_list_tolerates_absent_redirect_url(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``redirectUrl`` is skipped, not nulled, on list — and that is the normal case."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fixture("list_response.json"))

    with licensed_client(handler) as client:
        page = client.artifacts.list(RELEASE_ID)

    assert len(page.items) == 2
    assert all(a.redirect_url is None for a in page.items)
    assert page.items[1].status == "WAITING"
    assert page.items[1].filesize is None
    assert page.items[1].checksum is None


def test_list_sends_an_explicit_page_size(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Omitting ``limit`` would let the server apply its invisible default of 25.

    Without a known page size, a truncated page is indistinguishable from the
    last one — the same defect that made other list routes look complete at 25
    rows.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_fixture("list_response.json"))

    with licensed_client(handler) as client:
        client.artifacts.list(RELEASE_ID)

    assert seen[0].url.params["limit"] == "100"
    assert "page[after]" not in seen[0].url.params


def test_list_passes_the_cursor_through(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``page[after]`` really reaches the query on this route, unlike entitlements."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_fixture("list_response.json"))

    with licensed_client(handler) as client:
        page = client.artifacts.list(RELEASE_ID, limit=2, after=str(ARTIFACT_ID))

    assert seen[0].url.params["page[after]"] == str(ARTIFACT_ID)
    # A full page means there may be more; the cursor is the last item's id.
    assert page.next_after == "018f2f3a-0000-7000-8000-0000000000a2"


def test_get_reads_metadata_without_a_redirect_url(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``GET /artifacts/{id}`` — show, which never presigns."""
    seen: list[httpx.Request] = []
    body = _fixture("download_response.json")
    del body["data"]["attributes"]["redirectUrl"]

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=body)

    with licensed_client(handler) as client:
        artifact = client.artifacts.get(ARTIFACT_ID)

    assert seen[0].url.path.endswith(f"/artifacts/{ARTIFACT_ID}")
    assert "actions" not in seen[0].url.path
    assert artifact.redirect_url is None
    assert artifact.filename == "tamga-app-1.4.0-darwin-arm64.dmg"


# --------------------------------------------------------------------------
# 4. TTL bounds
# --------------------------------------------------------------------------


@pytest.mark.parametrize("ttl", [MIN_PRESIGN_TTL_SECONDS, 3600, MAX_PRESIGN_TTL_SECONDS])
def test_in_range_ttl_is_sent(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    ttl: int,
) -> None:
    """Both bounds are inclusive, matching ``validate_presign_ttl``."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client:
        client.artifacts.get_download_url(ARTIFACT_ID, ttl=ttl)

    assert seen[0].url.params["ttl"] == str(ttl)


@pytest.mark.parametrize(
    "ttl", [0, 59, MIN_PRESIGN_TTL_SECONDS - 1, MAX_PRESIGN_TTL_SECONDS + 1, -1]
)
def test_out_of_range_ttl_is_refused_before_any_request(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    ttl: int,
) -> None:
    """Rejected client-side, and rejected *without* sending anything.

    The count assertion is the load-bearing half: a check that raised only
    after the request went out would still pass a `pytest.raises` alone.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client, pytest.raises(ValueError, match="ttl must be between"):
        client.artifacts.get_download_url(ARTIFACT_ID, ttl=ttl)

    assert seen == []


def test_omitted_ttl_sends_no_ttl_parameter(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """No ``ttl`` means the server's own 300s default, not a client-invented one."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_fixture("download_response.json"))

    with licensed_client(handler) as client:
        client.artifacts.get_download_url(ARTIFACT_ID)

    assert "ttl" not in seen[0].url.params


def test_the_presign_ttl_range_is_not_the_checkout_ttl_range() -> None:
    """Two different limits under two different error codes; do not collapse them."""
    from tamga.client import MAX_CHECKOUT_TTL_SECONDS

    assert MIN_PRESIGN_TTL_SECONDS == 60
    assert MAX_PRESIGN_TTL_SECONDS == 604800
    assert MAX_PRESIGN_TTL_SECONDS != MAX_CHECKOUT_TTL_SECONDS


# --------------------------------------------------------------------------
# 5. Failure modes
# --------------------------------------------------------------------------


def test_a_403_on_download_may_be_the_release_gate_not_the_permission(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A closed release's binary is refused even to a holder of ``artifact.download``.

    The handler runs ``enforce_release_access`` on the owning release in
    addition to the permission check, so this 403 is not diagnosable as an auth
    misconfiguration. The docstring says so; this pins that the error still
    surfaces as an ordinary ``ForbiddenError`` rather than something bespoke.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"errors": [{"status": "403", "code": "FORBIDDEN", "detail": "release closed"}]},
        )

    with licensed_client(handler) as client, pytest.raises(ForbiddenError):
        client.artifacts.get_download_url(ARTIFACT_ID)


def test_storage_unavailable_is_its_own_error(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``422 STORAGE_UNAVAILABLE`` is a deployment condition, not a caller error."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "errors": [{"status": "422", "code": "STORAGE_UNAVAILABLE", "detail": "no backend"}]
            },
        )

    with licensed_client(handler) as client, pytest.raises(StorageUnavailableError):
        client.artifacts.get_download_url(ARTIFACT_ID)


def test_download_of_a_never_uploaded_artifact_reports_the_status(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """No ``redirectUrl`` and no second request — there is nothing to fetch."""
    seen: list[httpx.Request] = []
    body = _fixture("download_response.json")
    del body["data"]["attributes"]["redirectUrl"]
    body["data"]["attributes"]["status"] = "WAITING"

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=body)

    with licensed_client(handler) as client, pytest.raises(ArtifactDownloadError, match="WAITING"):
        client.artifacts.download(ARTIFACT_ID)

    assert len(seen) == 1


def test_a_storage_error_names_the_expiry_remedy(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A ``403`` from storage is almost always an expired URL, not a permission."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.tamga.sh":
            return httpx.Response(200, json=_fixture("download_response.json"))
        return httpx.Response(403, content=b"<Error>AccessDenied</Error>")

    with licensed_client(handler) as client, pytest.raises(ArtifactDownloadError) as excinfo:
        client.artifacts.download(ARTIFACT_ID)

    assert excinfo.value.status == 403
    assert "presign again" in excinfo.value.detail


def test_artifact_errors_are_catchable_as_tamga_error(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The documented ``except TamgaError`` convention must cover the new paths."""
    from tamga.errors import PresignTtlInvalidError, TamgaError

    assert issubclass(ArtifactDownloadError, TamgaError)
    assert issubclass(StorageUnavailableError, TamgaError)
    assert issubclass(PresignTtlInvalidError, TamgaError)


def test_presign_ttl_invalid_is_distinct_from_checkout_ttl_invalid() -> None:
    """Two codes, two ranges — mapping both onto one class misreports the bounds."""
    from tamga.errors import PresignTtlInvalidError, TtlInvalidError, parse_error_envelope

    presign = parse_error_envelope(
        422, json.dumps({"errors": [{"code": "PRESIGN_TTL_INVALID"}]}).encode()
    )
    checkout = parse_error_envelope(422, json.dumps({"errors": [{"code": "TTL_INVALID"}]}).encode())
    assert isinstance(presign, PresignTtlInvalidError)
    assert isinstance(checkout, TtlInvalidError)
    assert not isinstance(presign, TtlInvalidError)


def test_artifacts_subclient_is_reachable_from_the_facade(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """``TamgaClient.artifacts``, alongside the other namespaced sub-clients."""
    with licensed_client(lambda r: httpx.Response(200, json={"data": None})) as client:
        assert client.artifacts is not None
        assert client.artifacts._http is client._http


def test_a_malformed_resource_raises_value_error_not_attribute_error() -> None:
    """The parser must stay inside the documented exception contract.

    An empty-bodied 2xx or a 3xx parses to ``None``. Subscripting that bare
    would raise ``TypeError``/``AttributeError``, which escapes every
    ``except (ValueError, TamgaError)`` a caller was told to write — the exact
    escape that was a HIGH finding on the two ``verify()`` paths here.
    """
    from tamga.client import _parse_artifact_resource

    for bad in (None, [], "artifacts", 7, {"type": "artifacts"}):
        with pytest.raises(ValueError):
            _parse_artifact_resource(bad)  # type: ignore[arg-type]


def test_a_non_object_attributes_bag_does_not_escape_the_contract() -> None:
    """``attributes`` arriving as a non-object degrades to empty, never to a crash."""
    from tamga.client import _parse_artifact_resource

    artifact = _parse_artifact_resource(
        {"id": "018f2f3a-0000-7000-8000-0000000000a1", "attributes": "nonsense"}
    )
    assert artifact.filename == ""
    assert artifact.redirect_url is None


def test_the_303_error_does_not_echo_the_presigned_url(
    licensed_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Error text lands in logs; a presigned URL is a credential and must not.

    Pairs with ``test_a_303_is_surfaced_rather_than_chased``: that one proves
    the redirect is not followed, this one proves the URL is not leaked into a
    log line instead.
    """
    secret_url = "https://storage.example.com/leak?X-Amz-Signature=secret"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(303, headers={"Location": secret_url}, content=b"")

    with licensed_client(handler) as client, pytest.raises(ArtifactDownloadError) as excinfo:
        client.artifacts.get_download_url(ARTIFACT_ID)

    assert "X-Amz-Signature" not in str(excinfo.value)
    assert "storage.example.com" not in str(excinfo.value)
