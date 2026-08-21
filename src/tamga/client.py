"""``TamgaClient`` façade and namespaced sub-clients for every endpoint group.

``TamgaClient`` wraps an ``httpx.Client`` and exposes namespaced sub-clients
(``.licenses``, ``.machines``, ``.components``, ``.processes``,
``.entitlements``) rather than one flat method namespace, mirroring the
server's own resource grouping.

Auth note: auth **is** enforced server-side. For the license-key transport
(``Authorization: License <key>``) the license's policy must set
``authentication_strategy`` to ``"LICENSE"`` or ``"MIXED"``; the column
defaults to ``"TOKEN"``, and ``"NONE"`` behaves the same way at the auth gate,
so an unconfigured policy answers ``401 LICENSE_NOT_ALLOWED``
(``tamga.errors.LicenseNotAllowedError``). That is a configuration
precondition, not a transient failure — retrying the same key never helps.

Rate limiting: the server does answer ``429``. Requests that are safe to
repeat are retried here with capped ``Retry-After``/jittered backoff — see
``_is_retryable``, ``_retry_delay``, and ``_request_with_retry`` — and a
request that exhausts ``TamgaConfig.max_retries`` surfaces as
``tamga.errors.RateLimitedError``.
"""

from __future__ import annotations

import builtins
import contextlib
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Generic, TypeVar
from uuid import UUID

import httpx

from tamga.errors import (
    FingerprintTakenError,
    MachineOverLimitError,
    NotFoundError,
    TamgaError,
    TtlInvalidError,
    parse_error_envelope,
)
from tamga.models.health import HealthStatus
from tamga.models.license import LicenseFileResource, LicenseResource, LicenseScope
from tamga.models.machine import (
    ComponentResource,
    HeartbeatStatus,
    MachineFileResource,
    MachineResource,
    ProcessResource,
)
from tamga.models.policy import Entitlement, PolicyResource
from tamga.models.release import ReleaseResource
from tamga.models.validation import ValidationCode, ValidationMeta, ValidationResult
from tamga.proof import ProofResult
from tamga.transport import (
    DEFAULT_TIMEOUT_SECONDS,
    AuthTransport,
    LicenseAuth,
    apply_auth,
    build_base_url,
    build_root_url,
    parse_response,
    parse_retry_after,
    sanitize_tamga_version,
)

T = TypeVar("T")

#: Recommended machine heartbeat ping interval — roughly 1/3 of the server's
#: *default* 600s heartbeat window. The window is not a constant: it comes from
#: the license's ``policy.heartbeat_duration`` and only falls back to 600s when
#: that column is unset, so a policy with a short window needs a correspondingly
#: shorter interval. Do not compute one by hand — read the policy with
#: ``TamgaClient.licenses.get_policy`` and build the scheduler with
#: ``HeartbeatScheduler.for_policy``, which applies the same 1/3 rule to the
#: window the policy actually sets.
MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL: timedelta = timedelta(seconds=200)

#: Recommended process heartbeat ping interval — well inside the server's
#: hardcoded 30s process heartbeat window, which has no resurrection grace
#: period (see the Tamga API protocol specification section 8).
PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL: timedelta = timedelta(seconds=10)

#: The server's maximum (and this SDK's default) page size for the keyset-
#: paginated list routes. The server clamps `limit` to 1..100 and applies its
#: own default of 25 when the parameter is absent — which is invisible to the
#: caller, so this SDK always sends a page size explicitly.
MAX_PAGE_SIZE: int = 100

#: Server-side bounds on machine/process checkout `ttl` (seconds): must be
#: `> 0` and `<= 31536000` (365 days), else `422 TTL_INVALID`.
MAX_CHECKOUT_TTL_SECONDS: int = 31536000

#: How many pings the SDK aims to fit inside one heartbeat window.
#:
#: Three, so two consecutive pings can be lost — to a `429`, a network blip, a
#: paused process — before the machine falls outside the window. One ping per
#: window would make every single failure terminal.
HEARTBEAT_PINGS_PER_WINDOW: int = 3

#: Hard ceiling on how many pages ``MachinesClient.find_by_fingerprint`` will
#: walk before giving up.
#:
#: The search is bounded three separate ways — this ceiling, the server's own
#: ``meta.page.totalPages``, and an empty page — and the loop is written as a
#: ``range`` so that even a server reporting nonsense page metadata cannot make
#: it spin. That belt-and-braces is deliberate: this SDK has already shipped one
#: list helper that looped forever against an endpoint whose cursor turned out
#: to be inert (see ``EntitlementsClient.list_all``), and the failure mode was an
#: unbounded ``items`` list that exhausted memory rather than an error anyone
#: could see.
MAX_MACHINE_SEARCH_PAGES: int = 20

#: Create-time limit error codes on ``POST /machines``, mapped to the
#: ``ValidationCode`` that describes the same limit.
#:
#: Machine creation is **not** limit-free: the server checks machines/cores/
#: memory/disk before inserting the row. The check runs through the policy's
#: overage strategy, so under a permissive strategy (``ALLOW_ACCESS``-style
#: multipliers, ``ALLOW_1_25X_OVERAGE`` and friends) creation still succeeds and
#: the limit only shows up at validate time — which is why
#: ``MachinesClient.activate_machine`` keeps both paths.
_CREATE_LIMIT_CODE_TO_VALIDATION_CODE: dict[str, ValidationCode] = {
    "MACHINE_LIMIT_EXCEEDED": ValidationCode.TOO_MANY_MACHINES,
    "CORE_LIMIT_EXCEEDED": ValidationCode.TOO_MANY_CORES,
    "MEMORY_LIMIT_EXCEEDED": ValidationCode.TOO_MUCH_MEMORY,
    "DISK_LIMIT_EXCEEDED": ValidationCode.TOO_MUCH_DISK,
}


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp, tolerating a trailing ``Z``.

    Python 3.9's ``datetime.fromisoformat`` doesn't accept ``Z`` until 3.11.
    """
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_license_resource(
    data: dict[str, Any],
    entitlements_fetcher: Any = None,
) -> LicenseResource:
    return LicenseResource(
        id=UUID(str(data["id"])),
        type=data.get("type", "licenses"),
        attributes=data.get("attributes", {}),
        relationships=data.get("relationships", {}),
        _entitlements_fetcher=entitlements_fetcher,
    )


def _parse_machine_resource(data: dict[str, Any]) -> MachineResource:
    attrs = data.get("attributes", {})
    return MachineResource(
        id=UUID(str(data["id"])),
        fingerprint=attrs.get("fingerprint", ""),
        name=attrs.get("name"),
        ip=attrs.get("ip"),
        hostname=attrs.get("hostname"),
        platform=attrs.get("platform"),
        cores=attrs.get("cores"),
        memory=attrs.get("memory"),
        disk=attrs.get("disk"),
        metadata=attrs.get("metadata") or {},
        heartbeat_status=HeartbeatStatus(attrs.get("heartbeat_status", "NOT_STARTED")),
        last_heartbeat_at=_parse_datetime(attrs.get("last_heartbeat_at")),
        next_heartbeat_at=_parse_datetime(attrs.get("next_heartbeat_at")),
        last_check_out_at=_parse_datetime(attrs.get("last_check_out_at")),
        created=_parse_datetime(attrs.get("created")),
        updated=_parse_datetime(attrs.get("updated")),
    )


def _parse_component_resource(data: dict[str, Any]) -> ComponentResource:
    attrs = data.get("attributes", {})
    return ComponentResource(
        id=UUID(str(data["id"])),
        machine_id=UUID(str(attrs["machine_id"])),
        fingerprint=attrs.get("fingerprint", ""),
        name=attrs.get("name", ""),
        metadata=attrs.get("metadata") or {},
        created=_parse_datetime(attrs.get("created")),
        updated=_parse_datetime(attrs.get("updated")),
    )


def _parse_process_resource(data: dict[str, Any]) -> ProcessResource:
    attrs = data.get("attributes", {})
    return ProcessResource(
        id=UUID(str(data["id"])),
        machine_id=UUID(str(attrs["machine_id"])),
        pid=attrs.get("pid", ""),
        metadata=attrs.get("metadata") or {},
        last_heartbeat_at=_parse_datetime(attrs.get("last_heartbeat_at")),
        created=_parse_datetime(attrs.get("created")),
        updated=_parse_datetime(attrs.get("updated")),
    )


def _parse_entitlement(data: dict[str, Any]) -> Entitlement:
    attrs = data.get("attributes", {})
    return Entitlement(
        id=UUID(str(data["id"])),
        name=attrs.get("name", ""),
        code=attrs.get("code", ""),
        metadata=attrs.get("metadata") or {},
        created=_parse_datetime(attrs.get("created")),
        updated=_parse_datetime(attrs.get("updated")),
        inherited=attrs.get("inherited"),
    )


def _parse_policy_resource(data: dict[str, Any]) -> PolicyResource:
    """Parse a JSON:API ``policies`` resource object into a ``PolicyResource``.

    ``PolicyResource.from_api`` takes a flat attributes mapping and looks for
    ``id`` inside it, but JSON:API carries ``id`` on the resource object rather
    than among its attributes — so the id is merged in here. Attributes win on a
    collision: a future server that also emitted an ``id`` attribute would be
    describing the same resource, and preferring the envelope's copy would be an
    arbitrary choice between two spellings of one value.
    """
    attributes = dict(data.get("attributes") or {})
    attributes.setdefault("id", data["id"])
    return PolicyResource.from_api(attributes)


def _parse_release_resource(data: dict[str, Any]) -> ReleaseResource:
    attrs = data.get("attributes", {})
    return ReleaseResource(
        id=UUID(str(data["id"])),
        product_id=UUID(str(attrs["product_id"])),
        version=attrs.get("version", ""),
        channel=attrs.get("channel", ""),
        status=attrs.get("status", ""),
        name=attrs.get("name"),
        # Absent rather than null when unset — the server skips serializing it.
        tag=attrs.get("tag"),
        metadata=attrs.get("metadata") or {},
        created=_parse_datetime(attrs.get("created")),
        updated=_parse_datetime(attrs.get("updated")),
    )


def _parse_page_meta(meta: dict[str, Any]) -> tuple[int, int, int, int]:
    """Read ``meta.page{number,size,total,totalPages}`` off a list response.

    Note the lone camelCase key in an otherwise snake_case protocol:
    ``totalPages``. Falls back to zeroes rather than raising if the member is
    missing — a page of items with unreadable metadata is still a usable page,
    and ``has_next_page`` then reports ``False``, which stops a pagination loop
    instead of spinning it.
    """
    page = meta.get("page")
    if not isinstance(page, dict):
        return (0, 0, 0, 0)
    return (
        int(page.get("number", 0)),
        int(page.get("size", 0)),
        int(page.get("total", 0)),
        int(page.get("totalPages", 0)),
    )


def _parse_license_file_resource(data: dict[str, Any]) -> LicenseFileResource:
    attrs = data.get("attributes", {})
    return LicenseFileResource(
        certificate=attrs.get("certificate", ""),
        algorithm=attrs.get("algorithm", ""),
        includes=attrs.get("includes", []),
        ttl=attrs.get("ttl"),
        expiry=attrs.get("expiry"),
        issued=attrs.get("issued", ""),
    )


def _parse_validation_meta(meta: dict[str, Any]) -> ValidationMeta:
    return ValidationMeta(
        ts=_parse_datetime(meta.get("ts")) or datetime.now(timezone.utc),
        valid=bool(meta.get("valid", False)),
        detail=meta.get("detail", ""),
        code=ValidationCode(meta.get("code", ValidationCode.UNKNOWN.value)),
    )


def _scope_to_dict(scope: LicenseScope | None) -> dict[str, Any] | None:
    if scope is None:
        return None
    result: dict[str, Any] = {}
    if scope.product is not None:
        result["product"] = str(scope.product)
    if scope.policy is not None:
        result["policy"] = str(scope.policy)
    if scope.user is not None:
        result["user"] = str(scope.user)
    if scope.environment is not None:
        result["environment"] = str(scope.environment)
    if scope.entitlements is not None:
        result["entitlements"] = scope.entitlements
    if scope.fingerprint is not None:
        result["fingerprint"] = scope.fingerprint
    # `version` and `checksum` are deliberately NOT emitted. The server does
    # not ignore them: `reject_unenforced_scope` runs before any validation
    # work and fails the whole call with `422 SCOPE_NOT_SUPPORTED` the moment
    # either key is present, so a caller that sets one gets no `meta.valid` at
    # all. Dropping them here degrades that caller to a working validate
    # instead of a hard failure. The fields stay on `LicenseScope` (removing
    # them would be a breaking change) and are documented as deprecated there.
    return result


@dataclass(frozen=True)
class TamgaConfig:
    """Configuration for a ``TamgaClient``.

    Attributes:
        account_id: Required in both singleplayer and multiplayer server
            modes — in singleplayer mode it must equal the server's
            configured account, or the request resolves as unauthenticated.
        host: API host, without scheme (e.g. ``"api.tamga.sh"``).
        api_version: Sent as the ``Tamga-Version`` request header on every
            request. Should be pinned per SDK major version so server-side
            API evolution doesn't silently change response shapes underneath
            a released SDK version.
        default_auth: The default auth transport used when a per-call auth
            override isn't supplied.
        timeout_seconds: Connect/read timeout for the underlying
            ``httpx.Client``. Defaults to 45s — deliberately longer than the
            server's own 30s request timeout, so a slow request surfaces as
            the server's ``504`` (which carries an ``X-Request-Id`` to quote
            in a support ticket) rather than racing it to a local timeout
            that carries nothing.
        max_retries: How many times a rate-limited (``429``) request is
            retried before giving up. ``0`` disables automatic retries — the
            raised ``RateLimitedError`` still carries ``Retry-After`` so you
            can schedule your own backoff. Only requests that are safe to
            repeat are retried; see ``_is_retryable``.
        user_agent: Optional courtesy ``User-Agent`` header (e.g.
            ``"tamga-python/<version>"``). The server has no requirement or
            handling for this header.
    """

    account_id: str
    host: str
    api_version: str = "1"
    default_auth: AuthTransport | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    user_agent: str | None = None
    max_retries: int = 3


@dataclass(frozen=True)
class Page(Generic[T]):
    """A keyset-paginated page of resources.

    Attributes:
        items: The resources on this page.
        next_after: The cursor to pass as ``after`` to fetch the next page,
            or ``None`` if this is the last page.
    """

    items: list[T]
    next_after: str | None


@dataclass(frozen=True)
class OffsetPage(Generic[T]):
    """An offset-paginated page of resources, with real server-sent page metadata.

    Distinct from ``Page``, and the distinction is not cosmetic. ``Page`` models
    the *keyset* routes, where the server sends no pagination metadata at all
    and the SDK has to synthesize a cursor from ``len(items) == limit``.
    ``GET /machines`` is the one route on this SDK's surface that paginates the
    other way: it answers with ``meta.page{number,size,total,totalPages}``, so
    the page count is known rather than inferred, and pages are addressed by
    number rather than by the previous page's last id.

    Sending ``page[after]`` to an offset route, or a page number to a keyset
    route, is silently ignored in both directions — which is precisely the shape
    of bug that made ``EntitlementsClient.list_all`` loop forever. Keeping the
    two page types apart is what stops a caller writing that loop here.

    Attributes:
        items: The resources on this page.
        page_number: 1-based number of the page returned, as the server floored
            and reports it — not necessarily the number that was requested.
        page_size: Page size the server applied, after clamping to 1..100.
        total: Rows matching the request's filters across every page — not the
            size of the whole table.
        total_pages: Number of pages at this page size. ``0`` when ``total`` is
            ``0``.
    """

    items: list[T]
    page_number: int
    page_size: int
    total: int
    total_pages: int

    @property
    def has_next_page(self) -> bool:
        """Whether a page after this one exists, per the server's own page count."""
        return self.page_number < self.total_pages


def heartbeat_interval_for_policy(policy: PolicyResource) -> timedelta:
    """The machine ping interval this policy implies.

    ``policy.effective_heartbeat_window_seconds / HEARTBEAT_PINGS_PER_WINDOW``,
    which reduces to the 200s default only when the policy leaves
    ``heartbeat_duration`` unset. **This is the supported way to size a
    ``HeartbeatScheduler``** — see ``HeartbeatScheduler.for_policy``, which wires
    it up in one call.

    Read the policy through ``TamgaClient.licenses.get_policy(license_id)``:
    that route authorizes on ``license.read``, which a license-key credential
    holds, whereas ``TamgaClient.policies.get(policy_id)`` authorizes on
    ``policy.read``, which it does not.

    Do **not** try to recover the window from a machine response's
    ``next_heartbeat_at`` instead. The field is computed from whichever window
    the answering query happened to have joined, so ``POST /machines``,
    ``ping-heartbeat``, ``reset-heartbeat`` and ``PATCH /machines/{id}`` all
    size it against the 600s fallback while ``GET /machines/{id}``, the machine
    list, check-out and offline-proof size it against the policy. Two responses
    for the same machine seconds apart can disagree, and nothing on the wire
    says which kind you are holding.

    Args:
        policy: The policy governing the machine's license.

    Returns:
        The ping interval, floor-divided and clamped to at least one second so
        that an absurdly short policy window cannot turn the scheduler into a
        busy loop.
    """
    seconds = policy.effective_heartbeat_window_seconds // HEARTBEAT_PINGS_PER_WINDOW
    return timedelta(seconds=max(1, seconds))


def _send_request(
    http: httpx.Client,
    config: TamgaConfig,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    auth_override: AuthTransport | None = None,
    is_quick_validate: bool = False,
) -> Any:
    """Shared request-building/sending/parsing helper used by every sub-client.

    Applies the ``Tamga-Version`` header, dispatches ``auth_override`` (or
    ``config.default_auth`` if unset) via ``tamga.transport.apply_auth``, and
    parses the response through ``tamga.transport.parse_response`` (which
    raises a typed ``tamga.errors.TamgaError`` on any non-2xx response).

    Always returns just the parsed ``.data`` payload, already unwrapped from
    the JSON:API envelope. The response ``meta`` object is dropped here, so
    the endpoints that need it (validate, checkout, offline proof) build
    their request through ``_client_request`` and read ``meta`` off the raw
    response via ``_raw_response_meta`` instead.
    """
    return _send_request_raw(
        http,
        config,
        method,
        path,
        json_body=json_body,
        params=params,
        auth_override=auth_override,
        is_quick_validate=is_quick_validate,
    ).data


def _send_raw_response(
    http: httpx.Client,
    config: TamgaConfig,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    auth_override: AuthTransport | None = None,
    is_quick_validate: bool = False,
) -> httpx.Response:
    """Build, authenticate and send one request, returning the un-parsed response.

    Split out of ``_send_request_raw`` so the endpoints that need the response
    ``meta`` (or, for ``/v1/health``, a body that is not a JSON:API envelope at
    all) can reach the raw response without each rebuilding the header and auth
    assembly and drifting from it.
    """
    headers: dict[str, str] = {
        "Tamga-Version": sanitize_tamga_version(config.api_version),
    }
    if not is_quick_validate:
        headers["Content-Type"] = "application/vnd.api+json"
    if config.user_agent:
        headers["User-Agent"] = config.user_agent

    request_params: dict[str, Any] = dict(params or {})

    auth = auth_override if auth_override is not None else config.default_auth
    if auth is not None:
        apply_auth(headers, request_params, auth)

    return _request_with_retry(
        http,
        config,
        method,
        path,
        json_body=json_body,
        params=request_params,
        headers=headers,
    )


def _send_request_raw(
    http: httpx.Client,
    config: TamgaConfig,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    auth_override: AuthTransport | None = None,
    is_quick_validate: bool = False,
) -> Any:
    response = _send_raw_response(
        http,
        config,
        method,
        path,
        json_body=json_body,
        params=params,
        auth_override=auth_override,
        is_quick_validate=is_quick_validate,
    )
    return parse_response(response, is_quick_validate=is_quick_validate)


def _send_request_with_meta(
    http: httpx.Client,
    config: TamgaConfig,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Send a request and return ``(data, meta)`` from the JSON:API document.

    ``_send_request`` drops the document's ``meta`` member, which is where the
    offset-paginated routes put ``page{number,size,total,totalPages}``.
    """
    response = _send_raw_response(http, config, method, path, json_body=json_body, params=params)
    parsed = parse_response(response)
    return parsed.data, _raw_response_meta(response)


_RETRYABLE_POST_SUFFIXES = (
    "/actions/validate",
    "/actions/validate-key",
    "/actions/check-in",
    "/actions/check-out",
    "/actions/ping",
    # `/actions/ping-heartbeat` does NOT end with `/actions/ping` — that suffix
    # only matches the process ping route. Leaving it off excluded the single
    # call a machine makes on a timer from backoff, so a throttled heartbeat
    # was dropped silently and the machine drifted toward being culled. Both
    # heartbeat writes are bare idempotent `UPDATE`s server-side, so repeating
    # them is unconditionally safe (unlike `POST /machines`, which burns a seat).
    "/actions/ping-heartbeat",
    "/actions/reset-heartbeat",
)


def _is_retryable(method: str, path: str) -> bool:
    """Is this request safe to repeat after a ``429``?

    ``GET`` always is. Among the ``POST``s only the licensing *actions* are —
    they are effectively idempotent (validate, check in/out, ping or reset a
    heartbeat) and they are precisely the calls a client makes on a timer, so
    they are the ones that hit the rate limit in the first place. The rate
    limiter buckets per ``(caller, route pattern)``, and with proxy headers
    untrusted every caller shares one bucket per route — so a fleet throttles
    itself on exactly these routes.

    Creates are deliberately excluded: retrying ``POST /machines`` risks a
    second activation burning a second seat, and only the caller knows whether
    that is acceptable.
    """
    if method.upper() == "GET":
        return True
    return method.upper() == "POST" and path.endswith(_RETRYABLE_POST_SUFFIXES)


def _retry_delay(attempt: int, retry_after: int | None) -> float:
    """Seconds to wait before retry number ``attempt`` (0-based).

    Prefers the server's ``Retry-After`` — it knows when the bucket refills and
    guessing wastes the budget — but caps it, so a misconfigured or hostile
    proxy cannot park the caller for an hour on one header. Otherwise
    exponential backoff with jitter, because a fleet that all retries on the
    same schedule reconverges into the spike it was backing off from.
    """
    if retry_after is not None:
        return float(min(retry_after, 60))
    base = float(2 ** min(attempt, 5))
    return base + random.random()


def _request_with_retry(
    http: httpx.Client,
    config: TamgaConfig,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None,
    params: dict[str, Any],
    headers: dict[str, str],
) -> httpx.Response:
    """Send a request, transparently retrying while the server answers ``429``.

    Returns the first non-429 response, or the last 429 once the retry budget
    is spent — the caller then turns it into a ``RateLimitedError``.
    """
    retryable = _is_retryable(method, path)
    attempt = 0
    while True:
        response = http.request(
            method,
            path,
            json=json_body,
            params=params,
            headers=headers,
        )
        if response.status_code != 429 or not retryable or attempt >= config.max_retries:
            return response
        time.sleep(_retry_delay(attempt, parse_retry_after(response)))
        attempt += 1


def _client_request(
    sub: Any,
    method: str,
    path: str,
    **kwargs: Any,
) -> httpx.Response:
    """Retry-aware ``self._http.request`` for the namespaced sub-clients.

    They build their own requests rather than going through
    ``_send_request_raw`` (they need the raw response for ``meta``), so the
    `429` handling has to be reachable from here too — otherwise the endpoints
    most likely to be throttled, the ones a client calls on a timer, would be
    exactly the ones without backoff.
    """
    return _request_with_retry(
        sub._http,
        sub._config,
        method,
        path,
        json_body=kwargs.get("json"),
        params=kwargs.get("params") or {},
        headers=kwargs.get("headers") or {},
    )


def _raw_response_meta(response: httpx.Response) -> dict[str, Any]:
    """Extract the raw JSON:API ``meta`` object from a response, if present."""
    if not response.content:
        return {}
    body = json.loads(response.content)
    meta = body.get("meta")
    return meta if isinstance(meta, dict) else {}


@dataclass
class LicensesClient:
    """Namespaced client for ``/licenses`` endpoints. Access via ``TamgaClient.licenses``."""

    _http: httpx.Client
    _config: TamgaConfig
    _entitlements: EntitlementsClient | None = None

    def validate_by_key(self, key: str) -> ValidationResult:
        """``POST /licenses/actions/validate-key``. No scope support on this endpoint.

        Sends ``Authorization: License <key>`` using the key being
        validated, unless ``TamgaConfig.default_auth`` was explicitly set to
        something else — auth isn't enforced server-side on this endpoint
        today, but the SDK sends it anyway for forward-compatibility (see
        module docstring).
        """
        auth = self._config.default_auth or LicenseAuth(key)
        response = _client_request(
            self,
            "POST",
            "/licenses/actions/validate-key",
            json={"key": key},
            headers=self._headers(auth_override=auth),
        )
        parsed = parse_response(response)
        meta = _raw_response_meta(response)
        license_data = parsed.data
        return ValidationResult(
            license=self._license_from_data(license_data) if license_data else None,
            meta=_parse_validation_meta(meta),
        )

    def validate_by_id(
        self,
        license_id: UUID,
        scope: LicenseScope | None = None,
        skip_touch: bool = False,
    ) -> ValidationResult:
        """``POST /licenses/{license_id}/actions/validate``.

        ``skip_touch`` (default ``False``) suppresses the
        ``last_validated_at`` side effect — useful for a client polling
        validity without affecting check-in/telemetry timestamps.
        """
        body: dict[str, Any] = {}
        meta: dict[str, Any] = {}
        scope_dict = _scope_to_dict(scope)
        if scope_dict:
            meta["scope"] = scope_dict
        if skip_touch:
            meta["skip_touch"] = skip_touch
        if meta:
            body["meta"] = meta

        response = _client_request(
            self,
            "POST",
            f"/licenses/{license_id}/actions/validate",
            json=body if body else None,
            headers=self._headers(),
        )
        parsed = parse_response(response)
        response_meta = _raw_response_meta(response)
        license_data = parsed.data
        return ValidationResult(
            license=self._license_from_data(license_data) if license_data else None,
            meta=_parse_validation_meta(response_meta),
        )

    def quick_validate(self, license_id: UUID) -> ValidationResult:
        """``GET /licenses/{license_id}/actions/validate``.

        Parses the flat plain-JSON response (no ``data`` envelope) via
        ``tamga.transport.parse_response(..., is_quick_validate=True)``.

        Warning:
            The server **skips** the ``last_validated_at`` write whenever the
            request carries an ``Origin`` header, and the response body is
            byte-identical either way — the caller cannot tell. This SDK never
            sends ``Origin``, but a proxy or middleware that injects one turns
            this call into a pure read with no diagnostic. That matters:
            a license with no machines and a null ``last_validated_at`` reports
            ``INACTIVE``, and the same column is the baseline for check-in
            overdue sweeps. When the write must happen, use
            ``validate_by_id`` (``POST``), which has no ``Origin`` branch.
        """
        data = _send_request(
            self._http,
            self._config,
            "GET",
            f"/licenses/{license_id}/actions/validate",
            is_quick_validate=True,
        )
        return ValidationResult(license=None, meta=_parse_validation_meta(data))

    def get(self, license_id: UUID) -> LicenseResource:
        """``GET /licenses/{license_id}`` — read a license without validating it.

        A pure read: unlike ``validate_by_id`` it touches no timestamp, returns
        no ``meta.valid`` verdict, and tells you nothing about whether the
        license currently passes its policy's checks. Use it to inspect stored
        fields (``status``, ``expiry``, ``machines_count``, ``max_machines``,
        ``metadata``); use ``validate_by_id`` to ask whether the license is
        *valid*.

        Warning:
            **This route is not scoped to the calling credential's own
            license.** The server has a ``require_license_scope`` check that
            confines a license credential to its own license, and applies it to
            exactly five routes — validate, validate-key, quick-validate, and
            both license check-out variants. This is not one of them: it
            authorizes on the ``license.read`` permission and the account
            resolved from the bearer, and nothing further, so a license key that
            authenticates successfully can read every license in the same
            account, including each one's ``attributes.key`` in plain text.
            That is server-side behaviour this SDK cannot fix and does not work
            around; it is documented here so nobody builds a multi-tenant
            assumption on top of it. Reported upstream.

        Args:
            license_id: The license to read.

        Returns:
            The license resource.

        Raises:
            tamga.errors.NotFoundError: If no such license exists in the account.
        """
        data = _send_request(self._http, self._config, "GET", f"/licenses/{license_id}")
        return self._license_from_data(data)

    def get_policy(self, license_id: UUID) -> PolicyResource:
        """``GET /licenses/{license_id}/policy`` — the policy governing this license.

        **This is the SDK's supported way to learn the heartbeat window.**
        ``PolicyResource.effective_heartbeat_window_seconds`` reads
        ``heartbeat_duration`` off the result, and
        ``HeartbeatScheduler.for_policy`` turns it straight into a correctly
        sized ping loop. It is also how to read ``require_check_in`` before
        scheduling check-ins, and ``machine_uniqueness_strategy`` before
        reasoning about a ``409 FINGERPRINT_TAKEN``.

        Prefer this over ``TamgaClient.policies.get``. The two return the same
        resource but authorize differently: this route needs only
        ``license.read``, which a license-key credential holds, while
        ``GET /policies/{policy_id}`` needs ``policy.read``, which it does not —
        so under license-key auth the direct route answers ``403`` and this one
        works.

        Warning:
            Carries the same missing license scoping as ``get``: any license id
            in the account resolves, not just the caller's own.

        Args:
            license_id: The license whose policy to read.

        Returns:
            The policy resource. ``max_memory`` and ``max_disk`` are always
            ``None`` — the server omits both from this response even though it
            enforces them.

        Raises:
            tamga.errors.NotFoundError: If the license, or its policy, does not
                exist in the account.
        """
        data = _send_request(self._http, self._config, "GET", f"/licenses/{license_id}/policy")
        return _parse_policy_resource(data)

    def check_in(self, license_id: UUID) -> LicenseResource:
        """``POST /licenses/{license_id}/actions/check-in``, no body.

        Raises:
            tamga.errors.CheckInNotRequiredError: On ``422
                CHECK_IN_NOT_REQUIRED`` — check ``policy.require_check_in``
                before scheduling periodic check-ins rather than retrying
                through this.
        """
        data = _send_request(
            self._http, self._config, "POST", f"/licenses/{license_id}/actions/check-in"
        )
        return self._license_from_data(data)

    def check_out(
        self,
        license_id: UUID,
        encrypt: bool = False,
        ttl: int | None = None,
        *,
        as_bytes: bool = False,
    ) -> bytes | LicenseFileResource:
        """``GET``/``POST /licenses/{license_id}/actions/check-out``.

        The ``GET`` variant (``as_bytes=True``) returns the raw ``.lic``
        file contents; the ``POST`` variant (default) returns a structured
        ``LicenseFileResource`` (whose ``.certificate`` field holds the
        identical ``.lic`` content, plus ``ttl``/``expiry``/``issued``
        metadata the raw bytes don't carry). ``id``/certificate content is a
        fresh UUIDv7 per call — **not idempotent**, repeat calls yield
        different certificates.

        The returned certificate is format v2 — verify it with
        ``tamga.checkout.license_file.LicenseFile``, which enforces the
        signed ``exp`` claim.

        Note:
            One method with an ``as_bytes`` switch, rather than the two
            separate methods some sibling SDKs expose, is a deliberate
            choice for this SDK's surface.

        Raises:
            tamga.errors.LicenseNotEncryptedError: On ``422
                LICENSE_NOT_ENCRYPTED`` if ``encrypt=True`` but the license
                has no key set.
        """
        params: dict[str, Any] = {"encrypt": str(encrypt).lower()}
        if ttl is not None:
            params["ttl"] = ttl

        if as_bytes:
            headers = self._headers()
            headers["Accept"] = "application/octet-stream"
            response = _client_request(
                self,
                "GET",
                f"/licenses/{license_id}/actions/check-out",
                params=params,
                headers=headers,
            )
            if response.status_code >= 400:
                raise parse_error_envelope(response.status_code, response.content)
            return response.content

        body = {"meta": {"encrypt": encrypt, "ttl": ttl}}
        data = _send_request(
            self._http,
            self._config,
            "POST",
            f"/licenses/{license_id}/actions/check-out",
            json_body=body,
        )
        return _parse_license_file_resource(data)

    def _headers(self, auth_override: AuthTransport | None = None) -> dict[str, str]:
        headers = {
            "Tamga-Version": sanitize_tamga_version(self._config.api_version),
            "Content-Type": "application/vnd.api+json",
        }
        request_params: dict[str, Any] = {}
        auth = auth_override if auth_override is not None else self._config.default_auth
        if auth is not None:
            apply_auth(headers, request_params, auth)
        if self._config.user_agent:
            headers["User-Agent"] = self._config.user_agent
        return headers

    def _license_from_data(self, data: dict[str, Any]) -> LicenseResource:
        fetcher = None
        if self._entitlements is not None:
            license_id = UUID(str(data["id"]))
            fetcher = lambda: self._entitlements.list_all(license_id)  # noqa: E731
        return _parse_license_resource(data, entitlements_fetcher=fetcher)


@dataclass
class MachinesClient:
    """Namespaced client for ``/machines`` endpoints. Access via ``TamgaClient.machines``."""

    _http: httpx.Client
    _config: TamgaConfig

    def create(
        self,
        license_id: UUID,
        fingerprint: str,
        name: str | None = None,
        ip: str | None = None,
        hostname: str | None = None,
        platform: str | None = None,
        cores: int | None = None,
        memory: int | None = None,
        disk: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MachineResource:
        """``POST /machines``.

        Creation **does** enforce the policy's machine/core/memory/disk
        limits, evaluated through its overage strategy: under a strict
        strategy this call fails with a ``422`` before the row exists, while
        under a permissive one it succeeds and the limit only surfaces at
        validation time. Prefer ``activate_machine``, which handles both
        outcomes.

        ``memory`` and ``disk`` are **megabytes**, not bytes. Reporting bytes
        (e.g. ``17179869184`` for 16 GB) inflates the license's running total
        by roughly a million and trips ``MEMORY_LIMIT_EXCEEDED`` /
        ``DISK_LIMIT_EXCEEDED`` on the next activation against the same
        license.

        Note:
            The uniqueness pre-check runs *before* the limit checks, so an
            already-registered fingerprint always yields ``409
            FINGERPRINT_TAKEN`` — never a limit error. How wide "already
            registered" is depends on the policy's machine-uniqueness
            strategy (per license, per policy, or per account).

        Raises:
            tamga.errors.FingerprintTakenError: On ``409 FINGERPRINT_TAKEN``
                for a duplicate fingerprint within the policy's uniqueness
                scope.
            tamga.errors.MachineLimitExceededError: On ``422
                MACHINE_LIMIT_EXCEEDED``.
            tamga.errors.CoreLimitExceededError: On ``422 CORE_LIMIT_EXCEEDED``.
            tamga.errors.MemoryLimitExceededError: On ``422
                MEMORY_LIMIT_EXCEEDED``.
            tamga.errors.DiskLimitExceededError: On ``422 DISK_LIMIT_EXCEEDED``.
        """
        attributes: dict[str, Any] = {"fingerprint": fingerprint}
        if name is not None:
            attributes["name"] = name
        if ip is not None:
            attributes["ip"] = ip
        if hostname is not None:
            attributes["hostname"] = hostname
        if platform is not None:
            attributes["platform"] = platform
        if cores is not None:
            attributes["cores"] = cores
        if memory is not None:
            attributes["memory"] = memory
        if disk is not None:
            attributes["disk"] = disk
        if metadata is not None:
            attributes["metadata"] = metadata

        body = {
            "data": {
                "type": "machines",
                "attributes": attributes,
                "relationships": {"license": {"data": {"type": "licenses", "id": str(license_id)}}},
            }
        }
        data = _send_request(self._http, self._config, "POST", "/machines", json_body=body)
        return _parse_machine_resource(data)

    def delete(self, machine_id: UUID) -> None:
        """Standard resource deletion. Used by ``activate_machine``'s rollback path."""
        _send_request(self._http, self._config, "DELETE", f"/machines/{machine_id}")

    def get(self, machine_id: UUID) -> MachineResource:
        """``GET /machines/{machine_id}`` — read a machine without writing to it.

        This is the one plain-JSON route on this SDK's surface that reports a
        machine's **true** heartbeat state. The status is derived from
        ``last_heartbeat_at`` against the policy's window, and this query joins
        the policy, so both ``heartbeat_status`` and ``next_heartbeat_at`` are
        computed against the real window rather than the 600s fallback.

        Contrast the write routes. ``ping_heartbeat`` sets
        ``last_heartbeat_at = NOW()`` and then derives the status from that same
        timestamp, so it can only ever answer ``ALIVE`` or ``RESURRECTED``;
        ``reset_heartbeat`` nulls the column (``NOT_STARTED``); ``create`` never
        sets it (``NOT_STARTED``). A ``DEAD`` reading is therefore reachable
        here and from ``check_out``, and from nowhere else this SDK calls.

        ``DEAD`` still does not mean the row was culled — it means only that the
        last ping is older than the window. Culling is gated on the policy's
        ``require_heartbeat``, which defaults to ``False``, so under a default
        policy the row and its seat survive indefinitely and the next ping
        revives the machine. The only signal that the row is genuinely gone is a
        ``404`` from the ping itself.

        Warning:
            Not scoped to the calling credential's license. No machine route
            applies the server's ``require_license_scope`` check, and a license
            token's default permissions include ``machine.read``, so any machine
            id in the account resolves here.

        Args:
            machine_id: The machine to read.

        Returns:
            The machine resource.

        Raises:
            tamga.errors.NotFoundError: If no such machine exists in the account.
        """
        data = _send_request(self._http, self._config, "GET", f"/machines/{machine_id}")
        return _parse_machine_resource(data)

    def list(
        self,
        *,
        page_number: int = 1,
        page_size: int | None = None,
        search: str | None = None,
        license_id: UUID | None = None,
        platform: str | None = None,
    ) -> OffsetPage[MachineResource]:
        """``GET /machines`` — **offset**-paginated, unlike every other list here.

        This route answers with ``meta.page{number,size,total,totalPages}`` and
        addresses pages by number. It is the only route on this SDK's surface
        that does; ``components``, ``processes`` and ``entitlements`` are keyset
        routes returning ``Page``. Passing ``page[after]`` here is accepted and
        ignored, and so is passing a page number to a keyset route — which is
        exactly why the two return different types rather than one type with
        both sets of fields half-populated.

        There is deliberately no ``list_all`` companion. Walk pages with
        ``OffsetPage.has_next_page`` and a bounded loop; see
        ``find_by_fingerprint`` for the shape.

        Args:
            page_number: 1-based page to fetch. The server floors anything below
                1 and bounds the resulting offset, so a page far past the end
                returns an empty page rather than an error.
            page_size: Rows per page, clamped server-side to 1..100. Defaults to
                the maximum. The server's own default of 25 is applied silently
                when the parameter is absent, so the SDK always sends one — but
                note the reason differs from the keyset routes: here ``total``
                makes truncation visible either way, so this is about
                predictability rather than about detecting a short page.
            search: Free-text term, sent as ``filter[q]``. **A case-insensitive
                substring match across ``name``, ``hostname`` *and*
                ``fingerprint``**, not an exact match on any of them, and the
                term is truncated to 200 characters server-side. Treat the
                result as a superset to filter locally — see
                ``find_by_fingerprint``.
            license_id: Restrict to machines on one license, sent as
                ``filter[license]``. Note the machine resource carries no
                license id of its own, so this filter is the *only* way to tie
                a listed machine to a license.
            platform: Restrict to one platform string, sent as
                ``filter[platform]``.

        Returns:
            One page of machines plus the server's own page metadata.
        """
        effective_size = page_size if page_size is not None else MAX_PAGE_SIZE
        params: dict[str, Any] = {
            "page[number]": page_number,
            "page[size]": effective_size,
        }
        if search is not None:
            params["filter[q]"] = search
        if license_id is not None:
            params["filter[license]"] = str(license_id)
        if platform is not None:
            params["filter[platform]"] = platform

        data, meta = _send_request_with_meta(
            self._http, self._config, "GET", "/machines", params=params
        )
        number, size, total, total_pages = _parse_page_meta(meta)
        return OffsetPage(
            items=[_parse_machine_resource(d) for d in (data or [])],
            page_number=number,
            page_size=size,
            total=total,
            total_pages=total_pages,
        )

    def update(
        self,
        machine_id: UUID,
        *,
        name: str | None = None,
        ip: str | None = None,
        hostname: str | None = None,
        platform: str | None = None,
        cores: int | None = None,
        memory: int | None = None,
        disk: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MachineResource:
        """``PATCH /machines/{machine_id}`` — update mutable machine attributes.

        Every field is optional and **omitted fields are left untouched**: the
        server applies each one through ``COALESCE(new, existing)``. The
        corollary is that ``None`` means "leave alone", not "clear" — there is
        no way through this route to null out a column that already has a value.

        ``fingerprint`` is not updatable, by design: it is the identity the
        uniqueness scope and every activation check are keyed on.

        ``memory`` and ``disk`` are **megabytes**, the same unit as ``create``,
        and they feed the same license-wide totals that create-time and
        validate-time limit checks compare against.

        Warning:
            Not scoped to the calling credential's license, and this one
            **writes**. No machine route applies the server's
            ``require_license_scope`` check, and a license token's default
            permissions include ``machine.update``, so a license key can patch
            any machine in the account — not only the ones on its own license.
            Reported upstream.

        Note:
            The response's ``heartbeat_status`` and ``next_heartbeat_at`` are
            computed against the **600s fallback**, not the policy's window:
            this route's ``UPDATE ... RETURNING`` does not join ``policies``.
            The status can still read ``DEAD`` here (unlike on a ping, since
            this write does not touch ``last_heartbeat_at``) — but judged
            against the wrong window whenever the policy sets a different one.
            Read the machine back with ``get`` if either field matters.

        Args:
            machine_id: The machine to update.
            name: New display name.
            ip: New IP address.
            hostname: New hostname.
            platform: New platform string.
            cores: New core count.
            memory: New memory, in **megabytes**.
            disk: New disk, in **megabytes**.
            metadata: Replacement metadata object. Replaces the stored object
                wholesale rather than merging into it.

        Returns:
            The updated machine resource.

        Raises:
            tamga.errors.NotFoundError: If no such machine exists in the account.
            tamga.errors.ForbiddenError: If the credential's role may not update
                machines.
        """
        attributes: dict[str, Any] = {}
        if name is not None:
            attributes["name"] = name
        if ip is not None:
            attributes["ip"] = ip
        if hostname is not None:
            attributes["hostname"] = hostname
        if platform is not None:
            attributes["platform"] = platform
        if cores is not None:
            attributes["cores"] = cores
        if memory is not None:
            attributes["memory"] = memory
        if disk is not None:
            attributes["disk"] = disk
        if metadata is not None:
            attributes["metadata"] = metadata

        body = {"data": {"type": "machines", "attributes": attributes}}
        data = _send_request(
            self._http, self._config, "PATCH", f"/machines/{machine_id}", json_body=body
        )
        return _parse_machine_resource(data)

    def activate_machine(self, license_id: UUID, fingerprint: str, **attrs: Any) -> MachineResource:
        """Create a machine, then validate the license, rolling back on over-limit.

        A limit can stop the activation at either of two points, and both are
        handled here:

        1. **At creation.** The server checks machines/cores/memory/disk
           before inserting the row and answers ``422``
           ``MACHINE_LIMIT_EXCEEDED`` / ``CORE_LIMIT_EXCEEDED`` /
           ``MEMORY_LIMIT_EXCEEDED`` / ``DISK_LIMIT_EXCEEDED``. No row was
           created, so there is nothing to roll back — this method normalizes
           the code to its ``ValidationCode`` equivalent
           (``TOO_MANY_MACHINES`` / ``TOO_MANY_CORES`` / ``TOO_MUCH_MEMORY`` /
           ``TOO_MUCH_DISK``) and raises
           ``tamga.errors.MachineOverLimitError`` with ``rolled_back=False``,
           without issuing a ``DELETE``.
        2. **At validation.** The create-time check runs through the policy's
           overage strategy, so under a permissive strategy creation succeeds
           and the same limit only surfaces in the validate response's
           ``meta.code``. The just-created machine is then deleted before
           raising ``MachineOverLimitError`` with ``rolled_back=True``,
           because the row does exist and would otherwise hold a seat.

        Args:
            license_id: The license to activate the machine against.
            fingerprint: The machine's unique fingerprint.
            **attrs: Additional optional machine attributes (``name``,
                ``ip``, ``hostname``, ``platform``, ``cores``, ``memory``,
                ``disk``, ``metadata``). ``memory``/``disk`` are in
                **megabytes** — see ``create``.

        Returns:
            The created (and license-validated) ``MachineResource``.

        Raises:
            tamga.errors.MachineOverLimitError: If either limit path above
                rejects the activation. Read ``validation_code`` for which
                limit was hit and ``rolled_back`` for which path produced it
                (``False`` = refused at creation, nothing existed to delete;
                ``True`` = created under a permissive overage strategy, then
                deleted). It subclasses both ``TamgaError`` and ``ValueError``,
                so handlers written against either still catch it.
            tamga.errors.FingerprintTakenError: If the fingerprint is already
                registered within the policy's uniqueness scope. This method
                does not recover from that; ``activate_machine_idempotent``
                does, by looking the existing machine back up.
        """
        try:
            machine = self.create(license_id, fingerprint, **attrs)
        except TamgaError as exc:
            equivalent = _CREATE_LIMIT_CODE_TO_VALIDATION_CODE.get(exc.code)
            if equivalent is None:
                raise
            # Creation was refused, so no row exists: rolling back here would
            # DELETE a machine id we never received (or, worse, someone
            # else's). Raise the same type as the validate-time path so
            # callers keep one branch for "over limit"; `rolled_back` tells
            # the two apart.
            raise MachineOverLimitError(
                status=exc.status,
                code=exc.code,
                detail=(
                    f"machine activation rejected: creation returned {exc.code} "
                    f"({equivalent.value}) — no machine was created, nothing to roll back"
                ),
                validation_code=equivalent,
                rolled_back=False,
                pointer=exc.pointer,
            ) from exc

        licenses = LicensesClient(_http=self._http, _config=self._config)
        result = licenses.validate_by_id(license_id)

        over_limit_codes = {
            ValidationCode.TOO_MANY_MACHINES,
            ValidationCode.TOO_MANY_CORES,
            ValidationCode.TOO_MUCH_MEMORY,
            ValidationCode.TOO_MUCH_DISK,
            ValidationCode.TOO_MANY_PROCESSES,
        }
        if result.meta.code in over_limit_codes:
            self.delete(machine.id)
            # `status=200`: validation reports an over-limit license inside a
            # *successful* response, not an error envelope, so there is no
            # error status to carry. `code` is that response's `meta.code`.
            raise MachineOverLimitError(
                status=200,
                code=result.meta.code.value,
                detail=(
                    f"machine activation rejected: license validation returned "
                    f"{result.meta.code.value} — the created machine has been rolled back"
                ),
                validation_code=result.meta.code,
                rolled_back=True,
            )
        return machine

    def find_by_fingerprint(
        self,
        fingerprint: str,
        *,
        license_id: UUID,
        max_pages: int = MAX_MACHINE_SEARCH_PAGES,
    ) -> MachineResource | None:
        """Find a machine already registered to ``license_id`` by exact fingerprint.

        There is **no exact fingerprint filter server-side.** The nearest thing
        is the free-text ``filter[q]`` term, which is a case-insensitive
        substring match over ``name``, ``hostname`` and ``fingerprint``, and
        which the server truncates to 200 characters. So this method uses the
        search only to narrow the candidate set and then compares
        ``machine.fingerprint`` exactly in Python. Both approximations run in
        the safe direction — a truncated term matches a *superset*, and a
        substring hit is discarded unless it is also an exact match — so the
        result is never a machine with a different fingerprint.

        The scan is bounded three independent ways: by ``max_pages``, by the
        server's own ``meta.page.totalPages``, and by an empty page. The loop is
        a ``range`` rather than a ``while``, so even page metadata that never
        terminates cannot make it spin. That is deliberate belt-and-braces: this
        SDK previously shipped a list helper that looped forever against a route
        whose cursor turned out to be inert, growing its result list until the
        process ran out of memory.

        **``license_id`` is required, and that is a correctness constraint rather
        than caution.** A machine resource carries no license id and no
        relationships, so the only thing tying a listed machine to a license is
        this filter — an unscoped search returns rows the caller cannot attribute
        and must not act on. See ``activate_machine_idempotent`` for why handing
        one back would be actively wrong. A deliberate account-wide search is
        still possible through ``list(search=...)``, where it is explicit.

        Scoping costs nothing in recall for the case this exists to serve. All
        three machine-uniqueness strategies include the caller's own license in
        their duplicate check — ``UNIQUE_PER_LICENSE`` matches it exactly,
        ``UNIQUE_PER_POLICY`` joins on the policy that license already belongs
        to, and ``UNIQUE_PER_ACCOUNT`` covers everything — so a genuine
        re-activation of the same license and fingerprint is found here under
        every strategy.

        Args:
            fingerprint: The exact fingerprint to find. Must not be blank —
                a blank term is *ignored* by the server rather than matching
                nothing, which would widen the search rather than narrow it.
            license_id: The license to search within, sent as
                ``filter[license]``. Required; see above.
            max_pages: Hard ceiling on pages walked. Each page holds up to 100
                machines.

        Returns:
            The matching machine, or ``None`` if the scan completed without an
            exact match on this license.

        Raises:
            ValueError: If ``fingerprint`` is empty or whitespace-only.
        """
        if not fingerprint.strip():
            raise ValueError(
                "fingerprint must be a non-empty string — the server ignores a blank "
                "search term, which would widen this search to the whole license "
                "instead of matching none"
            )
        for page_number in range(1, max_pages + 1):
            page = self.list(
                page_number=page_number,
                page_size=MAX_PAGE_SIZE,
                search=fingerprint,
                license_id=license_id,
            )
            for machine in page.items:
                if machine.fingerprint == fingerprint:
                    return machine
            if not page.items or not page.has_next_page:
                return None
        return None

    def activate_machine_idempotent(
        self, license_id: UUID, fingerprint: str, **attrs: Any
    ) -> MachineResource:
        """``activate_machine``, but a re-activation returns the existing machine.

        The server reports a repeat activation as ``409 FINGERPRINT_TAKEN``
        rather than returning the row, and that is intentional on its side: its
        own comment reads "already activated, carry on". Getting from there back
        to the machine's id needs a second lookup, which is what this adds.

        1. Try ``activate_machine`` — create, validate, roll back on an
           over-limit verdict. Anything it returns or raises other than
           ``FingerprintTakenError`` passes straight through, including
           ``MachineOverLimitError``.
        2. On ``FingerprintTakenError``, look the machine up by exact
           fingerprint **within this license** and return it.
        3. If the lookup finds nothing, re-raise the conflict — with the
           original chained onto it — because there is nothing truthful to
           return.

        **Step 3 is the interesting one, and the scoping in step 2 is
        deliberate.** A machine on this license with this fingerprint trips the
        conflict under all three uniqueness strategies:
        ``UNIQUE_PER_LICENSE`` checks this license's rows exactly,
        ``UNIQUE_PER_POLICY`` joins licenses on the policy this one already
        belongs to, and ``UNIQUE_PER_ACCOUNT`` covers the account. So a genuine
        re-activation is always recoverable here. The only way the lookup comes
        back empty is that the conflict came from *another* license under one of
        the two wider scopes — and that machine must not be returned.

        Returning it would hand the caller a machine this license does not own,
        which it would then heartbeat and check out while this license's
        ``machines_count`` stayed at zero: exactly the seat-sharing the wider
        uniqueness scopes exist to prevent, per the server's own note that "a
        customer could register one fingerprint against N licenses and share
        seats". The caller could not even detect it, since the machine resource
        carries no license id. The conflict is the honest answer, so the
        conflict is what is raised.

        (An empty lookup can also mean the credential lacks ``machine.read``, or
        that the row was deleted between the two calls. All three cases are
        reported the same way, because all three leave this method with no
        machine it can honestly return.)

        **The recovery path deliberately does not validate the license.**
        ``activate_machine`` deletes the machine it just created when validation
        comes back over-limit; applying that here would delete a pre-existing
        machine this call did not create — destroying a seat the caller never
        asked to touch. Validate separately with
        ``TamgaClient.licenses.validate_by_id`` if the verdict matters, and
        decide for yourself what to do with it.

        Args:
            license_id: The license to activate the machine against.
            fingerprint: The machine's unique fingerprint.
            **attrs: Additional optional machine attributes, as
                ``activate_machine``. They are **not** applied to a machine
                recovered on the conflict path — that row already exists with
                whatever attributes it was created with. Use ``update`` if they
                need to be brought into line.

        Returns:
            The newly created machine, or the existing one that caused the
            conflict.

        Raises:
            tamga.errors.FingerprintTakenError: If no machine with this
                fingerprint exists on this license — most often because the
                conflict came from another license under a wider uniqueness
                scope, which is a rejection to respect rather than recover from.
            tamga.errors.MachineOverLimitError: As ``activate_machine``, on the
                creation path only.
        """
        try:
            return self.activate_machine(license_id, fingerprint, **attrs)
        except FingerprintTakenError as conflict:
            existing = self.find_by_fingerprint(fingerprint, license_id=license_id)
            if existing is not None:
                return existing
            raise FingerprintTakenError(
                status=conflict.status,
                code=conflict.code,
                detail=(
                    f"{conflict.detail} — and no machine with this fingerprint is "
                    f"registered to this license, so the conflict came from another "
                    f"license under a wider machine-uniqueness scope. That machine is "
                    f"deliberately not returned: this license does not own it, and "
                    f"using it would consume a seat the license never paid for"
                ),
                pointer=conflict.pointer,
            ) from conflict

    def ping_heartbeat(self, machine_id: UUID) -> MachineResource:
        """``POST /machines/{id}/actions/ping-heartbeat``, no body. Sets ``last_heartbeat_at``.

        A bare, unconditional ``UPDATE`` server-side, with no liveness
        precondition: it revives a machine whose window had long since lapsed
        just as readily as it refreshes a live one, and it is safe to repeat
        (it is retried after a ``429``; see ``_is_retryable``). The only
        response that means the row is really gone is ``404`` —
        ``tamga.errors.NotFoundError`` — which is the signal to re-activate.

        Warning:
            **Do not branch on the returned ``heartbeat_status``.** The server
            derives it from the very ``last_heartbeat_at`` this call just set
            to ``NOW()``, so the computed age is ~0 and the answer is always
            ``ALIVE`` or ``RESURRECTED``. A ping can never report ``DEAD`` —
            not because ``DEAD`` is unreachable in general, but because this
            route's own write rules it out. To read a machine's true heartbeat
            state, check out a machine file: ``check_out`` resolves the row
            without writing to it, and the status it embeds can be ``DEAD``
            (see ``HeartbeatStatus``).

        Note:
            The ``next_heartbeat_at`` on this response is computed without
            joining the policy, so it is not a trustworthy source for a ping
            schedule. Size the interval from the policy's
            ``heartbeat_duration`` instead.
        """
        data = _send_request(
            self._http, self._config, "POST", f"/machines/{machine_id}/actions/ping-heartbeat"
        )
        return _parse_machine_resource(data)

    def reset_heartbeat(self, machine_id: UUID) -> MachineResource:
        """``POST /machines/{id}/actions/reset-heartbeat``, no body. Rewinds to ``NOT_STARTED``.

        Warning:
            **Always ``403`` under license-key auth.** This route is gated on
            the caller's *role* (admin / developer / product token /
            environment token), not merely on a permission, and a license-key
            credential holds none of them — unlike ``ping_heartbeat``, which is
            permission-only and works. Server-side this is the only way to
            unstick a machine with a wedged heartbeat job, so an embedded
            license-key client cannot perform that recovery at all; it needs a
            privileged token.
        """
        data = _send_request(
            self._http, self._config, "POST", f"/machines/{machine_id}/actions/reset-heartbeat"
        )
        return _parse_machine_resource(data)

    def check_out(
        self,
        machine_id: UUID,
        encrypt: bool = False,
        ttl: int | None = None,
        *,
        as_bytes: bool = False,
    ) -> bytes | MachineFileResource:
        """``GET``/``POST /machines/{id}/actions/check-out``.

        Client-side ``ttl`` pre-check mirrors server validation (``> 0`` and
        ``<= 31536000``) before sending, though the server remains
        authoritative and still returns ``422 TTL_INVALID`` on violation.

        Note:
            Same ``as_bytes`` switch as ``LicensesClient.check_out``. Unlike
            license files, machine-file ``alg`` values carry no ``+v2``
            suffix — verify them with
            ``tamga.checkout.machine_file.MachineFile``, passing the
            license's own ``scheme``.

        Raises:
            tamga.errors.TtlInvalidError: If ``ttl`` fails the client-side
                pre-check (or the server rejects it anyway).
        """
        if ttl is not None and not (0 < ttl <= MAX_CHECKOUT_TTL_SECONDS):
            raise TtlInvalidError(
                status=422,
                code="TTL_INVALID",
                detail=f"ttl must be > 0 and <= {MAX_CHECKOUT_TTL_SECONDS}, got {ttl}",
            )

        params: dict[str, Any] = {"encrypt": str(encrypt).lower()}
        if ttl is not None:
            params["ttl"] = ttl

        if as_bytes:
            headers: dict[str, str] = {
                "Tamga-Version": sanitize_tamga_version(self._config.api_version),
                "Accept": "application/octet-stream",
            }
            request_params: dict[str, Any] = dict(params)
            if self._config.default_auth is not None:
                apply_auth(headers, request_params, self._config.default_auth)

            response = _client_request(
                self,
                "GET",
                f"/machines/{machine_id}/actions/check-out",
                params=request_params,
                headers=headers,
            )
            if response.status_code >= 400:
                raise parse_error_envelope(response.status_code, response.content)
            return response.content

        body = {"meta": {"encrypt": encrypt, "ttl": ttl}}
        data = _send_request(
            self._http,
            self._config,
            "POST",
            f"/machines/{machine_id}/actions/check-out",
            json_body=body,
        )
        attrs = data.get("attributes", {})
        return MachineFileResource(
            certificate=attrs.get("certificate", ""),
            algorithm=attrs.get("algorithm", ""),
            includes=attrs.get("includes", []),
            ttl=attrs.get("ttl"),
            expiry=attrs.get("expiry"),
            issued=attrs.get("issued", ""),
        )

    def generate_offline_proof(
        self, machine_id: UUID, dataset: dict[str, Any] | None = None
    ) -> Any:
        """``POST /machines/{id}/actions/generate-offline-proof``.

        Always signed with RSA-2048 PKCS#1 v1.5 / SHA-256 server-side,
        regardless of the license's ``scheme``. Returns a
        ``tamga.proof.ProofResult``.

        Warning:
            **Always ``403`` under license-key auth**, same role gate as
            ``reset_heartbeat`` — the license-key credential holds the
            ``machine.proofs.generate`` permission but not an accepted role.
            Generate proofs with a privileged token.
        """
        body = {"meta": {"dataset": dataset or {}}}
        response = _client_request(
            self,
            "POST",
            f"/machines/{machine_id}/actions/generate-offline-proof",
            json=body,
            headers=self._json_headers(),
        )
        parsed = parse_response(response)
        meta = _raw_response_meta(response)
        machine = _parse_machine_resource(parsed.data)
        proof_raw = meta.get("proof", "")

        return ProofResult.parse(
            proof_raw,
            account_id=UUID(str(self._config.account_id)),
            machine_id=machine.id,
            fingerprint=machine.fingerprint,
            dataset=dataset or {},
        )

    def _json_headers(self) -> dict[str, str]:
        headers = {
            "Tamga-Version": sanitize_tamga_version(self._config.api_version),
            "Content-Type": "application/vnd.api+json",
        }
        request_params: dict[str, Any] = {}
        if self._config.default_auth is not None:
            apply_auth(headers, request_params, self._config.default_auth)
        return headers


@dataclass
class ComponentsClient:
    """Namespaced client for ``/components`` endpoints. Access via ``TamgaClient.components``."""

    _http: httpx.Client
    _config: TamgaConfig

    def create(
        self,
        machine_id: UUID,
        fingerprint: str,
        name: str,
        metadata: dict[str, Any] | None = None,
    ) -> ComponentResource:
        """``POST /components`` — **flat request body, not a JSON:API envelope**.

        The handler deserializes into a plain struct
        (``CreateComponentBody { machine_id, fingerprint, name, metadata }``),
        so the fields go at the top level::

            {"machine_id": "...", "fingerprint": "...", "name": "...", "metadata": {}}

        Note:
            **The response is still enveloped**, and the asymmetry is real
            server behaviour rather than an inconsistency to smooth over. The
            request is flat; the reply is ``{"data": {"id", "type",
            "attributes"}}`` and is parsed as such. Nor can the request shape be
            inferred from a sibling endpoint: ``POST /machines`` and
            ``PATCH /machines/{id}`` genuinely do take an envelope. It is a
            per-endpoint fact, and the only reliable way to know is the
            handler's own body struct.

            This SDK previously sent the envelope here. Every call failed
            deserialization on the three required fields — ``machine_id``,
            ``fingerprint`` and ``name`` carry no ``serde`` default — so the
            server answered ``422`` and no component could be created at all.

        Args:
            machine_id: The machine this component belongs to.
            fingerprint: Component fingerprint, unique per
                ``(account_id, machine_id, fingerprint)``.
            name: Required display name.
            metadata: Optional metadata. Omitted from the body when ``None``;
                the server defaults the column rather than rejecting the
                request.

        Returns:
            The created component.

        Raises:
            tamga.errors.FingerprintTakenError: On ``409 FINGERPRINT_TAKEN``
                for a duplicate ``(account_id, machine_id, fingerprint)``.
            tamga.errors.NotFoundError: If the machine does not exist in the
                account — the handler resolves it before inserting.
        """
        body: dict[str, Any] = {
            "machine_id": str(machine_id),
            "fingerprint": fingerprint,
            "name": name,
        }
        if metadata is not None:
            body["metadata"] = metadata
        data = _send_request(self._http, self._config, "POST", "/components", json_body=body)
        return _parse_component_resource(data)

    def list(
        self, machine_id: UUID, limit: int | None = None, after: str | None = None
    ) -> Page[ComponentResource]:
        """``GET /machines/{id}/components``, keyset-paginated (``limit``/``page[after]``).

        This is the one list route where ``page[after]`` really works, so a
        caller can page through it to completion.

        When ``limit`` is omitted the SDK sends the server maximum (100)
        explicitly rather than letting the server apply its own default of 25.
        Without a known page size there is no way to tell a full page from the
        last one, so an omitted ``limit`` used to return ``next_after=None``
        after 25 rows and silently look complete.
        """
        effective_limit = limit if limit is not None else MAX_PAGE_SIZE
        params: dict[str, Any] = {"limit": effective_limit}
        if after is not None:
            params["page[after]"] = after
        response = _send_request_raw(
            self._http,
            self._config,
            "GET",
            f"/machines/{machine_id}/components",
            params=params,
        )
        items = [_parse_component_resource(d) for d in (response.data or [])]
        return Page(items=items, next_after=_next_after_cursor(items, effective_limit))


@dataclass
class ProcessesClient:
    """Namespaced client for ``/processes`` endpoints. Access via ``TamgaClient.processes``."""

    _http: httpx.Client
    _config: TamgaConfig

    def create(
        self, machine_id: UUID, pid: str, metadata: dict[str, Any] | None = None
    ) -> ProcessResource:
        """``POST /processes`` — **flat request body, not a JSON:API envelope**.

        The handler deserializes into a plain struct
        (``CreateProcessBody { machine_id, pid, metadata }``), so the fields go
        at the top level::

            {"machine_id": "...", "pid": "4242", "metadata": {}}

        ``pid`` must be a ``str`` on the wire — reject non-string input at
        this boundary rather than silently ``str()``-coercing it, so callers
        don't accidentally build the wrong wire type upstream.

        Note:
            **The response is still enveloped**, same asymmetry as
            ``ComponentsClient.create``, and same reason it cannot be inferred
            from ``POST /machines``, which really does take an envelope.

            This SDK previously sent the envelope here. ``machine_id`` and
            ``pid`` carry no ``serde`` default, so every call failed
            deserialization and the server answered ``422``.

        Args:
            machine_id: The machine this process belongs to.
            pid: Process ID, as a **string**.
            metadata: Optional metadata. Omitted from the body when ``None``.

        Returns:
            The created process.

        Raises:
            TypeError: If ``pid`` is not a ``str`` (e.g. an ``int`` was passed).
            tamga.errors.PidTakenError: On ``409 PID_TAKEN`` for a duplicate
                PID on this machine.
            tamga.errors.TooManyProcessesError: On ``422 TOO_MANY_PROCESSES``
                if the license is at its process limit.
        """
        if not isinstance(pid, str):
            raise TypeError(f"pid must be a str, got {type(pid).__name__}: {pid!r}")

        body: dict[str, Any] = {"machine_id": str(machine_id), "pid": pid}
        if metadata is not None:
            body["metadata"] = metadata
        data = _send_request(self._http, self._config, "POST", "/processes", json_body=body)
        return _parse_process_resource(data)

    def ping(self, process_id: UUID) -> ProcessResource:
        """``POST /processes/{id}/actions/ping``, no body."""
        data = _send_request(
            self._http, self._config, "POST", f"/processes/{process_id}/actions/ping"
        )
        return _parse_process_resource(data)

    def delete(self, process_id: UUID) -> None:
        """``DELETE /processes/{process_id}`` — remove a process row. ``204``, no body.

        **Nothing on the server deletes these rows for you.** A 30s process
        heartbeat window exists and a process reaper was written, but no
        scheduled job runs it, so a crashed or exited process keeps its row —
        and with it its slot against the policy's ``max_processes`` — forever.
        The count only ever grows, and a long-lived install eventually
        activates into ``TOO_MANY_PROCESSES`` for processes that stopped
        running months earlier.

        So this is not an optional tidy-up: an application that creates
        processes has to delete them, and the natural place is wherever it
        already tears the process down. ``ProcessHeartbeatScheduler.dispose``
        pairs stopping the ping loop with this call for exactly that reason.

        Args:
            process_id: The process row to delete.

        Raises:
            tamga.errors.NotFoundError: If the row does not exist — including
                when it was already deleted. ``dispose`` tolerates that;
                this method does not, because a caller deleting a specific id
                usually wants to know it was not there.
        """
        _send_request(self._http, self._config, "DELETE", f"/processes/{process_id}")

    def list(
        self, machine_id: UUID, limit: int | None = None, after: str | None = None
    ) -> Page[ProcessResource]:
        """``GET /machines/{id}/processes``, keyset-paginated (``limit``/``page[after]``).

        Keyset paging genuinely works here — the cursor reaches the query and
        narrows it — so unlike ``EntitlementsClient.list`` this page really can
        be followed to completion by feeding ``next_after`` back as ``after``.
        Note that puts it on the opposite pagination scheme from
        ``MachinesClient.list``, which is offset-based and returns an
        ``OffsetPage``.

        As with ``ComponentsClient.list``, an omitted ``limit`` sends the server
        maximum (100) rather than letting the server apply its own default of
        25: the next-page cursor is synthesized from ``len(items) == limit``, so
        without a known page size a truncated page is indistinguishable from the
        last one.

        Args:
            machine_id: The machine whose processes to list.
            limit: Page size, clamped server-side to 1..100.
            after: Cursor from a previous page's ``next_after``.

        Returns:
            One page of processes, with a synthesized ``next_after``.
        """
        effective_limit = limit if limit is not None else MAX_PAGE_SIZE
        params: dict[str, Any] = {"limit": effective_limit}
        if after is not None:
            params["page[after]"] = after
        response = _send_request_raw(
            self._http,
            self._config,
            "GET",
            f"/machines/{machine_id}/processes",
            params=params,
        )
        items = [_parse_process_resource(d) for d in (response.data or [])]
        return Page(items=items, next_after=_next_after_cursor(items, effective_limit))


@dataclass
class EntitlementsClient:
    """Namespaced client for ``/entitlements`` endpoints. Access via ``TamgaClient.entitlements``."""  # noqa: E501

    _http: httpx.Client
    _config: TamgaConfig

    def list(
        self, license_id: UUID, limit: int | None = None, after: str | None = None
    ) -> Page[Entitlement]:
        """``GET /licenses/{license_id}/entitlements`` — not paginable.

        The listing is a union of the license's direct entitlements and the
        ones inherited from its policy, so the server dropped keyset paging on
        this route: ``page[after]`` is accepted for wire compatibility and then
        **ignored**, and ``limit`` (max 100) is the only thing bounding the
        response.

        Consequences a caller has to live with:

        - ``Page.next_after`` is always ``None`` here. It cannot be anything
          else: every "next page" would repeat the first one verbatim.
        - A license with more than 100 effective entitlements **cannot be
          enumerated in full** through this endpoint, so a negative
          ``has_entitlement`` answer is only authoritative below that ceiling.
        - ``after`` is retained on the signature (removing it would break
          callers) but is not sent.

        Each item carries ``Entitlement.inherited``: ``True`` when the license
        holds it through its policy rather than directly. Inherited
        entitlements cannot be detached, and ``get()`` returns ``404`` for
        them — see ``get``.
        """
        params: dict[str, Any] = {"limit": limit if limit is not None else MAX_PAGE_SIZE}
        response = _send_request_raw(
            self._http,
            self._config,
            "GET",
            f"/licenses/{license_id}/entitlements",
            params=params,
        )
        items = [_parse_entitlement(d) for d in (response.data or [])]
        return Page(items=items, next_after=None)

    def get(self, license_id: UUID, entitlement_id: UUID) -> Entitlement:
        """``GET /licenses/{license_id}/entitlements/{entitlement_id}``.

        Despite the URL shape, returns a full ``Entitlement`` resource, not
        a lightweight junction record.

        Warning:
            Resolves **direct attachments only**. This route queries the
            license-entitlement join table alone, so an entitlement that
            ``list()`` returned with ``inherited=True`` raises
            ``tamga.errors.NotFoundError`` here. List-then-get-each is not a
            valid pattern against this resource; read the fields off the list
            response instead.
        """
        data = _send_request(
            self._http,
            self._config,
            "GET",
            f"/licenses/{license_id}/entitlements/{entitlement_id}",
        )
        return _parse_entitlement(data)

    def list_all(self, license_id: UUID) -> builtins.list[Entitlement]:
        """Fetch this license's entitlements — a single request, capped at 100.

        Internal helper backing ``LicenseResource.refresh_entitlements()``'s
        fetcher.

        This used to loop on ``page[after]`` until it saw a short page. The
        server ignores ``page[after]`` on this route (see ``list``), so a
        license with 100 or more effective entitlements returned the identical
        full page forever: an unbounded loop that never terminated and grew
        ``items`` until the process ran out of memory. There is no cursor to
        follow, so there is no loop.

        Warning:
            Truncates silently at 100 effective entitlements — the server
            offers no way to read past that on this route, and exposes no total
            count to detect it with.

        Note:
            Return type is spelled ``builtins.list[Entitlement]`` rather
            than the bare ``list[Entitlement]`` used elsewhere in this file
            — inside this class, the sibling method named ``list`` shadows
            the builtin ``list`` name for mypy's postponed-annotation
            resolution (``from __future__ import annotations``), so a bare
            ``list[Entitlement]`` here resolves to "the ``list`` method used
            as a type" instead of the builtin generic.
        """
        return self.list(license_id, limit=MAX_PAGE_SIZE).items


def _next_after_cursor(items: list[Any], limit: int | None) -> str | None:
    """Compute the keyset-pagination cursor for the next page, if any.

    No ``links``/cursor metadata is exposed by the server today beyond the
    page contents themselves. Rather than always returning a cursor (which
    would force every caller — including ``EntitlementsClient.list_all`` —
    into an extra round trip just to confirm an empty trailing page), this
    uses the standard keyset-pagination heuristic: a full page (``len(items)
    == limit``) might have more after it; a short page (``len(items) <
    limit``, including empty) is the last page. When no ``limit`` was
    supplied, there is no way to detect a "full" page, so this always
    returns ``None`` (i.e. treats the single unpaginated call as complete).
    Callers inside this module never hit that branch any more: they pass the
    page size they actually sent, defaulting to ``MAX_PAGE_SIZE``, precisely so
    a truncated page is detectable.
    """
    if not items or limit is None or len(items) < limit:
        return None
    last = items[-1]
    return str(last.id)


@dataclass
class PoliciesClient:
    """Namespaced client for ``/policies`` endpoints. Access via ``TamgaClient.policies``."""

    _http: httpx.Client
    _config: TamgaConfig

    def get(self, policy_id: UUID) -> PolicyResource:
        """``GET /policies/{policy_id}``.

        Warning:
            **Answers ``403`` under license-key auth.** This route authorizes on
            the ``policy.read`` permission, which is not among the permissions a
            license credential is granted — unlike ``license.read``, which is.
            An embedded client authenticating with a license key must read the
            policy through ``TamgaClient.licenses.get_policy(license_id)``
            instead, which returns the identical resource by way of a route
            gated on ``license.read``. This method exists for callers holding a
            privileged token, and for the case where the policy id is known but
            no license id is.

        Args:
            policy_id: The policy to read.

        Returns:
            The policy resource. ``max_memory`` and ``max_disk`` are always
            ``None``; the server omits both.

        Raises:
            tamga.errors.ForbiddenError: If the credential lacks ``policy.read``
                — which is the normal outcome for a license key.
            tamga.errors.NotFoundError: If no such policy exists in the account.
        """
        data = _send_request(self._http, self._config, "GET", f"/policies/{policy_id}")
        return _parse_policy_resource(data)


@dataclass
class ReleasesClient:
    """Namespaced client for ``/releases`` endpoints. Access via ``TamgaClient.releases``."""

    _http: httpx.Client
    _config: TamgaConfig

    def check_for_upgrade(
        self,
        *,
        product_id: UUID,
        platform: str,
        filetype: str,
        version: str,
        channel: str | None = None,
        constraint: str | None = None,
    ) -> ReleaseResource | None:
        """``GET /releases/actions/upgrade`` — the auto-updater's "is there a newer build?".

        Returning ``None`` means **"there is no update available to you"** — and
        that phrasing is exact, not cautious. The server answers ``204 No
        Content`` in two different situations and does so on purpose:

        1. No newer release exists; the caller is already current.
        2. A newer release *does* exist, but this license is not entitled to it
           — an expired license under an ``expiration_strategy`` that stops it
           receiving new builds.

        The server's own comment explains the second case: a denial there would
        leak "a newer version exists but you can't have it", and ``204`` is the
        honest answer for a license that is not entitled to move further. **No
        client-side way to tell the two apart exists, and none should.** Do not
        report ``None`` to a user as "you are up to date"; report it as "no
        update is available".

        A third outcome is distinct and does surface: a **suspended** license
        gets ``403``, not ``204``.

        The route uses optional authentication, so a product with an ``Open``
        distribution strategy is reachable with no credential at all — that is
        deliberate server-side, since otherwise every auto-updater in the field
        would break the moment its license lapsed. This SDK sends its configured
        credential anyway, per its "always send auth" rule; for a ``Licensed``
        product the credential is required, and for a ``Closed`` one only an
        admin, developer or product token is accepted.

        Args:
            product_id: The product to check for updates. Required.
            platform: Target platform string, e.g. ``"darwin-arm64"``. Required.
            filetype: Artifact file type, e.g. ``"dmg"``. Required. Note the
                server spells this ``filetype``, one word.
            version: The caller's **current** version, which the server compares
                against. Required.
            channel: Optional release channel to restrict to.
            constraint: Optional version constraint to restrict to.

        Returns:
            The release to upgrade to, or ``None`` when nothing is available to
            this caller.

        Raises:
            tamga.errors.ForbiddenError: If the license is suspended, or the
                product's distribution strategy excludes this credential.
            tamga.errors.UnauthorizedError: If the product requires a credential
                and none was configured.
            tamga.errors.NotFoundError: If the product does not exist in the
                account.
        """
        params: dict[str, Any] = {
            "product": str(product_id),
            "platform": platform,
            "filetype": filetype,
            "version": version,
        }
        if channel is not None:
            params["channel"] = channel
        if constraint is not None:
            params["constraint"] = constraint

        data = _send_request(
            self._http,
            self._config,
            "GET",
            "/releases/actions/upgrade",
            params=params,
        )
        # `204 No Content` parses to `None`; see the two meanings above.
        if data is None:
            return None
        return _parse_release_resource(data)


@dataclass
class HeartbeatScheduler:
    """Background-safe machine heartbeat ping loop.

    The default interval (~200s) is roughly 1/3 of the server's *default* 600s
    heartbeat window. That window is the license policy's
    ``heartbeat_duration`` and only falls back to 600s when it is unset, so
    against a policy with a shorter window the interval must be sized from the
    policy — a fixed 200s ping is not safe under, say, a 120s window. Use
    ``HeartbeatScheduler.for_policy`` to do that in one call rather than
    computing an interval by hand.

    **No heartbeat status ends this loop.** The loop pings until ``stop()`` is
    called, the caller's runtime cancels it, or the ping returns ``404`` — that
    last one being the only signal that the machine row is really gone.
    Nothing is read off the response to decide whether to continue, and nothing
    should be: the ping's own write makes its ``heartbeat_status`` always
    ``ALIVE`` or ``RESURRECTED`` (see ``MachinesClient.ping_heartbeat``), so a
    status check here is dead code at best.

    Even a ``DEAD`` learned elsewhere — machine checkout does report it
    truthfully, see ``tamga.models.machine.HeartbeatStatus`` — is not a reason
    to stop. It means the last ping is older than the window, which is precisely
    the situation the next ping fixes.

    Attributes:
        machine_id: The machine to ping.
        interval: Ping interval; defaults to
            ``MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL``. Size it against the
            policy's ``heartbeat_duration`` when that is known — see
            ``for_policy``. A non-positive value is replaced by that same
            default rather than honoured — see ``__post_init__``.
    """

    machines: MachinesClient
    machine_id: UUID
    interval: timedelta = field(default=MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL)
    _stop: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Clamp a non-positive ``interval`` to ``MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL``.

        ``for_policy`` cannot hand back a non-positive interval. A policy whose
        ``heartbeat_duration`` is zero or negative — which the column permits,
        having no positivity constraint, and which the server returns verbatim —
        is read as unset by ``PolicyResource.effective_heartbeat_window_seconds``
        and falls back to 600s, and ``heartbeat_interval_for_policy`` floors what
        is left at one second. Constructing this dataclass directly is an equally
        supported path and had no such guard, so the same guarantee is applied
        here rather than only on the way in through ``for_policy``.

        A zero interval is the case worth preventing. It does not make
        ``run_forever`` a fast heartbeat, it makes it an unthrottled one: the
        loop issues ``ping-heartbeat`` as fast as it can turn, from every machine
        running that code, with every request individually valid and correctly
        authenticated — so neither end sees anything obviously wrong while the
        licensing server absorbs the traffic. A negative interval is caught by
        the same branch; left alone it raises ``ValueError`` out of
        ``time.sleep``, but only after the first ping has already gone out.

        Falls back rather than raising, matching ``for_policy``. A constructor
        that rejected what the policy path silently defaults would make the two
        paths disagree about the same policy.
        """
        if self.interval <= timedelta(0):
            self.interval = MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL

    @classmethod
    def for_policy(
        cls,
        machines: MachinesClient,
        machine_id: UUID,
        policy: PolicyResource,
    ) -> HeartbeatScheduler:
        """Build a scheduler whose interval is sized from the license's actual policy.

        The default ``interval`` on this class is sized against the server's
        600s *fallback* window, which is only correct for a policy that leaves
        ``heartbeat_duration`` unset. Under a policy asking for, say, 120s, the
        default pings roughly twice per hour into a two-minute window: the
        machine spends nearly all its time outside that window, reports
        ``DEAD``, and — where ``require_heartbeat`` is on — is eventually
        culled, with no signal the SDK could have observed beforehand.

        Read the policy first, then build the scheduler from it::

            policy = client.licenses.get_policy(license_id)
            scheduler = HeartbeatScheduler.for_policy(
                client.machines, machine.id, policy
            )
            scheduler.run_forever()

        Args:
            machines: The machines sub-client to ping through.
            machine_id: The machine to ping.
            policy: The policy governing that machine's license, from
                ``TamgaClient.licenses.get_policy``.

        Returns:
            A scheduler whose ``interval`` is
            ``heartbeat_interval_for_policy(policy)``.
        """
        return cls(
            machines=machines,
            machine_id=machine_id,
            interval=heartbeat_interval_for_policy(policy),
        )

    def stop(self) -> None:
        """Signal ``run_forever`` to return after its current sleep completes."""
        self._stop = True

    def run_forever(self) -> None:
        """Ping on ``self.interval`` until stopped, cancelled, or the machine is gone.

        The loop stops for exactly three reasons: ``stop()`` was called, the
        caller's runtime cancelled it, or the ping raised. It never inspects
        the returned status.

        It used to ``break`` when the response reported ``DEAD``, which was
        wrong twice over. Wrong in effect: the break was permanent, nothing
        restarted the loop, so one such reading ended heartbeating for the life
        of the process even though the ping is an unconditional
        ``last_heartbeat_at = NOW()`` write that would have revived the machine
        on the very next attempt. And wrong in premise on this route: a ping
        response cannot say ``DEAD``, because the status is computed from the
        timestamp the same call just wrote. (``DEAD`` is real and readable
        elsewhere — machine checkout reports it — just never here.) The
        condition was unreachable *and* catastrophic if reached, so the rule is
        the general one rather than a narrower "don't stop on ``DEAD``": **do
        not stop on any status.**

        The row actually being gone is reported as ``404`` on the ping, not as
        a status: the resulting ``tamga.errors.NotFoundError`` propagates to
        the caller, who should re-activate via
        ``MachinesClient.activate_machine``. That is the only terminal signal.
        """
        while not self._stop:
            self.machines.ping_heartbeat(self.machine_id)
            time.sleep(self.interval.total_seconds())


@dataclass
class ProcessHeartbeatScheduler:
    """Background-safe process heartbeat ping loop.

    Separate from ``HeartbeatScheduler`` since the interval (~10s) and
    dead-state semantics (no resurrection grace period) differ substantially
    from the machine-level window.

    Note:
        Nothing reaps process rows server-side: the 30s window exists, but no
        scheduled job acts on it, so a crashed process keeps its slot against
        the policy's process limit until the row is deleted explicitly.
        **Stopping the loop does not free the slot** — ``stop`` only ends the
        pinging. Call ``dispose`` instead, or use the scheduler as a context
        manager, to stop pinging *and* delete the row.

    Attributes:
        process_id: The process to ping.
        interval: Ping interval; defaults to
            ``PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL``. A non-positive value is
            replaced by that same default rather than honoured — see
            ``__post_init__``.
    """

    processes: ProcessesClient
    process_id: UUID
    interval: timedelta = field(default=PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL)
    _stop: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Clamp a non-positive ``interval`` to ``PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL``.

        The same guard ``HeartbeatScheduler`` applies, and needed more here: the
        process window is a hardcoded server-side 30s rather than a policy field,
        so this scheduler has no ``for_policy`` equivalent and hand construction
        is the *only* way to build one. Nothing else stood between a zero
        ``interval`` and a ``run_forever`` that pings as fast as the loop turns.

        Falls back rather than raising, for the reason given on
        ``HeartbeatScheduler.__post_init__``.
        """
        if self.interval <= timedelta(0):
            self.interval = PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL

    def stop(self) -> None:
        """Signal ``run_forever`` to return after its current sleep completes.

        Ends the pinging only. The process row, and the slot it holds against
        the policy's ``max_processes``, survive — see ``dispose``.
        """
        self._stop = True

    def dispose(self) -> None:
        """Stop pinging **and** delete the process row, freeing its slot.

        The pair belongs together because the server will not do the second half
        for anyone: no job reaps process rows, so a process that merely stops
        pinging holds its slot against ``max_processes`` indefinitely. An
        application that creates one process per run and only ever calls
        ``stop`` accumulates rows until activation fails with
        ``TOO_MANY_PROCESSES`` — for processes that exited long ago.

        Stopping comes first, so the loop is not left pinging a row that is
        about to disappear.

        An already-deleted row (``404``) is treated as success: the outcome
        this method promises is "the row is gone", and it is. Every other error
        propagates — a ``403`` means the slot is still held and the caller needs
        to know.
        """
        self.stop()
        # Already gone is success: `dispose` promises the row does not exist,
        # not that this call is what removed it.
        with contextlib.suppress(NotFoundError):
            self.processes.delete(self.process_id)

    def __enter__(self) -> ProcessHeartbeatScheduler:
        """Return ``self``, so ``with`` guarantees the matching ``dispose``."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Dispose on exit — including when the body raised.

        Returns ``None``, so an exception in the body is never suppressed. A
        crash is precisely when the row would otherwise be orphaned.
        """
        self.dispose()

    def run_forever(self) -> None:
        """Ping on ``self.interval`` until stopped/cancelled by the caller's runtime.

        Errors are not swallowed — a ``tamga.errors.NotFoundError`` (the
        process row was deleted) propagates to the caller.
        """
        while not self._stop:
            self.processes.ping(self.process_id)
            time.sleep(self.interval.total_seconds())


class TamgaClient:
    """Top-level façade wrapping ``httpx.Client``.

    Exposes namespaced sub-clients: ``.licenses``, ``.machines``,
    ``.components``, ``.processes``, ``.entitlements``, ``.policies``,
    ``.releases``.

    Synchronous only — this wraps ``httpx.Client``, not ``httpx.AsyncClient``.
    Usable as a context manager, which closes the underlying HTTP client on
    exit.

    A rate-limited (``429``) request is retried automatically when it is safe
    to repeat; see ``TamgaConfig.max_retries`` and ``_is_retryable``.

    Example::

        from tamga import TamgaClient, TamgaConfig
        from tamga.transport import LicenseAuth

        config = TamgaConfig(
            account_id="018f2f3a-0000-7000-8000-000000000001",
            host="api.tamga.sh",
            default_auth=LicenseAuth(key="MY-LICENSE-KEY"),
        )
        with TamgaClient(config) as client:
            result = client.licenses.validate_by_key("MY-LICENSE-KEY")
            print(result.meta.valid, result.meta.code.value)
    """

    licenses: LicensesClient
    machines: MachinesClient
    components: ComponentsClient
    processes: ProcessesClient
    entitlements: EntitlementsClient
    policies: PoliciesClient
    releases: ReleasesClient

    def __init__(
        self, config: TamgaConfig, *, transport: httpx.BaseTransport | None = None
    ) -> None:
        """Build the underlying ``httpx.Client`` and every namespaced sub-client.

        Args:
            config: Client configuration, including account ID, host, auth,
                and timeout.
            transport: Optional ``httpx`` transport override, so tests can
                inject ``httpx.MockTransport`` without reaching into private
                ``httpx.Client`` internals. ``None`` (default) uses real
                network I/O via ``httpx``'s default transport.
        """
        self.config = config
        base_url = build_base_url(config.host, config.account_id)
        self._http = httpx.Client(
            base_url=base_url, timeout=config.timeout_seconds, transport=transport
        )

        self.entitlements = EntitlementsClient(_http=self._http, _config=config)
        self.licenses = LicensesClient(
            _http=self._http, _config=config, _entitlements=self.entitlements
        )
        self.machines = MachinesClient(_http=self._http, _config=config)
        self.components = ComponentsClient(_http=self._http, _config=config)
        self.processes = ProcessesClient(_http=self._http, _config=config)
        self.policies = PoliciesClient(_http=self._http, _config=config)
        self.releases = ReleasesClient(_http=self._http, _config=config)

    def health(self) -> HealthStatus:
        """``GET /v1/health`` — the server's unauthenticated liveness probe.

        The **only** route this SDK calls that lives outside
        ``/v1/accounts/{account_id}``. Every other request is built on a base
        URL with the account segment already appended, which is why this one
        assembles an absolute URL from ``tamga.transport.build_root_url``
        instead — the account segment cannot be un-appended from a client
        already constructed around it. It reuses the same ``httpx.Client``, so
        it shares the connection pool, timeout, injected transport and ``429``
        backoff.

        The response is a **bare object**, not a JSON:API document: no ``data``
        envelope, no ``type``/``id``. It is decoded directly rather than through
        the envelope parser the rest of the surface uses.

        **What this is actually for: telling a misconfiguration apart from a bad
        credential.** The route is exempt from two separate server-side gates —
        it is on the public-route allowlist, and it bypasses the ``Host``-header
        allowlist. So if every other call is failing with ``403`` and "The Host
        header does not match any configured host" while this one succeeds, the
        problem is the server's ``TAMGA_ALLOWED_HOSTS`` configuration, not the
        caller's token. If this one fails too, the server is unreachable and no
        credential would have helped.

        The configured credential is sent anyway, for consistency with this
        SDK's "always send auth" rule; the route ignores it either way.

        Returns:
            The server's status, its own build version, and its uptime.

        Raises:
            tamga.errors.TamgaError: On any non-2xx response.
        """
        url = f"{build_root_url(self.config.host)}/v1/health"
        response = _send_raw_response(self._http, self.config, "GET", url)
        if response.status_code >= 400:
            raise parse_error_envelope(
                response.status_code,
                response.content,
                retry_after=parse_retry_after(response),
            )
        body = json.loads(response.content) if response.content else {}
        return HealthStatus(
            status=body.get("status", ""),
            version=body.get("version", ""),
            uptime_seconds=int(body.get("uptime_secs", 0)),
        )

    def close(self) -> None:
        """Close the underlying ``httpx.Client``."""
        self._http.close()

    def __enter__(self) -> TamgaClient:
        """Return ``self`` for use as a context manager."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the underlying ``httpx.Client`` on context-manager exit."""
        self.close()
