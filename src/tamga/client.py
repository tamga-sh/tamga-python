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
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Generic, TypeVar
from uuid import UUID

import httpx

from tamga.errors import (
    MachineOverLimitError,
    TamgaError,
    TtlInvalidError,
    parse_error_envelope,
)
from tamga.models.license import LicenseFileResource, LicenseResource, LicenseScope
from tamga.models.machine import (
    ComponentResource,
    HeartbeatStatus,
    MachineFileResource,
    MachineResource,
    ProcessResource,
)
from tamga.models.policy import Entitlement
from tamga.models.validation import ValidationCode, ValidationMeta, ValidationResult
from tamga.proof import ProofResult
from tamga.transport import (
    DEFAULT_TIMEOUT_SECONDS,
    AuthTransport,
    LicenseAuth,
    apply_auth,
    build_base_url,
    parse_response,
    parse_retry_after,
    sanitize_tamga_version,
)

T = TypeVar("T")

#: Recommended machine heartbeat ping interval — roughly 1/3 of the server's
#: *default* 600s heartbeat window. The window is not a constant: it comes from
#: the license's ``policy.heartbeat_duration`` and only falls back to 600s when
#: that column is unset, so a policy with a short window needs a
#: correspondingly shorter interval passed explicitly to ``HeartbeatScheduler``.
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

    response = _request_with_retry(
        http,
        config,
        method,
        path,
        json_body=json_body,
        params=request_params,
        headers=headers,
    )
    return parse_response(response, is_quick_validate=is_quick_validate)


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
                registered within the policy's uniqueness scope. Activation is
                not idempotent — this SDK version offers no way to recover the
                existing machine's id.
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
        """``POST /components``.

        Raises:
            tamga.errors.FingerprintTakenError: On ``409 FINGERPRINT_TAKEN``
                for a duplicate ``(account_id, machine_id, fingerprint)``.
        """
        attributes: dict[str, Any] = {
            "fingerprint": fingerprint,
            "name": name,
            "machine_id": str(machine_id),
        }
        if metadata is not None:
            attributes["metadata"] = metadata
        body = {"data": {"type": "components", "attributes": attributes}}
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
        """``POST /processes``.

        ``pid`` must be a ``str`` on the wire — reject non-string input at
        this boundary rather than silently ``str()``-coercing it, so callers
        don't accidentally build the wrong wire type upstream.

        Raises:
            TypeError: If ``pid`` is not a ``str`` (e.g. an ``int`` was passed).
            tamga.errors.PidTakenError: On ``409 PID_TAKEN`` for a duplicate
                PID on this machine.
        """
        if not isinstance(pid, str):
            raise TypeError(f"pid must be a str, got {type(pid).__name__}: {pid!r}")

        attributes: dict[str, Any] = {"pid": pid, "machine_id": str(machine_id)}
        if metadata is not None:
            attributes["metadata"] = metadata
        body = {"data": {"type": "processes", "attributes": attributes}}
        data = _send_request(self._http, self._config, "POST", "/processes", json_body=body)
        return _parse_process_resource(data)

    def ping(self, process_id: UUID) -> ProcessResource:
        """``POST /processes/{id}/actions/ping``, no body."""
        data = _send_request(
            self._http, self._config, "POST", f"/processes/{process_id}/actions/ping"
        )
        return _parse_process_resource(data)


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
class HeartbeatScheduler:
    """Background-safe machine heartbeat ping loop.

    The default interval (~200s) is roughly 1/3 of the server's *default* 600s
    heartbeat window. That window is the license policy's
    ``heartbeat_duration`` and only falls back to 600s when it is unset, so
    against a policy with a shorter window the interval must be passed
    explicitly — a fixed 200s ping is not safe under, say, a 120s window.

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
            policy's ``heartbeat_duration`` when that is known.
    """

    machines: MachinesClient
    machine_id: UUID
    interval: timedelta = field(default=MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL)
    _stop: bool = field(default=False, repr=False, compare=False)

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
        the policy's process limit until the row is deleted explicitly. This
        SDK version exposes no process-delete method, so stopping the loop
        does **not** free the slot.

    Attributes:
        process_id: The process to ping.
        interval: Ping interval; defaults to
            ``PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL``.
    """

    processes: ProcessesClient
    process_id: UUID
    interval: timedelta = field(default=PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL)
    _stop: bool = field(default=False, repr=False, compare=False)

    def stop(self) -> None:
        """Signal ``run_forever`` to return after its current sleep completes."""
        self._stop = True

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
    ``.components``, ``.processes``, ``.entitlements``.

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

    def close(self) -> None:
        """Close the underlying ``httpx.Client``."""
        self._http.close()

    def __enter__(self) -> TamgaClient:
        """Return ``self`` for use as a context manager."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close the underlying ``httpx.Client`` on context-manager exit."""
        self.close()
