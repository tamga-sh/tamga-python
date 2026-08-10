"""``TamgaClient`` façade and namespaced sub-clients for every endpoint group.

``TamgaClient`` wraps an ``httpx.Client`` and exposes namespaced sub-clients
(``.licenses``, ``.machines``, ``.components``, ``.processes``,
``.entitlements``) rather than one flat method namespace, mirroring the
resource grouping in docs/sdk.md.

Auth note: server-side auth enforcement is **not currently active** on the
license or machine endpoints (see docs/sdk.md "Known Server-Side Gaps" item
3) — this SDK still always sends proper credentials (default: ``Authorization:
License <key>`` for license-key-based flows) for forward-compatibility, not
because the server currently checks them.
"""

from __future__ import annotations

import builtins
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Generic, TypeVar
from uuid import UUID

import httpx

from tamga.errors import TtlInvalidError, parse_error_envelope
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
    sanitize_tamga_version,
)

T = TypeVar("T")

#: Recommended machine heartbeat ping interval — roughly 1/3 of the
#: server's hardcoded 600s heartbeat window (see docs/sdk.md section 5).
MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL: timedelta = timedelta(seconds=200)

#: Recommended process heartbeat ping interval — well inside the server's
#: hardcoded 30s process heartbeat window, which has no resurrection grace
#: period (see docs/sdk.md section 8).
PROCESS_HEARTBEAT_RECOMMENDED_INTERVAL: timedelta = timedelta(seconds=10)

#: Server-side bounds on machine/process checkout `ttl` (seconds): must be
#: `> 0` and `<= 31536000` (365 days), else `422 TTL_INVALID`.
MAX_CHECKOUT_TTL_SECONDS: int = 31536000


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp, tolerating a trailing ``Z`` (Python 3.9
    ``datetime.fromisoformat`` doesn't accept ``Z`` until 3.11)."""
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
    )


def _parse_component_resource(data: dict[str, Any]) -> ComponentResource:
    attrs = data.get("attributes", {})
    return ComponentResource(
        id=UUID(str(data["id"])),
        machine_id=UUID(str(attrs["machine_id"])),
        fingerprint=attrs.get("fingerprint", ""),
        name=attrs.get("name", ""),
        metadata=attrs.get("metadata") or {},
    )


def _parse_process_resource(data: dict[str, Any]) -> ProcessResource:
    attrs = data.get("attributes", {})
    return ProcessResource(
        id=UUID(str(data["id"])),
        machine_id=UUID(str(attrs["machine_id"])),
        pid=attrs.get("pid", ""),
        metadata=attrs.get("metadata") or {},
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
    if scope.version is not None:
        result["version"] = scope.version
    if scope.checksum is not None:
        result["checksum"] = scope.checksum
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
            ``httpx.Client``. No retry-on-429 is configured, since the
            server never sends 429 today.
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

    Returns the parsed ``.data`` payload (already unwrapped from the
    JSON:API envelope), or, when ``meta`` is present in the raw JSON:API
    response body, a ``(data, meta)`` tuple — callers that need ``meta``
    (validate/checkout/offline-proof endpoints) pass ``want_meta=True``
    implicitly by inspecting the return value themselves via the lower-level
    ``_send_request_raw`` instead. Endpoint methods below call
    ``_send_request_raw`` directly when they need response ``meta``.
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

    response = http.request(
        method,
        path,
        json=json_body,
        params=request_params,
        headers=headers,
    )
    return parse_response(response, is_quick_validate=is_quick_validate)


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
        response = self._http.request(
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

        response = self._http.request(
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

        Note:
            The plan's stub signature for this method didn't include a
            parameter to select between the ``GET``/``POST`` variants
            despite documenting both — ``as_bytes`` is this SDK's resolution
            of that gap (documented deviation; see
            docs/plans/tamga-python.plan.md Section E's checkbox note).
            ``tamga-rust`` resolves the same ambiguity by exposing two
            separate methods (``check_out_license``/``check_out_license_json``)
            instead.

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
            response = self._http.request(
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

        No machine/core/etc. limit is checked at creation time — those
        limits only surface later via license validation. Prefer
        ``activate_machine`` for the documented create-then-validate flow.

        Raises:
            tamga.errors.FingerprintTakenError: On ``409 FINGERPRINT_TAKEN``
                for a duplicate ``(account_id, license_id, fingerprint)``.
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

        Implements the documented flow: create machine -> validate license ->
        on ``TOO_MANY_MACHINES``/``TOO_MANY_CORES``/``TOO_MUCH_MEMORY``/
        ``TOO_MUCH_DISK``/``TOO_MANY_PROCESSES``, delete the just-created
        machine and raise, since the machine row may already have been
        created even though the license is over its limit.

        Args:
            license_id: The license to activate the machine against.
            fingerprint: The machine's unique fingerprint.
            **attrs: Additional optional machine attributes (``name``,
                ``ip``, ``hostname``, ``platform``, ``cores``, ``memory``,
                ``disk``, ``metadata``).

        Returns:
            The created (and license-validated) ``MachineResource``.
        """
        machine = self.create(license_id, fingerprint, **attrs)

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
            raise ValueError(
                f"machine activation rejected: license validation returned "
                f"{result.meta.code.value} — the created machine has been rolled back"
            )
        return machine

    def ping_heartbeat(self, machine_id: UUID) -> MachineResource:
        """``POST /machines/{id}/actions/ping-heartbeat``, no body. Sets ``last_heartbeat_at``."""
        data = _send_request(
            self._http, self._config, "POST", f"/machines/{machine_id}/actions/ping-heartbeat"
        )
        return _parse_machine_resource(data)

    def reset_heartbeat(self, machine_id: UUID) -> MachineResource:
        """``POST /machines/{id}/actions/reset-heartbeat``, no body. Rewinds to ``NOT_STARTED``."""
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
            Same ``as_bytes`` deviation as ``LicensesClient.check_out`` — see
            its docstring and docs/plans/tamga-python.plan.md Section F's
            checkbox note.

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

            response = self._http.request(
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
        """
        body = {"meta": {"dataset": dataset or {}}}
        response = self._http.request(
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
        """``GET /machines/{id}/components``, keyset-paginated (``limit``/``page[after]``)."""
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
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
        return Page(items=items, next_after=_next_after_cursor(items, limit))


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
        """``GET /licenses/{license_id}/entitlements``, keyset-paginated.

        No auth/permission check is applied on this license-scoped read
        endpoint beyond the license existing.
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if after is not None:
            params["page[after]"] = after
        response = _send_request_raw(
            self._http,
            self._config,
            "GET",
            f"/licenses/{license_id}/entitlements",
            params=params,
        )
        items = [_parse_entitlement(d) for d in (response.data or [])]
        return Page(items=items, next_after=_next_after_cursor(items, limit))

    def get(self, license_id: UUID, entitlement_id: UUID) -> Entitlement:
        """``GET /licenses/{license_id}/entitlements/{entitlement_id}``.

        Despite the URL shape, returns a full ``Entitlement`` resource, not
        a lightweight junction record.
        """
        data = _send_request(
            self._http,
            self._config,
            "GET",
            f"/licenses/{license_id}/entitlements/{entitlement_id}",
        )
        return _parse_entitlement(data)

    def list_all(self, license_id: UUID) -> builtins.list[Entitlement]:
        """Fetch every page of entitlements for ``license_id`` and concatenate.

        Internal helper backing ``LicenseResource.refresh_entitlements()``'s
        fetcher — the public ``list()`` method above returns one page at a
        time for callers who want to paginate manually.

        Note:
            Return type is spelled ``builtins.list[Entitlement]`` rather
            than the bare ``list[Entitlement]`` used elsewhere in this file
            — inside this class, the sibling method named ``list`` shadows
            the builtin ``list`` name for mypy's postponed-annotation
            resolution (``from __future__ import annotations``), so a bare
            ``list[Entitlement]`` here resolves to "the ``list`` method used
            as a type" instead of the builtin generic.
        """
        page_size = 100
        items: list[Entitlement] = []
        after: str | None = None
        while True:
            page = self.list(license_id, limit=page_size, after=after)
            items.extend(page.items)
            if page.next_after is None:
                break
            after = page.next_after
        return items


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
    """
    if not items or limit is None or len(items) < limit:
        return None
    last = items[-1]
    return str(last.id)


@dataclass
class HeartbeatScheduler:
    """Background-safe machine heartbeat ping loop.

    Recommends pinging at roughly 1/3 of the server's hardcoded 600s
    heartbeat window (~200s) to stay safely inside it.
    ``DEAD`` is treated as "machine likely deleted server-side —
    re-activate rather than retry ping", not as a transient error to retry
    through.

    Attributes:
        machine_id: The machine to ping.
        interval: Ping interval; defaults to
            ``MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL``.
    """

    machines: MachinesClient
    machine_id: UUID
    interval: timedelta = field(default=MACHINE_HEARTBEAT_RECOMMENDED_INTERVAL)
    _stop: bool = field(default=False, repr=False, compare=False)

    def stop(self) -> None:
        """Signal ``run_forever`` to return after its current sleep completes."""
        self._stop = True

    def run_forever(self) -> None:
        """Ping on ``self.interval`` until stopped/cancelled by the caller's runtime.

        Treats a ``DEAD`` heartbeat status as "machine likely deleted
        server-side" and stops the loop rather than retrying the ping
        indefinitely — callers should re-activate via
        ``MachinesClient.activate_machine`` instead of relying on this loop
        to recover a dead machine.
        """
        while not self._stop:
            machine = self.machines.ping_heartbeat(self.machine_id)
            if machine.heartbeat_status == HeartbeatStatus.DEAD:
                break
            time.sleep(self.interval.total_seconds())


@dataclass
class ProcessHeartbeatScheduler:
    """Background-safe process heartbeat ping loop.

    Separate from ``HeartbeatScheduler`` since the interval (~10s) and
    dead-state semantics (immediate deletion, no resurrection grace period)
    differ substantially from the machine-level 600s window.

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

        Unlike machine heartbeats, a dead process row is deleted
        immediately server-side (no resurrection grace period) — a ping
        against an already-culled process will surface as a
        ``NotFoundError``, which this loop does not swallow.
        """
        while not self._stop:
            self.processes.ping(self.process_id)
            time.sleep(self.interval.total_seconds())


class TamgaClient:
    """Top-level façade wrapping ``httpx.Client``.

    Exposes namespaced sub-clients: ``.licenses``, ``.machines``,
    ``.components``, ``.processes``, ``.entitlements``.

    Example (illustrative — implementation is currently a stub):
        >>> client = TamgaClient(TamgaConfig(account_id="acct_123", host="api.tamga.sh"))
        >>> result = client.licenses.validate_by_key("MY-LICENSE-KEY")
        >>> result.meta.valid
        True
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
            transport: Optional ``httpx`` transport override — not part of
                the plan's literal stub signature, added so tests can inject
                ``httpx.MockTransport`` without reaching into private
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
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
