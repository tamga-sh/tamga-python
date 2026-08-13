"""Tamga error hierarchy and JSON:API error envelope parsing.

Every Tamga API error response is a JSON:API error envelope::

    {"errors": [{"id": ..., "status": ..., "code": ..., "title": ...,
                 "detail": ..., "source": {"pointer": ...}}]}

with ``Content-Type: application/vnd.api+json``. HTTP status is fixed per
error variant; ``code`` is the stable, machine-matchable identifier — SDK
code should branch on ``code``, never on ``detail`` (human text, may change
without notice).

Fixed-status codes seen across the SDK surface: ``NOT_FOUND`` (404),
``UNAUTHORIZED`` (401), ``FORBIDDEN`` (403), ``INTERNAL_SERVER_ERROR`` (500,
generic — never leaks DB detail). Per-endpoint conflict/validation codes are
modeled below as typed subclasses.

``429 TOO_MANY_REQUESTS`` is live and modelled as ``RateLimitedError``, which
carries the server's ``Retry-After``. Credential-accepting endpoints run on a
tight per-IP budget that a heartbeat timer reaches easily.
"""

from __future__ import annotations

import json


class TamgaError(Exception):
    """Base exception for all errors raised by the Tamga SDK.

    Attributes:
        status: HTTP status code of the response that produced this error.
        code: Stable, machine-matchable error code (e.g. ``"NOT_FOUND"``).
        detail: Human-readable detail string. May change without notice —
            never match on this field.
        pointer: JSON:API ``source.pointer`` value, if the server supplied
            one (points at the offending request field).
    """

    def __init__(
        self,
        *,
        status: int,
        code: str,
        detail: str,
        pointer: str | None = None,
    ) -> None:
        """Build a ``TamgaError``; see the class docstring for the attribute meanings."""
        self.status = status
        self.code = code
        self.detail = detail
        self.pointer = pointer
        super().__init__(f"{code} ({status}): {detail}")


class RateLimitedError(TamgaError):
    """The server answered ``429 Too Many Requests``.

    Credential-accepting endpoints (session creation, password reset,
    license-key validation, token minting) run on a tight per-IP budget — 5
    requests/second by default — which a heartbeat timer reaches easily.

    Its own class on purpose: a caller that cannot tell "you are going too
    fast, wait N seconds" from "your credential is wrong" will retry the second
    one forever and give up on the first.

    Attributes:
        retry_after: The server's ``Retry-After`` in seconds, when it sent one.
            Wait at least this long before trying again.
    """

    retry_after: int | None = None


class NotFoundError(TamgaError):
    """HTTP 404 — resource not found."""


class UnauthorizedError(TamgaError):
    """HTTP 401 — missing or invalid credentials."""


class ForbiddenError(TamgaError):
    """HTTP 403 — credentials valid but not permitted."""


class InternalServerError(TamgaError):
    """HTTP 500 — generic server error. Never expect leaked DB detail."""


class KeyTakenError(TamgaError):
    """409 ``KEY_TAKEN`` — duplicate license key."""


class FingerprintTakenError(TamgaError):
    """409 ``FINGERPRINT_TAKEN`` — duplicate fingerprint.

    Raised for a duplicate ``(account_id, license_id, fingerprint)`` on
    machine creation, or ``(account_id, machine_id, fingerprint)`` on
    component creation.
    """


class PidTakenError(TamgaError):
    """409 ``PID_TAKEN`` — duplicate PID for a machine's processes."""


class CheckInNotRequiredError(TamgaError):
    """422 ``CHECK_IN_NOT_REQUIRED`` — license's policy has ``require_check_in: false``.

    Surface as a caller error: check ``policy.require_check_in`` before
    scheduling periodic check-ins rather than retrying through this.
    """


class TtlInvalidError(TamgaError):
    """422 ``TTL_INVALID`` — machine checkout ``ttl`` outside ``(0, 31536000]``."""


class LicenseNotEncryptedError(TamgaError):
    """422 ``LICENSE_NOT_ENCRYPTED`` — ``encrypt=true`` requested but license has no key set."""


class LicenseKeyMissingError(TamgaError):
    """422 ``LICENSE_KEY_MISSING``."""


class SchemeNotSupportedError(TamgaError):
    """422 ``SCHEME_NOT_SUPPORTED`` — e.g. ``RSA_2048_JWT_RS256`` rejected for machine checkout."""


class DatasetInvalidError(TamgaError):
    """422 ``DATASET_INVALID`` — offline proof ``dataset`` payload rejected."""


class UnknownTamgaError(TamgaError):
    """Fallback for error ``code`` values not yet modeled by this SDK version."""


#: Dispatch table from stable JSON:API ``code`` to the typed exception class.
#: Single lookup point — new codes only need an entry here, not a new
#: call site at every endpoint method (mirrors tamga-rust's
#: ``TamgaError::from_json_api_error`` match statement).
_CODE_TO_EXCEPTION: dict[str, type[TamgaError]] = {
    "NOT_FOUND": NotFoundError,
    "UNAUTHORIZED": UnauthorizedError,
    "FORBIDDEN": ForbiddenError,
    "INTERNAL_SERVER_ERROR": InternalServerError,
    "KEY_TAKEN": KeyTakenError,
    "FINGERPRINT_TAKEN": FingerprintTakenError,
    "PID_TAKEN": PidTakenError,
    "CHECK_IN_NOT_REQUIRED": CheckInNotRequiredError,
    "TTL_INVALID": TtlInvalidError,
    "LICENSE_NOT_ENCRYPTED": LicenseNotEncryptedError,
    "LICENSE_KEY_MISSING": LicenseKeyMissingError,
    "SCHEME_NOT_SUPPORTED": SchemeNotSupportedError,
    "DATASET_INVALID": DatasetInvalidError,
}


def parse_error_envelope(status: int, body: bytes, retry_after: int | None = None) -> TamgaError:
    """Parse a JSON:API error envelope and dispatch to a typed ``TamgaError`` subclass.

    Args:
        status: HTTP status code of the response.
        body: Raw response body bytes (JSON:API error envelope).
        retry_after: Parsed ``Retry-After`` header value in seconds, if the
            response carried one (typically only present on a 429).

    Returns:
        The most specific ``TamgaError`` subclass matching the response's
        ``code``, falling back to ``UnknownTamgaError`` for unrecognized codes.
    """
    try:
        parsed = json.loads(body)
        errors = parsed.get("errors") or []
        first = errors[0] if errors else {}
    except (json.JSONDecodeError, AttributeError, IndexError):
        first = {}

    code = first.get("code", "UNKNOWN")
    detail = first.get("detail", "")
    source = first.get("source") or {}
    pointer = source.get("pointer")

    if status == 429:
        err = RateLimitedError(status=status, code=code, detail=detail, pointer=pointer)
        err.retry_after = retry_after
        return err

    exc_cls = _CODE_TO_EXCEPTION.get(code, UnknownTamgaError)
    return exc_cls(status=status, code=code, detail=detail, pointer=pointer)
