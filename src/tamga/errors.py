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

Every error this SDK raises against the server is a ``TamgaError``, so
``except TamgaError:`` is the one handler that catches all of them — including
``MachineOverLimitError``, which additionally inherits ``ValueError`` for
backward compatibility. Note that the *offline* parsers
(``tamga.checkout``, ``tamga.proof``) raise plain ``ValueError``/
``InvalidSignature``/``InvalidTag`` for malformed input; those are local
failures with no server involvement and are deliberately not in this hierarchy.

**Auth is enforced.** ``Authorization: License <key>`` is only accepted when
the license's policy has ``authentication_strategy`` set to ``"LICENSE"`` or
``"MIXED"``. That column defaults to ``"TOKEN"``, and ``"NONE"`` behaves like
``"TOKEN"`` at the auth gate — under either, license-key auth is rejected with
``401 LICENSE_NOT_ALLOWED`` (``LicenseNotAllowedError``). That is a
configuration precondition, **not** a retryable authentication failure: retrying
or re-sending the same key will never succeed. Likewise, a license whose policy
uses ``expiration_strategy: "REVOKE_ACCESS"`` stops authenticating entirely once
it expires (``401 LICENSE_EXPIRED``), while the other three expiration
strategies still authenticate an expired license and report expiry through the
validation ``meta.code`` instead.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tamga.models.validation import ValidationCode


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


class MachineLimitExceededError(TamgaError):
    """422 ``MACHINE_LIMIT_EXCEEDED`` — machine creation refused by the policy's machine limit.

    Creation *does* enforce limits: the server runs the check through the
    policy's overage strategy before inserting the row, so under
    ``NO_OVERAGE`` (and any strategy whose multiplied ceiling is already
    reached) ``POST /machines`` fails outright rather than succeeding and
    surfacing the problem at validation time. The equivalent validation code
    is ``ValidationCode.TOO_MANY_MACHINES``.
    """


class CoreLimitExceededError(TamgaError):
    """422 ``CORE_LIMIT_EXCEEDED`` — machine ``cores`` would exceed the policy's core limit.

    Same create-time enforcement as ``MachineLimitExceededError``; the
    equivalent validation code is ``ValidationCode.TOO_MANY_CORES``.
    """


class MemoryLimitExceededError(TamgaError):
    """422 ``MEMORY_LIMIT_EXCEEDED`` — machine ``memory`` would exceed the policy's limit.

    ``memory`` is reported in **megabytes**; reporting bytes inflates the
    license's running total by ~1e6 and trips this on the next activation.
    The equivalent validation code is ``ValidationCode.TOO_MUCH_MEMORY``.
    """


class DiskLimitExceededError(TamgaError):
    """422 ``DISK_LIMIT_EXCEEDED`` — machine ``disk`` would exceed the policy's limit.

    ``disk`` is reported in **megabytes**, same caveat as
    ``MemoryLimitExceededError``. The equivalent validation code is
    ``ValidationCode.TOO_MUCH_DISK``.
    """


class TooManyProcessesError(TamgaError):
    """422 ``TOO_MANY_PROCESSES`` — process spawn refused by the policy's process limit.

    Raised by ``POST /processes``. Note the server never reaps process rows on
    its own, so a crashed process holds its slot until it is deleted
    explicitly.
    """


class LicenseSuspendedError(TamgaError):
    """401 ``LICENSE_SUSPENDED`` — the license is suspended, so the credential is refused.

    Distinct from the ``ValidationCode.SUSPENDED`` validation result: this one
    fails at the auth gate, before any endpoint logic runs.
    """


class LicenseExpiredError(TamgaError):
    """401 ``LICENSE_EXPIRED`` — expired license under ``expiration_strategy: REVOKE_ACCESS``.

    Only ``REVOKE_ACCESS`` refuses the credential outright;
    ``RESTRICT_ACCESS``/``MAINTAIN_ACCESS``/``ALLOW_ACCESS`` still
    authenticate an expired license and report expiry through the validation
    ``meta.code`` instead.
    """


class LicenseNotAllowedError(TamgaError):
    """401 ``LICENSE_NOT_ALLOWED`` — license-key auth is disabled by the policy.

    The policy's ``authentication_strategy`` must be ``"LICENSE"`` or
    ``"MIXED"`` for ``Authorization: License <key>`` to be accepted; it
    defaults to ``"TOKEN"``, and ``"NONE"`` behaves the same way at this gate.
    A configuration precondition, not a transient failure — **do not retry**,
    and do not present it to end users as a bad-key error.
    """


class MachineOverLimitError(TamgaError, ValueError):
    """Machine activation was rejected because the license is at a policy limit.

    Raised by ``tamga.client.MachinesClient.activate_machine`` for both of the
    points at which a limit can stop an activation — the create-time ``422``
    and the validate-time over-limit result — so a caller has one type to
    catch. ``rolled_back`` tells the two apart.

    Note:
        **The ``ValueError`` base is deliberate and must not be removed.**
        Both paths used to raise a bare ``ValueError``; inheriting it keeps
        every existing ``except ValueError:`` handler working, so gaining the
        ``TamgaError`` base is purely additive. Dropping ``ValueError`` later
        would silently break those callers. A regression test asserts the
        ``ValueError`` catch specifically, precisely so this cannot be tidied
        away by accident.

        Being a ``TamgaError`` is the point of the change: this SDK documents
        ``except TamgaError:`` as the way to catch everything it raises against
        the server, and it also raises plain ``ValueError`` all over the
        offline-file parsers for malformed PEM/JSON/certificate input. A bare
        ``ValueError`` therefore filed "the license is at its seat limit" in
        the same bucket as "this file is corrupt" — invisible to the documented
        handler, and catchable by a ``ValueError`` handler written for parsing.

    Attributes:
        validation_code: The ``ValidationCode`` describing the limit that was
            hit — ``TOO_MANY_MACHINES``, ``TOO_MANY_CORES``,
            ``TOO_MUCH_MEMORY``, ``TOO_MUCH_DISK``, or ``TOO_MANY_PROCESSES``.
            On the create-time path the server's ``422`` code is normalized to
            its equivalent here, so this field means the same thing whichever
            path produced the error.
        rolled_back: Whether a machine row had to be deleted. ``False`` on the
            create-time path — the server refused before inserting, so nothing
            existed to remove. ``True`` on the validate-time path — the
            policy's overage strategy let the create through, so the row was
            created and then deleted before raising. Either way no machine
            survives; this says whether a seat was briefly consumed.
        status: HTTP status of the response that produced the rejection:
            ``422`` for the create-time refusal, ``200`` for the validate-time
            one (validation reports an over-limit license inside a *successful*
            response, not an error envelope).
        code: The wire code from that response — a JSON:API error ``code`` such
            as ``MACHINE_LIMIT_EXCEEDED`` on the create-time path, or the
            validation ``meta.code`` on the validate-time path.
    """

    def __init__(
        self,
        *,
        status: int,
        code: str,
        detail: str,
        validation_code: ValidationCode,
        rolled_back: bool,
        pointer: str | None = None,
    ) -> None:
        """Build a ``MachineOverLimitError``; see the class docstring for attribute meanings."""
        super().__init__(status=status, code=code, detail=detail, pointer=pointer)
        self.validation_code = validation_code
        self.rolled_back = rolled_back


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
    "MACHINE_LIMIT_EXCEEDED": MachineLimitExceededError,
    "CORE_LIMIT_EXCEEDED": CoreLimitExceededError,
    "MEMORY_LIMIT_EXCEEDED": MemoryLimitExceededError,
    "DISK_LIMIT_EXCEEDED": DiskLimitExceededError,
    "TOO_MANY_PROCESSES": TooManyProcessesError,
    "LICENSE_SUSPENDED": LicenseSuspendedError,
    "LICENSE_EXPIRED": LicenseExpiredError,
    "LICENSE_NOT_ALLOWED": LicenseNotAllowedError,
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
