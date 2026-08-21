"""Tests for the JSON:API error envelope parser and typed exception dispatch."""

from __future__ import annotations

import json

import pytest

from tamga.errors import (
    CheckInNotRequiredError,
    CoreLimitExceededError,
    DatasetInvalidError,
    DiskLimitExceededError,
    FingerprintTakenError,
    ForbiddenError,
    InternalServerError,
    KeyTakenError,
    LicenseExpiredError,
    LicenseKeyMissingError,
    LicenseNotAllowedError,
    LicenseNotEncryptedError,
    LicenseSuspendedError,
    MachineLimitExceededError,
    MemoryLimitExceededError,
    NotFoundError,
    PidTakenError,
    RateLimitedError,
    SchemeNotSupportedError,
    TooManyProcessesError,
    TtlInvalidError,
    UnauthorizedError,
    UnknownTamgaError,
    parse_error_envelope,
)


def test_parses_json_api_error_envelope(json_api_error_body: dict) -> None:
    body = json.dumps(json_api_error_body).encode("utf-8")
    error = parse_error_envelope(404, body)
    assert error.status == 404
    assert error.code == "NOT_FOUND"
    assert error.detail == "The requested resource does not exist."


@pytest.mark.parametrize(
    ("code", "status", "expected_cls"),
    [
        ("NOT_FOUND", 404, NotFoundError),
        ("UNAUTHORIZED", 401, UnauthorizedError),
        ("FORBIDDEN", 403, ForbiddenError),
        ("INTERNAL_SERVER_ERROR", 500, InternalServerError),
        ("KEY_TAKEN", 409, KeyTakenError),
        ("FINGERPRINT_TAKEN", 409, FingerprintTakenError),
        ("PID_TAKEN", 409, PidTakenError),
        ("CHECK_IN_NOT_REQUIRED", 422, CheckInNotRequiredError),
        ("TTL_INVALID", 422, TtlInvalidError),
        ("LICENSE_NOT_ENCRYPTED", 422, LicenseNotEncryptedError),
        ("LICENSE_KEY_MISSING", 422, LicenseKeyMissingError),
        ("SCHEME_NOT_SUPPORTED", 422, SchemeNotSupportedError),
        ("DATASET_INVALID", 422, DatasetInvalidError),
        # Limit codes: the server enforces machine/core/memory/disk at
        # creation time, and the process limit at spawn time.
        ("MACHINE_LIMIT_EXCEEDED", 422, MachineLimitExceededError),
        ("CORE_LIMIT_EXCEEDED", 422, CoreLimitExceededError),
        ("MEMORY_LIMIT_EXCEEDED", 422, MemoryLimitExceededError),
        ("DISK_LIMIT_EXCEEDED", 422, DiskLimitExceededError),
        ("TOO_MANY_PROCESSES", 422, TooManyProcessesError),
        # Auth-gate codes: these fail before any endpoint logic runs.
        ("LICENSE_SUSPENDED", 401, LicenseSuspendedError),
        ("LICENSE_EXPIRED", 401, LicenseExpiredError),
        ("LICENSE_NOT_ALLOWED", 401, LicenseNotAllowedError),
    ],
)
def test_each_typed_exception_raised_for_its_matching_code(
    code: str, status: int, expected_cls: type
) -> None:
    body = json.dumps(
        {
            "errors": [
                {
                    "id": "e1",
                    "status": str(status),
                    "code": code,
                    "title": "title",
                    "detail": "detail",
                    "source": None,
                }
            ]
        }
    ).encode("utf-8")
    error = parse_error_envelope(status, body)
    assert isinstance(error, expected_cls)
    assert error.code == code


def test_a_429_maps_to_rate_limited_not_the_unknown_fallback() -> None:
    # `TOO_MANY_REQUESTS` has no entry in the code table, so before this it
    # fell through to `UnknownTamgaError` — leaving a caller unable to tell
    # "slow down" from "your credential is wrong", and retrying the wrong one
    # of those forever.
    body = json.dumps(
        {
            "errors": [
                {
                    "id": "e1",
                    "status": "429",
                    "code": "TOO_MANY_REQUESTS",
                    "title": "title",
                    "detail": "rate limited",
                    "source": None,
                }
            ]
        }
    ).encode("utf-8")
    error = parse_error_envelope(429, body, retry_after=42)
    assert isinstance(error, RateLimitedError)
    assert error.code == "TOO_MANY_REQUESTS"
    assert error.retry_after == 42


def test_an_unrecognised_code_still_falls_back_to_unknown() -> None:
    body = json.dumps(
        {"errors": [{"id": "e1", "status": "418", "code": "TEAPOT", "detail": "no coffee"}]}
    ).encode("utf-8")
    error = parse_error_envelope(418, body)
    assert isinstance(error, UnknownTamgaError)
    assert error.code == "TEAPOT"


def test_error_with_source_pointer_is_parsed() -> None:
    body = json.dumps(
        {
            "errors": [
                {
                    "id": "e1",
                    "status": "422",
                    "code": "DATASET_INVALID",
                    "title": "Unprocessable Entity",
                    "detail": "dataset must be an object",
                    "source": {"pointer": "/meta/dataset"},
                }
            ]
        }
    ).encode("utf-8")
    error = parse_error_envelope(422, body)
    assert error.pointer == "/meta/dataset"


def test_malformed_body_does_not_crash() -> None:
    error = parse_error_envelope(500, b"not json at all")
    assert isinstance(error, UnknownTamgaError)
    assert error.status == 500


def test_license_not_allowed_is_a_configuration_error_not_a_bad_key() -> None:
    # 401 LICENSE_NOT_ALLOWED means the policy's authentication_strategy is
    # TOKEN (the default) or NONE, so license-key auth is switched off. It is
    # not a wrong-credential error and must never be retried — before this had
    # its own class it fell through to UnknownTamgaError alongside genuinely
    # unknown codes.
    body = json.dumps(
        {
            "errors": [
                {
                    "id": "e1",
                    "status": "401",
                    "code": "LICENSE_NOT_ALLOWED",
                    "title": "Unauthorized",
                    "detail": "license authentication is not permitted for this policy",
                }
            ]
        }
    ).encode("utf-8")

    error = parse_error_envelope(401, body)

    assert isinstance(error, LicenseNotAllowedError)
    assert not isinstance(error, UnknownTamgaError)
    assert error.status == 401
    assert error.code == "LICENSE_NOT_ALLOWED"
