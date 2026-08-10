"""Tests for the JSON:API error envelope parser and typed exception dispatch (plan Section K)."""

from __future__ import annotations

import json

import pytest

from tamga.errors import (
    CheckInNotRequiredError,
    DatasetInvalidError,
    FingerprintTakenError,
    ForbiddenError,
    InternalServerError,
    KeyTakenError,
    LicenseKeyMissingError,
    LicenseNotEncryptedError,
    NotFoundError,
    PidTakenError,
    SchemeNotSupportedError,
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


def test_unknown_code_falls_back_to_unknown_tamga_error() -> None:
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
    error = parse_error_envelope(429, body)
    assert isinstance(error, UnknownTamgaError)
    assert error.code == "TOO_MANY_REQUESTS"


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
