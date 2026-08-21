"""Validate a license by key, and by ID with a scope.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_KEY=... \
        python examples/validate_license.py
"""

from __future__ import annotations

import os
from uuid import UUID

from tamga import TamgaClient, TamgaConfig
from tamga.models.license import LicenseScope


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    license_key = os.environ["TAMGA_LICENSE_KEY"]

    with TamgaClient(TamgaConfig(account_id=account_id, host=host)) as client:
        # 1. Validate by key — no scope support on this endpoint.
        result = client.licenses.validate_by_key(license_key)
        print("validate_by_key:", result.meta.code, result.meta.detail)

        if result.license is None:
            return

        # 2. Validate by ID with a scope. Six fields are enforced:
        #    product/policy/user/environment, plus entitlements (codes,
        #    case-insensitive) and fingerprint (matches any machine on the
        #    license — this is the anti-key-sharing check). `version` and
        #    `checksum` are deprecated and never sent: the server rejects the
        #    whole call with 422 SCOPE_NOT_SUPPORTED if either is present.
        product_id = os.environ.get("TAMGA_PRODUCT_ID")
        scope = LicenseScope(product=UUID(product_id)) if product_id else None
        scoped_result = client.licenses.validate_by_id(
            result.license.id, scope=scope, skip_touch=True
        )
        print("validate_by_id:", scoped_result.meta.code, scoped_result.meta.detail)

        # 3. Quick-validate — a lightweight GET, flat JSON response, no
        #    embedded license resource. Note the server skips the
        #    `last_validated_at` write if the request carries an `Origin`
        #    header (this SDK never sends one, but a proxy might), and the
        #    response looks identical either way.
        quick_result = client.licenses.quick_validate(result.license.id)
        print("quick_validate:", quick_result.meta.code, quick_result.meta.valid)


if __name__ == "__main__":
    main()
