"""Create a machine, then validate the license, handling an over-limit rollback.

A limit can stop the activation at either of two points, and `activate_machine`
handles both:

- At creation, with a `422` (`MACHINE_LIMIT_EXCEEDED` and friends) — no row was
  created, so there is nothing to roll back.
- At validation, when the policy's overage strategy let the create through — the
  row exists and is deleted before the error is raised.

Either way the caller sees one `ValueError` naming the equivalent
`ValidationCode`, so there is one branch to write instead of two.

`memory` and `disk`, if reported, are in **megabytes**.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_ID=... \
        TAMGA_MACHINE_FINGERPRINT=... python examples/machine_activation_flow.py
"""

from __future__ import annotations

import os
import platform
from uuid import UUID

from tamga import TamgaClient, TamgaConfig


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    license_id = UUID(os.environ["TAMGA_LICENSE_ID"])
    fingerprint = os.environ["TAMGA_MACHINE_FINGERPRINT"]

    with TamgaClient(TamgaConfig(account_id=account_id, host=host)) as client:
        try:
            machine = client.machines.activate_machine(
                license_id,
                fingerprint,
                name=platform.node(),
                platform=platform.system(),
                cores=os.cpu_count(),
            )
        except ValueError as exc:
            # activate_machine has already cleaned up whatever needed cleaning
            # up: it deletes the machine row when the create succeeded and only
            # validation rejected it, and skips the delete when the create
            # itself was refused. No manual cleanup here either way.
            print("Activation rejected:", exc)
            return

        print("Machine activated:", machine.id, machine.heartbeat_status)


if __name__ == "__main__":
    main()
