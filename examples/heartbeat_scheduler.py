"""Machine and process heartbeat scheduling side by side.

Machines and processes have very different heartbeat windows:
- Machines: the window is the license policy's `heartbeat_duration`, and 600s
  (10 min) is only what the server falls back to when that column is unset. Read
  the policy and size the interval from it — `HeartbeatScheduler.for_policy`
  does both — rather than trusting the ~200s default, which is correct only for
  a policy that leaves the column null. Never stop the loop on a heartbeat
  status. A ping response reports the timestamp it just wrote, so it is always
  ALIVE or RESURRECTED; DEAD is real and readable — `machines.get` and a
  checked-out machine file both report it truthfully — but it only ever means
  "last ping older than the window", which the next ping fixes. The one signal
  that the machine is really gone is a 404 from the ping itself, which
  propagates out of `run_forever` for the caller to re-activate on.
- Processes: 30s window with NO resurrection grace period, ping every ~10s.
  Nothing reaps process rows server-side, so stopping the loop does not free the
  process slot — `dispose()` (used here as a context manager) stops the loop and
  deletes the row together.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_ID=... \
        TAMGA_MACHINE_ID=... TAMGA_PROCESS_ID=... python examples/heartbeat_scheduler.py
"""

from __future__ import annotations

import os
import threading
from uuid import UUID

from tamga import TamgaClient, TamgaConfig
from tamga.client import HeartbeatScheduler, ProcessHeartbeatScheduler


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    license_id = UUID(os.environ["TAMGA_LICENSE_ID"])
    machine_id = UUID(os.environ["TAMGA_MACHINE_ID"])
    process_id = UUID(os.environ["TAMGA_PROCESS_ID"])

    client = TamgaClient(TamgaConfig(account_id=account_id, host=host))

    # `licenses.get_policy`, not `policies.get`: the license-scoped route
    # authorizes on `license.read`, which a license key holds. The direct
    # `/policies/{id}` route needs `policy.read`, which it does not.
    policy = client.licenses.get_policy(license_id)
    print(f"Policy heartbeat window: {policy.effective_heartbeat_window_seconds}s")
    if policy.heartbeat_duration is None:
        print("  (the policy sets none — this is the server's 600s fallback)")

    machine_scheduler = HeartbeatScheduler.for_policy(client.machines, machine_id, policy)
    process_scheduler = ProcessHeartbeatScheduler(processes=client.processes, process_id=process_id)

    print(f"Machine heartbeat interval: {machine_scheduler.interval}")
    print(f"Process heartbeat interval: {process_scheduler.interval}")

    # Each scheduler blocks in its own loop — run them on separate threads
    # (or separate processes/async tasks in a real application).
    machine_thread = threading.Thread(target=machine_scheduler.run_forever, daemon=True)
    process_thread = threading.Thread(target=process_scheduler.run_forever, daemon=True)

    # Whatever ends this block — including a crash — the process row is deleted
    # and its slot against `policy.max_processes` is freed. `stop()` alone would
    # leak it, and nothing server-side would ever clean it up.
    with process_scheduler:
        machine_thread.start()
        process_thread.start()
        try:
            machine_thread.join()
            process_thread.join()
        except KeyboardInterrupt:
            machine_scheduler.stop()

    client.close()


if __name__ == "__main__":
    main()
