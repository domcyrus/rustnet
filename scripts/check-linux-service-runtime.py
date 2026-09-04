#!/usr/bin/env python3
"""Run the Linux example with synthetic loopback traffic in a disposable unit.

Requires root and a running systemd manager. Never monitors external traffic.
"""

import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import uuid


def systemctl(*args, check=True):
    return subprocess.run(["systemctl", *args], check=check, capture_output=True, text=True).stdout.strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "run this smoke check as root in a Linux test environment")
    root = Path(__file__).resolve().parent.parent
    template = (root / "resources/packaging/linux/systemd/rustnet-headless.service").read_text()
    name = "rustnet-headless-check-" + uuid.uuid4().hex
    unit_name = name + ".service"
    unit_path = Path("/run/systemd/system") / unit_name
    state_path = Path("/var/lib") / name
    stdout_path = state_path / "headless.jsonl"
    nobody = pwd.getpwnam("nobody").pw_uid

    # ProtectHome hides runner checkouts. Copy the test executable outside home
    # and /tmp, which the unit's PrivateTmp also isolates.
    with tempfile.TemporaryDirectory(prefix=name + "-", dir="/opt") as directory:
        executable = Path(directory) / "rustnet"
        shutil.copyfile(args.binary, executable)
        executable.chmod(0o755)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(1)
            port = receiver.getsockname()[1]
            command = (
                f'{executable} --headless --interface lo --show-localhost '
                f'--bpf-filter "udp port {port}" --no-resolve-dns --no-geoip '
                '--duration 20 --refresh-interval 100 --output jsonl'
            )
            original = next(line for line in template.splitlines() if line.startswith("ExecStart="))
            unit = template.replace(original, "ExecStart=" + command)
            unit = unit.replace("StateDirectory=rustnet", "StateDirectory=" + name)
            unit = unit.replace("/var/lib/rustnet", str(state_path))
            unit = unit.replace("Restart=on-failure", "Restart=no")
            # UnsetEnvironment must override even explicitly inherited identity.
            unit = unit.replace("Type=simple", "Type=simple\nEnvironment=SUDO_UID=12345 SUDO_GID=12345 SUDO_USER=untrusted")
            observed_pids = set()
            observed_uids = set()
            try:
                # Follow the documented first-install prerequisite. stdout may
                # be opened before systemd prepares StateDirectory.
                state_path.mkdir(mode=0o700)
                unit_path.write_text(unit)
                systemctl("daemon-reload")
                systemctl("start", unit_name)
                deadline = time.monotonic() + 30
                saw_nobody = False
                requested_stop = False
                while time.monotonic() < deadline:
                    sender.sendto(b"rustnet-service-check", ("127.0.0.1", port))
                    receiver.recv(128)
                    pid = systemctl("show", "--property=MainPID", "--value", unit_name)
                    observed_pids.add(pid)
                    try:
                        status = Path(f"/proc/{pid}/status").read_text()
                    except FileNotFoundError:
                        status = ""
                    for line in status.splitlines():
                        if line.startswith("Uid:"):
                            uids = tuple(int(value) for value in line.split()[1:])
                            observed_uids.add(uids)
                            real_uid = uids[0]
                            if real_uid:
                                require(real_uid == nobody, f"service selected unexpected UID {real_uid}")
                                saw_nobody = True
                    active = systemctl("show", "--property=ActiveState", "--value", unit_name)
                    if active in ("inactive", "failed"):
                        break
                    if saw_nobody and stdout_path.exists():
                        complete_lines = stdout_path.read_text().splitlines(keepends=True)
                        if any(
                            json.loads(line)["stats"]["packets_processed"] > 0
                            for line in complete_lines
                            if line.endswith("\n")
                        ):
                            systemctl("stop", unit_name)
                            requested_stop = True
                            break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("service did not stop within 30 seconds")

                require(systemctl("show", "--property=ExecMainStatus", "--value", unit_name) == "0", "service exited with an error")
                require(saw_nobody, "did not observe the service drop to nobody")
                require(requested_stop, "service ended before the SIGTERM smoke check")
                for path, mode in ((state_path, 0o700), (stdout_path, 0o600)):
                    info = path.stat()
                    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode, f"unsafe owner or mode: {path}")
                records = [json.loads(line) for line in stdout_path.read_text().splitlines()]
                require(bool(records), "no snapshots captured")
                final = records[-1]
                require(final["runtime"]["status"] == "stopped", "missing clean terminal record")
                require(final["runtime"]["termination_reason"] == "shutdown_requested", "service did not handle the stop request")
                require(final["sandbox"]["uid_dropped"], "privilege drop missing from snapshot")
                require(final["stats"]["packets_processed"] > 0, "synthetic packets were not captured")
                print("systemd service smoke check passed")
            except Exception:
                print(f"Observed service PIDs: {sorted(observed_pids)}", flush=True)
                print(f"Observed real/effective/saved/filesystem UIDs: {sorted(observed_uids)}", flush=True)
                if stdout_path.exists():
                    complete = [line for line in stdout_path.read_text().splitlines(keepends=True) if line.endswith("\n")]
                    if complete:
                        last = json.loads(complete[-1])
                        print(json.dumps({
                            "runtime": last.get("runtime"),
                            "sandbox": last.get("sandbox"),
                            "packets_processed": last.get("stats", {}).get("packets_processed"),
                        }), flush=True)
                subprocess.run(["journalctl", "--no-pager", "-u", unit_name, "-n", "50"], check=False)
                raise
            finally:
                systemctl("stop", unit_name, check=False)
                # Only the randomly named unit's StateDirectory is removed.
                systemctl("clean", "--what=state", unit_name, check=False)
                systemctl("reset-failed", unit_name, check=False)
                unit_path.unlink(missing_ok=True)
                systemctl("daemon-reload")


if __name__ == "__main__":
    main()
