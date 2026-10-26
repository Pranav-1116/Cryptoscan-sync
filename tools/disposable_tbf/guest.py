"""PID-1-owned diskless VM fixture. Never invoke as a host traffic controller."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

TC = "/sbin/tc"
IP = "/sbin/ip"
HANDLE = "7e01:"


def command(args):
    value = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=8,
        env={"PATH": "/bin:/sbin", "LC_ALL": "C"},
        check=True,
    )
    if len(value.stdout) + len(value.stderr) > 65536:
        raise ValueError("guest command output budget")
    return value.stdout


def qdisc():
    value = json.loads(command([TC, "-j", "-s", "-d", "qdisc", "show", "dev", "lo"]))
    if not isinstance(value, list) or len(value) != 1 or value[0].get("root") is not True:
        raise ValueError("one exact loopback root required")
    return value[0]


def clean(row):
    return row.get("kind") == "noqueue" and row.get("handle") == "0:"


def owned(row, rate):
    return (
        row.get("kind") == "tbf" and row.get("handle") == HANDLE and row.get("options", {}).get("rate") == rate * 125000
    )


def policy_hash(row):
    return hashlib.sha256(
        json.dumps(
            {k: row.get(k) for k in ("kind", "handle", "root", "options")}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def measure():
    return json.loads(command(["/probe", os.urandom(16).hex()]))


def main():
    # Both the fixed launch and this guest-only marker are checked; this is not a host option.
    cmdline = Path("/proc/cmdline").read_text().split()
    nonce = [v.split("=", 1)[1] for v in cmdline if v.startswith("cryptoscan_tbf_nonce=")]
    if (
        os.getppid() != 1
        or os.geteuid() != 0
        or len(nonce) != 1
        or not re.fullmatch("[0-9a-f]{64}", nonce[0])
        or not Path("/DISPOSABLE_TBF_VM").exists()
    ):
        raise ValueError("not the disposable VM fixture")
    links = json.loads(command([IP, "-j", "link", "show"]))
    if len(links) != 1 or links[0].get("ifname") != "lo" or links[0].get("ifindex") != 1:
        raise ValueError("guest must have no network adapters")
    command([IP, "link", "set", "dev", "lo", "up"])
    before = qdisc()
    if not clean(before):
        raise ValueError("unexpected initial policy")
    result = {
        "schema_version": "cryptoscan.disposable-tbf-guest/v1",
        "nonce": nonce[0],
        "kernel_release": os.uname().release,
        "interface": "lo",
        "baseline_policy": before,
        "baseline": measure(),
        "caps": [],
        "rollback_verified": False,
    }
    for rate in (10, 5):
        initial = qdisc()
        if not clean(initial) or policy_hash(initial) != policy_hash(before):
            raise ValueError("policy not restored before trial")
        installed = False
        try:
            command(
                [
                    TC,
                    "qdisc",
                    "add",
                    "dev",
                    "lo",
                    "root",
                    "handle",
                    HANDLE,
                    "tbf",
                    "rate",
                    f"{rate}mbit",
                    "burst",
                    "64kb",
                    "latency",
                    "50ms",
                ]
            )
            installed = True
            applied = qdisc()
            if not owned(applied, rate):
                raise ValueError("installed policy mismatch")
            sample = measure()
            end = qdisc()
            if not owned(end, rate):
                raise ValueError("policy changed during measurement")
        finally:
            if installed:
                current = qdisc()
                if not owned(current, rate):
                    raise ValueError("unowned policy: refuse deletion; VM must be destroyed")
                command([TC, "qdisc", "del", "dev", "lo", "root", "handle", HANDLE])
        restored = qdisc()
        if not clean(restored) or policy_hash(restored) != policy_hash(before):
            raise ValueError("rollback readback mismatch")
        result["caps"].append(
            {
                "rate_mbps": rate,
                "applied": applied,
                "after_measurement": end,
                "measurement": sample,
                "restored_policy": restored,
            }
        )
    result["restored"] = measure()
    result["final_policy"] = qdisc()
    result["rollback_verified"] = clean(result["final_policy"]) and policy_hash(result["final_policy"]) == policy_hash(
        before
    )
    result["guest_monotonic_finished_ns"] = time.monotonic_ns()
    print("CRYPTOSCAN_TBF_RESULT=" + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("CRYPTOSCAN_TBF_FAILURE=GUEST_REFUSED_OR_FAILED", flush=True)
        sys.exit(2)
