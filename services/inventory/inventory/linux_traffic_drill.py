"""Only an owned fresh user/net namespace can run the fixed loopback TBF drill."""

import json
import os
from pathlib import Path
import sys
import time
from datetime import datetime, timezone
from shared_models.host_collection import digest
from shared_models.linux_traffic_control import DrillAuthorization, DrillResult
from inventory.resource_monitoring import context, ResourceRefused
from inventory.linux_traffic_preflight import TOOLS, bounded_command, tool_pin, parse_qdiscs, json_rows

HANDLE = "7e01:"


def policy(raw):
    return parse_qdiscs(raw, "lo")


def policy_hash(raw):
    return digest([entry.model_dump() for entry in policy(raw).entries])


def own_policy(raw, mbps):
    rows = json_rows(raw, 32)
    roots = [row for row in rows if row.get("root") is True]
    return (
        len(roots) == 1
        and roots[0].get("kind") == "tbf"
        and roots[0].get("handle") == HANDLE
        and roots[0].get("options", {}).get("rate") == mbps * 125000
    )


def clean_policy(raw):
    rows = policy(raw).entries
    return len(rows) == 1 and rows[0].root and rows[0].kind == "noqueue" and rows[0].handle == "0:"


def isolated_command(argv):
    # Keep all namespace tools in the wrapper process group for outer deadline cleanup.
    return bounded_command(argv, new_session=False)


def child(auth, net_fd, user_fd, tool_pins):
    """Inherited namespace handles, not caller-provided names, prove isolation before tc."""
    original = context()
    net_parent = os.fstat(net_fd).st_ino
    user_parent = os.fstat(user_fd).st_ino
    if (
        net_parent != auth.expected_parent_network_namespace_inode
        or original[1] == net_parent
        or os.stat("/proc/self/ns/user").st_ino == user_parent
        or os.geteuid() != 0
        or original[0] != auth.expected_parent_boot_id
        or original[2] != auth.expected_parent_mount_namespace_inode
    ):
        raise ResourceRefused("CHILD_CONTEXT_NOT_ISOLATED")
    now = datetime.now(timezone.utc)
    if not auth.issued_at <= now or (auth.expires_at - now).total_seconds() < auth.duration_seconds + 10:
        raise ResourceRefused("DRILL_WINDOW_TOO_SHORT")
    for tool in ("ip", "tc"):
        tool_pin(tool, expected_sha256=tool_pins[tool])
    links = json_rows(isolated_command([TOOLS["ip"], "-j", "link", "show"]), 1)
    if links[0].get("ifname") != "lo" or links[0].get("ifindex") != 1:
        raise ResourceRefused("NOT_A_FRESH_EMPTY_NETWORK_NAMESPACE")
    isolated_command([TOOLS["ip"], "link", "set", "dev", "lo", "up"])
    show = [TOOLS["tc"], "-j", "-d", "qdisc", "show", "dev", "lo"]
    before = isolated_command(show)
    if not clean_policy(before):
        raise ResourceRefused("CHILD_HAS_EXISTING_POLICY")
    result = {
        "child_namespace_distinct": True,
        "child_network_namespace_inode": original[1],
        "qdisc_applied_in_child": False,
        "rollback_verified_in_child": False,
        "before_qdisc_sha256": policy_hash(before),
        "applied_qdisc_sha256": None,
        "after_qdisc_sha256": None,
    }
    added = False
    try:
        # Never replace: even inside our namespace, an unexpected policy must win over this test.
        isolated_command(
            [
                TOOLS["tc"],
                "qdisc",
                "add",
                "dev",
                "lo",
                "root",
                "handle",
                HANDLE,
                "tbf",
                "rate",
                f"{auth.egress_limit_mbps}mbit",
                "burst",
                "64kb",
                "latency",
                "50ms",
            ]
        )
        added = True
        applied = isolated_command(show)
        if not own_policy(applied, auth.egress_limit_mbps):
            raise ResourceRefused("TBF_READBACK_MISMATCH")
        result.update(qdisc_applied_in_child=True, applied_qdisc_sha256=policy_hash(applied))
        time.sleep(auth.duration_seconds)
    except (OSError, ValueError):
        pass
    finally:
        if added:
            current = isolated_command(show)
            if own_policy(current, auth.egress_limit_mbps) and context() == original:
                isolated_command([TOOLS["tc"], "qdisc", "del", "dev", "lo", "root", "handle", HANDLE])
                after = isolated_command(show)
                result["after_qdisc_sha256"] = policy_hash(after)
                result["rollback_verified_in_child"] = clean_policy(after) and policy_hash(after) == policy_hash(before)
        # Any failure still destroys this namespace when this last process exits; that is not readback proof.
    return result


def run_drill(auth: DrillAuthorization, expected_authorization_sha256):
    auth = DrillAuthorization.model_validate(auth.model_dump())
    if (
        sys.platform != "linux"
        or os.getuid() == 0
        or os.geteuid() == 0
        or digest(auth) != expected_authorization_sha256
    ):
        raise ResourceRefused("ORDINARY_USER_OR_EXACT_PACKET_REQUIRED")
    status = Path("/proc/self/status").read_text()
    for label in ("CapInh:", "CapPrm:", "CapEff:", "CapAmb:"):
        if any(line.startswith(label) and int(line.split()[1], 16) for line in status.splitlines()):
            raise ResourceRefused("CAPABILITY_BEARING_PARENT_REFUSED")
    original = context()
    if original != (
        auth.expected_parent_boot_id,
        auth.expected_parent_network_namespace_inode,
        auth.expected_parent_mount_namespace_inode,
    ):
        raise ResourceRefused("PARENT_CONTEXT_MISMATCH")
    now = datetime.now(timezone.utc)
    if not auth.issued_at <= now or (auth.expires_at - now).total_seconds() < auth.duration_seconds + 10:
        raise ResourceRefused("DRILL_WINDOW_TOO_SHORT")
    result = dict(
        authorization_sha256=digest(auth),
        verdict="REFUSED_OR_FAILED",
        parent_namespace_unchanged=True,
        child_namespace_distinct=False,
        qdisc_applied_in_child=False,
        rollback_verified_in_child=False,
        parent_network_namespace_inode=original[1],
        egress_limit_mbps=auth.egress_limit_mbps,
        duration_seconds=auth.duration_seconds,
        failure="UNSHARE_OR_KERNEL_UNAVAILABLE",
    )
    fds = []
    try:
        TOOLS["unshare"] = "/usr/bin/unshare"
        tool_pin("unshare")
        for path in ("/proc/self/ns/net", "/proc/self/ns/user"):
            fds.append(os.open(path, os.O_RDONLY | os.O_CLOEXEC))
        packet = os.memfd_create("namespace-validation-packet", os.MFD_CLOEXEC)
        fds.append(packet)
        pins = {name: tool_pin(name)["sha256"] for name in ("ip", "tc")}
        os.write(packet, json.dumps({"authorization": auth.model_dump(mode="json"), "tools": pins}).encode())
        os.lseek(packet, 0, os.SEEK_SET)
        import shared_models

        env = {
            "PATH": "/usr/bin:/usr/sbin",
            "LC_ALL": "C",
            "PYTHONPATH": os.pathsep.join(
                (str(Path(__file__).resolve().parents[1]), str(Path(shared_models.__file__).resolve().parents[1]))
            ),
        }
        raw = bounded_command(
            [
                TOOLS["unshare"],
                "--user",
                "--map-root-user",
                "--net",
                "--",
                sys.executable,
                "-m",
                "inventory.linux_traffic_drill",
                str(packet),
                str(fds[0]),
                str(fds[1]),
            ],
            timeout=auth.duration_seconds + 20,
            pass_fds=tuple(fds),
            env=env,
        )
        data = json.loads(raw)
        allowed = {
            "child_namespace_distinct",
            "child_network_namespace_inode",
            "qdisc_applied_in_child",
            "rollback_verified_in_child",
            "before_qdisc_sha256",
            "applied_qdisc_sha256",
            "after_qdisc_sha256",
        }
        if not isinstance(data, dict) or set(data) != allowed:
            raise ValueError("Child result shape")
        result.update(data)
        if data["qdisc_applied_in_child"] and data["rollback_verified_in_child"]:
            result.update(verdict="APPLIED_AND_ROLLED_BACK_IN_OWNED_NAMESPACE", failure="NONE")
        else:
            result["failure"] = "CHILD_REFUSED_OR_FAILED"
    except (OSError, ValueError) as error:
        result["failure"] = "TIMEOUT" if "TIMEOUT" in str(error) else "UNSHARE_OR_KERNEL_UNAVAILABLE"
    finally:
        for fd in fds:
            os.close(fd)
    if context() != original:
        result.update(parent_namespace_unchanged=False, verdict="REFUSED_OR_FAILED", failure="PARENT_CONTEXT_CHANGED")
    return DrillResult.model_validate(result)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 4:
            raise ValueError("Internal child invocation only")
        packet_fd, net_fd, user_fd = map(int, sys.argv[1:])
        raw = os.read(packet_fd, 65537)
        if len(raw) > 65536:
            raise ValueError("Packet budget")
        envelope = json.loads(raw)
        value = DrillAuthorization.model_validate_json(json.dumps(envelope["authorization"]))
        print(json.dumps(child(value, net_fd, user_fd, envelope["tools"]), sort_keys=True))
    except (OSError, ValueError):
        sys.exit(64)
