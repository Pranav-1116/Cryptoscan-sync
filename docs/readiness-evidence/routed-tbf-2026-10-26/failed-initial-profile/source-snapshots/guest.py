"""PID-1-child fixture: all links/namespaces are created INSIDE a NIC-less VM."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

IP, TC, HANDLE = "/sbin/ip", "/sbin/tc", "7e02:"
ROOT = Path("/tmp/routed")


def cmd(args, check=True):
    p = subprocess.run(
        args, stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env={"PATH": "/bin:/sbin", "LC_ALL": "C"}
    )
    if len(p.stdout) + len(p.stderr) > 65536 or (check and p.returncode):
        raise ValueError("fixed guest command failed: " + repr(args) + " " + p.stderr.decode(errors="replace")[:300])
    return p.stdout


def ip(*args):
    return cmd([IP, *map(str, args)])


def gw(*args):
    return [IP, "netns", "exec", "gw", *map(str, args)]


def read(args):
    raw = cmd(args)
    # This pinned tc emits no bytes (exit 0) for an empty class listing.
    # Never normalize a failed command or an empty qdisc/filter/route source.
    if not raw.strip() and TC in args and "class" in args and "show" in args:
        return []
    try:
        return json.loads(raw)
    except ValueError as exc:
        if TC in args and "class" in args and "show" in args:
            # This tc version also emits TEXT for nonempty class trees. Preserve it
            # as an unresolved nonempty source: always blocks, never infer absence.
            return [{"unsupported_class_encoding": raw.decode(errors="replace")}]
        raise ValueError("invalid JSON source: " + repr(args) + " " + repr(raw[:100])) from exc


def write(name, obj):
    p = ROOT / (name + ".tmp")
    p.write_text(json.dumps(obj, sort_keys=True))
    p.replace(ROOT / name)


def policy(dev="ge"):
    return read(gw(TC, "-j", "-s", "-d", "qdisc", "show", "dev", dev))


def identity(dev="ge"):
    rows = read(gw(IP, "-j", "link", "show", "dev", dev))
    if len(rows) != 1:
        raise ValueError("interface identity unresolved")
    return rows[0]["ifindex"]


def fingerprint(rows):
    # Counters legitimately advance; policy identity/options must not change.
    return hashlib.sha256(
        json.dumps(
            [{k: r.get(k) for k in ("kind", "handle", "root", "parent", "options")} for r in rows], sort_keys=True
        ).encode()
    ).hexdigest()


def clean(rows):
    return len(rows) == 1 and rows[0].get("kind") == "noqueue" and rows[0].get("handle") == "0:"


def owned(rows, rate):
    return (
        len(rows) == 1
        and rows[0].get("kind") == "tbf"
        and rows[0].get("handle") == HANDLE
        and rows[0].get("options", {}).get("rate") == rate * 125000
    )


def safety(target="ge", destinations=("10.78.1.2",)):
    checks = {"target": target, "destinations": list(destinations), "blockers": []}
    if target != "ge" or destinations != ("10.78.1.2",):
        checks["blockers"].append("UNAPPROVED_TARGET_OR_MANAGEMENT_SET")
    for kind in ("qdisc", "class", "filter"):
        checks[kind] = read(gw(TC, "-j", "-d", kind, "show", "dev", target))
    checks["ingress_filters"] = read(gw(TC, "-j", "filter", "show", "dev", target, "ingress"))
    checks["egress_filters"] = read(gw(TC, "-j", "filter", "show", "dev", target, "egress"))
    if not clean(checks["qdisc"]) or any(checks[k] for k in ("class", "filter", "ingress_filters", "egress_filters")):
        checks["blockers"].append("EXISTING_POLICY_OR_FILTER")
    checks["rules"] = read(gw(IP, "-j", "rule", "show"))
    if [(r.get("priority"), r.get("table")) for r in checks["rules"]] != [
        (0, "local"),
        (32766, "main"),
        (32767, "default"),
    ]:
        checks["blockers"].append("UNSUPPORTED_POLICY_ROUTING")
    checks["routes"] = read(gw(IP, "-j", "route", "show", "table", "all"))
    if any("nexthops" in r or r.get("type") in ("blackhole", "unreachable", "prohibit") for r in checks["routes"]):
        checks["blockers"].append("AMBIGUOUS_OR_UNSUPPORTED_ROUTE")
    checks["management_routes"] = [read(gw(IP, "-j", "route", "get", d)) for d in destinations]
    if any(
        len(r) != 1 or r[0].get("dev") != "gm" or r[0].get("gateway") or r[0].get("nexthops")
        for r in checks["management_routes"]
    ):
        checks["blockers"].append("MANAGEMENT_PATH_NOT_EXCLUDED")
    checks["ifindex"] = identity(target)
    checks["allowed"] = not checks["blockers"]
    return checks


def add(rate):
    check = safety()
    if not check["allowed"]:
        raise ValueError("unsafe policy installation")
    cmd(
        gw(
            TC,
            "qdisc",
            "add",
            "dev",
            "ge",
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
        )
    )
    row = policy()
    if not owned(row, rate):
        raise ValueError("installed readback mismatch")
    return check, row


def rollback(rate, index, expected):
    if identity() != index:
        return "REFUSED_IDENTITY_CHANGED"
    row = policy()
    if not owned(row, rate) or fingerprint(row) != expected:
        return "REFUSED_POLICY_CONFLICT"
    cmd(gw(TC, "qdisc", "del", "dev", "ge", "root", "handle", HANDLE))
    return "RECOVERED" if clean(policy()) else "ROLLBACK_READBACK_FAILED"


def pair(ns1, dev1, address1, ns2, dev2, address2):
    ip("link", "add", dev1, "type", "veth", "peer", "name", dev2)
    ip("link", "set", dev1, "netns", ns1)
    ip("link", "set", dev2, "netns", ns2)
    for ns, dev, address in ((ns1, dev1, address1), (ns2, dev2, address2)):
        ip("-n", ns, "addr", "add", address + "/24", "dev", dev)
        ip("-n", ns, "link", "set", dev, "up")


def topology():
    for ns in ("tx", "gw", "rx", "mgmt"):
        ip("netns", "add", ns)
        ip("-n", ns, "link", "set", "lo", "up")
    pair("tx", "s0", "10.77.1.2", "gw", "gi", "10.77.1.1")
    pair("gw", "ge", "10.77.2.1", "rx", "r0", "10.77.2.2")
    pair("mgmt", "m0", "10.78.1.2", "gw", "gm", "10.78.1.1")
    ip("-n", "tx", "route", "add", "10.77.2.0/24", "via", "10.77.1.1")
    ip("-n", "rx", "route", "add", "10.77.1.0/24", "via", "10.77.2.1")
    cmd(gw("/bin/busybox", "sysctl", "-w", "net.ipv4.ip_forward=1"))
    # Separate test-harness-owned policy: the enforcement controller must never alter it.
    cmd(gw(TC, "qdisc", "add", "dev", "gi", "root", "handle", "9b:", "pfifo", "limit", "1000"))
    return {n: read([IP, "-n", n, "-j", "addr", "show"]) for n in ("tx", "gw", "rx", "mgmt")}


def spawn(ns, *args):
    return subprocess.Popen(
        [IP, "netns", "exec", ns, *map(str, args)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/bin:/sbin", "LC_ALL": "C"},
    )


def collect(p, timeout=18):
    raw, err = p.communicate(timeout=timeout)
    if p.returncode or len(raw) + len(err) > 65536:
        raise ValueError("probe failed: " + err.decode(errors="replace")[:300])
    return json.loads(raw)


def phase(label, protocol="udp", payload=1200, flows=1, burst=1, rate=None):
    original = policy()
    check, applied = add(rate) if rate else (safety(), original)
    if not check["allowed"]:
        raise ValueError("baseline safety failed")
    index = identity()
    start = time.monotonic_ns() + 600_000_000
    suffix = [protocol, payload, flows, burst, 10, start]
    receiver = spawn("rx", "/probe", "receive", *suffix, "10.77.2.2")
    time.sleep(0.12)
    management = spawn("mgmt", "/probe", "latency", "10.78.1.1", start, 12)
    latency = spawn("tx", "/probe", "latency", "10.77.2.2", start, 12)
    sender = spawn("tx", "/probe", "send", *suffix, "10.77.2.2")
    try:
        sent, received = collect(sender), collect(receiver)
        after = policy()
        data_latency, management_latency = collect(latency), collect(management)
    finally:
        for p in (sender, receiver, latency, management):
            if p.poll() is None:
                p.kill()
            p.wait()
        if rate:
            status = rollback(rate, index, fingerprint(applied))
            if status != "RECOVERED":
                raise ValueError(status)
    return {
        "label": label,
        "protocol": protocol,
        "payload": payload,
        "flows": flows,
        "burst_packets": burst,
        "rate_mbps": rate,
        "preflight": check,
        "applied": applied,
        "after": after,
        "restored": policy(),
        "sender": sent,
        "receiver": received,
        "data_latency": data_latency,
        "management": management_latency,
        "started_ns": start,
        "finished_ns": time.monotonic_ns(),
        "ifindex": index,
    }


def controller(mode):
    check, rows = add(10)
    now = time.monotonic()
    write(
        "state",
        {
            "ifindex": check["ifindex"],
            "fingerprint": fingerprint(rows),
            "rate": 10,
            "expires": now + (0.8 if mode == "expired_authorization" else 20),
            "installed": rows,
        },
    )
    while True:
        if mode != "lost_connection" or time.monotonic() - now < 0.2:
            write("heartbeat", {"at": time.monotonic()})
        time.sleep(0.1)


def watchdog():
    start = time.monotonic()
    state = json.loads((ROOT / "state").read_text())
    while time.monotonic() - start < 8:
        now = time.monotonic()
        try:
            heartbeat = json.loads((ROOT / "heartbeat").read_text())["at"]
        except FileNotFoundError:
            heartbeat = start
        if now >= state["expires"] or now - heartbeat > 0.8:
            status = rollback(state["rate"], state["ifindex"], state["fingerprint"])
            write(
                "watchdog", {"status": status, "finished": time.monotonic(), "policy": policy(), "ifindex": identity()}
            )
            return
        time.sleep(0.05)
    write("watchdog", {"status": "WATCHDOG_DEADLINE_EXCEEDED", "finished": time.monotonic()})


def fault(mode):
    for name in ("state", "heartbeat", "watchdog"):
        (ROOT / name).unlink(missing_ok=True)
    controller_process = subprocess.Popen(["/bin/python3.11", "-I", "-S", "/guest.py", "controller", mode])
    deadline = time.monotonic() + 3
    while not (ROOT / "state").exists():
        if time.monotonic() > deadline or controller_process.poll() is not None:
            raise ValueError("controller did not install")
        time.sleep(0.02)
    state = json.loads((ROOT / "state").read_text())
    watch = subprocess.Popen(["/bin/python3.11", "-I", "-S", "/guest.py", "watchdog"])
    management = spawn("mgmt", "/probe", "latency", "10.78.1.1", time.monotonic_ns() + 100_000_000, 3)
    injected = time.monotonic()
    foreign = None
    if mode == "controller_crash":
        controller_process.kill()
    elif mode == "interface_recreation":
        cmd(gw(IP, "link", "del", "ge"))
        pair("gw", "ge", "10.77.2.1", "rx", "r0", "10.77.2.2")
        cmd(gw(TC, "qdisc", "add", "dev", "ge", "root", "handle", "8a:", "pfifo", "limit", "321"))
        foreign = policy()
        controller_process.kill()
    elif mode == "policy_conflict":
        cmd(gw(TC, "qdisc", "replace", "dev", "ge", "root", "handle", "8a:", "pfifo", "limit", "321"))
        foreign = policy()
        controller_process.kill()
    try:
        watch.wait(timeout=6)
        observed = json.loads((ROOT / "watchdog").read_text())
        result = {
            "case": mode,
            "injected": injected,
            "state": state,
            "watchdog": observed,
            "response_seconds": observed["finished"] - injected,
            "foreign_before": foreign,
            "foreign_after": policy() if foreign else None,
            "management": collect(management),
        }
    finally:
        for p in (controller_process, watch, management):
            if p.poll() is None:
                p.kill()
            p.wait()
    # Harness cleanup is separate from controller recovery. Never count it as successful withdrawal.
    if foreign:
        if fingerprint(policy()) != fingerprint(foreign):
            raise ValueError("foreign policy changed")
        cmd(gw(TC, "qdisc", "del", "dev", "ge", "root", "handle", "8a:"))
    if not foreign:
        result["recovery_probe"] = phase("fault_" + mode + "_recovery")
    else:
        result["recovery_probe"] = None
    result["harness_cleanup_separate"] = True
    return result


def negative_cases():
    results = []

    def capture(label, check):
        before = fingerprint(policy())
        result = check()
        results.append({"case": label, "preflight": result, "policy_preserved": before == fingerprint(policy())})
        if result["allowed"]:
            raise ValueError("unsafe case was allowed")

    cmd(gw(TC, "qdisc", "add", "dev", "ge", "root", "handle", "8a:", "htb", "default", "1"))
    cmd(gw(TC, "class", "add", "dev", "ge", "parent", "8a:", "classid", "8a:1", "htb", "rate", "20mbit"))
    cmd(
        gw(
            TC,
            "filter",
            "add",
            "dev",
            "ge",
            "parent",
            "8a:",
            "protocol",
            "ip",
            "prio",
            "1",
            "u32",
            "match",
            "ip",
            "dst",
            "10.77.2.2/32",
            "flowid",
            "8a:1",
        )
    )
    capture("existing_class_filter_tree", safety)
    cmd(gw(TC, "qdisc", "del", "dev", "ge", "root", "handle", "8a:"))
    cmd(gw(TC, "qdisc", "add", "dev", "ge", "clsact"))
    cmd(gw(TC, "filter", "add", "dev", "ge", "egress", "protocol", "ip", "prio", "1", "matchall", "action", "pass"))
    capture("existing_clsact_filter", safety)
    cmd(gw(TC, "qdisc", "del", "dev", "ge", "clsact"))
    capture("management_interface_target", lambda: safety("gm"))
    capture("unapproved_management_set", lambda: safety(destinations=("10.77.2.2",)))
    cmd(gw(IP, "rule", "add", "priority", "100", "from", "10.77.1.2", "table", "100"))
    capture("policy_routing_ambiguity", safety)
    cmd(gw(IP, "rule", "del", "priority", "100"))
    cmd(
        gw(
            IP,
            "route",
            "add",
            "10.78.1.2/32",
            "nexthop",
            "via",
            "10.77.1.2",
            "dev",
            "gi",
            "weight",
            "1",
            "nexthop",
            "via",
            "10.77.2.2",
            "dev",
            "ge",
            "weight",
            "1",
        )
    )
    capture("multipath_management_route", safety)
    cmd(gw(IP, "route", "del", "10.78.1.2/32"))
    return results


def guard():
    if os.geteuid() != 0 or not Path("/DISPOSABLE_TBF_VM").is_file():
        raise ValueError("guest only")
    args = Path("/proc/cmdline").read_text().split()
    nonce = [a.split("=", 1)[1] for a in args if a.startswith("cryptoscan_tbf_nonce=")]
    if len(nonce) != 1 or not re.fullmatch("[a-f0-9]{64}", nonce[0]):
        raise ValueError("fixed VM nonce required")
    return nonce[0]


def main():
    nonce = guard()
    if len(sys.argv) > 1:
        if sys.argv[1] == "controller":
            controller(sys.argv[2])
        elif sys.argv[1] == "watchdog":
            watchdog()
        else:
            raise ValueError("unknown fixture role")
        return
    if os.getppid() != 1 or [r["ifname"] for r in read([IP, "-j", "link", "show"])] != ["lo"]:
        raise ValueError("diskless NIC-less guest required")
    ROOT.mkdir(mode=0o700)
    Path("/run/netns").mkdir(parents=True)
    result = {
        "schema_version": "cryptoscan.routed-tbf-guest/v1",
        "nonce": nonce,
        "kernel": os.uname().release,
        "topology": topology(),
        "phases": [],
        "faults": [],
        "negative_cases": [],
    }
    echo = [spawn("rx", "/probe", "echo", "10.77.2.2"), spawn("gw", "/probe", "echo", "10.78.1.1")]
    result["unrelated_before"] = policy("gi")
    result["management_policy_before"] = policy("gm")
    try:
        result["negative_cases"] = negative_cases()
        matrix = [
            ("udp_baseline", "udp", 1200, 1, 1, None),
            ("tcp_baseline", "tcp", 1200, 4, 1, None),
            ("udp_10", "udp", 1200, 1, 1, 10),
            ("udp_5", "udp", 1200, 1, 1, 5),
            ("udp_small_burst", "udp", 256, 1, 16, 10),
            ("udp_large_burst", "udp", 1400, 1, 16, 10),
            ("tcp_one_10", "tcp", 1200, 1, 1, 10),
            ("tcp_four_10", "tcp", 1200, 4, 1, 10),
            ("tcp_four_5", "tcp", 1200, 4, 1, 5),
            ("udp_recovered", "udp", 1200, 1, 1, None),
            ("tcp_recovered", "tcp", 1200, 4, 1, None),
        ]
        for entry in matrix:
            row = phase(*entry)
            result["phases"].append(row)
            print("CRYPTOSCAN_ROUTED_PHASE=" + json.dumps(row, sort_keys=True), flush=True)
        for mode in (
            "controller_crash",
            "lost_connection",
            "expired_authorization",
            "interface_recreation",
            "policy_conflict",
        ):
            result["faults"].append(fault(mode))
        result["unrelated_after"] = policy("gi")
        result["management_policy_after"] = policy("gm")
        result["final_policy"] = policy()
    finally:
        for p in echo:
            p.terminate()
            p.wait(timeout=2)
    result["finished_ns"] = time.monotonic_ns()
    print("CRYPTOSCAN_ROUTED_RESULT=" + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("CRYPTOSCAN_ROUTED_FAILURE=" + type(exc).__name__ + ":" + str(exc), flush=True)
        sys.exit(2)
