"""Fixed read-only iproute2 preflight, bounded output, no shell or device writes."""

from datetime import datetime, timezone
import hashlib
import errno
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from shared_models.host_collection import digest
from shared_models.linux_traffic_control import PreflightSpec, TrafficPreflight, LinkReading, QdiscReading, RouteReading
from inventory.resource_monitoring import context, ResourceRefused

TOOLS = {"ip": "/usr/bin/ip", "tc": "/usr/sbin/tc"}
MAX_OUTPUT = 65536


def tool_pin(tool, *, expected_sha256=None):
    path = TOOLS[tool]
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or (expected_sha256 is None and info.st_uid != 0)
            or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
            or info.st_size > 4 * 1024 * 1024
        ):
            raise ResourceRefused("UNTRUSTED_IPROUTE_TOOL")
        try:
            os.getxattr(fd, "security.capability")
        except OSError as error:
            if error.errno not in (errno.ENODATA, errno.ENOTSUP):
                raise ResourceRefused("TOOL_CAPABILITY_CHECK_UNAVAILABLE") from None
        else:
            raise ResourceRefused("CAPABILITY_BEARING_TOOL_REFUSED")
        raw = bytearray()
        while len(raw) <= 4 * 1024 * 1024:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != info.st_size:
            raise ResourceRefused("TOOL_CHANGED")
        value = {"tool": tool, "sha256": hashlib.sha256(raw).hexdigest()}
        if expected_sha256 is not None and value["sha256"] != expected_sha256:
            raise ResourceRefused("TOOL_PIN_CHANGED")
        return value
    finally:
        os.close(fd)


def bounded_command(argv, timeout=2, *, pass_fds=(), env=None, new_session=True):
    """Known root-owned tools only; stop and reap this process group on output/time bound."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env or {"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
        start_new_session=new_session,
        close_fds=True,
        pass_fds=pass_fds,
    )
    result = bytearray()
    count = 0
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, True)
        selector.register(process.stderr, selectors.EVENT_READ, False)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResourceRefused("COMMAND_TIMEOUT")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                count += len(chunk)
                if count > MAX_OUTPUT:
                    raise ResourceRefused("COMMAND_OUTPUT_BUDGET")
                if key.data:
                    result.extend(chunk)
        status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if status:
            raise ResourceRefused("COMMAND_REFUSED")
        return bytes(result)
    finally:
        selector.close()
        if process.poll() is None:
            if new_session:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


def json_rows(raw, maximum):
    if len(raw) > MAX_OUTPUT:
        raise ValueError("JSON budget")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON field")
            value[key] = item
        return value

    value = json.loads(
        raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON"))
    )
    if not isinstance(value, list) or not 1 <= len(value) <= maximum or any(not isinstance(v, dict) for v in value):
        raise ValueError("Expected bounded nonempty object list")
    return value


def parse_link(raw, interface):
    rows = json_rows(raw, 1)
    row = rows[0]
    if row.get("ifname") != interface:
        raise ValueError("Unexpected link")
    info = row.get("linkinfo", {})
    if not isinstance(info, dict):
        raise ValueError("Invalid link metadata")
    return LinkReading(
        status="MEASURED",
        source_sha256=hashlib.sha256(raw).hexdigest(),
        interface=interface,
        ifindex=row.get("ifindex"),
        kind=info.get("info_kind") or row.get("link_type") or "unknown",
    )


def parse_qdiscs(raw, interface):
    rows = json_rows(raw, 32)
    entries = []
    for row in rows:
        if row.get("dev", interface) != interface or not isinstance(row.get("options", {}), dict):
            raise ValueError("Unexpected qdisc")
        entries.append(
            {
                "kind": row.get("kind"),
                "handle": row.get("handle"),
                "root": row.get("root", False),
                "options_sha256": digest(row.get("options", {})),
            }
        )
    return QdiscReading(status="MEASURED", source_sha256=hashlib.sha256(raw).hexdigest(), entries=entries)


def parse_route(raw, destination):
    rows = json_rows(raw, 1)
    row = rows[0]
    if row.get("type", "unicast") not in {"unicast", "local"} or any(k in row for k in ("nexthops", "multipath")):
        raise ValueError("Unsupported/ambiguous route")
    if row.get("dst") != destination:
        raise ValueError("Route source destination mismatch")
    # `ip route get` returns a single effective egress selection, not a path probe.
    return RouteReading(
        destination=destination,
        status="MEASURED",
        source_sha256=hashlib.sha256(raw).hexdigest(),
        interface=row.get("dev"),
    )


def collect_preflight(spec: PreflightSpec, expected_spec_sha256):
    spec = PreflightSpec.model_validate(spec.model_dump())
    if sys.platform != "linux" or os.geteuid() == 0 or digest(spec) != expected_spec_sha256:
        raise ResourceRefused("ORDINARY_USER_OR_REQUEST_REQUIRED")
    start = datetime.now(timezone.utc)
    if not spec.issued_at <= start < spec.expires_at:
        raise ResourceRefused("PREFLIGHT_WINDOW")
    original_context = context()
    pins = [tool_pin(name) for name in ("ip", "tc")]

    def reading(argv, parser, fallback):
        try:
            return parser(bounded_command(argv))
        except PermissionError:
            return fallback("DENIED")
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, RecursionError):
            return fallback("INVALID")

    link = reading(
        [TOOLS["ip"], "-j", "-d", "link", "show", "dev", spec.interface],
        lambda raw: parse_link(raw, spec.interface),
        lambda s: LinkReading(status=s),
    )
    qdiscs = reading(
        [TOOLS["tc"], "-j", "-d", "qdisc", "show", "dev", spec.interface],
        lambda raw: parse_qdiscs(raw, spec.interface),
        lambda s: QdiscReading(status=s),
    )
    routes = []
    for ip in spec.management_ips:
        family = "-6" if ":" in ip else "-4"
        routes.append(
            reading(
                [TOOLS["ip"], family, "-j", "route", "get", ip],
                lambda raw: parse_route(raw, ip),
                lambda s: RouteReading(destination=ip, status=s),
            )
        )
    if context() != original_context or pins != [tool_pin(name) for name in ("ip", "tc")]:
        raise ResourceRefused("PREFLIGHT_CONTEXT_OR_TOOL_CHANGED")
    return TrafficPreflight(
        spec=spec,
        started_at=start,
        finished_at=datetime.now(timezone.utc),
        boot_id=original_context[0],
        network_namespace_inode=original_context[1],
        mount_namespace_inode=original_context[2],
        tools=pins,
        link=link,
        qdiscs=qdiscs,
        routes=routes,
    )
