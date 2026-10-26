"""Fixed read-only argv and bounded malformed/failed source behavior."""

import json
import sys
import pytest
from inventory import linux_traffic_preflight as core
from shared.shared_models.tests.test_linux_traffic_control import spec
from shared_models.host_collection import digest


def raw(value):
    return json.dumps(value).encode()


@pytest.mark.parametrize("data", [b"[]", b"{}", b'[{"kind":"x","kind":"y"}]', b"NaN", b"x" * 65537])
def test_qdisc_invalid_is_not_clean(data):
    with pytest.raises(ValueError):
        core.parse_qdiscs(data, "lo")


@pytest.mark.parametrize("route", [{"dev": "lo", "type": "blackhole"}, {"dev": "lo", "nexthops": [{}]}, {}])
def test_route_needs_unambiguous_effective_device(route):
    with pytest.raises(ValueError):
        core.parse_route(raw([route]), "127.0.0.1")


def test_bounded_command_output_and_timeout():
    with pytest.raises(ValueError, match="BUDGET"):
        core.bounded_command([sys.executable, "-c", "print('x'*70000)"])
    with pytest.raises(ValueError, match="TIMEOUT"):
        core.bounded_command([sys.executable, "-c", "import time;time.sleep(5)"], timeout=0.05)


def test_collection_fixed_readonly_commands(monkeypatch):
    value = spec()
    calls = []
    monkeypatch.setattr(core.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(core, "context", lambda: (value.expected_boot_id, 1, 2))
    monkeypatch.setattr(core, "tool_pin", lambda name: {"tool": name, "sha256": "d" * 64})

    def command(argv):
        calls.append(argv)
        if "link" in argv:
            return raw([{"ifname": "lo", "ifindex": 1, "link_type": "loopback"}])
        if "qdisc" in argv:
            return raw([{"kind": "noqueue", "handle": "0:", "root": True}])
        return raw([{"dev": "lo", "dst": "127.0.0.1"}])

    monkeypatch.setattr(core, "bounded_command", command)
    result = core.collect_preflight(value, digest(value))
    assert result.link.status == "MEASURED" and not result.configuration_changed
    assert all("show" in call or "get" in call for call in calls)
    assert calls[-1][-1] == "127.0.0.1"


def test_failed_commands_are_retained(monkeypatch):
    value = spec()
    monkeypatch.setattr(core.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(core, "context", lambda: (value.expected_boot_id, 1, 2))
    monkeypatch.setattr(core, "tool_pin", lambda name: {"tool": name, "sha256": "d" * 64})

    def denied(_):
        raise PermissionError()

    monkeypatch.setattr(core, "bounded_command", denied)
    result = core.collect_preflight(value, digest(value))
    assert result.link.status == result.qdiscs.status == result.routes[0].status == "DENIED"


def test_route_destination_cannot_be_substituted():
    with pytest.raises(ValueError):
        core.parse_route(raw([{"dst": "192.0.2.1", "dev": "lo"}]), "127.0.0.1")


def test_tool_pins_never_follow_symlinks(tmp_path, monkeypatch):
    target = tmp_path / "tool"
    target.write_bytes(b"fixture")
    link = tmp_path / "link"
    link.symlink_to(target)
    monkeypatch.setitem(core.TOOLS, "ip", str(link))
    with pytest.raises(OSError):
        core.tool_pin("ip")


@pytest.mark.parametrize("mode", [0o777, 0o4755, 0o2755])
def test_untrusted_mode_refused_even_if_child_pin_matches(tmp_path, monkeypatch, mode):
    import hashlib

    target = tmp_path / "tool"
    target.write_bytes(b"fixture")
    target.chmod(mode)
    monkeypatch.setitem(core.TOOLS, "ip", str(target))
    with pytest.raises(ValueError):
        core.tool_pin("ip", expected_sha256=hashlib.sha256(b"fixture").hexdigest())


def test_capability_bearing_executable_refused(tmp_path, monkeypatch):
    target = tmp_path / "tool"
    target.write_bytes(b"fixture")
    target.chmod(0o755)
    monkeypatch.setitem(core.TOOLS, "ip", str(target))
    monkeypatch.setattr(core.os, "getxattr", lambda *args: b"synthetic capability xattr")
    with pytest.raises(ValueError, match="CAPABILITY_BEARING_TOOL"):
        core.tool_pin("ip", expected_sha256="a" * 64)
