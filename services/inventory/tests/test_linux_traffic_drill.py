"""Synthetic TC success/failure branches. Native kernel result is separately disclosed."""

import json
import os
from types import SimpleNamespace
import pytest
from inventory import linux_traffic_drill as core
from shared.shared_models.tests.test_linux_traffic_control import authorization
from shared_models.host_collection import digest


def _fake_stat(ino: int) -> os.stat_result:
    """A complete stat result: pytest's own file reads go through ``os.stat``.

    Patching the real ``os.stat`` with a bare namespace used to break the
    runner itself (``linecache`` reads ``st_size``/``st_mtime`` while reporting),
    which crashed the worker instead of failing this test.
    """
    return os.stat_result((0o100644, ino, 0, 1, 0, 0, 0, 0, 0, 0))


def setup_child(monkeypatch):
    auth = authorization()
    monkeypatch.setattr(core, "context", lambda: (auth.expected_parent_boot_id, 3, 2))
    monkeypatch.setattr(core.os, "geteuid", lambda: 0)
    monkeypatch.setattr(core.os, "fstat", lambda fd: _fake_stat(1 if fd == 10 else 5))
    monkeypatch.setattr(core.os, "stat", lambda path: _fake_stat(6))
    monkeypatch.setattr(core, "tool_pin", lambda *a, **kw: None)
    monkeypatch.setattr(core.time, "sleep", lambda _: None)
    return auth


def test_child_success_and_fixed_loopback_rollback(monkeypatch):
    auth = setup_child(monkeypatch)
    calls = []
    active = False

    def command(argv, **kwargs):
        nonlocal active
        calls.append(argv)
        if "link" in argv and "show" in argv:
            return b'[{"ifname":"lo","ifindex":1}]'
        if "add" in argv:
            active = True
            return b""
        if "del" in argv:
            active = False
            return b""
        if "qdisc" in argv:
            row = {"kind": "tbf" if active else "noqueue", "handle": core.HANDLE if active else "0:", "root": True}
            if active:
                row["options"] = {"rate": 1250000}
            return json.dumps([row]).encode()
        return b""

    monkeypatch.setattr(core, "bounded_command", command)
    result = core.child(auth, 10, 11, {"ip": "a" * 64, "tc": "b" * 64})
    assert result["qdisc_applied_in_child"] and result["rollback_verified_in_child"]
    assert result["before_qdisc_sha256"] == result["after_qdisc_sha256"]
    assert all(argv[argv.index("dev") + 1] == "lo" for argv in calls if "dev" in argv)
    assert not any("replace" in argv for argv in calls)
    assert any("del" in argv and core.HANDLE in argv for argv in calls)


def test_child_guard_refuses_parent_namespace_before_any_command(monkeypatch):
    auth = setup_child(monkeypatch)
    monkeypatch.setattr(core, "context", lambda: (auth.expected_parent_boot_id, 1, 2))
    monkeypatch.setattr(core, "bounded_command", lambda _: pytest.fail("Command before isolation"))
    with pytest.raises(ValueError, match="NOT_ISOLATED"):
        core.child(auth, 10, 11, {})


def test_parent_hash_refuses_before_namespace_launch():
    with pytest.raises(ValueError):
        core.run_drill(authorization(), "0" * 64)


def test_parent_context_refuses_before_namespace_launch(monkeypatch):
    monkeypatch.setattr(core.os, "getuid", lambda: 1001)
    monkeypatch.setattr(core.os, "geteuid", lambda: 1001)
    value = authorization()
    with pytest.raises(ValueError, match="CONTEXT_MISMATCH"):
        core.run_drill(value, digest(value))


def test_elevated_parent_refused(monkeypatch):
    monkeypatch.setattr(core.os, "getuid", lambda: 0)
    value = authorization()
    with pytest.raises(ValueError):
        core.run_drill(value, digest(value))


def test_kernel_rejection_never_attempts_delete_or_replace(monkeypatch):
    auth = setup_child(monkeypatch)
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        if "link" in argv and "show" in argv:
            return b'[{"ifname":"lo","ifindex":1}]'
        if "add" in argv:
            raise ValueError("unsupported kernel qdisc")
        if "qdisc" in argv:
            return b'[{"kind":"noqueue","handle":"0:","root":true}]'
        return b""

    monkeypatch.setattr(core, "bounded_command", command)
    result = core.child(auth, 10, 11, {"ip": "a" * 64, "tc": "b" * 64})
    assert not result["qdisc_applied_in_child"] and not result["rollback_verified_in_child"]
    assert not any("del" in call or "replace" in call for call in calls)


def test_unowned_readback_is_not_deleted(monkeypatch):
    auth = setup_child(monkeypatch)
    calls = []
    added = False

    def command(argv, **kwargs):
        nonlocal added
        calls.append(argv)
        if "link" in argv and "show" in argv:
            return b'[{"ifname":"lo","ifindex":1}]'
        if "add" in argv:
            added = True
            return b""
        if "qdisc" in argv:
            return (
                b'[{"kind":"tbf","handle":"9999:","root":true,"options":{"rate":1250000}}]'
                if added
                else b'[{"kind":"noqueue","handle":"0:","root":true}]'
            )
        return b""

    monkeypatch.setattr(core, "bounded_command", command)
    result = core.child(auth, 10, 11, {"ip": "a" * 64, "tc": "b" * 64})
    assert not result["rollback_verified_in_child"]
    assert not any("del" in call for call in calls)
