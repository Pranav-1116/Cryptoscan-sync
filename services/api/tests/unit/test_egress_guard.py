"""Runtime egress guard (audit 81, round 35)."""

from __future__ import annotations

import pytest

from api.security.egress_guard import (
    EgressBlocked,
    egress_guard_active,
    install_egress_guard,
    uninstall_egress_guard,
)


@pytest.fixture(autouse=True)
def _clean_guard():
    uninstall_egress_guard()
    yield
    uninstall_egress_guard()


def test_guard_blocks_non_allowlisted_destinations():
    install_egress_guard(["updates.internal:443", "vault.internal"])
    with pytest.raises(EgressBlocked) as exc:
        __import__("socket").create_connection(("ai.vendor.example", 443))
    assert "not in egress allowlist" in str(exc.value)
    assert egress_guard_active() is True


def test_guard_allows_exact_and_host_rules():
    import socket

    install_egress_guard(["127.0.0.1:59999", "localhost"])
    # exact host:port rule reaches the real create_connection (nothing
    # listening -> ConnectionRefusedError, NOT EgressBlocked)
    with pytest.raises(OSError) as exc:
        socket.create_connection(("127.0.0.1", 59999), timeout=0.2)
    assert not isinstance(exc.value, EgressBlocked)
    # bare-host rule covers any port
    with pytest.raises(OSError) as exc:
        socket.create_connection(("localhost", 59998), timeout=0.2)
    assert not isinstance(exc.value, EgressBlocked)


def test_guard_fail_closed_on_empty_allowlist():
    import socket

    install_egress_guard([])
    with pytest.raises(EgressBlocked):
        socket.create_connection(("anything.internal", 80))
    with pytest.raises(EgressBlocked):
        socket.create_connection(("127.0.0.1", 59997))


def test_guard_port_mismatch_is_blocked():
    import socket

    install_egress_guard(["updates.internal:443"])
    with pytest.raises(EgressBlocked):
        socket.create_connection(("updates.internal", 8443))


def test_install_idempotent_and_uninstall_restores():
    import socket

    install_egress_guard(["a.internal"])
    original = socket.create_connection
    install_egress_guard(["b.internal"])  # second install is a no-op
    assert socket.create_connection is original
    uninstall_egress_guard()
    assert egress_guard_active() is False
    # after uninstall, no destination raises EgressBlocked (nothing
    # listening on the test port, but the guard no longer denies)
    try:
        socket.create_connection(("ai.vendor.example", 443), timeout=0.2)
    except EgressBlocked:
        pytest.fail("guard still active after uninstall")
    except OSError:
        pass  # expected: unroutable, but NOT denied by the guard
