"""A collector's outcome uses the engine's vocabulary, and a refusal carries its report.

Two failures from a real run, both fixed here:

* the network collector emitted its own word ``NO_TARGET`` for "named targets, no
  result", and the estate engine rejected the whole payload with
  ``unknown collector status 'NO_TARGET'`` — a 422 for a *correct* observation
  about a plane nobody could reach;
* that 422 carried only the engine's complaint, so the twenty per-target errors
  that explained it were discarded. A refusal has to carry the report that
  caused it.
"""
from __future__ import annotations

import socket

import pytest

from shared_models.estate_graph import collector_outcome

from api import host_collect


def test_the_engine_accepts_the_coverage_word_for_a_missed_target():
    """``NO_TARGET`` is the coverage vocabulary's word; it means FAILED here."""
    outcome = collector_outcome("NETWORK", "NO_TARGET", expected=20, collected=0)
    assert outcome["status"] == "FAILED"
    assert outcome["impact"]  # a failed plane is unknown, never empty


def test_an_unknown_word_is_still_refused():
    with pytest.raises(ValueError):
        collector_outcome("NETWORK", "MOSTLY_FINE")


def _closed_port() -> int:
    """A port nothing is listening on, so the handshake really fails."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_no_target_negotiating_is_a_failed_plane_not_an_empty_one():
    port = _closed_port()
    package = host_collect.collect_network([f"127.0.0.1:{port}"], timeout=1.0)

    assert package["collector"]["status"] == "FAILED"
    assert package["collector"]["expected"] == 1
    assert package["collector"]["collected"] == 0
    assert "unknown, not empty" in package["collector"]["impact"]
    # and the target itself is a coverage row, not a silent omission
    assert package["coverage"][0]["status"] == "NOT_OBSERVED"
    assert package["coverage"][0]["target"] == f"127.0.0.1:{port}"


def test_a_partly_reachable_plane_is_partial():
    """One target that negotiates and one that does not is PARTIAL, not COMPLETE."""
    pytest.importorskip("network_scanner.probing.active_prober")
    from tools.banking_sandbox import live_synthetic  # noqa: F401  (sanity: lab present)
    from pathlib import Path

    estate = Path.home() / ".cache" / "bank-lab"
    if not (estate / "LAB.json").is_file():
        pytest.skip("no generated bank estate in this environment")

    import threading
    import time

    from tools.banking_sandbox.live_synthetic import _collect_services, _start_one, _synthetic_cert
    import ssl
    import tempfile

    root, _meta = live_synthetic.open_estate(estate)
    services = _collect_services(root, max_services=1)
    if not services:
        pytest.skip("the estate declares no live service")
    work = Path(tempfile.mkdtemp(prefix="collect-status-"))
    service = services[0]
    cert_pem, key_pem, _ = _synthetic_cert(work, "svc", "svc.lab.invalid", key_type="EC")
    ready, stop = threading.Event(), threading.Event()
    port = _closed_port()
    threading.Thread(
        target=_start_one,
        args=(cert_pem, key_pem, ssl.TLSVersion.TLSv1_2, port, ready, stop, "svc"),
        daemon=True,
    ).start()
    try:
        ready.wait(timeout=3.0)
        time.sleep(0.2)
        package = host_collect.collect_network(
            [f"127.0.0.1:{port}", f"127.0.0.1:{_closed_port()}"], timeout=2.0
        )
    finally:
        stop.set()

    assert package["collector"]["collected"] == 1, package["collector"]
    assert package["collector"]["status"] == "PARTIAL"
