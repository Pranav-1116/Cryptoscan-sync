"""Engineering tests; synthetic contracts never substitute for retained VM runs."""

import copy
from pathlib import Path
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.routed_tbf.authority import Authority, public, sign, verify
from tools.routed_tbf import guest, runner, trust
from tools.routed_tbf.report import GATES, latency_valid, Latency, preflight_blockers, report


@pytest.fixture
def authority(tmp_path):
    return Authority.initialize(tmp_path / "authority")


def grant(a):
    return a.approve(a.issue("lab", "diskless-routed-v1", "a" * 64, "b" * 64), True)


def redeem(a, g, **kwargs):
    fields = dict(tenant="lab", device="diskless-routed-v1", bundle="a" * 64, acceptance="b" * 64)
    fields.update(kwargs)
    return a.redeem(g, **fields)


def test_local_enrollment_keys_distinct_and_private(authority):
    with authority.transaction() as db:
        t, d, keys = authority.enrollment(db)
    assert t == "lab" and d == "diskless-routed-v1" and len(set(keys.values())) == 3
    assert all((authority.directory / (r + ".key")).stat().st_mode & 0o777 == 0o600 for r in keys)
    assert authority.path.stat().st_mode & 0o777 == 0o600


def test_explicit_simulated_reviewer_required(authority):
    lease = authority.issue("lab", "diskless-routed-v1", "a" * 64, "b" * 64)
    with pytest.raises(ValueError):
        authority.approve(lease)


@pytest.mark.parametrize(
    "field,value", [("tenant", "bank-b"), ("device", "other-device"), ("bundle", "c" * 64), ("acceptance", "d" * 64)]
)
def test_wrong_execution_context_refused(authority, field, value):
    with pytest.raises(ValueError):
        redeem(authority, grant(authority), **{field: value})


def test_one_time_redemption_and_active_revocation(authority):
    g = grant(authority)
    proof = redeem(authority, g)
    assert proof["challenge"] == g["lease"]["payload"]["nonce"]
    assert authority.active(g["lease"]["payload"]["id"])
    with pytest.raises(ValueError):
        redeem(authority, g)
    authority.revoke(g["lease"]["payload"]["id"])
    assert not authority.active(g["lease"]["payload"]["id"])


def test_revoked_before_redemption(authority):
    g = grant(authority)
    authority.revoke(g["lease"]["payload"]["id"])
    with pytest.raises(ValueError):
        redeem(authority, g)


@pytest.mark.parametrize("offset", [-1, 301, 601])
def test_expired_future_or_insufficient_lease_window(authority, offset):
    g = grant(authority)
    with pytest.raises(ValueError):
        redeem(authority, g, now=g["lease"]["payload"]["issued_at"] + offset)


@pytest.mark.parametrize("part", ["issuer", "reviewer"])
def test_signature_tampering(authority, part):
    g = grant(authority)
    if part == "issuer":
        g["lease"]["payload"]["production_authorized"] = True
    else:
        g["approval"]["independent_human_approval"] = True
    with pytest.raises(ValueError):
        redeem(authority, g)


def test_duplicate_reviewer_cannot_approve_twice(authority):
    lease = authority.issue("lab", "diskless-routed-v1", "a" * 64, "b" * 64)
    authority.approve(lease, True)
    with pytest.raises(ValueError):
        authority.approve(lease, True)


def test_concurrent_redeem_exactly_one_wins(authority):
    g = grant(authority)

    def attempt(_):
        try:
            redeem(authority, g)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert sum(executor.map(attempt, range(4))) == 1


def test_wrong_adapter_key_rejected(authority):
    signed = authority.sign_receipt({"test": True})
    with pytest.raises(ValueError):
        verify(public(Ed25519PrivateKey.generate()), signed["adapter_signature"], signed["payload"])


def test_unknown_lease_cannot_revoke(authority):
    with pytest.raises(ValueError):
        authority.revoke("missing")
    assert not authority.active("missing")


@pytest.mark.parametrize("ttl", [0, 329, 601])
def test_unbounded_lease_refused(authority, ttl):
    with pytest.raises(ValueError):
        authority.issue("lab", "diskless-routed-v1", "a" * 64, "b" * 64, ttl=ttl)


def test_authority_permission_refusal(authority):
    authority.directory.chmod(0o755)
    with pytest.raises(ValueError):
        Authority(authority.directory)


def test_private_key_symlink_refusal(authority, tmp_path):
    p = authority.directory / "issuer.key"
    raw = p.read_bytes()
    p.unlink()
    other = tmp_path / "other"
    other.write_bytes(raw)
    p.symlink_to(other)
    with pytest.raises(ValueError):
        authority.key("issuer")


def test_revocation_stops_actual_bounded_child(authority):
    g = grant(authority)
    redeem(authority, g)
    lease = g["lease"]["payload"]["id"]
    timer = threading.Timer(0.2, lambda: authority.revoke(lease))
    start = time.monotonic()
    timer.start()
    try:
        raw, failure = runner.bounded_vm(
            [sys.executable, "-c", 'import time;print("started",flush=True);time.sleep(30)'],
            lambda: authority.active(lease),
            timeout=3,
        )
    finally:
        timer.join()
    assert failure == "LEASE_REVOKED_OR_EXPIRED_VM_TERMINATED" and time.monotonic() - start < 2
    assert b"started" in raw


def test_actual_child_timeout():
    _, failure = runner.bounded_vm([sys.executable, "-c", "import time;time.sleep(10)"], lambda: True, timeout=0.1)
    assert failure == "VM_TIMEOUT"


def test_serial_budget_actual_child():
    raw, failure = runner.bounded_vm([sys.executable, "-c", 'import sys;sys.stdout.write("x"*600000)'], lambda: True)
    assert failure == "VM_SERIAL_BUDGET" and len(raw) <= 524288


def clean_policy():
    return [{"kind": "noqueue", "handle": "0:", "root": True, "options": {}}]


def preflight():
    return {
        "target": "ge",
        "destinations": ["10.78.1.2"],
        "qdisc": clean_policy(),
        "class": [],
        "filter": [],
        "ingress_filters": [],
        "egress_filters": [],
        "rules": [{"priority": a, "table": b} for a, b in [(0, "local"), (32766, "main"), (32767, "default")]],
        "routes": [],
        "management_routes": [[{"dev": "gm"}]],
        "ifindex": 4,
        "allowed": True,
        "blockers": [],
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c.update(target="gm"),
        lambda c: c.update(destinations=[]),
        lambda c: c.update(qdisc=[{"kind": "htb"}]),
        lambda c: c.update(**{"class": [{"classid": "8a:1"}]}),
        lambda c: c.update(filter=[{"kind": "u32"}]),
        lambda c: c.update(ingress_filters=[{"kind": "bpf"}]),
        lambda c: c.update(egress_filters=[{"kind": "matchall"}]),
        lambda c: c.update(rules=[]),
        lambda c: c.update(routes=[{"nexthops": [{"dev": "ge"}, {"dev": "gm"}]}]),
        lambda c: c.update(management_routes=[[{"dev": "ge"}]]),
        lambda c: c.update(management_routes=[]),
    ],
)
def test_policy_or_management_ambiguity_blocks(mutation):
    c = preflight()
    assert not preflight_blockers(c)
    mutation(c)
    assert preflight_blockers(c)


def test_unsafe_preflight_never_writes_policy(monkeypatch):
    monkeypatch.setattr(guest, "safety", lambda: {"allowed": False})
    monkeypatch.setattr(guest, "cmd", lambda *a, **k: pytest.fail("write attempted"))
    with pytest.raises(ValueError):
        guest.add(10)


@pytest.mark.parametrize("reason", ["identity", "foreign", "changed_options"])
def test_rollback_refuses_foreign_policy_without_writes(monkeypatch, reason):
    monkeypatch.setattr(guest, "identity", lambda: 5 if reason == "identity" else 4)
    rows = [{"kind": "tbf", "handle": "7e02:", "options": {"rate": 1250000, "burst": 123}}]
    if reason == "foreign":
        rows[0]["handle"] = "8a:"
    monkeypatch.setattr(guest, "policy", lambda: rows)
    monkeypatch.setattr(guest, "cmd", lambda *a, **k: pytest.fail("foreign deletion attempted"))
    assert guest.rollback(10, 4, "different-expected-fingerprint").startswith("REFUSED_")


def latency(**kwargs):
    v = dict(planned=240, sent=240, received=240, missed_schedule=0, errors=0, p95_ms=10.0, p99_ms=20.0)
    v.update(kwargs)
    return Latency(**v)


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(received=237),
        dict(p95_ms=101.0, p99_ms=110.0),
        dict(p99_ms=251.0),
        dict(errors=1),
        dict(sent=241),
        dict(received=241),
        dict(p95_ms=21.0, p99_ms=20.0),
    ],
)
def test_management_gate_negative(kwargs):
    assert not latency_valid(latency(**kwargs), True)


def test_agreed_gates_not_silently_weakened():
    assert GATES["management_delivery_min"] == 0.99 and GATES["management_p95_max_ms"] == 100
    assert GATES["management_p99_max_ms"] == 250 and GATES["recovery_deadline_seconds"] == 5
    assert GATES["udp_fraction"] == [0.8, 1.1] and GATES["tcp_fraction"] == [0.7, 1.1]
    assert GATES["measurement_seconds"] == 10


def test_guest_probe_host_execution_refused(tmp_path):
    binary = tmp_path / "probe"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-static",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(Path(guest.__file__).with_name("probe.c")),
            "-o",
            str(binary),
        ],
        check=True,
    )
    assert subprocess.run([str(binary), "echo", "10.77.2.2"]).returncode == 64


def test_capture_missing_sandbox_or_nonce_refused():
    for raw in (b"", b"CRYPTOSCAN_ROUTED_RESULT={}\n", b"CRYPTOSCAN_ROUTED_FAILURE=test\n"):
        with pytest.raises(ValueError):
            runner.capture(raw, "a" * 64)


def test_independent_review_same_environment_refused():
    key = Ed25519PrivateKey.generate()
    local = {
        "environment": {"environment_sha256": "x"},
        "profile_sources": {},
        "acceptance_sha256": "a",
        "binary_hashes": {},
    }
    peer = copy.deepcopy(local)
    peer.update(
        result_verdict="LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES",
        independent_reviewer="reviewer",
        reviewed_launcher_and_runtime=True,
        production_execution_qualified=False,
    )
    with pytest.raises(ValueError):
        trust.compare(local, {"payload": peer, "signature": sign(key, peer)}, public(key))


def synthetic_capture():
    """Clearly synthetic positive contracts; never retained as native measurements."""
    from tools.routed_tbf.report import MATRIX, FAULTS, NEGATIVES

    raw = {
        "schema_version": "cryptoscan.routed-tbf-guest/v1",
        "nonce": "a" * 64,
        "kernel": "6.12.58-cryptoscan-routed-tbf",
        "topology": {},
        "phases": [],
        "faults": [],
        "negative_cases": [],
        "unrelated_before": clean_policy(),
        "unrelated_after": clean_policy(),
        "management_policy_before": clean_policy(),
        "management_policy_after": clean_policy(),
        "final_policy": clean_policy(),
        "finished_ns": 300_000_000_000,
    }
    for namespace, dev, ip in [
        ("tx", "s0", "10.77.1.2"),
        ("gw", "ge", "10.77.2.1"),
        ("rx", "r0", "10.77.2.2"),
        ("mgmt", "m0", "10.78.1.2"),
    ]:
        names = ["lo", "gi", "ge", "gm"] if namespace == "gw" else ["lo", dev]
        raw["topology"][namespace] = [{"ifname": n, "addr_info": [{"local": ip}] if n == dev else []} for n in names]
    for i, (label, proto, payload, flows, burst, rate) in enumerate(MATRIX):
        mbps = rate * 0.9 if rate else 40
        packets = int(mbps * 1e6 * 10 / 8 / payload)
        b = packets * payload
        total_sends = int(6e6 * 11 / payload)
        original = clean_policy()
        applied = (
            [
                {
                    "kind": "tbf",
                    "handle": "7e02:",
                    "root": True,
                    "options": {"rate": rate * 125000},
                    "bytes": 0,
                    "packets": 0,
                    "overlimits": 0,
                }
            ]
            if rate
            else original
        )
        after = copy.deepcopy(applied)
        if rate:
            after[0].update(bytes=100000000, packets=1000000, overlimits=1000, drops=10)
        p = {
            "label": label,
            "protocol": proto,
            "payload": payload,
            "flows": flows,
            "burst_packets": burst,
            "rate_mbps": rate,
            "preflight": preflight(),
            "applied": applied,
            "after": after,
            "restored": original,
            "sender": {
                "flow_bytes": [total_sends * payload // flows] * flows,
                "successful_sends": total_sends,
                "sent_bytes_window": total_sends * payload // 2,
                "attempts": total_sends,
                "backpressure": 0,
                "errors": 0,
                "tcp_total_retransmissions": 0,
            },
            "receiver": {
                "bytes": b,
                "packets": packets if proto == "udp" else 0,
                "total_received": int(packets * 1.1) if proto == "udp" else b + 1200,
                "duplicates": 0,
                "invalid": 0,
                "errors": 0,
                "elapsed_ns": 10000000000,
            },
            "data_latency": latency().model_dump(),
            "management": latency().model_dump(),
            "started_ns": 1000000000 + i * 13000000000,
            "finished_ns": 13000000000 + i * 13000000000,
            "ifindex": 4,
        }
        raw["phases"].append(p)
    for name in NEGATIVES:
        c = preflight()
        c["target"] = "gm"
        c["blockers"] = preflight_blockers(c)
        c["allowed"] = False
        raw["negative_cases"].append({"case": name, "preflight": c, "policy_preserved": True})
    for name, status in FAULTS.items():
        foreign = (
            [{"kind": "pfifo", "handle": "8a:", "options": {"limit": 321}}]
            if name in ("policy_conflict", "interface_recreation")
            else None
        )
        raw["faults"].append(
            {
                "case": name,
                "injected": 10.0,
                "response_seconds": 1.0,
                "state": {"ifindex": 4},
                "watchdog": {
                    "status": status,
                    "finished": 11.0,
                    "policy": foreign or clean_policy(),
                    "ifindex": 5 if name == "interface_recreation" else 4,
                },
                "foreign_before": foreign,
                "foreign_after": foreign,
                "management": latency(planned=60, sent=60, received=60).model_dump(),
                "recovery_probe": copy.deepcopy(raw["phases"][0]) if not foreign else None,
            }
        )
    return raw


def test_synthetic_positive_is_not_full_recovery_or_production():
    r = report(synthetic_capture())
    assert r["blockers"] == [] and r["verdict"] == "LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES"
    assert not r["all_failure_modes_recovered"] and not r["production_execution_qualified"]
    assert len(r["refused_recovery_cases"]) == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["phases"][2]["receiver"].update(bytes=100000000, packets=83333),
        lambda c: c["phases"][2]["after"][0].update(overlimits=0),
        lambda c: c["phases"][2]["after"][0]["options"].update(rate=625000),
        lambda c: c["phases"][2]["restored"][0].update(kind="tbf"),
        lambda c: c["phases"][0]["sender"].update(backpressure=1),
        lambda c: c["phases"][0]["receiver"].update(invalid=1),
        lambda c: c["phases"][0]["management"].update(received=237),
        lambda c: c["phases"][0].update(finished_ns=2000000000),
        lambda c: c["phases"][0]["preflight"].update(target="gm"),
        lambda c: c["negative_cases"][0].update(policy_preserved=False),
        lambda c: c["negative_cases"][0]["preflight"].update(allowed=True),
        lambda c: c["faults"][0].update(response_seconds=6.0),
        lambda c: c["faults"][0]["watchdog"].update(status="RECOVERED_BY_FORCE"),
        lambda c: c["faults"][3]["watchdog"].update(ifindex=4),
        lambda c: c["faults"][4].update(foreign_after=clean_policy()),
        lambda c: c["unrelated_after"][0].update(handle="7e02:"),
        lambda c: c["management_policy_after"][0].update(kind="tbf"),
    ],
)
def test_report_tamper_and_failed_measurements_block(mutate):
    capture = synthetic_capture()
    mutate(capture)
    assert report(capture)["verdict"] == "INCONCLUSIVE_OR_FAILED"


def test_empty_class_output_only_normalized_on_successful_class_listing(monkeypatch):
    monkeypatch.setattr(guest, "cmd", lambda args: b"")
    assert guest.read([guest.TC, "-j", "class", "show", "dev", "ge"]) == []
    with pytest.raises(ValueError):
        guest.read([guest.TC, "-j", "qdisc", "show", "dev", "ge"])

    def failed(args):
        raise ValueError("failed command")

    monkeypatch.setattr(guest, "cmd", failed)
    with pytest.raises(ValueError):
        guest.read([guest.TC, "-j", "class", "show", "dev", "ge"])


def test_schema_snapshot_and_valid_draft():
    import json
    from jsonschema import Draft202012Validator
    from tools.routed_tbf.report import Capture

    p = Path(guest.__file__).with_name("schemas") / "capture-v1.schema.json"
    schema = json.loads(p.read_text())
    assert schema == Capture.model_json_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(synthetic_capture())


def test_nonempty_legacy_class_text_is_unknown_blocker_not_absence(monkeypatch):
    monkeypatch.setattr(guest, "cmd", lambda args: b"class htb 8a:1 root rate 20Mbit\n")
    rows = guest.read([guest.TC, "-j", "class", "show", "dev", "ge"])
    c = preflight()
    c["class"] = rows
    assert rows and "unsupported_class_encoding" in rows[0]
    assert "EXISTING_POLICY_OR_FILTER" in preflight_blockers(c)


def synthetic_signed_receipt(authority, tmp_path):
    """Synthetic local-envelope closure only, never a native qualification artifact."""
    from tools.disposable_tbf.runner import canonical

    cap = synthetic_capture()
    serial = b"CRYPTOSCAN_TBF_SANDBOX=LANDLOCK_SECCOMP_ACTIVE\nCRYPTOSCAN_ROUTED_RESULT=" + canonical(cap) + b"\n"
    payload = {
        "guest": cap,
        "report": report(cap),
        "sources": runner.source_bindings(),
        "acceptance": GATES,
        "grant": {"lease": {"payload": {"nonce": cap["nonce"]}}},
        "serial_sha256": runner.hashlib.sha256(serial).hexdigest(),
        "parent_before": {},
        "parent_after": {},
        "parent_policy_before": [],
        "parent_policy_after": [],
        "failure": None,
        "production_execution_qualified": False,
        "independent_review_complete": False,
        "physical_device_identity_verified": False,
        "wall_seconds": 200.0,
        "verdict": "LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES",
    }
    (tmp_path / "serial.log").write_bytes(serial)
    p = tmp_path / "result.json"
    signed = authority.sign_receipt(payload)
    p.write_bytes(canonical(signed))
    return p, signed


def test_synthetic_signed_closure(authority, tmp_path):
    p, signed = synthetic_signed_receipt(authority, tmp_path)
    assert (
        runner.verify_receipt(p, runner.sha(p), signed["adapter_public_key"])
        == "LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(production_execution_qualified=True),
        lambda p: p.update(independent_review_complete=True),
        lambda p: p.update(physical_device_identity_verified=True),
        lambda p: p["report"].update(all_failure_modes_recovered=True),
        lambda p: p["sources"].update(forged="a" * 64),
        lambda p: p.update(parent_after={"changed": True}),
        lambda p: p.update(wall_seconds=1.0),
        lambda p: p["guest"]["phases"][0]["management"].update(received=1),
    ],
)
def test_resealed_signed_receipt_still_recomputes_contracts(authority, tmp_path, mutation):
    from tools.disposable_tbf.runner import canonical

    p, signed = synthetic_signed_receipt(authority, tmp_path)
    mutation(signed["payload"])
    signed = authority.sign_receipt(signed["payload"])
    p.write_bytes(canonical(signed))
    with pytest.raises(ValueError):
        runner.verify_receipt(p, runner.sha(p), signed["adapter_public_key"])


def test_signed_external_review_comparison_is_only_an_assertion():
    key = Ed25519PrivateKey.generate()
    local = {
        "environment": {"environment_sha256": "local"},
        "profile_sources": {"x": "a"},
        "acceptance_sha256": "a",
        "binary_hashes": {"kernel": "old"},
    }
    peer = copy.deepcopy(local)
    peer.update(
        environment={"environment_sha256": "other"},
        result_verdict="LAB_GATES_PASSED_WITH_REFUSED_RECOVERY_CASES",
        binary_hashes={"kernel": "new"},
        independent_reviewer="SYNTHETIC_UNIT_REVIEWER",
        reviewed_launcher_and_runtime=True,
        production_execution_qualified=False,
    )
    r = trust.compare(local, {"payload": peer, "signature": sign(key, peer)}, public(key))
    assert r["build_differences"]["kernel"] == {"local": "old", "peer": "new"}
    assert not r["production_execution_qualified"]
