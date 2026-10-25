"""Explicit hybrid CLI, provider/version and non-promotable public fact controls."""

import subprocess
import sys
from pathlib import Path
import pytest
from services.inventory.tests.test_tls_hybrid import hybrid_server, hybrid_target
from inventory.collection import ApprovedTlsSessionCollector
from shared_models.host_collection import HostSnapshot
from shared_models.tls_hybrid import TlsHybridFact
from shared_models.tls_session import seal_session
from shared_models.tpm_quote_verification import canonical, sha


def test_actual_explicit_cli_no_overwrite_or_implicit_activation(tmp_path):
    with hybrid_server() as state:
        target = hybrid_target(state)
        source = tmp_path / "target.json"
        source.write_bytes(canonical(target))
        out = tmp_path / "snapshot.json"
        script = Path(__file__).resolve().parents[3] / "scripts/collect_tls_session.py"
        cmd = [
            sys.executable,
            str(script),
            "--target",
            str(source),
            "--approved-target-sha256",
            sha(target),
            "--acknowledge-active-tls",
            "--output",
            str(out),
        ]
        assert subprocess.run(cmd, capture_output=True).returncode == 64 and state["connections"] == 0
        result = subprocess.run([*cmd, "--include-hybrid"], capture_output=True)
        assert result.returncode == 0, result.stderr
        s = HostSnapshot.model_validate_json(out.read_bytes())
        assert s.receipts[0].facts[0].kind == "NETWORK_TLS13_HYBRID"
        original = out.read_bytes()
        assert subprocess.run([*cmd, "--include-hybrid"], capture_output=True).returncode == 64
        assert out.read_bytes() == original and state["connections"] == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("hybrid_session_completed", False),
        ("selected_group_id", 29),
        ("key_exchange_group", "X25519"),
        ("openssl_version", "OpenSSL 3.0.20 7 Apr 2026"),
        ("provider_identity_basis", "MEASURED_EXECUTION"),
        ("pqc_readiness_verified", True),
        ("application_identity_verified", True),
    ],
)
def test_resealed_hybrid_promotion_or_classical_provider_refused(field, value):
    with hybrid_server() as state:
        f = ApprovedTlsSessionCollector(include_hybrid=True).collect(hybrid_target(state)).receipts[0].facts[0]
    data = f.model_dump(mode="python")
    data.pop("interface_sha256")
    data["certificate"] = f.certificate
    data[field] = value
    with pytest.raises(ValueError):
        seal_session(fact_model=TlsHybridFact, **data)


def test_resealed_wrong_hybrid_share_length_rejected():
    with hybrid_server() as state:
        f = ApprovedTlsSessionCollector(include_hybrid=True).collect(hybrid_target(state)).receipts[0].facts[0]
    data = f.model_dump(mode="python")
    data.pop("interface_sha256")
    data["certificate"] = f.certificate
    raw = bytearray.fromhex(f.server_hello_hex)
    ext = 39 + raw[38] + 3
    pos = ext + 2
    while int.from_bytes(raw[pos : pos + 2], "big") != 51:
        pos += 4 + int.from_bytes(raw[pos + 2 : pos + 4], "big")
    n = int.from_bytes(raw[pos + 2 : pos + 4], "big")
    assert n == 1124
    del raw[pos + 4 + n - 1]
    raw[1:4] = (len(raw) - 4).to_bytes(3, "big")
    raw[ext : ext + 2] = (int.from_bytes(raw[ext : ext + 2], "big") - 1).to_bytes(2, "big")
    raw[pos + 2 : pos + 4] = (n - 1).to_bytes(2, "big")
    raw[pos + 6 : pos + 8] = (1119).to_bytes(2, "big")
    import hashlib

    data.update(server_hello_hex=raw.hex(), server_hello_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="32\\+1088"):
        seal_session(fact_model=TlsHybridFact, **data)
