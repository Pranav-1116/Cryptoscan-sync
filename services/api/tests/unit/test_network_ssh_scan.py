"""POST /network/ssh-scan returns findings, telemetry, and the updated TOFU map."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user
from api.main import create_app


def _fake_finding(endpoint, status="OK", issues=None, observed=None):
    return {
        "endpoint": endpoint,
        "status": status,
        "keys": [{"key_type": "ssh-ed25519", "fingerprint_sha256": "SHA256:xyz", "bits": 256}],
        "policy_issues": issues or [],
        "compliance_issue": (issues or [None])[0],
        "key_drift": {"status": "FIRST_OBSERVATION", "observed": observed or {"ssh-ed25519": "SHA256:xyz"}},
    }


@pytest.mark.asyncio
async def test_ssh_scan_endpoint(monkeypatch):
    import api.security.scan_admission as admission
    import network_scanner.probing.ssh_keyscan as ssh_module

    calls = []

    # this test exercises the SSH findings contract, not admission: pin the
    # decision (no emergency stop, no OT estate, active probing allowed)
    monkeypatch.setattr(admission, "_control_plane_state", lambda: ([], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)

    def fake_scan(host, port, *, timeout=8.0, baseline=None):
        endpoint = f"{host}:{port}"
        calls.append((endpoint, baseline))
        if baseline == {"ssh-ed25519": "SHA256:old"}:
            return _fake_finding(
                endpoint,
                issues=["SSH_HOST_KEY_CHANGED"],
                observed={"ssh-ed25519": "SHA256:new"},
            )
        return _fake_finding(endpoint, issues=["SSH_RSA_HOST_KEY"])

    monkeypatch.setattr(ssh_module, "scan_ssh_host_keys", fake_scan)
    # the router imports names from the module at call time, so patching the
    # module attribute is sufficient

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/ssh-scan",
            json={
                "hosts": ["10.0.0.1", "10.0.0.2:2222"],
                "known_host_keys": {"10.0.0.1:22": {"ssh-ed25519": "SHA256:old"}},
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["findings"]) == 2
    telemetry = payload["ssh_probe_telemetry"]
    assert telemetry["probed"] == 2 and telemetry["ok"] == 2
    assert telemetry["ssh_weak_host_keys"] == 1
    assert telemetry["ssh_host_key_changes"] == 1
    assert telemetry["status"] == "PARTIAL"
    # the updated TOFU map carries new fingerprints forward
    assert payload["known_host_keys"]["10.0.0.1:22"] == {"ssh-ed25519": "SHA256:new"}
    assert payload["known_host_keys"]["10.0.0.2:2222"] == {"ssh-ed25519": "SHA256:xyz"}
    # baseline was passed through per endpoint
    assert calls[0] == ("10.0.0.1:22", {"ssh-ed25519": "SHA256:old"})
    assert calls[1] == ("10.0.0.2:2222", None)


@pytest.mark.asyncio
async def test_ssh_scan_requires_hosts():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/network/ssh-scan", json={"hosts": []})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_ssh_scan_includes_kex_offer(monkeypatch):
    import network_scanner.probing.ssh_kex as kex_module
    import network_scanner.probing.ssh_keyscan as ssh_module

    def fake_keyscan(host, port, *, timeout=8.0, baseline=None):
        return _fake_finding(f"{host}:{port}")

    def fake_kex(host, port, *, timeout=8.0, strict=False):
        return {
            "endpoint": f"{host}:{port}",
            "status": "OK",
            "method": "ssh-kexinit",
            "server_banner": "SSH-2.0-OpenSSH_9.2",
            "ciphers": ["aes128-ctr", "3des-cbc"],
            "macs": ["hmac-sha2-256-etm@openssh.com"],
            "weak": {"weak_ciphers": ["3des-cbc"], "weak_macs": [], "weak_kex": []},
            "legacy": {"legacy_macs": [], "legacy_host_keys": [], "legacy_kex": []},
            "policy_issues": ["SSH_WEAK_CIPHER_OFFERED"],
        }

    monkeypatch.setattr(ssh_module, "scan_ssh_host_keys", fake_keyscan)
    monkeypatch.setattr(kex_module, "probe_ssh_kex_offer", fake_kex)

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/ssh-scan",
            json={"hosts": ["10.0.0.5"], "include_kex": True},
        )
    assert response.status_code == 200
    finding = response.json()["findings"][0]
    assert finding["kex_offer"]["weak"]["weak_ciphers"] == ["3des-cbc"]
    assert "SSH_WEAK_CIPHER_OFFERED" in finding["policy_issues"]
    assert response.json()["ssh_probe_telemetry"]["ssh_weak_algorithm_offers"] == 1
