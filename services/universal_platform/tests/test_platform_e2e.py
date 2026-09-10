"""§32 End-to-end platform journey — one control plane combining Network +
Cloud + Vendor + Hardware + Cryptography.

Drives the REAL crypto engine (UniversalCryptoEngine.scan) and the REAL
hardware scanner (HardwareScanner.scan) with synthetic network/cloud/vendor
reports, then runs: security enforcement → discovery → correlation → risk →
blast radius → what-if → combined CycloneDX CBOM+HBOM → evidence chain.

Deterministic, no AI anywhere.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from universal_platform.engine import UniversalPlatform
from universal_platform.evidence import EvidenceChain
from universal_platform.security import SecurityControls


def _crypto_domains() -> dict:
    from universal_crypto.engine import UniversalCryptoEngine
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # a real self-signed RSA-2048 cert (metadata only — keys never stored)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "payments.internal")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now + timedelta(days=335))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)

    report = UniversalCryptoEngine().scan({
        "policy": "NIST",
        "source_code": [{
            "language": "python", "asset_id": "payments",
            "text": "import hashlib\nh = hashlib.sha256(data)\n"
                    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "key = rsa.generate_private_key(public_exponent=65537, "
                    "key_size=2048)"}],
        "tls": [{"suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                 "endpoint": "payments.internal:443", "asset_id": "payments"}],
        "certificates": [{"der": der, "asset_id": "payments",
                          "location": "tls:payments.internal:443"}],
    })
    return {
        "observations": report["observations"],
        "libraries": report["libraries"],
        "certificates": report["certificates"],
    }


def _hardware_domains() -> dict:
    from universal_vendor.hardware.scanner import UniversalHardwareScanner

    report = UniversalHardwareScanner().scan({
        "asset_id": "pay-server-01",
        "device_type": "server",
        "dmi": {"manufacturer": "Dell", "product": "R760",
                "serial": "SN-X9", "bios_version": "2.14"},
        "pci_devices": [{"class": "cryptographic", "name": "HSM"}],
    })
    return {"assets": report.get("observations") or []}


def _synthetic_domains() -> dict:
    return {
        "network": {"assets": [
            {"asset_type": "load_balancer", "identity": "lb-pay-01",
             "ip": "10.0.0.10", "certificates": ["payments.internal"]},
            {"asset_type": "firewall", "identity": "fw-edge-01",
             "ip": "10.0.0.1"},
            {"asset_type": "vpn_gateway", "identity": "vpn-01",
             "ip": "10.0.0.2", "certificates": ["payments.internal"]},
        ]},
        "cloud": {"assets": [
            {"asset_type": "cloud_resource", "identity": "aws-elb-pay",
             "provider": "aws", "certificates": ["payments.internal"]},
            {"asset_type": "vm", "identity": "pay-server-01",
             "provider": "aws"},
        ]},
        "vendor": {"assets": [
            {"asset_type": "vendor", "identity": "Acme",
             "pqc_support": "ml-kem"},
            {"asset_type": "vendor_product", "identity": "Acme CryptoModule",
             "vendor": "Acme"},
        ]},
    }


def test_end_to_end_platform_pipeline():
    platform = UniversalPlatform()
    domains = _synthetic_domains()
    domains["crypto"] = _crypto_domains()
    # real hardware scanner output (DMI server host) + a hardware component
    # (HSM) that lives on that host — the cross-domain link the platform
    # exists to draw
    domains["hardware"] = {
        "assets": _hardware_domains()["assets"] + [
            {"asset_type": "hsm", "identity": "hsm-pci-01",
             "host": "pay-server-01", "firmware": "7.2",
             "crypto_capabilities": ["AES", "RSA", "mlkem768"]},
        ],
    }

    # ── security enforcement gates the request (§33) ─────────────────────
    controls = SecurityControls(authorized_scope=["10.0.0.0/8"])
    blocked = controls.enforce({"mode": "AGGRESSIVE", "scope": "10.9.0.0/16"})
    assert blocked["allowed"] is False
    allowed = controls.enforce({"mode": "SAFE", "scope": "10.0.0.0/8"})
    assert allowed["allowed"] is True

    # ── discovery: all five domains in one system (§1) ───────────────────
    report = platform.discover(domains)
    assert report["asset_count"] >= 10
    assert set(report["sources_run"]) == {"network", "cloud", "vendor",
                                          "hardware", "crypto"}
    assert all(report["verified"].values()), "every asset verifies"

    # hardware scanner really ran: DMI record present (the server is a
    # network-domain host; the HSM is the hardware-domain component)
    server = [a for a in report["assets"]
              if a["identity"] == "pay-server-01"
              and a["asset_type"] == "server"]
    assert server, "DMI host must be a network-domain server asset"
    assert server[0]["attributes"].get("firmware") == "2.14"
    hw = [a for a in report["assets"] if a["domain"] == "hardware"]
    assert hw, "hardware component assets expected"
    assert hw[0]["identity"] == "hsm-pci-01"
    assert any(r["kind"] == "has_hw" for r in report["relationships"])

    # crypto really ran: RSA + SHA-256 observations present
    algos = {a["identity"] for a in report["assets"]
             if a["asset_type"] == "algorithm"}
    assert "RSA" in algos and "SHA-256" in algos

    # ── correlation: cert ↔ lb/vpn/cloud; vm ↔ host; vendor ↔ product ───
    kinds = {r["kind"] for r in report["relationships"]}
    assert "uses_cert" in kinds and "vendor_of" in kinds

    # ── risk (§29) ───────────────────────────────────────────────────────
    estate = platform.risk()
    assert estate["count"] == report["asset_count"]
    assert estate["level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    # ── blast radius (§30): what breaks if the payments cert changes? ────
    blast = platform.blast("payments.internal")
    assert blast["affected_count"] >= 3
    assert any("lb" in a for a in blast["affected"])
    assert any("aws" in a for a in blast["affected"])

    # ── what-if (§31): replace RSA with ML-KEM-768 ───────────────────────
    wif = platform.what_if("RSA", "ML-KEM-768")
    assert wif["migration_plan"]["steps"]
    assert wif["checks"]["impact"]["projected_quantum_status"] in (
        "QUANTUM_SAFE", "UNKNOWN")

    # ── combined CycloneDX CBOM + HBOM (§21/§22) ─────────────────────────
    bom = platform.bom()
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    types = {c["type"] for c in bom["components"]}
    assert "cryptography" in types and "device" in types
    assert any(c["name"] == "pay-server-01" for c in bom["components"])
    assert bom["dependencies"], "relationships must be in the BOM"

    # ── live events (§18/§19) ────────────────────────────────────────────
    from universal_platform.events import PlatformEvent, PlatformEventType
    result = platform.ingest_event(PlatformEvent(
        event_type=PlatformEventType.CLOUD_RESOURCE_CHANGED,
        asset_identity="aws-elb-pay", domain="cloud",
        payload={"certificates": ["payments.internal"]}))
    assert result["changed"] is True
    assert "resource_recheck" in result["targeted_analysis"]

    # ── drift (§20) ──────────────────────────────────────────────────────
    baseline_state = {"crypto": sorted(algos), "network": ["lb-pay-01"]}
    platform.drift.set_baseline(baseline_state)
    drift = platform.drift_check(baseline_state)
    assert drift["drift_detected"] is False
    assert drift["categories"]["crypto"]["drift"] is False
    # a new algorithm shows up in live → crypto drift is detected
    drift2 = platform.drift_check(
        {"crypto": sorted(algos) + ["ML-KEM-768"], "network": ["lb-pay-01"]})
    assert drift2["categories"]["crypto"]["drift"] is True

    # ── evidence chain (§23) ─────────────────────────────────────────────
    chain = platform.evidence.verify()
    assert chain["valid"] is True
    assert chain["records"] >= 2


def test_evidence_chain_detects_tampering():
    chain = EvidenceChain()
    chain.append(asset="a", source="s", observation="o", evidence={"v": 1},
                 method="observation")
    chain.append(asset="b", source="s", observation="o", evidence={"v": 2},
                 method="api")
    assert chain.verify()["valid"] is True
    # tamper with a stored record
    chain.records[0]["evidence"] = {"v": 999}
    assert chain.verify()["valid"] is False
    assert chain.verify()["broken_at"] == 0


def test_platform_pipeline_one_shot():
    from universal_platform.engine import platform_pipeline
    result = platform_pipeline({"crypto": _crypto_domains()})
    assert result["allowed"] is True
    assert result["discovery"]["asset_count"] >= 2
    assert result["bom"]["bomFormat"] == "CycloneDX"
    assert result["evidence_chain_valid"] is True

    blocked = platform_pipeline(
        {"crypto": _crypto_domains()},
        security=SecurityControls(),
        request={"mode": "AGGRESSIVE"})
    assert blocked["allowed"] is False
    assert not blocked["security"]["allowed"]
