"""§36 End-to-end test — one realistic scenario through the whole product.

Journey: multi-source discovery (18-language AST, TLS/SSH/IPsec protocols,
real certificate, key metadata, trust store, libraries, binary, runtime,
hard-coded, randomness, custom crypto) → evidence fusion → explainable
findings → quantum classification → live crypto engine (events → state →
targeted recalc → versioned CycloneDX CBOM → PQC risk) → state_at replay →
what-if migration simulator → ground-truth accuracy platform.

Deterministic, no AI anywhere.
"""

from __future__ import annotations

import base64
import json
import struct
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from universal_crypto.accuracy import AccuracyPlatform, default_detector
from universal_crypto.engine import UniversalCryptoEngine
from universal_crypto.live.engine import LiveCryptoEngine
from universal_crypto.live.events import CryptoEvent
from universal_crypto.models import CryptoEventType
from universal_crypto.simulator import MigrationSimulator


def _rsa_cert_der() -> bytes:
    """A real self-signed RSA-2048 cert (metadata only — keys never stored)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "payments.internal")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=335))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("payments.internal")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _minimal_elf_with_crypto_symbols() -> bytes:
    """ELF64 with a .symtab carrying EVP_sha256 + .rodata "OpenSSL 3.0.13"."""
    elf = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8)
    elf += struct.pack("<HHIQQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 0, 0, 64, 0, 0, 64, 0)
    symtab = b"EVP_sha256\x00"
    rodata = b"OpenSSL 3.0.13\x00"
    shstr = b"\x00.symtab\x00.rodata\x00.shstrtab\x00"
    body = symtab + rodata
    shoff = len(elf) + len(body)
    shstr_off = shoff + 4 * 64
    sym_ent = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym_ent += struct.pack("<IBBHQQ", 0, 0, 0, 2, 0, 0)

    def sh(name, typ, off, size):
        return struct.pack("<IIQQQQIIQQ", name, typ, 0, off, size, 0, 0, 0, 0, 0)

    sections = b""
    sections += sh(0, 0, 0, 0)
    sections += sh(len(".symtab") + 1, 2, shoff, len(sym_ent))
    sections += sh(len(".symtab\x00.rodata") + 1, 1, shoff + len(symtab), len(rodata))
    sections += sh(len(".symtab\x00.rodata\x00.shstrtab") + 1, 3, shstr_off, len(shstr))
    elf += body + sections + shstr
    struct.pack_into("<Q", elf, 0x28, shoff)
    struct.pack_into("<H", elf, 0x3C, 4)
    struct.pack_into("<H", elf, 0x3E, 3)
    return bytes(elf)


# ── 1. full §36 multi-source scan ───────────────────────────────────────

def test_end_to_end_scan_pipeline():
    engine = UniversalCryptoEngine()
    report = engine.scan({
        "policy": "NIST",
        "source_code": [
            {"language": "python", "asset_id": "auth",
             "location": "auth/main.py",
             "text": "import hashlib\nh = hashlib.sha256(data)\n"
                     "key = os.urandom(32)"},
            {"language": "java", "asset_id": "auth",
             "location": "auth/SignatureService.java",
             "text": 'Signature.getInstance("SHA384withRSA")\n'
                     'Cipher.getInstance("AES/GCM/NoPadding")'},
            {"language": "typescript", "asset_id": "web",
             "location": "web/crypto.ts",
             "text": "import { createHash } from 'node:crypto';\n"
                     "const h = createHash('sha256', data).digest('hex');"},
            {"language": "python", "asset_id": "auth",
             "location": "auth/private_crypto.py",
             "text": "def custom_sign(msg):\n"
                     "    return proprietary_signing(msg)"},
            {"language": "go", "asset_id": "payments",
             "location": "payments/tls.go",
             "text": "import \"crypto/tls\"\n"
                     "cfg := &tls.Config{MinVersion: tls.VersionTLS13}"},
            {"language": "solidity", "asset_id": "chain",
             "location": "chain/Verify.sol",
             "text": "bytes32 h = keccak256(abi.encodePacked(a, b));"},
        ],
        "tls": [
            {"suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
             "endpoint": "auth:443", "asset_id": "auth"},
            {"suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
             "endpoint": "legacy:443", "asset_id": "legacy"},
        ],
        "ssh": [{"host_key": "ssh-ed25519", "kex": "curve25519-sha256",
                 "ciphers": ["aes256-gcm@openssh.com"], "macs": ["hmac-sha2-256"],
                 "host": "bastion", "asset_id": "infra"}],
        "ipsec": [{"ike_version": "IKEv2", "encryption": "AES_GCM_16",
                   "integrity": "HMAC_SHA2_256_128", "dh_group": "19",
                   "authentication": "PSK", "pfs": True,
                   "gateway": "gw-1", "asset_id": "vpn"}],
        "certificates": [{"der": _rsa_cert_der(), "asset_id": "payments",
                          "location": "tls:payments.internal:443"}],
        "key_metadata": [
            {"key_id": "k-sign", "algorithm": "RSA", "size": 2048,
             "usage": "signing", "generated_at": "2021-01-01T00:00:00+00:00",
             "stored": True, "used": True, "location": "hsm-slot-1",
             "hardware_backed": True},
            {"key_id": "k-orphan", "algorithm": "AES", "size": 256,
             "usage": "encryption", "generated_at": "2020-06-01T00:00:00+00:00",
             "revoked_at": "2021-06-01T00:00:00+00:00", "still_referenced": True,
             "stored": True, "used": True},
        ],
        "trust_store": [{"store_name": "system.jks", "asset_id": "auth",
                         "expected_roots": ["CN=OrgRoot"],
                         "anchors": [
                             {"subject": "CN=OrgRoot", "expired": False,
                              "signature_algorithm": "SHA256WithRSA",
                              "public_key_algorithm": "RSA", "key_size": 4096},
                             {"subject": "CN=RogueRoot", "expired": False,
                              "signature_algorithm": "SHA1WithRSA",
                              "public_key_algorithm": "RSA", "key_size": 2048},
                         ]}],
        "libraries": [{"imports": ["openssl/ssl.h", "libssl.so"],
                       "symbols": ["SSL_CTX_new", "EVP_sha256"],
                       "strings": ["OpenSSL 3.0.13"], "asset_id": "auth"}],
        "binaries": [{"name": "payments-svc", "asset_id": "payments",
                      "data": base64.b64encode(_minimal_elf_with_crypto_symbols()).decode()}],
        "runtime": [{"process": "payments-svc", "asset_id": "payments",
                     "loaded_libraries": ["libssl.so"],
                     "api_calls": ["EVP_EncryptUpdate", "RAND_bytes"],
                     "connections": [{"protocol": "TLS", "peer": "gw:443"}]}],
        "hardcoded_scan": [{"language": "java", "asset_id": "auth",
                            "text": 'cipher = "AES/GCM/NoPadding"\nkey_size = 2048'}],
        "randomness_scan": [{"language": "python", "asset_id": "auth",
                             "text": "import random\nkey = random.choice(chars)"}],
        "custom_crypto": [{"implementation_name": "my_digest", "asset_id": "auth"}],
    })

    # ── every report section is populated and consistent ────────────────
    assert report["observations"], "observations expected"
    assert report["findings"], "findings expected"
    assert report["quantum_classifications"]
    assert report["readiness"]
    assert report["agility"]
    assert report["certificates"], "certificate analysis expected"
    assert report["trust_stores"]
    assert report["libraries"]
    assert report["key_lifecycle"]["findings"], "lifecycle findings expected"
    assert report["graph"]["nodes"] and report["graph"]["edges"]
    assert report["unknown_crypto"]

    # ── §29 every finding is explainable ────────────────────────────────
    for finding in report["findings"]:
        for field in ("what", "where", "how_detected", "evidence",
                      "confidence", "impact", "recommendation"):
            assert finding.get(field), f"finding missing {field}: {finding}"

    # ── §3 enriched shape: RSA-PSS with padding + digest ────────────────
    rsa_pss = next(o for o in report["observations"]
                   if o["algorithm"] == "RSA-PSS")
    assert rsa_pss["padding"] == "RSA-PSS"
    assert rsa_pss["digest"] == "SHA-384"

    # ── §18 quantum classification: priority, never blanket RSA=BAD ─────
    quantum = report["quantum_classifications"]
    rsa_key = next(k for k in quantum if k.startswith("RSA"))
    assert quantum[rsa_key]["quantum_status"] == "QUANTUM_VULNERABLE"
    assert quantum[rsa_key]["migration_priority"] in ("HIGH", "MEDIUM")
    mlkem = next((k for k in quantum if "ML-KEM" in k), None)
    if mlkem:
        assert quantum[mlkem]["quantum_status"] == "QUANTUM_SAFE"

    # ── §22 policy-driven weak crypto (3DES under NIST) ─────────────────
    assert any(o["algorithm"] in ("3DES", "AES-CBC", "TLS") for o in report["observations"])

    # ── §15 trust store finds the unexpected + weak anchor ──────────────
    trust = report["trust_stores"][0]
    trust_types = {f["type"] for f in trust["findings"]}
    assert "unexpected_ca" in trust_types, trust["findings"]
    assert "deprecated_algorithm" in trust_types  # SHA1WithRSA anchor

    # ── §26 key lifecycle findings ───────────────────────────────────────
    lifecycle_types = {f["type"] for f in report["key_lifecycle"]["findings"]}
    assert "never_rotated" in lifecycle_types
    assert "orphaned" in lifecycle_types

    # ── §25 randomness: weak PRNG feeding a key is flagged ──────────────
    assert report["randomness"][0]["verdict"] == "DANGEROUS_PATTERN"

    # ── §21 hard-coded crypto ────────────────────────────────────────────
    assert report["hardcoded"][0]["migration_risk"] == "HIGH"

    # ── §24 custom crypto: UNKNOWN never gets a security label ──────────
    custom = report["custom_crypto"][0]
    assert custom["classification"] == "CUSTOM_IMPLEMENTATION"
    assert custom.get("security_label") is None

    # ── §31 unknown crypto queue is populated ────────────────────────────
    assert any("custom_sign" in u["snippet"] for u in report["unknown_crypto"])


# ── 2. live engine: the §34 certificate-renewal journey ─────────────────

def test_end_to_end_live_engine_cert_renewal():
    engine = LiveCryptoEngine()
    t0 = datetime.now(timezone.utc)

    def event(event_type, at, asset_id="payments", **payload):
        return CryptoEvent(event_type=event_type, asset_id=asset_id,
                           observed_at=at, payload=payload)

    # discovery phase
    engine.ingest(event(CryptoEventType.TLS_POLICY_CHANGED, t0,
                        protocol="TLS", min_version="TLS 1.3", pfs=True))
    before_version = engine.state("payments").cbom_version

    # vulnerable certificate arrives → risk climbs
    engine.ingest(event(CryptoEventType.CERT_NEW, t0 + timedelta(seconds=60),
                        certificate_id="cert-1",
                        subject="payments.internal", signature_algorithm="RSA-PSS",
                        public_key_algorithm="RSA", key_size=2048))
    assert engine.risk("payments")["level"] == "HIGH"
    assert engine.state("payments").readiness == "QUANTUM_VULNERABLE"

    # §34 example: certificate renewed → signature changed → CBOM bumped →
    # PQC status recalculated → risk updated
    result = engine.ingest(event(CryptoEventType.CERT_RENEWED,
                                 t0 + timedelta(seconds=120),
                                 certificate_id="cert-1",
                                 previous_signature_algorithm="RSA-PSS",
                                 signature_algorithm="ML-DSA-65",
                                 public_key_algorithm="ML-DSA-65", key_size=1952))
    state = engine.state("payments")
    assert state.certificates["cert-1"]["status"] == "RENEWED"
    assert state.quantum_status["ML-DSA-65"] == "QUANTUM_SAFE"
    assert "RSA-PSS" not in state.quantum_status
    assert state.cbom_version == before_version + 2  # CERT_NEW + CERT_RENEWED
    assert result["readiness"] == "PQC_READY"
    assert engine.risk("payments")["level"] == "NONE"

    # ── §35 live CBOM is CycloneDX with registry OIDs ───────────────────
    cbom = engine.cbom("payments")
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    crypto_components = [c for c in cbom["components"] if c["type"] == "cryptography"]
    assert any(c["name"] == "ML-DSA-65" for c in crypto_components)
    ml_dsa = next(c for c in crypto_components if c["name"] == "ML-DSA-65")
    assert ml_dsa["cryptography"]["algorithm"]["oid"]
    assert any(r["relationship"] == "uses" for r in cbom["relationships"])
    assert cbom["metadata"]["properties"]  # readiness/agility attached

    # ── state_at replay: raw state evolution is reconstructable ─────────
    # (derived quantum/readiness are recomputed live by the engine; the
    # journal faithfully reconstructs the underlying crypto state)
    past = engine.state_engine.state_at(
        "payments", t0 + timedelta(seconds=90))
    assert past["certificates"]["cert-1"]["status"] == "VALID"
    assert past["certificates"]["cert-1"]["signature_algorithm"] == "RSA-PSS"
    assert "ML-DSA-65" not in past["quantum_status"]
    replayed = engine.state_engine.state_at(
        "payments", t0 + timedelta(seconds=180))
    assert replayed["certificates"]["cert-1"]["status"] == "RENEWED"
    assert replayed["certificates"]["cert-1"]["signature_algorithm"] == "ML-DSA-65"


# ── 3. what-if migration agrees with the readiness engine ───────────────

def test_end_to_end_simulator_consistency():
    sim = MigrationSimulator().simulate(
        current_algorithm="RSA", target_algorithm="ML-KEM-768",
        protocol="TLS", library="OpenSSL", hardware="HSM", usage=True)
    assert sim["projected_quantum_status"] == "QUANTUM_SAFE"
    assert sim["risk_impact"]["risk_reduction"] == "HIGH"
    assert sim["migration_readiness"] == "READY"
    assert sim["compatible"] is True
    assert sim["agility_after"] > sim["agility_current"]


# ── 4. ground-truth accuracy platform over every dataset ────────────────

def test_end_to_end_accuracy_platform():
    platform = AccuracyPlatform()
    detector = default_detector()
    f1s = []
    for name in platform.dataset_names():
        result = platform.evaluate_dataset(name, detector)
        overall = result["metrics"]["overall"]
        f1s.append(overall["f1"])
        assert overall["precision"] >= 0.9, name
        assert overall["recall"] >= 0.9, name
        assert overall["false_positive_rate"] <= 0.05, name
    assert sum(f1s) / len(f1s) >= 0.95
    # every evaluator category is measured on at least one dataset
    for cat in ("algorithm", "protocol", "certificate", "library",
                "implementation", "weak_crypto", "pqc_classification"):
        measured = False
        for name in platform.dataset_names():
            counts = platform.evaluate_dataset(name, detector)["metrics"][cat]
            if counts["tp"] + counts["fp"] + counts["fn"] > 0:
                measured = True
                break
        assert measured, f"category {cat} never exercised"


# ── 5. the CLI runs the same engine end-to-end ──────────────────────────

def test_end_to_end_cli_scan(capsys, tmp_path):
    from universal_crypto.cli import main
    request = tmp_path / "request.json"
    request.write_text(json.dumps({
        "source_code": [{"language": "python", "asset_id": "svc",
                         "text": "import hashlib\nh = hashlib.sha256(x)"}],
        "tls": [{"suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                 "endpoint": "svc:443"}],
        "policy": "NIST",
    }))
    assert main(["scan", "--request", str(request)]) == 0
    out = capsys.readouterr().out
    assert "SHA-256" in out
    assert "findings:" in out
    assert "quantum=" in out

    assert main(["simulate", "--current", "RSA", "--target", "ML-KEM-768",
                 "--protocol", "TLS", "--library", "OpenSSL",
                 "--hardware", "HSM"]) == 0
    out = capsys.readouterr().out
    assert "READY" in out and "HIGH reduction" in out

    assert main(["accuracy"]) == 0
    out = capsys.readouterr().out
    assert "MEAN" in out

    # ── machine-readable export: --json on stdout, -o to a file ────────
    assert main(["scan", "--request", str(request), "--json"]) == 0
    exported = json.loads(capsys.readouterr().out)
    for key in ("observations", "findings", "quantum_classifications",
                "readiness", "graph", "unknown_crypto"):
        assert key in exported, key
    assert exported["observations"]  # same pipeline, full report

    out_path = tmp_path / "report.json"
    assert main(["scan", "--request", str(request), "-o", str(out_path)]) == 0
    assert out_path.exists()
    assert json.loads(out_path.read_text())["observations"]
