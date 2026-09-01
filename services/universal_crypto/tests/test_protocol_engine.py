"""§10/§11/§12 TLS / SSH / IPsec protocol analysis."""

from __future__ import annotations

from universal_crypto.protocol_engine import (
    IpsecAnalysis,
    SshAnalysis,
    TlsAnalysis,
)


def test_tls_suite_structured_observation():
    analysis = TlsAnalysis().analyze_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert analysis["known"] is True
    assert analysis["cipher"] == "AES-GCM"
    assert analysis["hash"] == "SHA-256"
    assert analysis["pfs"] is True
    assert analysis["key_exchange"] == "ECDH"


def test_tls13_suite():
    analysis = TlsAnalysis().analyze_suite("TLS_AES_256_GCM_SHA384")
    assert analysis["protocol_version"] == "TLS 1.3"
    assert analysis["cipher"] == "AES-GCM"
    assert analysis["hash"] == "SHA-384"


def test_tls_weak_suite_maps_3des():
    analysis = TlsAnalysis().analyze_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
    assert analysis["cipher"] == "3DES"
    assert analysis["pfs"] is False


def test_server_hello_parse():
    # TLS 1.2 record + ServerHello: version 0x0303, random(32),
    # session id len 0, cipher 0xC02F (ECDHE_RSA_AES128_GCM_SHA256),
    # compression 0, no extensions
    import struct
    body = struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", 0xC02F) + b"\x00" + struct.pack(">H", 0)
    record = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(body)) + bytes([0x02]) + body
    parsed = TlsAnalysis().parse_server_hello(record)
    assert parsed["legacy_version"] == "TLS 1.2"
    assert parsed["cipher_suite"] == "TLS 0xc02f"


def test_server_hello_tls13_extensions():
    # TLS 1.3 ServerHello with supported_versions (0x002b) + groups (0x000a)
    import struct
    body = struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", 0x1301) + b"\x00"
    ext = struct.pack(">H", 0x002b) + struct.pack(">H", 2) + struct.pack(">H", 0x0304)
    ext += struct.pack(">H", 0x000a) + struct.pack(">H", 2) + struct.pack(">H", 0x001d)
    body += struct.pack(">H", len(ext)) + ext
    record = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(body)) + bytes([0x02]) + body
    parsed = TlsAnalysis().parse_server_hello(record)
    assert parsed["cipher_suite"] == "TLS_AES_128_GCM_SHA256"
    assert "TLS 1.3" in parsed["supported_versions"]  # 0x0304 wire value
    assert "0x1d" in parsed["supported_groups"]  # x25519


def test_ssh_analysis():
    analysis = SshAnalysis().analyze(
        host_key="ssh-ed25519",
        kex="curve25519-sha256",
        ciphers=["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-cbc"],
        macs=["hmac-sha2-256"],
        signature_algorithms=["rsa-sha2-512"],
    )
    by_role = {o["role"]: o["algorithm"] for o in analysis["observations"]}
    assert by_role["host_key"] == "Ed25519"
    assert by_role["kex"] == "X25519"
    assert {"AES-GCM", "ChaCha20-Poly1305", "AES-CBC"} <= {
        o["algorithm"] for o in analysis["observations"] if o["role"] == "cipher"}
    assert by_role["mac"] == "HMAC-SHA256"
    assert by_role["signature_algorithm"] == "RSA"


def test_ssh_pqc_kex():
    analysis = SshAnalysis().analyze(kex="mlkem768x25519-sha256")
    assert any(o["algorithm"] == "ML-KEM-768" for o in analysis["observations"])


def test_ipsec_analysis():
    analysis = IpsecAnalysis().analyze(
        ike_version="IKEv2", encryption="AES_GCM_16",
        integrity="HMAC_SHA2_256_128", dh_group="19",
        authentication="PSK", pfs=True)
    assert analysis["encryption"]["algorithm"] == "AES-GCM"
    assert analysis["dh_group"]["algorithm"] == "ECDH-P-256"
    assert analysis["pfs"] is True
    assert analysis["quantum_status"] == "QUANTUM_VULNERABLE"


def test_ipsec_weak_dh_group():
    analysis = IpsecAnalysis().analyze(dh_group="2")
    assert analysis["dh_group"]["algorithm"] == "DH-1024"
    assert analysis["quantum_status"] == "QUANTUM_VULNERABLE"


def test_ipsec_policy_map():
    analysis = IpsecAnalysis()
    mapped = analysis.map_policy(vpn="site-vpn", gateway="gw-1",
                                 applications=["erp", "payments"])
    assert mapped["gateway"] == "gw-1"
    assert mapped["applications"] == ["erp", "payments"]
