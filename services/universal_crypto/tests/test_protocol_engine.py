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
    assert "x25519" in parsed["supported_groups"]  # named, not raw hex


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
    # hybrid KEX reports its hybrid identity — the classical half alone would
    # understate the endpoint's quantum posture
    analysis = SshAnalysis().analyze(kex="mlkem768x25519-sha256")
    assert any(o["algorithm"] == "X25519MLKEM768" for o in analysis["observations"])
    analysis = SshAnalysis().analyze(kex="sntrup761x25519-sha512@openssh.com")
    assert any(o["algorithm"] == "X25519SNTRUP761" for o in analysis["observations"])


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


def test_tls_hybrid_pqc_groups_named():
    # RFC 10024 hybrids + pre-standard Kyber drafts must come out named, not
    # as anonymous hex — otherwise quantum classification degrades to UNKNOWN
    import struct
    groups = [0x11EC, 0x11EB, 0x11EF, 0x6399, 0x001D]
    body = struct.pack(">H", 0x0303) + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", 0x1301) + b"\x00"
    ext = struct.pack(">H", 0x002b) + struct.pack(">H", 2) + struct.pack(">H", 0x0304)
    ext += struct.pack(">H", 0x000a) + struct.pack(">H", 2 * len(groups))
    for g in groups:
        ext += struct.pack(">H", g)
    body += struct.pack(">H", len(ext)) + ext
    record = bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(body)) + bytes([0x02]) + body
    parsed = TlsAnalysis().parse_server_hello(record)
    assert parsed["supported_groups"] == [
        "X25519MLKEM768", "SecP256r1MLKEM768", "X25519MLKEM1024",
        "X25519Kyber768Draft00", "x25519"]
    # unknown codepoints still fall back to hex
    from universal_crypto.protocol_engine import TLS_GROUPS
    assert TLS_GROUPS.get(0x9999, "0x9999") == "0x9999"


def test_ipsec_mlkem_dh_groups():
    # RFC ipsecme-ikev2-mlkem KE methods: IKEv2 can negotiate pure ML-KEM
    for group, name in (("35", "ML-KEM-512"), ("36", "ML-KEM-768"), ("37", "ML-KEM-1024")):
        analysis = IpsecAnalysis().analyze(dh_group=group)
        assert analysis["dh_group"]["algorithm"] == name
        assert analysis["quantum_status"] == "QUANTUM_SAFE"


def test_ipsec_dh_group_registry_matches_iana():
    # groups 27-30 are brainpool (not X25519/X448); 31/32 are the RFC 8031
    # curves — the old table mislabelled 27/28 and duplicated 31
    from universal_crypto.protocol_engine import _IPSEC_DH
    assert _IPSEC_DH["27"] == "BRAINPOOLP224R1"
    assert _IPSEC_DH["28"] == "BRAINPOOLP256R1"
    assert _IPSEC_DH["31"] == "X25519"
    assert _IPSEC_DH["32"] == "X448"
