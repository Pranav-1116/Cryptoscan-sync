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


# --------------------------------------------------------------------------- #
# QUIC / DTLS / WireGuard (round 17 — audits 13/14 "protocol coverage gaps")
# --------------------------------------------------------------------------- #

def test_quic_analysis_maps_tls13_suites_and_groups():
    from universal_crypto.protocol_engine import QuicAnalysis

    analysis = QuicAnalysis().analyze(
        cipher_suite="TLS_AES_256_GCM_SHA384", key_exchange="x25519", version="1")
    assert analysis["protocol"] == "QUIC"
    assert analysis["protocol_version"] == "QUIC v1"
    by_role = {o["role"]: o for o in analysis["observations"]}
    assert by_role["cipher_suite"]["algorithm"] == "AES-GCM"
    assert by_role["key_exchange"]["algorithm"] == "X25519"
    assert by_role["version"]["value"] == "QUIC v1"

    # numeric group codepoints resolve through the TLS registry
    analysis2 = QuicAnalysis().analyze(key_exchange="4588")
    assert {o["algorithm"] for o in analysis2["observations"] if o["role"] == "key_exchange"} == {
        "X25519MLKEM768"
    }

    # non-TLS-1.3 suites (QUIC v1 forbids them) and unknown groups say so
    analysis3 = QuicAnalysis().analyze(
        cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange="mystery-group", version="9")
    by_role3 = {o["role"]: o for o in analysis3["observations"]}
    assert by_role3["cipher_suite"]["algorithm"] == "UNKNOWN"
    assert by_role3["key_exchange"]["algorithm"] == "UNKNOWN"
    assert analysis3["protocol_version"] == "9"


def test_dtls_analysis_reuses_iana_registry():
    from universal_crypto.protocol_engine import DtlsAnalysis

    analysis = DtlsAnalysis().analyze(
        suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", version="1.2")
    assert analysis["protocol"] == "DTLS"
    assert analysis["protocol_version"] == "DTLS 1.2"
    assert analysis["pfs"] is True
    roles = {o["role"]: o["algorithm"] for o in analysis["observations"]}
    assert roles["cipher"] == "AES-GCM"
    assert roles["key_exchange"] == "ECDH"
    assert roles["hash"] == "SHA-256"

    # DTLS 1.3 suites and unknown suites
    a13 = DtlsAnalysis().analyze(suite="TLS_CHACHA20_POLY1305_SHA256", version="1.3")
    assert a13["protocol_version"] == "DTLS 1.3"
    assert a13["pfs"] is True
    assert {o["algorithm"] for o in a13["observations"]} == {
        "ChaCha20-Poly1305", "TLS1.3-KE", "SHA-256"}
    a_unk = DtlsAnalysis().analyze(suite="SOME_NOVEL_SUITE")
    assert all(o["algorithm"] == "UNKNOWN" for o in a_unk["observations"])
    assert a_unk["pfs"] is False
    a_none = DtlsAnalysis().analyze()
    assert a_none["observations"] == [] and a_none["pfs"] is None


def test_wireguard_analysis_is_fixed_not_negotiated():
    from universal_crypto.protocol_engine import WireGuardAnalysis

    analysis = WireGuardAnalysis().analyze()
    assert analysis["negotiable"] is False
    assert analysis["noise_pattern"] == "Noise_IKpsk2"
    assert analysis["quantum_status"] == "QUANTUM_VULNERABLE"  # X25519 kex
    algos = {o["role"]: o["algorithm"] for o in analysis["observations"]}
    assert algos["kex"] == "X25519"
    assert algos["cipher"] == "ChaCha20-Poly1305"
    assert algos["hash"] == "BLAKE2s"
    assert algos["integrity"] == "HMAC-BLAKE2s"
    assert algos["kdf"] == "HKDF-BLAKE2s"

    pskless = WireGuardAnalysis().analyze(psk=False)
    assert all(o["role"] != "psk_mode" for o in pskless["observations"])


def test_engine_emits_quic_dtls_wireguard_drafts():
    from universal_crypto.engine import UniversalCryptoEngine

    engine = UniversalCryptoEngine()
    report = engine.scan(inputs={
        "quic": [{"endpoint": "https://hq.example.com", "asset_id": "hq",
                  "cipher_suite": "TLS_AES_128_GCM_SHA256",
                  "key_exchange": "x25519", "version": "1"}],
        "dtls": [{"endpoint": "coaps://sensor-7.lan", "asset_id": "sensor",
                  "suite": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}],
        "wireguard": [{"endpoint": "vpn-gw-1", "asset_id": "vpn"}],
    })
    obs = report["observations"]
    quic = [o for o in obs if o["protocol"] == "QUIC"]
    dtls = [o for o in obs if o["protocol"] == "DTLS"]
    wg = [o for o in obs if o["protocol"] == "WireGuard"]
    assert {(o["algorithm"], o["location"]) for o in quic} >= {
        ("AES-GCM", "https://hq.example.com"), ("X25519", "https://hq.example.com")}
    assert any(o["algorithm"] == "ECDH" for o in dtls)
    assert {o["algorithm"] for o in wg} >= {"X25519", "ChaCha20-Poly1305", "BLAKE2s"}
    # version observations stay metadata, never crypto observations
    assert all(o["algorithm"] != "QUIC" for o in quic)


def test_engine_fuses_same_algorithm_across_protocols_as_evidence():
    """QUIC and WireGuard X25519 on ONE asset corroborate one observation (§28)."""
    from universal_crypto.engine import UniversalCryptoEngine

    engine = UniversalCryptoEngine()
    report = engine.scan(inputs={
        "quic": [{"endpoint": "https://hq.example.com", "asset_id": "edge",
                  "cipher_suite": "TLS_AES_128_GCM_SHA256", "key_exchange": "x25519"}],
        "wireguard": [{"endpoint": "vpn-gw-1", "asset_id": "edge"}],
    })
    x25519 = [o for o in report["observations"] if o["algorithm"] == "X25519"]
    assert len(x25519) == 1, "same asset + same algorithm fuse into one observation"
    details = " | ".join(e["detail"] for e in x25519[0]["evidence"])
    assert "QUIC" in details and "WireGuard" in details
