"""Enterprise layer — protocol discovery engine + probes (spec areas 6, 12).

The four classification statuses are distinct and strictly ordered:
PROTOCOL_PRESENT < CRYPTOGRAPHY_OBSERVED < CRYPTOGRAPHY_CONFIGURED <
CRYPTOGRAPHY_VERIFIED. Safe UDP probes never send handshake-init packets by
default (allow_init=False), enforced here.
"""

from __future__ import annotations

import pytest

from network_scanner.enterprise.protocols.engine import (
    ALL_PROTOCOLS,
    APPLICATION_PROTOCOLS,
    ENCRYPTION_PROTOCOLS,
    ENTERPRISE_PROTOCOLS,
    STATUSES,
    ProtocolDetectionEngine,
    ProtocolObservation,
    merge_status,
    status_from_findings,
)
from network_scanner.enterprise.protocols.probes import (
    _classify_udp_reply,
    _udp_magic,
    classify_banner_present,
    probe_tcp_banners,
    probe_udp_protocols,
)


# ------------------------------------------------------------- status rules

class TestStatusRules:
    def test_statuses_distinct_and_ordered(self) -> None:
        assert STATUSES == ("PROTOCOL_PRESENT", "CRYPTOGRAPHY_OBSERVED",
                            "CRYPTOGRAPHY_CONFIGURED", "CRYPTOGRAPHY_VERIFIED")

    def test_merge_status_stronger_wins(self) -> None:
        assert merge_status("PROTOCOL_PRESENT", "CRYPTOGRAPHY_OBSERVED") == "CRYPTOGRAPHY_OBSERVED"
        assert merge_status("CRYPTOGRAPHY_VERIFIED", "CRYPTOGRAPHY_OBSERVED") == "CRYPTOGRAPHY_VERIFIED"
        assert merge_status("CRYPTOGRAPHY_CONFIGURED", "PROTOCOL_PRESENT") == "CRYPTOGRAPHY_CONFIGURED"

    def test_status_from_findings(self) -> None:
        # no crypto info -> present only
        assert status_from_findings("TLS", [{"endpoint": "h", "status": "OK"}]) == "CRYPTOGRAPHY_OBSERVED"
        # negotiated cipher -> observed crypto
        assert status_from_findings("TLS", [{"status": "OK",
                                             "crypto": {"cipher_suite": "TLS_AES_128_GCM_SHA256"}}]) == "CRYPTOGRAPHY_OBSERVED"
        # verification result -> verified
        assert status_from_findings("TLS", [{"status": "OK",
                                             "policy_issues": ["CHAIN_VERIFIED"]}]) == "CRYPTOGRAPHY_VERIFIED"

    def test_protocol_families_cover_spec(self) -> None:
        for protocol in ("TLS", "DTLS", "QUIC", "SSH", "IPsec", "IKE", "WireGuard",
                         "OpenVPN", "SSTP"):
            assert protocol in ENCRYPTION_PROTOCOLS
        for protocol in ("HTTP/HTTPS", "SMTP/STARTTLS", "IMAP/STARTTLS", "POP3/STARTTLS",
                         "LDAP/LDAPS", "FTPS", "MQTT", "AMQP", "DB-TLS", "RDP-TLS", "K8S-API-TLS"):
            assert protocol in APPLICATION_PROTOCOLS
        for protocol in ("SAML", "OAuth", "OIDC", "Kerberos", "AD-CS"):
            assert protocol in ENTERPRISE_PROTOCOLS
        assert set(ALL_PROTOCOLS) == set(ENCRYPTION_PROTOCOLS + APPLICATION_PROTOCOLS + ENTERPRISE_PROTOCOLS)


# ------------------------------------------------------------- safe probes

class _FakeUdpSocket:
    def __init__(self, replies: dict[bytes, bytes]) -> None:
        self.replies = replies
        self.sent: list[bytes] = []

    def settimeout(self, t: float) -> None:
        pass

    def sendto(self, data: bytes, addr: tuple) -> None:
        self.sent.append(data)

    def recvfrom(self, size: int) -> tuple[bytes, tuple]:
        for magic, reply in self.replies.items():
            if self.sent and self.sent[-1].startswith(magic[:4]):
                return reply, ("127.0.0.1", 500)
        raise TimeoutError("no reply")

    def close(self) -> None:
        pass


class TestSafeUdpProbes:
    def test_init_packets_gated_by_allow_init(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for protocol in ("IKE", "WireGuard", "OpenVPN", "DTLS"):
            assert _udp_magic(protocol, allow_init=False) is None, protocol
            assert _udp_magic(protocol, allow_init=True) is not None, protocol

    def test_quic_magic_always_safe(self) -> None:
        assert _udp_magic("QUIC", allow_init=False) is not None

    def test_classify_udp_replies(self) -> None:
        # IKEv2 SA response: next payload SA(33) at 16, version 2.0 (0x20) at 17
        ike_reply = b"\x00" * 16 + bytes([33, 0x20]) + b"\x00" * 10
        assert _classify_udp_reply("IKE", ike_reply) is True
        assert _classify_udp_reply("IKE", b"\x00" * 28) is False
        # WireGuard handshake response: type 2, 92 bytes
        assert _classify_udp_reply("WireGuard", b"\x02" + b"\x00" * 91) is True
        # OpenVPN server reset: 0x28
        assert _classify_udp_reply("OpenVPN", b"\x28" + b"\x00" * 8) is True
        # QUIC v1 server initial
        assert _classify_udp_reply("QUIC", b"\xc0\x00\x00\x00\x01" + b"\x00" * 10) is True
        # DTLS ServerHello
        assert _classify_udp_reply("DTLS", b"\x16\xfe\xfd" + b"\x00\x00") is True

    def test_probe_udp_safe_mode_sends_nothing_for_gated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.protocols.probes as probes

        sock = _FakeUdpSocket(replies={})
        monkeypatch.setattr(probes.socket, "socket", lambda *a, **k: sock)
        results = probe_udp_protocols("127.0.0.1", ports=[500, 51820, 1194], allow_init=False)
        assert results == {"IKE": False, "WireGuard": False, "OpenVPN": False}

    def test_probe_udp_detects_ike(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.protocols.probes as probes

        ike_reply = b"\x00" * 16 + bytes([33, 0x20]) + b"\x00" * 10
        sock = _FakeUdpSocket(replies={b"\x01\x01\x01\x01": ike_reply})
        monkeypatch.setattr(probes.socket, "socket", lambda *a, **k: sock)
        results = probe_udp_protocols("127.0.0.1", ports=[500], allow_init=True)
        assert results["IKE"] is True


class _FakeTcpSocket:
    def __init__(self, banners: dict[int, bytes]) -> None:
        self.banners = banners
        self._connected_port = 0

    def settimeout(self, t: float) -> None:
        pass

    def connect(self, addr: tuple) -> None:
        self._connected_port = addr[1]

    def recv(self, size: int) -> bytes:
        if self._connected_port in self.banners:
            return self.banners[self._connected_port]
        raise TimeoutError("no banner")

    def close(self) -> None:
        pass


class TestTcpBannerProbes:
    def test_ssh_banner_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.protocols.probes as probes

        sock = _FakeTcpSocket({22: b"SSH-2.0-OpenSSH_9.3\r\n"})
        monkeypatch.setattr(probes.socket, "socket", lambda *a, **k: sock)
        results = probe_tcp_banners("127.0.0.1", ports=[22])
        assert results["SSH"] is True

    def test_tls_port_presence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.protocols.probes as probes

        sock = _FakeTcpSocket({443: b""})
        monkeypatch.setattr(probes.socket, "socket", lambda *a, **k: sock)
        results = probe_tcp_banners("127.0.0.1", ports=[443])
        assert results["TLS"] is True

    def test_closed_port_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.protocols.probes as probes

        class Refuse(_FakeTcpSocket):
            def connect(self, addr: tuple) -> None:
                raise ConnectionRefusedError("closed")

        monkeypatch.setattr(probes.socket, "socket", lambda *a, **k: Refuse({}))
        assert probe_tcp_banners("127.0.0.1", ports=[443]) == {}

    def test_classify_banner_present(self) -> None:
        assert classify_banner_present("SSH", "SSH-2.0-OpenSSH")
        assert not classify_banner_present("SSH", "HTTP/1.1 200 OK")


# ------------------------------------------------------------- engine

class TestProtocolEngine:
    def test_record_and_dedupe(self) -> None:
        engine = ProtocolDetectionEngine()
        engine.record(ProtocolObservation("h1", "TLS", "PROTOCOL_PRESENT", confidence=0.5))
        engine.record(ProtocolObservation("h1", "TLS", "CRYPTOGRAPHY_VERIFIED", confidence=0.95))
        obs = engine.for_asset("h1")
        assert len(obs) == 1
        assert obs[0].status == "CRYPTOGRAPHY_VERIFIED"
        assert obs[0].confidence == 0.95

    def test_from_probe_results_verified(self) -> None:
        engine = ProtocolDetectionEngine()
        count = engine.from_probe_results("api.example.com", [{
            "endpoint": "api.example.com:443", "status": "OK",
            "crypto": {"tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256"},
        }])
        assert count == 1
        obs = engine.for_asset("api.example.com")[0]
        assert obs.protocol == "TLS"
        assert obs.status == "CRYPTOGRAPHY_VERIFIED"
        assert obs.method == "tls-handshake"

    def test_from_probe_results_observed_only(self) -> None:
        engine = ProtocolDetectionEngine()
        # version without a negotiated cipher -> observed, not verified
        engine.from_probe_results("h", [{"endpoint": "h:443", "status": "OK",
                                         "crypto": {"tls_version": "TLSv1.2"}}])
        obs = engine.for_asset("h")[0]
        assert obs.status == "CRYPTOGRAPHY_OBSERVED"
        assert obs.confidence < 0.95

    def test_from_passive_metadata(self) -> None:
        engine = ProtocolDetectionEngine()
        count = engine.from_passive_metadata("h", ["TLS", "SMTP/STARTTLS", "NOT_A_PROTOCOL"])
        assert count == 2
        statuses = {obs.protocol: obs.status for obs in engine.for_asset("h")}
        assert statuses["TLS"] == "CRYPTOGRAPHY_OBSERVED"

    def test_from_vendor_config(self) -> None:
        engine = ProtocolDetectionEngine()
        engine.from_vendor_config("r1", [
            {"protocol": "IPsec", "status": "CRYPTOGRAPHY_CONFIGURED", "detail": "ikev2"},
            {"protocol": "SSH"},
            {"name": "TLS"},
        ])
        statuses = {obs.protocol: obs.status for obs in engine.for_asset("r1")}
        assert statuses["IPsec"] == "CRYPTOGRAPHY_CONFIGURED"
        assert statuses["SSH"] == "CRYPTOGRAPHY_CONFIGURED"
        assert statuses["TLS"] == "CRYPTOGRAPHY_CONFIGURED"

    def test_engine_gates_udp_init(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import network_scanner.enterprise.protocols.engine as engine_mod
        import network_scanner.enterprise.protocols.probes as probes

        calls: dict[str, bool] = {}

        def fake_udp(host: str, **kw: Any) -> dict[str, bool]:
            calls["udp"] = kw.get("allow_init", False)
            return {}

        def fake_tcp(host: str, **kw: Any) -> dict[str, bool]:
            return {}

        monkeypatch.setattr(probes, "probe_udp_protocols", fake_udp)
        monkeypatch.setattr(probes, "probe_tcp_banners", fake_tcp)
        # engine imports the probe functions at module load; patch through engine
        monkeypatch.setattr(engine_mod, "probe_udp_protocols", fake_udp)
        monkeypatch.setattr(engine_mod, "probe_tcp_banners", fake_tcp)

        safe = ProtocolDetectionEngine(allow_udp_init=False)
        safe.from_active_probes("h", ports=(500, 443))
        assert calls["udp"] is False

        deep = ProtocolDetectionEngine(allow_udp_init=True)
        deep.from_active_probes("h", ports=(500, 443))
        assert calls["udp"] is True
