"""network_runner enterprise extras: IPsec/IKE + DNSSEC monitor targets.

Local UDP IKE responder + local DNS server stand in for real hosts — the
runner's config.ipsec / config.dnssec must surface weak crypto as monitor
issues and mark the target degraded, exactly like the TLS path does.
"""

from __future__ import annotations

import socket
import struct
import threading

from worker.monitor.runners import network_runner


# ------------------------------------------------------------------ IKE


def _transform(ttype: int, tid: int, key_length: int = 0) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_length) if key_length else b""
    body = bytes([ttype, 0]) + struct.pack("!H", tid) + attrs
    return struct.pack("!H", len(body) + 2) + body


def _sa_payload_with(transforms: list[bytes]) -> bytes:
    proposal = bytes([1, 1, 0, len(transforms)]) + b"".join(transforms)
    return bytes([34, 0]) + struct.pack("!H", len(proposal) + 4) + proposal


def _ike_response(payload: bytes) -> bytes:
    header = struct.pack(
        "!8s8sBBBBII",
        b"\x11" * 8, b"\x22" * 8, 33, 0x20, 34, 0x08, 0, len(payload) + 28,
    )
    return header + payload


class _IkeResponder:
    def __init__(self, transforms: list[bytes]):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.transforms = transforms
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        self.sock.settimeout(5.0)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            self.sock.sendto(_ike_response(_sa_payload_with(self.transforms)), addr)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()


# ------------------------------------------------------------------ DNS


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in str(name).rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


class _DnsServer:
    """Answers SOA always; DNSKEY/DS only when provided (else unsigned zone)."""

    def __init__(self, zone: str, dnskey: list[bytes]):
        self.zone = zone
        self.dnskey = dnskey
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        self.sock.settimeout(5.0)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            qid = struct.unpack("!H", data[:2])[0]
            qtype = self._qtype(data)
            answers: list[tuple[int, bytes]] = []
            if qtype == 6:  # SOA
                rdata = _encode_name("ns1.example.") + _encode_name("host.example.") + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)
                answers.append((6, rdata))
            elif qtype == 48:  # DNSKEY
                answers = [(48, r) for r in self.dnskey]
            header = struct.pack("!HHHHHH", qid, 0x8180, 1, len(answers), 0, 0)
            question = data[12:]
            body = b""
            for rtype, rdata in answers:
                body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
            self.sock.sendto(header + question + body, addr)

    @staticmethod
    def _qtype(data: bytes) -> int:
        try:
            pos = 12
            while data[pos] != 0:
                pos += data[pos] + 1
            return struct.unpack("!H", data[pos + 1:pos + 3])[0]
        except Exception:
            return 0

    def close(self) -> None:
        self._stop.set()
        self.sock.close()


# ------------------------------------------------------------------ tests


def test_network_runner_ipsec_and_dnssec_flags_issues():
    # ipsec: point the probe at the ephemeral responder port so weak
    # transforms are really classified over the wire
    responder = _IkeResponder([_transform(1, 2), _transform(2, 2), _transform(4, 2)])  # 3DES/SHA1/MODP-1024
    try:
        result = network_runner(
            {"ipsec": [f"127.0.0.1:{responder.port}"], "ike_ports": str(responder.port)},
            None,
        )
    finally:
        responder.close()
    assert result["summary"]["ipsec_targets"] == 1
    assert result["degraded"] is True
    assert any("WEAK_IKE_ENCRYPTION:3DES" in issue for issue in result["issues"])

    # dnssec: unsigned zone surfaced via monitor config
    server = _DnsServer(zone="unsigned.org", dnskey=[])
    try:
        result = network_runner(
            {"dnssec": ["unsigned.org"], "dns_resolver": f"127.0.0.1:{server.port}", "check_zone_transfer": False},
            None,
        )
    finally:
        server.close()
    assert result["summary"]["dnssec_zones"] == 1
    assert "UNSIGNED_ZONE" in result["issues"]
    assert result["degraded"] is True


def test_network_runner_blocked_without_targets():
    result = network_runner({"endpoints": []}, None)
    assert "blocked_reason" in result and "endpoints" in result["blocked_reason"]


def test_network_runner_global_discovery_scope(monkeypatch):
    """config.scope runs the full enterprise discovery pipeline each tick and
    surfaces its findings as monitor issues."""
    from network_scanner.core.scanner import NetworkTlsScanner

    captured = {}

    def fake_discover_network(self, scope_specs, **kw):
        captured["scope_specs"] = list(scope_specs)
        captured["mode"] = kw.get("mode")
        return {
            "scope": [{"value": str(scope_specs[0])}],
            "assets": [{"asset_identity": "10.0.0.1", "device_type": "router"}],
            "protocol_observations": [{"asset": "10.0.0.1", "protocol": "TLS", "status": "CRYPTOGRAPHY_VERIFIED"}],
            "tunnels": [{"tunnel_id": "t1", "pre_shared_key_used": True, "certificate_reference": None}],
            "findings": [{"endpoint": "10.0.0.1", "policy_issues": ["WEAK_TLS_VERSION"]}],
            "pqc_network_readiness": {
                "by_status": {"MIGRATION_REQUIRED": 2},
                "migration_blockers": ["HSM dependency"],
            },
        }

    monkeypatch.setattr(NetworkTlsScanner, "discover_network", fake_discover_network)
    result = network_runner({"scope": ["10.0.0.0/24"]}, None)

    assert captured["scope_specs"] == ["10.0.0.0/24"]
    assert captured["mode"] == "SAFE"
    assert result["summary"]["scope"]["assets"] == 1
    assert result["summary"]["scope"]["observations"] == 1
    assert result["summary"]["scope"]["pqc_migration_required"] == 2
    assert result["degraded"] is True
    assert any("WEAK_TLS_VERSION" in issue for issue in result["issues"])
    assert any("TUNNEL_PSK_ONLY" in issue for issue in result["issues"])
    assert any("PQC_MIGRATION_BLOCKERS" in issue for issue in result["issues"])


def test_network_runner_scope_config_error_surfaces_as_issue(monkeypatch):
    """DEEP scope without authorization must degrade the target with a clear
    issue instead of being silently swallowed."""
    from network_scanner.core.scanner import NetworkTlsScanner

    def failing_discover_network(self, scope_specs, **kw):
        raise ValueError("scan mode DEEP requires an authorization_scope")

    monkeypatch.setattr(NetworkTlsScanner, "discover_network", failing_discover_network)
    result = network_runner({"scope": ["10.0.0.0/24"], "scan_mode": "DEEP"}, None)
    assert result["degraded"] is True
    assert any("SCOPE_ERROR" in issue for issue in result["issues"])
