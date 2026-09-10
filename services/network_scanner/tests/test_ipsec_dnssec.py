"""IPsec/IKE probe + DNSSEC posture checker — live localhost integration.

A local UDP IKE responder and a local DNS server (UDP + TCP/AXFR) stand in
for the real world, exactly like the live-OCSP tests: real sockets, real
packet parsing, no mocks of the code under test.
"""

from __future__ import annotations

import json
import socket
import struct
import threading


from network_scanner.discovery.dnssec_checker import scan_dnssec
from network_scanner.probing.ipsec_probe import (
    build_ikev2_sa_init,
    classify_ipsec,
    extract_sa_from_response,
    parse_sa_payload,
    probe_ike,
)

# ------------------------------------------------------------------ IKE


def _transform(ttype: int, tid: int, key_length: int = 0) -> bytes:
    attrs = struct.pack("!HH", 0x800E, key_length) if key_length else b""
    body = bytes([ttype, 0]) + struct.pack("!H", tid) + attrs
    return struct.pack("!H", len(body) + 2) + body


def _sa_payload_with(transforms: list[bytes]) -> bytes:
    proposal = bytes([1, 1, 0, len(transforms)]) + b"".join(transforms)
    return bytes([34, 0]) + struct.pack("!H", len(proposal) + 4) + proposal  # next=KE(dummy)


def _ike_response(payload: bytes) -> bytes:
    header = struct.pack(
        "!8s8sBBBBII",
        b"\x11" * 8, b"\x22" * 8, 33, 0x20, 34, 0x08, 0, len(payload) + 28,
    )
    return header + payload


def test_parse_strong_proposal():
    transforms = [_transform(1, 5, 16), _transform(2, 5), _transform(4, 14)]
    payload = _sa_payload_with(transforms)
    proposals = extract_sa_from_response(_ike_response(payload))
    assert len(proposals) == 1
    names = [t["name"] for t in proposals[0]["transforms"]]
    assert "AES-CBC-256" in names and "HMAC-SHA2-256" in names and "MODP-2048" in names
    assert classify_ipsec(proposals) == []  # strong -> no issues


def test_classify_weak_proposal():
    transforms = [_transform(1, 2), _transform(2, 2), _transform(4, 2)]  # 3DES, SHA1, MODP-1024
    payload = _sa_payload_with(transforms)
    proposals = extract_sa_from_response(_ike_response(payload))
    issues = classify_ipsec(proposals)
    assert "WEAK_IKE_ENCRYPTION:3DES" in issues
    assert "WEAK_IKE_MAC:HMAC-SHA1" in issues
    assert "WEAK_IKE_DH_GROUP:MODP-1024" in issues
    assert "IKE_NO_PFS" not in issues  # a DH group is offered, just a weak one


def test_classify_no_pfs():
    # ENCR + PRF only, no DH-group transform -> no PFS possible
    transforms = [_transform(1, 5, 16), _transform(2, 5)]
    payload = _sa_payload_with(transforms)
    proposals = extract_sa_from_response(_ike_response(payload))
    assert "IKE_NO_PFS" in classify_ipsec(proposals)


class _IkeResponder:
    """Speaks just enough IKEv2 to return an SA proposal (no handshake)."""

    def __init__(self, transforms: list[bytes]):
        self.transforms = transforms
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        self.sock.settimeout(5.0)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            payload = _sa_payload_with(self.transforms)
            self.sock.sendto(_ike_response(payload), addr)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def test_probe_ike_end_to_end():
    responder = _IkeResponder([_transform(1, 5, 16), _transform(2, 5), _transform(4, 14)])
    try:
        result = probe_ike("127.0.0.1", ports=(responder.port,), timeout=2.0)
        assert result["status"] == "OK"
        assert result["proposals"] and result["proposals"][0]["transforms"]
        assert result["issues"] == []
    finally:
        responder.close()


def test_probe_ike_flags_weak_end_to_end():
    responder = _IkeResponder([_transform(1, 2), _transform(2, 2), _transform(4, 2)])
    try:
        result = probe_ike("127.0.0.1", ports=(responder.port,), timeout=2.0)
        assert result["status"] == "OK"
        assert "WEAK_IKE_ENCRYPTION:3DES" in result["issues"]
    finally:
        responder.close()


def test_probe_ike_no_response_on_closed_port():
    result = probe_ike("127.0.0.1", ports=(9,), timeout=0.4)  # discard port, nothing listens
    assert result["status"] in {"NO_RESPONSE", "PORT_CLOSED"}


def test_build_sa_init_is_valid_shape():
    packet = build_ikev2_sa_init(b"\x01" * 8)
    assert len(packet) >= 28
    assert packet[16] == 33  # header next-payload at offset 16: SA
    assert packet[17] == 0x20  # IKEv2
    length = struct.unpack("!I", packet[24:28])[0]
    assert length == len(packet)
    # self-parse: the built packet's SA payload round-trips
    proposals = extract_sa_from_response(packet)
    assert proposals and proposals[0]["protocol"] == "IKE"


def test_malformed_sa_payload_never_raises():
    proposals = parse_sa_payload(b"\x00\x00\x00\x00\xff", 0, 5)  # truncated
    assert proposals == []


# ------------------------------------------------------------------ DNSSEC


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in str(name).rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


def _question(qid: int, name: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", qtype, 1)


def _dnskey_rdata(flags: int, algorithm: int, modulus: bytes) -> bytes:
    exp_len = bytes([1])
    exp = b"\x03"
    return struct.pack("!HBB", flags, 3, algorithm) + exp_len + exp + modulus


def _soa_rdata() -> bytes:
    return _encode_name("ns1.example.com.") + _encode_name("hostmaster.example.com.") + struct.pack(
        "!IIIII", 1, 3600, 600, 86400, 300
    )


def _response(qid: int, name: str, qtype: int, answers: list[tuple[int, bytes]]) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, len(answers), 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return header + question + body


class _DnsServer:
    """Tiny DNS server: answers SOA/DNSKEY/DS over UDP, AXFR over TCP."""

    def __init__(self, *, zone: str, dnskey: list[bytes], ds: list[bytes], axfr: list[bytes] | None = None):
        self.zone = zone
        self.dnskey = dnskey
        self.ds = ds
        self.axfr = axfr  # None = refuse transfer
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        # TCP binds the SAME port number (UDP and TCP ports are independent)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(2)
        self.tcp.settimeout(5.0)
        self._stop = threading.Event()
        self.threads = [
            threading.Thread(target=self._udp_loop, daemon=True),
            threading.Thread(target=self._tcp_loop, daemon=True),
        ]
        for t in self.threads:
            t.start()

    def _udp_loop(self) -> None:
        self.udp.settimeout(5.0)
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            qid = struct.unpack("!H", data[:2])[0]
            qtype = self._qtype(data)
            answers: list[tuple[int, bytes]] = []
            if qtype == 6:  # SOA
                answers.append((6, _soa_rdata()))
            elif qtype == 48:  # DNSKEY
                answers = [(48, r) for r in self.dnskey]
            elif qtype == 43:  # DS
                answers = [(43, r) for r in self.ds]
            self.udp.sendto(_response(qid, self.zone, qtype, answers), addr)

    def _tcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(5.0)
                length_raw = b""
                while len(length_raw) < 2:
                    chunk = conn.recv(2 - len(length_raw))
                    if not chunk:
                        break
                    length_raw += chunk
                if len(length_raw) < 2:
                    continue
                length = struct.unpack("!H", length_raw)[0]
                query = b""
                while len(query) < length:
                    chunk = conn.recv(length - len(query))
                    if not chunk:
                        break
                    query += chunk
                qid = struct.unpack("!H", query[:2])[0]
                if self.axfr is not None:
                    answers = [(6, _soa_rdata())] + [(48, r) for r in self.axfr]
                    msg = _response(qid, self.zone, 252, answers)
                    conn.sendall(struct.pack("!H", len(msg)) + msg)
            except (OSError, struct.error):
                pass
            finally:
                conn.close()

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
        self.udp.close()
        self.tcp.close()
        for t in self.threads:
            t.join(timeout=2)


def test_dnssec_signed_strong_zone():
    server = _DnsServer(
        zone="example.com",
        dnskey=[_dnskey_rdata(257, 8, b"\xAA" * 128)],  # RSASHA256, 1024-bit
        ds=[b"\x00\x01\x08\x02" + b"\x11" * 20],
    )
    try:
        result = scan_dnssec("example.com", resolver=f"127.0.0.1:{server.port}", timeout=2.0)
        assert result["status"] == "SIGNED" and result["signed"] is True
        assert result["algorithms"] == ["RSASHA256"]
        assert result["issues"] == []
    finally:
        server.close()


def test_dnssec_unsigned_zone():
    server = _DnsServer(zone="unsigned.org", dnskey=[], ds=[])
    try:
        result = scan_dnssec("unsigned.org", resolver=f"127.0.0.1:{server.port}", timeout=2.0)
        assert result["status"] == "UNSIGNED"
        assert "UNSIGNED_ZONE" in result["issues"]
    finally:
        server.close()


def test_dnssec_weak_algorithm_and_key_size():
    server = _DnsServer(
        zone="weak.example",
        dnskey=[
            _dnskey_rdata(257, 5, b"\xBB" * 64),  # RSASHA1, 512-bit -> both weak
            _dnskey_rdata(256, 8, b"\xCC" * 128),  # RSASHA256, 1024-bit -> ok
        ],
        ds=[],
    )
    try:
        result = scan_dnssec("weak.example", resolver=f"127.0.0.1:{server.port}", timeout=2.0)
        assert "WEAK_DNSSEC_ALGORITHM:RSASHA1" in result["issues"]
        assert "WEAK_DNSSEC_KEY_SIZE:512" in result["issues"]
        assert result["algorithms"] == ["RSASHA1", "RSASHA256"]
    finally:
        server.close()


def test_dnssec_zone_transfer_exposed():
    server = _DnsServer(
        zone="leaky.example",
        dnskey=[_dnskey_rdata(257, 8, b"\xAA" * 128)],
        ds=[],
        axfr=[_dnskey_rdata(257, 8, b"\xAA" * 128)],
    )
    try:
        result = scan_dnssec("leaky.example", resolver=f"127.0.0.1:{server.port}", timeout=2.0)
        assert "ZONE_TRANSFER_EXPOSED" in result["issues"]
        assert result["transfer_exposed"] is True
    finally:
        server.close()


def test_dnssec_no_zone():
    server = _DnsServer(zone="ghost.example", dnskey=[], ds=[], axfr=None)
    server.udp.close()  # simulate: no SOA answer -> NO_ZONE
    try:
        # point at a dead port -> NO_ZONE is only for empty answers; here we
        # assert the honest ERROR/UNKNOWN path when the resolver is unreachable
        result = scan_dnssec("ghost.example", resolver="127.0.0.1", timeout=0.3)
        assert result["status"] in {"NO_ZONE", "UNKNOWN", "ERROR"}
    finally:
        server.close()


# ------------------------------------------------------------------ CLI


def test_cli_ipsec_probe(tmp_path):
    from network_scanner.main import main

    responder = _IkeResponder([_transform(1, 2), _transform(2, 2), _transform(4, 2)])
    out = tmp_path / "ipsec.json"
    try:
        rc = main(["--ipsec", "127.0.0.1", "--ike-ports", str(responder.port), "-o", str(out)])
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["target_kind"] == "ipsec-vpn"
        assert any("WEAK_IKE_ENCRYPTION:3DES" in i for i in data["findings"][0]["issues"])
    finally:
        responder.close()


def test_cli_dnssec_zone(tmp_path):
    from network_scanner.main import main

    server = _DnsServer(zone="cli.example", dnskey=[], ds=[])
    out = tmp_path / "dnssec.json"
    try:
        rc = main(
            ["--dnssec", "cli.example", "--resolver", f"127.0.0.1:{server.port}",
             "--skip-transfer-check", "-o", str(out)]
        )
        assert rc == 0
        data = json.loads(out.read_text())
        assert data["target_kind"] == "dnssec"
        assert "UNSIGNED_ZONE" in data["issues"]
    finally:
        server.close()


def test_cli_global_discovery_scope(tmp_path):
    """--scope runs the enterprise global discovery pipeline (SAFE mode)."""
    from network_scanner.main import main

    out = tmp_path / "discovery.json"
    rc = main(["--scope", "localhost", "--mode", "safe", "--plugin", "cisco",
               "-o", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["target_kind"] == "global-network-discovery"
    assert data["scan_context"]["scan_mode"] == "SAFE"
    assert data["scan_metadata"]["scan_mode"] == "SAFE"
    # localhost has no TLS server: the probe error is data, not a crash
    assert data["findings"]
