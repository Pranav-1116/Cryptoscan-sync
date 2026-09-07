"""Deterministic tests for passive pcap OT capture ingestion (feature 27 last
mile). Builds a valid classic-pcap in memory; parses with zero dependencies."""
import struct

from network_scanner.passive import ot_capture as cap


def _eth_ip_tcp(dport: int, payload: bytes, sport: int = 50000) -> bytes:
    # TCP header (20 bytes, data offset 5)
    tcp = struct.pack(">HHIIHHHH", sport, dport, 1, 1, 0x5000, 8192, 0, 0)
    # IPv4 header (20 bytes, IHL=5, proto=6 TCP)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBHII", 0x45, 0, total, 0x1234, 0, 64, 6, 0,
                     0x0A000001, 0x0A000002)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
    return eth + ip + tcp + payload


def _eth_ip_udp(dport: int, payload: bytes, sport: int = 50001) -> bytes:
    ulen = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, ulen, 0)
    total = 20 + ulen
    ip = struct.pack(">BBHHHBBHII", 0x45, 0, total, 0x1234, 0, 64, 17, 0,
                     0x0A000001, 0x0A000002)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
    return eth + ip + udp + payload


def _pcap(packets: list[bytes], network: int = 1) -> bytes:
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, network)
    out = gh
    for pkt in packets:
        out += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return out


def _s7_download():
    s7 = struct.pack(">BBHHHBB", 0x32, 0x01, 0x0001, 4, 0, 0x04, 0x00)
    body = bytes([0x02, 0xF0, 0x80]) + s7
    return bytes([0x03, 0x00]) + struct.pack(">H", len(body)) + body


def _bacnet_write():
    npdu = bytes([0x01, 0x00])
    apdu = bytes([0x00, 0x01, 15])  # confirmed, invoke id, WriteProperty
    payload = npdu + apdu
    return bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(payload)) + payload


def test_pcap_parses_s7_download_and_flags():
    blob = _pcap([_eth_ip_tcp(102, _s7_download())])
    r = cap.analyze_pcap(blob)
    assert r["capture_stats"]["packets"] == 1
    assert r["capture_stats"]["ot_packets"] == 1
    assert r["frames_flagged"] == 1
    assert r["active_probes_sent"] == 0
    assert r["findings"][0]["flags"][0] == "S7_CLEARTEXT_ENGINEERING_DOWNLOAD"
    assert r["findings"][0]["severity"] == "HIGH"


def test_pcap_parses_bacnet_udp_and_ignores_non_ot_traffic():
    blob = _pcap([
        _eth_ip_tcp(443, b"GET / HTTP/1.1\r\n"),      # non-OT TCP, ignored
        _eth_ip_udp(47808, _bacnet_write()),           # BACnet write
    ])
    r = cap.analyze_pcap(blob)
    assert r["capture_stats"]["packets"] == 2
    assert r["capture_stats"]["ot_packets"] == 1
    assert r["frames_flagged"] == 1
    assert "BACNET_IP" in r["protocols"]


def test_pcap_bad_magic_raises():
    import pytest
    with pytest.raises(cap.PcapError):
        cap.analyze_pcap(b"not a pcap file at all" * 5)


def test_pcap_empty_returns_zero():
    blob = _pcap([])
    r = cap.analyze_pcap(blob)
    assert r["frames_decoded"] == 0 and r["cleartext_engineering_detected"] is False
