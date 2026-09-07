"""Deterministic tests for passive OT decoders (feature 27). Frames are
hand-crafted byte captures; nothing is sent on the wire."""
import struct

from network_scanner.passive import ot_protocols as ot


def _s7_frame(rosctr=0x01, function=0x04, param_len=4, data_len=0):
    # TPKT (4) + COTP (3: len, 0xF0/DT, 0x80) + S7 header
    s7 = struct.pack(">BBHHHBB", 0x32, rosctr, 0x0001, param_len, data_len,
                     function, 0x00)
    cotp = bytes([0x02, 0xF0, 0x80])
    body = cotp + s7
    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", len(body)) + body
    return tpkt


def test_s7_download_job_flagged_cleartext():
    f = ot.decode_s7comm(_s7_frame(rosctr=0x01, function=0x04))
    assert f.protocol == "S7COMM"
    assert f.detail["service"] == "DOWNLOAD_BLOCK"
    assert "S7_CLEARTEXT_ENGINEERING_DOWNLOAD" in f.flags
    assert f.risk == "HIGH"


def test_s7_setup_communication_not_flagged():
    f = ot.decode_s7comm(_s7_frame(rosctr=0x01, function=0xF0))
    assert f.detail["service"] == "SETUP_COMMUNICATION"
    assert f.flags == []
    assert f.risk == "INFO"


def test_s7_plc_stop_flagged():
    f = ot.decode_s7comm(_s7_frame(function=0x1B))
    assert "S7_CLEARTEXT_PLC_CONTROL" in f.flags


def test_non_s7_bytes_rejected():
    assert ot.decode_s7comm(b"\x00" * 20) is None


def _enip_frame(command=0x006F, body=b"", session=0x1234):
    # 24-byte ENIP encapsulation header: command, length, session, status,
    # sender context (8 bytes), options.
    hdr = struct.pack("<HHIIQI", command, len(body), session, 0, 0, 0)
    return hdr + body


def test_enip_register_session_no_flag():
    f = ot.decode_enip(_enip_frame(command=0x0065))
    assert f.protocol == "ETHERNET_IP"
    assert f.detail["command"] == "REGISTER_SESSION"
    assert f.flags == []


def test_enip_forward_open_flagged():
    # CIP body containing ForwardOpen service code 0x5B
    body = bytes([0x00, 0x00, 0x02, 0x5B, 0x01])
    f = ot.decode_enip(_enip_frame(command=0x006F, body=body))
    assert f.detail["cip_service"] == "FORWARD_OPEN"
    assert any("FORWARD_OPEN" in fl for fl in f.flags)


def _bacnet_frame(apdu_service=15, confirmed=True):
    # BVLC: 0x81, func 0x0A (original-unicast-NPDU), length
    npdu = bytes([0x01, 0x00])  # version, control (no src/dst)
    if confirmed:
        apdu = bytes([0x00, 0x01, apdu_service])  # confirmed-req, invoke id, service
    else:
        apdu = bytes([0x10, apdu_service])  # unconfirmed
    payload = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(payload)) + payload
    return bvlc


def test_bacnet_write_property_flagged():
    f = ot.decode_bacnet_ip(_bacnet_frame(apdu_service=15))
    assert f.protocol == "BACNET_IP"
    assert f.detail["service_choice"] == "WRITE_PROPERTY"
    assert "BACNET_WRITE_PROPERTY_CLEARTEXT_ENGINEERING" in f.flags
    assert f.risk == "HIGH"


def test_bacnet_who_is_not_flagged():
    f = ot.decode_bacnet_ip(_bacnet_frame(apdu_service=8, confirmed=False))
    assert f.detail["service_choice"] == "WHO_IS"
    assert f.flags == []


def _opcua_open_none():
    # 'OPN' 'F', size, secure channel id, then ASCII policy + mode=None(1)
    policy = b"http://opcfoundation.org/UA/SecurityPolicy#None"
    body = b"OPNF" + struct.pack("<I", 100) + struct.pack("<I", 55) + policy + b"\x00" + struct.pack("<H", 1)
    return body


def test_opcua_cleartext_none_flagged():
    f = ot.decode_opcua(_opcua_open_none())
    assert f.protocol == "OPC_UA"
    assert f.detail["security_mode"] in ("NONE",)
    assert "OPCUA_CLEARTEXT_SECURITY_MODE_NONE" in f.flags
    assert f.risk == "HIGH"


def test_opcua_hello_parsed():
    # HEL header + 20-byte hello fields + length-prefixed endpoint url
    url = b"opc.tcp://plc:4840"
    hello_fields = struct.pack("<IIIII", 1000, 1000, 4096, 4096, 4840)
    msg = b"HELF" + struct.pack("<I", 8 + 20 + 4 + len(url)) + hello_fields + struct.pack("<i", len(url)) + url
    f = ot.decode_opcua(msg)
    assert f.detail["service"] == "HELLO"
    assert f.detail["endpoint_url"] == "opc.tcp://plc:4840"


def test_analyze_capture_is_passive_and_flags_cleartext():
    frames = [
        {"tcp_payload": _s7_frame(function=0x04), "dport": 102},
        {"udp_payload": _bacnet_frame(apdu_service=15), "dport": 47808},
        {"tcp_payload": _enip_frame(command=0x0065), "dport": 44818},
    ]
    r = ot.analyze_capture(frames)
    assert r["active_probes_sent"] == 0
    assert r["cleartext_engineering_detected"] is True
    assert r["frames_flagged"] == 2
    assert "S7COMM" in r["protocols"] and "BACNET_IP" in r["protocols"]
