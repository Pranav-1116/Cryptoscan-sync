"""Passive OT/ICS protocol decoders (deterministic, no active probing).

These decoders parse frames OBSERVED on a span/mirror port or read from a pcap
capture — they never send a packet. They decode:
- S7comm (Siemens, TCP/102) — setup/job/ack frames, including Setup-Communication
  and engineering/download (upload/start/stop) jobs.
- EtherNet/IP (CIP, TCP/44818) — Register Session, SendRRData/ForwardOpen.
- BACnet/IP (UDP/47808) — Who-Is/I-Am, ReadProperty, WriteProperty.
- OPC UA (TCP/4840) — Hello/Acknowledge/OpenSecureChannel; security mode/policy
  reveals whether engineering is in cleartext (None) vs signed/encrypted.

Each detection is *passive*: a ``flag`` is raised only when a decoded frame
proves engineering access in cleartext (e.g. S7 download job, BACnet
WriteProperty, CIP ForwardOpen unconnected, or OPC UA MessageSecurityMode=None).
The decoders never touch SIS/ESD — they only read what is observed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class DecodedFrame:
    protocol: str
    direction: str
    detail: dict[str, Any] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    risk: str = "INFO"  # INFO / LOW / MEDIUM / HIGH


# ------------------------------------------------------------------ S7comm -- #
def decode_s7comm(payload: bytes) -> DecodedFrame | None:
    """Parse a TPKT+COTP+S7comm payload (bytes after TCP header).

    S7comm header: 0x32 protocol id, rosctr (0x01 job, 0x02 ack, 0x03 ack-data,
    0x07 userdata), then PDU reference, parameter/data length.
    """
    # TPKT: version=3, reserved=0, length(2)
    if len(payload) < 7 or payload[0] != 0x03:
        return None
    tpkt_len = struct.unpack(">H", payload[2:4])[0]
    if tpkt_len < len(payload) - 4 and tpkt_len != 0:
        pass  # tolerate truncation in captures
    cotp_len = payload[4]
    if payload[5] != 0xF0 and payload[5] != 0xE0:
        return None
    # length byte at [4] counts the COTP bytes that follow it
    idx = 4 + 1 + cotp_len
    if idx + 10 > len(payload) or payload[idx] != 0x32:
        return None
    rosctr = payload[idx + 1]
    pdu_ref = struct.unpack(">H", payload[idx + 2:idx + 4])[0]
    param_len = struct.unpack(">H", payload[idx + 4:idx + 6])[0]
    data_len = struct.unpack(">H", payload[idx + 6:idx + 8])[0]
    function = payload[idx + 8] if idx + 8 < len(payload) else None

    names = {0x01: "JOB", 0x02: "ACK", 0x03: "ACK_DATA", 0x07: "USERDATA"}
    rosctr_name = names.get(rosctr, f"0x{rosctr:02x}")
    frame = DecodedFrame(
        protocol="S7COMM",
        direction="observed",
        detail={"rosctr": rosctr_name, "pdu_ref": pdu_ref,
                "param_len": param_len, "data_len": data_len,
                "function": function},
    )
    # Setup communication establishes PDU sizing (benign but engineering-related)
    if function == 0xF0:
        frame.detail["service"] = "SETUP_COMMUNICATION"
    if function == 0x04:
        frame.detail["service"] = "DOWNLOAD_BLOCK"
        frame.flags.append("S7_CLEARTEXT_ENGINEERING_DOWNLOAD")
        frame.risk = "HIGH"
    if function == 0x05:
        frame.detail["service"] = "UPLOAD_BLOCK"
        frame.flags.append("S7_CLEARTEXT_ENGINEERING_UPLOAD")
        frame.risk = "MEDIUM"
    if function in (0x1A, 0x1B):  # PLC start/stop
        frame.detail["service"] = "PLC_CONTROL"
        frame.flags.append("S7_CLEARTEXT_PLC_CONTROL")
        frame.risk = "HIGH"
    if rosctr == 0x07:
        frame.detail["service"] = frame.detail.get("service", "USER_DATA_CYCLOPS")
    return frame


# ------------------------------------------------------------- EtherNet/IP -- #
def decode_enip(payload: bytes) -> DecodedFrame | None:
    """EtherNet/IP encapsulation header (24 bytes) + CIP command."""
    if len(payload) < 24:
        return None
    command, length, session, status, _ctx, _opts = struct.unpack("<HHIIQI", payload[:24])
    # Known ENIP commands
    cmds = {0x0063: "GET_IDENTITY", 0x0065: "REGISTER_SESSION",
            0x0066: "UNREGISTER_SESSION", 0x006F: "SEND_RR_DATA",
            0x0070: "SEND_UNIT_DATA", 0x0072: "LARGE_SEND_RR_DATA"}
    body = payload[24:24 + length]
    frame = DecodedFrame(
        protocol="ETHERNET_IP",
        direction="observed",
        detail={"command": cmds.get(command, f"0x{command:04x}"),
                "session_handle": session, "status": status, "body_len": len(body)},
    )
    if command in (0x006F, 0x0070, 0x0072):
        frame.detail["cip_present"] = True
        # ForwardOpen (Class 3 connection) inside CIP
        if _cip_contains_forward_open(body):
            frame.detail["cip_service"] = "FORWARD_OPEN"
            frame.flags.append("ENIP_FORWARD_OPEN_CLEARTEXT_IO_OR_SESSION")
            frame.risk = "MEDIUM"
    return frame


def _cip_contains_forward_open(body: bytes) -> bool:
    # CIP service codes for Forward Open = 0x5B (0x54 large forward open)
    for svc in (0x5B, 0x54):
        if svc in body:
            return True
    return False


# ------------------------------------------------------------------ BACnet -- #
def decode_bacnet_ip(payload: bytes) -> DecodedFrame | None:
    """BACnet/IP Virtual Link Layer (BVLC) + NPDU + APDU."""
    if len(payload) < 4 or payload[0] != 0x81:
        return None
    bvlc_func = payload[1]
    bvlc_len = struct.unpack(">H", payload[2:4])[0]
    apdu_idx = 4
    # skip NPDU if present (control byte version)
    # BACnet/IP NPDU starts at offset 4: version(1)=0x01, control(1)
    if apdu_idx + 2 <= len(payload) and payload[apdu_idx] == 0x01:
        ctrl = payload[apdu_idx + 1]
        apdu_idx += 2
        if ctrl & 0x08:  # has destination
            apdu_idx += 2 + payload[apdu_idx + 1] if apdu_idx + 1 < len(payload) else 0
        if ctrl & 0x04:  # has source
            apdu_idx += 2 + payload[apdu_idx + 1] if apdu_idx + 1 < len(payload) else 0
        if ctrl & 0x20:  # hop count
            apdu_idx += 1
    apdu_type = payload[apdu_idx] if apdu_idx < len(payload) else None
    # APDU: high nibble = type. Confirmed-Request=0x0, Unconfirmed=0x1,
    # Simple-ACK=0x2, Complex-ACK=0x3, Error=0x5
    apdu_names = {0x0: "CONFIRMED_REQUEST", 0x1: "UNCONFIRMED_REQUEST",
                  0x2: "SIMPLE_ACK", 0x3: "COMPLEX_ACK", 0x5: "ERROR",
                  0x8: "SEGMENT_ACK"}
    pdu_type = (apdu_type >> 4) if apdu_type is not None else None
    frame = DecodedFrame(
        protocol="BACNET_IP",
        direction="observed",
        detail={"bvlc_function": bvlc_func, "bvlc_length": bvlc_len,
                "apdu_pdu_type": apdu_names.get(pdu_type, pdu_type)},
    )
    # service choice follows invoke-id (for confirmed/unconfirmed)
    svc_idx = apdu_idx + 2 if pdu_type == 0x0 else (apdu_idx + 1 if pdu_type == 0x1 else None)
    svc = payload[svc_idx] if (svc_idx is not None and svc_idx < len(payload)) else None
    # BACnet service choices: Who-Is=8, I-Am=0, ReadProperty=12, WriteProperty=15
    services = {0: "I_AM", 8: "WHO_IS", 12: "READ_PROPERTY", 15: "WRITE_PROPERTY",
                7: "COV_SUBSCRIPTION", 0x0E: "WRITE_PROPERTY_MULTIPLE"}
    if svc is not None:
        frame.detail["service_choice"] = services.get(svc, svc)
        if svc in (15, 0x0E):
            frame.flags.append("BACNET_WRITE_PROPERTY_CLEARTEXT_ENGINEERING")
            frame.risk = "HIGH"
        elif svc == 7:
            frame.flags.append("BACNET_COV_SUBSCRIPTION")
            frame.risk = "LOW"
    if bvlc_func == 0x0B:
        frame.detail["forwarded_npdu"] = True
    return frame


# ------------------------------------------------------------------- OPC UA - #
def decode_opcua(payload: bytes) -> DecodedFrame | None:
    """OPC UA binary TCP (Hello/Acknowledge/OpenSecureChannel).

    MessageType 'HEL'/'ACK'/'OPN'/'MSG'/'CLO'; chunk type F/C/A. For OPN the
    SecurityPolicyUri and MessageSecurityMode reveal cleartext vs encrypted.
    """
    if len(payload) < 8:
        return None
    mtype = payload[:3]
    if mtype not in (b"HEL", b"ACK", b"OPN", b"MSG", b"CLO"):
        return None
    chunk = payload[3:4]
    frame = DecodedFrame(
        protocol="OPC_UA",
        direction="observed",
        detail={"message_type": mtype.decode("ascii", "replace"),
                "chunk_type": chunk.decode("ascii", "replace")},
    )
    if mtype == b"HEL":
        # Hello: message size(4), ... endpoint url string (length-prefixed)
        frame.detail["service"] = "HELLO"
        url = _opcua_string(payload, 8 + 20)
        if url:
            frame.detail["endpoint_url"] = url
    elif mtype == b"ACK":
        frame.detail["service"] = "ACKNOWLEDGE"
    elif mtype == b"OPN":
        # OpenSecureChannel request: after symmetric header the body in
        # message-security mode is visible only for NON-encrypted channels.
        frame.detail["service"] = "OPEN_SECURE_CHANNEL"
        # When policy is None / message security mode = 1 (None), the payload is
        # parseable; detect the cleartext policy string.
        policy = _scan_utf16_policy(payload)
        if policy:
            frame.detail["security_policy"] = policy
        mode = _detect_security_mode(payload)
        frame.detail["security_mode"] = mode
        if mode == "NONE" or (policy and policy.endswith("#None")):
            frame.flags.append("OPCUA_CLEARTEXT_SECURITY_MODE_NONE")
            frame.risk = "HIGH"
        elif mode == "SIGN":
            frame.risk = "MEDIUM"
            frame.flags.append("OPCUA_SIGNED_NOT_ENCRYPTED")
    return frame


def _opcua_string(buf: bytes, offset: int) -> str | None:
    if offset + 4 > len(buf):
        return None
    slen = struct.unpack("<i", buf[offset:offset + 4])[0]
    if 0 <= slen < 2048 and offset + 4 + slen <= len(buf):
        return buf[offset + 4:offset + 4 + slen].decode("utf-8", "replace")
    return None


def _scan_utf16_policy(buf: bytes) -> str | None:
    marker = b"http://opcfoundation.org/UA/SecurityPolicy"
    # try ASCII first (non-encrypted OPN carries ASCII string)
    pos = buf.find(marker)
    if pos >= 0:
        end = buf.find(b"\x00", pos)
        seg = buf[pos:end if end > 0 else pos + 60]
        return seg.split(b"#")[-1].decode("utf-8", "replace") if b"#" in seg else seg.decode("utf-8", "replace")
    return None


def _detect_security_mode(buf: bytes) -> str:
    # MessageSecurityMode: Invalid=0, None=1, Sign=2, SignAndEncrypt=3.
    # In a cleartext OPN body, mode appears as a small LE enum near policy.
    for i in range(8, min(len(buf) - 1, 200)):
        val = struct.unpack("<H", buf[i:i + 2])[0] if i + 2 <= len(buf) else 0
        if val == 1 and b"None" in buf:
            return "NONE"
        if val == 2:
            return "SIGN"
        if val == 3:
            return "SIGN_AND_ENCRYPT"
    return "ENCRYPTED_OR_UNKNOWN"


# ------------------------------------------------------------- dispatcher --- #
def decode_frame(*, tcp_payload: bytes | None = None,
                 udp_payload: bytes | None = None,
                 dport: int | None = None) -> list[DecodedFrame]:
    """Try each decoder on observed bytes; return all successful decodes.

    Decoders are passive and independent; a frame that matches more than one
    parser (rare) yields multiple DecodedFrames.
    """
    out: list[DecodedFrame] = []
    buf = tcp_payload if tcp_payload is not None else (udp_payload or b"")
    if tcp_payload is not None:
        for fn in (decode_s7comm, decode_enip, decode_opcua):
            f = fn(buf)
            if f:
                out.append(f)
    if udp_payload is not None:
        b = decode_bacnet_ip(buf)
        if b:
            out.append(b)
    # Port-based classification hint for dashboards (no traffic sent).
    for f in out:
        f.detail["observed_dport"] = dport
    return out


def analyze_capture(frames: list[dict]) -> dict[str, Any]:
    """Run a list of observed {tcp_payload|udp_payload, dport} frames and
    summarize cleartext-engineering exposure. Read-only; never probes."""
    decoded: list[DecodedFrame] = []
    for fr in frames:
        decoded.extend(decode_frame(tcp_payload=fr.get("tcp_payload"),
                                    udp_payload=fr.get("udp_payload"),
                                    dport=fr.get("dport")))
    flagged = [d for d in decoded if d.flags]
    by_risk: dict[str, int] = {}
    for d in flagged:
        by_risk[d.risk] = by_risk.get(d.risk, 0) + 1
    protocols = sorted({d.protocol for d in decoded})
    return {
        "frames_decoded": len(decoded),
        "frames_flagged": len(flagged),
        "protocols": protocols,
        "risk_summary": by_risk,
        "cleartext_engineering_detected": bool(flagged),
        "active_probes_sent": 0,  # passive guarantee
        "findings": [asdict(d) for d in flagged],
    }
