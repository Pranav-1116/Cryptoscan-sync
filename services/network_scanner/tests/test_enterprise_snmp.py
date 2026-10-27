"""Enterprise layer — pure-python SNMPv2c BER + client + discovery.

Spec area 14: SNMP discovery of identity, interfaces, routes, model, OS,
uptime, vendor, topology hints, and security capability as metadata — never
secrets. A fake in-memory responder (injected via ``sock_factory``) stands in
for the wire so the whole client/walk/discovery path is exercised offline.
"""

from __future__ import annotations

import pytest

from network_scanner.enterprise.vendors.snmp import (
    IF_TABLE,
    IP_ROUTE_TABLE,
    PDU_GET,
    PDU_GET_NEXT,
    PDU_RESPONSE,
    SYS_DESCR,
    SYS_NAME,
    SYS_OBJECT_ID,
    SYS_UPTIME,
    SnmpClient,
    SnmpDeviceInfo,
    SnmpError,
    _TAG_INTEGER,
    _TAG_NULL,
    _TAG_OCTET,
    _TAG_OID,
    _TAG_SEQUENCE,
    _encode_tlv,
    _read_tlv,
    build_get,
    build_get_next,
    decode_oid,
    encode_integer,
    encode_octet_string,
    encode_oid,
    parse_response,
    snmp_discover,
    vendor_from_sys_object_id,
)


# ------------------------------------------------------------------ BER

class TestBerEncoding:
    def test_integer_roundtrip(self) -> None:
        for value in (0, 1, 127, 128, 255, 256, 65535, 2147483647):
            encoded = encode_integer(value)
            tag, payload, _ = _read_tlv(encoded, 0)
            assert tag == _TAG_INTEGER
            assert int.from_bytes(payload, "big") == value

    def test_integer_negative(self) -> None:
        tag, payload, _ = _read_tlv(encode_integer(-1), 0)
        assert payload == b"\xff"

    def test_oid_roundtrip(self) -> None:
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.1.1",
                    "1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.2.1.2.2.1.7.11"):
            assert decode_oid(encode_oid(oid)[2:]) == oid

    def test_oid_large_arc_encoding(self) -> None:
        # OIDs with sub-identifiers >= 128 exercise multi-byte base-128
        payload = encode_oid("1.3.6.1.2.1.2.2.1.5.1000")[2:]
        assert decode_oid(payload) == "1.3.6.1.2.1.2.2.1.5.1000"

    def test_long_length_encoding(self) -> None:
        # 300-byte octet string forces multi-byte BER length
        blob = bytes(range(256)) * 2  # 512 bytes
        encoded = encode_octet_string(blob)
        tag, payload, _ = _read_tlv(encoded, 0)
        assert tag == _TAG_OCTET
        assert payload == blob

    def test_short_oid_rejected(self) -> None:
        with pytest.raises(SnmpError):
            encode_oid("1")


def _handcrafted_response() -> bytes:
    """A response built byte-by-byte (independent of the encoder) for
    sysDescr = 'Cisco IOS XE' — proves wire compatibility, not self-consistency."""
    version = b"\x02\x01\x01"
    community = b"\x04\x06public"
    req_id = b"\x02\x03\x01\x02\x03"
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"
    oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
    value = b"\x04\x0cCisco IOS XE"
    varbind = _encode_tlv(_TAG_SEQUENCE, oid + value)
    varbinds = _encode_tlv(_TAG_SEQUENCE, varbind)
    pdu = _encode_tlv(PDU_RESPONSE, req_id + error_status + error_index + varbinds)
    return _encode_tlv(_TAG_SEQUENCE, version + community + pdu)


class TestParseResponse:
    def test_parse_handcrafted_response(self) -> None:
        rows = parse_response(_handcrafted_response())
        assert rows == [(SYS_DESCR, "Cisco IOS XE")]

    def test_parse_rejects_non_response_pdu(self) -> None:
        with pytest.raises(SnmpError):
            parse_response(build_get(SYS_DESCR, "public", 1))  # request PDU

    def test_parse_rejects_garbage(self) -> None:
        with pytest.raises(SnmpError):
            parse_response(b"not snmp")

    def test_parse_ipaddr_value(self) -> None:
        version = b"\x02\x01\x01"
        community = b"\x04\x06public"
        req_id = b"\x02\x01\x01"
        err = b"\x02\x01\x00"
        oid = encode_oid("1.3.6.1.2.1.4.21.1.7.0.10.0.0.1")
        value = _encode_tlv(0x40, bytes([10, 0, 0, 1]))  # IpAddress
        vb = _encode_tlv(_TAG_SEQUENCE, oid + value)
        vbs = _encode_tlv(_TAG_SEQUENCE, vb)
        pdu = _encode_tlv(PDU_RESPONSE, req_id + err + err + vbs)
        packet = _encode_tlv(_TAG_SEQUENCE, version + community + pdu)
        rows = parse_response(packet)
        assert rows[0][1] == "10.0.0.1"


# ------------------------------------------------------- fake responder

class _FakeResponder:
    """In-memory SNMPv2c agent: GET returns exact OIDs, GET_NEXT returns the
    next lexicographic OID under the table. Table: oid -> (tag, payload)."""

    def __init__(self, table: dict[str, bytes], community: str = "public") -> None:
        self.table = table
        self.community = community
        self.requests: list[tuple[int, str]] = []

    # -- socket-like factory -----------------------------------------
    def socket(self, family: int = 2, socktype: int = 2) -> "_FakeSocket":
        return _FakeSocket(self)

    # -- agent logic -------------------------------------------------
    def handle(self, packet: bytes) -> bytes:
        tag, payload, _ = _read_tlv(packet, 0)
        _version, _, pos = _read_tlv(payload, 0)
        _community, _, pos = _read_tlv(payload, pos)
        pdu_tag, pdu_payload, _ = _read_tlv(payload, pos)
        _req_tag, req_id, pos = _read_tlv(pdu_payload, 0)
        req_id = _encode_tlv(_req_tag, req_id)  # full TLV for echo
        _err, _, pos = _read_tlv(pdu_payload, pos)
        _idx, _, pos = _read_tlv(pdu_payload, pos)
        _vbs_tag, vbs, _ = _read_tlv(pdu_payload, pos)
        _vb_tag, vb, _ = _read_tlv(vbs, 0)
        oid_tag, oid_payload, vpos = _read_tlv(vb, 0)
        oid = decode_oid(oid_payload)
        self.requests.append((pdu_tag, oid))

        if pdu_tag == PDU_GET:
            response_oid, response_value = oid, self.table.get(oid)
            if response_value is None:
                return self._error_response(req_id, oid, b"\x02\x01\x02")  # noSuchObject? noSuchName=2
        else:  # GET_NEXT
            keys = sorted(self.table)
            after = [k for k in keys if k > oid]
            if not after:
                return self._error_response(req_id, oid, b"\x02\x01\x02")
            response_oid = after[0]
            response_value = self.table[response_oid]
        return self._response(req_id, response_oid, response_value)

    def _response(self, req_id: bytes, oid: str, value: bytes) -> bytes:
        varbind = _encode_tlv(_TAG_SEQUENCE, encode_oid(oid) + value)
        varbinds = _encode_tlv(_TAG_SEQUENCE, varbind)
        pdu = _encode_tlv(PDU_RESPONSE, req_id + b"\x02\x01\x00" + b"\x02\x01\x00" + varbinds)
        return _encode_tlv(_TAG_SEQUENCE, encode_integer(1) + encode_octet_string(b"public") + pdu)

    def _error_response(self, req_id: bytes, oid: str, err: bytes) -> bytes:
        varbind = _encode_tlv(_TAG_SEQUENCE, encode_oid(oid) + _encode_tlv(_TAG_NULL, b""))
        varbinds = _encode_tlv(_TAG_SEQUENCE, varbind)
        pdu = _encode_tlv(PDU_RESPONSE, req_id + err + b"\x02\x01\x00" + varbinds)
        return _encode_tlv(_TAG_SEQUENCE, encode_integer(1) + encode_octet_string(b"public") + pdu)


class _FakeSocket:
    def __init__(self, responder: _FakeResponder) -> None:
        self.responder = responder
        self._pending: bytes = b""

    def settimeout(self, timeout: float) -> None:
        pass

    def sendto(self, packet: bytes, addr: tuple) -> None:
        self._pending = self.responder.handle(packet)

    def recvfrom(self, size: int) -> tuple[bytes, tuple]:
        return self._pending, ("127.0.0.1", 161)

    def close(self) -> None:
        pass


def _value_octet(text: str) -> bytes:
    return encode_octet_string(text.encode())


def _value_integer(num: int) -> bytes:
    return encode_integer(num)


def _if_table_responder() -> _FakeResponder:
    """Two interfaces, one route — realistic walkable tables."""
    table = {
        SYS_DESCR: _value_octet("Cisco IOS Software, ASR1000"),
        SYS_OBJECT_ID: _value_octet("1.3.6.1.4.1.9.1.1222"),
        SYS_UPTIME: _value_integer(123456),
        SYS_NAME: _value_octet("edge-01.dxb.example.com"),
        IF_TABLE + ".2.1": _value_octet("Gi0/0/0"),
        IF_TABLE + ".2.2": _value_octet("Gi0/0/1"),
        IF_TABLE + ".4.1": _value_integer(1500),
        IF_TABLE + ".4.2": _value_integer(1500),
        IF_TABLE + ".8.1": _value_integer(1),
        IF_TABLE + ".8.2": _value_integer(1),
        IP_ROUTE_TABLE + ".1.0.10.0.0.0": _value_octet("10.0.0.0"),
        IP_ROUTE_TABLE + ".1.0.10.1.0.0": _value_octet("10.1.0.0"),
        IP_ROUTE_TABLE + ".7.0.10.0.0.0": _value_octet("10.0.0.254"),
        IP_ROUTE_TABLE + ".7.0.10.1.0.0": _value_octet("10.1.0.1"),
    }
    return _FakeResponder(table)


# ------------------------------------------------------------- client

class TestSnmpClient:
    def test_get_via_fake_responder(self) -> None:
        responder = _if_table_responder()
        client = SnmpClient("127.0.0.1", sock_factory=responder.socket)
        assert client.get(SYS_DESCR) == "Cisco IOS Software, ASR1000"
        assert client.get(SYS_UPTIME) == 123456

    def test_walk_interface_table(self) -> None:
        responder = _if_table_responder()
        client = SnmpClient("127.0.0.1", sock_factory=responder.socket)
        table = client.walk(IF_TABLE)
        assert IF_TABLE + ".2.1" in table
        assert table[IF_TABLE + ".2.2"] == "Gi0/0/1"
        assert table[IF_TABLE + ".4.1"] == 1500
        # walk must stay inside the base subtree
        assert all(oid.startswith(IF_TABLE) for oid in table)

    def test_walk_respects_limit(self) -> None:
        responder = _if_table_responder()
        client = SnmpClient("127.0.0.1", sock_factory=responder.socket)
        table = client.walk(IF_TABLE, limit=3)
        assert len(table) <= 3

    def test_timeout_raises_snmp_error(self) -> None:
        class DeadSocket(_FakeSocket):
            def sendto(self, packet: bytes, addr: tuple) -> None:
                raise TimeoutError("timed out")

        class DeadResponder:
            def socket(self, family: int = 2, socktype: int = 2) -> DeadSocket:
                return DeadSocket(self)

        client = SnmpClient("10.255.255.1", timeout=0.1, sock_factory=DeadResponder().socket)
        with pytest.raises(SnmpError):
            client.get(SYS_DESCR)

    def test_get_next_uses_request_pdu(self) -> None:
        responder = _if_table_responder()
        client = SnmpClient("127.0.0.1", sock_factory=responder.socket)
        client.walk(IF_TABLE, limit=2)
        assert responder.requests and responder.requests[0][0] == PDU_GET_NEXT


# ---------------------------------------------------------- discovery

class TestSnmpDiscovery:
    def test_full_discovery(self) -> None:
        responder = _if_table_responder()
        info = snmp_discover("edge-01", sock_factory=responder.socket)
        assert info.reachable is True
        assert info.sys_name == "edge-01.dxb.example.com"
        assert info.sys_uptime == 123456
        assert len(info.interfaces) == 2
        assert len(info.routes) == 2

    def test_interface_and_route_shapes(self) -> None:
        responder = _if_table_responder()
        info = snmp_discover("edge-01", sock_factory=responder.socket)
        assert info.interfaces[0]["ifDescr"] == "Gi0/0/0"
        assert info.interfaces[0]["ifMtu"] == 1500
        assert info.routes[0]["routeNextHop"] == "10.0.0.254"

    def test_security_mode_is_metadata_only(self) -> None:
        responder = _if_table_responder()
        info = snmp_discover("edge-01", sock_factory=responder.socket)
        data = info.to_dict()
        assert data["security_mode"] == "SNMPv2c-community"
        assert data["credential_ref"] is None
        assert "community" not in data

    def test_unreachable_device(self) -> None:
        class DeadSocket(_FakeSocket):
            def sendto(self, packet: bytes, addr: tuple) -> None:
                raise TimeoutError("no route")

        class DeadResponder:
            def socket(self, family: int = 2, socktype: int = 2) -> DeadSocket:
                return DeadSocket(self)

        info = snmp_discover("10.0.0.99", sock_factory=DeadResponder().socket)
        assert info.reachable is False
        assert info.interfaces == []

    def test_vendor_mapping(self) -> None:
        assert vendor_from_sys_object_id("1.3.6.1.4.1.9.1.1222") == "Cisco"
        assert vendor_from_sys_object_id("1.3.6.1.4.1.2636.1.1.1") == "Juniper"
        assert vendor_from_sys_object_id("1.3.6.1.4.1.3375.2.1.1") == "F5"
        assert vendor_from_sys_object_id("1.3.6.1.4.1.99999.1") == "Generic"
        assert vendor_from_sys_object_id(None) is None

    def test_device_info_dataclass(self) -> None:
        info = SnmpDeviceInfo(host="h", sys_descr="d", reachable=True)
        assert info.to_dict()["host"] == "h"
        assert info.to_dict()["sys_descr"] == "d"
