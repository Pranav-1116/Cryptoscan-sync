"""IKEv1 + IKEv2 IPsec probing, and ESP/PFS stated only on a real basis (spec 67 §13).

The rule this file enforces: CryptoScan never authenticates (no IKE_AUTH, no
Quick Mode), so the CHILD_SA suite and the PFS actually in use can only be

* ``DECLARED_IN_SA_INIT`` when the responder volunteers an ESP proposal,
* ``CONFIGURED`` when an operator declares the suite,
* ``NOT_OBSERVED`` otherwise — never "no ESP", never "PFS off".

IKEv1 is a different wire format from IKEv2 (algorithm in the first attribute,
not in the transform id; length-less proposals; DOI + situation header), and a
v1-only concentrator that is probed with a v2 packet looks like "no VPN here".
So v1 is built and parsed explicitly, and an unresponsive host is re-probed with
it before anything is reported as absent.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from network_scanner.inventory.network_evidence import build_ipsec_evidence
from network_scanner.probing.ipsec_probe import (
    AUTH_METHOD,
    DH_GROUP,
    ENCR,
    IKEV1_ENCR,
    IKEV1_HASH,
    PRF,
    build_ikev1_main_mode,
    build_ikev2_sa_init,
    classify_esp,
    classify_ipsec,
    esp_from_config,
    extract_sa_from_response,
    parse_ike_header,
    parse_sa_payload_v1,
    probe_ike,
    summarize_proposals,
)


# --------------------------------------------------------------------------- #
# IKEv1 wire format
# --------------------------------------------------------------------------- #
def _v1_proposal(*transforms: bytes, num: int = 1, proto: int = 1) -> bytes:
    return bytes([num, proto, 0, len(transforms)]) + b"".join(transforms)


def _v1_transform(number: int, ttype: int, algorithm: int, *extra: tuple[int, int]) -> bytes:
    attrs = struct.pack("!HH", ttype, algorithm)
    attrs += b"".join(struct.pack("!HH", klass, value) for klass, value in extra)
    return bytes([number, ttype]) + struct.pack("!H", 4 + len(attrs)) + attrs


def _v1_response(*proposals: bytes, version: int = 0x10, exchange: int = 2) -> bytes:
    sa_body = struct.pack("!II", 1, 1) + b"".join(proposals)  # DOI IPsec, SIT_IDENTITY_ONLY
    payload = bytes([0, 0]) + struct.pack("!H", len(sa_body) + 4) + sa_body
    header = struct.pack("!8s8sBBBBII", b"\x11" * 8, b"\x22" * 8, 33, version, exchange, 0, 0,
                         len(payload) + 28)
    return header + payload


def test_the_v1_packet_carries_the_algorithm_in_an_attribute_not_in_the_transform_id():
    packet = build_ikev1_main_mode(b"\x01" * 8)
    header = parse_ike_header(packet)
    assert header["version"] == "IKEv1.0"
    assert header["major"] == 1
    assert header["exchange"] == "MAIN_MODE"

    transforms = extract_sa_from_response(packet)[0]["transforms"]
    names = [item["name"] for item in transforms]
    assert names == ["AES-CBC-256", "HMAC-SHA1", "RSA-SIGNATURES", "MODP-2048"]
    # the algorithm lives in the class attribute, the transform id is a type
    assert transforms[0]["v1_type"] == ENCR and transforms[0]["id"] == 7
    assert transforms[0]["attributes"]["14"] == 256
    # the v1 authentication method is not a v2 integrity transform
    assert transforms[2]["type"] == AUTH_METHOD


def test_a_v1_response_is_parsed_with_the_v1_layout():
    response = _v1_response(_v1_proposal(
        _v1_transform(1, 1, 5),  # 5 = 3DES
        _v1_transform(2, 2, 1),  # 1 = HMAC-MD5
        _v1_transform(3, 3, 1),  # 1 = PSK
        _v1_transform(4, 4, 2),
    ))
    proposals = extract_sa_from_response(response)
    assert proposals[0]["ike_version"] == 1
    assert proposals[0]["protocol"] == "IKE"

    summary = summarize_proposals(proposals)
    assert summary["ike"]["version"] == "IKEv1"
    assert summary["ike"]["encryption"] == "3DES"
    assert summary["ike"]["prf"] == "HMAC-MD5"
    assert summary["ike"]["dh_group"] == "MODP-1024"
    assert summary["ike"]["auth_methods_offered"] == ["PRE-SHARED-KEY"]
    issues = classify_ipsec(proposals)
    assert "WEAK_IKE_ENCRYPTION:3DES" in issues
    assert "WEAK_IKE_MAC:HMAC-MD5" in issues
    assert "WEAK_IKE_DH_GROUP:MODP-1024" in issues
    # a v1 phase-1 DH group is not PFS, so absence of PFS is not claimed
    assert "IKE_NO_PFS" not in issues


def test_a_v1_esp_proposal_is_reported_as_offered_with_pfs_on():
    response = _v1_response(
        _v1_proposal(_v1_transform(1, 1, 7, (14, 256)), _v1_transform(2, 2, 2),
                     _v1_transform(3, 3, 3), _v1_transform(4, 4, 14)),
        _v1_proposal(_v1_transform(1, 1, 7, (14, 256)), _v1_transform(3, 3, 2),
                     _v1_transform(4, 4, 14), num=1, proto=3),
    )
    summary = summarize_proposals(extract_sa_from_response(response))
    assert summary["esp"]["status"] == "DECLARED_IN_SA_INIT"
    assert summary["esp"]["basis"] == "RESPONDER_OFFERED"
    assert summary["esp"]["encryption"] == "AES-CBC-256"
    assert summary["esp"]["pfs"] == "OFFERED"
    assert summary["esp"]["pfs_state"] == "ON"


def test_v1_transform_tables_are_not_the_v2_ones():
    # id 2 is 3DES in v1 ENCR and HMAC-SHA1 in v2 PRF: mixing them would label
    # an IKEv1 3DES proposal "HMAC-SHA1"
    response = _v1_response(_v1_proposal(_v1_transform(1, 1, 2)))
    ike = summarize_proposals(extract_sa_from_response(response))["ike"]
    assert ike["encryption"] == "IDEA", "v1 id 2 is IDEA; v2 id 2 would be HMAC-SHA1"
    assert IKEV1_ENCR[5] == "3DES" and IKEV1_HASH[2] == "HMAC-SHA1"


def test_a_truncated_v1_payload_never_raises():
    assert parse_sa_payload_v1(b"\x00\x00\x00\x00\x01\x00", 0, 6) == []


# --------------------------------------------------------------------------- #
# ESP/PFS bases
# --------------------------------------------------------------------------- #
def test_esp_without_any_basis_stays_not_observed_with_a_version_aware_reason():
    v2 = summarize_proposals([], ike_version=2)["esp"]
    v1 = summarize_proposals([], ike_version=1)["esp"]
    assert v2["status"] == v1["status"] == "NOT_OBSERVED"
    assert v2["pfs"] == v1["pfs"] == "UNKNOWN"
    assert v2["pfs_state"] == "UNKNOWN"
    assert "IKE_AUTH" in v2["reason"]
    assert "Quick Mode" in v1["reason"]


def test_a_declared_esp_suite_is_configured_and_never_observed():
    configured = esp_from_config({
        "encryption": "AES-CBC-256", "integrity": "HMAC-SHA2-256", "dh_group": "MODP-2048",
        "pfs": True, "reference": "cisco-asa running-config vpn-1",
    })
    assert configured["status"] == "CONFIGURED"
    assert configured["basis"] == "CONFIGURATION"
    assert configured["claim"] == "CONFIGURED"
    assert configured["pfs_state"] == "ON"
    assert configured["reference"].startswith("cisco-asa")
    assert "nobody has seen it negotiated" in configured["reason"]

    off = esp_from_config({"encryption": "AES-CBC-128", "pfs": "off"})
    assert off["pfs_state"] == "OFF"

    unknown = esp_from_config({"encryption": "AES-CBC-256"})
    assert unknown["pfs_state"] == "UNKNOWN", "a missing PFS statement is not PFS off"

    observed = summarize_proposals([], ike_version=2, esp_config={"encryption": "AES-CBC-256",
                                                                 "dh_group": "MODP-2048"})
    assert observed["esp"]["status"] == "CONFIGURED"
    assert observed["esp"]["pfs_state"] == "ON"


def test_an_esp_proposal_from_the_responder_outranks_a_declared_suite():
    proposals = [{"protocol": "ESP", "ike_version": 2, "transforms": [
        {"type": ENCR, "id": 5, "name": "AES-CBC-256"},
        {"type": DH_GROUP, "id": 14, "name": "MODP-2048"},
    ]}]
    summary = summarize_proposals(proposals, esp_config={"encryption": "3DES"})
    assert summary["esp"]["status"] == "DECLARED_IN_SA_INIT"
    assert summary["esp"]["encryption"] == "AES-CBC-256"
    assert "ESP_NO_PFS" not in classify_esp(proposals)


def test_the_evidence_record_carries_the_basis_and_the_real_version():
    probe = {
        "endpoint": "10.0.0.1:500",
        "status": "OK",
        "header": {"version": "IKEv1.0", "major": 1},
        "ike": summarize_proposals([{"protocol": "IKE", "ike_version": 1, "transforms": [
            {"type": ENCR, "id": 7, "name": "AES-CBC-256"},
            {"type": PRF, "id": 2, "name": "HMAC-SHA1"},
            {"type": DH_GROUP, "id": 14, "name": "MODP-2048"},
        ]}])["ike"],
        "esp": esp_from_config({"encryption": "AES-CBC-256", "pfs": True, "reference": "cmdb:vpn-1"}),
        "proposals": [],
        "issues": [],
        "notifies": [],
    }
    record = build_ipsec_evidence(probe, observed_at="2026-04-01T00:00:00Z")
    assert record["ike"]["version"] == "IKEv1.0"      # not hardcoded to IKEv2
    assert record["esp"]["status"] == "CONFIGURED"
    assert record["esp"]["basis"] == "CONFIGURATION"
    assert record["esp"]["pfs_state"] == "ON"
    assert record["esp"]["pfs_basis"] == "CONFIGURATION"


def test_an_unobserved_esp_is_not_reported_as_pfs_off():
    record = build_ipsec_evidence({"endpoint": "10.0.0.1:500", "status": "NO_RESPONSE"},
                                  observed_at="2026-04-01T00:00:00Z")
    assert record["esp"]["status"] == "NOT_OBSERVED"
    assert record["esp"]["pfs"] == "UNKNOWN"
    assert record["esp"]["pfs_state"] == "UNKNOWN"
    assert record["ike"]["version"] is None


# --------------------------------------------------------------------------- #
# live probe: v1-only responder, and the fallback order
# --------------------------------------------------------------------------- #
class _V1Responder:
    """Answers IKEv1 packets only; an IKEv2 packet gets nothing back."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen_versions: list[int] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        self.sock.settimeout(5.0)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                if self._stop.is_set():
                    break
                continue
            version = data[17] >> 4 if len(data) > 17 else 0
            self.seen_versions.append(version)
            if version != 1:
                continue  # a v1-only appliance ignores IKEv2 entirely
            response = _v1_response(_v1_proposal(
                _v1_transform(1, 1, 7, (14, 256)),
                _v1_transform(2, 2, 2),
                _v1_transform(3, 3, 3),
                _v1_transform(4, 4, 14),
            ))
            self.sock.sendto(response, addr)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def test_a_v1_only_concentrator_is_found_not_reported_as_absent():
    responder = _V1Responder()
    try:
        probe = probe_ike("127.0.0.1", ports=(responder.port,), timeout=1.0)
    finally:
        responder.close()

    assert probe["status"] == "OK"
    assert probe["ike_version"] == "IKEv1"
    assert probe["ike"]["encryption"] == "AES-CBC-256"
    assert probe["ike"]["dh_group"] == "MODP-2048"
    assert probe["esp"]["status"] == "NOT_OBSERVED"
    # v2 was tried first and recorded as an attempt, then v1 answered
    assert [item["version"] for item in probe["attempts"]] == ["IKEv2", "IKEv1"]
    assert probe["attempts"][0]["status"] == "NO_RESPONSE"
    assert 2 in responder.seen_versions and 1 in responder.seen_versions


class _V2Responder:
    def __init__(self) -> None:
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
            except (socket.timeout, OSError):
                if self._stop.is_set():
                    break
                continue
            if (data[17] >> 4) != 2:
                continue
            transforms = (struct.pack("!HBBH", 8, 1, 0, 5) + struct.pack("!HH", 0x800E, 256)
                          + struct.pack("!HBBH", 8, 2, 0, 5) + struct.pack("!HBBH", 8, 4, 0, 14))
            proposal = bytes([1, 1, 0, 3]) + transforms
            sa_body = b"\x00\x00\x00\x00" + proposal
            payload = bytes([0, 0]) + struct.pack("!H", len(sa_body) + 4) + sa_body
            header = struct.pack("!8s8sBBBBII", b"\x11" * 8, b"\x22" * 8, 33, 0x20, 34, 0x20, 0,
                                 len(payload) + 28)
            self.sock.sendto(header + payload, addr)

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def test_a_modern_concentrator_answers_the_first_packet_and_v1_is_not_sent():
    responder = _V2Responder()
    try:
        probe = probe_ike("127.0.0.1", ports=(responder.port,), timeout=1.0)
    finally:
        responder.close()
    assert probe["status"] == "OK"
    assert probe["ike_version"] == "IKEv2"
    assert len(probe["attempts"]) == 1, "one answer ends the probe"


def test_no_answer_on_any_version_is_a_gap_with_every_attempt_listed():
    probe = probe_ike("127.0.0.1", ports=(9,), timeout=0.2)
    assert probe["status"] in {"NO_RESPONSE", "PORT_CLOSED"}
    attempts = {(item["version"], item["port"], item["status"]) for item in probe["attempts"]}
    assert attempts, "the report says what was tried"
    if probe["status"] == "PORT_CLOSED":
        assert probe["attempts"][-1]["status"] == "PORT_CLOSED"
    else:
        assert {"IKEv2", "IKEv1"} <= {item["version"] for item in probe["attempts"]}


def test_an_ipev1_probe_request_differs_only_in_the_version_byte():
    v1 = build_ikev1_main_mode(b"\x07" * 8)
    v2 = build_ikev2_sa_init(b"\x07" * 8)
    assert v1[17] >> 4 == 1 and v2[17] >> 4 == 2
    assert v1[:16] == v2[:16] == b"\x07" * 8 + b"\x00" * 8


def test_the_probe_is_still_opt_in_and_takes_no_endpoints_implicitly():
    with pytest.raises(TypeError):
        probe_ike()
