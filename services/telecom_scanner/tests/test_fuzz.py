"""Robustness fuzzing (roadmap G): the passive wire parsers and the stream
normalizer must NEVER raise on arbitrary input — they return None, a valid
record, or the honest unmapped marker. Deterministic seeded fuzzing (no
external property-testing dependency)."""

from __future__ import annotations

import json
import random
import struct


from eventstream.stream.normalize import normalize
from telecom_scanner.passive import parse_diameter, parse_gtpc_v2, parse_sip_security

SEED = 20260915
CASES_PER_PARSER = 600


def _random_bytes(rng: random.Random, max_len: int = 4096) -> bytes:
    return bytes(rng.randrange(256) for _ in range(rng.randrange(0, max_len)))


def _valid_diameter(rng: random.Random) -> bytes:
    code = rng.choice([257, 258, 280, 316, 318, 1672, 1678, 601, 628, 9999])
    body = struct.pack("!IB", 264, 0x80) + (6).to_bytes(3, "big") + b"host1" + b"\x00" * 3
    total = 20 + len(body)
    return (struct.pack("!B3sB", 1, total.to_bytes(3, "big"), 0b11000000)
            + code.to_bytes(3, "big")
            + struct.pack("!III", 16777251, 1, 2) + body)


def _valid_gtpc(rng: random.Random) -> bytes:
    flags = rng.choice([0x40, 0x48])
    body = struct.pack("!BH", 71, 2) + b"PG"
    if flags & 0x08:
        return (struct.pack("!BBH", flags, 32, 12 - 4 + len(body))
                + struct.pack("!I", 1234) + struct.pack("!I", 7)[1:4] + b"\x00" + body)
    return struct.pack("!BBH", flags, 1, 4 + len(body)) + struct.pack("!I", 7)[1:4] + b"\x00" + body


def _truncations(valid: bytes, rng: random.Random) -> list[bytes]:
    cut = rng.randrange(1, max(2, len(valid)))
    return [valid[:cut]]


def test_parsers_never_raise_on_random_bytes():
    rng = random.Random(SEED)
    builders = (_valid_diameter, _valid_gtpc)
    parsers = (parse_diameter, parse_gtpc_v2)
    for parser, builder in zip(parsers, builders):
        for _ in range(CASES_PER_PARSER):
            blob = _random_bytes(rng)
            rec = parser(blob)  # must not raise
            assert rec is None or isinstance(rec, dict)
            if isinstance(rec, dict):
                json.dumps(rec)  # bus-safe: always serializable
        # structured corruption: valid frames with random byte flips
        for _ in range(CASES_PER_PARSER // 2):
            buf = bytearray(builder(rng))
            for _ in range(rng.randrange(1, 6)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
            rec = parser(bytes(buf))
            assert rec is None or isinstance(rec, dict)
            if isinstance(rec, dict):
                json.dumps(rec)
        # truncations of valid frames
        for _ in range(50):
            rec = parser(rng.choice(_truncations(builder(rng), rng)))
            assert rec is None or isinstance(rec, dict)


def test_sip_parser_never_raise_on_random_text():
    rng = random.Random(SEED + 1)
    for _ in range(CASES_PER_PARSER):
        blob = _random_bytes(rng, max_len=2048)
        rec = parse_sip_security(blob)
        assert rec is None or isinstance(rec, dict)
        if isinstance(rec, dict):
            json.dumps(rec)
    # semi-valid SIP with corrupted Security-Server values
    for _ in range(100):
        val = "".join(rng.choice(";=,ipsec-3gpp tls alg spi0123456789abcdef\"")
                      for _ in range(rng.randrange(1, 80)))
        sip = f"INVITE sip:x SIP/2.0\r\nSecurity-Server: {val}\r\n\r\n"
        rec = parse_sip_security(sip.encode())
        assert rec is None or isinstance(rec, dict)


def test_normalize_never_raise_on_arbitrary_dicts():
    rng = random.Random(SEED + 2)
    keys = ["kind", "endpoint", "host", "system", "crypto", "extra", "tls_version",
            "nf_name", "origin_host", "fingerprint_sha256", "policy_issues", 12345]
    values = [None, 7, "x" * 300, {"tls_version": 12}, [1, "a"], {}, "TLSv1.3",
              b"\x00\x01", 3.14, {"deep": {"deeper": [None]}}]
    for _ in range(CASES_PER_PARSER):
        raw = {rng.choice(keys): rng.choice(values) for _ in range(rng.randrange(0, 8))}
        out = normalize(raw, source="fuzz")
        assert isinstance(out, dict)
        assert out["kind"] in {"tls_finding", "monitor_pass", "telecom_nf", "cert",
                               "diameter", "gtpc", "sip", "kms_policy", "unknown"}
        json.dumps(out)  # canonical event must stay serializable


def test_fuzz_findings_are_reproducible():
    """Same seed -> same verdicts (deterministic robustness, not spot checks)."""
    rng1 = random.Random(SEED)
    rng2 = random.Random(SEED)
    out1 = [parse_diameter(_random_bytes(rng1, 256)) is None for _ in range(100)]
    out2 = [parse_diameter(_random_bytes(rng2, 256)) is None for _ in range(100)]
    assert out1 == out2
