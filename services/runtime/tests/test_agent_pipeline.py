"""Library risk table + capture parsers + collector tests."""

from __future__ import annotations

import json

from runtime.agent.capture_parsers import parse_openssl_cipher, parse_sclient_output, parse_tap_jsonl
from runtime.agent.library_risk import assess_library
from runtime.core.collector import collect, merge_observations, sessions_to_findings
from runtime.core.submitter import RuntimeSubmitter

# --------------------------------------------------------------------------- #
# library risk
# --------------------------------------------------------------------------- #


def test_openssl_lifecycle_verdicts():
    assert assess_library("openssl", "1.0.2k")["status"] == "DISALLOWED"
    assert assess_library("openssl", "1.1.1w")["status"] == "DISALLOWED"
    assert assess_library("openssl", "1.1.0l")["status"] == "DISALLOWED"
    assert assess_library("openssl", "3.0.2")["status"] == "DEPRECATED"  # EOL scheduled/passed
    assert assess_library("openssl", "3.0.13")["status"] == "DEPRECATED"
    assert assess_library("openssl", "3.2.1")["status"] == "ALLOWED"
    assert assess_library("openssl", None)["status"] == "UNKNOWN"


def test_other_libraries():
    assert assess_library("gnutls", "3.5.18")["status"] == "DISALLOWED"  # real old version
    assert assess_library("gnutls", "3.7.11")["status"] == "ALLOWED"
    # ABI soname tags are NOT release versions: GnuTLS soname "30.x" ships with
    # modern 3.7/3.8 too, so it must never be flagged deprecated on its own.
    assert assess_library("gnutls", "30.40.3")["status"] == "UNKNOWN"
    assert assess_library("mbedtls", "2.16.0")["status"] == "DISALLOWED"
    assert assess_library("boringssl", None)["status"] == "ALLOWED"
    # libnss3.so carries no version in its name -> UNKNOWN until package-resolved
    assert assess_library("nss", None)["status"] == "UNKNOWN"
    assert assess_library("nss", "3.87.1")["status"] == "ALLOWED"
    # OpenSSL soname "3" spans 3.0 (EOL) through 3.5 (current): never flag from major alone
    assert assess_library("openssl", "3")["status"] == "UNKNOWN"
    assert assess_library("openssl", "3.0.20")["status"] == "DEPRECATED"  # 3.0 line EOL
    assert assess_library("openssl", "3.5.0")["status"] == "ALLOWED"


# --------------------------------------------------------------------------- #
# openssl s_client + cipher-name decomposition
# --------------------------------------------------------------------------- #


SCLIENT_TLS13 = """---
CONNECTED(00000003)
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Verification error: self signed certificate
---
Verify return code: 21 (self-signed certificate)
"""

SCLIENT_TLS12 = """---
New, (TLSv1.2), Cipher is ECDHE-RSA-AES256-GCM-SHA384
---
Protocol  : TLSv1.2
Cipher    : ECDHE-RSA-AES256-GCM-SHA384
Verify return code: 0 (ok)
"""


def test_parse_sclient_modern_and_legacy():
    tls13 = parse_sclient_output(SCLIENT_TLS13)
    assert tls13["tls_version"] == "TLSv1.3"
    assert tls13["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert tls13["cert_verified"] is False

    tls12 = parse_sclient_output(SCLIENT_TLS12)
    assert tls12["tls_version"] == "TLSv1.2"
    assert tls12["cipher_suite"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert tls12["cert_verified"] is True


def test_parse_openssl_cipher_names():
    strong = parse_openssl_cipher("ECDHE-RSA-AES256-GCM-SHA384")
    assert strong["key_exchange"] == "ECDHE-RSA"
    assert strong["bulk_cipher"] == "AES256"
    assert strong["mode"] == "GCM"
    assert strong["algorithm"] == "AES"
    assert strong["key_size"] == 256
    assert strong["status"] == "ALLOWED"

    legacy = parse_openssl_cipher("AES128-SHA")
    assert legacy["bulk_cipher"] == "AES128"
    assert legacy["mode"] == "CBC"
    assert legacy["mac"] == "SHA-1"

    ancient = parse_openssl_cipher("DES-CBC3-SHA")
    assert ancient["bulk_cipher"] == "3DES"
    assert ancient["mac"] == "SHA-1"

    rc4 = parse_openssl_cipher("RC4-SHA")
    assert rc4["bulk_cipher"] == "RC4"
    assert rc4["status"] == "DISALLOWED"

    chacha = parse_openssl_cipher("ECDHE-ECDSA-CHACHA20-POLY1305")
    assert chacha["algorithm"] == "ChaCha20-Poly1305"
    assert chacha["key_size"] == 256

    components = parse_openssl_cipher("ECDHE-RSA-AES256-GCM-SHA384")["components"]
    roles = {c["role"] for c in components}
    assert "key_exchange" in roles and "mac" in roles


def test_parse_tap_jsonl_skips_bad_lines(tmp_path):
    path = tmp_path / "sessions.jsonl"
    good = json.dumps({"sni": "a", "negotiated": {"cipher_suite": "TLS_AES_128_GCM_SHA256", "negotiated_version": "TLSv1.3"}})
    path.write_text(good + "\nnot-json\n\n" + good + "\n", encoding="utf-8")
    sessions = parse_tap_jsonl(path)
    assert len(sessions) == 2


# --------------------------------------------------------------------------- #
# collector
# --------------------------------------------------------------------------- #


def _session(suite, version, sni="payments.internal"):
    return {
        "sni": sni,
        "client": "10.0.0.9:44000",
        "negotiated": {"cipher_suite": suite, "negotiated_version": version},
        "certificate": {"chain": [{"sha256_fingerprint": "ab" * 32, "common_names": ["payments.internal"]}]},
        "offered_suites": [suite],
        "error": None,
    }


def test_sessions_to_findings_registry_enriched():
    findings = sessions_to_findings([
        _session("TLS_AES_256_GCM_SHA384", "TLSv1.3"),
        _session("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.0"),
    ])
    assert len(findings) == 2
    modern, legacy = findings[0], findings[1]
    assert modern["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert modern["key_size"] == 256
    assert modern["extra"]["suite_status"] == "ALLOWED"
    assert modern["extra"]["cert_sha256"] == "ab" * 32
    assert legacy["extra"]["suite_status"] == "DISALLOWED"
    assert legacy["extra"]["weak_tls_version"] is True
    assert legacy["algorithm"] == "3DES"
    assert legacy["key_size"] == 168


def test_merge_observations_counts_repeats():
    findings = sessions_to_findings([_session("TLS_AES_128_GCM_SHA256", "TLSv1.3"), _session("TLS_AES_128_GCM_SHA256", "TLSv1.3")])
    merged = merge_observations(findings)
    assert len(merged) == 1
    assert merged[0]["observation_count"] == 2


def test_collect_aggregates_sessions_and_processes():
    process_scan = {
        "host": "prod-web-1",
        "findings": [
            {
                "process_name": "nginx",
                "pid": 101,
                "library": "openssl",
                "version": "1.0.2",
                "status": "DISALLOWED",
                "notes": "EOL 2019-12-31",
                "library_name": "OpenSSL 1.0.2",
                "listening_ports": [443],
                "containerized": True,
            }
        ],
    }
    payload = collect(sessions=[_session("TLS_RSA_WITH_RC4_128_SHA", "TLSv1.1")], process_scan=process_scan)
    assert payload["scanner_id"] == "runtime-agent-v1.0"
    assert payload["summary"]["sessions"] == 1
    assert payload["summary"]["session_findings"] == 1
    assert payload["summary"]["process_findings"] == 1
    assert payload["summary"]["weak_cipher_suites"] == 1  # RC4
    assert payload["summary"]["weak_tls_versions"] == 1  # TLSv1.1
    assert payload["summary"]["risky_libraries"] == 1

    lib_finding = next(f for f in payload["findings"] if (f.get("extra") or {}).get("kind") == "tls-library-risk")
    assert lib_finding["process_name"] == "nginx"
    assert lib_finding["extra"]["library_status"] == "DISALLOWED"
    # payload matches the API RuntimeFinding model shape
    for key in ("process_name", "pid", "hostname", "tls_version", "cipher_suite", "algorithm", "observation_count", "extra"):
        assert key in lib_finding or key in payload["findings"][0]


def test_submitter_fail_open_without_url():
    result = RuntimeSubmitter(api_url=None).submit({"scanner_id": "x", "findings": []})
    assert result["ok"] is False and result["skipped"] is True


def test_submitter_uses_injected_transport():
    calls = []

    def transport(url, payload):
        calls.append((url, payload))
        return {"accepted": 1, "anomalies": 0}

    result = RuntimeSubmitter(api_url="https://api.internal", transport=transport).submit({"scanner_id": "x", "findings": []})
    assert result["ok"] is True
    assert calls[0][0] == "https://api.internal/api/v1/scans/runtime-findings"
    assert calls[0][1]["scanner_id"] == "x"
