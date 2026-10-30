"""Windows artefact parsers: real export formats, configuration-only claims.

Each fixture is what the corresponding Windows command actually writes, so a parser
regression shows up here rather than on a customer's host.
"""
from __future__ import annotations

from api.windows_artifacts import (
    iana_suite_algorithms,
    parse_artifact,
    parse_artifacts,
    parse_certificate_store,
    parse_cipher_suites,
    parse_schannel_registry,
)

SCHANNEL_REG = """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0]
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server]
"Enabled"=dword:00000000
"DisabledByDefault"=dword:00000001

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2]
[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server]
"Enabled"=dword:00000001
"DisabledByDefault"=dword:00000000
"""

SUITES_JSON = """[
  {"Name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "CipherStrength": 256},
  {"Name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "CipherStrength": 256},
  {"Name": "TLS_RSA_WITH_AES_128_CBC_SHA", "CipherStrength": 128}
]"""

SUITES_CSV = """Name,CipherStrength
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,256
TLS_AES_128_GCM_SHA256,128
"""

CERTS_JSON = """[
  {"Subject": "CN=bank-portal.internal", "Issuer": "CN=Bank Issuing CA",
   "Thumbprint": "ab12cd34ef56", "NotBefore": "/Date(1735689600000)/",
   "NotAfter": "/Date(1830297600000)/", "HasPrivateKey": true,
   "PublicKeyAlgorithm": "RSA", "DnsNameList": ["bank-portal.internal"]}
]"""


def test_schannel_registry_policy_is_read_per_protocol_and_role():
    parsed = parse_schannel_registry(SCHANNEL_REG)
    by_protocol = {(row["protocol"], row["scope"]): row for row in parsed["records"]}
    assert by_protocol[("TLS 1.0", "server")]["enabled"] is False
    assert by_protocol[("TLS 1.0", "server")]["disabled_by_default"] is True
    assert by_protocol[("TLS 1.2", "server")]["enabled"] is True
    # the parent key carries no values, so it does not fabricate a policy of its own
    assert ("TLS 1.2", "global") not in by_protocol


def test_cipher_suites_from_json_and_csv_expand_to_algorithms():
    from_json = parse_cipher_suites(SUITES_JSON)
    assert from_json["format"] == "cipher-suites-json"
    first = from_json["records"][0]
    assert first["suite"] == "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    algorithms = {row["algorithm"] for row in first["algorithms"]}
    assert {"ECDHE", "ECDSA", "CHACHA20-POLY1305", "SHA-256"} <= algorithms

    from_csv = parse_cipher_suites(SUITES_CSV)
    assert from_csv["format"] == "cipher-suites-csv"
    assert len(from_csv["records"]) == 2


def test_suite_name_does_not_read_ecdhe_as_dhe():
    algorithms = [row["algorithm"] for row in iana_suite_algorithms(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")]
    assert "ECDHE" in algorithms
    assert "DHE" not in algorithms


def test_certificate_store_keeps_the_thumbprint_as_a_sha1_thumbprint():
    parsed = parse_certificate_store(CERTS_JSON)
    record = parsed["records"][0]
    assert record["thumbprint"] == "AB12CD34EF56"
    assert record["has_private_key"] is True
    # a thumbprint is not a SHA-256 fingerprint and must not be promoted to one
    assert "fingerprint_sha256" not in record


def test_unrecognised_artefact_is_refused_with_a_reason(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some notes\n", encoding="utf-8")
    result = parse_artifact(path)
    assert result.format is None
    assert "unrecognised artefact" in (result.error or "")


def test_parse_artifacts_reports_every_file_it_read_and_every_file_it_refused(tmp_path):
    reg = tmp_path / "schannel.reg"
    reg.write_text(SCHANNEL_REG, encoding="utf-8")
    suites = tmp_path / "suites.json"
    suites.write_text(SUITES_JSON, encoding="utf-8")
    certs = tmp_path / "certs.json"
    certs.write_text(CERTS_JSON, encoding="utf-8")
    junk = tmp_path / "image.png"
    junk.write_bytes(b"\x89PNG\r\n\x1a\n")

    parsed = parse_artifacts([reg, suites, certs, junk, tmp_path / "missing.json"])
    assert len(parsed["files"]) == 5
    assert len(parsed["refused"]) == 2
    assert len(parsed["protocols"]) == 2
    assert len(parsed["suites"]) == 3
    assert len(parsed["certificates"]) == 1
    # the note states what these facts are, in the response itself
    assert "not a handshake" in parsed["note"]
