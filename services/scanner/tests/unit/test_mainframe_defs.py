"""Natural (Adabas) + CICS/IMS/AT-TLS definition parsers — routing, comment handling, CIPHERS() decoding."""

from pathlib import Path

from scanner.core.file_discovery import FileDiscovery
from scanner.parsers.mainframe_defs_parser import decode_cics_ciphers
from scanner.registry.language_scanners import scan_file


def _algos(findings):
    return sorted({f.crypto.algorithm for f in findings})


def test_decode_cics_ciphers():
    assert decode_cics_ciphers("352F0A") == ["AES", "3DES"]
    assert decode_cics_ciphers("C027C02B") == ["AES"]
    assert decode_cics_ciphers("0102") == []  # NULL suites
    assert decode_cics_ciphers("ZZ") == []
    assert decode_cics_ciphers("35X") == []


def test_natural_comments_do_not_count(tmp_path):
    p = tmp_path / "CUST.NSP"
    p.write_text("* CALL 'CSNBENC' removed\n/* CALL 'CSNBOWH' also a comment\nDEFINE DATA LOCAL\n1 #X (A8)\nEND-DEFINE\nEND\n")
    assert scan_file(p, tmp_path) == []


def test_natural_icsf_call_and_rule_array(tmp_path):
    p = tmp_path / "HASH.NSN"
    p.write_text("DEFINE DATA LOCAL\n1 #RA (A8) INIT <'SHA-256 '>\nEND-DEFINE\nCALL 'CSNBOWH' #RC #RS #EDL #ED 1 #RA 8 #IN 128 #CH 32 #OUT /* hash it\nEND\n")
    findings = scan_file(p, tmp_path)
    assert "SHA-256" in _algos(findings)
    assert all(f.source.language == "NATURAL" for f in findings)


def test_cics_csd_ssl_and_ciphers(tmp_path):
    p = tmp_path / "web.csd"
    p.write_text("DEFINE TCPIPSERVICE(HTTPS) GROUP(WEB)\n       PORTNUMBER(8443) SSL(YES) CIPHERS(0A35)\nDEFINE PROGRAM(X) GROUP(WEB) LANGUAGE(COBOL)\n")
    assert _algos(scan_file(p, tmp_path)) == ["3DES", "AES", "TLS"]


def test_cics_batch_defs_are_silent(tmp_path):
    p = tmp_path / "batch.csd"
    p.write_text("DEFINE PROGRAM(PAYPOST) GROUP(BAT) LANGUAGE(COBOL)\nDEFINE FILE(PAYFILE) GROUP(BAT) DSNAME(PROD.PAY) KEYLENGTH(12)\n")
    assert scan_file(p, tmp_path) == []


def test_attls_policy_in_conf_file_decomposes_suites(tmp_path):
    p = tmp_path / "TTLS.conf"
    p.write_text("TTLSRule MQ\n{\n  Direction Outbound\n}\nTTLSCipherParms strong\n{\n  V3CipherSuites TLS_RSA_WITH_3DES_EDE_CBC_SHA\n}\nTTLSEnvironmentAdvancedParms adv\n{\n  TLSv1.2 On\n}\n")
    algos = _algos(scan_file(p, tmp_path))
    assert {"TLS", "3DES", "RSA", "SHA-1"} <= set(algos)


def test_discovery_picks_up_new_extensions(tmp_path):
    for name in ("A.NSP", "b.nsn", "web.csd", "sit.sit", "HWSCFG.proclib", "readme.md"):
        (tmp_path / name).write_text("x")
    found = {p.name for p in FileDiscovery().discover(tmp_path)}
    assert {"A.NSP", "b.nsn", "web.csd", "sit.sit", "HWSCFG.proclib"} <= found
    assert "readme.md" not in found
