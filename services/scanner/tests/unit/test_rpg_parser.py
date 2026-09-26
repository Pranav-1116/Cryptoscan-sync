"""IBM i RPG / CL / ILE C detector."""
from pathlib import Path

from scanner.registry.language_scanners import scan_file


def _algos(tmp_path: Path, name: str, code: str) -> set[str]:
    p = tmp_path / name
    p.write_text(code)
    return {f.crypto.algorithm for f in scan_file(p, tmp_path)}


def test_qc3_encrypt_resolves_algd0200_code(tmp_path):
    code = "**free\ndcl-ds algd0200 qualified;\n  blockCipherAlg int(10) inz(22);\nend-ds;\nQc3EncryptData(d : l : 'DATA0100' : algd0200 : 'ALGD0200' : k : 'KEYD0200' : '0' : '' : o : s : r : e);\n"
    assert _algos(tmp_path, "enc.rpgle", code) == {"AES"}


def test_qc3_hash_fixed_form_d_spec(tmp_path):
    code = "     D algd0500        DS\n     D  hashAlg                      10I 0 inz(3)\n     C                   callp     Qc3CalculateHash(d : l : 'DATA0100' : algd0500 : 'ALGD0500' : '0' : '' : h : e)\n"
    assert _algos(tmp_path, "hash.rpgle", code) == {"SHA-256"}


def test_qc3_without_any_algorithm_is_unknown_not_guessed(tmp_path):
    code = "**free\nQc3EncryptData(d : l : 'DATA0100' : algd : 'ALGD0100' : k : 'KEYD0100' : '0' : '' : o : s : r : e);\n"
    assert _algos(tmp_path, "ctx.rpgle", code) == {"UNKNOWN"}


def test_cl_sysvals_split_into_versions_and_suite_components(tmp_path):
    code = "PGM\nCHGSYSVAL SYSVAL(QSSLPCL) VALUE('*TLSV1.2 *SSLV3')\nCHGSYSVAL SYSVAL(QSSLCSL) VALUE('*RSA_RC4_128_SHA')\nENDPGM\n"
    algos = _algos(tmp_path, "tls.clle", code)
    assert {"TLS1.2", "SSLv3", "RC4", "SHA-1", "RSA"} <= algos


def test_cl_unrelated_sysvals_and_library_names_are_silent(tmp_path):
    code = "PGM\nCHGSYSVAL SYSVAL(QPWDLVL) VALUE(3)\nADDLIBLE LIB(QC3LIB)\nOVRDBF FILE(A) TOFILE(*LIBL/A)\nENDPGM\n"
    assert _algos(tmp_path, "neg.clle", code) == set()


def test_rpg_comments_do_not_fire(tmp_path):
    code = "     H DFTACTGRP(*NO)\n      * Qc3EncryptData with AES one day\n     C                   return\n"
    assert _algos(tmp_path, "cmt.rpgle", code) == set()


def test_ile_c_qc3_and_gskit(tmp_path):
    code = '#include <qc3cci.h>\nint f(){ char algDesc[8]; algDesc[3] = Qc3_SHA1;\nQc3CalculateHash(k, &l, "DATA0100", algDesc, "ALGD0500", &csp, dev, out, &err);\ngsk_attribute_set_enum(env, GSK_PROTOCOL_TLSV12, GSK_TRUE); return 0; }\n'
    algos = _algos(tmp_path, "ws.c", code)
    assert {"SHA-1", "TLS", "TLS1.2"} <= algos


def test_plain_c_without_ibm_i_markers_is_untouched(tmp_path):
    code = "int main(){ int hashAlg = 3; return hashAlg; }\n"
    assert _algos(tmp_path, "plain.c", code) == set()
