"""Cross-file constant resolution (constants classes) — precision rules and pipeline integration."""

from pathlib import Path

from scanner.core.constant_index import ConstantIndex
from scanner.core.scanner import Scanner

ALGOS = '''package com.bank;
public final class Algorithms {
    public static final String DIGEST = "SHA-1";
    public static final String MAC = "HmacSHA256";
    public static final String KEY_ALG = "DESede";
    public static final String LABEL = "customer-id";
}
'''
OTHER = '''package com.other;
public final class Legacy {
    public static final String DIGEST = "MD5";
}
'''
SVC = '''package com.bank;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import static com.bank.Algorithms.KEY_ALG;
public class Svc {
    byte[] d(byte[] x) throws Exception { return MessageDigest.getInstance(Algorithms.DIGEST).digest(x); }
    byte[] d2(byte[] x) throws Exception { return MessageDigest.getInstance(Legacy.DIGEST).digest(x); }
    Mac m() throws Exception { return Mac.getInstance(Algorithms.MAC); }
    SecretKeySpec k(byte[] b) { return new SecretKeySpec(b, KEY_ALG); }
    SecretKeySpec bad(byte[] b) { return new SecretKeySpec(b, Algorithms.LABEL); }
}
'''


def _write(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return tmp_path


def test_lookup_qualified_simple_and_ambiguous():
    idx = ConstantIndex()
    idx.add_source(ALGOS)
    idx.add_source(OTHER)
    assert idx.lookup("Algorithms.DIGEST") == ("SHA-1", "Algorithms.DIGEST")
    assert idx.lookup("Legacy.DIGEST") == ("MD5", "Legacy.DIGEST")
    assert idx.lookup("DIGEST") == (None, None)  # same simple name, two literals → ambiguous
    assert idx.lookup("KEY_ALG") == ("DESede", "Algorithms.KEY_ALG")  # unique simple name resolves
    assert idx.lookup("Nope.DIGEST") == (None, None)
    assert idx.lookup("") == (None, None)


def test_kotlin_and_csharp_constants_indexed():
    idx = ConstantIndex()
    idx.add_source('object Crypto { const val ALG = "AES/GCM/NoPadding" }')
    idx.add_source('public static class Names { public const string Hash = "SHA512"; private static readonly string Old = "MD5"; }')
    assert idx.lookup("Crypto.ALG")[0] == "AES/GCM/NoPadding"
    assert idx.lookup("Names.Hash")[0] == "SHA512"
    assert idx.lookup("Names.Old")[0] == "MD5"


def test_pipeline_resolves_cross_file_constants(tmp_path):
    root = _write(tmp_path, {"com/bank/Algorithms.java": ALGOS, "com/other/Legacy.java": OTHER, "com/bank/Svc.java": SVC})
    result = Scanner().scan(root)
    svc = {f.source.line_number: f for f in result.findings if f.source.file_path.endswith("Svc.java")}
    assert svc[7].crypto.algorithm == "SHA-1"
    assert svc[8].crypto.algorithm == "MD5"
    assert svc[9].crypto.algorithm == "HMAC-SHA-256"
    assert svc[10].crypto.algorithm == "3DES"
    # a constant whose literal is not an algorithm must stay UNKNOWN (no coined names)
    assert svc[11].crypto.algorithm == "UNKNOWN"
    for line in (7, 8, 9, 10):
        assert svc[line].metadata.confidence == "MEDIUM"
        assert "cross-file constant" in svc[line].metadata.confidence_reason
    assert result.statistics.resolved_cross_file == 4


def test_no_constants_is_a_noop(tmp_path):
    root = _write(tmp_path, {"A.java": 'import java.security.MessageDigest; class A { void f(String a) throws Exception { MessageDigest.getInstance(a); } }'})
    result = Scanner().scan(root)
    assert [f.crypto.algorithm for f in result.findings] == ["UNKNOWN"]
    assert result.statistics.resolved_cross_file == 0
