"""Dependency & cascade analysis: providers, blast radius, libraries, shared keys, weak parameters, waves."""
from pathlib import Path

from scanner.analysis.cascade import DependencyGraph, key_references, parse_manifest
from scanner.core.scanner import Scanner


def _estate(tmp: Path) -> Path:
    w = lambda rel, text: (tmp / rel).parent.mkdir(parents=True, exist_ok=True) or (tmp / rel).write_text(text)
    # shared crypto utility, used by two services; one service also has its own crypto
    w("core/src/main/java/com/bank/core/crypto/CryptoUtil.java", """package com.bank.core.crypto;
import javax.crypto.Cipher;
import java.security.KeyStore;
public class CryptoUtil {
  public static Cipher cipher() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }
  public static KeyStore ks() throws Exception { KeyStore k = KeyStore.getInstance("JKS"); k.load(new java.io.FileInputStream("/etc/bank/payments.jks"), System.getenv("PAYMENTS_KEYSTORE_PASSWORD").toCharArray()); return k; }
}
""")
    w("payments/src/main/java/com/bank/payments/PaymentService.java", """package com.bank.payments;
import com.bank.core.crypto.CryptoUtil;
public class PaymentService { void pay() throws Exception { CryptoUtil.cipher(); } }
""")
    w("payments/src/main/java/com/bank/payments/PaymentController.java", """package com.bank.payments;
import com.bank.payments.PaymentService;
public class PaymentController { PaymentService s; }
""")
    w("cards/src/main/java/com/bank/cards/CardSigner.java", """package com.bank.cards;
import com.bank.core.crypto.*;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
public class CardSigner {
  void k() throws Exception { CryptoUtil.ks(); KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(1024);
    KeyStore ks = KeyStore.getInstance("JKS"); ks.load(new java.io.FileInputStream("/etc/bank/payments.jks"), null); }
}
""")
    w("core/pom.xml", """<project><dependencies>
<dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency>
<dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.12.5</version></dependency>
<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
</dependencies></project>""")
    # python batch: hashing module + two importers
    w("batch/bank/hashing.py", "import hashlib\ndef h(b):\n    return hashlib.md5(b).hexdigest()\n")
    w("batch/bank/reconcile.py", "from bank.hashing import h\n")
    w("batch/bank/report.py", "from bank import hashing\n")
    w("batch/requirements.txt", "cryptography==42.0.5\nrequests==2.31.0\n")
    # COBOL: ICSF wrapper called by two programs
    w("mf/CRYPTO01.cbl", """       IDENTIFICATION DIVISION.
       PROGRAM-ID. CRYPTO01.
       PROCEDURE DIVISION.
           CALL 'CSNBENC' USING RC RS EXIT-LEN EXIT-DATA KEY-ID TEXT-LEN CLEAR-TEXT IV RULE-COUNT RULE-ARRAY PAD CHAIN CIPHER-TEXT.
""")
    w("mf/PAYPOST.cbl", "       IDENTIFICATION DIVISION.\n       PROGRAM-ID. PAYPOST.\n       PROCEDURE DIVISION.\n           CALL 'CRYPTO01' USING WS-AREA.\n")
    w("mf/STMTGEN.cbl", "       IDENTIFICATION DIVISION.\n       PROGRAM-ID. STMTGEN.\n       PROCEDURE DIVISION.\n           CALL 'CRYPTO01' USING WS-AREA.\n")
    return tmp


def test_dependency_graph_resolves_java_python_cobol(tmp_path):
    root = _estate(tmp_path)
    g = DependencyGraph.build([p for p in root.rglob("*") if p.is_file()], root)
    util = "core/src/main/java/com/bank/core/crypto/CryptoUtil.java"
    assert g.dependents[util] == {"payments/src/main/java/com/bank/payments/PaymentService.java", "cards/src/main/java/com/bank/cards/CardSigner.java"}
    assert "payments/src/main/java/com/bank/payments/PaymentController.java" in g.transitive_dependents(util)
    assert g.dependents["batch/bank/hashing.py"] == {"batch/bank/reconcile.py", "batch/bank/report.py"}
    assert g.dependents["mf/CRYPTO01.cbl"] == {"mf/PAYPOST.cbl", "mf/STMTGEN.cbl"}


def test_manifest_and_key_reference_parsers(tmp_path):
    root = _estate(tmp_path)
    deps = parse_manifest(root / "core/pom.xml", "core/pom.xml")
    assert {(d["library"], d["version"]) for d in deps} == {("BouncyCastle", "1.78"), ("jjwt", "0.12.5")}  # slf4j ignored
    deps = parse_manifest(root / "batch/requirements.txt", "batch/requirements.txt")
    assert [(d["library"], d["version"]) for d in deps] == [("python-cryptography", "42.0.5")]
    refs = key_references('KeyStore.getInstance("JKS"); k.load(new FileInputStream("/etc/bank/payments.jks"), System.getenv("PAYMENTS_KEYSTORE_PASSWORD"))')
    assert ("key_file", "payments.jks") in refs and ("secret_env", "PAYMENTS_KEYSTORE_PASSWORD") in refs
    assert key_references("PRIMARY_KEY int; cache.get(CACHE_KEY)") == []


def test_scan_emits_cascade_report(tmp_path):
    root = _estate(tmp_path)
    result = Scanner().scan(str(root))
    c = result.cascade
    assert c["summary"]["providers"] >= 4
    prov = {p["file"]: p for p in c["providers"]}
    util = prov["core/src/main/java/com/bank/core/crypto/CryptoUtil.java"]
    assert util["direct_dependents"] == 2 and util["transitive_dependents"] == 3 and util["rank"] == 1 and util["wave"] == 1
    assert "AES" in util["algorithms"]
    signer = prov["cards/src/main/java/com/bank/cards/CardSigner.java"]
    assert signer["depends_on_providers"] == [util["file"]] and signer["wave"] == 2
    assert prov["mf/CRYPTO01.cbl"]["direct_dependents"] == 2 and "3DES" in prov["mf/CRYPTO01.cbl"]["algorithms"]
    assert prov["batch/bank/hashing.py"]["direct_dependents"] == 2
    # libraries: declared crypto deps, platform APIs never flagged as undeclared
    libs = {l["library"]: l for l in c["libraries"]}
    assert libs["BouncyCastle"]["versions"] == ["1.78"] and libs["BouncyCastle"]["declared_but_unused"]
    assert libs["jjwt"]["declared_but_unused"] and libs["python-cryptography"]["manifests"] == ["batch/requirements.txt"]
    assert not any(l["used_but_undeclared"] for l in c["libraries"] if l["library"] in ("JCA", "JCE", "hashlib", "ICSF"))
    # shared key material: one keystore, two consumers
    shared = {(s["kind"], s["identifier"]): s for s in c["shared_keys"]}
    assert set(shared[("key_file", "payments.jks")]["files"]) == {util["file"], signer["file"]}
    # weak parameter: RSA 1024 < 2048
    assert any(w["algorithm"] == "RSA" and w["key_size"] == 1024 and w["minimum"] == 2048 for w in c["weak_parameters"])
    # waves: util first, signer second
    waves = {w["wave"]: w for w in c["migration_waves"]}
    assert util["file"] in waves[1]["providers"] and signer["file"] in waves[2]["providers"]
    assert result.statistics.cascade_providers == c["summary"]["providers"]


def test_cascade_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_CASCADE", "0")
    root = _estate(tmp_path)
    result = Scanner().scan(str(root))
    assert getattr(result, "cascade", None) is None
