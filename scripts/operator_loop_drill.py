#!/usr/bin/env python3
"""Operator-loop drill: run the whole remediation chain on a real estate, twice.

The P1 vision row ("operator loop") has a Done-when that no other harness in
this repository satisfies:

    Execute the entire chain on a realistic authorized estate twice, including
    failed, inconclusive and reintroduced cases; no ticket-as-fix shortcut.

The chain, and the surface that carries each step:

    authorized system      POST /systems                (named technical + security owner)
      -> scan              POST /systems/{id}/scan      (admission-checked, 202 + job)
      -> verified evidence GET  /scans/{id}/verify      (SHA-256 content/chain/manifest)
      -> approved baseline POST /baselines/approve      (auditor, audited)
      -> drift             GET  /drift                  (deterministic compare)
      -> owned task        POST /remediation/tasks      (snapshots the finding + rule)
      -> authorized change <the estate is edited on disk — a real mutation>
      -> adequate rescan   POST /systems/{id}/scan
      -> verification      POST /remediation/tasks/{id}/complete | /verify
      -> signed report     POST /scans/{id}/report-snapshot + GET /report-snapshots/{id}

"A ticket is not a fix" is not asserted here, it is *provoked*: the drill
completes tasks against estates that were deliberately NOT fixed, half-fixed,
fixed-then-broken, fixed-then-reintroduced, and rescanned-to-nothing, and
requires the platform to refuse credit in each case. The five outcomes the
verification engine defines are each produced by a real file mutation:

    VERIFIED      the weak construct is gone from the rescan's evidence
    FAILED        task completed with the code untouched (the ticket-as-fix trap)
    PARTIAL       the site changed but is still non-compliant (3DES ECB -> CBC)
    REGRESSION    the fix landed and a NEW violation appeared in the same target
    INCONCLUSIVE  the rescan produced no evidence for the target at all
    REINTRODUCED  a VERIFIED fix is put back; the next rescan must catch it

Honest by construction: every step records its HTTP status and the exact field
it asserted on, a step that cannot run is FAIL with the reason (never a silent
skip), and the summary reports failures rather than hiding them behind a
percentage. What this drill does NOT prove is stated in the artifact: the estate
is synthetic (built from this repository's own parser corpora), so it is
corpus evidence, not customer validation — the same distinction the engineering
gate applies to the COBOL/PL-I/RPG customer-sample checks.

    # against a running API (no Redis needed: the API runs the pipeline inline)
    python scripts/operator_loop_drill.py --api http://127.0.0.1:8010 \\
        --estate /tmp/cryptoscan-sources/operator-loop --passes 2 \\
        --out docs/readiness-evidence/operator-loop-drill-2026-10-16.json

The estate must live under an allow-listed source root
(`CRYPTOSCAN_SOURCE_ROOTS`, or one of the built-in roots such as
`/tmp/cryptoscan-sources`) because `POST /scans/trigger` confines local targets.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOW = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")  # noqa: E731

TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "TIMEOUT"}


# --------------------------------------------------------------------- HTTP


class Api:
    """Minimal authenticated client (same shape as scripts/soak.py)."""

    def __init__(self, base: str, username: str, password: str, timeout: float = 120.0):
        self.base = base.rstrip("/")
        self.username, self.password = username, password
        self.timeout = timeout
        self.token: str | None = None

    def _req(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Content-Type": "application/json"}
        if self.token:
            hdrs["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            payload, status = exc.read(), exc.code
        except Exception as exc:  # connection refused, timeout, DNS
            return 0, {"_transport_error": f"{type(exc).__name__}: {exc}"}, \
                (time.perf_counter() - started) * 1000
        ms = (time.perf_counter() - started) * 1000
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = {"_raw": payload[:400].decode(errors="replace")}
        return status, parsed, ms

    def login(self) -> None:
        status, body, _ = self._req("POST", "/api/v1/auth/login",
                                    {"username": self.username, "password": self.password})
        if status != 200 or not body or not body.get("token"):
            raise SystemExit(f"login failed: {status} {body}")
        self.token = body["token"]

    def call(self, method: str, path: str, body: dict | None = None):
        status, out, ms = self._req(method, path, body)
        if status == 401 and self.token:
            self.login()
            status, out, ms = self._req(method, path, body)
        return status, out, ms

    def get(self, path, body=None):
        return self.call("GET", path, body)

    def post(self, path, body=None):
        return self.call("POST", path, body)


def pick(obj, *names, default=None):
    """First present key — the drill must not break on a renamed field, it must
    report which field it could not find."""
    if isinstance(obj, dict):
        for n in names:
            if n in obj:
                return obj[n]
    return default


# ------------------------------------------------------------------ recorder


class Recorder:
    def __init__(self):
        self.checks: list[dict] = []
        self.notes: list[str] = []

    def check(self, cid: str, ok: bool, detail: str, **evidence) -> bool:
        self.checks.append({
            "id": cid,
            "status": "PASS" if ok else "FAIL",
            "detail": detail,
            **{k: v for k, v in evidence.items() if v is not None},
        })
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {cid}: {detail}", flush=True)
        return ok

    def note(self, text: str) -> None:
        self.notes.append(text)
        print(f"  [note] {text}", flush=True)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c["status"] == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c["status"] == "FAIL")


# -------------------------------------------------------------------- estate
# A synthetic-but-realistic authorized estate. The mainframe and IBM i members
# are adapted from this repository's own parser corpora
# (services/scanner/tests/accuracy/corpus_wave13_mainframe_defs.py,
# services/scanner/tests/unit/test_rpg_parser.py) so the drill exercises the
# real parsers rather than inventing syntax they do not read.

JAVA_WEAK = """package com.bank.pay;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class CardService {
    private static final byte[] PAN_KEY = "0123456789abcdef".getBytes();

    public byte[] encryptPan(byte[] pan) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(PAN_KEY, "DESede"));
        return cipher.doFinal(pan);
    }

    public byte[] pinDigest(byte[] pin) throws Exception {
        return MessageDigest.getInstance("MD5").digest(pin);
    }
}
"""

# The *driving* file for the remediation lifecycle. Remediation verification
# fingerprints a finding as (file_path, line_number, algorithm) — see
# services/remediation/remediation/verification.py:_fingerprint — so a variant
# that shifts line numbers invents phantom "new violations" and turns an honest
# fix into a REGRESSION. Every variant below therefore keeps the crypto call
# sites on lines 15, 16 and 22; PIN_VARIANT_LINE_COUNTS asserts it.
PIN_PATH = "src/main/java/com/bank/payments/PinBlockService.java"
WEAK_CIPHERS = {"3DES", "DES", "TRIPLE_DES", "DES3"}

PIN_BASE = '''package com.bank.payments;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** PIN block encryption for the ATM switching host (ZELIAC 2.13). */
public class PinBlockService {

    private static final byte[] KEK = {
        (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44,
        (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x88,
    };

    public byte[] encryptPin(byte[] pin) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEK, "DESede"));
        return cipher.doFinal(pin);
    }

    public byte[] mac(byte[] data) throws Exception {
        java.security.MessageDigest md =
            java.security.MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
'''

# The real fix: 3DES -> AES/GCM, the literal KEK deleted, MD5 -> SHA-256.
PIN_FIXED = '''package com.bank.payments;

import javax.crypto.Cipher;
import com.bank.vault.KeyProvider;

/** PIN block encryption for the ATM switching host (ZELIAC 2.13). */
public class PinBlockService {

    // the literal KEK is gone: keys and IVs come from the vault (ZELIAC 4.2)
    private final KeyProvider vault;

    public PinBlockService(KeyProvider vault) { this.vault = vault; }

    public byte[] encryptPin(byte[] pin) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, vault.key("PIN-KEK"), vault.gcmSpec());
        return cipher.doFinal(pin);
    }

    public byte[] mac(byte[] data) throws Exception {
        java.security.MessageDigest md =
            java.security.MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
'''

# The partial fix: the 3DES call moved into a shared library that is still 3DES
# underneath, so the original condition is gone from this file but the file is
# not compliant — verification must say PARTIAL, never VERIFIED.
PIN_PARTIAL = PIN_BASE.replace(
    '''        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEK, "DESede"));
        return cipher.doFinal(pin);''',
    '''        byte[] block = LegacyPinBlocks.format(pin);   // 3DES moved to the shared lib
        byte[] out = SharedCrypto.encrypt(block);      // still 3DES underneath
        return out;''')

# The reintroduction: a hotfix branch puts the weak cipher back at the same site
# after the fix was verified. A verified fix is not a permanent state.
PIN_REINTRODUCED = PIN_FIXED.replace(
    '''        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, vault.key("PIN-KEK"), vault.gcmSpec());''',
    '''        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, vault.key("PIN-KEK-LEGACY"));''')

# The regression: the driving file is genuinely fixed, but the same change set
# drops a NEW weak cipher into a NEW file. Verification compares the whole
# target, so this must read as REGRESSION and not as VERIFIED.
LEGACY_SIGNER_PATH = "src/main/java/com/bank/payments/LegacySigner.java"
LEGACY_SIGNER = '''package com.bank.payments;

/** Came back with the HOTFIX-4502 rollback: the old single-DES signer. */
public class LegacySigner {

    public byte[] sign(byte[] data) throws Exception {
        javax.crypto.Cipher c =
            javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
        return c.doFinal(data);
    }
}
'''

PIN_VARIANTS = {
    "base": PIN_BASE,
    "fixed": PIN_FIXED,
    "partial": PIN_PARTIAL,
    "reintroduced": PIN_REINTRODUCED,
}
PIN_VARIANT_LINE_COUNTS = {name: len(text.splitlines())
                           for name, text in PIN_VARIANTS.items()}


def assert_variants_are_line_stable() -> None:
    """Fail loudly if a variant would shift line numbers (see PIN_BASE)."""
    counts = set(PIN_VARIANT_LINE_COUNTS.values())
    if len(counts) != 1:
        raise SystemExit(
            f"drill bug: PIN variants are not line-count stable {PIN_VARIANT_LINE_COUNTS}; "
            "verification fingerprints include line_number, so a shift would invent "
            "phantom regressions")

TLS_CONF = """# payments-api ingress TLS policy
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers "RC4-SHA:DES-CBC3-SHA:AES128-SHA";
ssl_prefer_server_ciphers on;
"""

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.bank</groupId><artifactId>payments-api</artifactId><version>4.2.1</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk15on</artifactId><version>1.60</version>
    </dependency>
  </dependencies>
</project>
"""

SIGNER_PY = """import hashlib
from Crypto.Cipher import ARC4

SIGNING_KEY = "sup3r-s3cr3t-signing-key"


def fingerprint(blob: bytes) -> str:
    return hashlib.sha1(blob).hexdigest()


def scramble(blob: bytes) -> bytes:
    return ARC4.new(SIGNING_KEY).encrypt(blob)
"""

NSN_PWDCHK_MD5 = """/* PWDCHK - legacy password check: home-grown hash (MD5 via ICSF one-way hash)
DEFINE DATA PARAMETER
1 #USER (A8) 1 #PWD (A8) 1 #OK (L)
LOCAL
1 #RC (I4) 1 #RS (I4) 1 #EDL (I4) 1 #ED (A4)
1 #RA-COUNT (I4) INIT <1>
1 #RA (A8) INIT <'MD5     '>
1 #CHAIN (B128) 1 #CHAIN-LEN (I4) INIT <128>
1 #DIGEST (B16)
1 #STORED (B16)
END-DEFINE
CALL 'CSNBOWH' #RC #RS #EDL #ED #RA-COUNT #RA 8 #PWD #CHAIN-LEN #CHAIN 16 #DIGEST
IF #DIGEST = #STORED THEN #OK := TRUE END-IF
END
"""

NSN_PWDCHK_SHA1 = NSN_PWDCHK_MD5.replace("INIT <'MD5     '>", "INIT <'SHA-1   '>")
NSN_PWDCHK_SHA256 = NSN_PWDCHK_MD5.replace(
    "INIT <'MD5     '>", "INIT <'SHA-256 '>").replace(
    "home-grown hash (MD5 via ICSF one-way hash)",
    "password check via ICSF one-way hash (SHA-256)")

NSN_HASHSUB = """* HASHSUB - one-way hash of a statement image for the archive index
DEFINE DATA PARAMETER
1 #IMAGE        (A) DYNAMIC
1 #DIGEST       (B32)
LOCAL
1 #RC (I4) 1 #RS (I4) 1 #EDL (I4) 1 #ED (A4)
1 #RA-COUNT     (I4) INIT <2>
1 #RA           (A8/2) INIT <'SHA-256 ','ONLY    '>
1 #CHAIN-LEN    (I4) INIT <128>
1 #CHAIN        (B128)
END-DEFINE
CALL 'CSNBOWH' #RC #RS #EDL #ED #RA-COUNT #RA
     *LENGTH(#IMAGE) #IMAGE #CHAIN-LEN #CHAIN 32 #DIGEST
END
"""

NSN_PANENC = """* PANENC - encrypt the PAN at rest under an AES key label (ICSF symmetric)
DEFINE DATA LOCAL
1 #RC          (I4)
1 #REASON      (I4)
1 #EXIT-DATA-L (I4)
1 #EXIT-DATA   (A4)
1 #RULE-COUNT  (I4) INIT <3>
1 #RULE-ARRAY  (A8/3) INIT <'AES     ','CBC     ','KEYIDENT'>
1 #KEY-LABEL   (A64) INIT <'CARD.PAN.AESDATA.2024'>
1 #CLEAR-PAN   (A19)
1 #ENC-PAN     (B32)
END-DEFINE
CALL 'CSNBSYE' #RC #REASON #EXIT-DATA-L #EXIT-DATA
     #RULE-COUNT #RULE-ARRAY #KEY-LABEL ...
IF #RC NE 0
  WRITE 'CSNBSYE failed' #RC #REASON
  TERMINATE 8
END-IF
END
"""

RPG_3DES = """**free
// CLAIMS - encrypt the claim payload before it leaves the IBM i
dcl-ds algd0200 qualified;
  blockCipherAlg int(10) inz(21);   // 21 = 3DES
  mode           int(10) inz(1);    // CBC
end-ds;
dcl-pr Qc3EncryptData extproc('Qc3EncryptData');
  inputData    pointer value;  inputLen   int(10) value;
  inputFmt     char(8) const;  algDesc    pointer value;
  algFmt       char(8) const;  keyDesc    pointer value;
  keyFmt       char(8) const;  cryptoDev  char(10) const;
  cryptoProv   pointer value;  outputBuf  pointer value;
  outputLen    int(10) value;  bytesRtn   int(10);
  errCode      pointer value;
end-pr;
Qc3EncryptData(%addr(clear) : %len(clear) : 'DATA0100' : %addr(algd0200) :
               'ALGD0200' : %addr(key) : 'KEYD0200' : '0' : '' :
               %addr(cipher) : %size(cipher) : cipherLen : %addr(err));
"""

RPG_AES = RPG_3DES.replace("inz(21);   // 21 = 3DES", "inz(22);   // 22 = AES")

ILE_C = """#include <qc3cci.h>
#include <stdio.h>

int sign_claim(unsigned char *blob, unsigned long len, unsigned char *out) {
    Qc3_Des_Algorithm_Desc_t algDesc;
    algDesc.algorithm = Qc3_SHA1;                 /* legacy digest */
    Qc3CalculateHash(blob, &len, "DATA0100", &algDesc, "ALGD0500",
                     NULL, NULL, out, NULL);
    gsk_attribute_set_enum(env, GSK_PROTOCOL_TLSV12, GSK_TRUE);
    return 0;
}
"""

CLLE = """             PGM
             DCL VAR(&ENV) TYPE(*PTR)
             /* GSKit environment: TLS 1.2 only, keyring from the vault */
             CALL PGM(gsk_environment_open) PARM(&ENV)
             CALL PGM(gsk_attribute_set_enum) PARM(&ENV GSK_PROTOCOL_TLSV12 GSK_TRUE)
             CALL PGM(gsk_environment_init) PARM(&ENV)
             ENDPGM
"""

SYSTEMS = {
    "payments-api": {
        "description": "Card authorization and PAN vault API (Java 17, TLS terminating ingress)",
        "owner": "payments-engineering",
        "technical_owner": "m.iyer@bank.example",
        "security_owner": "s.duarte@bank.example",
        "environment": "production",
        "business_unit": "Retail Payments",
        "criticality": "critical",
        "compliance_scopes": ["PCI-DSS", "NIST SP 800-131A"],
        "files": {
            PIN_PATH: PIN_BASE,
            "src/main/java/com/bank/pay/CardService.java": JAVA_WEAK,
            "src/main/resources/tls.conf": TLS_CONF,
            "src/main/python/signer.py": SIGNER_PY,
            "pom.xml": POM,
        },
    },
    "mainframe-icsf": {
        "description": "z/OS ICSF callers: password check, statement archive hash, PAN at rest",
        "owner": "mainframe-platform",
        "technical_owner": "r.okonkwo@bank.example",
        "security_owner": "s.duarte@bank.example",
        "environment": "production",
        "business_unit": "Core Banking",
        "criticality": "critical",
        "compliance_scopes": ["PCI-DSS"],
        "files": {
            "natural/PWDCHK.NSN": NSN_PWDCHK_MD5,
            "natural/HASHSUB.NSN": NSN_HASHSUB,
            "natural/PANENC.NSN": NSN_PANENC,
        },
    },
    "claims-ibmi": {
        "description": "IBM i claims payload encryption (RPG IV Cryptographic Services APIs, GSKit TLS)",
        "owner": "insurance-platform",
        "technical_owner": "a.lindqvist@bank.example",
        "security_owner": "s.duarte@bank.example",
        "environment": "production",
        "business_unit": "Insurance",
        "criticality": "high",
        "compliance_scopes": ["ISO 27001"],
        "files": {
            "qrpglesrc/CLAIMS.rpgle": RPG_3DES,
            "qilec/paysig.c": ILE_C,
            "qcllesrc/CLAIMS.clle": CLLE,
        },
    },
}


def write_estate(root: Path) -> None:
    """(Re)create the estate exactly as it was at the start of a pass."""
    assert_variants_are_line_stable()
    if root.exists():
        shutil.rmtree(root)
    for name, spec in SYSTEMS.items():
        for rel, content in spec["files"].items():
            dest = root / name / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")


def set_pin_variant(root: Path, variant: str, regression_file: bool = False) -> None:
    """Apply one authorized change to the driving file (and, for the regression
    case, drop the new weak cipher into a NEW file so it cannot be mistaken for
    a shifted line number in the driving file)."""
    edit(root, "payments-api", PIN_PATH, PIN_VARIANTS[variant])
    edit(root, "payments-api", LEGACY_SIGNER_PATH,
         LEGACY_SIGNER if regression_file else None)


def condition_in(findings: list[dict], algorithms: set[str],
                 rel_path: str = PIN_PATH) -> list[dict]:
    """The evidence rows for one algorithm at one file — condition-level, not
    'somewhere in the target'."""
    return [f for f in findings
            if str(pick(f, "file_path", default="")).endswith(rel_path)
            and str(pick(f, "algorithm", default="")).upper() in algorithms]


def evidence_id_of(finding: dict | None) -> str | None:
    return pick(finding, "id", "evidence_id", "record_id") if finding else None


def coordinates(findings: list[dict]) -> set[tuple]:
    """The evidence fingerprint remediation verification compares on:
    (file_path, line_number, algorithm) — see
    services/remediation/remediation/verification.py:_fingerprint."""
    return {(str(pick(f, "file_path", default="")), int(pick(f, "line_number", default=0) or 0),
             str(pick(f, "algorithm", default="")).upper()) for f in findings}


def staging_paths(findings: list[dict]) -> list[str]:
    """Evidence coordinates that still carry the worker's staging directory."""
    return sorted({str(pick(f, "file_path", default="")) for f in findings
                   if "workspaces" in str(pick(f, "file_path", default=""))
                   or "job-" in str(pick(f, "file_path", default=""))
                   or str(pick(f, "file_path", default="")).startswith("/")})


def edit(root: Path, system: str, rel: str, content: str | None) -> None:
    """The 'authorized change': a real mutation of the estate on disk."""
    path = root / system / rel
    if content is None:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def empty_estate(root: Path, system: str) -> None:
    """Remove every source file — the rescan then produces no evidence, which is
    the INCONCLUSIVE case (a scan of nothing must not read as 'fixed')."""
    shutil.rmtree(root / system, ignore_errors=True)
    (root / system).mkdir(parents=True, exist_ok=True)
    (root / system / "README.txt").write_text(
        "sources moved to the archive volume pending migration\n", encoding="utf-8")


# --------------------------------------------------------------- chain steps


def register_systems(api: Api, rec: Recorder, root: Path) -> dict[str, dict]:
    """Step 1: the authorized estate — named systems with accountable owners."""
    out: dict[str, dict] = {}
    for name, spec in SYSTEMS.items():
        body = {
            "name": f"{name}-{int(time.time()) % 100000}",
            "description": spec["description"],
            "owner": spec["owner"],
            "technical_owner": spec["technical_owner"],
            "security_owner": spec["security_owner"],
            "environment": spec["environment"],
            "business_unit": spec["business_unit"],
            "criticality": spec["criticality"],
            "compliance_scopes": spec["compliance_scopes"],
            "scan_target": f"local://{root / name}",
            "scan_branch": "main",
        }
        status, res, _ms = api.post("/api/v1/systems", body)
        sid = pick(res, "id", "system_id")
        rec.check(f"system.register.{name}", status in (200, 201) and sid,
                  f"POST /systems -> {status}; id={sid}; owners "
                  f"{spec['technical_owner']} / {spec['security_owner']}",
                  http_status=status, system_id=sid)
        if sid:
            out[name] = {"id": sid, "name": body["name"], "target": body["scan_target"]}
    return out


def run_scan(api: Api, rec: Recorder, system: dict, label: str,
             timeout: float = 240.0) -> dict | None:
    """Step 2: scan the authorized target and wait for the terminal state."""
    status, res, _ms = api.post(f"/api/v1/systems/{system['id']}/scan")
    job_id = pick(res, "job_id")
    # 202 on POST /scans/trigger (declared status_code); 200 on
    # POST /systems/{id}/scan, which calls enqueue_scan_job without overriding it
    if not rec.check(f"scan.accept.{label}", status in (200, 202) and job_id,
                     f"POST /systems/{system['id'][:8]}/scan -> {status}; job={job_id}",
                     http_status=status, job_id=job_id):
        return None

    deadline = time.monotonic() + timeout
    state: dict = {}
    while time.monotonic() < deadline:
        st, job, _ms = api.get(f"/api/v1/jobs/{job_id}")
        state = job if isinstance(job, dict) else {}
        if str(pick(state, "status", default="")).upper() in TERMINAL:
            break
        time.sleep(1.0)

    job_status = str(pick(state, "status", default="UNKNOWN")).upper()
    scan_id = pick(state, "scan_id")
    rec.check(f"scan.completed.{label}", job_status == "COMPLETED" and scan_id,
              f"job {job_id[:8]} -> {job_status}; scan_id={scan_id}",
              http_status=st, job_status=job_status, scan_id=scan_id,
              error=pick(state, "error_message"))
    if not scan_id:
        return None
    return {"job_id": job_id, "scan_id": scan_id, "status": job_status}


def verify_chain(api: Api, rec: Recorder, scan_id: str, label: str) -> bool:
    """Step 3: the evidence chain must verify, or the scan proves nothing."""
    status, res, _ms = api.get(f"/api/v1/scans/{scan_id}/verify")
    overall = str(pick(res, "status", "overall", "result", default="")).upper()
    ok = status == 200 and overall in {"PASS", "VERIFIED", "OK", "TRUE"}
    return rec.check(f"evidence.verify.{label}", ok,
                     f"GET /scans/{scan_id[:8]}/verify -> {status}; {overall or res}",
                     http_status=status, verdict=overall or None,
                     manifest_hash=pick(res, "manifest_hash"))


def read_findings(api: Api, scan_id: str) -> list[dict]:
    status, res, _ms = api.get(f"/api/v1/findings?scan_id={scan_id}&page_size=200")
    if status != 200 or not isinstance(res, dict):
        return []
    return pick(res, "findings", "items", default=[]) or []


def approve_baseline(api: Api, rec: Recorder, scan_id: str, label: str) -> str | None:
    """Step 4: an approved baseline is what makes the next scan drift-aware."""
    status, res, _ms = api.post("/api/v1/baselines/approve",
                                {"scan_id": scan_id, "notes": f"operator-loop drill {label}",
                                 "environment": "production"})
    bid = pick(res, "baseline_id", "id")
    rec.check(f"baseline.approve.{label}", status in (200, 201) and bid,
              f"POST /baselines/approve -> {status}; baseline={bid}; "
              f"approved_by={pick(res, 'approved_by')}",
              http_status=status, baseline_id=bid)
    return bid


def read_drift(api: Api, rec: Recorder, label: str) -> list[dict]:
    status, res, _ms = api.get("/api/v1/drift?page_size=200")
    events = pick(res, "drift_events", "events", "items", "drifts", default=[]) or []
    rec.check(f"drift.list.{label}", status == 200,
              f"GET /drift -> {status}; {len(events)} event(s)",
              http_status=status, events=len(events))
    return events if isinstance(events, list) else []


def open_task(api: Api, rec: Recorder, evidence_id: str, owner: str, label: str,
              opened: list[str] | None = None) -> str | None:
    """Step 5: an owned task that snapshots the finding and its rule."""
    status, res, _ms = api.post("/api/v1/remediation/tasks",
                                {"evidence_id": evidence_id, "owner": owner,
                                 "notes": f"operator-loop drill {label}"})
    tid = pick(res, "id", "task_id")
    rule = pick(res, "rule_id", "rule")
    ok = status in (200, 201) and tid
    rec.check(f"task.create.{label}", ok,
              f"POST /remediation/tasks -> {status}; task={tid}; rule={rule}; "
              f"status={pick(res, 'status')}",
              http_status=status, task_id=tid, rule_id=rule)
    if not tid:
        return None
    if opened is not None:
        opened.append(str(tid))
    st2, res2, _ = api.post(f"/api/v1/remediation/tasks/{tid}/accept")
    rec.check(f"task.accept.{label}", st2 == 200 and pick(res2, "status") == "ACCEPTED",
              f"POST /tasks/{tid[:8]}/accept -> {st2}; status={pick(res2, 'status')}",
              http_status=st2)
    return tid


def complete_task(api: Api, rec: Recorder, task_id: str, rescan_id: str | None,
                  label: str, expect: str, notes: str) -> str | None:
    """Step 6: completing the task runs verification against the rescan."""
    status, res, _ms = api.post(f"/api/v1/remediation/tasks/{task_id}/complete",
                                {"rescan_id": rescan_id, "notes": notes})
    result = str(pick(res, "verification_result", "result", default="") or "").upper()
    if not result:
        ver = pick(res, "verification", "latest_verification", default={}) or {}
        result = str(pick(ver, "result", default="") or "").upper()
    task_status = str(pick(res, "status", default="") or "").upper()
    reason = pick(res, "verification_reason", "reason") or pick(
        pick(res, "verification", default={}) or {}, "reason")
    ok = status == 200 and result == expect
    rec.check(f"verification.{expect.lower()}.{label}", ok,
              f"complete -> {status}; result={result or 'NONE'} (expected {expect}); "
              f"task={task_status}; {str(reason)[:110]}",
              http_status=status, result=result or None, expected=expect,
              task_status=task_status or None, reason=str(reason)[:300] if reason else None)
    return result or None


def reverify_task(api: Api, rec: Recorder, task_id: str, rescan_id: str | None,
                  label: str, expect: set[str]) -> str | None:
    status, res, _ms = api.post(f"/api/v1/remediation/tasks/{task_id}/verify",
                                {"rescan_id": rescan_id})
    result = str(pick(res, "verification_result", "result", default="") or "").upper()
    if not result:
        ver = pick(res, "verification", "latest_verification", default={}) or {}
        result = str(pick(ver, "result", default="") or "").upper()
    task_status = str(pick(res, "status", default="") or "").upper()
    ok = status == 200 and result in expect
    rec.check(f"verification.reintroduced.{label}", ok,
              f"re-verify -> {status}; result={result or 'NONE'} "
              f"(expected one of {sorted(expect)}); task={task_status}",
              http_status=status, result=result or None, task_status=task_status or None)
    return result or None


def check_audit_trail(api: Api, rec: Recorder, label: str, task_ids: list[str]) -> None:
    """Step 6b: the audit journal must hold the transitions themselves.

    A task row says what the state IS; the journal says what happened, when, and
    on whose authority. Round 81 found five accepted and five completed tasks
    with ZERO ``remediation.task_created`` rows: ``POST /remediation/tasks``
    created the row on the request's session (which the FastAPI dependency
    commits) and then emitted on a *second* connection, so on SQLite — the
    documented single-box backend — the write waited out ``busy_timeout`` and was
    dropped with ``platform_event_persist_failed``. The drop is disclosed in the
    server log and invisible in the audit trail: the proposal step of the
    operator's own workflow was simply missing. The check is per task id so one
    dropped proposal cannot hide behind the events that did land.
    """
    if not task_ids:
        rec.note("no remediation tasks were opened this pass; nothing to audit")
        return
    status, res, _ms = api.get("/api/v1/events/recent?limit=500")
    events = pick(res, "events", default=[]) or []
    by_task: dict[str, set] = {tid: set() for tid in task_ids}
    for event in events:
        payload = pick(event, "payload", default={}) or {}
        tid = str(payload.get("task_id") or "")
        if tid in by_task:
            by_task[tid].add(str(pick(event, "type", default="")))
    created = "platform.remediation.task_created"
    missing = sorted(tid for tid, seen in by_task.items() if created not in seen)
    lifecycle = sorted({t for seen in by_task.values() for t in seen})
    gap = bool(pick(res, "replay_gap"))
    # replay_gap is disclosed, not asserted: the bus is an in-memory ring, so a
    # gap says old events aged out, not that this pass's journal is incomplete.
    rec.check(f"audit.trail.{label}",
              status == 200 and not missing,
              f"GET /events/recent -> {status}; {len(events)} journal event(s) read "
              f"(latest_id={pick(res, 'latest_id')}, replay_gap={gap}); {len(task_ids) - len(missing)}/{len(task_ids)} task(s) "
              f"opened this pass carry their proposal event; lifecycle recorded="
              f"{[t.replace('platform.remediation.', '') for t in lifecycle]}",
              http_status=status, tasks_missing_proposal=missing[:5],
              lifecycle=lifecycle, replay_gap=gap, journal_events=len(events),
              task_ids=task_ids)

    # The durable rows behind those events are NOT reachable through
    # GET /monitor/events: platform-scope events are written with target_id NULL
    # and that endpoint filters on target_id, so it returns zero rows even for a
    # platform admin. Recorded here rather than worked around silently.
    st_m, res_m, _ = api.get("/api/v1/monitor/events?limit=50")
    rows_m = pick(res_m, "events", default=[]) or []
    rec.note(f"GET /monitor/events -> {st_m} with {len(rows_m)} row(s): platform-scope "
             f"journal rows (target_id NULL — every remediation.task_* event) are "
             f"unreachable through that endpoint; the readable paths are /events/recent "
             f"and the SSE stream. Open defect, recorded in PRODUCT-VISION-AND-GAPS.md.")


def pin_report(api: Api, rec: Recorder, scan_id: str, label: str) -> None:
    """Step 7: the signed, content-addressed report for this exact scan."""
    # the template must be one the platform actually serves — ask, do not guess
    st_t, tpl, _ = api.get("/api/v1/report-templates")
    ids = [str(pick(t, "id")) for t in (pick(tpl, "templates", default=[]) or [])]
    template_id = "fips-140-3" if "fips-140-3" in ids else (ids[0] if ids else "")
    if not template_id:
        rec.check(f"report.pin.{label}", False,
                  f"GET /report-templates -> {st_t} with no usable template id; "
                  f"cannot pin a report without naming one",
                  http_status=st_t)
        return
    status, res, _ms = api.post(f"/api/v1/scans/{scan_id}/report-snapshot",
                                {"template_id": template_id})
    sid = pick(res, "id", "snapshot_id")
    phash = pick(res, "payload_hash")
    if not rec.check(f"report.pin.{label}", status in (200, 201) and sid and phash,
                     f"POST /scans/{scan_id[:8]}/report-snapshot "
                     f"{{template_id={template_id}}} -> {status}; snapshot={str(sid)[:8]}; "
                     f"payload_hash={str(phash)[:16]}; created={pick(res, 'created')}",
                     http_status=status, snapshot_id=sid, template_id=template_id):
        return
    st2, res2, _ = api.get(f"/api/v1/report-snapshots/{sid}")
    # GET returns the report payload with the stored row under "snapshot"
    row = res2.get("snapshot") if isinstance(res2, dict) else None
    row = row if isinstance(row, dict) else (res2 if isinstance(res2, dict) else {})
    integrity = str(pick(row, "integrity", default="") or "").upper()
    stored_hash = pick(row, "payload_hash")
    scan_row = res2.get("scan") if isinstance(res2, dict) else None
    pinned_scan = str((scan_row or {}).get("scan_id") or "") if isinstance(scan_row, dict) else ""
    rec.check(f"report.serve.{label}",
              st2 == 200 and integrity == "OK" and stored_hash == phash
              and pinned_scan == scan_id,
              f"GET /report-snapshots/{str(sid)[:8]} -> {st2}; integrity={integrity or 'n/a'} "
              f"(the recomputed SHA-256 over the stored payload equals the pinned hash="
              f"{stored_hash == phash}); template={template_id}; "
              f"pinned scan={pinned_scan[:8]} (the scan named in the request="
              f"{pinned_scan == scan_id})",
              http_status=st2, integrity=integrity or None, stored_payload_hash=stored_hash,
              pinned_scan_id=pinned_scan or None)


def coverage_of(api: Api, scan_id: str) -> dict:
    status, res, _ms = api.get(f"/api/v1/scans/{scan_id}/coverage")
    return res if status == 200 and isinstance(res, dict) else {}


# ------------------------------------------------------------------- passes


def run_pass(api: Api, rec: Recorder, root: Path, systems: dict, pass_no: int) -> None:
    label = f"p{pass_no}"
    print(f"\n=== pass {pass_no}: rebuild the estate, run the whole chain ===", flush=True)
    write_estate(root)

    tasks_opened: list[str] = []
    pay = systems["payments-api"]
    mf = systems["mainframe-icsf"]
    ibmi = systems["claims-ibmi"]

    # ---- 1. scan every system in the authorized estate
    scans: dict[str, dict] = {}
    for name, system in (("payments", pay), ("mainframe", mf), ("ibmi", ibmi)):
        got = run_scan(api, rec, system, f"{label}.{name}")
        if got:
            scans[name] = got

    if "payments" not in scans:
        rec.check(f"chain.{label}", False, "no scan completed for the primary system; "
                                          "the rest of the chain cannot run")
        return

    pay_scan = scans["payments"]["scan_id"]

    # ---- 2. evidence chain verifies, and the mainframe/IBM i legs produced evidence
    verify_chain(api, rec, pay_scan, f"{label}.payments")
    for name in ("mainframe", "ibmi"):
        if name in scans:
            findings = read_findings(api, scans[name]["scan_id"])
            rec.check(f"evidence.{name}.{label}", len(findings) > 0,
                      f"{name} scan produced {len(findings)} evidence record(s) — the "
                      f"{'Natural/ICSF' if name == 'mainframe' else 'RPG IV/ILE C/GSKit'} "
                      f"parsers participate in the loop",
                      findings=len(findings),
                      algorithms=sorted({str(pick(f, 'algorithm')) for f in findings})[:8])
            verify_chain(api, rec, scans[name]["scan_id"], f"{label}.{name}")

    findings = read_findings(api, pay_scan)
    algorithms = sorted({str(pick(f, "algorithm")) for f in findings})
    rec.check(f"findings.{label}", len(findings) > 0,
              f"payments-api scan produced {len(findings)} finding(s): {algorithms[:10]}",
              findings=len(findings), algorithms=algorithms)

    leaked = staging_paths(findings)
    rec.check(f"evidence.paths_target_relative.{label}", not leaked,
              f"all {len(findings)} evidence record(s) name their file in the TARGET's "
              f"coordinates ({len(leaked)} carried a worker staging path) — evidence "
              f"identity has to survive a rescan or verification invents regressions",
              staging_paths=leaked[:5])

    # The drill drives the remediation lifecycle from ONE named condition: the
    # 3DES PIN block in PinBlockService.java. Everything else in the target is
    # left untouched across the variants, so what verification compares is
    # attributable to the change the operator actually made.
    driving = condition_in(findings, WEAK_CIPHERS)
    evidence_id = evidence_id_of(driving[0] if driving else None)
    rec.check(f"target.finding.{label}", bool(evidence_id),
              f"driving condition: {pick(driving[0], 'algorithm') if driving else None} at "
              f"{PIN_PATH}:{pick(driving[0], 'line_number') if driving else '?'} "
              f"(evidence {str(evidence_id)[:8]}, {len(driving)} record(s) at that site)",
              evidence_id=evidence_id, records_at_site=len(driving))
    if not evidence_id:
        return

    # ---- 3. approve the baseline (first pass) / confirm it exists (later passes)
    if pass_no == 1:
        approve_baseline(api, rec, pay_scan, label)
    else:
        st, res, _ = api.get("/api/v1/baselines?page_size=50")
        # GET /baselines answers with a bare array of {baseline_id,
        # system_identifier, approved_scan_id, approved_by, status}
        rows = res if isinstance(res, list) else (pick(res, "baselines", "items",
                                                       default=[]) or [])
        active = [r for r in rows if str(pick(r, "status", default="")).upper() == "ACTIVE"]
        this_scan = str(scans["payments"]["scan_id"])
        carried = [r for r in active
                   if str(pick(r, "approved_scan_id", "scan_id", default="")) != this_scan]
        first = carried[0] if carried else (active[0] if active else {})
        rec.check(f"baseline.exists.{label}", st == 200 and bool(carried),
                  f"GET /baselines -> {st}; {len(rows)} row(s), {len(active)} ACTIVE, "
                  f"{len(carried)} approved against an EARLIER scan — the baseline "
                  f"survived the pass that created it "
                  f"({pick(first, 'system_identifier')} -> "
                  f"{str(pick(first, 'approved_scan_id', 'scan_id', default=''))[:8]}, "
                  f"approved_by={pick(first, 'approved_by')})",
                  http_status=st, baselines=len(rows), active=len(active),
                  carried_over=len(carried))

    owner = str(pick(pay, "owner") or SYSTEMS["payments-api"]["technical_owner"])

    # ---- 4. the VERIFIED case: a real fix, then a real rescan
    set_pin_variant(root, "fixed")
    task_verified = open_task(api, rec, evidence_id, owner, f"{label}.verified",
                                            opened=tasks_opened)
    rescan = run_scan(api, rec, pay, f"{label}.fix")
    if task_verified and rescan:
        complete_task(api, rec, task_verified, rescan["scan_id"], f"{label}.verified",
                      "VERIFIED",
                      "3DES/CBC PIN block replaced with AES/GCM, the literal KEK deleted "
                      "and the MD5 MAC moved to SHA-256")
        # condition-level proof, not target-level: the named site is clean
        after = read_findings(api, rescan["scan_id"])
        still = condition_in(after, WEAK_CIPHERS)
        rec.check(f"condition.gone.{label}", not still,
                  f"{PIN_PATH.rsplit('/', 1)[-1]} holds {len(still)} weak-cipher record(s) "
                  f"after the fix (the 3DES cipher string in tls.conf is a different "
                  f"condition and is not what this task names)",
                  remaining_at_site=len(still),
                  site_algorithms=[str(pick(f, "algorithm")) for f in condition_in(after, {"AES", "SHA2"})])

        # ---- 5. the REINTRODUCED case: a hotfix branch puts the weak cipher back
        set_pin_variant(root, "reintroduced")
        reintro = run_scan(api, rec, pay, f"{label}.reintroduced")
        if reintro:
            back = condition_in(read_findings(api, reintro["scan_id"]), WEAK_CIPHERS)
            rec.check(f"reintroduction.detected.{label}", len(back) > 0,
                      f"the reintroduced 3DES PIN block is observed again at the same site "
                      f"({len(back)} record(s)) — a verified fix is not a permanent state",
                      records=len(back),
                      lines=[pick(f, "line_number") for f in back])
            reverify_task(api, rec, task_verified, reintro["scan_id"], label,
                          {"REGRESSION", "FAILED", "PARTIAL"})

    # ---- 6. the FAILED case: complete a task with the code untouched
    set_pin_variant(root, "base")
    scan_untouched = run_scan(api, rec, pay, f"{label}.untouched")
    untouched = read_findings(api, scan_untouched["scan_id"]) if scan_untouched else []
    md5_id = evidence_id_of((condition_in(untouched, {"MD5"}) or [None])[0])
    if md5_id and scan_untouched:
        task_failed = open_task(api, rec, md5_id, owner, f"{label}.failed",
                                            opened=tasks_opened)
        if task_failed:
            complete_task(api, rec, task_failed, scan_untouched["scan_id"], f"{label}.failed",
                          "FAILED", "ticket raised and closed, no code change made")
            rec.note("the ticket-as-fix trap: the operator marks the task COMPLETED, the "
                     "platform refuses the credit because the condition is still in the "
                     "rescan evidence")
    else:
        rec.check(f"verification.failed.{label}", False,
                  f"no MD5 condition found at {PIN_PATH} in the untouched scan "
                  f"({len(untouched)} findings) — cannot provoke the FAILED outcome",
                  findings=len(untouched))

    # ---- 7. the PARTIAL case: the named condition leaves the file, but the file
    #         is still not compliant — verification must not read this as fixed
    pin_again = evidence_id_of((condition_in(untouched, WEAK_CIPHERS) or [None])[0])
    set_pin_variant(root, "partial")
    partial_scan = run_scan(api, rec, pay, f"{label}.partial")
    partial_findings = read_findings(api, partial_scan["scan_id"]) if partial_scan else []
    if pin_again and partial_scan:
        task_partial = open_task(api, rec, pin_again, owner, f"{label}.partial",
                                            opened=tasks_opened)
        if task_partial:
            complete_task(api, rec, task_partial, partial_scan["scan_id"], f"{label}.partial",
                          "PARTIAL",
                          "the 3DES call moved into a shared library that is still 3DES "
                          "underneath, and the file still hashes with MD5")
        rec.check(f"partial.state.{label}",
                  not condition_in(partial_findings, WEAK_CIPHERS)
                  and bool(condition_in(partial_findings, {"MD5"})),
                  f"after the partial change the named site holds "
                  f"{len(condition_in(partial_findings, WEAK_CIPHERS))} weak-cipher and "
                  f"{len(condition_in(partial_findings, {'MD5'}))} MD5 record(s) — the "
                  f"state PARTIAL describes",
                  weak=len(condition_in(partial_findings, WEAK_CIPHERS)),
                  md5=len(condition_in(partial_findings, {"MD5"})))
    else:
        rec.check(f"verification.partial.{label}", False,
                  "no 3DES evidence in the untouched scan to open the partial task from",
                  findings=len(untouched))

    # ---- 8. the REGRESSION case: the fix is genuine, and the same change set
    #         introduces a NEW weak cipher in a NEW file
    set_pin_variant(root, "base")
    reg_base = run_scan(api, rec, pay, f"{label}.regression-base")
    reg_base_findings = read_findings(api, reg_base["scan_id"]) if reg_base else []
    reg_evidence = evidence_id_of((condition_in(reg_base_findings, WEAK_CIPHERS) or [None])[0])
    reg_scan = None
    if reg_evidence and reg_base:
        task_reg = open_task(api, rec, reg_evidence, owner, f"{label}.regression",
                                            opened=tasks_opened)
        set_pin_variant(root, "fixed", regression_file=True)
        reg_scan = run_scan(api, rec, pay, f"{label}.regression")
        if task_reg and reg_scan:
            reg_findings = read_findings(api, reg_scan["scan_id"])
            introduced = condition_in(reg_findings, WEAK_CIPHERS, LEGACY_SIGNER_PATH)
            rec.check(f"regression.observed.{label}", len(introduced) > 0,
                      f"the change set fixed {PIN_PATH.rsplit('/', 1)[-1]} and dropped "
                      f"{len(introduced)} new weak-cipher record(s) into "
                      f"{LEGACY_SIGNER_PATH.rsplit('/', 1)[-1]}",
                      introduced=[f"{pick(f, 'algorithm')}:{pick(f, 'line_number')}"
                                  for f in introduced],
                      driving_file_clean=not condition_in(reg_findings, WEAK_CIPHERS))
            complete_task(api, rec, task_reg, reg_scan["scan_id"], f"{label}.regression",
                          "REGRESSION",
                          "AES/GCM landed on the PIN block, but the same change set "
                          "reintroduced single-DES in LegacySigner.java")
    else:
        rec.check(f"verification.regression.{label}", False,
                  "no 3DES evidence in the regression base scan to open the task from",
                  findings=len(reg_base_findings))

    # ---- 9. the INCONCLUSIVE case: a rescan that produced no evidence at all
    task_inc = None
    inc_findings: list[dict] = []
    set_pin_variant(root, "base")
    base_scan = run_scan(api, rec, pay, f"{label}.inconclusive-base")
    if base_scan:
        inc_findings = read_findings(api, base_scan["scan_id"])
        inc_id = evidence_id_of(inc_findings[0] if inc_findings else None)
        if inc_id:
            task_inc = open_task(api, rec, inc_id, owner, f"{label}.inconclusive",
                                            opened=tasks_opened)
    if reg_base and base_scan:
        # reg_base and base_scan are the SAME estate (PIN_BASE, no LegacySigner)
        # scanned under two different job ids. Their evidence coordinates must be
        # identical — this is the property that was broken when dependency
        # findings carried data/workspaces/job-<uuid>/repo/pom.xml.
        a, b = coordinates(reg_base_findings), coordinates(inc_findings)
        rec.check(f"identity.stable.{label}", bool(a) and a == b,
                  f"the same estate scanned under two job ids produced identical "
                  f"evidence coordinates ({len(a)} vs {len(b)}; "
                  f"{len(a ^ b)} differing) — a rescan can therefore be compared "
                  f"to its predecessor at all",
                  coordinates=len(a), differing=sorted(a ^ b)[:5])

    empty_estate(root, "payments-api")
    empty_scan = run_scan(api, rec, pay, f"{label}.inconclusive-empty")
    if task_inc and empty_scan:
        produced = read_findings(api, empty_scan["scan_id"])
        rec.check(f"rescan.empty.{label}", len(produced) == 0,
                  f"the emptied target produced {len(produced)} evidence record(s) — "
                  f"this is the rescan that must NOT read as 'fixed'",
                  findings=len(produced))
        complete_task(api, rec, task_inc, empty_scan["scan_id"], f"{label}.inconclusive",
                      "INCONCLUSIVE", "sources moved to the archive volume pending migration")
    write_estate(root)  # leave the estate whole for the next pass

    # ---- 9b. the audit journal: every transition above must be durable
    check_audit_trail(api, rec, label, tasks_opened)

    # ---- 10. drift and the report pin, on the last real scan
    final_scan = (reg_scan or partial_scan or scan_untouched or scans["payments"])
    read_drift(api, rec, label)
    pin_report(api, rec, final_scan["scan_id"], label)

    # ---- 11. coverage: the system row must say what the last scan observed
    cov = coverage_of(api, final_scan["scan_id"])
    if cov:
        rec.check(f"coverage.{label}", True,
                  f"GET /scans/{final_scan['scan_id'][:8]}/coverage -> "
                  f"{json.dumps({k: cov[k] for k in list(cov)[:5]})[:200]}")
    else:
        rec.note("coverage endpoint returned nothing for the final scan")

    # ---- 12. durable derived writes survived the run (round 80 regression guard)
    st, snap, _ = api.get(f"/api/v1/cbom/scan/{final_scan['scan_id']}/snapshots")
    rows = pick(snap, "snapshots", default=[]) or []
    pinned = [r for r in rows if pick(r, "generator") == "pipeline"]
    rec.check(f"durable.cbom_pin.{label}", st == 200 and len(pinned) >= 1,
              f"the scan's CBOM pin is durable: {len(pinned)} pipeline-generated "
              f"snapshot(s) of {len(rows)} (round 80: this was 0 on SQLite)",
              http_status=st, pipeline_pins=len(pinned))


# ------------------------------------------------------------------- artifact


def repo_state() -> dict:
    def git(*args):
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                                  timeout=30).stdout.strip()
        except Exception:
            return ""
    return {
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
    }


def write_artifact(out: Path, rec: Recorder, args, systems: dict, estate: Path) -> dict:
    verdict = "PASS" if rec.failed == 0 and rec.passed > 0 else "FAIL"
    artifact = {
        "schema": "cryptoscan.operator-loop-drill/1",
        "captured_at": NOW(),
        "repository": repo_state(),
        "command": " ".join(sys.argv),
        "environment": {
            "api": args.api,
            "passes": args.passes,
            "estate": str(estate),
            "queue": "inline (no REDIS_URL: the API runs the pipeline in-process)",
        },
        "systems": {k: {"id": v["id"], "target": v["target"]} for k, v in systems.items()},
        "checks": rec.checks,
        "summary": {
            "total": len(rec.checks),
            "passed": rec.passed,
            "failed": rec.failed,
        },
        "notes": rec.notes,
        "limitations": [
            "The estate is synthetic: built from this repository's own parser corpora "
            "(corpus_wave13_mainframe_defs.py, test_rpg_parser.py) plus hand-written "
            "Java/Python/TLS/Maven sources. It is corpus evidence, NOT customer "
            "validation - the same distinction the engineering gate applies to the "
            "COBOL/PL-I/RPG customer-sample checks.",
            "Runs against a single-node development deployment on SQLite with the "
            "pipeline executed inline in the API process. It does not exercise the "
            "Redis queue, a worker fleet, PostgreSQL, or Neo4j.",
            "Authorization is exercised as the bootstrap admin (auditor-gated routes "
            "accept an admin session outside production). A denied-actor traversal "
            "belongs to the frontend P1 row, not this drill.",
            "Notification dispatch is not asserted: no SMTP transport is wired, so "
            "email routing stays count-only.",
        ],
        "verdict": verdict,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    md = out.with_suffix(".md")
    lines = [
        "# Operator-loop drill — " + artifact["captured_at"],
        "",
        f"Verdict: **{verdict}** ({rec.passed} passed / {rec.failed} failed of "
        f"{len(rec.checks)} checks, {args.passes} pass(es))",
        "",
        f"- API: `{args.api}` (inline pipeline, no Redis)",
        f"- Estate: `{estate}` — {len(systems)} authorized systems",
        f"- Repository: `{artifact['repository']['commit'][:8]}` on "
        f"`{artifact['repository']['branch']}`"
        f"{' (dirty)' if artifact['repository']['dirty'] else ''}",
        f"- Command: `{artifact['command']}`",
        "",
        "## Checks",
        "",
        "| Status | Check | Detail |",
        "|---|---|---|",
    ]
    for c in rec.checks:
        detail = str(c["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {c['status']} | `{c['id']}` | {detail} |")
    lines += ["", "## Notes", ""]
    lines += [f"- {n}" for n in rec.notes] or ["- none"]
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {lim}" for lim in artifact["limitations"]]
    lines.append("")
    md.write_text("\n".join(lines), encoding="utf-8")
    return artifact


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", default="http://127.0.0.1:8010")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="cryptoscan")
    ap.add_argument("--estate", default="/tmp/cryptoscan-sources/operator-loop",
                    help="must be under an allow-listed source root")
    ap.add_argument("--passes", type=int, default=2,
                    help="the Done-when requires the chain to be executed twice")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "docs" / "readiness-evidence" /
                    f"operator-loop-drill-{datetime.now(timezone.utc):%Y-%m-%d}.json")
    ap.add_argument("--keep", action="store_true", help="leave the estate on disk")
    args = ap.parse_args()

    estate = Path(args.estate).resolve()
    api = Api(args.api, args.username, args.password)
    api.login()
    rec = Recorder()

    print(f"operator-loop drill: {args.api}, estate {estate}, {args.passes} passes", flush=True)
    write_estate(estate)
    systems = register_systems(api, rec, estate)
    if not systems:
        rec.check("estate.registered", False, "no system could be registered; aborting")
        artifact = write_artifact(args.out, rec, args, systems, estate)
        print(f"\nverdict: {artifact['verdict']} -> {args.out}")
        return 1

    for pass_no in range(1, args.passes + 1):
        run_pass(api, rec, estate, systems, pass_no)

    if not args.keep:
        shutil.rmtree(estate, ignore_errors=True)

    artifact = write_artifact(args.out, rec, args, systems, estate)
    print(f"\nverdict: {artifact['verdict']} "
          f"({rec.passed} passed / {rec.failed} failed) -> {args.out}")
    print(f"markdown twin: {args.out.with_suffix('.md')}")
    return 0 if artifact["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
