#!/usr/bin/env python3
"""Bank triage loop — the human review step that turns a pilot scan into measured accuracy.

    # 1. produce the review workbook for a repository
    python scripts/bank_triage.py workbook /path/to/repo -o triage/repo-A.json [--md triage/repo-A.md]

    # 2. reviewers fill the "verdict" field of every finding ("TP" | "FP") and of every
    #    candidate miss ("FN" | "OK"), optionally adding "expected": ["AES", ...]

    # 3. score the engagement and emit corpus skeletons for every confirmed FP/FN
    python scripts/bank_triage.py score triage/repo-A.json [--corpus-out triage/repo-A-cases.py]

The workbook has three parts:

* ``findings`` — every finding the production ``scan_file`` produced, one row per
  (file, line, algorithm), with the source line quoted so a reviewer can decide
  without opening the file.
* ``candidate_misses`` — files that scored **zero** findings but contain a crypto
  *signal*: an import of a known crypto library, an ICSF/CCA ``CSN*`` verb, a PKCS#11
  or HSM symbol, or a cipher name inside a string literal. This is the recall
  side of the loop: the scanner cannot see what it does not report, so the
  reviewer looks here for misses.
* ``unowned_extensions`` — extensions present in the estate for which no parser
  exists, ranked by line count. Anything large here is a coverage gap, not a bug.

Scores are per (file, algorithm family) exactly like ``accuracy_benchmark.py`` so
pilot numbers are comparable with the corpus numbers.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("services/scanner", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))
os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")

# Crypto *signals* — deliberately broader than the detector. False positives here only
# cost a reviewer a glance; the point is not to miss a file that uses crypto.
_SIGNALS: list[tuple[str, re.Pattern[str]]] = [
    ("jca-import", re.compile(r"^[ \t]*import\s+(?:javax\.crypto|java\.security\.(?!(?:Privileged|AccessControl|Permission|Principal|NoSuchAlgorithm|GeneralSecurity|Security\b|Provider\b|CodeSource|ProtectionDomain|SecureClassLoader|Policy|Guard|Identity|Timestamp|DomainCombiner|BasicPermission|UnrecoverableKey|InvalidKey|InvalidAlgorithm|Key\b|PublicKey|PrivateKey|KeyException|SignatureException|DigestException|InvalidParameter|cert\.CertificateException|AllPermission))|org\.bouncycastle|com\.nimbusds|io\.jsonwebtoken|org\.jose4j)", re.M)),
    ("dotnet-crypto", re.compile(r"\busing\s+System\.Security\.Cryptography\b|\bBouncyCastle\b|\bPkcs11Interop\b")),
    ("python-crypto", re.compile(r"^[ \t]*(?:from|import)\s+(?:cryptography|Crypto|Cryptodome|hashlib|hmac|ssl|nacl|jwt|jose|bcrypt|argon2|pkcs11|M2Crypto|OpenSSL|paramiko)\b", re.M)),
    ("node-crypto", re.compile(r"require\(\s*['\"](?:crypto|node:crypto|tls|https|jsonwebtoken|jose|bcrypt|argon2|node-forge|tweetnacl|sjcl|crypto-js|pkcs11js|graphene-pk11)['\"]|from\s+['\"](?:crypto|node:crypto|jose|node-forge|crypto-js|@peculiar/webcrypto)['\"]|\bwindow\.crypto\.subtle\b|\bcrypto\.subtle\b")),
    ("go-crypto", re.compile(r"^[ \t]*\"(?:crypto/[a-z0-9]+|golang\.org/x/crypto/[a-z0-9/]+|github\.com/miekg/pkcs11|github\.com/ThalesIgnite/crypto11)\"", re.M)),
    ("c-crypto", re.compile(r"#include\s*[<\"](?:openssl/[a-z0-9_]+\.h|gcrypt\.h|mbedtls/[a-z0-9_]+\.h|wolfssl/|sodium\.h|pkcs11\.h|cryptoki\.h|gskssl\.h|csfbext\.h|qc3[a-z]+\.h|bcrypt\.h|wincrypt\.h|ncrypt\.h)", re.I)),
    ("rust-crypto", re.compile(r"^[ \t]*use\s+(?:ring|openssl|rustls|aes|aes_gcm|chacha20poly1305|sha2|sha1|md5|hmac|rsa|ed25519_dalek|x25519_dalek|p256|pbkdf2|argon2|bcrypt|jsonwebtoken|cryptoki)::", re.M)),
    ("ruby-php-crypto", re.compile(r"\brequire\s+['\"](?:openssl|digest|bcrypt|jwt|rbnacl)['\"]|\bopenssl_(?:encrypt|decrypt|sign|verify|digest|pkey_new|random_pseudo_bytes)\s*\(|\bsodium_crypto_|\bpassword_hash\s*\(|\bhash_hmac\s*\(")),
    ("mainframe-icsf", re.compile(r"\bCSN[BEF][A-Z0-9]{2,5}\b|\bCSFP[A-Z0-9]{2,4}\b|\bICSF\b|\bCSFKEYS\b|\bRACDCERT\b|\bTTLS(?:Rule|Environment|Connection)Action\b|\bAT-TLS\b|\bKEYRING\b", re.I)),
    ("ibm-i", re.compile(r"\bQc3(?:Encrypt|Decrypt|CalculateHash|CalculateHMAC|GenKeyRecord|CreateKeyContext|CalculateSignature|VerifySignature)\w*|\bQC3[A-Z]{5,6}\b|\bgsk_(?:environment|secure_soc|attribute)_\w+")),
    ("hsm-payments", re.compile(r"\bpayShield\b|\bThales\b.*\bHSM\b|\bHSM\b.*\bcommand\b|\bSafeNet\b|\bLuna\b.*\bHSM\b|\bnCipher\b|\bnShield\b|\bAtalla\b|\bCKM_[A-Z0-9_]+\b|\bC_(?:Encrypt|Decrypt|Sign|Verify|GenerateKey|GenerateKeyPair|DeriveKey|WrapKey|Digest)Init\b|\bDUKPT\b|\bTR-?31\b|\bKCV\b|\bZPK\b|\bZMK\b|\bTMK\b|\bLMK\b|\bPIN\s*block\b|\bCVV\b.*\b(?:generate|verify|calc)", re.I)),
    ("cipher-literal", re.compile(r"[\"'](?:AES|DES|3DES|DESede|TripleDES|RSA|ECDSA|Ed25519|X25519|ChaCha20|Blowfish|RC4|RC2|SHA-?1|SHA-?256|SHA-?384|SHA-?512|SHA3-\d+|MD5|HMAC(?:SHA\d+)?|PBKDF2\w*|bcrypt|scrypt|argon2\w*|TLSv?1(?:\.[0-3])?|SSLv[23])(?:/[A-Za-z0-9/-]+)?[\"']")),
    ("tls-config", re.compile(r"\bssl_ciphers\b|\bssl_protocols\b|\bSSLCipherSuite\b|\bSSLProtocol\b|\btls_min_version\b|\bcipher_suites\b|\bciphersuites\b|\bMinVersion\s*:\s*tls\.|\bSslProtocols\.|\bTLS_[A-Z0-9_]+_WITH_[A-Z0-9_]+\b|\bECDHE-[A-Z0-9-]+\b", re.I)),
    ("keystore", re.compile(r"[\"'/=][\w.-]+\.(?:jks|p12|pfx|pem|crt|cer|kdb|bks)\b|\bKeyStore\.getInstance\b|\bX509Certificate2?\b|\bkeytool\b|\bopenssl\s+(?:req|x509|genrsa|ecparam|pkcs12|dgst|enc|rsa|s_client)\b", re.I)),
]
_SIGNAL_MAX_BYTES = 2_000_000


def _load_scanner():
    import logging

    import structlog

    logging.basicConfig(level=logging.ERROR)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    from scanner.core.constant_index import ConstantIndex
    from scanner.core.file_discovery import DEFAULT_SOURCE_EXTENSIONS as SUPPORTED_EXTENSIONS, FileDiscovery
    from scanner.registry.language_scanners import scan_file

    return FileDiscovery, SUPPORTED_EXTENSIONS, scan_file, ConstantIndex


def _signals(text: str) -> list[tuple[str, int, str]]:
    out = []
    for name, rx in _SIGNALS:
        m = rx.search(text)
        if m:
            line_no = text.count("\n", 0, m.start()) + 1
            line = text.split("\n")[line_no - 1].strip()
            out.append((name, line_no, line[:160]))
    return out


def _all_files(root: Path):
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target", ".idea", ".gradle"}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip]
        for fn in fns:
            yield Path(dp) / fn


def cmd_workbook(args: argparse.Namespace) -> int:
    FileDiscovery, supported, scan_file, ConstantIndex = _load_scanner()
    root = Path(args.repo).resolve()
    files = list(FileDiscovery().discover(root))
    findings = []
    crashes = []
    for f in files:
        try:
            findings.extend(scan_file(f, root))
        except Exception as exc:  # noqa: BLE001 — a crash is a triage row, not a stop
            crashes.append({"file": str(f.relative_to(root)), "error": repr(exc)[:200]})
    ConstantIndex.build(files).resolve(findings)
    scanned_rel = {str(f.relative_to(root)) for f in files}
    files_with = collections.defaultdict(list)
    for x in findings:
        if (x.crypto.algorithm or "UNKNOWN").upper() == "UNKNOWN":
            continue
        files_with[x.source.file_path].append(x)

    rows = []
    line_cache: dict[str, list[str]] = {}
    for rel, fs in sorted(files_with.items()):
        if rel not in line_cache:
            try:
                line_cache[rel] = (root / rel).read_text(encoding="utf-8", errors="replace").split("\n")
            except OSError:
                line_cache[rel] = []
        seen = set()
        for x in sorted(fs, key=lambda y: (y.source.line_number, y.crypto.algorithm or "")):
            key = (x.source.line_number, x.crypto.algorithm)
            if key in seen:
                continue
            seen.add(key)
            ln = x.source.line_number
            src = line_cache[rel][ln - 1].strip() if 0 < ln <= len(line_cache[rel]) else ""
            rows.append({
                "file": rel, "line": ln, "algorithm": x.crypto.algorithm, "api_type": x.crypto.api_type,
                "confidence": x.metadata.confidence, "reason": x.metadata.confidence_reason, "library": x.metadata.library,
                "code_origin": x.metadata.code_origin, "source_line": src[:200], "verdict": "",
            })

    # Recall side: signal-bearing files that produced nothing.
    misses = []
    unowned = collections.Counter()
    unowned_lines = collections.Counter()
    for f in _all_files(root):
        rel = str(f.relative_to(root))
        ext = f.suffix.lower()
        try:
            if f.stat().st_size > _SIGNAL_MAX_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\0" in text[:4096]:
            continue
        if rel not in scanned_rel:
            unowned[ext or "(none)"] += 1
            unowned_lines[ext or "(none)"] += text.count("\n")
        if rel in files_with:
            continue
        sig = _signals(text)
        if sig:
            misses.append({"file": rel, "scanned": rel in scanned_rel, "signals": [{"kind": k, "line": n, "text": t} for k, n, t in sig],
                           "verdict": "", "expected": []})

    unowned_rows = [{"ext": e, "files": unowned[e], "lines": unowned_lines[e]} for e in unowned]
    unowned_rows.sort(key=lambda r: -r["lines"])
    wb = {
        "repo": str(root), "files_scanned": len(files), "files_total": len(scanned_rel) + sum(unowned.values()),
        "findings": rows, "candidate_misses": misses, "unowned_extensions": unowned_rows[:40], "crashes": crashes,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(wb, indent=1))
    if args.md:
        Path(args.md).write_text(_markdown(wb))
    print(f"files_scanned={len(files)} findings={len(rows)} files_with_findings={len(files_with)} "
          f"candidate_misses={len(misses)} unowned_ext={len(unowned_rows)} crashes={len(crashes)} -> {out}")
    return 0


def _cell(text: str, n: int) -> str:
    return text[:n].replace("|", "\\|")


def _markdown(wb: dict) -> str:
    L = [f"# Triage workbook — `{wb['repo']}`", "",
         f"files scanned {wb['files_scanned']} / present {wb['files_total']} · findings {len(wb['findings'])} · candidate misses {len(wb['candidate_misses'])}", "",
         "## Findings (mark TP / FP)", "", "| # | file:line | algorithm | api | conf | source line | verdict |", "|---|---|---|---|---|---|---|"]
    for i, r in enumerate(wb["findings"], 1):
        L.append(f"| {i} | `{r['file']}:{r['line']}` | {r['algorithm']} | {r['api_type']} | {r['confidence']} | `{_cell(r['source_line'], 90)}` | |")
    L += ["", "## Candidate misses — files with a crypto signal and zero findings (mark FN / OK)", "", "| file | signal | line | text | verdict |", "|---|---|---|---|---|"]
    for m in wb["candidate_misses"]:
        s = m["signals"][0]
        L.append(f"| `{m['file']}`{'' if m['scanned'] else ' (no parser)'} | {s['kind']} (+{len(m['signals']) - 1}) | {s['line']} | `{_cell(s['text'], 80)}` | |")
    L += ["", "## Extensions without a parser", "", "| ext | files | lines |", "|---|---|---|"]
    for u in wb["unowned_extensions"][:25]:
        L.append(f"| `{u['ext']}` | {u['files']} | {u['lines']} |")
    if wb["crashes"]:
        L += ["", "## Parser crashes", ""] + [f"- `{c['file']}` — {c['error']}" for c in wb["crashes"]]
    return "\n".join(L) + "\n"


def _score_shared(wb: dict, args: argparse.Namespace):
    """Score with the shared field-accuracy model (same code the API runs) and optionally write the TriageResult."""
    sys.path.insert(0, str(ROOT / "shared" / "shared_models"))
    from shared_models.field_accuracy import score_workbook

    result = score_workbook(wb, reviewer=getattr(args, "reviewer", None), notes=getattr(args, "notes", None))
    if getattr(args, "json_out", None):
        Path(args.json_out).write_text(result.model_dump_json(indent=2))
        print(f"wrote scored TriageResult -> {args.json_out}  (publish: bank_triage.py publish {args.json_out} --scan-id <id> --api <url>)")
    if result.by_language:
        print("per language: " + ", ".join(f"{l.language} P={l.precision:.2f} R={l.recall:.2f} (n={l.tp + l.fp + l.fn})" for l in result.by_language))
    return result


def cmd_publish(args: argparse.Namespace) -> int:
    """POST a scored TriageResult (or a reviewed workbook) to the API: it lands on the scan and in GET /accuracy/field."""
    import urllib.request

    body = json.loads(Path(args.result).read_text())
    if "findings" in body and "tp" not in body:  # raw workbook → let the server score it
        body = {"workbook": body, "reviewer": args.reviewer, "notes": args.notes}
    req = urllib.request.Request(f"{args.api.rstrip('/')}/api/v1/scans/{args.scan_id}/triage", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"X-API-Key": args.api_key} if args.api_key else {}),
                                          **({"Authorization": f"Bearer {args.token}"} if args.token else {})})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 — operator-supplied URL
        out = json.loads(resp.read())
    print(f"published: precision={out['precision']:.3f} recall={out['recall']:.3f} f1={out['f1']:.3f} on scan {args.scan_id}")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    wb = json.loads(Path(args.workbook).read_text())
    _score_shared(wb, args)
    per_file_tp = collections.defaultdict(set)
    per_file_fp = collections.defaultdict(set)
    unreviewed = 0
    for r in wb["findings"]:
        v = (r.get("verdict") or "").upper()
        if v == "TP":
            per_file_tp[r["file"]].add(r["algorithm"])
        elif v == "FP":
            per_file_fp[r["file"]].add(r["algorithm"])
        else:
            unreviewed += 1
    fn_files = {}
    for m in wb["candidate_misses"]:
        v = (m.get("verdict") or "").upper()
        if v == "FN":
            fn_files[m["file"]] = set(m.get("expected") or ["UNKNOWN"])
        elif v not in ("OK", "FN"):
            unreviewed += 1
    tp = sum(len(v) for v in per_file_tp.values())
    fp = sum(len(v - per_file_tp[k]) for k, v in per_file_fp.items())
    fn = sum(len(v) for v in fn_files.values())
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"reviewed: TP={tp} FP={fp} FN={fn} (unreviewed rows={unreviewed})")
    print(f"precision={prec:.3f} recall={rec:.3f} f1={f1:.3f}   (per file × algorithm family, same unit as the corpus benchmark)")
    if args.corpus_out:
        cases = []
        for k, v in per_file_fp.items():
            cases.append(_case_skeleton(wb["repo"], k, per_file_tp[k], note=f"FP on {sorted(v - per_file_tp[k])}"))
        for k, v in fn_files.items():
            cases.append(_case_skeleton(wb["repo"], k, v | per_file_tp[k], note="FN"))
        Path(args.corpus_out).write_text(
            '"""Corpus skeletons from a bank triage — redact, then paste into a corpus_waveNN file."""\n\n'
            "def build():\n    _c = None  # bind to the corpus helper\n" + "".join(cases))
        print(f"wrote {len(cases)} corpus skeletons -> {args.corpus_out}")
    return 0


def _case_skeleton(repo: str, rel: str, expected: set[str], note: str) -> str:
    try:
        body = (Path(repo) / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        body = ""
    ext = Path(rel).suffix.lstrip(".") or "txt"
    body = body[:4000].replace('"""', "'''")
    return (f"    # {note}: {rel}\n    _c({ext!r}, {Path(rel).name!r}, \"\"\"\n{body}\n\"\"\", {sorted(expected)!r})\n\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("workbook", help="scan a repo and write the review workbook")
    w.add_argument("repo")
    w.add_argument("-o", "--output", required=True)
    w.add_argument("--md")
    w.set_defaults(fn=cmd_workbook)
    s = sub.add_parser("score", help="score a reviewed workbook")
    s.add_argument("workbook")
    s.add_argument("--corpus-out")
    s.add_argument("--json-out", help="write the scored TriageResult (for `publish`)")
    s.add_argument("--reviewer", help="team / role that signed off the review")
    s.add_argument("--notes")
    pb = sub.add_parser("publish", help="POST a scored result (or reviewed workbook) to the API → GET /api/v1/accuracy/field")
    pb.add_argument("result")
    pb.add_argument("--scan-id", required=True, help="the pipeline scan of the same repository")
    pb.add_argument("--api", required=True, help="e.g. https://cryptoscan.bank.internal")
    pb.add_argument("--api-key")
    pb.add_argument("--token")
    pb.add_argument("--reviewer")
    pb.add_argument("--notes")
    pb.set_defaults(fn=cmd_publish)
    s.set_defaults(fn=cmd_score)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
