#!/usr/bin/env python3
"""Detection-accuracy benchmark for the production source scanner.

Materialises the hard ground-truth corpus (services/scanner/tests/accuracy/
corpus.py) into a temporary tree, scans every file with the same
``scan_file`` the worker uses, and scores the result **per algorithm family
per file**:

    TP  expected family reported            FN  expected family missing
    FP  reported family not expected        TN  negative file, nothing reported

Precision, recall, F1 and accuracy are reported overall, per language and per
category (positive / negative / obfuscated / config), together with every
miss so a regression is a named file, not a percentage.

    python scripts/accuracy_benchmark.py                 # print table
    python scripts/accuracy_benchmark.py --json out.json --md docs/accuracy/REPORT.md
    python scripts/accuracy_benchmark.py --min-f1 0.95   # exit 1 below the bar

No network, no database; runs in a few seconds.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in ("services/scanner", "services/scanner/tests", "shared/shared_models", "shared/shared_config", "shared/shared_logging"):
    sys.path.insert(0, str(ROOT / p))

os.environ.setdefault("CRYPTOSCAN_LOG_LEVEL", "warning")

from accuracy.corpus import CASES, canonical_families, spec_families, summary  # noqa: E402


def _quiet_logging() -> None:
    try:
        import logging
        import structlog

        logging.basicConfig(level=logging.WARNING)
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    except Exception:  # pragma: no cover
        pass


def run() -> dict:
    _quiet_logging()
    from scanner.registry.language_scanners import scan_file

    per_case = []
    with tempfile.TemporaryDirectory(prefix="cryptoscan-accuracy-") as tmp:
        root = Path(tmp)
        for lang, fname, code, expected, category in CASES:
            path = root / lang / fname
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(code, encoding="utf-8")
            try:
                findings = scan_file(path, root)
            except Exception as exc:  # a crash is a miss, never a pass
                findings, crash = [], repr(exc)
            else:
                crash = None
            predicted: set[str] = set()
            unknown = 0
            for f in findings:
                fams = canonical_families(f.crypto.algorithm)
                if not fams:
                    unknown += 1
                predicted.update(fams)
                if (f.source.language or "").upper() in {"JAVA", "KOTLIN", "SCALA"}:
                    # JCA transformation strings are algorithm specs by construction
                    predicted.update(spec_families(f.crypto.raw_transformation))
            tp = sorted(expected & predicted)
            fn = sorted(expected - predicted)
            fp = sorted(predicted - expected)
            tn = 1 if not expected and not predicted else 0
            per_case.append({
                "language": lang, "file": fname, "category": category,
                "expected": sorted(expected), "predicted": sorted(predicted),
                "tp": tp, "fn": fn, "fp": fp, "tn": tn, "unknown": unknown, "crash": crash,
            })

    def metrics(rows):
        tp = sum(len(r["tp"]) for r in rows)
        fn = sum(len(r["fn"]) for r in rows)
        fp = sum(len(r["fp"]) for r in rows)
        tn = sum(r["tn"] for r in rows)
        prec = tp / (tp + fp) if tp + fp else 1.0
        rec = tp / (tp + fn) if tp + fn else 1.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        acc = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 1.0
        clean_files = sum(1 for r in rows if not r["fn"] and not r["fp"])
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 4), "recall": round(rec, 4),
                "f1": round(f1, 4), "accuracy": round(acc, 4), "files": len(rows), "files_exact": clean_files,
                "file_exact_rate": round(clean_files / len(rows), 4) if rows else 1.0}

    by_lang = defaultdict(list)
    by_cat = defaultdict(list)
    for r in per_case:
        by_lang[r["language"]].append(r)
        by_cat[r["category"]].append(r)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus": summary(),
        "overall": metrics(per_case),
        "by_language": {k: metrics(v) for k, v in sorted(by_lang.items())},
        "by_category": {k: metrics(v) for k, v in sorted(by_cat.items())},
        "misses": [r for r in per_case if r["fn"] or r["fp"] or r["crash"]],
        "cases": per_case,
    }


# Blind first-pass scores recorded when each wave was added (never edited afterwards).
FIRST_PASS_HISTORY = [
    {"wave": "1 — baseline corpus (199 files) on the pre-existing parsers", "files": 199, "precision": None, "recall": None, "f1": 0.660, "after": "F1 1.000 (199/199 exact); first pass was 106/199 exact"},
    {"wave": "2 — real-world idioms: frameworks, kill-switches, cipher strings, PRNG-for-tokens, config", "files": 91, "precision": 0.968, "recall": 0.899, "f1": 0.932, "after": "F1 1.000 (290/290)"},
    {"wave": "3 — platform/mobile/infra: CommonCrypto & ObjC, Scala, Django/Flask settings, k8s/CloudFormation/Azure/DB configs, gradle.kts", "files": 58, "precision": 0.994, "recall": 0.912, "f1": 0.951, "after": "F1 1.000 (348/348)"},
    {"wave": "4 — in-the-wild excerpts from 20 real projects (Django, curl, Laravel, jjwt, caddy, ...; generated by scripts/build_wild_corpus.py). Note: the parsers had already been tuned on the *full* projects (docs/accuracy/EXTERNAL-VALIDATION.md), so this pass is not blind — the 4 misses were Python fragments that do not parse (now regex fallback), an OpenSSL cipher-name table, and a Rust ecdsa:: module path", "files": 38, "precision": 1.000, "recall": 0.932, "f1": 0.965, "after": "F1 1.000 (386/386)"},
    {"wave": "5 — provisioning shell / Dockerfile / Makefile, Swift (CryptoKit, CommonCrypto, Security.framework, CryptoSwift, sodium, JWTKit, Alamofire), ATS plists, pg_hba/MySQL auth. Not blind: the shell and Swift parsers were written in the same session. 23 of 64 files were not exact on the first pass — 16 of those were corpus label-spelling slips (TLS1.0/TRUST-ALL/CSPRNG written instead of the TLS/RNG families) and 7 were real detector gaps: upper-case mkpasswd/gpg algorithm names, `\"$OPENSSL_BIN\"` with no prefix, `.rsaEncryptionOAEPSHA256AESGCM`, CryptoSwift `.sha2(.sha256)` variants, MySQL require_secure_transport", "files": 64, "precision": 0.979, "recall": 0.958, "f1": 0.968, "after": "F1 1.000 (450/450)"},
    {"wave": "6 — XML configuration: web.config/WCF/ADO.NET, Spring Security XML, Android network security, Tomcat/WildFly, JDBC URLs, pom/NuGet crypto deps, SAML/XML-DSig URIs. Not blind (parser written alongside). The single first-pass miss: Tomcat `ciphers=` list was not expanded per algorithm because the rule exposed the whole tag as raw text (new `raw_group` engine key)", "files": 20, "precision": 1.000, "recall": 0.992, "f1": 0.996, "after": "F1 1.000 (470/470)"},
    {"wave": "7 — BLIND: Android Keystore, javax.crypto specs, .NET ECDiffieHellman/IncrementalHash, PHP sodium_*, RbNaCl/ActiveSupport, Rust openssl::symm, sodium-native/tweetnacl, Go x/crypto/ssh+nacl, pyca AESGCMSIV/X25519/PSS, paramiko, plus 8 hostile negatives. Labels frozen in commit before the first run. First pass 41/45 exact: KeyAgreement \"XDH\" leaked as a raw name, ECCurve inside ECDiffieHellman.Create reported as ECDSA, IncrementalHash.CreateHMAC missed, password_hash(…, PASSWORD_ARGON2ID) also emitted the BCRYPT default", "files": 45, "precision": 0.996, "recall": 0.999, "f1": 0.998, "after": "F1 1.000 (513/513)"},
    {"wave": "8 — BLIND, bank/payments realism: jPOS SMAdapter (PIN translate/verify, CVV, ARQC/ARPC, DUKPT, TR-31 import, retail MAC, KCV), Thales payShield adapter + LMK, PKCS#11 providers (SunPKCS11, IAIK CKM_*, Luna, CloudHSM, IBMJCECCA), SWIFT LAU, 3-D Secure CAVV/JWS, FF1 FPE, plus 6 payment-domain negatives (Luhn, PAN masking, ISO 8583 field 52/64, key-value store, Base64, settlement). Labels frozen before the first run. First pass 25/31 exact: KeyScheme.R (TR-31 key block) not mapped, `(SecureDESKey) ks.getKey(...)` cast, `translatePin(` verb, `zpkUnderLMK` camel-case suffix, CKM_AES_CBC_PAD/CKM_DES3_ECB not in the algo_map (rewritten as per-family rules), FPEFF1Engine", "files": 31, "precision": 1.000, "recall": 0.992, "f1": 0.996, "after": "F1 1.000 (544/544)"},
    {"wave": "9 — database + mainframe: Oracle PL/SQL (DBMS_CRYPTO, OBFUSCATION_TOOLKIT, TDE, DBMS_RANDOM), T-SQL (HASHBYTES, symmetric/asymmetric keys, Always Encrypted, TDE, ENCRYPTBYPASSPHRASE), pgcrypto, MySQL, DB2, COBOL/ICSF (CSNB PIN/CVV/MAC/OWH/HMG/KGN, CSND RSA/ECC, CSFP PKCS#11, RACF KDFAES, JCL). Not blind (parsers written alongside; labels written before the first run). First pass 588/594: secret-context PRNG rules only looked *after* the call (gen_otp / reset_tokens context on an earlier line → new `line_group` engine key), COBOL `FUNCTION RANDOM` context too narrow, `'ECDSA   '` padded literal, RACF `ALGORITHM(KDFAES)` also fired the DES rule, and one label-convention slip (scram-sha-256 → SHA-256)", "files": 50, "precision": 0.997, "recall": 0.995, "f1": 0.996, "after": "F1 1.000 (594/594)"},
]


def render_md(rep: dict) -> str:
    o = rep["overall"]
    lines = [
        "# Detection accuracy — production source scanner",
        "",
        f"_Generated {rep['generated_at']} by `scripts/accuracy_benchmark.py` against the hard ground-truth corpus "
        f"(`services/scanner/tests/accuracy/corpus.py`, {rep['corpus']['total']} files). Scored per algorithm family per file._",
        "",
        "## Overall",
        "",
        "| Metric | Value |", "|---|---|",
        f"| Precision | **{o['precision']:.1%}** |",
        f"| Recall | **{o['recall']:.1%}** |",
        f"| F1 | **{o['f1']:.1%}** |",
        f"| Accuracy (TP+TN over all decisions) | **{o['accuracy']:.1%}** |",
        f"| Files scored exactly right | {o['files_exact']} / {o['files']} ({o['file_exact_rate']:.1%}) |",
        f"| TP / FP / FN / TN | {o['tp']} / {o['fp']} / {o['fn']} / {o['tn']} |",
        "",
        "## By language",
        "",
        "| Language | Files | Precision | Recall | F1 | Exact files |", "|---|---|---|---|---|---|",
    ]
    for k, m in rep["by_language"].items():
        lines.append(f"| {k} | {m['files']} | {m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.1%} | {m['files_exact']}/{m['files']} |")
    lines += ["", "## By category", "", "| Category | Files | Precision | Recall | F1 | Exact files |", "|---|---|---|---|---|---|"]
    for k, m in rep["by_category"].items():
        lines.append(f"| {k} | {m['files']} | {m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.1%} | {m['files_exact']}/{m['files']} |")
    lines += ["", "## Misses", ""]
    if not rep["misses"]:
        lines.append("None — every file in the corpus was scored exactly.")
    else:
        lines += ["| File | Category | Expected | Predicted | Missed (FN) | Spurious (FP) |", "|---|---|---|---|---|---|"]
        for r in rep["misses"]:
            lines.append(f"| `{r['language']}/{r['file']}` | {r['category']} | {', '.join(r['expected']) or '—'} | {', '.join(r['predicted']) or '—'} | {', '.join(r['fn']) or '—'} | {', '.join(r['fp']) or '—'}{' · CRASH' if r['crash'] else ''} |")
    lines += [
        "",
        "## Held-out first-pass history",
        "",
        "Each corpus wave is written blind (labels from the code, before any rule is touched) and scored once *before* fixes.",
        "That first-pass number is the honest estimate of accuracy on unseen code; the table above is the score after the",
        "misses were fixed and locked in as regression tests.",
        "",
        "| Wave | Files added | First-pass P / R / F1 | After fixes |",
        "|---|---|---|---|",
    ]
    for w in FIRST_PASS_HISTORY:
        fmt = lambda v: "—" if v is None else f"{v:.3f}"  # noqa: E731
        lines.append(f"| {w['wave']} | {w['files']} | {fmt(w['precision'])} / {fmt(w['recall'])} / {fmt(w['f1'])} | {w['after']} |")
    lines += [
        "",
        "## How to read this",
        "",
        "- **Precision** — of the algorithm families the scanner reported, how many were really there. Low precision = noise.",
        "- **Recall** — of the algorithm families really present, how many the scanner found. Low recall = blind spots.",
        "- Labels are written by hand from the code, never copied from scanner output; a scanner change that flips a label is a corpus bug and is reviewed as such.",
        "- The negative set is deliberately hostile: `md5sum` paths, `description`/`shader`/`desired` identifiers, CRC32/base64/UUID, git SHAs, hash maps, comments quoting crypto APIs.",
        "- Regenerate: `python scripts/accuracy_benchmark.py --md docs/accuracy/REPORT.md --json docs/accuracy/report.json`.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", help="write full JSON report here")
    ap.add_argument("--md", help="write Markdown report here")
    ap.add_argument("--min-f1", type=float, default=None, help="exit 1 if overall F1 is below this")
    ap.add_argument("--min-recall", type=float, default=None)
    ap.add_argument("--min-precision", type=float, default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    rep = run()
    o = rep["overall"]
    if not args.quiet:
        print(f"corpus: {rep['corpus']}")
        print(f"{'language':12s} {'files':>5s} {'prec':>7s} {'rec':>7s} {'f1':>7s} {'exact':>7s}")
        for k, m in rep["by_language"].items():
            print(f"{k:12s} {m['files']:5d} {m['precision']:7.3f} {m['recall']:7.3f} {m['f1']:7.3f} {m['files_exact']:3d}/{m['files']:<3d}")
        print("-" * 52)
        for k, m in rep["by_category"].items():
            print(f"{k:12s} {m['files']:5d} {m['precision']:7.3f} {m['recall']:7.3f} {m['f1']:7.3f} {m['files_exact']:3d}/{m['files']:<3d}")
        print("-" * 52)
        print(f"{'OVERALL':12s} {o['files']:5d} {o['precision']:7.3f} {o['recall']:7.3f} {o['f1']:7.3f} {o['files_exact']:3d}/{o['files']:<3d}")
        if rep["misses"]:
            print(f"\n{len(rep['misses'])} files not exact:")
            for r in rep["misses"]:
                print(f"  {r['language']}/{r['file']:36s} FN={r['fn']} FP={r['fp']}{'  CRASH ' + r['crash'] if r['crash'] else ''}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps({k: v for k, v in rep.items() if k != "cases"}, indent=2))
    if args.md:
        Path(args.md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md).write_text(render_md(rep))
    bad = False
    for name, bar in (("f1", args.min_f1), ("recall", args.min_recall), ("precision", args.min_precision)):
        if bar is not None and o[name] < bar:
            print(f"FAIL: {name} {o[name]:.4f} < {bar}", file=sys.stderr)
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
