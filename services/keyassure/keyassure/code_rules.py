"""Deterministic code-scanning rules for weak cryptographic primitives.

Rule-based, semantic where feasible (Python AST), plus line-based patterns for
Java/JS/C/Go. No model, no heuristics-on-model — every finding maps to a fixed
rule id with a deterministic trigger, so results are reproducible and have zero
false-positive tuning beyond the explicit rule set.

Rules (id -> severity):
  WP-MD5          MD5 used for hashing (CRYPTO/security context)        HIGH
  WP-SHA1         SHA-1 used for signatures/certs (not HMAC/general)     MEDIUM
  WP-DES          DES / 3DES / Blowfish(<tolerable) instantiation        CRITICAL
  WP-ECB          ECB block mode                                         CRITICAL
  WP-RSA-SHORT    RSA key with modulus < 2048 bits                       CRITICAL
  WP-EC-SHORT     EC curve under ~224 bits                               HIGH
  WP-SECURERANDOM java.security.SecureRandom misuse (static/seeded)      MEDIUM
  WP-HARDCODED-KEY hardcoded literal assigned to a key/secret variable   HIGH
  WP-STATIC-IV    fixed/zero IV used with a block cipher                 HIGH

Findings carry file/line/column/snippet and the matched rule.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

WEAK_HASH = {"md5": "WP-MD5", "sha1": "WP-SHA1"}
# contexts where sha1/md5 are NOT security-sensitive (kept conservative)
_NONSECURY_HINT = ("etag", "cache", "checksum", "content_hash", "idempoten", "correlation")

DES_TOKENS = re.compile(r"\b(DESede|DESedeKeySpec|DESKeySpec|TripleDES|3DES|Blowfish|DES)\b", re.I)
ECB_TOKENS = re.compile(r"\b(AES|DES|3DES|Blowfish)?[-_./]?ECB\b|Cipher\.getInstance\(\s*[\"'][^\"']*ECB|MODE_ECB|\bECB\b", re.I)
RSA_SHORT = re.compile(r"RSA[_\s/(]*\s*(512|1024)\b|keysize\s*[:=]\s*(512|1024)\b|modulus.*?\b(512|1024)\b", re.I)
SECURERANDOM_BAD = re.compile(r"new\s+SecureRandom\s*\(\s*(new\s+byte\[\]\s*\{[^}]*0\b|\"[^\"]*\"|\d+)\s*\)|setSeed\s*\(\s*(0L?|\"[^\"]*\"|\d{1,6})\s*\)", re.I)
HARDCODED = re.compile(
    r"""(?ix)
    \b(secret|api[_-]?key|apikey|private[_-]?key|passwd|password|passphrase|
        encryption[_-]?key|aes[_-]?key|hmac[_-]?key|access[_-]?token)\b
    [^=\n]{0,20}=\s*["']([^"']{8,})["']
    """)
STATIC_IV = re.compile(r"(IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{|new\s+byte\[\]\s*\{\s*0(\s*,\s*0)*\s*\}|IV\s*=\s*b?[\"'][^\"']{6,}[\"'])", re.I)
MD5_RE = re.compile(r"\b(MD5|md5|MessageDigest\.getInstance\(\s*[\"']MD5|DigestUtils\.md5|hashlib\.md5)\b")
SHA1_RE = re.compile(r"\b(SHA-?1|sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1|DigestUtils\.sha1|hashlib\.sha1)\b")


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    col: int = 0
    snippet: str = ""
    detail: str = ""


SEVERITY = {
    "WP-MD5": "HIGH", "WP-SHA1": "MEDIUM", "WP-DES": "CRITICAL", "WP-ECB": "CRITICAL",
    "WP-RSA-SHORT": "CRITICAL", "WP-EC-SHORT": "HIGH", "WP-SECURERANDOM": "MEDIUM",
    "WP-HARDCODED-KEY": "HIGH", "WP-STATIC-IV": "HIGH",
}


# --------------------------------------------------------------------------- #
# Python AST scanning (semantic)
# --------------------------------------------------------------------------- #
class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str]):
        self.path = path
        self.lines = source_lines
        self.findings: list[Finding] = []

    def _add(self, rule_id, node, detail):
        self.findings.append(Finding(
            rule_id=rule_id, severity=SEVERITY[rule_id], file=self.path,
            line=getattr(node, "lineno", 0), col=getattr(node, "col_offset", 0),
            snippet=self.lines[node.lineno - 1].strip() if getattr(node, "lineno", 0) <= len(self.lines) else "",
            detail=detail))

    def _call_name(self, node):
        f = node.func
        parts = []
        while isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        if isinstance(f, ast.Name):
            parts.append(f.id)
        return ".".join(reversed(parts))

    def visit_Call(self, node):
        name = self._call_name(node)
        low = name.lower()
        # hashlib.new("md5") / hashlib.md5() / Crypto hash
        if "hashlib" in low or "md5" in low or "sha1" in low or "messagedigest" in low:
            algo = None
            if low.endswith(".md5") or low.endswith("md5"):
                algo = "md5"
            elif low.endswith(".sha1") or low.endswith("sha1"):
                algo = "sha1"
            elif node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                algo = node.args[0].value.lower()
            if algo in WEAK_HASH:
                rid = WEAK_HASH[algo]
                self._add(rid, node, f"weak hash {algo.upper()} via {name}()")
        # Crypto.Cipher.DES / DES3 / AES with ECB
        if "des" in low and ("cipher" in low or "key" in low):
            self._add("WP-DES", node, f"DES-family cipher via {name}()")
        if "cipher" in low and node.args and isinstance(node.args[0], ast.Constant):
            mode = str(node.args[0].value).upper()
            if "ECB" in mode or node.args[0].value == 1:  # MODE_ECB == 1 in PyCryptodome
                self._add("WP-ECB", node, f"ECB mode via {name}({node.args[0].value!r})")
        # Crypto.PublicKey.RSA.generate(bits)
        if "rsa" in low and "generate" in low:
            bits = _const_int(node.args[0] if node.args else None)
            if bits is not None and bits < 2048:
                self._add("WP-RSA-SHORT", node, f"RSA {bits}-bit key (<2048) via {name}()")
        # cryptography ec / SECP curves — check generate_private_key curve arg
        if "generate_private_key" in low:
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                cls = _attr_chain(arg)
                if cls and re.search(r"SEC(112|128|160)R1|SECT163|Weak", cls):
                    self._add("WP-EC-SHORT", node, f"weak EC curve {cls}")
        self.generic_visit(node)

    def visit_Assign(self, node):
        # hardcoded key: KEY-ish name = "literal"
        for t in node.targets:
            if isinstance(t, ast.Name):
                if _keyish_name(t.id) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 8:
                    if not _looks_like_placeholder(node.value.value):
                        self._add("WP-HARDCODED-KEY", node, f"hardcoded secret assigned to {t.id}")
        # static IV: iv = b"\x00..." or bytes([0,0,...])
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (bytes, str)):
            for t in node.targets:
                if isinstance(t, ast.Name) and "iv" in t.id.lower():
                    if node.value.value and set(node.value.value) <= {0, "\x00", "0"}:
                        self._add("WP-STATIC-IV", node, f"static/zero IV assigned to {t.id}")
        self.generic_visit(node)


def _const_int(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Call):  # int(...)
        return None
    return None


def _attr_chain(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts)) if parts else None


def _keyish_name(name: str) -> bool:
    n = name.lower()
    return any(k in n for k in ("secret", "api_key", "apikey", "private_key",
                                "passphrase", "password", "aes_key", "hmac_key",
                                "encryption_key", "access_token"))


def _looks_like_placeholder(v: str) -> bool:
    low = v.lower()
    return any(t in low for t in ("changeme", "example", "placeholder", "xxxx",
                                  "your-", "<", "env", "os.environ", "getenv"))


def scan_python(source: str, path: str = "<string>") -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return _regex_scan(source, path, suffix=".py")
    lines = source.splitlines()
    v = _PythonVisitor(path, lines)
    v.visit(tree)
    # supplement AST with cheap regex (hardcoded keys across more shapes)
    v.findings += [f for f in _regex_scan(source, path, suffix=".py")
                   if not _dup(f, v.findings)]
    return _dedupe(v.findings)


# --------------------------------------------------------------------------- #
# Line-based regex scanning for Java/JS/TS/C/Go/others
# --------------------------------------------------------------------------- #
def _regex_scan(source: str, path: str, suffix: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("#"):
            comment_ctx = True
        else:
            comment_ctx = False

        def hit(rule_id, detail, rx):
            m = rx.search(line)
            if m:
                findings.append(Finding(rule_id, SEVERITY[rule_id], path, i,
                                        m.start(), stripped[:160], detail))

        if MD5_RE.search(line) and not comment_ctx:
            hit("WP-MD5", "MD5 usage", MD5_RE)
        if SHA1_RE.search(line) and not comment_ctx and not _nonsecurity(line):
            hit("WP-SHA1", "SHA-1 usage", SHA1_RE)
        if DES_TOKENS.search(line) and not comment_ctx:
            hit("WP-DES", "DES/3DES/Blowfish cipher", DES_TOKENS)
        if ECB_TOKENS.search(line) and not comment_ctx:
            hit("WP-ECB", "ECB block mode", ECB_TOKENS)
        m = RSA_SHORT.search(line)
        if m and not comment_ctx:
            findings.append(Finding("WP-RSA-SHORT", SEVERITY["WP-RSA-SHORT"], path, i,
                                    m.start(), stripped[:160], "RSA key < 2048 bits"))
        if SECURERANDOM_BAD.search(line) and not comment_ctx:
            hit("WP-SECURERANDOM", "SecureRandom seeded with static/predictable value", SECURERANDOM_BAD)
        if STATIC_IV.search(line) and not comment_ctx:
            hit("WP-STATIC-IV", "static/zero initialization vector", STATIC_IV)
        m = HARDCODED.search(line)
        if m and not comment_ctx and not _looks_like_placeholder(m.group(2) or ""):
            findings.append(Finding("WP-HARDCODED-KEY", SEVERITY["WP-HARDCODED-KEY"], path, i,
                                    m.start(), stripped[:160],
                                    f"hardcoded secret in {m.group(1)} assignment"))
    return findings


def _nonsecurity(line: str) -> bool:
    low = line.lower()
    return any(h in low for h in _NONSECURY_HINT)


def _dup(f: Finding, existing: list[Finding]) -> bool:
    return any(e.rule_id == f.rule_id and e.line == f.line and e.file == f.file for e in existing)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in sorted(findings, key=lambda x: (x.file, x.line, x.rule_id)):
        key = (f.file, f.line, f.rule_id, f.snippet)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scan_file(path: str | Path) -> list[Finding]:
    p = Path(path)
    try:
        source = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    suffix = p.suffix.lower()
    if suffix == ".py":
        return scan_python(source, str(p))
    return _dedupe(_regex_scan(source, str(p), suffix=suffix))


def scan_paths(paths: Iterable[str | Path]) -> dict:
    findings: list[Finding] = []
    files_scanned = 0
    for path in paths:
        p = Path(path)
        targets = [p] if p.is_file() else [q for q in p.rglob("*")
                                           if q.suffix.lower() in
                                           (".py", ".java", ".js", ".ts", ".jsx", ".tsx",
                                            ".c", ".cc", ".cpp", ".go", ".kt", ".scala")]
        for f in targets:
            if any(part in {"node_modules", ".git", "dist", "build", "__pycache__", ".venv"}
                   for part in f.parts):
                continue
            files_scanned += 1
            findings.extend(scan_file(f))

    by_rule: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "by_rule": by_rule,
        "by_severity": by_sev,
        "findings": [f.__dict__ for f in _dedupe(findings)],
    }
