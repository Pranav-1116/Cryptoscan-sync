"""Tree-sitter deep parsers — CST-based crypto API detection.

The original parsers are AST-lite / regex based (ADRs 002/005/006 documented
the intended stronger path). This module ships that path: a real Concrete
Syntax Tree walker over the tree-sitter grammars (via
``tree_sitter_language_pack``), driven by a per-language catalog of crypto
API call signatures with string-literal argument extraction.

Design rules:

- **Deterministic**: the same source produces the same findings. No AI,
  no heuristics beyond the catalog.
- **Opt-in**: enable with ``CRYPTOSCAN_TREE_SITTER=1`` (or import the module
  directly). The module degrades gracefully when the tree-sitter wheels are
  not installed — the existing parsers remain the default path.
- **Catalog-driven**: one table per language maps call names to
  (algorithm-arg index, key-size source, mode tokens, purpose, api type,
  library). Adding a language is adding a row, not a parser.
- **Evidence-compatible**: findings are RawFindings via make_finding, with
  scanner_id ``tree-sitter-scanner-v1.0`` and HIGH confidence, so they flow
  through evidence → policy → drift unchanged.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "tree-sitter-scanner-v1.0"

# ------------------------------------------------------------- availability

_TREE_SITTER = None

# Per-language grammar wheels (tree-sitter-<lang> on PyPI). The
# tree-sitter-language-pack downloader needs GitHub access at runtime, which
# air-gapped deployments do not have — the wheels are self-contained.
_GRAMMAR_MODULES: dict[str, str] = {
    "java": "tree_sitter_java",
    "kotlin": "tree_sitter_kotlin",
    "python": "tree_sitter_python",
    "csharp": "tree_sitter_c_sharp",
    "go": "tree_sitter_go",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_javascript",   # js grammar covers ts
    "rust": "tree_sitter_rust",
    "ruby": "tree_sitter_ruby",
    "php": "tree_sitter_php",
}


def _make_parser(grammar_name: str):
    """Build a tree-sitter Parser for a grammar; None when unavailable."""
    import tree_sitter

    module_name = _GRAMMAR_MODULES.get(grammar_name)
    if module_name is None:
        return None
    try:
        module = __import__(module_name)
        language = getattr(module, "language", None)
        if language is None:
            language = getattr(module, f"language_{grammar_name}", None)
        if language is None:
            return None
        return tree_sitter.Parser(tree_sitter.Language(language()))
    except Exception:
        return None


def tree_sitter_available() -> bool:
    global _TREE_SITTER
    if _TREE_SITTER is None:
        try:
            import tree_sitter  # noqa: F401

            _TREE_SITTER = {"ok": True}
        except Exception:
            _TREE_SITTER = {}
    return bool(_TREE_SITTER)


def tree_sitter_enabled() -> bool:
    """Opt-in via CRYPTOSCAN_TREE_SITTER=1; auto-enabled when explicitly
    requested by callers regardless of the env var."""
    value = os.environ.get("CRYPTOSCAN_TREE_SITTER", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return tree_sitter_available()
    if value in {"0", "false", "no", "off"}:
        return False
    return False  # default off: deterministic baseline unchanged


# ------------------------------------------------------------- catalog

@dataclass(frozen=True)
class Signature:
    call: str                       # call-name suffix to match (e.g. "Cipher.getInstance")
    algorithm: str | None           # fixed algorithm, or None when read from an arg
    algo_arg: int = -1              # index of the string-literal arg holding the algorithm
    key_size: int | None = None     # fixed key size (e.g. Aes256 -> 256)
    key_size_arg: int = -1          # index of an integer arg holding the key size
    mode_tokens: tuple[str, ...] = ()   # mode strings to detect in any arg (e.g. "MODE_GCM")
    purpose: str = "UNKNOWN"
    api_type: str = "UNKNOWN"
    library: str = ""
    kind: str = "call"              # "call" | "new" (object creation)
    match: str = "suffix"           # "suffix" | "prefix" (e.g. Rust ::new variants)


# call name suffix -> Signature. Per language.
CATALOG: dict[str, list[Signature]] = {
    "java": [
        Signature("Cipher.getInstance", None, algo_arg=0, mode_tokens=(), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="javax.crypto"),
        Signature("MessageDigest.getInstance", None, algo_arg=0, purpose="HASHING", api_type="MESSAGE_DIGEST", library="java.security"),
        Signature("KeyGenerator.getInstance", None, algo_arg=0, purpose="KEY_GENERATION", api_type="KEY_GENERATOR", library="javax.crypto"),
        Signature("KeyPairGenerator.getInstance", None, algo_arg=0, purpose="KEY_GENERATION", api_type="KEY_PAIR_GENERATOR", library="java.security"),
        Signature("Mac.getInstance", None, algo_arg=0, purpose="MAC_GENERATION", api_type="MAC", library="javax.crypto"),
        Signature("Signature.getInstance", None, algo_arg=0, purpose="SIGNING", api_type="SIGNATURE", library="java.security"),
        Signature("SecretKeyFactory.getInstance", None, algo_arg=0, purpose="KEY_MANAGEMENT", api_type="SECRET_KEY_SPEC", library="javax.crypto"),
    ],
    "kotlin": [
        Signature("Cipher.getInstance", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="javax.crypto"),
        Signature("MessageDigest.getInstance", None, algo_arg=0, purpose="HASHING", api_type="MESSAGE_DIGEST", library="java.security"),
        Signature("KeyGenerator.getInstance", None, algo_arg=0, purpose="KEY_GENERATION", api_type="KEY_GENERATOR", library="javax.crypto"),
        Signature("Mac.getInstance", None, algo_arg=0, purpose="MAC_GENERATION", api_type="MAC", library="javax.crypto"),
    ],
    "python": [
        Signature("hashlib.new", None, algo_arg=0, purpose="HASHING", api_type="MESSAGE_DIGEST", library="hashlib"),
        Signature("hashlib.md5", "MD5", purpose="HASHING", api_type="MESSAGE_DIGEST", library="hashlib"),
        Signature("hashlib.sha1", "SHA-1", purpose="HASHING", api_type="MESSAGE_DIGEST", library="hashlib"),
        Signature("hashlib.sha256", "SHA-256", purpose="HASHING", api_type="MESSAGE_DIGEST", library="hashlib"),
        Signature("hashlib.sha512", "SHA-512", purpose="HASHING", api_type="MESSAGE_DIGEST", library="hashlib"),
        Signature("hashlib.pbkdf2_hmac", None, algo_arg=0, purpose="PASSWORD_HASHING", api_type="MESSAGE_DIGEST", library="hashlib"),
        Signature("AES.new", "AES", mode_tokens=("MODE_",), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="pycryptodome"),
        Signature("DES3.new", "3DES", mode_tokens=("MODE_",), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="pycryptodome"),
        Signature("DES.new", "DES", mode_tokens=("MODE_",), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="pycryptodome"),
        Signature("ARC4.new", "RC4", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="pycryptodome"),
        Signature("AESGCM", "AES", mode_tokens=("GCM",), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="cryptography"),
        Signature("hmac.new", None, algo_arg=-1, purpose="MAC_GENERATION", api_type="MAC", library="hmac"),
    ],
    "csharp": [
        Signature("Aes.Create", "AES", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="System.Security.Cryptography"),
        Signature("Rijndael.Create", "RIJNDAEL", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="System.Security.Cryptography"),
        Signature("DES.Create", "DES", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="System.Security.Cryptography"),
        Signature("TripleDES.Create", "3DES", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="System.Security.Cryptography"),
        Signature("AesGcm", "AES", mode_tokens=("GCM",), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="System.Security.Cryptography", kind="new"),
        Signature("SHA256.Create", "SHA-256", purpose="HASHING", api_type="MESSAGE_DIGEST", library="System.Security.Cryptography"),
        Signature("SHA1.Create", "SHA-1", purpose="HASHING", api_type="MESSAGE_DIGEST", library="System.Security.Cryptography"),
        Signature("MD5.Create", "MD5", purpose="HASHING", api_type="MESSAGE_DIGEST", library="System.Security.Cryptography"),
        Signature("SHA512.Create", "SHA-512", purpose="HASHING", api_type="MESSAGE_DIGEST", library="System.Security.Cryptography"),
        Signature("RSA.Create", "RSA", key_size_arg=0, purpose="SIGNING", api_type="KEY_PAIR_GENERATOR", library="System.Security.Cryptography"),
        Signature("ECDsa.Create", "ECDSA", purpose="SIGNING", api_type="KEY_PAIR_GENERATOR", library="System.Security.Cryptography"),
        Signature("HMACSHA256", "HmacSHA256", purpose="MAC_GENERATION", api_type="MAC", library="System.Security.Cryptography", kind="new"),
        Signature("HMACSHA1", "HmacSHA1", purpose="MAC_GENERATION", api_type="MAC", library="System.Security.Cryptography", kind="new"),
    ],
    "go": [
        Signature("aes.NewCipher", "AES", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="crypto/aes"),
        Signature("md5.New", "MD5", purpose="HASHING", api_type="MESSAGE_DIGEST", library="crypto/md5"),
        Signature("sha1.New", "SHA-1", purpose="HASHING", api_type="MESSAGE_DIGEST", library="crypto/sha1"),
        Signature("sha256.New", "SHA-256", purpose="HASHING", api_type="MESSAGE_DIGEST", library="crypto/sha256"),
        Signature("sha512.New", "SHA-512", purpose="HASHING", api_type="MESSAGE_DIGEST", library="crypto/sha512"),
        Signature("rsa.GenerateKey", "RSA", key_size_arg=1, purpose="KEY_GENERATION", api_type="KEY_PAIR_GENERATOR", library="crypto/rsa"),
        Signature("ecdsa.GenerateKey", "ECDSA", purpose="KEY_GENERATION", api_type="KEY_PAIR_GENERATOR", library="crypto/ecdsa"),
        Signature("hmac.New", None, purpose="MAC_GENERATION", api_type="MAC", library="crypto/hmac"),
    ],
    "javascript": [
        Signature("createCipheriv", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="node:crypto"),
        Signature("createCipher", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="node:crypto"),
        Signature("createDecipheriv", None, algo_arg=0, purpose="DECRYPTION", api_type="CIPHER_INSTANCE", library="node:crypto"),
        Signature("createHash", None, algo_arg=0, purpose="HASHING", api_type="MESSAGE_DIGEST", library="node:crypto"),
        Signature("createHmac", None, algo_arg=0, purpose="MAC_GENERATION", api_type="MAC", library="node:crypto"),
        Signature("forge.cipher.createCipher", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="node-forge"),
    ],
    "typescript": [
        Signature("createCipheriv", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="node:crypto"),
        Signature("createCipher", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="node:crypto"),
        Signature("createHash", None, algo_arg=0, purpose="HASHING", api_type="MESSAGE_DIGEST", library="node:crypto"),
        Signature("createHmac", None, algo_arg=0, purpose="MAC_GENERATION", api_type="MAC", library="node:crypto"),
    ],
    "rust": [
        Signature("Aes128::new", "AES", key_size=128, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="aes", match="prefix"),
        Signature("Aes256::new", "AES", key_size=256, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="aes", match="prefix"),
        Signature("Aes128Gcm::new", "AES", mode_tokens=("GCM",), match="prefix", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="aes-gcm"),
        Signature("Aes256Gcm::new", "AES", mode_tokens=("GCM",), match="prefix", purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="aes-gcm"),
        Signature("Md5::new", "MD5", purpose="HASHING", api_type="MESSAGE_DIGEST", library="md-5", match="prefix"),
        Signature("Sha1::new", "SHA-1", purpose="HASHING", api_type="MESSAGE_DIGEST", library="sha1", match="prefix"),
        Signature("Sha256::new", "SHA-256", purpose="HASHING", api_type="MESSAGE_DIGEST", library="sha2", match="prefix"),
        Signature("Sha512::new", "SHA-512", purpose="HASHING", api_type="MESSAGE_DIGEST", library="sha2", match="prefix"),
        Signature("Aes128Gcm::encrypt", "AES", mode_tokens=("GCM",), purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="aes-gcm"),
    ],
    "ruby": [
        Signature("Cipher.new", None, algo_arg=0, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="openssl", kind="new"),
        Signature("Digest::MD5.hexdigest", "MD5", purpose="HASHING", api_type="MESSAGE_DIGEST", library="digest"),
        Signature("Digest::SHA1.hexdigest", "SHA-1", purpose="HASHING", api_type="MESSAGE_DIGEST", library="digest"),
        Signature("Digest::SHA256.hexdigest", "SHA-256", purpose="HASHING", api_type="MESSAGE_DIGEST", library="digest"),
        Signature("Digest::SHA512.hexdigest", "SHA-512", purpose="HASHING", api_type="MESSAGE_DIGEST", library="digest"),
        Signature("HMAC.new", None, algo_arg=-1, purpose="MAC_GENERATION", api_type="MAC", library="openssl", kind="new"),
    ],
    "php": [
        Signature("openssl_encrypt", None, algo_arg=1, purpose="ENCRYPTION", api_type="CIPHER_INSTANCE", library="openssl"),
        Signature("openssl_decrypt", None, algo_arg=1, purpose="DECRYPTION", api_type="CIPHER_INSTANCE", library="openssl"),
        Signature("hash", None, algo_arg=0, purpose="HASHING", api_type="MESSAGE_DIGEST", library="hash"),
        Signature("hash_hmac", None, algo_arg=0, purpose="MAC_GENERATION", api_type="MAC", library="hash"),
        Signature("password_hash", None, algo_arg=0, purpose="PASSWORD_HASHING", api_type="MESSAGE_DIGEST", library="password"),
    ],
}

# tree-sitter grammar name per scanner language
LANGUAGE_GRAMMAR: dict[str, str] = {
    "java": "java",
    "kotlin": "kotlin",
    "python": "python",
    "csharp": "csharp",
    "go": "go",
    "javascript": "javascript",
    "typescript": "typescript",
    "rust": "rust",
    "ruby": "ruby",
    "php": "php",
}

EXT_TO_LANGUAGE: dict[str, str] = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".py": "python",
    ".cs": "csharp",
    ".go": "go",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
}

# CST node types that represent a call (language -> set)
CALL_NODE_TYPES: dict[str, tuple[str, ...]] = {
    "java": ("method_invocation", "object_creation_expression"),
    "kotlin": ("call_expression",),
    "python": ("call",),
    "csharp": ("invocation_expression", "object_creation_expression"),
    "go": ("call_expression",),
    "javascript": ("call_expression", "new_expression"),
    "typescript": ("call_expression", "new_expression"),
    "rust": ("call_expression", "method_call_expression"),
    "ruby": ("call",),
    "php": ("function_call_expression", "member_call_expression", "scoped_call_expression"),
}

STRING_NODE_TYPES = {
    "string_literal", "string", "string_content", "interpreted_string_literal",
    "raw_string_literal", "heredoc_body", "encapsed_string",
}

_IDENTIFIER_TYPES = {
    "identifier", "field_identifier", "simple_identifier", "property_identifier",
    "scoped_identifier", "type_identifier", "method_identifier", "name",
    "constant", "global",
}

# ------------------------------------------------------------- parsing

_ALGO_RE = re.compile(r"([A-Za-z0-9-]+)")
_MODE_TOKENS = {"GCM", "CBC", "ECB", "CTR", "CCM", "OFB", "CFB", "XTS"}
_KEY_RE = re.compile(r"\b(\d{3,4})\b")
_FULL_DIGITS_RE = re.compile(r"\d{3,4}")
# Key sizes are always standalone numeric parts; names like MD5/3DES/SHA1
# must never be mistaken for a key size.
_KEY_SIZES = {128, 192, 256, 384, 512, 1024, 2048, 3072, 4096}


def _split_algorithm(spec: str) -> tuple[str | None, int | None, str | None]:
    """'AES/GCM/NoPadding' -> (AES, None, GCM); 'AES-256-GCM' -> (AES, 256, GCM).

    Standalone numeric parts (256, 2048) are key sizes; names containing
    digits (MD5, 3DES, SHA1) are never treated as key sizes.
    """
    if not spec:
        return None, None, None
    parts = re.split(r"[/\-]", spec)
    algo = None
    key_size = None
    mode = None
    for part in parts:
        upper = part.upper().strip()
        if not upper:
            continue
        if upper in _MODE_TOKENS:
            mode = upper
            continue
        if upper in {"NOPADDING", "PKCS5PADDING", "PKCS7PADDING", "OAEP", "PSS"}:
            continue  # padding, not tracked in the fact fields
        if upper in {"WITH", "AND"}:
            continue
        if _FULL_DIGITS_RE.fullmatch(upper) and int(upper) in _KEY_SIZES:
            key_size = int(upper)
            continue
        if algo is None and len(upper) >= 2:
            algo = upper
    if algo == "SHA" and key_size is not None:
        algo = f"SHA-{key_size}"   # "SHA-256" written as SHA + 256
    if algo is None and key_size is not None:
        algo = "UNKNOWN"
    return algo, key_size, mode


def _node_text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _callee_name(node) -> str:
    """Best-effort dotted call name from the node's leading children."""
    text = _node_text(node)
    paren = text.find("(")
    if paren >= 0:
        text = text[:paren]
    if text.startswith("new "):
        text = text[4:]
    return " ".join(text.split()).replace(" ", "")


def _collect_args(node, string_types: tuple[str, ...]) -> list[str]:
    """Return the raw argument texts of a call node."""
    args: list[str] = []
    arg_list = None
    for child in node.children:
        if child.type in {"argument_list", "arguments", "call_suffix", "template_arguments"}:
            arg_list = child
            break
    if arg_list is None:
        return args
    for child in arg_list.children:
        if child.type in {",", "(", ")", "[", "]", "{", "}"}:
            continue
        args.append(_node_text(child))
    return args


def _arg_at(args: list[str], index: int) -> str | None:
    if 0 <= index < len(args):
        return args[index]
    return None


def _strip_quotes(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        return value[1:-1]
    return value


def _key_size_from_args(args: list[str], index: int) -> int | None:
    raw = _arg_at(args, index)
    if raw is None:
        return None
    match = _KEY_RE.search(raw.replace("_", ""))
    if match and not raw.upper().startswith(("TLS", "SSL")):
        return int(match.group(1))
    return None


def _mode_from_args(args: list[str], tokens: tuple[str, ...]) -> str | None:
    for arg in args:
        upper = arg.upper()
        for token in tokens:
            if token in upper:
                match = re.search(r"MODE_(\w+)", upper)
                if match:
                    return match.group(1)
                return token
    return None


def scan_tree_sitter_file(
    path: Path,
    repo_root: Path | None = None,
    *,
    language: str | None = None,
) -> list[RawFinding]:
    """Scan one file with the tree-sitter CST walker."""
    if not tree_sitter_available():
        return []
    lang = language or EXT_TO_LANGUAGE.get(path.suffix.lower())
    if lang is None or lang not in CATALOG or lang not in CALL_NODE_TYPES:
        return []
    grammar_name = LANGUAGE_GRAMMAR.get(lang)
    if grammar_name is None:
        return []
    try:
        parser = _make_parser(grammar_name)
        if parser is None:
            return []
        source = path.read_bytes()
    except Exception:
        return []
    tree = parser.parse(source)
    signatures = CATALOG[lang]
    findings: list[RawFinding] = []
    seen: set[tuple[str, int, str]] = set()
    call_types = CALL_NODE_TYPES[lang]

    def walk(node) -> None:
        if node.type in call_types:
            callee = _callee_name(node)
            args = _collect_args(node, STRING_NODE_TYPES)
            for sig in signatures:
                matches = False
                upper_callee = callee.upper()
                upper_call = sig.call.upper()
                if sig.match == "prefix":
                    matches = upper_callee.startswith(upper_call)
                elif sig.kind == "new":
                    matches = upper_callee.endswith(upper_call) or upper_callee == upper_call
                else:
                    matches = upper_callee.endswith(upper_call)
                if not matches:
                    continue
                algorithm = sig.algorithm
                key_size = sig.key_size
                mode = None
                if sig.algo_arg >= 0:
                    spec = _strip_quotes(_arg_at(args, sig.algo_arg))
                    if spec:
                        parsed_algo, parsed_size, parsed_mode = _split_algorithm(spec)
                        if parsed_algo:
                            algorithm = parsed_algo
                        if parsed_size:
                            key_size = parsed_size
                        if parsed_mode:
                            mode = parsed_mode
                if sig.key_size_arg >= 0:
                    size = _key_size_from_args(args, sig.key_size_arg)
                    if size:
                        key_size = size
                if sig.mode_tokens:
                    detected = _mode_from_args(args, sig.mode_tokens)
                    if detected:
                        mode = detected
                    elif mode is None:
                        for token in sig.mode_tokens:
                            if token in upper_callee:
                                mode = token
                                break
                if algorithm is None:
                    continue
                dedup_key = (algorithm, key_size or 0, callee)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    make_finding(
                        file_path=path,
                        repo_root=repo_root,
                        line_number=node.start_point[0] + 1,
                        language=lang.upper(),
                        scanner_id=SCANNER_ID,
                        api_type=sig.api_type,
                        algorithm=algorithm,
                        purpose=sig.purpose,
                        library=sig.library,
                        mode=mode,
                        key_size=key_size,
                        confidence="HIGH",
                        confidence_reason="tree-sitter-cst",
                        raw_transformation=sig.call,
                    )
                )
                break
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings


def scan_tree_sitter_root(
    root_path: Path | str,
    repo_root: Path | str | None = None,
) -> list[RawFinding]:
    """Scan every supported source file under a tree."""
    root = Path(root_path)
    if not root.exists():
        return []
    repo = Path(repo_root) if repo_root else root
    findings: list[RawFinding] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in EXT_TO_LANGUAGE:
            findings.extend(scan_tree_sitter_file(path, repo))
    return findings
