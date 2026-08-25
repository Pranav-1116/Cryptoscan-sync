"""Python cryptographic API parser (stdlib ast)."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Optional

from scanner.extractors.entropy_calculator import looks_like_secret
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

logger = logging.getLogger(__name__)

SCANNER_ID = "static-python-scanner-v1.0"

HASHLIB_ALGOS = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
}

CRYPTOGRAPHY_HASH = {
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_256": "SHA3-256",
}

WEAK_SECRET_NAMES = {
    "password",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "token",
    "private_key",
    "aes_key",
    "encryption_key",
}


def parse_python_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except (OSError, SyntaxError) as exc:
        logger.warning("python_parse_failed", extra={"file": str(file_path), "error": str(exc)})
        return []
    visitor = _PythonCryptoVisitor(file_path, repo_root)
    visitor.visit(tree)
    return visitor.findings


class _PythonCryptoVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, repo_root: Path | None):
        self.file_path = file_path
        self.repo_root = repo_root
        self.findings: list[RawFinding] = []
        self._aliases: dict[str, str] = {}
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[-1]
            self._aliases[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self._aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = prev

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        value = _string_literal(node.value)
        if value:
            for target in node.targets:
                name = _name_of(target)
                if name and name.lower() in WEAK_SECRET_NAMES and looks_like_secret(value):
                    self._add(
                        node,
                        api_type="HARDCODED_KEY",
                        algorithm="UNKNOWN",
                        purpose="KEY_GENERATION",
                        library="python-literal",
                        is_hardcoded_key=True,
                        hardcoded_key_length=len(value),
                        confidence="MEDIUM",
                        confidence_reason="high-entropy assignment to secret-named variable",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = _call_name(node)
        if not func:
            self.generic_visit(node)
            return

        lowered = func.lower()
        if lowered.endswith("hashlib.md5") or func.endswith("hashlib.md5") or func == "md5":
            if self._is_hashlib("md5", func):
                self._hash(node, "MD5")
        elif lowered.endswith("hashlib.sha1") or func == "sha1":
            if self._is_hashlib("sha1", func):
                self._hash(node, "SHA-1")
        elif any(func.endswith(f"hashlib.{name}") or func == name for name in HASHLIB_ALGOS):
            for name, algo in HASHLIB_ALGOS.items():
                if func.endswith(f"hashlib.{name}") or func == name:
                    if self._is_hashlib(name, func):
                        self._hash(node, algo)
                    break

        if "hashlib.new" in func:
            algo = _string_arg(node, 0)
            if algo:
                mapped = HASHLIB_ALGOS.get(algo.lower(), algo.upper())
                self._hash(node, mapped)

        if self._is_hmac_call(func):
            digest = self._hmac_digest(node)
            self._add(
                node,
                api_type="MAC",
                algorithm=f"HMAC-{digest}",
                purpose="MAC_GENERATION",
                library="hmac",
                raw_transformation=func,
            )

        if self._is_cipher_ctor(func):
            algo, mode = self._cryptography_cipher(node)
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm=algo,
                mode=mode,
                purpose="ENCRYPTION",
                library="cryptography",
                raw_transformation=func,
            )

        if func.endswith("Fernet.generate_key") or func.endswith("Fernet"):
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="AES",
                mode="CBC",
                purpose="ENCRYPTION",
                library="cryptography.fernet",
                raw_transformation="Fernet",
            )
        if func.endswith("AES.new") or func.endswith("AESGCM"):
            mode = "GCM" if "AESGCM" in func else _mode_from_node(node)
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="AES",
                mode=mode,
                purpose="ENCRYPTION",
                library="pycryptodome" if func.endswith("AES.new") else "cryptography",
            )
        if func.endswith("DES.new") or "algorithms.TripleDES" in func:
            algo = "3DES" if "Triple" in func or "DES3" in func else "DES"
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm=algo,
                purpose="ENCRYPTION",
                library="pycryptodome" if func.endswith("DES.new") else "cryptography",
            )
        if func.endswith("DES3.new"):
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="3DES",
                purpose="ENCRYPTION",
                library="pycryptodome",
            )
        if func.endswith("RSA.generate") or func.endswith("rsa.generate_private_key"):
            bits = _int_arg(node, 0) or _kwint(node, "key_size") or _kwint(node, "bits")
            self._add(
                node,
                api_type="KEY_PAIR_GENERATOR",
                algorithm="RSA",
                purpose="KEY_GENERATION",
                library="cryptography" if "generate_private_key" in func else "pycryptodome",
                key_size=bits,
            )
        if any(func.endswith(name) for name in ("pbkdf2_hmac", "PBKDF2HMAC", "scrypt", "argon2.PasswordHasher")):
            algo = "PBKDF2" if "pbkdf2" in func.lower() else ("SCRYPT" if "scrypt" in func.lower() else "ARGON2")
            self._add(
                node,
                api_type="KEY_GENERATOR",
                algorithm=algo,
                purpose="PASSWORD_HASHING",
                library="hashlib" if "pbkdf2_hmac" in func or func.endswith("scrypt") else "cryptography",
            )
        if func.endswith("bcrypt.hashpw") or func.endswith("bcrypt.hash"):
            self._add(
                node,
                api_type="KEY_GENERATOR",
                algorithm="BCRYPT",
                purpose="PASSWORD_HASHING",
                library="bcrypt",
            )
        if func.endswith("jwt.encode") or func.endswith("jwt.decode"):
            alg = _dict_kw(node, "algorithm") or _nested_algorithm(node)
            self._add(
                node,
                api_type="SIGNATURE",
                algorithm=alg or "HS256",
                purpose="SIGNING" if func.endswith("encode") else "VERIFICATION",
                library="PyJWT",
                raw_transformation=alg,
            )
        if func.endswith("nacl.secret.SecretBox") or func.endswith("SecretBox"):
            self._add(
                node,
                api_type="CIPHER_INSTANCE",
                algorithm="XSalsa20-Poly1305",
                purpose="ENCRYPTION",
                library="pynacl",
            )
        if func.endswith("ssl.wrap_socket") or func.endswith("SSLContext"):
            self._add(
                node,
                api_type="KEY_AGREEMENT",
                algorithm="TLS",
                purpose="KEY_EXCHANGE",
                library="ssl",
                confidence="MEDIUM",
                confidence_reason="TLS context construction",
            )
        if self._is_insecure_random(func) and self._looks_like_key_context(node):
            self._add(
                node,
                api_type="KEY_GENERATOR",
                algorithm="PRNG",
                purpose="KEY_GENERATION",
                library="random",
                confidence="MEDIUM",
                confidence_reason="non-CSPRNG used in a key/token/nonce context; use secrets or os.urandom",
            )
        hashes = CRYPTOGRAPHY_HASH
        for attr, algo in hashes.items():
            if func.endswith(f"hashes.{attr}"):
                self._hash(node, algo, library="cryptography")
        self.generic_visit(node)

    def _is_hmac_call(self, func: str) -> bool:
        if func.endswith("hmac.new") or func.endswith("hmac.digest") or func.endswith("hmac.compare_digest"):
            return func.endswith("hmac.new") or func.endswith("hmac.digest")
        imported = self._aliases.get(func.split(".")[0], "")
        return imported.startswith("hmac") and func.endswith(("new", "digest"))

    def _hmac_digest(self, node: ast.Call) -> str:
        digest = None
        if len(node.args) >= 3:
            digest = _dotted(node.args[2]) or _string_literal(node.args[2])
        for kw in node.keywords:
            if kw.arg in {"digestmod", "digest"}:
                digest = _dotted(kw.value) or _string_literal(kw.value)
        name = (digest or "sha256").split(".")[-1].lower()
        return HASHLIB_ALGOS.get(name, name.upper().replace("_", "-"))

    def _is_cipher_ctor(self, func: str) -> bool:
        if func.endswith("Cipher") or func == "Cipher":
            imported = self._aliases.get("Cipher", "")
            return "cryptography" in imported or func.endswith("Cipher")
        return False

    def _cryptography_cipher(self, node: ast.Call) -> tuple[str, str | None]:
        algo = "UNKNOWN"
        mode = None
        if node.args:
            first = node.args[0]
            first_name = _dotted(first.func if isinstance(first, ast.Call) else first)
            if "AES" in first_name:
                algo = "AES"
            elif "TripleDES" in first_name or "DES3" in first_name:
                algo = "3DES"
            elif first_name.endswith("DES") or ".DES" in first_name:
                algo = "DES"
            elif "ChaCha20" in first_name:
                algo = "ChaCha20"
        if len(node.args) > 1:
            second = node.args[1]
            second_name = _dotted(second.func if isinstance(second, ast.Call) else second)
            mode = _mode_from_name(second_name)
        return algo, mode

    def _is_hashlib(self, name: str, func: str) -> bool:
        if func.endswith(f"hashlib.{name}"):
            return True
        imported = self._aliases.get(name, "")
        return imported.endswith(f"hashlib.{name}") or imported == f"hashlib.{name}"


    def _is_insecure_random(self, func: str) -> bool:
        tail = func.split(".")[-1]
        if tail not in {"random", "randint", "randrange", "choice", "getrandbits", "randbytes"}:
            return False
        if func.startswith("secrets.") or ".secrets." in func:
            return False
        imported = self._aliases.get(func.split(".")[0], "")
        if imported.startswith("secrets"):
            return False
        return func.startswith("random.") or imported.startswith("random") or func in {
            "random",
            "randint",
            "getrandbits",
            "randbytes",
        }

    def _looks_like_key_context(self, node: ast.AST) -> bool:
        hay = " ".join(
            part.lower()
            for part in (
                self._current_function or "",
                self._current_class or "",
            )
            if part
        )
        markers = ("key", "token", "secret", "password", "nonce", "iv", "salt", "seed")
        return any(marker in hay for marker in markers)

    def _hash(self, node: ast.AST, algorithm: str, library: str = "hashlib") -> None:
        self._add(
            node,
            api_type="MESSAGE_DIGEST",
            algorithm=algorithm,
            purpose="HASHING",
            library=library,
        )

    def _add(self, node: ast.AST, **kwargs) -> None:
        self.findings.append(
            make_finding(
                file_path=self.file_path,
                repo_root=self.repo_root,
                line_number=getattr(node, "lineno", 1),
                language="PYTHON",
                scanner_id=SCANNER_ID,
                method_name=self._current_function,
                class_name=self._current_class,
                **kwargs,
            )
        )


def _call_name(node: ast.Call) -> str:
    return _dotted(node.func)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _name_of(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _string_literal(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _string_arg(node: ast.Call, index: int) -> Optional[str]:
    if len(node.args) > index:
        return _string_literal(node.args[index])
    return None


def _int_arg(node: ast.Call, index: int) -> Optional[int]:
    if len(node.args) > index and isinstance(node.args[index], ast.Constant) and isinstance(node.args[index].value, int):
        return node.args[index].value
    return None


def _kwint(node: ast.Call, name: str) -> Optional[int]:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return kw.value.value
    return None


def _dict_kw(node: ast.Call, name: str) -> Optional[str]:
    for kw in node.keywords:
        if kw.arg == name:
            return _string_literal(kw.value)
        if kw.arg == "algorithm":
            return _string_literal(kw.value)
    return None


def _mode_from_name(name: str) -> Optional[str]:
    upper = (name or "").upper()
    for mode in ("GCM", "CCM", "CTR", "CBC", "ECB", "CFB", "OFB"):
        if mode in upper:
            return mode
    return None


def _mode_from_node(node: ast.Call) -> Optional[str]:
    if len(node.args) > 1:
        return _mode_from_name(_dotted(node.args[1]) or _string_literal(node.args[1]) or "")
    for kw in node.keywords:
        if kw.arg in {"mode", "MODE"}:
            return _mode_from_name(_dotted(kw.value) or _string_literal(kw.value) or "")
    return None


def _nested_algorithm(node: ast.Call) -> Optional[str]:
    for kw in node.keywords:
        if kw.arg in {"algorithm", "algorithms"}:
            value = _string_literal(kw.value)
            if value:
                return value
        if isinstance(kw.value, ast.Dict):
            for key, val in zip(kw.value.keys, kw.value.values):
                if isinstance(key, ast.Constant) and key.value == "algorithm":
                    return _string_literal(val)
    return None
