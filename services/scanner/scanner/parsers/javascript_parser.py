"""JavaScript / TypeScript cryptographic API parser (regex, no tree-sitter required)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.extractors.entropy_calculator import looks_like_secret
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-js-scanner-v1.0"

NODE_CIPHER = re.compile(
    r"""crypto\.createCipher(?:iv)?\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_DECIPHER = re.compile(
    r"""crypto\.createDecipher(?:iv)?\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_HASH = re.compile(
    r"""crypto\s*\.\s*createHash\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_HMAC = re.compile(
    r"""crypto\s*\.\s*createHmac\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_SIGN = re.compile(
    r"""crypto\s*\.\s*createSign\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_PBKDF = re.compile(r"""crypto\.pbkdf2(?:Sync)?\s*\(""", re.IGNORECASE)
NODE_SCRYPT = re.compile(r"""crypto\.scrypt(?:Sync)?\s*\(""", re.IGNORECASE)
NODE_RANDOM = re.compile(r"""crypto\.randomBytes\s*\(""", re.IGNORECASE)
NODE_IMPORT = re.compile(
    r"""(?:from\s+['\"](?:node:)?crypto['\"]|require\(\s*['\"](?:node:)?crypto['\"]\))""",
    re.IGNORECASE,
)
BARE_CIPHER = re.compile(r"""\bcreateCipher(?:iv)?\(\s*['\"]([^'\"]+)['\"]""", re.IGNORECASE)
BARE_HASH = re.compile(r"""\bcreateHash\(\s*['\"]([^'\"]+)['\"]""", re.IGNORECASE)
BARE_HMAC = re.compile(r"""\bcreateHmac\(\s*['\"]([^'\"]+)['\"]""", re.IGNORECASE)
WEBCRYPTO = re.compile(
    r"""(?:crypto\.subtle|window\.crypto\.subtle)\.(\w+)\s*\(""",
    re.IGNORECASE,
)
WEBCRYPTO_NAMED = re.compile(
    r"""(?:crypto\.subtle|window\.crypto\.subtle)\.(\w+)\(\s*\{\s*name\s*:\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
WEBCRYPTO_DIGEST = re.compile(
    r"""(?:crypto\.subtle|window\.crypto\.subtle)\.digest\(\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
_WEBCRYPTO_ARG_ALGO = re.compile(
    r"""\bname\s*:\s*['"]([A-Za-z0-9._-]+)['"]|['"](AES-(?:GCM|CBC|CTR|KW)|HMAC|RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDSA|ECDH|X25519|Ed25519|HKDF|PBKDF2|SHA-(?:1|256|384|512))['"]"""
)
FORGE_MD = re.compile(r"""forge\.md\.(md5|sha1|sha256|sha384|sha512)\b""", re.IGNORECASE)
FORGE_CIPHER = re.compile(
    r"""forge\.cipher\.createCipher\(\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
FORGE_RSA = re.compile(r"""forge\.pki\.rsa\.(generateKeyPair|setPublicKey|setPrivateKey)\b""", re.IGNORECASE)
FORGE_HMAC = re.compile(r"""forge\.hmac\.(create|start)\b""", re.IGNORECASE)
FORGE_PBKDF = re.compile(r"""forge\.pkcs5\.pbkdf2\b""", re.IGNORECASE)
JWT_SIGN = re.compile(
    r"""jwt\.sign\s*\((?:[^;]{0,200}?algorithm\s*:\s*['"]([^'"]+)['"])?""",
    re.IGNORECASE | re.DOTALL,
)
BCRYPT = re.compile(r"""bcrypt\.(?:hash|compare|genSalt)\s*\(""", re.IGNORECASE)
ARGON = re.compile(r"""argon2\.(?:hash|verify)\s*\(""", re.IGNORECASE)
SJCL = re.compile(r"""sjcl\.(?:encrypt|decrypt|codec)\b""", re.IGNORECASE)
CRYPTOJS = re.compile(
    r"""CryptoJS\.(AES|DES|TripleDES|MD5|SHA1|SHA256|SHA512|HmacSHA256)\b""",
    re.IGNORECASE,
)
TLS_MIN = re.compile(r"""minVersion\s*:\s*['\"](TLSv1(?:\.[0-3])?)['\"]""", re.IGNORECASE)
TLS_REJECT = re.compile(r"""rejectUnauthorized\s*:\s*false""")
TLS_SECURE_PROTO = re.compile(r"""secureProtocol\s*:\s*['\"](\w+)['\"]""", re.IGNORECASE)
SECRET_ASSIGN = re.compile(
    r"""(?:const|let|var)\s+(secret|password|apiKey|api_key|token|privateKey)\s*=\s*['"]([^'"]{12,})['"]""",
    re.IGNORECASE,
)

HASH_MAP = {
    "md2": "MD2",
    "md4": "MD4",
    "md5": "MD5",
    "sha": "SHA-1",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "sha512-256": "SHA-512",
    "sha3-224": "SHA3-224",
    "sha3-256": "SHA3-256",
    "sha3-384": "SHA3-384",
    "sha3-512": "SHA3-512",
    "shake128": "SHAKE128",
    "shake256": "SHAKE256",
    "ripemd160": "RIPEMD-160",
    "rmd160": "RIPEMD-160",
    "whirlpool": "WHIRLPOOL",
    "blake2b512": "BLAKE2b",
    "blake2s256": "BLAKE2s",
    "sm3": "SM3",
}


_JOIN_LITERAL = re.compile(r"""\[\s*((?:['"][^'"]*['"]\s*,\s*)*['"][^'"]*['"])\s*\]\s*\.\s*join\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)""")
_CONCAT_LITERAL = re.compile(r"""(['"])([^'"\n]*)\1\s*\+\s*(['"])([^'"\n]*)\3""")
_TEMPLATE_PLAIN = re.compile(r"`([^`$\\\n]*)`")
_BRACKET_ACCESS = re.compile(r"""\[\s*(['"])(createHash|createHmac|createCipheriv|createCipher|createDecipheriv|createDecipher|createSign|createVerify|pbkdf2|pbkdf2Sync|scrypt|scryptSync|randomBytes|generateKeyPair|generateKeyPairSync|createECDH|createDiffieHellman|subtle|digest|encrypt|decrypt|sign|verify|generateKey|importKey|deriveKey|deriveBits|hash)\1\s*\]""")
_DESTRUCTURE_ALIAS = re.compile(r"""\{([^}]*)\}\s*=\s*(?:await\s+)?(?:require\s*\(\s*['"](?:node:)?crypto['"]\s*\)|import\s*\(\s*['"](?:node:)?crypto['"]\s*\))""")
_IMPORT_ALIAS = re.compile(r"""import\s*\{([^}]*)\}\s*from\s*['"](?:node:)?crypto['"]""")
_STRING_CONST = re.compile(r"""\b(?:const|let|var)\s+(\w+)\s*(?::\s*string)?\s*=\s*(['"])([^'"\n]{1,80})\2\s*;?""")
_TEMPLATE_SUBST = re.compile(r"\$\{\s*(\w+)\s*\}")
_NUM_CONST = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*(?::\s*number)?\s*=\s*(\d{1,4})\s*;?")
# TS `const enum Algo { Legacy = "des-ede3-cbc" }` / `enum` / plain object `const Algo = { Legacy: "…" }`
_ENUM_MEMBER = re.compile(r"""\b(\w+)\s*[:=]\s*(['"])([^'"\n]{1,80})\2\s*[,;}\n]""")
_ENUM_BLOCK = re.compile(r"""\b(?:const\s+)?enum\s+(\w+)\s*\{([^}]*)\}|\bconst\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:Object\.freeze\s*\()?\{([^}]*)\}\s*(?:as\s+const)?\)?""")


def _desugar_js(source: str) -> str:
    """Fold trivial string constructions so obfuscated algorithm names are seen
    as literals.  Line-preserving.

    * ``["a", "es-128-ecb"].join("")``       -> ``"aes-128-ecb"``
    * ``"sha" + "512"``                       -> ``"sha512"``
    * ``\`sha256\``` (template, no substitutions) -> ``"sha256"``
    * ``\`${alg}-gcm\``` with ``const alg = "aes-256"`` -> ``"aes-256-gcm"``
    * ``c["createHash"]("md5")``              -> ``c.createHash("md5")``
    * ``const { createHash: mk } = require("crypto")`` / ``import { createHash as mk }``
      -> later ``mk(`` calls are rewritten to ``createHash(``.
    """
    def _join(m: re.Match) -> str:
        parts = re.findall(r"""['"]([^'"]*)['"]""", m.group(1))
        return '"' + (m.group(2) or "").join(parts) + '"'

    for _ in range(3):  # nested folds
        new = _JOIN_LITERAL.sub(_join, source)
        new = _CONCAT_LITERAL.sub(lambda m: '"' + m.group(2) + m.group(4) + '"', new)
        new = _TEMPLATE_PLAIN.sub(lambda m: '"' + m.group(1) + '"', new)
        if new == source:
            break
        source = new
    source = _BRACKET_ACCESS.sub(lambda m: "." + m.group(2), source)

    aliases: dict[str, str] = {}
    for m in list(_DESTRUCTURE_ALIAS.finditer(source)) + list(_IMPORT_ALIAS.finditer(source)):
        for item in m.group(1).split(","):
            item = item.strip()
            if ":" in item:
                orig, alias = [x.strip() for x in item.split(":", 1)]
            elif " as " in item:
                orig, alias = [x.strip() for x in item.split(" as ", 1)]
            else:
                continue
            if orig and alias and orig != alias and re.fullmatch(r"\w+", alias):
                aliases[alias] = orig
    for alias, orig in aliases.items():
        source = re.sub(rf"(?<![\w.]){re.escape(alias)}\s*\(", orig + "(", source)

    consts = {m.group(1): m.group(3) for m in _STRING_CONST.finditer(source)}
    for m in _NUM_CONST.finditer(source):
        consts.setdefault(m.group(1), m.group(2))
    # enum / object members: Algo.Legacy → its literal (only when referenced)
    for m in _ENUM_BLOCK.finditer(source):
        owner, body = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        for mm in _ENUM_MEMBER.finditer(body + "\n"):
            source = re.sub(rf"\b{re.escape(owner)}\.{re.escape(mm.group(1))}\b(?!\s*[:=])", '"' + mm.group(3) + '"', source)
    if consts:
        def _tmpl(m: re.Match) -> str:
            body = m.group(1)
            def _sub(mm: re.Match) -> str:
                return consts.get(mm.group(1), mm.group(0))
            folded = _TEMPLATE_SUBST.sub(_sub, body)
            if "${" in folded:
                return m.group(0)
            return '"' + folded + '"'
        source = re.sub(r"`([^`\\\n]*)`", _tmpl, source)
    return source


def parse_javascript_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw_source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_c_like_comments

    source = _desugar_js(strip_c_like_comments(raw_source))
    findings: list[RawFinding] = []
    language = "TYPESCRIPT" if file_path.suffix.lower() in {".ts", ".tsx"} else "JAVASCRIPT"

    def add(match: re.Match, **kwargs) -> None:
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=source[: match.start()].count("\n") + 1,
                language=language,
                scanner_id=SCANNER_ID,
                **kwargs,
            )
        )

    # named imports from node:crypto make bare calls unambiguous: import { randomInt, randomFillSync } from "crypto"
    imp = re.search(r"""import\s*\{([^}]*)\}\s*from\s*['"](?:node:)?crypto['"]|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"](?:node:)?crypto['"]\s*\)""", source)
    if imp:
        names = {n.strip().split(" as ")[-1].strip() for n in (imp.group(1) or imp.group(2) or "").split(",") if n.strip()}
        rng = names & {"randomInt", "randomFill", "randomFillSync", "randomBytes", "randomUUID", "getRandomValues", "generateKey", "generateKeySync"}
        if rng:
            for match in re.finditer(r"(?<![\w.])(" + "|".join(sorted(rng)) + r")\s*\(", source):
                add(match, api_type="KEY_GENERATOR", algorithm="CSPRNG", purpose="KEY_GENERATION", library="node-crypto",
                    raw_transformation=match.group(1), confidence="HIGH", confidence_reason="named import from node:crypto")
    for match in NODE_CIPHER.finditer(source):
        algo, mode, key_size = _parse_node_cipher(match.group(1))
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=key_size,
            purpose="ENCRYPTION",
            library="node-crypto",
            raw_transformation=match.group(1),
        )
    for match in NODE_DECIPHER.finditer(source):
        algo, mode, key_size = _parse_node_cipher(match.group(1))
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=key_size,
            purpose="DECRYPTION",
            library="node-crypto",
            raw_transformation=match.group(1),
        )
    for match in NODE_HASH.finditer(source):
        raw = match.group(1)
        add(
            match,
            api_type="MESSAGE_DIGEST",
            algorithm=HASH_MAP.get(raw.lower(), raw.upper()),
            purpose="HASHING",
            library="node-crypto",
        )
    for match in NODE_HMAC.finditer(source):
        raw = match.group(1)
        add(
            match,
            api_type="MAC",
            algorithm=f"HMAC-{HASH_MAP.get(raw.lower(), raw.upper())}",
            purpose="MAC_GENERATION",
            library="node-crypto",
            raw_transformation=f"createHmac({raw})",
        )
    for match in NODE_SIGN.finditer(source):
        add(
            match,
            api_type="SIGNATURE",
            algorithm=match.group(1).upper(),
            purpose="SIGNING",
            library="node-crypto",
        )
    for match in NODE_PBKDF.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="PBKDF2", purpose="PASSWORD_HASHING", library="node-crypto")
        tail = source[match.end(): match.end() + 240]
        digest = re.search(r"""^(?:[^;()]*?,){4}\s*['"]([A-Za-z0-9-]+)['"]""", tail)
        if digest:
            raw = digest.group(1)
            add(match, api_type="MESSAGE_DIGEST", algorithm=HASH_MAP.get(raw.lower(), raw.upper()), purpose="HASHING", library="node-crypto")
    for match in NODE_SCRYPT.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="SCRYPT", purpose="PASSWORD_HASHING", library="node-crypto")
    for match in NODE_RANDOM.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="CSPRNG", purpose="KEY_GENERATION", library="node-crypto")
    claimed_node = {m.start() for m in NODE_CIPHER.finditer(source)} | {
        m.start() for m in NODE_HASH.finditer(source)
    } | {m.start() for m in NODE_HMAC.finditer(source)}
    if NODE_IMPORT.search(source):
        for match in BARE_CIPHER.finditer(source):
            if match.start() in claimed_node:
                continue
            algo, mode, key_size = _parse_node_cipher(match.group(1))
            add(
                match,
                api_type="CIPHER_INSTANCE",
                algorithm=algo,
                mode=mode,
                key_size=key_size,
                purpose="ENCRYPTION",
                library="node-crypto",
                raw_transformation=match.group(1),
            )
        for match in BARE_HASH.finditer(source):
            if match.start() in claimed_node:
                continue
            raw = match.group(1)
            add(
                match,
                api_type="MESSAGE_DIGEST",
                algorithm=HASH_MAP.get(raw.lower(), raw.upper()),
                purpose="HASHING",
                library="node-crypto",
            )
        for match in BARE_HMAC.finditer(source):
            if match.start() in claimed_node:
                continue
            raw = match.group(1)
            add(
                match,
                api_type="MAC",
                algorithm="HMAC-" + HASH_MAP.get(raw.lower(), raw.upper()),
                purpose="MAC_GENERATION",
                library="node-crypto",
            )
    claimed_webcrypto: set[int] = set()
    for match in WEBCRYPTO_NAMED.finditer(source):
        method, raw_algo = match.group(1), match.group(2)
        claimed_webcrypto.add(match.start())
        algo, mode, purpose, api_type = _webcrypto_spec(method, raw_algo)
        add(
            match,
            api_type=api_type,
            algorithm=algo,
            mode=mode,
            purpose=purpose,
            library="Web Crypto API",
            raw_transformation=raw_algo,
        )
    for match in WEBCRYPTO_DIGEST.finditer(source):
        claimed_webcrypto.add(match.start())
        add(
            match,
            api_type="MESSAGE_DIGEST",
            algorithm=HASH_MAP.get(match.group(1).lower(), match.group(1).upper()),
            purpose="HASHING",
            library="Web Crypto API",
        )
    for match in WEBCRYPTO.finditer(source):
        if match.start() in claimed_webcrypto:
            continue
        method = match.group(1)
        # Multi-line algorithm objects ({ iv, name: 'AES-CBC' }) and bare algorithm strings
        # (importKey('raw', key, 'AES-CBC', ...)): look inside the argument list.
        window = source[match.end(): match.end() + 400]
        depth, cut = 0, len(window)
        for idx, ch in enumerate(window):
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    cut = idx
                    break
                depth -= 1
        args = window[:cut]
        named = _WEBCRYPTO_ARG_ALGO.search(args)
        if named:
            raw_algo = named.group(1) or named.group(2)
            algo, mode, purpose, api_type = _webcrypto_spec(method, raw_algo)
            add(
                match,
                api_type=api_type,
                algorithm=algo,
                mode=mode,
                purpose=purpose,
                library="Web Crypto API",
                raw_transformation=raw_algo,
            )
            continue
        purpose = {
            "encrypt": "ENCRYPTION",
            "decrypt": "DECRYPTION",
            "sign": "SIGNING",
            "verify": "VERIFICATION",
            "digest": "HASHING",
            "generateKey": "KEY_GENERATION",
            "deriveBits": "KEY_EXCHANGE",
        }.get(method, "UNKNOWN")
        add(
            match,
            api_type="CIPHER_INSTANCE" if method in {"encrypt", "decrypt"} else "KEY_GENERATOR",
            algorithm="UNKNOWN",
            purpose=purpose,
            library="Web Crypto API",
            confidence="LOW",
            confidence_reason="WebCrypto call without algorithm object inspection",
            raw_transformation="subtle." + method,
        )
    for match in FORGE_MD.finditer(source):
        add(
            match,
            api_type="MESSAGE_DIGEST",
            algorithm=HASH_MAP.get(match.group(1).lower(), match.group(1).upper()),
            purpose="HASHING",
            library="node-forge",
        )
    for match in FORGE_CIPHER.finditer(source):
        raw = match.group(1)
        algo = "AES" if "AES" in raw.upper() else ("3DES" if "3DES" in raw.upper() or "DES-EDE" in raw.upper() else raw.upper())
        mode = None
        for item in ("GCM", "CBC", "ECB", "CFB", "OFB", "CTR"):
            if item in raw.upper():
                mode = item
                break
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            purpose="ENCRYPTION",
            library="node-forge",
            raw_transformation=raw,
        )
    for match in FORGE_RSA.finditer(source):
        add(match, api_type="KEY_PAIR_GENERATOR", algorithm="RSA", purpose="KEY_GENERATION", library="node-forge")
    for match in FORGE_HMAC.finditer(source):
        add(match, api_type="MAC", algorithm="HMAC", purpose="MAC_GENERATION", library="node-forge")
    for match in FORGE_PBKDF.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="PBKDF2", purpose="PASSWORD_HASHING", library="node-forge")
    for match in JWT_SIGN.finditer(source):
        add(
            match,
            api_type="SIGNATURE",
            algorithm=match.group(1) or "HS256",
            purpose="SIGNING",
            library="jsonwebtoken",
        )
    for match in BCRYPT.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="BCRYPT", purpose="PASSWORD_HASHING", library="bcrypt")
    for match in ARGON.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="ARGON2", purpose="PASSWORD_HASHING", library="argon2")
    for match in SJCL.finditer(source):
        add(match, api_type="CIPHER_INSTANCE", algorithm="AES", purpose="ENCRYPTION", library="sjcl")
    for match in CRYPTOJS.finditer(source):
        name = match.group(1).upper()
        algo_map = {"TRIPLEDES": "3DES", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512", "HMACSHA256": "HMAC-SHA256"}
        purpose = "HASHING" if name in {"MD5", "SHA1", "SHA256", "SHA512"} else "ENCRYPTION"
        add(
            match,
            api_type="MESSAGE_DIGEST" if purpose == "HASHING" else "CIPHER_INSTANCE",
            algorithm=algo_map.get(name, name),
            purpose=purpose,
            library="crypto-js",
        )
    for match in TLS_MIN.finditer(source):
        raw = match.group(1)
        algo = {"TLSv1": "TLS1.0", "TLSv1.0": "TLS1.0", "TLSv1.1": "TLS1.1", "TLSv1.2": "TLS1.2", "TLSv1.3": "TLS1.3"}.get(raw, raw)
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm=algo,
            purpose="NETWORK_ENCRYPTION",
            library="node-tls",
            raw_transformation=raw,
        )
    for match in TLS_REJECT.finditer(source):
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm="TLS-UNVERIFIED",
            purpose="NETWORK_ENCRYPTION",
            library="node-tls",
            confidence="HIGH",
            confidence_reason="rejectUnauthorized-false",
        )
    for match in TLS_SECURE_PROTO.finditer(source):
        raw = match.group(1)
        algo = "TLS1.0" if raw.upper().startswith("TLSV1_METHOD") or raw.upper() == "TLSV1_METHOD" else raw
        if "TLSV1_1" in raw.upper():
            algo = "TLS1.1"
        elif "TLSV1_2" in raw.upper():
            algo = "TLS1.2"
        add(
            match,
            api_type="KEY_AGREEMENT",
            algorithm=algo,
            purpose="NETWORK_ENCRYPTION",
            library="node-tls",
            raw_transformation=raw,
        )
    for match in SECRET_ASSIGN.finditer(source):
        value = match.group(2)
        if looks_like_secret(value):
            add(
                match,
                api_type="HARDCODED_KEY",
                algorithm="UNKNOWN",
                purpose="KEY_GENERATION",
                library="javascript-literal",
                is_hardcoded_key=True,
                hardcoded_key_length=len(value),
                confidence="MEDIUM",
                confidence_reason="high-entropy secret assignment",
            )
    findings.extend(_resolved_node_calls(file_path, repo_root, source, language, findings))
    try:
        from scanner.parsers.javascript_rules import run_javascript_rules

        seen = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
        findings.extend(run_javascript_rules(file_path, repo_root, source, language, SCANNER_ID, seen=seen))
    except Exception:  # pragma: no cover - supplementary pass must never break the parser
        pass
    return findings


def _webcrypto_spec(method: str, raw_algo: str) -> tuple[str, str | None, str, str]:
    upper = raw_algo.upper().replace("_", "-")
    purpose = {
        "encrypt": "ENCRYPTION",
        "decrypt": "DECRYPTION",
        "sign": "SIGNING",
        "verify": "VERIFICATION",
        "digest": "HASHING",
        "generateKey": "KEY_GENERATION",
        "importKey": "KEY_GENERATION",
        "deriveBits": "KEY_EXCHANGE",
        "deriveKey": "KEY_EXCHANGE",
    }.get(method, "UNKNOWN")
    mode = None
    if "GCM" in upper:
        mode = "GCM"
    elif "CBC" in upper:
        mode = "CBC"
    elif "CTR" in upper:
        mode = "CTR"
    if "AES" in upper:
        return "AES", mode, purpose, "CIPHER_INSTANCE" if purpose in {"ENCRYPTION", "DECRYPTION"} else "KEY_GENERATOR"
    if "RSA" in upper:
        return "RSA", None, purpose, "KEY_PAIR_GENERATOR" if purpose == "KEY_GENERATION" else "SIGNATURE"
    if "ECDSA" in upper or "ECDH" in upper:
        return "ECDSA" if "ECDSA" in upper else "ECDH", None, purpose, "KEY_PAIR_GENERATOR"
    if upper.startswith("SHA"):
        return HASH_MAP.get(raw_algo.lower(), upper), None, "HASHING", "MESSAGE_DIGEST"
    if "HMAC" in upper:
        return "HMAC", None, "MAC_GENERATION", "MAC"
    if "PBKDF2" in upper:
        return "PBKDF2", None, "PASSWORD_HASHING", "KEY_GENERATOR"
    return raw_algo, mode, purpose, "CIPHER_INSTANCE"

def _resolved_node_calls(file_path: Path, repo_root, source: str, language: str, existing: list[RawFinding]) -> list[RawFinding]:
    """createHash(name) when name is a local string constant."""
    try:
        from scanner.parsers.java_ast import extract_calls, tokenize
    except Exception:
        return []
    seen = {(f.source.line_number, f.crypto.algorithm, f.crypto.api_type) for f in existing}
    tokens = tokenize(source)
    calls, locals_map = extract_calls(tokens)
    extra: list[RawFinding] = []
    specs = {
        "createCipheriv": ("CIPHER_INSTANCE", "ENCRYPTION", True),
        "createCipher": ("CIPHER_INSTANCE", "ENCRYPTION", True),
        "createDecipheriv": ("CIPHER_INSTANCE", "DECRYPTION", True),
        "createDecipher": ("CIPHER_INSTANCE", "DECRYPTION", True),
        "createHash": ("MESSAGE_DIGEST", "HASHING", False),
        "createHmac": ("MAC", "MAC_GENERATION", False),
        "createSign": ("SIGNATURE", "SIGNING", False),
    }
    for call in calls:
        spec = specs.get(call.name)
        if spec is None or not call.args:
            continue
        arg = call.args[0]
        if not isinstance(arg, dict):
            continue
        raw = None
        if arg.get("strings"):
            raw = str(arg["strings"][0])
        else:
            for ident in arg.get("idents") or []:
                if ident in locals_map:
                    raw = locals_map[ident]
                    break
        if not raw:
            continue
        api_type, purpose, cipher = spec
        if cipher:
            algo, mode, key_size = _parse_node_cipher(raw)
        else:
            algo, mode, key_size = HASH_MAP.get(raw.lower(), raw.upper()), None, None
        line = source[: int(arg.get("offset") or call.offset)].count("\n") + 1
        key = (line, algo, api_type)
        if key in seen:
            continue
        seen.add(key)
        extra.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language=language,
                scanner_id=SCANNER_ID,
                api_type=api_type,
                algorithm=algo,
                mode=mode,
                key_size=key_size,
                purpose=purpose,
                library="node-crypto",
                raw_transformation=raw,
            )
        )
    return extra


def _parse_node_cipher(spec: str) -> tuple[str, str | None, int | None]:
    parts = spec.lower().replace("_", "-").split("-")
    algo = parts[0].upper()
    if algo == "DES3" or spec.lower().startswith("des-ede"):
        algo = "3DES"
    key_size = None
    mode = None
    for part in parts[1:]:
        if part.isdigit():
            key_size = int(part)
        elif part.upper() in {"CBC", "GCM", "CTR", "ECB", "CFB", "OFB", "CCM"}:
            mode = part.upper()
    return algo, mode, key_size
