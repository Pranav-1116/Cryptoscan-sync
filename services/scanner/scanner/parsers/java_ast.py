"""Brace-aware Java AST walker for cryptographic API calls.

This is not a full JLS parser and does not require Eclipse JDT or tree-sitter.
It tokenizes source (comments and string literals are real tokens, not text),
walks invocations and constructors, and resolves local string constants.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from scanner.extractors.algorithm_extractor import parse_transformation
from scanner.models.enums import ApiType, Purpose

GETINSTANCE_APIS: dict[str, tuple[str, str, str]] = {
    "Cipher": (ApiType.CIPHER_INSTANCE.value, Purpose.ENCRYPTION.value, "javax.crypto"),
    "MessageDigest": (ApiType.MESSAGE_DIGEST.value, Purpose.HASHING.value, "java.security"),
    "KeyGenerator": (ApiType.KEY_GENERATOR.value, Purpose.KEY_GENERATION.value, "javax.crypto"),
    "KeyPairGenerator": (ApiType.KEY_PAIR_GENERATOR.value, Purpose.KEY_GENERATION.value, "java.security"),
    "Signature": (ApiType.SIGNATURE.value, Purpose.SIGNING.value, "java.security"),
    "Mac": (ApiType.MAC.value, Purpose.MAC_GENERATION.value, "javax.crypto"),
    "SSLContext": (ApiType.KEY_AGREEMENT.value, Purpose.NETWORK_ENCRYPTION.value, "javax.net.ssl"),
    "KeyStore": (ApiType.KEY_GENERATOR.value, Purpose.KEY_GENERATION.value, "java.security"),
    "KeyAgreement": (ApiType.KEY_AGREEMENT.value, "KEY_EXCHANGE", "javax.crypto"),
    "SecureRandom": (ApiType.KEY_GENERATOR.value, Purpose.KEY_GENERATION.value, "java.security"),
    "SecretKeyFactory": (ApiType.KEY_GENERATOR.value, Purpose.KEY_GENERATION.value, "javax.crypto"),
    "KeyFactory": (ApiType.KEY_PAIR_GENERATOR.value, Purpose.KEY_GENERATION.value, "java.security"),
    "AlgorithmParameters": (ApiType.CIPHER_INSTANCE.value, Purpose.ENCRYPTION.value, "java.security"),
    "AlgorithmParameterGenerator": (ApiType.KEY_PAIR_GENERATOR.value, Purpose.KEY_GENERATION.value, "java.security"),
    "CertificateFactory": (ApiType.SIGNATURE.value, "VERIFICATION", "java.security.cert"),
}

TLS_MAP = {
    "SSL": "SSLv3",
    "SSLV3": "SSLv3",
    "SSLV3.0": "SSLv3",
    "TLSV1": "TLS1.0",
    "TLS1": "TLS1.0",
    "TLSV1.0": "TLS1.0",
    "TLSV1.1": "TLS1.1",
    "TLS1.1": "TLS1.1",
    "TLSV1.2": "TLS1.2",
    "TLS1.2": "TLS1.2",
    "TLSV1.3": "TLS1.3",
    "TLS1.3": "TLS1.3",
}


@dataclass
class Token:
    kind: str
    value: str
    line: int
    column: int
    offset: int


@dataclass
class CryptoEvent:
    start: int
    api_type: str
    algorithm: Optional[str]
    purpose: str
    library: str
    mode: Optional[str] = None
    padding: Optional[str] = None
    key_size: Optional[int] = None
    is_string_literal: bool = True
    is_hardcoded_key: bool = False
    hardcoded_key_length: Optional[int] = None
    variable_name: Optional[str] = None
    raw_transformation: Optional[str] = None
    is_from_local_variable: bool = False


@dataclass
class Call:
    qualifier: list[str]
    name: str
    args: list[object]
    offset: int
    is_constructor: bool = False


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    line = 1
    col = 1
    n = len(source)
    while i < n:
        ch = source[i]
        if ch in " \t\r":
            i += 1
            col += 1
            continue
        if ch == "\n":
            i += 1
            line += 1
            col = 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            i += 2
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                if source[i] == "\n":
                    line += 1
                    col = 1
                i += 1
            i = min(n, i + 2)
            continue
        if ch == '"' or ch == "'":
            quote = ch
            start = i
            sl, sc = line, col
            i += 1
            col += 1
            buf: list[str] = []
            while i < n and source[i] != quote:
                if source[i] == "\\" and i + 1 < n:
                    buf.append(source[i + 1])
                    i += 2
                    col += 2
                    continue
                if source[i] == "\n":
                    line += 1
                    col = 1
                buf.append(source[i])
                i += 1
                col += 1
            if i < n:
                i += 1
                col += 1
            tokens.append(Token("string", "".join(buf), sl, sc, start))
            continue
        if ch.isdigit():
            start = i
            sl, sc = line, col
            if ch == "0" and i + 1 < n and source[i + 1] in "xX":
                i += 2
                col += 2
                while i < n and source[i] in "0123456789abcdefABCDEF":
                    i += 1
                    col += 1
            else:
                while i < n and source[i].isdigit():
                    i += 1
                    col += 1
            tokens.append(Token("number", source[start:i], sl, sc, start))
            continue
        if ch.isalpha() or ch == "_" or ch == "$":
            start = i
            sl, sc = line, col
            i += 1
            col += 1
            while i < n and (source[i].isalnum() or source[i] in "_$"):
                i += 1
                col += 1
            tokens.append(Token("ident", source[start:i], sl, sc, start))
            continue
        tokens.append(Token("symbol", ch, line, col, i))
        i += 1
        col += 1
    return tokens


def _skip_balanced(tokens: list[Token], i: int, open_s: str, close_s: str) -> int:
    depth = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind == "symbol" and tok.value == open_s:
            depth += 1
        elif tok.kind == "symbol" and tok.value == close_s:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def _parse_args(tokens: list[Token], i: int) -> tuple[list[object], int]:
    """Parse `( ... )` into a flat list of simple argument atoms."""
    if i >= len(tokens) or not (tokens[i].kind == "symbol" and tokens[i].value == "("):
        return [], i
    i += 1
    args: list[object] = []
    current: list[Token] = []
    depth = 1
    while i < len(tokens) and depth > 0:
        tok = tokens[i]
        if tok.kind == "symbol" and tok.value == "(":
            depth += 1
            current.append(tok)
            i += 1
            continue
        if tok.kind == "symbol" and tok.value == ")":
            depth -= 1
            if depth == 0:
                if current:
                    args.append(_atom(current))
                return args, i + 1
            current.append(tok)
            i += 1
            continue
        if tok.kind == "symbol" and tok.value == "," and depth == 1:
            if current:
                args.append(_atom(current))
            current = []
            i += 1
            continue
        current.append(tok)
        i += 1
    if current:
        args.append(_atom(current))
    return args, i


def _atom(tokens: list[Token]) -> object:
    if not tokens:
        return None
    strings = [t.value for t in tokens if t.kind == "string"]
    idents = [t.value for t in tokens if t.kind == "ident"]
    numbers = [t.value for t in tokens if t.kind == "number"]
    text = " ".join(t.value for t in tokens)
    return {
        "strings": strings,
        "idents": idents,
        "numbers": numbers,
        "text": text,
        "offset": tokens[0].offset,
        "tokens": [(t.kind, t.value) for t in tokens],
    }


def extract_calls(tokens: list[Token]) -> tuple[list[Call], dict[str, str]]:
    calls: list[Call] = []
    locals_map: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind == "ident" and tok.value == "new" and i + 1 < len(tokens):
            j = i + 1
            qual: list[str] = []
            while j < len(tokens) and tokens[j].kind == "ident":
                qual.append(tokens[j].value)
                j += 1
                if j < len(tokens) and tokens[j].kind == "symbol" and tokens[j].value == ".":
                    j += 1
                    continue
                break
            if j < len(tokens) and tokens[j].kind == "symbol" and tokens[j].value == "(":
                args, nxt = _parse_args(tokens, j)
                calls.append(Call(qualifier=qual[:-1], name=qual[-1] if qual else "new", args=args, offset=tok.offset, is_constructor=True))
                i = nxt
                continue
        if tok.kind == "ident":
            j = i
            qual = [tokens[j].value]
            j += 1
            while j + 1 < len(tokens) and tokens[j].kind == "symbol" and tokens[j].value == "." and tokens[j + 1].kind == "ident":
                qual.append(tokens[j + 1].value)
                j += 2
            if j < len(tokens) and tokens[j].kind == "symbol" and tokens[j].value == "(":
                args, nxt = _parse_args(tokens, j)
                calls.append(Call(qualifier=qual[:-1], name=qual[-1], args=args, offset=tok.offset, is_constructor=False))
                i = nxt
                continue
            # String name = "AES";
            if (
                i + 3 < len(tokens)
                and tokens[i].value in {"String", "final"}
            ):
                k = i
                if tokens[k].value == "final":
                    k += 1
                if k + 3 < len(tokens) and tokens[k].kind == "ident" and tokens[k].value == "String":
                    name_tok = tokens[k + 1]
                    eq = tokens[k + 2]
                    val = tokens[k + 3]
                    if name_tok.kind == "ident" and eq.kind == "symbol" and eq.value == "=" and val.kind == "string":
                        locals_map[name_tok.value] = val.value
        i += 1
    # ident = "literal";
    i = 0
    while i + 2 < len(tokens):
        if (
            tokens[i].kind == "ident"
            and tokens[i + 1].kind == "symbol"
            and tokens[i + 1].value == "="
            and tokens[i + 2].kind == "string"
        ):
            locals_map[tokens[i].value] = tokens[i + 2].value
        i += 1
    return calls, locals_map


def _concat_string(arg: dict, locals_map: dict[str, str]) -> tuple[Optional[str], Optional[str]]:
    """Fold ``ALG + "/ECB/PKCS5Padding"`` / ``"AES" + mode`` when every piece is a
    literal or a string constant bound in the file.  Returns (value, variable)."""
    toks = arg.get("tokens") or []
    if not any(k == "symbol" and v == "+" for k, v in toks):
        return None, None
    pieces: list[str] = []
    var: Optional[str] = None
    expect_operand = True
    for kind, value in toks:
        if kind == "symbol" and value == "+":
            expect_operand = True
            continue
        if kind == "symbol" and value in {"(", ")"}:
            continue
        if not expect_operand:
            return None, None
        if kind == "string":
            pieces.append(value)
        elif kind == "ident" and value in locals_map:
            pieces.append(locals_map[value])
            var = var or value
        elif kind == "ident" and value in {"String", "valueOf", "toString"}:
            continue
        else:
            return None, None
        expect_operand = False
    return ("".join(pieces) if pieces else None), var


def _first_string(arg: object, locals_map: dict[str, str]) -> tuple[Optional[str], bool, Optional[str]]:
    if not isinstance(arg, dict):
        return None, False, None
    folded, folded_var = _concat_string(arg, locals_map)
    if folded:
        return folded, True, folded_var
    if arg.get("strings"):
        # A literal that is itself an argument of a lookup call
        # (props.getProperty("crypto.alg"), System.getenv("ALG"), cfg.getString(..))
        # names a *configuration key*, not an algorithm: the value is dynamic.
        toks = arg.get("tokens") or []
        callee = None
        for kind, value in toks:
            if kind == "string":
                break
            if kind == "symbol" and value == "(" and callee not in (None, "String", "valueOf", "toString"):
                return None, False, callee
            if kind == "ident":
                callee = value
        return str(arg["strings"][0]), True, None
    for ident in arg.get("idents") or []:
        if ident in locals_map:
            return locals_map[ident], True, ident
        if ident not in {"String", "new", "byte", "getBytes"}:
            return None, False, ident
    return None, False, None


def _first_number(arg: object) -> Optional[int]:
    if not isinstance(arg, dict):
        return None
    for raw in arg.get("numbers") or []:
        try:
            if str(raw).lower().startswith("0x"):
                return int(raw, 16)
            return int(raw)
        except ValueError:
            continue
    return None


def _looks_hardcoded_bytes(arg: object) -> tuple[bool, Optional[int]]:
    if not isinstance(arg, dict):
        return False, None
    text = str(arg.get("text") or "")
    strings = arg.get("strings") or []
    if "getBytes" in (arg.get("idents") or []) and strings:
        return True, len(str(strings[0])) * 8
    if "byte" in (arg.get("idents") or []) and (arg.get("numbers") or []):
        return True, len(arg.get("numbers") or []) * 8
    if "new byte" in text.replace("  ", " "):
        return True, max(len(arg.get("numbers") or []), 1) * 8
    return False, None


def _tls_algo(raw: str) -> str:
    key = raw.upper().replace(" ", "")
    return TLS_MAP.get(key, "TLS" if "TLS" in key or "SSL" in key else raw)


def extract_crypto_events(source: str) -> list[CryptoEvent]:
    tokens = tokenize(source)
    calls, locals_map = extract_calls(tokens)
    events: list[CryptoEvent] = []
    pending_key_size: list[tuple[int, Optional[int]]] = []

    for call in calls:
        type_name = call.qualifier[-1] if call.qualifier else call.name
        if call.is_constructor and call.name in {"SecretKeySpec", "PBEKeySpec"}:
            if call.name == "PBEKeySpec":
                events.append(
                    CryptoEvent(
                        start=call.offset,
                        api_type=ApiType.KEY_GENERATOR.value,
                        algorithm="PBKDF2",
                        purpose="PASSWORD_HASHING",
                        library="javax.crypto",
                        raw_transformation="PBEKeySpec",
                    )
                )
                continue
            algo = None
            literal = False
            varname = None
            if call.args:
                algo, literal, varname = _first_string(call.args[-1], locals_map)
            hardcoded, bits = (False, None)
            if call.args:
                hardcoded, bits = _looks_hardcoded_bytes(call.args[0])
            parsed = parse_transformation(algo) if algo else None
            events.append(
                CryptoEvent(
                    start=call.offset,
                    api_type=ApiType.HARDCODED_KEY.value if hardcoded else ApiType.SECRET_KEY_SPEC.value,
                    algorithm=parsed.algorithm if parsed else (algo or "UNKNOWN"),
                    purpose=Purpose.KEY_GENERATION.value,
                    library="javax.crypto",
                    is_string_literal=literal,
                    is_hardcoded_key=hardcoded,
                    hardcoded_key_length=bits,
                    variable_name=varname,
                    raw_transformation=algo,
                    is_from_local_variable=bool(varname),
                )
            )
            continue

        if call.name in {"setHostnameVerifier", "setDefaultHostnameVerifier"}:
            events.append(
                CryptoEvent(
                    start=call.offset,
                    api_type=ApiType.KEY_AGREEMENT.value,
                    algorithm="TLS",
                    purpose=Purpose.NETWORK_ENCRYPTION.value,
                    library="javax.net.ssl",
                    raw_transformation=call.name,
                )
            )
            continue

        if call.name == "init" and call.args:
            size = _first_number(call.args[0])
            if size is not None:
                pending_key_size.append((call.offset, size))
            continue
        if call.name == "initialize" and call.args:
            size = _first_number(call.args[0])
            if size is not None:
                pending_key_size.append((call.offset, size))
            continue

        spec = GETINSTANCE_APIS.get(type_name) or GETINSTANCE_APIS.get(call.name)
        if spec is None or call.name != "getInstance":
            continue
        api_type, purpose, library = spec
        raw, literal, varname = (None, False, None)
        if call.args:
            raw, literal, varname = _first_string(call.args[0], locals_map)
        parsed = parse_transformation(raw) if raw else None
        algorithm = parsed.algorithm if parsed else (raw or "UNKNOWN")
        mode = parsed.mode if parsed else None
        padding = parsed.padding if parsed else None
        if type_name == "SSLContext" and raw:
            algorithm = _tls_algo(raw)
        if type_name == "KeyStore" and raw:
            algorithm = raw.upper()
        if type_name == "KeyAgreement" and raw:
            upper = raw.upper()
            algorithm = "ECDH" if "ECDH" in upper else ("DH" if upper in {"DH", "DIFFIEHELLMAN"} else upper)
        if type_name == "SecureRandom" and raw:
            algorithm = "SHA1PRNG" if raw.upper() == "SHA1PRNG" else "CSPRNG"
        if type_name == "SecretKeyFactory" and raw:
            upper = raw.upper()
            if upper.startswith("PBKDF2") or upper.startswith("PBE") or upper in {"SCRYPT", "BCRYPT", "ARGON2"}:
                purpose = "PASSWORD_HASHING"
                algorithm = "PBKDF2" if upper.startswith("PBKDF2") else algorithm
        if type_name == "CertificateFactory" and raw:
            algorithm = raw.upper().replace(".", "")
        if len(call.args) > 1 and isinstance(call.args[1], dict):
            provider = None
            if call.args[1].get("strings"):
                provider = call.args[1]["strings"][0]
            if provider == "BC":
                library = "BouncyCastle"
        events.append(
            CryptoEvent(
                start=call.offset,
                api_type=api_type,
                algorithm=algorithm,
                purpose=purpose,
                library=library,
                mode=mode,
                padding=padding,
                is_string_literal=literal or bool(raw),
                variable_name=varname,
                raw_transformation=raw,
                is_from_local_variable=bool(varname) and not literal if varname and not raw else bool(varname),
            )
        )

    for event in events:
        if event.api_type in {ApiType.KEY_GENERATOR.value, ApiType.KEY_PAIR_GENERATOR.value} and event.key_size is None:
            later = [size for offset, size in pending_key_size if offset >= event.start]
            if later:
                event.key_size = later[0]
    return events
