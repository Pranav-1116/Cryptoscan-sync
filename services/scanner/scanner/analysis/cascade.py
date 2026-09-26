"""Crypto dependency & cascade analysis — what depends on each piece of crypto and what breaks when it changes.

A bank does not only need *which algorithm, which key size*; it needs:

* **providers** — the files that actually perform crypto, and every file that (transitively) imports them,
  i.e. the blast radius of changing that one class / module / COBOL program;
* **libraries** — the third-party crypto packages the estate depends on (from manifests *and* from the
  detected API usage), with versions, so an upgrade or a PQC-capable replacement can be planned once;
* **shared key material** — keystores, PEM/cert files, key aliases and secret environment variables referenced
  from more than one place: one key rotation, N consumers;
* **weak parameters** — findings whose key size is below the registry floor for the family;
* **migration waves** — the order in which to change things: leaf providers nobody else depends on can move
  alone; shared providers (crypto utilities, wrappers) must move first *with a compatible interface* because
  everything downstream inherits the change; the largest blast radius gets the earliest wave and the most care.

Everything here is derived from the same static scan (no build system, no network) so it works on
mainframe and vendor code as well as on modern services. Edge extraction is language-aware but deliberately
simple: package/module imports, relative file imports, COBOL ``CALL``/``COPY``, C includes.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, Field

from shared_models.algorithm_registry import parse_algorithm

# --------------------------------------------------------------------------------------- module identity
_JAVA_LIKE = {".java", ".kt", ".kts", ".scala", ".groovy"}
_PY = {".py"}
_JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
_GO = {".go"}
_CS = {".cs", ".vb"}
_COBOL = {".cbl", ".cob", ".cobol", ".cpy", ".pli", ".pl1"}
_C = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".m", ".mm"}
_PHP = {".php"}
_RB = {".rb"}
_RS = {".rs"}

_CAP_TOKEN = re.compile(r"\b[A-Z]\w+\b")
_PKG_RE = re.compile(r"^\s*package\s+([\w.]+)", re.M)
_NS_RE = re.compile(r"^\s*namespace\s+([\w.]+)", re.M)
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+?)(\.\*)?\s*;?\s*$", re.M)
_CS_USING = re.compile(r"^\s*using\s+(?:static\s+)?([\w.]+)\s*;", re.M)
_PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import\s+([\w.,\s]+)|import\s+([\w.]+))", re.M)
_JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\(\s*|import\s+)['"]([^'"]+)['"]""")
_GO_IMPORT = re.compile(r'"([\w./\-]+)"')
_GO_BLOCK = re.compile(r"^\s*import\s*(?:\(([^)]*)\)|\"([^\"]+)\")", re.M | re.S)
_COBOL_PROG = re.compile(r"PROGRAM-ID\s*\.?\s+([\w-]+)", re.I)
_COBOL_CALL = re.compile(r"\bCALL\s+['\"]([\w-]+)['\"]", re.I)
_COBOL_COPY = re.compile(r"\bCOPY\s+([\w-]+)", re.I)
_C_INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.M)
_PHP_INCLUDE = re.compile(r"""(?:require|include)(?:_once)?\s*\(?\s*(?:__DIR__\s*\.\s*)?['"]([^'"]+)['"]""")
_RB_REQUIRE = re.compile(r"""require(?:_relative)?\s+['"]([^'"]+)['"]""")
_RS_USE = re.compile(r"^\s*(?:pub\s+)?use\s+crate::([\w:]+)", re.M)

_MAX_BYTES = 2_000_000


class _Module:
    __slots__ = ("path", "rel", "ext", "names", "imports", "tokens")

    def __init__(self, path: Path, rel: str):
        self.path = path
        self.rel = rel
        self.ext = path.suffix.lower()
        self.names: set[str] = set()      # identities other files may import this file by
        self.imports: set[str] = set()    # raw import targets (resolved later)
        self.tokens: set[str] = set()     # capitalised identifiers — used to narrow wildcard imports


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _module_of(path: Path, rel: str, text: str) -> _Module:
    m = _Module(path, rel)
    stem = path.stem
    ext = m.ext
    rel_noext = rel.rsplit(".", 1)[0]
    if ext in _JAVA_LIKE:
        pkg = _PKG_RE.search(text)
        if pkg:
            m.names.add(f"{pkg.group(1)}.{stem}")
            m.names.add(f"{pkg.group(1)}.*")  # wildcard imports resolve to every class of the package
        m.imports.update(i + ".*" if w else i for i, w in _JAVA_IMPORT.findall(text))
        if any(w for _, w in _JAVA_IMPORT.findall(text)):
            m.tokens = set(_CAP_TOKEN.findall(text))
    elif ext in _PY:
        dotted = rel_noext.replace("/", ".")
        m.names.add(dotted)
        if dotted.endswith(".__init__"):
            m.names.add(dotted[: -len(".__init__")])
        # also register every suffix so `from crypto.utils import x` matches `src/app/crypto/utils.py`
        parts = dotted.split(".")
        for i in range(1, len(parts)):
            m.names.add(".".join(parts[i:]))
        for pkg, names, plain in _PY_IMPORT.findall(text):
            if plain:
                m.imports.add(plain)
            else:
                m.imports.add(pkg)
                for n in names.split(","):  # `from pkg import mod` — mod may itself be a module
                    n = n.strip().split(" as ")[0].strip()
                    if n and n != "*":
                        m.imports.add(f"{pkg}.{n}")
    elif ext in _JS:
        m.names.add(rel_noext)
        if stem == "index":
            m.names.add(rel_noext.rsplit("/", 1)[0] if "/" in rel_noext else "")
        m.imports.update(_JS_IMPORT.findall(text))
    elif ext in _GO:
        d = rel.rsplit("/", 1)[0] if "/" in rel else ""
        m.names.add(d)
        for block, single in _GO_BLOCK.findall(text):
            if single:
                m.imports.add(single)
            else:
                m.imports.update(_GO_IMPORT.findall(block))
    elif ext in _CS:
        ns = _NS_RE.search(text)
        if ns:
            m.names.add(ns.group(1))
        m.imports.update(_CS_USING.findall(text))
    elif ext in _COBOL:
        prog = _COBOL_PROG.search(text)
        m.names.add((prog.group(1) if prog else stem).upper())
        m.names.add(stem.upper())
        m.imports.update(c.upper() for c in _COBOL_CALL.findall(text))
        m.imports.update(c.upper() for c in _COBOL_COPY.findall(text))
    elif ext in _C:
        m.names.add(rel)
        m.names.add(path.name)
        m.imports.update(_C_INCLUDE.findall(text))
    elif ext in _PHP:
        m.names.add(rel)
        m.names.add(path.name)
        m.imports.update(_PHP_INCLUDE.findall(text))
    elif ext in _RB:
        m.names.add(rel_noext)
        m.names.add(stem)
        m.imports.update(_RB_REQUIRE.findall(text))
    elif ext in _RS:
        m.names.add(rel_noext.replace("/", "::").replace("src::", ""))
        m.imports.update(x.replace("::", "::") for x in _RS_USE.findall(text))
    else:
        m.names.add(rel)
    m.names.discard("")
    return m


def _resolve_import(imp: str, importer: _Module, by_name: dict[str, list[str]]) -> list[str]:
    """Map a raw import target to the repo-relative files that provide it (empty for external)."""
    ext = importer.ext
    if ext in _JS or ext in _PHP or ext in _RB or ext in _C:
        if imp.startswith("."):
            base = importer.rel.rsplit("/", 1)[0] if "/" in importer.rel else ""
            parts = (base.split("/") if base else []) if imp.startswith("./") or imp.startswith("../") else []
            for seg in imp.split("/"):
                if seg == "..":
                    if parts:
                        parts.pop()
                elif seg not in (".", ""):
                    parts.append(seg)
            cand = "/".join(parts)
            cand_noext = cand.rsplit(".", 1)[0] if "." in cand.rsplit("/", 1)[-1] else cand
            return by_name.get(cand_noext) or by_name.get(cand) or by_name.get(cand + "/index") or []
        if ext in _C:
            return by_name.get(imp) or by_name.get(imp.rsplit("/", 1)[-1]) or []
        return by_name.get(imp) or []
    if ext in _JAVA_LIKE or ext in _CS:
        hit = by_name.get(imp)
        if hit:
            if imp.endswith(".*"):  # wildcard: only the classes this file actually names
                return [t for t in hit if t.rsplit("/", 1)[-1].rsplit(".", 1)[0] in importer.tokens]
            return hit
        # static import a.b.Class.member / nested a.b.Outer.Inner → the class, never the whole package
        if "." in imp and not imp.endswith(".*"):
            return by_name.get(imp.rsplit(".", 1)[0]) or []
        return []
    if ext in _PY:
        hit = by_name.get(imp)
        if hit:
            return hit
        parts = imp.split(".")
        while len(parts) > 1:
            parts.pop()
            hit = by_name.get(".".join(parts))
            if hit:
                return hit
        return []
    if ext in _GO:
        # module path suffix match: "github.com/bank/core/internal/crypto" → "internal/crypto"
        segs = imp.split("/")
        for i in range(len(segs)):
            hit = by_name.get("/".join(segs[i:]))
            if hit:
                return hit
        return []
    if ext in _COBOL:
        return by_name.get(imp.upper()) or []
    if ext in _RS:
        return by_name.get(imp) or by_name.get(imp.rsplit("::", 1)[0]) or []
    return by_name.get(imp) or []


class DependencyGraph:
    """file → files it imports (edges) and the reverse (dependents)."""

    def __init__(self) -> None:
        self.imports: dict[str, set[str]] = defaultdict(set)
        self.dependents: dict[str, set[str]] = defaultdict(set)
        self.files: set[str] = set()
        self.key_refs: dict[tuple[str, str], set[str]] = defaultdict(set)  # (kind, identifier) → files referencing it

    @classmethod
    def build(cls, files: Iterable[Path], root: Path) -> "DependencyGraph":
        g = cls()
        mods: list[_Module] = []
        by_name: dict[str, list[str]] = defaultdict(list)
        for p in files:
            try:
                rel = p.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = p.as_posix()
            text = _read(p)
            if not text:
                continue
            m = _module_of(p, rel, text)
            mods.append(m)
            g.files.add(rel)
            for kind, ident in key_references(text):
                g.key_refs[(kind, ident)].add(rel)
            for n in m.names:
                by_name[n].append(rel)
        for m in mods:
            for imp in m.imports:
                for target in _resolve_import(imp, m, by_name):
                    if target != m.rel:
                        g.imports[m.rel].add(target)
                        g.dependents[target].add(m.rel)
        return g

    def transitive_dependents(self, start: str, limit: int = 10_000) -> set[str]:
        seen: set[str] = set()
        q = deque(self.dependents.get(start, ()))
        while q and len(seen) < limit:
            f = q.popleft()
            if f in seen:
                continue
            seen.add(f)
            q.extend(self.dependents.get(f, ()))
        return seen


# --------------------------------------------------------------------------------------- libraries
# manifest → (regex on the dependency coordinate, canonical library name)
_LIB_COORDS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p, re.I), name) for p, name in (
        (r"org\.bouncycastle|bcprov|bcpkix|bcpg|bctls", "BouncyCastle"),
        (r"io\.jsonwebtoken|jjwt", "jjwt"),
        (r"com\.nimbusds|nimbus-jose-jwt", "nimbus-jose-jwt"),
        (r"com\.auth0.*java-jwt|java-jwt", "java-jwt"),
        (r"com\.google\.crypto\.tink|tink", "Tink"),
        (r"org\.jasypt|jasypt", "jasypt"),
        (r"commons-codec", "commons-codec"),
        (r"spring-security-crypto|spring-security-core", "spring-security-crypto"),
        (r"org\.apache\.shiro|shiro-core", "shiro"),
        (r"com\.ibm\.crypto|ibmjce|ibmpkcs11impl", "IBM-JCE"),
        (r"^cryptography$|\bcryptography\b(?:[=<>~!]|$)", "python-cryptography"),
        (r"pycryptodome|pycryptodomex|pycrypto", "PyCryptodome"),
        (r"^pynacl|\bpynacl\b", "PyNaCl"),
        (r"^bcrypt\b|\bbcrypt\b", "bcrypt"),
        (r"^passlib|\bpasslib\b", "passlib"),
        (r"^pyjwt|\bpyjwt\b", "PyJWT"),
        (r"python-jose|\bjose\b", "python-jose"),
        (r"paramiko", "paramiko"),
        (r"pyopenssl", "pyOpenSSL"),
        (r"jsonwebtoken", "jsonwebtoken"),
        (r"\bjose\b|\bjws\b", "jose"),
        (r"crypto-js|cryptojs", "crypto-js"),
        (r"node-forge|\bforge\b", "node-forge"),
        (r"bcryptjs|\bbcrypt\b", "bcryptjs"),
        (r"argon2", "argon2"),
        (r"tweetnacl|libsodium-wrappers|sodium-native", "libsodium"),
        (r"golang\.org/x/crypto", "golang.org/x/crypto"),
        (r"github\.com/golang-jwt/jwt|github\.com/dgrijalva/jwt-go", "jwt-go"),
        (r"github\.com/google/tink", "Tink"),
        (r"github\.com/cloudflare/circl", "circl"),
        (r"^ring$|\bring\b", "ring"),
        (r"rustls", "rustls"),
        (r"openssl-sys|^openssl$|\bopenssl\b", "OpenSSL"),
        (r"\baes-gcm\b|\bchacha20poly1305\b|\brsa\b|\bed25519-dalek\b|\bp256\b|\bsha2\b|\bhmac\b", "RustCrypto"),
        (r"System\.Security\.Cryptography|Microsoft\.AspNetCore\.DataProtection", "System.Security.Cryptography"),
        (r"BouncyCastle\.Cryptography|Portable\.BouncyCastle|BouncyCastle\.NetCore", "BouncyCastle"),
        (r"System\.IdentityModel\.Tokens\.Jwt|Microsoft\.IdentityModel", "Microsoft.IdentityModel"),
        (r"libsodium|Sodium\.Core|NSec", "libsodium"),
        (r"phpseclib", "phpseclib"),
        (r"firebase/php-jwt|lcobucci/jwt", "php-jwt"),
        (r"defuse/php-encryption", "php-encryption"),
        (r"paragonie/sodium_compat|paragonie/halite", "libsodium"),
        (r"\brbnacl\b", "RbNaCl"),
        (r"\bjwt\b", "ruby-jwt"),
        (r"\bopenssl\b", "OpenSSL"),
        (r"mbedtls|mbed-tls", "mbedTLS"),
        (r"wolfssl", "wolfSSL"),
        (r"libgcrypt|gnutls", "GnuTLS/libgcrypt"),
        (r"cryptoswift", "CryptoSwift"),
        (r"jwtkit|jwt-kit", "JWTKit"),
        (r"swift-crypto", "swift-crypto"),
    )
)

_MANIFEST_FILES = {
    "libs.versions.toml", "pom.xml", "build.gradle", "build.gradle.kts", "ivy.xml", "build.sbt",
    "package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "Pipfile", "environment.yml",
    "go.mod", "Cargo.toml", "Gemfile", "composer.json", "Package.swift", "Podfile", "pubspec.yaml", "mix.exs",
    "packages.config", "Directory.Packages.props", "vcpkg.json", "conanfile.txt", "CMakeLists.txt",
}
_MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".props", ".nuspec", ".gemspec", ".cabal", ".podspec")

# coordinate + version extractors per manifest family
_POM_DEP = re.compile(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?", re.S)
_GRADLE_DEP = re.compile(r"""['"]([\w.\-]+):([\w.\-]+)(?::([\w.\-+]+))?['"]""")
_NPM_DEP = re.compile(r'"([@\w./\-]+)"\s*:\s*"([^"]*)"')
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:([=<>~!]=?)\s*([\w.*+\-]+))?", re.M)
_GOMOD = re.compile(r"^\s*([\w./\-]+)\s+(v[\w.\-+]+)", re.M)
_CARGO = re.compile(r'^\s*([\w\-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")', re.M)
_GEM = re.compile(r"""gem\s+['"]([\w\-]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""")
_COMPOSER = re.compile(r'"([\w\-]+/[\w\-]+)"\s*:\s*"([^"]*)"')
_NUGET = re.compile(r"""<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?|<package\s+id="([^"]+)"\s+version="([^"]+)\"""", re.I)
_SWIFTPM = re.compile(r"""\.package\(\s*(?:name:\s*"[^"]+",\s*)?url:\s*"([^"]+)"[^)]*?(?:from:\s*"([^"]+)"|exact:\s*"([^"]+)"|\.upToNextMajor\(from:\s*"([^"]+)")?""")


def is_manifest(path: Path) -> bool:
    return path.name in _MANIFEST_FILES or path.name.lower().endswith(_MANIFEST_SUFFIXES)


def _canon_lib(coord: str, ecosystem: str) -> str | None:
    # ecosystem keeps generic names ("jwt", "openssl") from matching across languages
    for pat, name in _LIB_COORDS:
        if pat.search(coord):
            if name == "ruby-jwt" and ecosystem != "rubygems":
                continue
            if name == "jose" and ecosystem != "npm":
                continue
            if name == "RustCrypto" and ecosystem != "cargo":
                continue
            if name == "bcryptjs" and ecosystem != "npm":
                continue
            if name == "bcrypt" and ecosystem != "pypi":
                continue
            if name == "ring" and ecosystem != "cargo":
                continue
            if name == "OpenSSL" and ecosystem not in ("cargo", "pypi", "rubygems", "conan", "vcpkg", "cmake"):
                continue
            return name
    return None


def parse_manifest(path: Path, rel: str) -> list[dict[str, Any]]:
    """→ [{library, coordinate, version, ecosystem, manifest}] for crypto-bearing dependencies only."""
    text = _read(path)
    if not text:
        return []
    name = path.name
    low = name.lower()
    out: list[tuple[str, str, str | None]] = []  # (ecosystem, coordinate, version)
    if name == "pom.xml" or low == "ivy.xml":
        for g, a, v in _POM_DEP.findall(text):
            out.append(("maven", f"{g.strip()}:{a.strip()}", (v or "").strip() or None))
    elif name in ("build.gradle", "build.gradle.kts", "build.sbt"):
        for g, a, v in _GRADLE_DEP.findall(text):
            out.append(("maven", f"{g}:{a}", v or None))
    elif name == "libs.versions.toml":  # gradle version catalog
        versions = dict(re.findall(r'^\s*([\w\-]+)\s*=\s*"([^"]+)"', text.split("[libraries]")[0], re.M))
        for line in text.splitlines():
            mm = re.search(r'module\s*=\s*"([^"]+)"', line)
            if not mm:
                continue
            ref = re.search(r'version\.ref\s*=\s*"([^"]+)"', line)
            inline = re.search(r'\bversion\s*=\s*"([^"]+)"', line)
            out.append(("maven", mm.group(1), (versions.get(ref.group(1)) if ref else None) or (inline.group(1) if inline else None)))
        for g, a, v in re.findall(r'^\s*[\w\-]+\s*=\s*"([\w.\-]+):([\w.\-]+):([\w.\-+]+)"', text, re.M):
            out.append(("maven", f"{g}:{a}", v))
    elif name == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for k, v in (data.get(section) or {}).items():
                out.append(("npm", k, str(v) or None))
    elif name.startswith("requirements") or name in ("Pipfile", "environment.yml"):
        for pkg, _op, ver in _REQ_LINE.findall(text):
            if pkg and not pkg.startswith(("#", "-")):
                out.append(("pypi", pkg.split("[")[0].lower(), ver or None))
    elif name in ("pyproject.toml", "setup.py"):
        for m in re.finditer(r"""['"]([A-Za-z0-9_.\-]+)\s*(?:[=<>~!]=?\s*([\w.*+\-]+))?['"]""", text):
            out.append(("pypi", m.group(1).lower(), m.group(2)))
    elif name == "go.mod":
        for mod, ver in _GOMOD.findall(text):
            out.append(("go", mod, ver))
    elif name == "Cargo.toml":
        for crate, v1, v2 in _CARGO.findall(text):
            out.append(("cargo", crate, v1 or v2 or None))
    elif name == "Gemfile" or low.endswith(".gemspec"):
        for gem, ver in _GEM.findall(text):
            out.append(("rubygems", gem, ver or None))
    elif name == "composer.json":
        for pkg, ver in _COMPOSER.findall(text):
            out.append(("packagist", pkg, ver or None))
    elif low.endswith((".csproj", ".fsproj", ".vbproj", ".props")) or name == "packages.config":
        for a, av, b, bv in _NUGET.findall(text):
            out.append(("nuget", a or b, av or bv or None))
    elif name == "Package.swift":
        for url, v1, v2, v3 in _SWIFTPM.findall(text):
            out.append(("swiftpm", url, v1 or v2 or v3 or None))
    elif name == "Podfile" or low.endswith(".podspec"):
        for m in re.finditer(r"""pod\s+['"]([\w\-/]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", text):
            out.append(("cocoapods", m.group(1), m.group(2)))
    elif name in ("conanfile.txt", "vcpkg.json", "CMakeLists.txt"):
        eco = {"conanfile.txt": "conan", "vcpkg.json": "vcpkg"}.get(name, "cmake")
        for m in re.finditer(r"\b(openssl|mbedtls|wolfssl|libsodium|libgcrypt|gnutls|botan|cryptopp)\b(?:[/@ ]([\w.]+))?", text, re.I):
            out.append((eco, m.group(1).lower(), m.group(2)))
    result = []
    for eco, coord, ver in out:
        lib = _canon_lib(coord, eco)
        if lib:
            result.append({"library": lib, "coordinate": coord, "version": ver, "ecosystem": eco, "manifest": rel})
    return result


# --------------------------------------------------------------------------------------- shared key material
_KEY_FILE = re.compile(r"""['"]([^'"\s]{3,200}\.(?:jks|p12|pfx|pem|key|crt|cer|der|bks|keystore|truststore|kdb|rdb|sth|gpg|asc))['"]""", re.I)
_ENV_KEY = re.compile(r"\b((?:[A-Z][A-Z0-9]*_)*(?:KEY|SECRET|KEYSTORE|TRUSTSTORE|PRIVATE_KEY|CERT|CERTIFICATE|PASSPHRASE|HMAC|SIGNING_KEY|JWT_SECRET|API_KEY|MASTER_KEY|KEK|DEK|LMK|ZMK|ZPK|PVK|CVK|TMK|TPK|TAK|BDK)(?:_[A-Z0-9]+)*)\b")
_ALIAS = re.compile(r"""(?:\b(?:getKey|getCertificate|getEntry|getCertificateChain|setKeyEntry|setCertificateEntry|deleteEntry|containsAlias|GetKey|DescribeKey|getSecretValue|GetSecretValue|access_secret_version|getSecret|GetSecret)\s*\(\s*|\b(?:alias|keyAlias|key_alias|keyId|KeyId|key_id|kid|KeyLabel|key_label|label|LABEL|secretName|SecretId|secret_id|SecretName|KeyName|key_name|keyRef|KEY-LABEL)\s*[=:(]\s*|-alias\s+|KEYLABEL\s*[=(]\s*|LABEL\s*\(\s*)['"]([\w./:@#\-]{2,120})['"]""", re.I)
_ENV_CTX = re.compile(r"""(?:getenv|GetEnvironmentVariable|getProperty|environ(?:\.get)?|env(?:\.get)?|Env::var|std::env::var|os\.Getenv|LookupEnv|ENV\.fetch|ENV|process\.env|Environment)\s*[\[(.]\s*['"]?([A-Z][A-Z0-9_]{2,80})['"]?|\$\{([A-Z][A-Z0-9_]{2,80})(?::-[^}]*)?\}|%([A-Z][A-Z0-9_]{2,80})%|\bsecretKeyRef:\s*\{?\s*name:\s*([\w\-]+)""")
_ENV_NOISE = {"KEY", "SECRET", "CERT", "PRIMARY_KEY", "FOREIGN_KEY", "PUBLIC_KEY", "CACHE_KEY", "ROW_KEY", "PARTITION_KEY", "SORT_KEY", "HASH_KEY", "RANGE_KEY", "MAP_KEY", "DICT_KEY", "SESSION_KEY", "IDEMPOTENCY_KEY", "SHARD_KEY", "ROUTING_KEY", "CERTIFICATE"}


# mainframe / HSM spellings: COBOL "KEY-LABEL PIC X(64) VALUE 'A.B.C'", KGUP "LABEL(A.B.C)", payShield console "A6 01 000 U A.B.C"
_COBOL_LABEL = re.compile(r"""\b[\w-]*(?:LABEL|KEY-?NAME|KEY-?ID|ALIAS|ZPK|ZMK|TMK|TPK|TAK|PVK|CVK|KEK|BDK|IMK)[\w-]*\s+PIC\s+X\(\d+\)\s+VALUE\s+['"]([\w./@#:\-]{2,120})['"]""", re.I)
_KGUP_LABEL = re.compile(r"\bLABEL\(\s*([A-Za-z0-9][\w./@#:\-]{1,120})\s*\)")
_DOTTED_LABEL = re.compile(r"(?m)^[^\n]*\b(?:ZPK|ZMK|TMK|TPK|TAK|PVK|CVK|KEK|LMK|BDK|IMK|KEY|LABEL|AES|DES|RSA)\b[^\n]*?\b([A-Z][A-Z0-9]*(?:\.[A-Z0-9]+){2,})\b")


def key_references(snippet: str) -> list[tuple[str, str]]:
    """→ [(kind, identifier)] — keystore/cert files, secret env vars, key aliases seen in one code snippet."""
    refs: list[tuple[str, str]] = []
    for rx in (_COBOL_LABEL, _KGUP_LABEL, _DOTTED_LABEL):
        for m in rx.finditer(snippet):
            ident = m.group(1)
            if ident.upper() not in {"UNKNOWN", "NONE"} and not ident.replace(".", "").isdigit():
                refs.append(("key_alias", ident))
    for m in _KEY_FILE.finditer(snippet):
        refs.append(("key_file", m.group(1).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]))
    for m in _ENV_CTX.finditer(snippet):
        ident = next(g for g in m.groups() if g)
        if _ENV_KEY.fullmatch(ident) and ident not in _ENV_NOISE and "_" in ident:
            refs.append(("secret_env", ident))
    for m in _ALIAS.finditer(snippet):
        refs.append(("key_alias", m.group(1)))
    return refs


# --------------------------------------------------------------------------------------- report models
class ProviderNode(BaseModel):
    file: str
    algorithms: list[str]
    findings: int
    direct_dependents: int
    transitive_dependents: int
    dependents_sample: list[str] = Field(default_factory=list)
    depends_on_providers: list[str] = Field(default_factory=list)
    code_origin: str | None = None
    wave: int = 1
    rank: int = 0


class LibraryNode(BaseModel):
    library: str
    versions: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    coordinates: list[str] = Field(default_factory=list)
    files_using: int = 0
    findings: int = 0
    algorithms: list[str] = Field(default_factory=list)
    declared_but_unused: bool = False
    used_but_undeclared: bool = False


class SharedKeyNode(BaseModel):
    kind: str
    identifier: str
    files: list[str]
    algorithms: list[str]


class WeakParameter(BaseModel):
    file: str
    line: int
    algorithm: str
    key_size: int
    minimum: int


class MigrationWave(BaseModel):
    wave: int
    why: str
    providers: list[str]
    dependents_affected: int


class SystemNode(BaseModel):
    system: str
    criticality: str | None = None
    owner: str | None = None
    paths: list[str]
    compliance_scopes: list[str] = Field(default_factory=list)  # regulatory scopes declared for this system (CBUAE, PAYMENT, PDPL, PERSONAL_DATA…)
    legal_entity: str | None = None  # group-registry entity code (the supervisory roll-up key: which bank / licensed entity owns this system)
    business_unit: str | None = None
    files: int = 0
    providers: int = 0
    algorithms: list[str] = Field(default_factory=list)
    weak_parameters: int = 0
    depends_on_systems: list[str] = Field(default_factory=list)   # this system imports crypto providers living in those systems
    dependent_systems: list[str] = Field(default_factory=list)    # systems whose files import this system's providers
    earliest_wave: int | None = None


class KeyReferenceNode(BaseModel):
    """Every key identifier the source refers to (keystore file, alias, env var, KMS id) — one file is enough.

    Feeds inventory reconciliation: an identifier here with no matching key-inventory record is
    "in source but in no inventory"; an inventory key matched by none is an orphan.
    """

    kind: str
    identifier: str
    files: int
    sample_files: list[str] = Field(default_factory=list)


class CascadeReport(BaseModel):
    files_in_graph: int
    edges: int
    systems: list[SystemNode] = Field(default_factory=list)
    providers: list[ProviderNode]
    libraries: list[LibraryNode]
    shared_keys: list[SharedKeyNode]
    key_references: list[KeyReferenceNode] = Field(default_factory=list)
    weak_parameters: list[WeakParameter]
    migration_waves: list[MigrationWave]
    summary: dict[str, Any]


# --------------------------------------------------------------------------------------- main analysis
def _scc(adj: dict[str, list[str]]) -> dict[str, int]:
    """Tarjan — node → component id (iterative; provider graphs can be thousands of nodes)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on: set[str] = set()
    stack: list[str] = []
    comp: dict[str, int] = {}
    counter = [0, 0]
    for root in adj:
        if root in index:
            continue
        work = [(root, iter(adj.get(root, ())))]
        index[root] = low[root] = counter[0]; counter[0] += 1
        stack.append(root); on.add(root)
        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter[0]; counter[0] += 1
                    stack.append(w); on.add(w)
                    work.append((w, iter(adj.get(w, ()))))
                    advanced = True
                    break
                if w in on:
                    low[v] = min(low[v], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                u = work[-1][0]
                low[u] = min(low[u], low[v])
            if low[v] == index[v]:
                while True:
                    w = stack.pop(); on.discard(w); comp[w] = counter[1]
                    if w == v:
                        break
                counter[1] += 1
    return comp


def _finding_file(f) -> str:
    return f.source.file_path.split("!", 1)[0]


def _min_key_size(algorithm: str | None) -> int | None:
    if not algorithm:
        return None
    try:
        return parse_algorithm(algorithm).min_key_size
    except Exception:
        return None


def analyse_cascade(findings: list, files: Iterable[Path], root: Path, *, sample: int = 10) -> CascadeReport:
    files = list(files)
    graph = DependencyGraph.build(files, root)

    # providers -------------------------------------------------------------------------------
    per_file: dict[str, list] = defaultdict(list)
    for f in findings:
        if (f.crypto.algorithm or "UNKNOWN") == "UNKNOWN":
            continue
        per_file[_finding_file(f)].append(f)
    providers: list[ProviderNode] = []
    provider_files = set(per_file)
    for file, fs in per_file.items():
        direct = graph.dependents.get(file, set())
        trans = graph.transitive_dependents(file)
        upstream = sorted(p for p in graph.imports.get(file, ()) if p in provider_files)
        providers.append(ProviderNode(
            file=file,
            algorithms=sorted({f.crypto.algorithm for f in fs}),
            findings=len(fs),
            direct_dependents=len(direct),
            transitive_dependents=len(trans),
            dependents_sample=sorted(trans)[:sample],
            depends_on_providers=upstream,
            code_origin=next((f.metadata.code_origin for f in fs if f.metadata.code_origin), None),
        ))
    providers.sort(key=lambda p: (-p.direct_dependents, -p.transitive_dependents, -p.findings, p.file))
    for i, p in enumerate(providers, 1):
        p.rank = i

    # waves: a provider that other providers depend on must move before them. Monoliths have import
    # cycles, so run Kahn over the strongly-connected components — every member of a cycle shares a wave.
    idx = {p.file: p for p in providers}
    comp = _scc({p.file: [u for u in p.depends_on_providers if u in idx] for p in providers})
    comp_up: dict[int, set[int]] = defaultdict(set)
    for p in providers:
        for up in p.depends_on_providers:
            if up in idx and comp[up] != comp[p.file]:
                comp_up[comp[p.file]].add(comp[up])
    comp_wave: dict[int, int] = {}

    def _wave_of(c: int) -> int:
        if c not in comp_wave:
            comp_wave[c] = 1 + max((_wave_of(u) for u in comp_up.get(c, ())), default=0)
        return comp_wave[c]

    for p in providers:
        p.wave = _wave_of(comp[p.file])
    waves: list[MigrationWave] = []
    for w in sorted({p.wave for p in providers}):
        members = [p for p in providers if p.wave == w]
        why = ("shared crypto providers with no crypto upstream — change first, keep the interface compatible; everything downstream inherits the change"
               if w == 1 else f"depend on wave-{w - 1} providers — migrate once those expose the new primitives")
        waves.append(MigrationWave(wave=w, why=why, providers=[p.file for p in members],
                                   dependents_affected=len(set().union(*(set(graph.transitive_dependents(p.file)) for p in members)) if members else set())))

    # libraries -------------------------------------------------------------------------------
    libs: dict[str, LibraryNode] = {}
    for p in files:
        if is_manifest(p):
            try:
                rel = p.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                rel = p.as_posix()
            for dep in parse_manifest(p, rel):
                node = libs.setdefault(dep["library"], LibraryNode(library=dep["library"]))
                if dep["version"] and dep["version"] not in node.versions:
                    node.versions.append(dep["version"])
                if rel not in node.manifests:
                    node.manifests.append(rel)
                if dep["coordinate"] not in node.coordinates:
                    node.coordinates.append(dep["coordinate"])
    used: dict[str, tuple[set[str], int, set[str]]] = {}
    for f in findings:
        lib = f.metadata.library
        if not lib:
            continue
        fl, n, algos = used.setdefault(lib, (set(), 0, set()))
        fl.add(_finding_file(f))
        if f.crypto.algorithm and f.crypto.algorithm != "UNKNOWN":
            algos.add(f.crypto.algorithm)
        used[lib] = (fl, n + 1, algos)
    for lib, (fl, n, algos) in used.items():
        node = libs.setdefault(lib, LibraryNode(library=lib))
        node.files_using, node.findings, node.algorithms = len(fl), n, sorted(algos)
    for node in libs.values():
        node.declared_but_unused = bool(node.manifests) and node.files_using == 0
        node.used_but_undeclared = not node.manifests and node.files_using > 0 and node.library in _THIRD_PARTY_LIBS
    libraries = sorted(libs.values(), key=lambda n: (-n.files_using, -len(n.manifests), n.library))

    # shared key material ------------------------------------------------------------------------
    # whole-file references (the keystore path and the cipher call are rarely on the same line) …
    refs: dict[tuple[str, str], tuple[set[str], set[str]]] = defaultdict(lambda: (set(), set()))
    for key, fl in graph.key_refs.items():
        refs[key][0].update(fl)
    # … plus finding snippets (covers archives, configs and logs that are not in the import graph)
    for f in findings:
        for kind, ident in key_references(f.source.code_snippet or ""):
            refs[(kind, ident)][0].add(_finding_file(f))
    for (kind, ident), (fl, algos) in refs.items():
        for file in fl:
            algos.update(a for p in per_file.get(file, ()) for a in [p.crypto.algorithm] if a and a != "UNKNOWN")
    shared_keys = sorted(
        (SharedKeyNode(kind=k, identifier=i, files=sorted(fl), algorithms=sorted(a)) for (k, i), (fl, a) in refs.items() if len(fl) > 1),
        key=lambda s: (-len(s.files), s.kind, s.identifier),
    )
    key_ref_nodes = sorted(
        (KeyReferenceNode(kind=k, identifier=i, files=len(fl), sample_files=sorted(fl)[:3]) for (k, i), (fl, _a) in refs.items()),
        key=lambda r: (-r.files, r.kind, r.identifier),
    )

    # weak parameters ---------------------------------------------------------------------------
    weak: list[WeakParameter] = []
    for f in findings:
        ks = f.crypto.key_size
        if not ks:
            continue
        floor = _min_key_size(f.crypto.algorithm)
        if floor and ks < floor:
            weak.append(WeakParameter(file=f.source.file_path, line=f.source.line_number, algorithm=f.crypto.algorithm, key_size=ks, minimum=floor))
    weak.sort(key=lambda w: (w.algorithm, w.file, w.line))

    # business systems (optional mapping: .cryptoscan/systems.yml or cryptoscan-systems.yml at the repo root) --
    systems = _systems_rollup(root, graph, providers, weak)

    edges = sum(len(v) for v in graph.imports.values())
    summary = {
        "systems": len(systems),
        "cross_system_edges": sum(len(s.dependent_systems) for s in systems),
        "providers": len(providers),
        "providers_with_dependents": sum(1 for p in providers if p.transitive_dependents),
        "largest_blast_radius": providers[0].model_dump(include={"file", "transitive_dependents", "algorithms"}) if providers else None,
        "libraries": len(libraries),
        "libraries_declared_but_unused": sum(1 for n in libraries if n.declared_but_unused),
        "libraries_used_but_undeclared": sum(1 for n in libraries if n.used_but_undeclared),
        "shared_key_identifiers": len(shared_keys),
        "key_references": len(key_ref_nodes),
        "weak_parameters": len(weak),
        "migration_waves": len(waves),
    }
    return CascadeReport(files_in_graph=len(graph.files), edges=edges, systems=systems, providers=providers, libraries=libraries,
                         shared_keys=shared_keys, key_references=key_ref_nodes, weak_parameters=weak, migration_waves=waves, summary=summary)


# only libraries a manifest parser can recognise may be reported as "used but undeclared";
# rule-pack names (payments/EMV, HSM/Thales, java.security …) and platform APIs never are
SYSTEM_MAP_FILES = (".cryptoscan/systems.yml", ".cryptoscan/systems.yaml", "cryptoscan-systems.yml", "cryptoscan-systems.yaml", "cryptoscan-systems.json")


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [v for v in re.split(r"[,\s]+", value) if v]
    return list(value)


def load_system_map(root: Path) -> list[dict[str, Any]]:
    """[{system, paths:[glob…], criticality?, owner?}] — how the bank names the code (CMDB ids, app codes)."""
    for rel in SYSTEM_MAP_FILES:
        p = root / rel
        if not p.is_file():
            continue
        text = _read(p)
        data: Any = None
        if p.suffix == ".json":
            try:
                data = json.loads(text)
            except ValueError:
                return []
        else:
            try:
                import yaml  # type: ignore

                data = yaml.safe_load(text)
            except Exception:
                return []
        items = data.get("systems") if isinstance(data, dict) else data
        # top-level defaults: a bank normally declares ONE legal_entity / business_unit for the whole repository
        default_entity = str(data.get("legal_entity") or data.get("entity") or "").strip().lower() if isinstance(data, dict) else ""
        default_bu = str(data.get("business_unit") or "").strip() if isinstance(data, dict) else ""
        out = []
        for it in items or []:
            if isinstance(it, dict) and it.get("system") and it.get("paths"):
                out.append({"system": str(it["system"]), "paths": [str(x) for x in (it["paths"] if isinstance(it["paths"], list) else [it["paths"]])],
                            "criticality": it.get("criticality"), "owner": it.get("owner"),
                            # declared business dependencies (CMDB knowledge the code cannot show: runtime calls, queues, batch feeds)
                            "depends_on": [str(x) for x in (it.get("depends_on") or it.get("depends_on_systems") or []) if x],
                            # regulatory scopes that gate policy rules (CBUAE / PAYMENT / CARD / PDPL / PERSONAL_DATA / DIFC …)
                            "compliance_scopes": sorted({str(x).strip().upper() for x in _as_list(it.get("compliance_scopes") or it.get("scopes")) if str(x).strip()}),
                            # legal entity (group registry code) and business unit this system belongs to — the supervisory roll-up key
                            "legal_entity": str(it.get("legal_entity") or it.get("entity") or "").strip().lower() or default_entity or None,
                            "business_unit": str(it.get("business_unit") or "").strip() or default_bu or None})
        return out
    return []


def _system_of(rel: str, sysmap: list[dict[str, Any]]) -> str | None:
    from fnmatch import fnmatch

    best, best_len = None, -1
    for it in sysmap:
        for g in it["paths"]:
            g2 = g.rstrip("/").removesuffix("/**").removesuffix("/*")
            if rel == g2 or rel.startswith(g2 + "/") or fnmatch(rel, g):
                if len(g2) > best_len:
                    best, best_len = it["system"], len(g2)
    return best


def _systems_rollup(root: Path, graph: "DependencyGraph", providers: list[ProviderNode], weak: list[WeakParameter]) -> list[SystemNode]:
    sysmap = load_system_map(root)
    if not sysmap:
        return []
    nodes = {it["system"]: SystemNode(system=it["system"], criticality=it.get("criticality"), owner=it.get("owner"), paths=it["paths"],
                                      compliance_scopes=list(it.get("compliance_scopes") or []), legal_entity=it.get("legal_entity"), business_unit=it.get("business_unit")) for it in sysmap}
    file_sys: dict[str, str | None] = {}
    for f in graph.files:
        file_sys[f] = _system_of(f, sysmap)
        if file_sys[f]:
            nodes[file_sys[f]].files += 1
    algos: dict[str, set[str]] = defaultdict(set)
    up: dict[str, set[str]] = defaultdict(set)
    down: dict[str, set[str]] = defaultdict(set)
    for p in providers:
        s = file_sys.get(p.file) or _system_of(p.file, sysmap)
        if not s:
            continue
        n = nodes[s]
        n.providers += 1
        algos[s].update(p.algorithms)
        n.earliest_wave = p.wave if n.earliest_wave is None else min(n.earliest_wave, p.wave)
        for d in graph.dependents.get(p.file, ()):
            ds = file_sys.get(d)
            if ds and ds != s:
                down[s].add(ds)
                up[ds].add(s)
    for w in weak:
        s = _system_of(w.file.split("!", 1)[0], sysmap)
        if s:
            nodes[s].weak_parameters += 1
    declared = {str(it["system"]): [d for d in (it.get("depends_on") or []) if d in nodes and d != it["system"]] for it in sysmap}
    for s, deps in declared.items():
        for d in deps:
            up[s].add(d)
            down[d].add(s)
    for s, n in nodes.items():
        n.algorithms = sorted(algos[s])
        n.depends_on_systems = sorted(up[s])
        n.dependent_systems = sorted(down[s])
    return sorted(nodes.values(), key=lambda n: (-len(n.dependent_systems), -n.providers, n.system))


_THIRD_PARTY_LIBS = {name for _, name in _LIB_COORDS} | {"BouncyCastle", "jjwt", "nimbus-jose-jwt", "java-jwt", "Tink", "jasypt", "commons-codec", "spring-security-crypto", "shiro"}
_PLATFORM_LIBS = {
    "JCA", "JCE", "JSSE", "JDK", "hashlib", "hmac", "ssl", "secrets", "crypto", "node:crypto", "WebCrypto", "SubtleCrypto",
    "crypto/aes", "crypto/rsa", "crypto/tls", "crypto/sha256", "crypto/rand", "System.Security.Cryptography", "CNG", "CAPI",
    "CommonCrypto", "CryptoKit", "Security.framework", "SecureTransport", "ICSF", "CCA", "RACF", "AT-TLS", "GSKit", "Qc3",
    "OpenSSL", "openssl", "pgcrypto", "DBMS_CRYPTO", "T-SQL", "MySQL", "DB2", "App-Transport-Security", "SSH", "sshd",
}
