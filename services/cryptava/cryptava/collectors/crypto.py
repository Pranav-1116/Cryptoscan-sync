"""CBOM: the cryptography on this host — libraries, certificates, keys (public facts
only), and the configuration that decides which algorithms are allowed.

What is read:

* **crypto libraries** — every OpenSSL/GnuTLS/NSS/libgcrypt/libsodium/Mbed TLS/
  wolfSSL/BoringSSL/Nettle/liboqs shared object owned by a package or found under
  ``/usr/local`` and ``/opt`` (a hand-built OpenSSL is exactly what a CBOM must find);
* **which running process loaded which library** — ``/proc/<pid>/maps``;
* **certificates on disk** in the usual server locations (private-key files are never
  parsed), plus a count of the system trust store;
* **SSH** host public keys and ``sshd_config`` algorithm lists;
* **TLS configuration** — ``openssl.cnf`` system defaults, RHEL crypto-policies,
  nginx / Apache / HAProxy / PostgreSQL TLS directives, Java ``java.security``.

Usage states follow the evidence: a library's algorithm list is ``SUPPORTED``; a config
directive is ``CONFIGURED``; a handshake (network plane) is ``NEGOTIATED``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import struct
from typing import Any

from cryptava.collectors import Context, certs
from cryptava.util import slug
from cryptava.x509 import certificates_in

LIBRARY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenSSL", re.compile(r"^lib(?:ssl|crypto)\.so(?:\.[\d.]+[a-z]?)?$")),
    ("GnuTLS", re.compile(r"^libgnutls\.so(?:\.[\d.]+)?$")),
    ("NSS", re.compile(r"^libnss3\.so$")),
    ("Libgcrypt", re.compile(r"^libgcrypt\.so(?:\.[\d.]+)?$")),
    ("libsodium", re.compile(r"^libsodium\.so(?:\.[\d.]+)?$")),
    ("Mbed TLS", re.compile(r"^libmbed(?:crypto|tls)\.so(?:\.[\d.]+)?$")),
    ("wolfSSL", re.compile(r"^libwolfssl\.so(?:\.[\d.]+)?$")),
    ("BoringSSL", re.compile(r"^libboringssl(?:-dynamic)?\.so$")),
    ("Nettle", re.compile(r"^libnettle\.so(?:\.[\d.]+)?$")),
    ("liboqs", re.compile(r"^liboqs\.so(?:\.[\d.]+)?$")),
    ("Java runtime (JCA/JCE)", re.compile(r"^libjvm\.so$")),
]

#: vendor-declared capability per library family (the strongest honest state is SUPPORTED)
LIBRARY_CAPABILITIES = {
    "OpenSSL": ["TLSv1.2", "AES-GCM", "ChaCha20-Poly1305", "RSA", "ECDSA", "ECDH", "SHA-256", "SHA-384"],
    "GnuTLS": ["TLSv1.2", "TLSv1.3", "AES-GCM", "ChaCha20-Poly1305", "RSA", "ECDSA", "Ed25519"],
    "NSS": ["TLSv1.2", "TLSv1.3", "AES-GCM", "ChaCha20-Poly1305", "RSA", "ECDSA"],
    "Libgcrypt": ["AES", "ChaCha20", "RSA", "ECDSA", "Ed25519", "SHA-256", "SHA-3"],
    "libsodium": ["XChaCha20-Poly1305", "AES-256-GCM", "Ed25519", "X25519", "BLAKE2b", "Argon2id"],
    "Mbed TLS": ["TLSv1.2", "AES-GCM", "RSA", "ECDSA", "SHA-256"],
    "wolfSSL": ["TLSv1.2", "TLSv1.3", "AES-GCM", "ChaCha20-Poly1305", "RSA", "ECDSA"],
    "BoringSSL": ["TLSv1.2", "TLSv1.3", "AES-GCM", "ChaCha20-Poly1305", "X25519", "ECDSA"],
    "Nettle": ["AES", "ChaCha20", "RSA", "ECDSA", "Ed25519", "SHA-256"],
    "liboqs": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA"],
}

LIB_DIRS = ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/local/lib", "/usr/local/lib64"]
EXTRA_LIB_DIRS = ["/usr/local", "/opt"]

CERT_DIRS = [
    "/etc/ssl", "/etc/pki/tls", "/etc/pki/ca-trust/source/anchors", "/etc/nginx", "/etc/apache2",
    "/etc/httpd", "/etc/haproxy", "/etc/postfix", "/etc/dovecot", "/etc/letsencrypt/live",
    "/etc/ldap", "/etc/openldap", "/etc/postgresql", "/var/lib/postgresql", "/etc/kubernetes/pki",
    "/etc/docker/certs.d", "/etc/ipsec.d/certs", "/etc/swanctl/x509", "/etc/openvpn", "/usr/local/etc",
    "/opt", "/certs", "/srv",
]
CERT_EXCLUDE = ("/etc/ssl/certs/", "/usr/share/ca-certificates/", "/etc/pki/ca-trust/extracted/",
                "/etc/pki/tls/certs/ca-bundle", "/etc/ssl/cert.pem")
CERT_SUFFIXES = (".pem", ".crt", ".cer", ".der", ".cert")
TRUST_STORES = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"]

SSH_KEY_TYPES = {
    "ssh-ed25519": ("Ed25519", 256, None), "ssh-ed448": ("Ed448", 456, None),
    "ecdsa-sha2-nistp256": ("ECDSA", 256, "P-256"), "ecdsa-sha2-nistp384": ("ECDSA", 384, "P-384"),
    "ecdsa-sha2-nistp521": ("ECDSA", 521, "P-521"), "ssh-dss": ("DSA", 1024, None), "ssh-rsa": ("RSA", None, None),
}
SSHD_LISTS = {"ciphers": "Ciphers", "macs": "MACs", "kexalgorithms": "KexAlgorithms",
              "hostkeyalgorithms": "HostKeyAlgorithms", "pubkeyacceptedalgorithms": "PubkeyAcceptedAlgorithms",
              "pubkeyacceptedkeytypes": "PubkeyAcceptedAlgorithms", "casignaturealgorithms": "CASignatureAlgorithms"}
IGNORED_PROCESSES = {"sh", "bash", "dash", "ash", "zsh", "ps", "grep", "sleep", "cat", "less", "cryptava"}


# --------------------------------------------------------------------------- #
# libraries
# --------------------------------------------------------------------------- #

def _family(basename: str) -> str | None:
    for family, pattern in LIBRARY_PATTERNS:
        if pattern.match(basename):
            return family
    return None


def _version_from(package_version: str | None, basename: str) -> str | None:
    if package_version:
        match = re.match(r"(?:\d+:)?(\d+(?:\.\d+){1,3}[a-z]?)", package_version)
        if match:
            return match.group(1)
    match = re.search(r"\.so\.([\d.]+[a-z]?)$", basename)
    return match.group(1) if match else None


def _openssl_extras(version: str | None) -> tuple[list[str], dict[str, Any]]:
    extra: list[str] = []
    facts: dict[str, Any] = {}
    if not version:
        return extra, facts
    parts = [int(x) for x in re.findall(r"\d+", version)[:2]] + [0, 0]
    major, minor = parts[0], parts[1]
    if (major, minor) >= (1, 1):
        extra += ["TLSv1.3", "X25519", "Ed25519"]
    if (major, minor) >= (3, 5):
        extra += ["ML-KEM-768", "X25519MLKEM768", "ML-DSA-65", "SLH-DSA"]
        facts["pqc_native"] = True
    elif major >= 1:
        facts["pqc_native"] = False
    return extra, facts


def _realpath(ctx: Context, path: str) -> str:
    return ctx.view.resolve(path)


def _library(ctx: Context, family: str, path: str, *, in_container: bool = False) -> str:
    real = path if in_container else _realpath(ctx, path)
    key = f"{'ctr:' if in_container else ''}{real}"
    if key in ctx.libraries:
        return ctx.libraries[key]
    basename = real.rsplit("/", 1)[-1]
    owner = None if in_container else (ctx.file_owner.get(real) or ctx.file_owner.get(path))
    package = ctx.packages.get(owner) if owner else None
    version = _version_from(package["version"] if package else None, basename)
    ref = ctx.obs.asset(f"lib:{slug(family)}:{slug(real, limit=100)}", "LIBRARY",
                        f"{family} {version or ''}".strip(),
                        identity={"name": family, "version": version or "unknown",
                                  "path": f"{ctx.fqdn}:{real}" if in_container else real},
                        attributes={"family": family, "version": version, "path": real, "package": owner,
                                    "package_version": package["version"] if package else None,
                                    "in_container_filesystem": in_container or None},
                        source="cryptava-libs")
    ctx.libraries[key] = ref
    ev = ctx.obs.observe(ref, "STATIC_OBSERVED", {
        "library": family, "version": version, "path": real, "package": owner, "host": ctx.fqdn,
        "source": "package file list" if owner else "shared-object scan",
    }, layer="PLATFORM", source="cryptava-libs")
    if package:
        ctx.obs.relate(ref, "part_of", package["ref"], basis="DEPLOYMENT_CONFIG", evidence=[ev])
    else:
        ctx.obs.relate(ref, "hosted_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
    capabilities = list(LIBRARY_CAPABILITIES.get(family, []))
    extra_facts: dict[str, Any] = {}
    if family == "OpenSSL":
        extra, extra_facts = _openssl_extras(version)
        capabilities += extra
    if capabilities:
        ctx.obs.observe(ref, "VENDOR_DECLARED", {
            "supported_algorithms": sorted(set(capabilities)), "library": family, "version": version,
            "basis": f"{family} published capability for this release line", **extra_facts,
        }, layer="PLATFORM", source="cryptava-libs")
    ctx.vendor_links.append((ref, family, family, version, "crypto library family"))
    return ref


def _static_libraries(ctx: Context) -> int:
    count = 0
    for path in sorted(ctx.file_owner):
        if _family(path.rsplit("/", 1)[-1]) and ctx.view.exists(path):
            if not os.path.islink(ctx.view.path(path)):
                _library(ctx, _family(path.rsplit("/", 1)[-1]), path)
                count += 1
    for directory in EXTRA_LIB_DIRS:
        if not ctx.view.exists(directory):
            continue
        for path in ctx.view.walk_files(directory, max_depth=5, max_files=20000):
            basename = path.rsplit("/", 1)[-1]
            family = _family(basename)
            if family and path not in ctx.file_owner and not os.path.islink(ctx.view.path(path)):
                _library(ctx, family, path)
                count += 1
    return count


def _same_root(ctx: Context, pid: int) -> bool:
    try:
        a = os.stat(ctx.view.proc / str(pid) / "root")
        b = os.stat(ctx.view.root)
        return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)
    except OSError:
        return False


def _runtime_libraries(ctx: Context) -> tuple[int, int, int]:
    """(processes inspected, processes denied, process→library edges)."""
    inspected = denied = edges = 0
    for pid, proc in sorted(ctx.processes.items()):
        if proc["comm"] in IGNORED_PROCESSES:
            continue
        maps, reason = ctx.view.proc_text_or_reason(f"{pid}/maps", limit=8 * 1024 * 1024)
        if maps is None:
            denied += reason == "denied"  # an exited process is not an access gap
            continue
        inspected += 1
        loaded: dict[str, str] = {}
        for line in maps.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6 or not parts[5].startswith("/"):
                continue
            path = parts[5].replace(" (deleted)", "")
            family = _family(path.rsplit("/", 1)[-1])
            if family:
                loaded[path] = family
        if not loaded:
            continue
        same = _same_root(ctx, pid)
        svc = ctx.services.get(proc["comm"])
        if svc is None:
            svc = ctx.obs.asset(f"svc:{slug(proc['comm'])}", "SERVICE", proc["comm"],
                                identity={"name": proc["comm"], "host": ctx.fqdn},
                                attributes={"executable": proc.get("exe")}, source="cryptava-proc",
                                environment=ctx.environment)
            ctx.services[proc["comm"]] = svc
        for path, family in sorted(loaded.items()):
            lib = _library(ctx, family, path, in_container=not same)
            ev = ctx.obs.observe(svc, "RUNTIME_OBSERVED", {
                "loaded_library": family, "path": path, "executable": proc.get("exe"), "host": ctx.fqdn,
                "source": "/proc/<pid>/maps",
            }, layer="PLATFORM", source="cryptava-maps")
            ctx.obs.relate(svc, "runs_on", ctx.host_ref, basis="RUNTIME_OBSERVATION", evidence=[ev])
            ctx.obs.relate(svc, "uses_crypto_library", lib, basis="RUNTIME_OBSERVATION", evidence=[ev])
            edges += 1
    return inspected, denied, edges


# --------------------------------------------------------------------------- #
# certificates
# --------------------------------------------------------------------------- #

def _certificates_on_disk(ctx: Context) -> tuple[int, int]:
    found = skipped_keys = 0
    dirs = list(dict.fromkeys(CERT_DIRS + list(ctx.config.get("cert_dirs") or [])))
    max_certs = int(ctx.config.get("max_certificates", 500))
    for directory in dirs:
        if not ctx.view.exists(directory):
            continue
        for path in ctx.view.walk_files(directory, max_depth=5, max_files=5000, suffixes=CERT_SUFFIXES):
            if path.startswith(CERT_EXCLUDE) or "/private/" in path:
                continue
            try:
                if os.path.getsize(ctx.view.host_path(path)) > 1024 * 1024:
                    continue
            except OSError:
                continue
            data = ctx.view.read_bytes(path, limit=1024 * 1024) or b""
            if b"PRIVATE KEY" in data:
                skipped_keys += 1  # never parsed: a key file is not a certificate fact
                continue
            for der in certificates_in(data)[:50]:
                registered = certs.register(ctx, der, layer="PLATFORM", source="cryptava-certfile", where=path)
                if not registered:
                    continue
                ref, ev, _cert = registered
                ctx.obs.relate(ref, "hosted_on", ctx.host_ref, basis="CONFIGURATION", evidence=[ev])
                found += 1
                if found >= max_certs:
                    return found, skipped_keys
    return found, skipped_keys


def _trust_store(ctx: Context) -> None:
    for path in TRUST_STORES:
        data = ctx.view.read_bytes(path, limit=4 * 1024 * 1024)
        if not data:
            continue
        ders = certificates_in(data)
        sha1 = 0
        from cryptava.x509 import CertificateError, parse_der
        for der in ders:
            try:
                if parse_der(der)["signature_algorithm"] in certs.WEAK_SIGNATURES:
                    sha1 += 1
            except CertificateError:
                continue
        ctx.obs.observe(ctx.host_ref, "STATIC_OBSERVED", {
            "trust_store": path, "trusted_root_certificates": len(ders), "weak_signature_roots": sha1,
            "role": "system-trust-store",
        }, layer="PLATFORM", source="cryptava-truststore")
        return


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

def _ssh_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    (length,) = struct.unpack(">I", blob[offset:offset + 4])
    return blob[offset + 4:offset + 4 + length], offset + 4 + length


def ssh_key_facts(line: str) -> dict[str, Any] | None:
    parts = line.strip().split()
    if len(parts) < 2 or parts[0] not in SSH_KEY_TYPES:
        return None
    try:
        blob = base64.b64decode(parts[1])
    except ValueError:
        return None
    algorithm, bits, curve = SSH_KEY_TYPES[parts[0]]
    if parts[0] == "ssh-rsa":
        try:
            _kind, offset = _ssh_string(blob, 0)
            _e, offset = _ssh_string(blob, offset)
            modulus, _ = _ssh_string(blob, offset)
            bits = int.from_bytes(modulus, "big").bit_length()
        except (struct.error, ValueError):
            bits = None
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"algorithm": algorithm, "key_size": bits, "curve": curve, "key_type": parts[0],
            "fingerprint": fingerprint}


def _sshd_config(ctx: Context) -> tuple[dict[str, list[str]], list[str]]:
    settings: dict[str, list[str]] = {}
    files: list[str] = []

    def read(path: str, depth: int = 0) -> None:
        if depth > 3:
            return
        text = ctx.view.read_text(path, limit=1024 * 1024)
        if text is None:
            return
        files.append(path)
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, value = line.partition(" ")
            if "=" in key:
                key, _, value = line.partition("=")
            key, value = key.strip().lower(), value.strip().strip('"')
            if key == "match":
                break  # Match blocks scope the rest; global settings end here
            if key == "include":
                for pattern in value.split():
                    pattern = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                    directory, _, glob = pattern.rpartition("/")
                    for included in ctx.view.glob(directory or "/", glob):
                        read(included, depth + 1)
                continue
            if key in SSHD_LISTS and SSHD_LISTS[key] not in settings:  # first value wins
                settings[SSHD_LISTS[key]] = [v.strip() for v in value.split(",") if v.strip()]
            elif key in {"hostkey", "permitrootlogin", "passwordauthentication", "protocol"}:
                settings.setdefault(key, []).append(value)
    read("/etc/ssh/sshd_config")
    return settings, files


def _ssh(ctx: Context) -> int:
    keys = 0
    sshd = ctx.services.get("sshd")
    settings, files = _sshd_config(ctx)
    config_ev = None
    target = sshd or ctx.host_ref
    for name, values in settings.items():
        if name not in SSHD_LISTS.values():
            continue
        enabled = [v.lstrip("+^") for v in values if not v.startswith("-")]
        config_ev = ctx.obs.observe(target, "CONFIGURED", {
            "algorithms": enabled, "setting": f"sshd {name}", "raw": ",".join(values)[:600],
            "host": ctx.fqdn, "path": files[0] if files else "/etc/ssh/sshd_config",
        }, layer="NETWORK_TRANSPORT", source="cryptava-sshd")
    if files and not any(name in settings for name in SSHD_LISTS.values()):
        config_ev = ctx.obs.observe(target, "CONFIGURED", {
            "setting": "sshd algorithm lists", "value": "OpenSSH compiled-in defaults (no Ciphers/MACs/KexAlgorithms set)",
            "host": ctx.fqdn, "path": files[0],
        }, layer="NETWORK_TRANSPORT", source="cryptava-sshd")
    for path in ctx.view.glob("/etc/ssh", "ssh_host_*_key.pub"):
        text = ctx.view.read_text(path, limit=16384) or ""
        facts = ssh_key_facts(text)
        if not facts:
            continue
        ref = ctx.obs.asset(f"sshkey:{slug(facts['fingerprint'], limit=60)}", "KEY_METADATA",
                            f"SSH host key {facts['algorithm']} ({ctx.hostname})",
                            identity={"name": f"ssh-host-key:{facts['fingerprint']}"},
                            attributes={**facts, "path": path, "host": ctx.fqdn}, source="cryptava-sshd")
        ev = ctx.obs.observe(ref, "STATIC_OBSERVED", {
            "algorithm": facts["algorithm"], "key_size": facts["key_size"], "curve": facts["curve"],
            "protocol": "SSH", "role": "ssh-host-key", "fingerprint": facts["fingerprint"], "path": path,
            "host": ctx.fqdn,
        }, layer="NETWORK_TRANSPORT", source="cryptava-sshd")
        ctx.obs.relate(ref, "hosted_on", ctx.host_ref, basis="CONFIGURATION", evidence=[ev])
        if sshd:
            ctx.obs.relate(sshd, "uses_key", ref, basis="CONFIGURATION", evidence=[e for e in (ev, config_ev) if e])
        keys += 1
    return keys


# --------------------------------------------------------------------------- #
# TLS configuration
# --------------------------------------------------------------------------- #

def _suite_names(value: str) -> list[str]:
    out = []
    for token in re.split(r"[:,\s]+", value.strip().strip('"\'')):
        if not token or token.startswith(("!", "-", "+", "@")):
            continue
        if re.fullmatch(r"[A-Z0-9_]+(?:[-_][A-Z0-9_]+)+", token):
            out.append(token)
    return out


def _openssl_cnf(ctx: Context) -> tuple[int, bool]:
    """System-wide OpenSSL TLS policy. Returns (settings found, runs on library defaults)."""
    count = 0
    seen: set[str] = set()
    read: list[str] = []
    for path in ("/etc/ssl/openssl.cnf", "/usr/lib/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf",
                 "/etc/crypto-policies/back-ends/opensslcnf.config"):
        real = ctx.view.resolve(path)
        if real in seen:  # Debian: /usr/lib/ssl/openssl.cnf -> /etc/ssl/openssl.cnf
            continue
        seen.add(real)
        text = ctx.view.read_text(path, limit=1024 * 1024)
        if not text:
            continue
        read.append(path)
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if "=" not in line:
                continue
            key, _, value = (part.strip() for part in line.partition("="))
            lowered = key.lower()
            facts: dict[str, Any] | None = None
            if lowered in {"minprotocol", "maxprotocol"}:
                facts = {"protocol": value, "role": f"system-{'minimum' if lowered == 'minprotocol' else 'maximum'}-protocol"}
            elif lowered == "ciphersuites":
                facts = {"algorithms": [v for v in value.split(":") if v], "setting": "TLS 1.3 Ciphersuites"}
            elif lowered in {"groups", "curves"}:
                facts = {"algorithms": [v for v in value.split(":") if v], "setting": f"TLS {key}"}
            elif lowered == "cipherstring":
                seclevel = re.search(r"@SECLEVEL=(\d)", value)
                facts = {"setting": "CipherString", "value": value,
                         "seclevel": int(seclevel.group(1)) if seclevel else None}
                names = _suite_names(value)
                if names:
                    facts["algorithms"] = names
            elif lowered == "signaturealgorithms":
                facts = {"algorithms": [v for v in value.split(":") if v], "setting": "SignatureAlgorithms"}
            elif lowered in {"fips", "oqsprovider"} or (lowered == "activate" and "fips" in path):
                facts = {"setting": f"provider {key}", "value": value}
            if facts:
                ctx.obs.observe(ctx.host_ref, "CONFIGURED", {**facts, "path": path, "host": ctx.fqdn},
                                layer="NETWORK_TRANSPORT", source="cryptava-opensslcnf")
                count += 1
    policy = (ctx.view.read_text("/etc/crypto-policies/config", limit=4096) or "").strip()
    if policy:
        ctx.obs.observe(ctx.host_ref, "CONFIGURED", {
            "setting": "system crypto policy", "value": policy.splitlines()[-1].strip(),
            "path": "/etc/crypto-policies/config", "host": ctx.fqdn,
        }, layer="PLATFORM", source="cryptava-cryptopolicy")
        count += 1
    defaults = bool(read) and count == 0
    if defaults:
        # A fact, not a gap: every OpenSSL client/server on this host without its own
        # settings negotiates with the library's compiled-in minimum and cipher list.
        ctx.obs.observe(ctx.host_ref, "CONFIGURED", {
            "setting": "OpenSSL system TLS policy",
            "value": "library defaults — openssl.cnf sets no MinProtocol, CipherString or Ciphersuites",
            "path": read[0], "host": ctx.fqdn,
        }, layer="NETWORK_TRANSPORT", source="cryptava-opensslcnf")
    return count, defaults


def _server_tls(ctx: Context) -> int:
    count = 0
    rules = [
        ("nginx", ["/etc/nginx"], (".conf", ""), {
            "ssl_protocols": "protocols", "ssl_ciphers": "ciphers", "ssl_certificate": "certificate",
            "ssl_ecdh_curve": "groups", "proxy_ssl_protocols": "protocols"}, r"^\s*({keys})\s+([^;]+);"),
        ("apache2", ["/etc/apache2", "/etc/httpd"], (".conf",), {
            "SSLProtocol": "protocols", "SSLCipherSuite": "ciphers", "SSLCertificateFile": "certificate",
            "SSLOpenSSLConfCmd": "openssl-conf"}, r"^\s*({keys})\s+(.+)$"),
        ("haproxy", ["/etc/haproxy"], (".cfg",), {
            "ssl-default-bind-ciphers": "ciphers", "ssl-default-bind-ciphersuites": "ciphers",
            "ssl-default-bind-options": "options"}, r"^\s*({keys})\s+(.+)$"),
        ("postgres", ["/etc/postgresql", "/var/lib/postgresql"], ("postgresql.conf",), {
            "ssl": "enabled", "ssl_min_protocol_version": "min-protocol", "ssl_ciphers": "ciphers",
            "ssl_cert_file": "certificate"}, r"^\s*({keys})\s*=\s*'?([^'#\n]+)'?"),
    ]
    for product, roots, suffixes, keys, template in rules:
        pattern = re.compile(template.format(keys="|".join(re.escape(k) for k in keys)), re.M | re.I)
        target_service = ctx.services.get(product) or ctx.services.get({"apache2": "httpd"}.get(product, ""))
        target = target_service or ctx.host_ref
        for root in roots:
            if not ctx.view.exists(root):
                continue
            for path in ctx.view.walk_files(root, max_depth=4, max_files=400):
                wanted = path.endswith(tuple(s for s in suffixes if s)) or (
                    product == "nginx" and "/sites-enabled/" in path)
                if not wanted:
                    continue
                text = ctx.view.read_text(path, limit=1024 * 1024) or ""
                for match in pattern.finditer(text):
                    key = next(k for k in keys if k.lower() == match.group(1).lower())
                    value = match.group(2).strip().strip('"')
                    kind = keys[key]
                    base = {"setting": f"{product} {key}", "path": path, "host": ctx.fqdn}
                    if kind == "protocols":
                        for token in value.split():
                            if token.startswith(("-", "!")):
                                continue
                            ctx.obs.observe(target, "CONFIGURED", {**base, "protocol": token.lstrip("+"),
                                                                   "role": "enabled-protocol"},
                                            layer="NETWORK_TRANSPORT", source=f"cryptava-{product}")
                    elif kind == "min-protocol":
                        ctx.obs.observe(target, "CONFIGURED", {**base, "protocol": value, "role": "minimum-protocol"},
                                        layer="NETWORK_TRANSPORT", source=f"cryptava-{product}")
                    elif kind == "ciphers":
                        names = _suite_names(value)
                        facts = {**base, "value": value[:600]}
                        if names:
                            facts["algorithms"] = names
                        ctx.obs.observe(target, "CONFIGURED", facts, layer="NETWORK_TRANSPORT",
                                        source=f"cryptava-{product}")
                    elif kind == "groups":
                        ctx.obs.observe(target, "CONFIGURED", {**base, "algorithms": re.split(r"[:,]", value)},
                                        layer="NETWORK_TRANSPORT", source=f"cryptava-{product}")
                    elif kind == "certificate":
                        cert_path = value if value.startswith("/") else None
                        ev = ctx.obs.observe(target, "CONFIGURED", {**base, "certificate_file": value},
                                             layer="NETWORK_TRANSPORT", source=f"cryptava-{product}")
                        data = ctx.view.read_bytes(cert_path, limit=1024 * 1024) if cert_path else None
                        if data and b"PRIVATE KEY" not in data:
                            ders = certificates_in(data)
                            if ders:
                                registered = certs.register(ctx, ders[0], layer="PLATFORM",
                                                            source="cryptava-certfile", where=cert_path)
                                if registered and target_service:
                                    ctx.obs.relate(target_service, "uses_certificate", registered[0],
                                                   basis="CONFIGURATION", evidence=[ev, registered[1]])
                    else:
                        ctx.obs.observe(target, "CONFIGURED", {**base, "value": value[:600]},
                                        layer="NETWORK_TRANSPORT", source=f"cryptava-{product}")
                    count += 1
    return count


def _java_security(ctx: Context) -> int:
    count = 0
    for path in ctx.view.glob("/usr/lib/jvm", "*/conf/security/java.security") + ctx.view.glob(
            "/usr/lib/jvm", "*/jre/lib/security/java.security") + ctx.view.glob("/opt", "*/conf/security/java.security"):
        text = ctx.view.read_text(path, limit=1024 * 1024) or ""
        joined = re.sub(r"\\\n\s*", "", text)
        for key in ("jdk.tls.disabledAlgorithms", "jdk.certpath.disabledAlgorithms"):
            match = re.search(rf"^{re.escape(key)}=(.+)$", joined, re.M)
            if match:
                ctx.obs.observe(ctx.host_ref, "CONFIGURED", {
                    "setting": key, "value": match.group(1).strip()[:800], "path": path, "host": ctx.fqdn,
                }, layer="APPLICATION", source="cryptava-java")
                count += 1
    return count


# --------------------------------------------------------------------------- #
# the plane
# --------------------------------------------------------------------------- #

def collect(ctx: Context) -> None:
    libs = _static_libraries(ctx)
    inspected, denied, edges = _runtime_libraries(ctx)
    certs_found, keys_skipped = _certificates_on_disk(ctx)
    _trust_store(ctx)
    ssh_keys = _ssh(ctx)
    system_settings, openssl_defaults = _openssl_cnf(ctx)
    config_settings = system_settings + _server_tls(ctx) + _java_security(ctx)
    served = len(ctx.served_certificates)
    notes = []
    if denied:
        notes.append(f"{denied} processes' memory maps not readable (root/CAP_SYS_PTRACE needed)")
    if keys_skipped:
        notes.append(f"{keys_skipped} private-key files skipped unread")
    status = "PARTIAL" if denied else "COMPLETE"
    ctx.obs.plane("CBOM · cryptography", status,
                  f"{len(ctx.libraries)} crypto libraries ({edges} loaded by running processes), "
                  f"{len(ctx.certificates)} certificates ({certs_found} on disk, {served} served), "
                  f"{ssh_keys} SSH host keys, {config_settings} TLS/crypto settings"
                  + (" (system TLS policy: OpenSSL library defaults)" if openssl_defaults else "")
                  + (f"; {'; '.join(notes)}" if notes else ""), expected=1, collected=1)
    ctx.obs.cover(f"{ctx.hostname} · processes inspected for crypto libraries", inspected + denied, inspected)
    del libs
