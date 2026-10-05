"""NBOM — Network Bill of Materials (CycloneDX 1.5).

What an NBOM is for
-------------------
A CBOM answers "what cryptography does our *code* contain". An NBOM answers
the question a network owner actually gets asked in an audit: **what
cryptography is exposed on the wire, on which listener, terminated by what,
and what breaks when we turn one of them off.**

Those are different inventories and they miss different things. Code scanning
cannot see a load balancer that terminates TLS 1.0 for a legacy partner,
because no repository in the estate mentions it. Network scanning cannot see
an algorithm chosen at runtime from configuration. An estate needs both, and
the parts that overlap are the parts you can corroborate.

Components emitted
------------------
Each becomes a CycloneDX component with a ``cryptographic-asset`` type where
the spec allows it, so an NBOM loads in any CycloneDX 1.5 consumer:

``endpoint``    a listener: host, port, protocol, negotiated TLS version
``certificate`` a leaf served by one or more endpoints
``cipher-suite`` a suite an endpoint actually negotiated
``tunnel``      IPsec / VPN / SSH transport with its declared algorithms
``device``      the network element terminating the above

Dependencies and cascade
------------------------
The ``dependencies`` graph is what makes this more than a list. CycloneDX
models it as ``ref -> dependsOn[]``, and here it carries the real
relationships: an endpoint depends on its certificate and on the suite it
negotiated; a certificate depends on its issuer; a tunnel depends on its key
exchange. :func:`cascade` walks that graph backwards from a weak component to
everything that would be affected by replacing it — the number a migration
programme is planned from, and the one nobody can produce from a spreadsheet.

Honesty rules, inherited from the scanners that feed this:
absence of evidence is never a pass. An endpoint that was never probed is
recorded with ``observed: false`` and contributes to no verdict; it is
reported as unknown rather than counted as healthy.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SPEC_VERSION = "1.5"
_TOOL = {"vendor": "CryptoScan", "name": "nbom-generator", "version": "1.0"}

#: TLS versions that are not acceptable on a network interface.
_DISALLOWED_TLS = {"ssl2", "sslv2", "ssl3", "sslv3", "tls1", "tls10", "tlsv1", "tlsv10",
                   "tls11", "tlsv11"}
_WEAK_TLS = {"tls12", "tlsv12"}  # permitted, but no longer preferred

#: The five TLS 1.3 suites (RFC 8446 §B.4), normalised by _norm().
#: Their names carry no key-exchange token because (EC)DHE is mandatory in
#: TLS 1.3 — there is no static-key mode — so they must not be mistaken for
#: suites that lack forward secrecy.
_TLS13_SUITES = {
    "tlsaes128gcmsha256",
    "tlsaes256gcmsha384",
    "tlschacha20poly1305sha256",
    "tlsaes128ccmsha256",
    "tlsaes128ccm8sha256",
}

#: Substrings that make a cipher suite weak regardless of the rest of it.
_WEAK_SUITE_TOKENS = {
    "null": ("critical", "no encryption"),
    "export": ("critical", "deliberately weakened export-grade key"),
    "anon": ("critical", "anonymous key exchange — no peer authentication"),
    "rc4": ("high", "RC4 is broken"),
    "des-cbc3": ("high", "3DES is withdrawn (Sweet32)"),
    "3des": ("high", "3DES is withdrawn (Sweet32)"),
    "des": ("critical", "single DES"),
    "md5": ("high", "MD5 MAC"),
    "rc2": ("high", "RC2"),
    "idea": ("medium", "IDEA is deprecated"),
    "seed": ("low", "SEED is rarely reviewed"),
}

#: Public-key algorithms a CRQC breaks (NIST IR 8547).
_SHOR_VULNERABLE = ("rsa", "ec", "ecdsa", "ecdh", "dsa", "dh", "ed25519", "ed448", "x25519")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ref(kind: str, *parts: Any) -> str:
    """A stable bom-ref, so two runs over the same estate diff cleanly."""
    raw = "|".join(str(p) for p in parts if p is not None)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def _norm(value: Any) -> str:
    return re.sub(r"[\s_.-]+", "", str(value if value is not None else "")).strip().lower()


def _finding(code: str, severity: str, message: str, ref: str | None = None) -> dict[str, Any]:
    out = {"code": code, "severity": severity, "message": message}
    if ref:
        out["ref"] = ref
    return out


# ------------------------------------------------------------- assessment


def assess_tls_version(version: Any) -> list[dict[str, Any]]:
    key = _norm(version)
    if not key:
        return []
    if key in _DISALLOWED_TLS:
        return [_finding("nbom.tls_version_disallowed", "critical",
                         f"{version} is disallowed for network interfaces",
                         "NIST SP 800-52r2")]
    if key in _WEAK_TLS:
        return [_finding("nbom.tls_version_legacy", "low",
                         f"{version} is permitted but TLS 1.3 is preferred",
                         "NIST SP 800-52r2")]
    return []


def assess_transport_encryption(
    tls_version: Any, cipher_suite: Any, protocol: Any = None,
) -> list[dict[str, Any]]:
    """An observed endpoint that negotiated nothing is carrying plaintext.

    assess_tls_version() returns [] for an absent version, because it grades
    the version it is given and there is nothing to grade. That left the
    worst transport posture — no encryption at all — as the only one the
    NBOM scored clean: an endpoint with TLS 1.0 was critical, and an
    endpoint with no TLS was silent. A real estate scan of 14 listening
    services, every one of them plaintext (PostgreSQL, MySQL, Redis, AMQP
    among them), produced `findings: 0`.

    That also contradicted this module's own rule, stated at the top of the
    file: absence of evidence is never a pass. An observed endpoint with no
    negotiated version and no suite is not missing data — the probe
    succeeded and the answer was "none". Unprobed endpoints are a different
    case and are already excluded by ``observed: false`` before this runs.

    Rated critical, matching a disallowed TLS version rather than sitting
    below it: TLS 1.0 at least authenticates the peer and encrypts the
    stream against a passive observer, and plaintext does neither.
    """
    if _norm(tls_version) or _norm(cipher_suite):
        return []
    label = str(protocol).strip() if protocol else ""
    detail = f" ({label})" if label and _norm(label) != "unknown" else ""
    return [_finding(
        "nbom.no_transport_encryption", "critical",
        f"endpoint negotiated no TLS{detail}: traffic is carried in plaintext",
        "NIST SP 800-52r2",
    )]


def assess_cipher_suite(suite: Any) -> list[dict[str, Any]]:
    key = _norm(suite)
    if not key:
        return []
    out: list[dict[str, Any]] = []
    for token, (severity, why) in _WEAK_SUITE_TOKENS.items():
        if _norm(token) in key:
            out.append(_finding("nbom.weak_cipher_suite", severity,
                                f"{suite}: {why}", "NIST SP 800-52r2"))
            break
    # Forward secrecy is a property of the key exchange, not the cipher.
    #
    # TLS 1.3 suite names omit the key exchange entirely (RFC 8446 §B.4:
    # TLS_AES_256_GCM_SHA384 and friends), because (EC)DHE is mandatory for
    # every one of them -- the handshake has no static-key mode to fall back
    # to. Matching on the absence of an "ecdhe"/"dhe" token therefore flagged
    # every TLS 1.3 endpoint as lacking forward secrecy: a false positive on
    # precisely the configuration this product exists to move estates toward.
    if (not any(t in key for t in ("ecdhe", "dhe"))
            and key.startswith("tls")
            and key not in _TLS13_SUITES):
        out.append(_finding("nbom.no_forward_secrecy", "medium",
                            f"{suite} does not provide forward secrecy: recorded traffic "
                            "becomes readable if the server key is ever recovered"))
    return out


def assess_public_key(algorithm: Any, bits: Any) -> list[dict[str, Any]]:
    algo = _norm(algorithm)
    out: list[dict[str, Any]] = []
    try:
        size = int(bits) if bits is not None else None
    except (TypeError, ValueError):
        size = None
    if algo.startswith("rsa") and size is not None and size < 2048:
        out.append(_finding("nbom.rsa_key_too_short", "critical",
                            f"RSA {size} is below the 2048-bit floor", "NIST SP 800-131A"))
    if algo.startswith(("ec", "ecdsa")) and size is not None and size < 256:
        out.append(_finding("nbom.ec_key_too_short", "critical",
                            f"EC {size} is below the 256-bit floor", "NIST SP 800-131A"))
    if any(algo.startswith(p) for p in _SHOR_VULNERABLE):
        out.append(_finding("nbom.shor_vulnerable", "info",
                            f"{algorithm or 'public key'} is broken by a CRQC; inventory fact "
                            "for migration planning", "NIST IR 8547"))
    return out


# -------------------------------------------------------------- building


def _component(kind: str, name: str, ref: str, props: Mapping[str, Any],
               findings: list[dict[str, Any]]) -> dict[str, Any]:
    """A CycloneDX component. Properties carry the network facts verbatim."""
    return {
        "type": "cryptographic-asset" if kind in ("cipher-suite", "certificate", "tunnel") else "device",
        "bom-ref": ref,
        "name": name,
        "properties": (
            [{"name": "cryptoscan:kind", "value": kind}]
            + [{"name": f"cryptoscan:{k}", "value": str(v)}
               for k, v in sorted(props.items()) if v is not None]
        ),
        "cryptoscan:findings": findings,
    }


def build_nbom(
    endpoints: Iterable[Mapping[str, Any]] = (),
    *,
    tunnels: Iterable[Mapping[str, Any]] = (),
    devices: Iterable[Mapping[str, Any]] = (),
    estate: str | None = None,
) -> dict[str, Any]:
    """Assemble a CycloneDX 1.5 NBOM with its dependency graph.

    ``endpoints``: ``{host, port, protocol?, tls_version?, cipher_suite?,
    certificate?: {subject, issuer, public_key_algorithm, public_key_size,
    not_after, is_self_signed}, device?, observed?}``

    ``observed`` defaults to True. An endpoint that was never successfully
    probed must pass ``observed: False``; it is inventoried but excluded from
    every verdict, because an unprobed listener is unknown, not healthy.
    """
    components: list[dict[str, Any]] = []
    dependencies: dict[str, set[str]] = {}
    seen: set[str] = set()

    def add(component: dict[str, Any]) -> str:
        ref = component["bom-ref"]
        if ref not in seen:
            seen.add(ref)
            components.append(component)
        return ref

    def depend(parent: str, child: str) -> None:
        dependencies.setdefault(parent, set()).add(child)
        dependencies.setdefault(child, set())

    for device in devices:
        name = device.get("name") or device.get("host") or "device"
        add(_component("device", str(name), _ref("device", name),
                       {"vendor": device.get("vendor"), "model": device.get("model"),
                        "role": device.get("role")}, []))

    for ep in endpoints:
        host, port = ep.get("host"), ep.get("port")
        observed = ep.get("observed", True)
        ep_ref = _ref("endpoint", host, port, ep.get("protocol"))
        ep_findings: list[dict[str, Any]] = []
        if observed:
            ep_findings += assess_tls_version(ep.get("tls_version"))
            ep_findings += assess_transport_encryption(
                ep.get("tls_version"), ep.get("cipher_suite"), ep.get("protocol"))
        add(_component("endpoint", f"{host}:{port}", ep_ref, {
            "host": host, "port": port,
            "protocol": ep.get("protocol"),
            "tls_version": ep.get("tls_version"),
            "observed": observed,
            "service": ep.get("service"),
        }, ep_findings))

        device_name = ep.get("device")
        if device_name:
            dev_ref = add(_component("device", str(device_name), _ref("device", device_name),
                                     {"role": "terminator"}, []))
            depend(dev_ref, ep_ref)

        suite = ep.get("cipher_suite")
        if suite:
            suite_ref = add(_component("cipher-suite", str(suite), _ref("suite", suite), {},
                                       assess_cipher_suite(suite) if observed else []))
            depend(ep_ref, suite_ref)

        cert = ep.get("certificate") or {}
        if cert:
            subject = cert.get("subject") or "certificate"
            cert_ref = _ref("certificate", subject, cert.get("serial_number"))
            cert_findings: list[dict[str, Any]] = []
            if observed:
                cert_findings += assess_public_key(cert.get("public_key_algorithm"),
                                                   cert.get("public_key_size"))
                if cert.get("is_self_signed"):
                    cert_findings.append(_finding(
                        "nbom.self_signed_certificate", "high",
                        f"{subject} is self-signed: no third party vouches for this identity"))
                if str(cert.get("expiry_status") or "").upper() == "EXPIRED":
                    cert_findings.append(_finding(
                        "nbom.certificate_expired", "critical", f"{subject} has expired"))
            add(_component("certificate", str(subject), cert_ref, {
                "issuer": cert.get("issuer"),
                "public_key_algorithm": cert.get("public_key_algorithm"),
                "public_key_size": cert.get("public_key_size"),
                "not_after": cert.get("not_after"),
                "self_signed": cert.get("is_self_signed"),
            }, cert_findings))
            depend(ep_ref, cert_ref)

            issuer = cert.get("issuer")
            if issuer and issuer != subject:
                issuer_ref = add(_component("certificate", str(issuer), _ref("certificate", issuer, None),
                                            {"role": "issuer"}, []))
                depend(cert_ref, issuer_ref)

    for tunnel in tunnels:
        name = tunnel.get("name") or f"{tunnel.get('kind', 'tunnel')}:{tunnel.get('peer', '?')}"
        t_ref = _ref("tunnel", name)
        t_findings: list[dict[str, Any]] = []
        # Same contract as an endpoint: a tunnel nobody could inspect is
        # inventoried and scored by nothing.
        t_observed = tunnel.get("observed", True)
        for label, value in (("encryption", tunnel.get("encryption")),
                             ("integrity", tunnel.get("integrity"))):
            key = _norm(value)
            if not key:
                # The weak-token loop below is guarded by `if key`, so a
                # tunnel that declares no algorithm at all used to score
                # clean -- the same blind spot endpoints had, and worse
                # here: an unencrypted tunnel is the thing a VPN exists to
                # prevent.
                if t_observed:
                    t_findings.append(_finding(
                        "nbom.no_tunnel_encryption" if label == "encryption"
                        else "nbom.no_tunnel_integrity",
                        "critical" if label == "encryption" else "high",
                        f"{name} declares no {label} algorithm",
                        "3GPP TS 33.210 / RFC 8221"))
                continue
            for token, (severity, why) in _WEAK_SUITE_TOKENS.items():
                if _norm(token) in key:
                    t_findings.append(_finding(
                        "nbom.weak_tunnel_algorithm", severity,
                        f"{name} {label} uses {value}: {why}", "3GPP TS 33.210 / RFC 8221"))
                    break
        if t_observed:
            t_findings += assess_public_key(tunnel.get("key_exchange"),
                                            tunnel.get("key_exchange_bits"))
        add(_component("tunnel", str(name), t_ref, {
            "kind": tunnel.get("kind"), "peer": tunnel.get("peer"),
            "encryption": tunnel.get("encryption"), "integrity": tunnel.get("integrity"),
            "key_exchange": tunnel.get("key_exchange"),
            # summarise() counts unobserved components off this property;
            # without it an unprobed tunnel was scored by nothing and also
            # reported as nothing, so it vanished from the honesty tally.
            "observed": t_observed,
        }, t_findings))
        device_name = tunnel.get("device")
        if device_name:
            dev_ref = add(_component("device", str(device_name), _ref("device", device_name),
                                     {"role": "terminator"}, []))
            depend(dev_ref, t_ref)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": [_TOOL],
            "component": {"type": "platform", "name": estate or "network-estate",
                          "bom-ref": _ref("estate", estate or "network-estate")},
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(children)}
            for ref, children in sorted(dependencies.items())
        ],
    }


# --------------------------------------------------------------- cascade


def cascade(nbom: Mapping[str, Any], component_ref: str) -> dict[str, Any]:
    """Everything affected by replacing ``component_ref``.

    Walks the dependency graph **backwards**: a certificate's blast radius is
    every endpoint that serves it and every device terminating those, not the
    issuer beneath it. That direction is the one a migration plan needs and
    the one a flat inventory cannot answer.
    """
    parents: dict[str, set[str]] = {}
    for entry in nbom.get("dependencies", []):
        for child in entry.get("dependsOn", []):
            parents.setdefault(child, set()).add(entry["ref"])

    by_ref = {c["bom-ref"]: c for c in nbom.get("components", [])}
    if component_ref not in by_ref:
        return {"ref": component_ref, "found": False, "affected": [], "affected_count": 0}

    seen: set[str] = set()
    queue = [component_ref]
    while queue:
        current = queue.pop()
        for parent in parents.get(current, ()):  # noqa: SIM118
            if parent not in seen:
                seen.add(parent)
                queue.append(parent)

    affected = [
        {"ref": r, "name": by_ref[r]["name"],
         "kind": next((p["value"] for p in by_ref[r].get("properties", [])
                       if p["name"] == "cryptoscan:kind"), None)}
        for r in sorted(seen) if r in by_ref
    ]
    return {
        "ref": component_ref,
        "found": True,
        "name": by_ref[component_ref]["name"],
        "affected": affected,
        "affected_count": len(affected),
        "by_kind": {
            kind: sum(1 for a in affected if a["kind"] == kind)
            for kind in sorted({a["kind"] for a in affected if a["kind"]})
        },
    }


def summarise(nbom: Mapping[str, Any]) -> dict[str, Any]:
    """Estate totals plus the weakest components, ranked by blast radius."""
    components = list(nbom.get("components", []))
    findings = [
        {**f, "component": c["name"], "ref": c["bom-ref"]}
        for c in components for f in c.get("cryptoscan:findings", [])
    ]
    by_kind: dict[str, int] = {}
    unobserved = 0
    for c in components:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        kind = props.get("cryptoscan:kind", "unknown")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if props.get("cryptoscan:observed") == "False":
            unobserved += 1

    severities = ("critical", "high", "medium", "low", "info")
    ranked = sorted(
        (
            {**cascade(nbom, c["bom-ref"]),
             "worst_severity": min((f["severity"] for f in c.get("cryptoscan:findings", [])),
                                   key=lambda s: severities.index(s) if s in severities else 9,
                                   default=None)}
            for c in components if c.get("cryptoscan:findings")
        ),
        key=lambda r: (severities.index(r["worst_severity"]) if r["worst_severity"] in severities else 9,
                       -r["affected_count"]),
    )
    return {
        "components": len(components),
        "by_kind": dict(sorted(by_kind.items())),
        "unobserved": unobserved,
        "findings": len(findings),
        "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in severities},
        "migration_priority": ranked[:20],
    }
