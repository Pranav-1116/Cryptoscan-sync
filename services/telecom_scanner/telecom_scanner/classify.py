"""Telecom crypto classification (pure) — probe result → NF posture verdicts.

Deterministic rules over the network_scanner's probe shape (see
``network_scanner.probing.active_prober.probe_endpoint``): status, negotiated
TLS version/cipher, leaf-certificate metadata, chain validation.

Policy anchors (documented, cited on the findings):

* 3GPP TS 33.210 (NDS/IP) — network-domain security: TLS 1.2+ / IPsec; TLS
  1.0/1.1 are not acceptable on network-function interfaces.
* 3GPP TS 33.501 — 5G security: SBA runs over TLS; inter-PLMN roaming SBI is
  protected by SEPP — an unprotected SEPP exposes international roaming.
* NIST SP 800-52r2 — TLS 1.0/1.1 disallowed, TLS 1.3 preferred; SHA-1/MD5
  certificates and RSA <2048 / EC <256 are disallowed.
* NIST IR 8547 — Shor-vulnerable public keys are inventory facts; hybrid
  ML-KEM key exchange on SBI is recorded when detected (early adoption).

Honesty rules: an IPsec gateway is NOT probed by IKE from this scanner —
``ipsec.ingest_required`` records that classification needs operator-side
results (POST /telecom/ingest); absence of evidence is never scored as a
failure and never as a pass.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Mapping

SEV_ORDER = ("ok", "info", "low", "medium", "high", "critical")

# probe statuses that mean "we could not reach / complete a handshake"
_UNREACHABLE = {"DNS_FAILED", "TIMEOUT", "PORT_CLOSED", "CONNECT_ERROR"}
_TLS_REFUSED = {"TLS_ERROR", "STARTTLS_REFUSED", "MTLS_REQUIRED"}

_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-CBC", "NULL", "EXP-", "-EXP", "RC2", "IDEA")
_WEAK_SIG_TOKENS = ("md5", "sha1", "sha-1", "dsa")
_PQC_TOKENS = ("mlkem", "ml-kem", "kyber", "pqc", "hybrid")

MIN_TLS = "TLSv1.2"

_REF_33210 = "3GPP TS 33.210 (NDS/IP)"
_REF_33501 = "3GPP TS 33.501 (5G security)"
_REF_80052 = "NIST SP 800-52r2"
_REF_IR8547 = "NIST IR 8547"

_DEDUCTIONS = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 0}

_MISSION_PLANES = ("5gc", "roaming", "epc")


def _norm(text: Any) -> str:
    return str(text or "").strip()


def _leaf_cert(probe: Mapping[str, Any]) -> Mapping[str, Any]:
    certs = probe.get("certificates") or []
    return certs[0] if certs else {}


def _finding(code: str, severity: str, message: str, ref: str | None = None) -> dict[str, Any]:
    out = {"code": code, "severity": severity, "message": message}
    if ref:
        out["ref"] = ref
    return out


def _cert_findings(probe: Mapping[str, Any]) -> list[dict[str, Any]]:
    leaf = _leaf_cert(probe)
    findings: list[dict[str, Any]] = []
    expiry_status = _norm(leaf.get("expiry_status")).upper()
    if expiry_status == "EXPIRED":
        findings.append(_finding("cert.expired", "critical", "The serving certificate has expired — interfaces will fail or run on overridden trust", _REF_80052))
    elif expiry_status == "EXPIRING_CRITICAL":
        findings.append(_finding("cert.expiring", "high", f"Certificate expires within {_norm(leaf.get('days_until_expiry')) or 7} days", _REF_80052))
    elif expiry_status == "EXPIRING_SOON":
        findings.append(_finding("cert.expiring", "medium", f"Certificate expires in {_norm(leaf.get('days_until_expiry')) or 30} days", _REF_80052))
    if leaf.get("is_self_signed"):
        findings.append(_finding("cert.self_signed", "high", "Serving certificate is self-signed — no third-party or PKI accountability", _REF_80052))
    chain = probe.get("chain_validation") or {}
    if chain and chain.get("is_valid") is False and not leaf.get("is_self_signed"):
        findings.append(_finding("cert.chain_invalid", "high", f"Certificate chain does not validate: {'; '.join(chain.get('errors') or []) or 'unspecified error'}", _REF_80052))
    sig = " ".join([
        _norm(leaf.get("signature_algorithm")),
        _norm(leaf.get("sig_alg")),
        _norm(leaf.get("signature_hash_algorithm")),
    ]).lower()
    if sig and any(token in sig for token in _WEAK_SIG_TOKENS):
        findings.append(_finding("cert.sig_weak", "critical", f"Certificate signed with a broken hash ({sig.strip()}) — forgeable", _REF_80052))
    bits = leaf.get("key_size") or leaf.get("key_bits") or leaf.get("public_key_size")
    kind = _norm(leaf.get("key_type") or leaf.get("public_key_type") or leaf.get("algorithm")).lower()
    try:
        bits_int = int(bits) if bits is not None else None
    except (TypeError, ValueError):
        bits_int = None
    if bits_int is not None:
        if "rsa" in kind and bits_int < 2048:
            findings.append(_finding("cert.key_weak", "critical", f"RSA-{bits_int} public key — below the 2048-bit floor", _REF_80052))
        elif ("ec" in kind or "ecdsa" in kind) and bits_int < 256:
            findings.append(_finding("cert.key_weak", "critical", f"EC-{bits_int} public key — below the P-256 floor", _REF_80052))
    return findings


def classify_target(
    target: Mapping[str, Any],
    probe: Mapping[str, Any] | None,
    *,
    as_of: date | None = None,
) -> dict[str, Any]:
    """Verdicts for one NF target from its (optional) live probe result.

    ``probe=None`` means "not probed in this pass" (e.g. IPsec gateways, or
    an ingest-driven scan) — classified honestly as unknown where the
    transport warrants it, never as pass and never as fail.
    """
    nf_type = _norm(target.get("nf_type")).lower()
    spec = {"transport": "tls", "plane": "transport"}
    # import lazily to keep the module importable without the catalog (tests)
    from telecom_scanner.registry import NF_CATALOG

    spec = NF_CATALOG.get(nf_type, spec)
    findings: list[dict[str, Any]] = []
    pqc_groups: list[str] = []
    user_plane: dict[str, Any] | None = None
    now_iso = (as_of or datetime.now(timezone.utc).date()).isoformat()

    from telecom_scanner.user_plane import assess_user_plane, is_user_plane_target

    if is_user_plane_target(target):
        # N3/N9 is GTP-U, not a TLS endpoint. No active user-plane packets
        # are emitted here; operator-side evidence is ingested and classified.
        user_plane = assess_user_plane(target, probe)
        findings.extend(user_plane.get("findings") or [])
        status = str(user_plane.get("status") or "USER_PLANE_UNKNOWN")
    elif spec["transport"] == "ipsec":
        # NDS/IP gateways: live IKE from this vantage is unreliable (UDP,
        # filtered); classification comes from operator-side ingest.
        ike = (probe or {}).get("ike") or {}
        if ike:
            findings.extend(_ike_findings(ike))
        else:
            findings.append(_finding("ipsec.ingest_required", "info",
                                     "NDS/IP gateway — IKE/IPsec classification requires operator-side results (POST /telecom/ingest); not probed from this vantage", _REF_33210))
        status = "IPSEC_REVIEWED" if ike else "IPSEC_UNKNOWN"
    elif probe is None:
        findings.append(_finding("target.not_probed", "info", "No probe result available in this pass"))
        status = "NOT_PROBED"
    elif _norm(probe.get("status")) in _UNREACHABLE or not _norm(probe.get("status")):
        sev = "critical" if spec["plane"] in _MISSION_PLANES else "high"
        findings.append(_finding("target.unreachable", sev,
                                 f"Endpoint not reachable ({_norm(probe.get('status')) or 'UNKNOWN'}) — monitoring blind spot on a {'mission-critical' if sev == 'critical' else 'production'} NF"))
        status = "UNREACHABLE"
    elif _norm(probe.get("status")) in _TLS_REFUSED:
        findings.append(_finding("tls.refused", "critical",
                                 f"Endpoint refused a TLS handshake ({_norm(probe.get('status'))}) — interface is running without TLS", _REF_33210))
        status = "NO_TLS"
    else:
        version = _norm(probe.get("crypto", {}).get("tls_version") or probe.get("tls_version"))
        cipher = _norm(probe.get("crypto", {}).get("cipher_suite") or probe.get("cipher_suite"))
        kex = _norm(probe.get("crypto", {}).get("key_exchange")).lower()
        if version and _tls_rank(version) < _tls_rank(MIN_TLS):
            findings.append(_finding("tls.version_obsolete", "critical",
                                     f"{version} negotiated on a network-function interface — TLS 1.2 is the floor, 1.3 preferred", f"{_REF_33210}; {_REF_80052}"))
        elif version == "TLSv1.2":
            findings.append(_finding("tls.no_tls13", "info", "TLS 1.2 in use — migrate to TLS 1.3 (preferred)", _REF_80052))
        if cipher and any(token in cipher.upper() for token in _WEAK_CIPHER_TOKENS):
            findings.append(_finding("cipher.weak", "critical", f"Weak cipher suite negotiated ({cipher})", f"{_REF_33210}; {_REF_80052}"))
        findings.extend(_cert_findings(probe))
        for token in _PQC_TOKENS:
            if token in kex:
                pqc_groups.append(kex)
        if pqc_groups:
            findings.append(_finding("pqc.hybrid_kem", "info",
                                     f"Hybrid PQC key exchange detected ({', '.join(sorted(set(pqc_groups)))}) — early SBI adoption, inventory fact", _REF_IR8547))
        status = "TLS_OK"

    if nf_type == "sepp" and status != "TLS_OK":
        findings.append(_finding("sepp.roaming_unprotected", "critical",
                                 "SEPP (international roaming edge) is not demonstrably TLS-protected — inter-PLMN SBI exposure", _REF_33501))

    severities = [f["severity"] for f in findings]
    severity = max(severities, key=lambda s: SEV_ORDER.index(s)) if severities else "ok"
    if not findings or all(f["severity"] == "info" for f in findings):
        severity = "ok" if not findings else "info"
    score = max(0, 100 - sum(_DEDUCTIONS.get(f["severity"], 0) for f in findings))
    cert = _leaf_cert(probe or {})

    # Crypto facts for the migration planner (cbom/supervisor.py): the leaf
    # key and signature algorithm plus the negotiated cipher — the families
    # an IR 8547 roadmap is built from. Empty unless TLS was actually
    # observed; an unprobed target contributes nothing it did not show.
    crypto_inventory: dict[str, str] = {}
    if status == "TLS_OK":
        sig_raw = (_norm(cert.get("signature_algorithm"))
                   or _norm(cert.get("sig_alg"))
                   or _norm(cert.get("signature_hash_algorithm"))).upper()
        key_type = _norm(cert.get("key_type") or cert.get("public_key_type")
                         or cert.get("algorithm")).upper()
        try:
            key_bits = int(cert.get("key_size") or cert.get("key_bits")
                           or cert.get("public_key_size"))
        except (TypeError, ValueError):
            key_bits = None
        if key_type and key_bits:
            crypto_inventory["cert_key"] = f"{key_type}-{key_bits}"
        if sig_raw:
            crypto_inventory["cert_sig"] = sig_raw.replace("WITHTSA", "WITH").replace("ENCRYPTION", "")
        cipher_suite = _norm(probe.get("crypto", {}).get("cipher_suite")
                             or probe.get("cipher_suite"))
        if cipher_suite:
            crypto_inventory["cipher"] = cipher_suite

    fingerprint = "|".join([
        status,
        ",".join(sorted(f["code"] for f in findings if f["severity"] != "info")),
        _norm(cert.get("not_after")) or "-",
    ])
    return {
        "nf_id": _norm(target.get("nf_id")),
        "nf_type": nf_type,
        "endpoint": _norm(target.get("endpoint")),
        "carrier_code": _norm(target.get("carrier_code")),
        "environment": _norm(target.get("environment")) or "production",
        "plane": spec["plane"],
        "status": status,
        "severity": severity,
        "findings": findings,
        "user_plane": user_plane,
        "pqc_kex": sorted(set(pqc_groups)),
        # drift-diff fact for the realtime layer: hybrid ML-KEM observed on
        # THIS probe (roaming/rollup views derive the same flag from pqc_kex)
        "pqc_ready": bool(pqc_groups),
        "crypto_inventory": crypto_inventory,
        "score": score,
        "cert_not_after": _norm(cert.get("not_after")) or None,
        "probed_at": (_norm((probe.get("metadata") or {}).get("probed_at"))
                      if isinstance(probe, dict) else None),
        "generated_for": now_iso,
        "fingerprint": fingerprint,
    }


def _tls_rank(version: str) -> int:
    order = {"SSLv2": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5}
    return order.get(version.strip(), -1)


def _ike_findings(ike: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Classify operator-side IKE/IPsec ingest (TS 33.210 NDS/IP + NIST floors)."""
    findings: list[dict[str, Any]] = []
    ike_version = _norm(ike.get("ike_version"))
    if ike_version and ike_version not in ("IKEv2", "2", "ikev2"):
        findings.append(_finding("ipsec.ikev1", "critical", f"{ike_version} negotiated — NDS/IP requires IKEv2", _REF_33210))
    groups = [str(g) for g in (ike.get("dh_groups") or [])]
    weak_groups = [g for g in groups if g.isdigit() and int(g) < 14]
    if weak_groups:
        findings.append(_finding("ipsec.dh_weak", "critical", f"DH group(s) {', '.join(weak_groups)} — below group 14 (2048-bit MODP)", f"{_REF_33210}; {_REF_80052}"))
    enc = _norm(ike.get("encryption")).upper()
    if enc and any(t in enc for t in ("3DES", "DES", "NULL")):
        findings.append(_finding("ipsec.enc_weak", "critical", f"Weak IPsec encryption ({enc}) — AES-GCM required", _REF_33210))
    if not findings:
        findings.append(_finding("ipsec.ok", "info", "Operator-reported IKE/IPsec parameters meet the NDS/IP floors", _REF_33210))
    return findings
