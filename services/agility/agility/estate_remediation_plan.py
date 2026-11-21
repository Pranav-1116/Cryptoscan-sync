"""Remediation from the Digital Twin: what is wrong in the estate, in what order to fix it,
and the work a simulated migration needs.

The input is the migration twin ``twin_from_estate`` builds from the agents' estate graph.
These functions are pure: no I/O, no clock unless one is passed in. The same twin always gives
the same findings, the same ids and the same waves.

* ``estate_findings`` lists the crypto weaknesses the agents observed. Examples are a broken or
  deprecated algorithm, a short RSA key, an expired certificate, a TLS 1.0 endpoint, a
  hard-coded key, a library or a vendor with no post-quantum path, and an HSM outside FIPS
  mode. Each finding is ranked by its severity and by how critical the systems it touches are.
* ``migration_waves`` orders the systems that hold quantum-vulnerable or weak crypto. Providers
  come before the systems that call them, so a caller never switches before its peer can answer.
  It also lists the estate-wide workstreams, for example RSA → ML-KEM-768 / ML-DSA-65.
* ``migration_task_candidates`` turns the issues of one simulated change (from
  ``simulate_bom_impact``) into task candidates with stable ids.
* ``verify_candidate`` decides whether a newer observation still shows a finding.

Boundaries:

* A finding needs evidence. An unrecorded capability is listed under ``unknowns`` and is
  never treated as a weakness.
* A vendor's post-quantum readiness is declared by the vendor, not observed.
* Assets reach systems only through the twin's evidenced membership.
* The output names the work. Nothing here changes the estate.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Iterable, Mapping

FINDINGS_SCHEMA = "cryptoscan.estate-remediation-findings/1"
WAVES_SCHEMA = "cryptoscan.estate-migration-waves/1"
CANDIDATES_SCHEMA = "cryptoscan.migration-remediation-candidates/1"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEV_WEIGHT = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10}
_SEV_PRIORITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}
_CRITICALITY_WEIGHT = {
    "critical": 1.5, "tier-0": 1.5, "tier0": 1.5,
    "high": 1.25, "tier-1": 1.25, "tier1": 1.25,
    "medium": 1.0, "tier-2": 1.0, "tier2": 1.0,
    "low": 0.8, "tier-3": 0.8, "tier3": 0.8,
}

_BOM_OF_TYPE = {
    "CERTIFICATE": "CBOM", "CA": "CBOM", "KEY": "CBOM", "KMS_KEY": "CBOM", "SECRET": "CBOM",
    "LIBRARY": "SBOM", "PACKAGE": "SBOM",
    "HSM": "HBOM", "HARDWARE": "HBOM",
    "NETWORK_ENDPOINT": "NBOM",
    "VENDOR": "VBOM",
}

#: what replaces a weak primitive (by the classifier's canonical family name)
_REPLACEMENT = {
    "RSA": ("ML-KEM-768", "ML-DSA-65"), "ECDSA": ("ML-DSA-65",), "Ed25519": ("ML-DSA-65",),
    "Ed448": ("ML-DSA-87",), "DSA": ("ML-DSA-65",), "ECDH": ("ML-KEM-768",),
    "X25519": ("ML-KEM-768",), "X448": ("ML-KEM-1024",), "DH": ("ML-KEM-768",),
    "P-256": ("ML-DSA-65",), "P-384": ("ML-DSA-87",),
    "3DES": ("AES-256-GCM",), "DES": ("AES-256-GCM",), "RC4": ("AES-256-GCM",),
    "RC2": ("AES-256-GCM",), "Blowfish": ("AES-256-GCM",),
    "MD5": ("SHA-384",), "MD4": ("SHA-384",), "SHA-1": ("SHA-384",),
    "AES": ("AES-256",),
}

_PQC_TOKENS = ("ml-kem", "mlkem", "kyber", "ml-dsa", "mldsa", "dilithium", "slh-dsa", "sphincs",
               "falcon", "fn-dsa", "oqs", "hqc")
_WEAK_SUITE_TOKENS = ("RC4", "DES", "NULL", "EXPORT", "MD5", "ANON", "ADH")
_OLD_TLS = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLS1.0", "TLSV1.1", "TLS1.1", "TLS 1.0", "TLS 1.1"}


def _verdict(name: str) -> dict[str, Any]:
    try:
        from shared_models.quantum_classify import quantum_verdict
    except Exception:  # pragma: no cover - shared_models is a declared dependency
        return {"algorithm": name, "family": None, "status": None, "verdict": "UNKNOWN",
                "key_size": None, "recognized": False}
    return quantum_verdict(name)


def finding_id(*parts: Any) -> str:
    """A stable id for a finding: the same evidence in a later observation gives the same id."""
    blob = "|".join("" if p is None else str(p) for p in parts)
    return "rf-" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _sys_index(twin: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(s.get("id")): dict(s) for s in twin.get("systems") or []}


def _score(severity: str, systems: list[dict[str, Any]]) -> int:
    weight = max([_CRITICALITY_WEIGHT.get(str(s.get("criticality") or "").lower(), 1.0)
                  for s in systems] or [1.0])
    shared = 5 * min(max(len(systems) - 1, 0), 4)
    return int(round(_SEV_WEIGHT[severity] * weight + shared))


def _rank_reason(severity: str, systems: list[dict[str, Any]]) -> str:
    if not systems:
        return f"{severity.lower()} severity; no system claims this asset yet"
    top = max(systems, key=lambda s: _CRITICALITY_WEIGHT.get(str(s.get("criticality") or "").lower(), 1.0))
    crit = str(top.get("criticality") or "unrated")
    extra = f", shared by {len(systems)} systems" if len(systems) > 1 else ""
    return f"{severity.lower()} severity on {top.get('name')} ({crit}){extra}"


class _Collector:
    def __init__(self, systems: dict[str, dict[str, Any]]):
        self.systems = systems
        self.items: dict[str, dict[str, Any]] = {}

    def add(self, *, code: str, severity: str, title: str, cause: str, action: str,
            asset_id: str | None, asset_name: str | None, asset_type: str | None,
            system_ids: Iterable[str], bom: str, algorithm: str | None = None,
            replace_with: str | None = None, basis: str, who_acts: str,
            verify_by: str, key: Any = None) -> None:
        fid = finding_id("estate", code, asset_id, key if key is not None else algorithm)
        systems = sorted((self.systems[sid] for sid in set(system_ids) if sid in self.systems),
                         key=lambda s: str(s.get("name") or s.get("id")))
        if fid in self.items:
            return
        self.items[fid] = {
            "id": fid, "code": code, "severity": severity, "priority": _SEV_PRIORITY[severity],
            "title": title, "cause": cause, "action": action, "who_acts": who_acts,
            "bom": bom, "basis": basis, "verify_by": verify_by,
            "asset_id": asset_id, "asset_name": asset_name, "asset_type": asset_type,
            "algorithm": algorithm, "replace_with": replace_with,
            "system_ids": [s["id"] for s in systems],
            "systems": [s.get("name") for s in systems],
            "score": _score(severity, systems),
            "rank_reason": _rank_reason(severity, systems),
        }


def _algorithm_finding(col: _Collector, asset: Mapping[str, Any], name: str, has_signing: bool) -> None:
    v = _verdict(name)
    family = str(v.get("algorithm") or name)
    status, verdict = v.get("status"), v.get("verdict")
    kind = str(v.get("family") or "")
    targets = _REPLACEMENT.get(family)
    if family == "RSA" and targets:
        targets = ("ML-DSA-65",) if (has_signing and "with" in name.lower()) else targets
    replace = " / ".join(targets) if targets else None
    common = dict(asset_id=asset.get("asset_id"), asset_name=asset.get("name"),
                  asset_type=asset.get("type"), system_ids=asset.get("system_ids") or [],
                  bom=_BOM_OF_TYPE.get(str(asset.get("type") or ""), "CBOM"),
                  algorithm=name, replace_with=replace, basis="AGENT_OBSERVATION")
    where = asset.get("name") or asset.get("asset_id")
    if status == "DISALLOWED":
        col.add(code="BROKEN_ALGORITHM", severity="CRITICAL",
                title=f"{name} is broken and still in use on {where}",
                cause=f"{family} is disallowed by current policy: it can be attacked today, not only by a future quantum computer",
                action=f"replace {name} with {replace or 'an approved algorithm'} and re-key",
                who_acts="the system owner", verify_by=f"the next agent report no longer shows {name} on {where}",
                **common)
    elif status in ("DEPRECATED", "RESTRICTED"):
        col.add(code="DEPRECATED_ALGORITHM", severity="HIGH",
                title=f"{name} is deprecated on {where}",
                cause=f"{family} is {str(status).lower()}: its approval is ending and auditors will flag it",
                action=f"plan the move from {name} to {replace or 'an approved algorithm'}",
                who_acts="the system owner", verify_by=f"the next agent report no longer shows {name} on {where}",
                **common)
    elif verdict == "SHOR_VULNERABLE":
        weak = finding_id("estate", "WEAK_KEY", asset.get("asset_id"), "key")
        if weak in col.items:
            return  # the short key is the urgent finding on this asset; it covers the migration too
        merged = col.items.get(finding_id("estate", "QUANTUM_VULNERABLE", asset.get("asset_id"), family))
        if merged is not None:
            merged["algorithm"] = f"{merged['algorithm']}, {name}"
            merged["title"] = f"{merged['algorithm']} on {where} will be broken by a quantum computer"
            return
        col.add(key=family, code="QUANTUM_VULNERABLE", severity="MEDIUM",
                title=f"{name} on {where} will be broken by a quantum computer",
                cause=f"{family} rests on factoring or discrete logarithms (Shor's algorithm); data captured today can be decrypted later",
                action=f"migrate to {replace or 'a post-quantum algorithm'}, running both side by side first",
                who_acts="the migration owner", verify_by=f"the next agent report shows {replace or 'a post-quantum algorithm'} instead of {name} on {where}",
                **common)
    elif verdict == "GROVER_MARGINAL" and kind in ("block-cipher", "stream-cipher", "aead"):
        col.add(code="SYMMETRIC_KEY_TOO_SHORT", severity="LOW",
                title=f"{name} on {where} is below the post-quantum key length",
                cause=f"Grover's algorithm halves the strength of a {v.get('key_size') or 'short'}-bit key",
                action=f"move to {replace or 'a 256-bit key'} when the system is next changed",
                who_acts="the system owner", verify_by=f"the next agent report shows a 256-bit key on {where}",
                **common)


def estate_findings(twin: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Every crypto weakness in the observed estate, ranked. Pure."""
    systems = _sys_index(twin)
    col = _Collector(systems)
    unknowns: list[str] = []
    assets = {str(a.get("asset_id")): a for a in twin.get("assets") or []}

    # ---- hard-coded keys (CBOM, from the evidence the agents recorded)
    for row in twin.get("evidence") or []:
        if not row.get("is_hardcoded_key"):
            continue
        asset = assets.get(str(row.get("asset_id")), {})
        where = row.get("file_path") or asset.get("name") or row.get("asset_id")
        col.add(code="HARDCODED_KEY", severity="CRITICAL",
                title=f"hard-coded {row.get('algorithm') or ''} key in {where}".replace("  ", " "),
                cause="a key written into code or configuration is shared with everyone who can read it",
                action="move the key into the HSM or key vault, rotate it, and remove it from the source",
                asset_id=row.get("asset_id"), asset_name=asset.get("name"), asset_type=asset.get("type"),
                system_ids=[row["system_id"]] if row.get("system_id") else asset.get("system_ids") or [],
                bom="CBOM", algorithm=row.get("algorithm"), basis="AGENT_OBSERVATION",
                who_acts="the application team", verify_by=f"the next agent report finds no key in {where}",
                key=where)

    # ---- certificates: key length and expiry
    usages = twin.get("certificate_usages") or {}
    for cert in twin.get("certificates") or []:
        asset = assets.get(str(cert.get("asset_id")), {})
        sids = usages.get(str(cert.get("fingerprint_sha256"))) or asset.get("system_ids") or []
        name = cert.get("subject") or asset.get("name") or cert.get("asset_id")
        base = dict(asset_id=cert.get("asset_id"), asset_name=name, asset_type="CERTIFICATE",
                    system_ids=sids, bom="CBOM", basis="CERTIFICATE_OBSERVED", who_acts="the PKI team")
        algo, bits = str(cert.get("public_key_algorithm") or ""), cert.get("public_key_bits")
        try:
            bits_n = int(bits) if bits not in (None, "") else None
        except (TypeError, ValueError):
            bits_n = None
        if algo.upper().startswith("RSA") and bits_n is not None and bits_n < 2048:
            col.add(code="WEAK_KEY", severity="CRITICAL", title=f"{name} has an RSA-{bits_n} key",
                    cause=f"an RSA key of {bits_n} bits can be factored with today's computers",
                    action="reissue the certificate with ML-DSA-65 (or RSA-3072 as an interim) and revoke the old one",
                    algorithm=f"RSA-{bits_n}", replace_with="ML-DSA-65",
                    verify_by=f"the next agent report shows a new key on {name}", key="key", **base)
        days = cert.get("days_until_expiry")
        if days is None and cert.get("not_after") and now is not None:
            try:
                end = datetime.fromisoformat(str(cert["not_after"]).replace("Z", "+00:00"))
                days = (end - now).days
            except ValueError:
                days = None
        if isinstance(days, (int, float)):
            if days < 0:
                col.add(code="CERT_EXPIRED", severity="CRITICAL", title=f"{name} expired {abs(int(days))} day(s) ago",
                        cause="clients reject an expired certificate, so the connection fails",
                        action="renew and deploy the certificate now", replace_with=None,
                        verify_by=f"the next agent report shows a valid certificate on {name}", key="expiry", **base)
            elif days <= 30:
                col.add(code="CERT_EXPIRING", severity="HIGH", title=f"{name} expires in {int(days)} day(s)",
                        cause="the certificate runs out within 30 days",
                        action="renew it now; if it is RSA, renew it with the post-quantum target",
                        verify_by=f"the next agent report shows a later expiry on {name}", key="expiry", **base)
            elif days <= 90:
                col.add(code="CERT_EXPIRING", severity="MEDIUM", title=f"{name} expires in {int(days)} day(s)",
                        cause="the certificate runs out within 90 days",
                        action="schedule the renewal; use it to move to the post-quantum target",
                        verify_by=f"the next agent report shows a later expiry on {name}", key="expiry", **base)

    # ---- algorithms in use, per asset (endpoints are judged by their handshake below)
    for asset in assets.values():
        if asset.get("type") == "NETWORK_ENDPOINT":
            continue
        usage = asset.get("usage") or {}
        has_signing = any("signature" in str(k) for k in usage)
        for name in sorted(asset.get("algorithms") or {}):
            _algorithm_finding(col, asset, str(name), has_signing)

    # ---- network endpoints: protocol version and cipher suite (NBOM)
    for ep in twin.get("network_endpoints") or []:
        asset = assets.get(str(ep.get("asset_id")), {})
        name = f"{ep.get('host')}:{ep.get('port')}" if ep.get("host") else (asset.get("name") or ep.get("asset_id"))
        sids = [ep["system_id"]] if ep.get("system_id") else asset.get("system_ids") or []
        base = dict(asset_id=ep.get("asset_id"), asset_name=name, asset_type="NETWORK_ENDPOINT",
                    system_ids=sids, bom="NBOM", basis="NETWORK_OBSERVATION",
                    who_acts="the platform / network team")
        version = str(ep.get("version") or "")
        if version and version.upper().replace("_", ".") in _OLD_TLS:
            col.add(code="TLS_PROTOCOL_OLD", severity="HIGH", title=f"{name} negotiates {version}",
                    cause=f"{version} is disallowed (PCI DSS, NIST SP 800-52) and cannot carry post-quantum key exchange",
                    action="enable TLS 1.3 (TLS 1.2 at minimum) on the endpoint and its load balancer, then turn the old version off",
                    algorithm=version, replace_with="TLS 1.3",
                    verify_by=f"the next network observation of {name} negotiates TLS 1.2 or 1.3", key="protocol", **base)
        elif not version and ep.get("observed"):
            unknowns.append(f"the TLS version of {name} was not recorded")
        suite = str(ep.get("cipher_suite") or "")
        if suite:
            upper = suite.upper()
            if any(tok in upper.replace("3DES", "DES") for tok in _WEAK_SUITE_TOKENS):
                col.add(code="WEAK_CIPHER_SUITE", severity="HIGH", title=f"{name} negotiates {suite}",
                        cause="the negotiated suite uses a broken cipher or hash",
                        action="remove the suite from the server configuration and prefer TLS 1.3 AEAD suites",
                        algorithm=suite, replace_with="TLS_AES_256_GCM_SHA384",
                        verify_by=f"the next network observation of {name} negotiates a modern suite", key="suite", **base)
            elif not upper.startswith("TLS_") and "DHE" not in upper and "ECDHE" not in upper:
                col.add(code="NO_FORWARD_SECRECY", severity="MEDIUM", title=f"{name} has no forward secrecy ({suite})",
                        cause="RSA key transport: anyone who later obtains the server key can decrypt recorded traffic",
                        action="prefer (EC)DHE or TLS 1.3 suites, then add hybrid ML-KEM key exchange",
                        algorithm=suite, replace_with="TLS 1.3 + X25519MLKEM768",
                        verify_by=f"the next network observation of {name} negotiates an ephemeral key exchange", key="suite", **base)

    # ---- crypto libraries without a post-quantum implementation (SBOM)
    catalog = twin.get("library_catalog") or {}
    lib_assets = {str(a.get("name")): a for a in assets.values() if a.get("type") == "LIBRARY"}
    vulnerable_systems = {sid for a in assets.values() for algo in (a.get("algorithms") or {})
                          if _verdict(str(algo)).get("verdict") == "SHOR_VULNERABLE"
                          for sid in a.get("system_ids") or []}
    for lib_name, info in sorted(catalog.items()):
        asset = lib_assets.get(lib_name, {})
        sids = list(asset.get("system_ids") or [])
        caps = [str(x).lower() for x in info.get("algorithms") or []]
        if info.get("pqc_native") is True or any(tok in c for c in caps for tok in _PQC_TOKENS):
            continue
        if not caps and info.get("pqc_native") is None:
            unknowns.append(f"what {lib_name} implements was not recorded, so its post-quantum support is unknown")
            continue
        if sids and not (set(sids) & vulnerable_systems):
            continue
        col.add(code="LIBRARY_NO_PQC", severity="MEDIUM", title=f"{lib_name} has no post-quantum algorithms",
                cause=f"the library implements {', '.join(info.get('algorithms') or [])[:160]} — no ML-KEM or ML-DSA",
                action="upgrade to a release (or add a provider, e.g. oqs-provider / OpenSSL 3.5+) that implements ML-KEM and ML-DSA",
                asset_id=asset.get("asset_id"), asset_name=lib_name, asset_type="LIBRARY", system_ids=sids,
                bom="SBOM", replace_with="ML-KEM-768 / ML-DSA-65", basis="LIBRARY_CATALOG",
                who_acts="the application team",
                verify_by=f"the next agent report shows a {lib_name.split(' ')[0]} release with ML-KEM", key=lib_name)

    # ---- HSMs (HBOM)
    hsm_systems: dict[str, list[str]] = {}
    for asset in assets.values():
        if asset.get("type") == "HSM":
            hsm_systems[str(asset.get("asset_id"))] = list(asset.get("system_ids") or [])
    for hw in twin.get("hardware") or []:
        if hw.get("device_type") != "hsm":
            continue
        hsm = hw.get("hsm") or {}
        name = hw.get("name") or hw.get("asset_id")
        sids = hsm_systems.get(str(hw.get("asset_id"))) or []
        if hsm.get("fips_mode") is False:
            col.add(code="HSM_NOT_FIPS_MODE", severity="MEDIUM", title=f"HSM {name} is not in FIPS mode",
                    cause="keys held outside FIPS-approved mode do not meet PCI PIN / PCI DSS key-management expectations",
                    action="enable FIPS mode (and confirm the firmware is a validated version) in a maintenance window",
                    asset_id=hw.get("asset_id"), asset_name=name, asset_type="HSM", system_ids=sids, bom="HBOM",
                    basis="HSM_REPORT", who_acts="the payments security team",
                    verify_by=f"the next HSM report from {name} shows FIPS mode on", key="fips")
        elif hsm.get("fips_mode") is None:
            unknowns.append(f"whether HSM {name} runs in FIPS mode was not reported")
        if not hsm.get("pqc_capability") and not (hw.get("crypto_capabilities") or {}).get("supported_algorithms"):
            unknowns.append(f"which algorithms HSM {name} supports was not reported, so its post-quantum readiness is unknown")

    # ---- vendors (VBOM — declared, not observed)
    vendor_systems: dict[str, list[str]] = {}
    for row in twin.get("system_vendors") or []:
        vendor_systems.setdefault(str(row.get("vendor_id")), []).append(str(row.get("system_id")))
    vendor_crypto = twin.get("vendor_crypto") or {}
    for vendor in twin.get("vendors") or []:
        vid, name = str(vendor.get("id")), vendor.get("name") or vendor.get("id")
        sids = vendor_systems.get(vid, [])
        base = dict(asset_id=vid, asset_name=name, asset_type="VENDOR", system_ids=sids, bom="VBOM",
                    who_acts="vendor management / procurement")
        not_ready = [r for r in vendor_crypto.get(vid, []) if r.get("pqc_ready") is False]
        if not_ready:
            products = ", ".join(sorted({f"{r.get('product') or ''} {r.get('version') or ''}".strip() for r in not_ready}))
            col.add(code="VENDOR_NOT_PQC_READY", severity="MEDIUM", title=f"{name} declares no post-quantum support",
                    cause=f"the vendor's declaration for {products} says it is not post-quantum ready (declared, not observed)",
                    action=f"ask {name} for a dated post-quantum roadmap and put it in the contract",
                    replace_with=None, basis="VENDOR_DECLARATION",
                    verify_by=f"{name} declares a post-quantum-ready release", key="pqc", **base)
        state = str(vendor.get("contract_state") or "").upper()
        if state in ("NONE_ON_RECORD", "EXPIRED", "LAPSED"):
            col.add(code="VENDOR_NO_SUPPORT_CONTRACT", severity="MEDIUM" if state != "NONE_ON_RECORD" else "LOW",
                    title=f"{name}: no active support contract ({state.replace('_', ' ').lower()})",
                    cause="without support there is no one to escalate to when a crypto change breaks",
                    action="put a support agreement in place before the migration touches this vendor's product",
                    basis="ASSET_REGISTER", verify_by=f"the asset register shows an active contract for {name}",
                    key="contract", **base)

    findings = sorted(col.items.values(), key=lambda f: (-f["score"], SEVERITIES.index(f["severity"]), f["title"]))
    by_sev = {s: 0 for s in SEVERITIES}
    by_bom: dict[str, int] = {}
    by_system: dict[str, dict[str, int]] = {}
    for f in findings:
        by_sev[f["severity"]] += 1
        by_bom[f["bom"]] = by_bom.get(f["bom"], 0) + 1
        for name in f["systems"]:
            row = by_system.setdefault(name, {s: 0 for s in SEVERITIES})
            row[f["severity"]] += 1
    if not twin.get("certificates"):
        unknowns.append("no certificate was observed, so expiry and key length could not be checked")
    if not twin.get("network_endpoints"):
        unknowns.append("no network endpoint was observed, so TLS versions could not be checked")
    unowned = sum(1 for f in findings if not f["systems"])
    if unowned:
        unknowns.append(f"{unowned} finding(s) are on assets no system claims — map them to a system to rank them properly")
    return {
        "schema": FINDINGS_SCHEMA, "estate": twin.get("estate"),
        "findings": findings, "total": len(findings),
        "counts_by_severity": by_sev, "counts_by_bom": dict(sorted(by_bom.items())),
        "counts_by_system": dict(sorted(by_system.items())),
        "unknowns": sorted(set(unknowns)),
        "ranking": "severity weight (critical 100, high 60, medium 30, low 10) × the most critical system's weight "
                   "(critical 1.5, high 1.25, medium 1.0, low 0.8) + 5 per extra system sharing the asset (max 20)",
        "mutates_nothing": True,
    }


# --------------------------------------------------------------------------- #
# migration waves
# --------------------------------------------------------------------------- #

_CLASSES = ("broken", "deprecated", "quantum_vulnerable", "symmetric_short", "safe", "unknown")


def _klass(name: str) -> str:
    v = _verdict(name)
    if v.get("status") == "DISALLOWED":
        return "broken"
    if v.get("status") in ("DEPRECATED", "RESTRICTED"):
        return "deprecated"
    if v.get("verdict") == "SHOR_VULNERABLE":
        return "quantum_vulnerable"
    if v.get("verdict") == "GROVER_MARGINAL" and v.get("family") in ("block-cipher", "stream-cipher", "aead"):
        return "symmetric_short"
    if v.get("verdict") in ("QUANTUM_RESISTANT", "PQC_RESISTANT") or v.get("verdict") == "GROVER_MARGINAL":
        return "safe"
    return "unknown"


def _sccs(nodes: list[str], deps: dict[str, set[str]]) -> list[list[str]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on: set[str] = set()
    out: list[list[str]] = []
    counter = [0]

    def visit(v: str) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in sorted(deps.get(v, ())):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            group = []
            while True:
                w = stack.pop()
                on.discard(w)
                group.append(w)
                if w == v:
                    break
            out.append(sorted(group))

    for n in sorted(nodes):
        if n not in index:
            visit(n)
    return out


def migration_waves(twin: Mapping[str, Any], findings: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The systems to migrate, in dependency order (providers first), with estate workstreams. Pure."""
    systems = _sys_index(twin)
    ids = sorted(systems)
    uses: dict[str, dict[str, dict[str, int]]] = {sid: {} for sid in ids}
    work: dict[tuple[str, str], dict[str, Any]] = {}
    for asset in twin.get("assets") or []:
        if asset.get("type") == "NETWORK_ENDPOINT":
            continue
        for name, count in (asset.get("algorithms") or {}).items():
            klass = _klass(str(name))
            v = _verdict(str(name))
            family = str(v.get("algorithm") or name)
            for sid in asset.get("system_ids") or []:
                if sid not in uses:
                    continue
                row = uses[sid].setdefault(klass, {})
                row[str(name)] = row.get(str(name), 0) + int(count or 1)
            if klass in ("broken", "deprecated", "quantum_vulnerable", "symmetric_short"):
                targets = _REPLACEMENT.get(family) or ()
                entry = work.setdefault((klass, family), {
                    "family": family, "class": klass, "targets": list(targets),
                    "algorithms": set(), "uses": 0, "system_ids": set()})
                entry["algorithms"].add(str(name))
                entry["uses"] += int(count or 1)
                entry["system_ids"].update(s for s in asset.get("system_ids") or [] if s in systems)

    open_by_system: dict[str, dict[str, int]] = {}
    for f in (findings or {}).get("findings") or []:
        for sid in f.get("system_ids") or []:
            row = open_by_system.setdefault(sid, {s: 0 for s in SEVERITIES})
            row[f["severity"]] += 1

    needs = {sid for sid in ids if any(k in uses[sid] for k in ("broken", "deprecated", "quantum_vulnerable", "symmetric_short"))}
    deps: dict[str, set[str]] = {sid: set() for sid in ids}
    callers: dict[str, set[str]] = {sid: set() for sid in ids}
    all_deps: dict[str, set[str]] = {sid: set() for sid in ids}
    all_callers: dict[str, set[str]] = {sid: set() for sid in ids}
    for d in twin.get("dependencies") or []:
        s, t = str(d.get("source")), str(d.get("target"))
        if s in all_deps and t in all_deps and s != t:
            all_deps[s].add(t)
            all_callers[t].add(s)
        # only connections between two systems that both change constrain the order
        if s in needs and t in needs and s != t:
            deps[s].add(t)
            callers[t].add(s)
    groups = _sccs(ids, deps)
    group_of = {m: i for i, g in enumerate(groups) for m in g}
    level: dict[int, int] = {}
    for i, group in enumerate(groups):  # Tarjan emits providers before their callers
        targets = {group_of[t] for m in group for t in deps[m]} - {i}
        level[i] = 1 + max((level[t] for t in targets), default=0)

    def counts(sid: str) -> dict[str, int]:
        return {k: sum(uses[sid].get(k, {}).values()) for k in _CLASSES}

    def readiness(c: dict[str, int]) -> int | None:
        total = sum(c[k] for k in _CLASSES if k != "unknown")
        return round(100 * c["safe"] / total) if total else None

    levels = sorted({level[group_of[sid]] for sid in needs})
    wave_no = {lv: n + 1 for n, lv in enumerate(levels)}
    rows: list[dict[str, Any]] = []
    for sid in ids:
        s = systems[sid]
        c = counts(sid)
        moves = []
        for klass in ("broken", "deprecated", "quantum_vulnerable", "symmetric_short"):
            for name, n in sorted(uses[sid].get(klass, {}).items()):
                fam = str(_verdict(name).get("algorithm") or name)
                moves.append({"algorithm": name, "class": klass, "uses": n,
                              "replace_with": " / ".join(_REPLACEMENT.get(fam) or ()) or None})
        group = groups[group_of[sid]]
        row = {
            "system_id": sid, "name": s.get("name"), "owner": s.get("owner"),
            "criticality": s.get("criticality"), "counts": c, "readiness_pct": readiness(c),
            "moves": moves, "open_findings": open_by_system.get(sid, {x: 0 for x in SEVERITIES}),
            "depends_on": sorted(systems[t].get("name") for t in all_deps[sid]),
            "called_by": sorted(systems[t].get("name") for t in all_callers[sid]),
            "cycle_with": sorted(systems[m].get("name") for m in group if m != sid),
            "needs_migration": sid in needs,
        }
        if sid in needs:
            row["wave"] = wave_no[level[group_of[sid]]]
            before = sorted(systems[t].get("name") for t in deps[sid] if t in needs and t not in group)
            after = sorted(systems[t].get("name") for t in callers[sid] if t in needs and t not in group)
            parts = []
            if after:
                parts.append(f"goes before {', '.join(after)}, which {'calls' if len(after) == 1 else 'call'} it, "
                             "so callers switch against a peer that already speaks the new algorithm")
            if before:
                parts.append(f"waits for {', '.join(before)}, which it calls")
            if row["cycle_with"]:
                parts.append(f"moves together with {', '.join(row['cycle_with'])} (they call each other)")
            if not parts:
                parts.append("no connection constrains it, so it can move as soon as its own work is done")
            row["rationale"] = "; ".join(parts)
        rows.append(row)

    def urgency(r: dict[str, Any]) -> tuple:
        c = r["counts"]
        crit = _CRITICALITY_WEIGHT.get(str(r.get("criticality") or "").lower(), 1.0)
        return (-c["broken"], -c["deprecated"], -crit, -c["quantum_vulnerable"], str(r["name"]))

    waves = []
    for n in range(1, len(levels) + 1):
        members = sorted((r for r in rows if r.get("wave") == n), key=urgency)
        waves.append({"wave": n, "systems": members,
                      "focus": "providers that other systems call" if n == 1 and len(levels) > 1 else
                               "systems whose providers have moved" if n > 1 else "every system that needs a change"})

    class_order = {"broken": 0, "deprecated": 1, "quantum_vulnerable": 2, "symmetric_short": 3}
    workstreams = []
    for (klass, family), e in sorted(work.items(), key=lambda kv: (class_order[kv[0][0]], -kv[1]["uses"], kv[0][1])):
        names = sorted(e["algorithms"])
        if family == "RSA" and all("with" in n.lower() for n in names):
            e["targets"] = ["ML-DSA-65"]  # only RSA signatures are in use
        workstreams.append({
            "family": family, "class": klass, "algorithms": names, "targets": e["targets"],
            "uses": e["uses"], "systems": sorted(systems[s].get("name") for s in e["system_ids"]),
            "simulate": {"from_algo": family if family in ("RSA", "ECDSA", "Ed25519", "DSA", "ECDH", "X25519", "DH", "AES") else names[0],
                         "to_algo": e["targets"][0]} if e["targets"] else None,
        })

    total = {k: sum(counts(sid)[k] for sid in ids) for k in _CLASSES}
    return {
        "schema": WAVES_SCHEMA, "estate": twin.get("estate"),
        "waves": waves,
        "no_migration_needed": [r for r in rows if not r["needs_migration"]],
        "systems": rows,
        "workstreams": workstreams,
        "totals": {"systems": len(ids), "to_migrate": len(needs), "algorithm_uses": total,
                   "readiness_pct": readiness(total)},
        "rule": "a system moves after every system it calls (providers first); systems that call each other move together; "
                "inside a wave, broken and deprecated crypto and critical systems go first",
        "unknowns": ([] if twin.get("dependencies") else
                     ["no system-to-system connection is recorded, so every system is in wave 1 — map dependencies to order them"]),
        "mutates_nothing": True,
    }


# --------------------------------------------------------------------------- #
# migration → task candidates, and verification
# --------------------------------------------------------------------------- #

_IMPACT_SEVERITY = {"BLOCKER": "CRITICAL", "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def migration_task_candidates(impact: Mapping[str, Any]) -> dict[str, Any]:
    """Every issue of one simulated change as a task candidate with a stable id. Pure."""
    change = impact.get("change") or {}
    src, dst = change.get("from_algo"), change.get("to_algo")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    system_ids = {str(s.get("name")): str(s.get("id")) for s in impact.get("systems") or []}
    for bom in impact.get("boms") or []:
        for issue in bom.get("issues") or []:
            severity = _IMPACT_SEVERITY.get(str(issue.get("severity") or "").upper())
            if severity is None:
                continue  # INFO is context, not work
            names = list(issue.get("systems") or ([issue["system"]] if issue.get("system") else []))
            cid = finding_id("migration", src, dst, bom.get("bom"), issue.get("code"),
                             issue.get("subject"), ",".join(sorted(str(n) for n in names)))
            if cid in seen:
                continue
            seen.add(cid)
            out.append({
                "id": cid, "code": issue.get("code"), "severity": severity,
                "priority": _SEV_PRIORITY[severity], "bom": bom.get("bom"),
                "title": issue.get("title"), "cause": issue.get("cause"), "effect": issue.get("effect"),
                "action": issue.get("action"), "who_acts": issue.get("who_acts"),
                "subject": issue.get("subject"), "systems": names,
                "system_ids": [system_ids[n] for n in names if n in system_ids],
                "algorithm": src, "replace_with": dst, "basis": issue.get("basis"),
                "verify_by": f"simulating {src} → {dst} on a newer agent report no longer raises this issue",
            })
    out.sort(key=lambda c: (SEVERITIES.index(c["severity"]), str(c["bom"]), str(c["title"])))
    counts = {s: sum(1 for c in out if c["severity"] == s) for s in SEVERITIES}
    return {"schema": CANDIDATES_SCHEMA, "change": {"from_algo": src, "to_algo": dst},
            "candidates": out, "total": len(out), "counts_by_severity": counts, "mutates_nothing": True}


def verify_candidate(item_id: str, current_ids: Iterable[str], *, asset_id: str | None,
                     observed_assets: Iterable[str] | None, system_ids: Iterable[str] = (),
                     observed_systems: Iterable[str] = ()) -> dict[str, str]:
    """VERIFIED / FAILED / INCONCLUSIVE for one finding against a newer observation. Pure.

    The finding still present → FAILED. Gone, and its asset (or system) still observed →
    VERIFIED. Gone because nothing about it was observed → INCONCLUSIVE: silence is not a fix.
    """
    if item_id in set(current_ids):
        return {"result": "FAILED", "reason": "the newer agent report still shows this finding"}
    if asset_id and observed_assets is not None:
        if asset_id in set(observed_assets):
            return {"result": "VERIFIED", "reason": "the asset is still observed and the finding is gone"}
        return {"result": "INCONCLUSIVE",
                "reason": "the newer agent report does not contain the asset at all — removed, renamed or not collected; "
                          "silence is not proof of a fix"}
    wanted = set(system_ids)
    if wanted and not (wanted & set(observed_systems)):
        return {"result": "INCONCLUSIVE", "reason": "none of the systems the finding was on is in the newer report"}
    return {"result": "VERIFIED", "reason": "the newer agent report no longer raises this finding"}
