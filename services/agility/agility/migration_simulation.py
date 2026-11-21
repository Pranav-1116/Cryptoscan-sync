"""Migration simulation — a crypto change, read against everything the Digital Twin holds.

``algorithm_migration`` used to answer one question: *who uses the old algorithm today*.
A bank planning the change needs the next five:

1. **What is there** — for every system the change touches, the hardware it runs its keys
   on, the software that implements the crypto, the systems it is connected to, the
   vendors behind it, the certificates it presents and the business processes it carries.
   All of it comes from the twin snapshot (``digital_twin._snapshot``): the hardware fleet,
   ``crypto_hardware_links``, ``system_vendors``, the vendor crypto inventory (VBOM),
   vendor sub-tier edges, ``system_dependencies``, observed TLS endpoints, certificate
   usage, software deployments and the library catalog.
2. **Can it run the target** — each of those is checked against the target algorithm,
   using only capability the twin actually recorded. A device or vendor with no recorded
   capability is ``UNKNOWN``, never assumed capable.
3. **What could go wrong** — the problems that arise *during* the migration: a peer that
   still speaks the old algorithm, a vendor whose product does not support the new one,
   a certificate chain relying parties do not yet trust, a TLS version that cannot carry
   the new key exchange, hard-coded keys that need a release, data that is still
   encrypted or signed under the old keys.
4. **Parallel or normal** — a direct cut-over is recommended only when the twin shows
   nothing that needs the old algorithm to stay alive. Anything else (a connected system
   outside the change, unknown clients on a network endpoint, stored data, a vendor,
   unknown capability) means running old and new side by side, and the reasons are listed.
5. **How** — ordered phases: prerequisites, keys and trust, enable-alongside (parallel
   only), cut-over in dependency order (providers before their callers), verify,
   decommission.

Every answer is computed from the snapshot alone: no clock, no randomness, nothing is
written. What the twin cannot see — which algorithm a connection negotiates, clients that
are not assets, a vendor's roadmap — is reported in ``unknowns`` instead of being guessed.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.migration-simulation/1"

#: lists in the answer are bounded so one huge estate cannot produce an unbounded payload
MAX_LISTED = 50

STRATEGIES: dict[str, str] = {
    "BLOCKED": "cannot start: something on the path cannot run the target algorithm yet",
    "PARALLEL": "run the old and the new algorithm side by side, then retire the old one",
    "DIRECT": "a normal migration (one planned cut-over) is enough",
    "NOT_DETERMINED": "the twin holds nothing this change touches, so no strategy can be chosen",
}
_STRATEGY_RANK = {"NOT_DETERMINED": 0, "DIRECT": 1, "PARALLEL": 2, "BLOCKED": 3}

SEVERITIES: tuple[str, ...] = ("BLOCKER", "HIGH", "MEDIUM", "INFO")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# --------------------------------------------------------------------------- #
# algorithm families — properties of the algorithms, not of the estate
# --------------------------------------------------------------------------- #

_PQC_KEM = ("mlkem", "kyber", "hqc", "frodokem", "bikekem", "mceliece")
_PQC_SIG = ("mldsa", "dilithium", "slhdsa", "sphincs", "falcon", "fndsa", "xmss", "lms")
_SYMMETRIC = ("aes", "3des", "tdes", "des", "chacha20", "chacha", "rc4", "rc2", "blowfish",
              "camellia", "sm4", "idea", "seed", "twofish")
_HASH_PREFIX = ("sha", "md5", "md4", "ripemd", "blake", "sm3", "whirlpool")
_CLASSICAL_SIG = ("ecdsa", "eddsa", "ed25519", "ed448", "dsa")
_CLASSICAL_KEX = ("ecdh", "ecdhe", "x25519", "x448", "dh", "dhe", "ffdhe")

ROLE_LABEL = {
    "key_establishment": "key exchange / key transport",
    "signature": "digital signatures",
    "encryption": "data encryption",
    "hash": "hashing",
}


def _compact(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _tokens(value: Any) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", str(value or "").lower()) if token]


def algorithm_profile(name: Any) -> dict[str, Any]:
    """The family of an algorithm name and the jobs it can do.

    This is algorithm knowledge (ML-KEM cannot sign, RSA can both sign and transport a
    key), stated as such — never a claim about how the estate uses it.
    """
    compact = _compact(name)
    tokens = _tokens(name)
    roles: set[str] = set()
    pqc = False
    hybrid = False
    if any(marker in compact for marker in _PQC_KEM):
        roles.add("key_establishment")
        pqc = True
    if any(marker in compact for marker in _PQC_SIG):
        roles.add("signature")
        pqc = True
    if pqc and any(token in ("x25519", "secp256r1", "p256", "p384", "ecdh", "x448")
                   or token.startswith("x25519") for token in tokens):
        hybrid = True
    if not pqc:
        if "rsa" in tokens or compact.startswith("rsa"):
            roles.update({"key_establishment", "signature"})
        if any(token in _CLASSICAL_SIG for token in tokens) or compact.startswith(("ecdsa", "ed25519")):
            roles.add("signature")
        if any(token in _CLASSICAL_KEX for token in tokens) or compact.startswith(("ecdh", "x25519")):
            roles.add("key_establishment")
        if any(token in _SYMMETRIC or token.startswith(("aes", "chacha")) for token in tokens):
            roles.add("encryption")
        if any(token.startswith(_HASH_PREFIX) for token in tokens) and not roles:
            roles.add("hash")
    if roles == {"hash"}:
        family = "HASH"
    elif roles == {"encryption"}:
        family = "SYMMETRIC"
    elif pqc:
        family = "PQC_HYBRID" if hybrid else "PQC"
    elif roles:
        family = "ASYMMETRIC_CLASSICAL"
    else:
        family = "UNKNOWN"
    return {"name": str(name or ""), "family": family, "pqc": pqc, "hybrid": hybrid,
            "roles": sorted(roles)}


def _matches(value: Any, wanted: str) -> bool:
    """Containment on the compact form: 'rsa' matches 'RSA-2048' and 'TLS_ECDHE_RSA_…'."""
    want = _compact(wanted)
    return bool(want) and want in _compact(value)


def _supports(capabilities: Iterable[str], target: str) -> bool:
    want = _compact(target)
    for item in capabilities:
        have = _compact(item)
        if have and (want in have or have in want):
            return True
    return False


# --------------------------------------------------------------------------- #
# reading the snapshot
# --------------------------------------------------------------------------- #

def _names(value: Any) -> list[str]:
    """Algorithm / library names from the twin's dict-or-list fields."""
    if isinstance(value, Mapping):
        return [str(key) for key in value.keys()]
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, Mapping):
                out.append(str(item.get("name") or item.get("algorithm") or ""))
            else:
                out.append(str(item))
        return [item for item in out if item]
    if isinstance(value, str) and value.strip():
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _capability_list(*sources: Any) -> list[str]:
    """Every algorithm a hardware row says it can do, from the shapes collectors produce."""
    found: list[str] = []
    for source in sources:
        if isinstance(source, Mapping):
            for key in ("supported_algorithms", "algorithms", "mechanisms", "supported",
                        "crypto_capabilities", "supported_mechanisms"):
                found.extend(_names(source.get(key)))
            # {"aes": true, "rsa": true}: only keys that name an algorithm — a flag such
            # as {"fips": true} is not a capability list, and must not turn UNKNOWN into
            # NOT_SUPPORTED
            for key, flag in source.items():
                if (flag is True and isinstance(key, str) and len(key) <= 40
                        and algorithm_profile(key)["family"] != "UNKNOWN"):
                    found.append(key)
        else:
            found.extend(_names(source))
    seen: list[str] = []
    for item in found:
        if item and item not in seen:
            seen.append(item)
    return seen


def _hardware_view(hw: Mapping[str, Any], target: str, target_profile: Mapping[str, Any]) -> dict[str, Any]:
    hsm = hw.get("hsm") if isinstance(hw.get("hsm"), Mapping) else {}
    firmware = hw.get("firmware")
    firmware_version = (firmware.get("version") if isinstance(firmware, Mapping)
                        else firmware) or hsm.get("firmware")
    capabilities = _capability_list(hw.get("crypto_capabilities"), hsm)
    pqc_claim = str(hsm.get("pqc_capability") or "").upper() or None
    device_type = str(hw.get("device_type") or hsm.get("device_type") or "").lower()
    is_hsm = device_type == "hsm" or bool(hsm)
    if capabilities and _supports(capabilities, target):
        state, basis = "SUPPORTED", "the recorded capability list names the target"
    elif target_profile.get("pqc") and pqc_claim and "NOT" in pqc_claim:
        state, basis = "NOT_SUPPORTED", f"the device declares PQC capability {pqc_claim}"
    elif target_profile.get("pqc") and pqc_claim and any(
            word in pqc_claim for word in ("READY", "SUPPORTED", "HYBRID")):
        state, basis = "SUPPORTED_DECLARED", f"the device declares PQC capability {pqc_claim}"
    elif capabilities:
        state, basis = "NOT_SUPPORTED", (
            f"the recorded capability list ({', '.join(capabilities[:8])}) does not name {target}")
    else:
        state, basis = "UNKNOWN", "no capability list was collected for this device"
    return {
        "asset_id": hw.get("asset_id"),
        "kind": "HSM" if is_hsm else (device_type.upper() or "HARDWARE"),
        "manufacturer": hw.get("manufacturer") or hsm.get("manufacturer"),
        "model": hw.get("model") or hsm.get("model"),
        "firmware": firmware_version,
        "capabilities": capabilities[:20],
        "pqc_capability": pqc_claim,
        "target_support": state,
        "basis": basis,
    }


class _Twin:
    """Indexes over one snapshot, built once."""

    def __init__(self, snapshot: Mapping[str, Any]) -> None:
        self.snapshot = snapshot
        self.systems = {str(s.get("id")): dict(s) for s in snapshot.get("systems") or []
                        if s.get("id") is not None}
        self.system_by_name = {str(s.get("name") or "").lower(): sid
                               for sid, s in self.systems.items() if s.get("name")}
        self.assets = [dict(a) for a in snapshot.get("assets") or []]
        # crypto asset → systems: the twin row's own system_ids, the SystemAsset links,
        # and (for an estate keyed by system) an asset whose id *is* a system id
        self.asset_systems: dict[str, set[str]] = {}
        for asset in self.assets:
            asset_id = str(asset.get("asset_id"))
            ids = {str(x) for x in asset.get("system_ids") or []}
            if not ids and asset_id in self.systems:
                ids = {asset_id}
            self.asset_systems.setdefault(asset_id, set()).update(ids)
        for link in snapshot.get("system_asset_links") or []:
            if link.get("asset_id") and link.get("system_id"):
                self.asset_systems.setdefault(str(link["asset_id"]), set()).add(str(link["system_id"]))
        self.system_assets: dict[str, set[str]] = {}
        for asset_id, ids in self.asset_systems.items():
            for sid in ids:
                self.system_assets.setdefault(sid, set()).add(asset_id)
        self.asset_by_id = {str(a.get("asset_id")): a for a in self.assets}
        self.hardware = {str(h.get("asset_id")): dict(h) for h in snapshot.get("hardware") or []
                         if h.get("asset_id")}
        self.hardware_assets: dict[str, set[str]] = {
            str(hw_id): {str(x) for x in ids}
            for hw_id, ids in (snapshot.get("crypto_hardware") or {}).items()}
        for link in snapshot.get("crypto_hardware_links") or []:
            if link.get("hardware_asset_id") and link.get("asset_id"):
                self.hardware_assets.setdefault(str(link["hardware_asset_id"]), set()).add(
                    str(link["asset_id"]))
        self.vendors = {str(v.get("id")): dict(v) for v in snapshot.get("vendors") or []
                        if v.get("id") is not None}
        self.system_vendor_rows: dict[str, list[dict[str, Any]]] = {}
        for row in snapshot.get("system_vendors") or []:
            if row.get("system_id") and row.get("vendor_id"):
                self.system_vendor_rows.setdefault(str(row["system_id"]), []).append(dict(row))
        for sid, system in self.systems.items():
            # the snapshot pre-joins vendor_ids onto systems; keep any link only seen there
            known = {str(r.get("vendor_id")) for r in self.system_vendor_rows.get(sid, [])}
            for vendor_id in system.get("vendor_ids") or []:
                if str(vendor_id) not in known:
                    self.system_vendor_rows.setdefault(sid, []).append(
                        {"system_id": sid, "vendor_id": str(vendor_id), "dependency_type": None})
        self.vendor_crypto = {str(k): list(v or []) for k, v in
                              (snapshot.get("vendor_crypto") or {}).items()}
        self.vendor_children: dict[str, list[dict[str, Any]]] = {}
        for row in snapshot.get("vendor_dependencies") or []:
            if row.get("parent") and row.get("child"):
                self.vendor_children.setdefault(str(row["parent"]), []).append(dict(row))
        self.evidence = list(snapshot.get("evidence") or [])
        self.dependencies = [dict(d) for d in snapshot.get("dependencies") or []
                             if d.get("source") is not None and d.get("target") is not None]
        self.endpoints = [dict(e) for e in snapshot.get("network_endpoints") or []]
        self.certificates = {str(c.get("fingerprint_sha256")): dict(c)
                             for c in snapshot.get("certificates") or []
                             if c.get("fingerprint_sha256")}
        self.cert_systems = {str(fp): {str(x) for x in ids}
                             for fp, ids in (snapshot.get("certificate_usages") or {}).items()}
        self.processes = {str(k): list(v or []) for k, v in
                          (snapshot.get("business_processes") or {}).items()}
        self.library_catalog = dict(snapshot.get("library_catalog") or {})
        # the servers a system runs on (estate graph): listed, never checked as key holders —
        # a general-purpose CPU runs any algorithm in software
        self.platform = {str(k): [dict(row) for row in v or []]
                         for k, v in (snapshot.get("platform_hardware") or {}).items()}
        self.deployments: dict[str, list[dict[str, Any]]] = {}
        for row in snapshot.get("software_deployments") or []:
            if row.get("system_id"):
                self.deployments.setdefault(str(row["system_id"]), []).append(dict(row))

    def name(self, system_id: str) -> str:
        system = self.systems.get(system_id)
        return str((system or {}).get("name") or system_id)

    def resolve_system(self, reference: Any) -> str | None:
        text = str(reference or "").strip()
        if not text:
            return None
        if text in self.systems:
            return text
        return self.system_by_name.get(text.lower())


# --------------------------------------------------------------------------- #
# the simulation
# --------------------------------------------------------------------------- #

def _finding(code: str, severity: str, title: str, detail: str, *, system: str | None = None,
             subject: str | None = None, who_acts: str, mitigation: str,
             if_ignored: str, basis: str) -> dict[str, Any]:
    return {"code": code, "severity": severity, "title": title, "detail": detail,
            "system": system, "subject": subject, "who_acts": who_acts,
            "mitigation": mitigation, "if_ignored": if_ignored, "basis": basis}


def _version_rank(version: Any) -> float | None:
    text = str(version or "").lower().replace("tlsv", "").replace("tls", "").strip(" v")
    match = re.match(r"^(\d+)(?:\.(\d+))?", text)
    if not match:
        return None
    return float(f"{match.group(1)}.{match.group(2) or 0}")


def simulate_migration(snapshot: Mapping[str, Any], *, from_algo: str, to_algo: str,
                       systems: Any = None, now: datetime | None = None) -> dict[str, Any]:
    """The full migration answer for one crypto change. Pure: reads ``snapshot`` only."""
    source = str(from_algo or "").strip()
    target = str(to_algo or "").strip()
    if not source or not target:
        raise ValueError("from_algo and to_algo are required")
    twin = _Twin(snapshot)
    source_profile = algorithm_profile(source)
    target_profile = algorithm_profile(target)

    # ---- scope ----------------------------------------------------------- #
    requested = [part.strip() for part in (
        systems if isinstance(systems, (list, tuple)) else str(systems or "").split(","))
        if str(part).strip()]
    scope: set[str] | None = None
    unresolved_scope: list[str] = []
    if requested:
        scope = set()
        for reference in requested:
            resolved = twin.resolve_system(reference)
            if resolved:
                scope.add(resolved)
            else:
                unresolved_scope.append(str(reference))

    # ---- 1. the change set: everything in the twin that holds the old algorithm ---- #
    matched_assets = sorted(
        str(a.get("asset_id")) for a in twin.assets
        if any(_matches(name, source) for name in _names(a.get("algorithms"))))
    matched_evidence = [e for e in twin.evidence
                        if _matches(e.get("algorithm") or e.get("normalized_algorithm"), source)]
    matched_certs = sorted(fp for fp, c in twin.certificates.items()
                           if _matches(c.get("public_key_algorithm"), source))
    matched_endpoints = [e for e in twin.endpoints if _matches(e.get("cipher_suite"), source)]

    touched: dict[str, set[str]] = {}

    def touch(system_id: Any, why: str) -> None:
        if system_id is None or str(system_id) == "":
            return
        touched.setdefault(str(system_id), set()).add(why)

    for asset_id in matched_assets:
        for sid in twin.asset_systems.get(asset_id, set()):
            touch(sid, "a twin crypto asset of this system uses it")
    for row in matched_evidence:
        touch(row.get("system_id"), "source evidence linked to this system uses it")
    for fp in matched_certs:
        for sid in twin.cert_systems.get(fp, set()):
            touch(sid, "a certificate this system uses carries it")
    for endpoint in matched_endpoints:
        touch(endpoint.get("system_id"), "an observed TLS endpoint of this system negotiates it")
    if scope is not None:
        touched = {sid: why for sid, why in touched.items() if sid in scope}
    change_set = sorted(touched)
    unowned_assets = [a for a in matched_assets if not twin.asset_systems.get(a)]
    unowned_evidence = sum(1 for e in matched_evidence if not e.get("system_id"))

    findings: list[dict[str, Any]] = []
    unknowns: list[str] = []

    # ---- a property of the change itself: can the target do the old algorithm's jobs? -- #
    lost_roles = sorted(set(source_profile["roles"]) - set(target_profile["roles"]))
    if source_profile["roles"] and target_profile["roles"] and not (
            set(source_profile["roles"]) & set(target_profile["roles"])):
        findings.append(_finding(
            "TARGET_ROLE_MISMATCH", "BLOCKER",
            f"{target} cannot do what {source} does",
            f"{source} is used for {', '.join(ROLE_LABEL[r] for r in source_profile['roles'])}; "
            f"{target} only provides {', '.join(ROLE_LABEL[r] for r in target_profile['roles'])}",
            who_acts="the migration owner", basis="ALGORITHM_PROPERTY",
            mitigation=(f"pick a target that provides "
                        f"{', '.join(ROLE_LABEL[r] for r in source_profile['roles'])}"
                        + (" — e.g. ML-DSA or SLH-DSA for signatures"
                           if "signature" in source_profile["roles"] else "")
                        + (" — e.g. ML-KEM for key establishment"
                           if "key_establishment" in source_profile["roles"] else "")),
            if_ignored="every use of the old algorithm stays in place, or breaks with no replacement"))
    elif lost_roles:
        signing_seen = any(
            any("sign" in str(key).lower() or "sign" in str(value).lower()
                for key, value in (twin.asset_by_id.get(asset_id, {}).get("usage") or {}).items())
            for asset_id in matched_assets)
        findings.append(_finding(
            "TARGET_COVERS_PART", "HIGH",
            f"{target} replaces only part of {source}",
            f"{source} can also be used for {', '.join(ROLE_LABEL[r] for r in lost_roles)}, "
            f"which {target} cannot do"
            + (" — and the twin records a signing use for an affected asset" if signing_seen
               and "signature" in lost_roles else ""),
            who_acts="the migration owner",
            basis="TWIN_USAGE" if signing_seen else "ALGORITHM_PROPERTY",
            mitigation=("run a second simulation for the remaining use"
                        + (" (e.g. RSA signatures → ML-DSA-65)" if "signature" in lost_roles else "")),
            if_ignored=f"the {', '.join(ROLE_LABEL[r] for r in lost_roles)} uses keep {source}"))

    # ---- 2. per system: what is there, and can it run the target ---------- #
    system_reports: list[dict[str, Any]] = []
    vendor_index: dict[str, dict[str, Any]] = {}
    connected_index: dict[str, dict[str, Any]] = {}
    change = set(change_set)

    for sid in change_set:
        system = twin.systems.get(sid, {"id": sid, "name": sid})
        name = twin.name(sid)
        criticality = str(system.get("criticality") or "").lower() or None
        own_assets = sorted(twin.system_assets.get(sid, set()))
        own_matched = [a for a in own_assets if a in matched_assets]
        sys_findings: list[dict[str, Any]] = []
        reasons_parallel: list[dict[str, str]] = []
        reasons_block: list[dict[str, str]] = []

        def add(finding: dict[str, Any]) -> None:
            sys_findings.append(finding)

        # -- hardware: the devices holding this system's keys
        hardware_ids = sorted(hw_id for hw_id, assets in twin.hardware_assets.items()
                              if assets & set(own_assets))
        hardware = []
        for hw_id in hardware_ids:
            row = twin.hardware.get(hw_id)
            if row is None:
                hardware.append({"asset_id": hw_id, "kind": "HARDWARE", "target_support": "UNKNOWN",
                                 "basis": "a crypto↔hardware link names a device the hardware "
                                          "fleet does not hold"})
                continue
            view = _hardware_view(row, target, target_profile)
            view["holds_affected_keys"] = bool(twin.hardware_assets.get(hw_id, set()) & set(own_matched))
            hardware.append(view)
        for device in hardware:
            label = f"{device.get('kind')} {device.get('asset_id')}"
            make = " ".join(str(x) for x in (device.get("manufacturer"), device.get("model")) if x)
            if device["target_support"] == "NOT_SUPPORTED":
                declared = "declares PQC capability" in device["basis"]
                add(_finding(
                    "HARDWARE_CANNOT_RUN_TARGET", "BLOCKER",
                    (f"{label} cannot run {target}" if declared
                     else f"{label} does not list {target} in its recorded capabilities"),
                    f"{make or 'device'} firmware {device.get('firmware') or 'unknown'}: {device['basis']}",
                    system=name, subject=str(device.get("asset_id")),
                    who_acts=f"hardware owner / {device.get('manufacturer') or 'the device vendor'}",
                    mitigation=("upgrade the firmware to a release that lists the target, or replace "
                                "the device; until then keys for this system cannot be generated or "
                                f"used under {target} on it"),
                    if_ignored="key generation or signing on this device fails the moment the system switches",
                    basis="HARDWARE_CAPABILITY_RECORDED"))
                reasons_block.append({"code": "HARDWARE_CANNOT_RUN_TARGET",
                                      "text": f"{label} cannot run {target}"})
            elif device["target_support"] == "UNKNOWN":
                add(_finding(
                    "HARDWARE_CAPABILITY_UNKNOWN", "HIGH",
                    f"{label}: support for {target} is not recorded",
                    f"{make or 'device'} — {device['basis']}",
                    system=name, subject=str(device.get("asset_id")),
                    who_acts=f"hardware owner / {device.get('manufacturer') or 'the device vendor'}",
                    mitigation="read the device's mechanism list (PKCS#11 / KMIP query) or get the "
                               "vendor's written confirmation before scheduling",
                    if_ignored="the cut-over can fail on the device with no warning in the plan",
                    basis="NO_CAPABILITY_RECORD"))
                reasons_parallel.append({"code": "HARDWARE_CAPABILITY_UNKNOWN",
                                         "text": f"support for {target} on {label} is unproven"})
        if not hardware and own_assets:
            unknowns.append(f"{name}: no crypto↔hardware link is recorded, so whether its keys "
                            "live in an HSM (and whether that HSM can run the target) is unknown")

        # -- software: libraries implementing the crypto, and releases to rebuild
        libraries: dict[str, dict[str, Any]] = {}
        for asset_id in own_assets:
            asset = twin.asset_by_id.get(asset_id) or {}
            raw = asset.get("libraries") or {}
            pairs = raw.items() if isinstance(raw, Mapping) else ((lib, None) for lib in _names(raw))
            for lib, version in pairs:
                lib_name = str(lib)
                entry = twin.library_catalog.get(lib_name)
                if entry is None and lib_name in twin.library_catalog:
                    state, basis = "UNKNOWN", "the library catalog does not know this library"
                elif entry is None:
                    state, basis = "UNKNOWN", "no catalog entry was loaded for this library"
                elif _supports(entry.get("algorithms") or [], target):
                    state, basis = "SUPPORTED", "the catalog lists the target for this library"
                elif entry.get("algorithms"):
                    state, basis = "NOT_SUPPORTED", (
                        "the catalog lists " + ", ".join(str(x) for x in entry["algorithms"][:8]))
                else:
                    state, basis = "UNKNOWN", "the catalog entry lists no algorithms"
                libraries.setdefault(lib_name, {
                    "name": lib_name, "version": version if isinstance(version, str) else None,
                    "target_support": state, "basis": basis,
                    "deprecated": bool((entry or {}).get("deprecated")),
                    "vendor": (entry or {}).get("vendor")})
        for lib in libraries.values():
            if lib["target_support"] == "NOT_SUPPORTED":
                add(_finding(
                    "LIBRARY_LACKS_TARGET", "HIGH", f"library {lib['name']} does not implement {target}",
                    lib["basis"], system=name, subject=lib["name"],
                    who_acts="the application team",
                    mitigation=f"upgrade to a version (or add a provider) that implements {target}, "
                               "then rebuild and redeploy",
                    if_ignored="the code cannot call the new algorithm at all",
                    basis="LIBRARY_CATALOG"))
            if lib["deprecated"]:
                add(_finding(
                    "LIBRARY_DEPRECATED", "MEDIUM", f"library {lib['name']} is deprecated",
                    "the catalog marks it deprecated", system=name, subject=lib["name"],
                    who_acts="the application team",
                    mitigation="replace it as part of the same change rather than patching it",
                    if_ignored="the migration lands on a library with no future fixes",
                    basis="LIBRARY_CATALOG"))
        deployments = twin.deployments.get(sid, [])

        # -- hard-coded keys: a release, not a configuration switch
        hardcoded = [e for e in matched_evidence if str(e.get("system_id")) == sid and e.get("is_hardcoded_key")]
        if hardcoded:
            sites = sorted({str(e.get("file_path")) for e in hardcoded if e.get("file_path")})
            add(_finding(
                "HARDCODED_KEYS", "HIGH", f"{len(hardcoded)} hard-coded {source} key site(s)",
                "keys embedded in source cannot be switched by configuration: "
                + ", ".join(sites[:5]) + ("…" if len(sites) > 5 else ""),
                system=name, who_acts="the application team",
                mitigation="move the key to the HSM/KMS, change the code, rebuild and release "
                           f"({len(deployments)} recorded deployment(s) to roll)",
                if_ignored="the old key keeps working in the binary after the 'migration'",
                basis="SOURCE_EVIDENCE"))

        # -- connections: systems this one calls or is called by
        connections = []
        for edge in twin.dependencies:
            src, dst = str(edge.get("source")), str(edge.get("target"))
            if sid not in (src, dst) or src == dst:
                continue
            other = dst if src == sid else src
            direction = "CALLS" if src == sid else "CALLED_BY"
            other_known = other in twin.systems
            other_in_change = other in change
            other_uses_source = any(
                str(e.get("system_id")) == other for e in matched_evidence) or any(
                twin.asset_systems.get(a, set()) & {other} for a in matched_assets)
            other_has_crypto = any(str(e.get("system_id")) == other for e in twin.evidence) or bool(
                twin.system_assets.get(other))
            other_uses_target = any(
                str(e.get("system_id")) == other
                and _matches(e.get("algorithm") or e.get("normalized_algorithm"), target)
                for e in twin.evidence) or any(
                any(_matches(n, target) for n in _names(twin.asset_by_id.get(a, {}).get("algorithms")))
                for a in twin.system_assets.get(other, set()))
            connections.append({
                "system_id": other, "name": twin.name(other) if other_known else other,
                "direction": direction, "relation": edge.get("type"),
                "provenance": edge.get("source_system") or edge.get("relationship_source")
                or edge.get("provenance") or edge.get("source_kind"),
                "in_change": other_in_change, "uses_source": other_uses_source,
                "uses_target": other_uses_target,
                "crypto_recorded": other_has_crypto, "registered": other_known})
            entry = connected_index.setdefault(other, {
                "system_id": other, "name": twin.name(other) if other_known else other,
                "registered": other_known, "in_change": other_in_change,
                "uses_source": other_uses_source, "uses_target": other_uses_target,
                "crypto_recorded": other_has_crypto,
                "criticality": (twin.systems.get(other) or {}).get("criticality"),
                "links": []})
            entry["links"].append({"with": name, "direction": "CALLED_BY" if direction == "CALLS" else "CALLS",
                                   "relation": edge.get("type")})
            if not other_in_change:
                peer = twin.name(other) if other_known else other
                if other_uses_target:
                    peer_state = (f"{peer} already uses {target} elsewhere in the twin, but which "
                                  "algorithm this connection negotiates is not recorded")
                elif other_has_crypto:
                    peer_state = f"the twin holds no evidence that {peer} supports {target}"
                else:
                    peer_state = (f"its crypto is not recorded in the twin, so its support for "
                                  f"{target} is unknown")
                add(_finding(
                    "PEER_OUTSIDE_CHANGE", "MEDIUM" if other_uses_target else "HIGH",
                    f"{peer} is connected to {name} but is not part of this change",
                    f"{name} {'calls' if direction == 'CALLS' else 'is called by'} {peer}; {peer_state}",
                    system=name, subject=peer,
                    who_acts=f"the owner of {peer}",
                    mitigation=f"keep {source} available on this connection until {peer} confirms "
                               f"{target}, then retire it",
                    if_ignored=f"the connection between {name} and {peer} fails its handshake or "
                               "signature check at cut-over",
                    basis="SYSTEM_DEPENDENCY"))
                reasons_parallel.append({"code": "PEER_OUTSIDE_CHANGE",
                                         "text": f"{peer} still needs {source} on its connection"})
        if not connections:
            unknowns.append(f"{name}: no system dependency is recorded — a connection that exists "
                            "but was never registered cannot be warned about")

        # -- network endpoints: where unseen clients connect
        endpoints = []
        for endpoint in twin.endpoints:
            if str(endpoint.get("system_id")) != sid:
                continue
            rank = _version_rank(endpoint.get("version"))
            endpoints.append({
                "endpoint": f"{endpoint.get('host')}:{endpoint.get('port')}",
                "protocol": endpoint.get("protocol"), "tls_version": endpoint.get("version"),
                "cipher_suite": endpoint.get("cipher_suite"),
                "observed": bool(endpoint.get("observed")),
                "negotiates_source": _matches(endpoint.get("cipher_suite"), source)})
            if (target_profile["pqc"] and "key_establishment" in target_profile["roles"]
                    and rank is not None and rank < 1.3):
                add(_finding(
                    "TLS_VERSION_TOO_OLD", "HIGH",
                    f"{endpoint.get('host')}:{endpoint.get('port')} negotiates TLS {endpoint.get('version')}",
                    f"post-quantum and hybrid key exchange ({target}) is only defined for TLS 1.3",
                    system=name, subject=f"{endpoint.get('host')}:{endpoint.get('port')}",
                    who_acts="the platform / network team",
                    mitigation="enable TLS 1.3 on this endpoint (and its load balancer) first",
                    if_ignored="the endpoint can never offer the new key exchange",
                    basis="NETWORK_OBSERVATION"))
            elif rank is None and endpoint.get("observed") is False:
                unknowns.append(f"{name}: endpoint {endpoint.get('host')}:{endpoint.get('port')} is "
                                "registered but never observed, so its TLS version is unknown")
        if endpoints:
            reasons_parallel.append({
                "code": "EXTERNAL_CLIENTS_UNKNOWN",
                "text": f"{len(endpoints)} network endpoint(s): clients that connect to them are not "
                        "assets in the twin, so their support for the target cannot be checked"})
            if target_profile["pqc"]:
                add(_finding(
                    "HANDSHAKE_SIZE", "MEDIUM",
                    f"larger keys and signatures on {len(endpoints)} endpoint(s)",
                    f"{target} keys/ciphertexts/signatures are much larger than {source}'s; "
                    "handshakes grow by kilobytes",
                    system=name, who_acts="the network team",
                    mitigation="test through every load balancer, WAF and TLS-inspecting middlebox "
                               "on the path; check MTU/fragmentation and constrained clients",
                    if_ignored="middleboxes that cap ClientHello size drop the new handshakes",
                    basis="ALGORITHM_PROPERTY"))

        # -- vendors behind this system
        vendors = []
        uncontracted: list[tuple[str, str]] = []
        for row in twin.system_vendor_rows.get(sid, []):
            vendor_id = str(row.get("vendor_id"))
            vendor = twin.vendors.get(vendor_id, {"id": vendor_id, "name": vendor_id})
            rows = twin.vendor_crypto.get(vendor_id, [])
            uses_source = any(_matches(r.get("algorithm"), source) for r in rows)
            supports_target = any(_matches(r.get("algorithm"), target) for r in rows) or (
                target_profile["pqc"] and any(r.get("pqc_ready") for r in rows))
            # a release the vendor itself declares not PQC-ready (e.g. OpenSSL < 3.5); only a
            # row that states readiness counts — an absent flag is not a "no"
            release_not_ready = target_profile["pqc"] and any(
                r.get("pqc_ready_declared") and not r.get("pqc_ready") for r in rows)
            if not rows:
                readiness = "UNKNOWN"
            elif supports_target:
                readiness = "READY"
            elif uses_source:
                readiness = "NOT_READY"
            elif release_not_ready:
                readiness = "RELEASE_NOT_READY"
            else:
                readiness = "NOT_RECORDED_FOR_TARGET"
            contract = str(vendor.get("contract_state") or "").upper() or None
            children = [twin.vendors.get(str(c.get("child")), {}).get("name") or str(c.get("child"))
                        for c in twin.vendor_children.get(vendor_id, [])]
            view = {"vendor_id": vendor_id, "name": vendor.get("name") or vendor_id,
                    "criticality": vendor.get("criticality"), "vendor_type": vendor.get("vendor_type"),
                    "dependency_type": row.get("dependency_type"), "readiness": readiness,
                    "uses_source": uses_source,
                    "products": [{"algorithm": r.get("algorithm"), "key_size": r.get("key_size"),
                                  "pqc_ready": bool(r.get("pqc_ready")),
                                  "use_case": r.get("crypto_use_case")} for r in rows[:10]],
                    "sub_tier": sorted(children), "contract_state": contract,
                    "contract_end": vendor.get("contract_end"),
                    "supplies": vendor.get("products") if isinstance(vendor.get("products"), list) else None}
            vendors.append(view)
            agg = vendor_index.setdefault(vendor_id, {**{k: view[k] for k in (
                "vendor_id", "name", "criticality", "vendor_type", "readiness", "uses_source",
                "products", "sub_tier", "contract_state", "contract_end")},
                "systems": [], "dependency_types": set()})
            agg["systems"].append(name)
            if row.get("dependency_type"):
                agg["dependency_types"].add(str(row["dependency_type"]))
            vname = view["name"]
            if readiness == "NOT_READY":
                add(_finding(
                    "VENDOR_NOT_READY", "BLOCKER", f"{vname} has no {target} support on record",
                    f"{vname}'s recorded products implement {source} and none implements {target}",
                    system=name, subject=vname, who_acts=f"{vname} (vendor)",
                    mitigation=f"get {vname}'s {target} release and date; plan this system's "
                               "cut-over after it ships",
                    if_ignored=f"the {row.get('dependency_type') or 'vendor'} integration breaks at cut-over",
                    basis="VENDOR_CRYPTO_INVENTORY"))
                reasons_block.append({"code": "VENDOR_NOT_READY",
                                      "text": f"waiting on {vname} for {target}"})
            elif readiness == "RELEASE_NOT_READY":
                releases = sorted({f"{r.get('product')} {r.get('version') or ''}".strip()
                                   for r in rows if r.get("pqc_ready_declared") and not r.get("pqc_ready")})
                add(_finding(
                    "VENDOR_RELEASE_NOT_READY", "HIGH",
                    f"the deployed {vname} release is not {target}-capable",
                    f"{vname} declares no post-quantum support in the release this system runs: "
                    + ", ".join(releases[:4]),
                    system=name, subject=vname, who_acts="the platform team, with " + vname,
                    mitigation=f"upgrade to a {vname} release that ships {target} (and test it) "
                               "before this system's cut-over",
                    if_ignored=f"the software cannot negotiate or verify {target} at all",
                    basis="VENDOR_DECLARATION"))
                reasons_parallel.append({"code": "VENDOR_RELEASE_NOT_READY",
                                         "text": f"{vname} must be upgraded to a {target}-capable release"})
            elif readiness in ("UNKNOWN", "NOT_RECORDED_FOR_TARGET"):
                add(_finding(
                    "VENDOR_CAPABILITY_UNKNOWN", "MEDIUM",
                    f"{vname}: {target} support is not recorded",
                    ("no vendor crypto inventory is recorded for this vendor" if readiness == "UNKNOWN"
                     else f"the recorded products do not mention {target}"),
                    system=name, subject=vname, who_acts=f"{vname} (vendor)",
                    mitigation="ask the vendor for its supported-algorithm statement and add it "
                               "to the vendor crypto inventory",
                    if_ignored="the vendor side of the integration may reject the new algorithm",
                    basis="NO_VENDOR_RECORD"))
                reasons_parallel.append({"code": "VENDOR_INVOLVED",
                                         "text": f"{vname}'s support for {target} is unconfirmed"})
            else:
                reasons_parallel.append({
                    "code": "VENDOR_INVOLVED",
                    "text": f"{vname} must switch its side in step with {name}"})
            if contract in ("EXPIRED", "NONE_ON_RECORD") and readiness != "READY":
                uncontracted.append((vname, contract))
            if children:
                add(_finding(
                    "VENDOR_SUB_TIER", "INFO", f"{vname} depends on {len(children)} sub-tier vendor(s)",
                    ", ".join(sorted(children)[:6]), system=name, subject=vname,
                    who_acts=f"{vname} (vendor)",
                    mitigation="ask the vendor to confirm its own suppliers' readiness",
                    if_ignored="a supplier further down can hold the vendor's release back",
                    basis="VENDOR_DEPENDENCY"))

        if uncontracted:
            expired = sorted(n for n, state in uncontracted if state == "EXPIRED")
            missing = sorted(n for n, state in uncontracted if state != "EXPIRED")
            add(_finding(
                "VENDOR_NO_SUPPORT_CONTRACT", "MEDIUM",
                f"{len(uncontracted)} supplier(s) in this change without an active support contract",
                "; ".join(part for part in (
                    ("expired: " + ", ".join(expired)) if expired else "",
                    ("none on record: " + ", ".join(missing)) if missing else "") if part),
                system=name, subject=", ".join(sorted(n for n, _ in uncontracted))[:200],
                who_acts="vendor management / procurement",
                mitigation=f"put support agreements in place so the {target} releases, fixes and an "
                           "escalation path are available during the migration",
                if_ignored="a failure during cut-over has no vendor to escalate to",
                basis="ASSET_REGISTER"))

        # -- certificates this system presents
        certificates = []
        for fp in matched_certs:
            if sid not in twin.cert_systems.get(fp, set()):
                continue
            cert = twin.certificates[fp]
            certificates.append({"fingerprint_sha256": fp, "subject": cert.get("subject"),
                                 "issuer": cert.get("issuer"),
                                 "public_key_algorithm": cert.get("public_key_algorithm"),
                                 "not_after": cert.get("not_after"),
                                 "days_until_expiry": cert.get("days_until_expiry")})
        if certificates:
            soon = [c for c in certificates if isinstance(c.get("days_until_expiry"), (int, float))
                    and c["days_until_expiry"] <= 90]
            add(_finding(
                "CERTIFICATES_TO_REISSUE", "HIGH" if "signature" in target_profile["roles"] else "MEDIUM",
                f"{len(certificates)} {source} certificate(s) to reissue",
                ("issuers: " + ", ".join(sorted({str(c.get('issuer') or 'unknown') for c in certificates})[:4]))
                + (f"; {len(soon)} expire within 90 days — renew straight into the new algorithm"
                   if soon else ""),
                system=name, who_acts="the PKI team",
                mitigation=("confirm the issuing CA can sign with the new algorithm, issue the new "
                            "certificates, and distribute the new chain to every relying party "
                            "before switching"),
                if_ignored="relying parties that do not trust the new chain reject the connection",
                basis="CERTIFICATE_USAGE"))
            if connections or endpoints:
                reasons_parallel.append({
                    "code": "RELYING_PARTIES",
                    "text": "relying parties must trust the new chain before the old one is withdrawn"})

        # -- data and signatures that outlive the switch
        if "encryption" in source_profile["roles"]:
            add(_finding(
                "STORED_DATA", "HIGH", f"data encrypted under {source} stays encrypted under it",
                "changing the algorithm affects new writes only",
                system=name, who_acts="the data owner",
                mitigation=f"keep {source} keys for decryption until the stored data is re-encrypted "
                           f"under {target}",
                if_ignored="old records become unreadable the day the old key is destroyed",
                basis="ALGORITHM_PROPERTY"))
            reasons_parallel.append({"code": "STORED_DATA",
                                     "text": f"existing data stays readable only with {source} keys"})
        if "signature" in source_profile["roles"] and "signature" in target_profile["roles"]:
            add(_finding(
                "EXISTING_SIGNATURES", "MEDIUM", f"signatures already made with {source}",
                "documents, tokens and code signed before the switch still carry the old signature",
                system=name, who_acts="the application team",
                mitigation=f"sign with {target} from cut-over, keep verifying {source} until those "
                           "signatures expire",
                if_ignored="valid old documents fail verification",
                basis="ALGORITHM_PROPERTY"))
            reasons_parallel.append({"code": "EXISTING_SIGNATURES",
                                     "text": f"old {source} signatures must still verify"})

        # -- business weight
        processes = twin.processes.get(sid, [])
        considerations: list[dict[str, str]] = []
        if criticality in ("critical", "high") or processes:
            # weight, not mechanism: a critical system that nothing else needs the old
            # algorithm for can still migrate directly — it needs a window and a rollback
            considerations.append({
                "code": "BUSINESS_CRITICAL",
                "text": (f"criticality {criticality}" if criticality else "carries business processes")
                        + (f"; {len(processes)} business process(es)" if processes else "")
                        + " — schedule a change window with a tested rollback"})
        coverage = str(system.get("coverage_status") or "").upper() or None
        if coverage and coverage not in ("COMPLETE", "FULL", "COVERED"):
            unknowns.append(f"{name}: collection coverage is {coverage}, so parts of its crypto may "
                            "not be in the twin")

        if reasons_block:
            strategy = "BLOCKED"
        elif reasons_parallel:
            strategy = "PARALLEL"
        else:
            strategy = "DIRECT"
        findings.extend(sys_findings)
        system_reports.append({
            "system_id": sid, "name": name, "environment": system.get("environment"),
            "criticality": system.get("criticality"),
            "migration_wave": system.get("migration_wave"),
            "why_in_change": sorted(touched.get(sid, set())),
            "strategy": strategy,
            "blocked_by": reasons_block,
            "parallel_because": reasons_parallel,
            "considerations": considerations,
            "twin": {
                "crypto_assets": own_assets[:MAX_LISTED],
                "crypto_assets_using_source": own_matched[:MAX_LISTED],
                "evidence_records_using_source": sum(
                    1 for e in matched_evidence if str(e.get("system_id")) == sid),
                "hardware": hardware,
                "platform": twin.platform.get(sid, [])[:20],
                "software": {"libraries": sorted(libraries.values(), key=lambda x: x["name"]),
                             "deployments": [{"deployment_key": d.get("deployment_key"),
                                              "environment": d.get("environment"),
                                              "artifact_id": d.get("artifact_id")}
                                             for d in deployments[:20]]},
                "connections": connections,
                "network_endpoints": endpoints,
                "vendors": vendors,
                "certificates": certificates,
                "business_processes": [{"name": p.get("name"), "role": p.get("role"),
                                        "revenue_daily": p.get("revenue_daily"),
                                        "customer_count": p.get("customer_count")}
                                       for p in processes[:20]],
            },
            "findings": sorted(sys_findings, key=lambda f: (_SEVERITY_RANK[f["severity"]], f["code"])),
        })

    # ---- 3. overall strategy and parallel mechanisms --------------------- #
    global_block = [f for f in findings if f["code"] == "TARGET_ROLE_MISMATCH"]
    if global_block:
        overall = "BLOCKED"
    elif not system_reports:
        overall = "NOT_DETERMINED"
    else:
        overall = max((r["strategy"] for r in system_reports), key=lambda s: _STRATEGY_RANK[s])
    counts = {name: sum(1 for r in system_reports if r["strategy"] == name)
              for name in ("BLOCKED", "PARALLEL", "DIRECT")}
    reason_counts: dict[str, int] = {}
    for report in system_reports:
        for reason in {r["code"] for r in report["parallel_because"] + report["blocked_by"]}:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    mechanisms: list[dict[str, str]] = []
    if overall in ("PARALLEL", "BLOCKED") and system_reports:
        if "key_establishment" in target_profile["roles"] and target_profile["pqc"]:
            mechanisms.append({
                "mechanism": "HYBRID_KEY_EXCHANGE",
                "how": f"offer a hybrid group (classical + {target}, e.g. X25519MLKEM768) on TLS 1.3: "
                       "upgraded peers negotiate it, the rest fall back to the classical group"})
        if any(r["twin"]["certificates"] for r in system_reports) or "signature" in target_profile["roles"]:
            mechanisms.append({
                "mechanism": "DUAL_CERTIFICATE_CHAIN",
                "how": f"serve both the {source} and the {target} chain (or a composite certificate) "
                       "until every relying party trusts the new root"})
        if "encryption" in source_profile["roles"]:
            mechanisms.append({
                "mechanism": "DUAL_KEY_PERIOD",
                "how": f"write new data under {target}, keep {source} keys read-only until the "
                       "stored data is re-encrypted"})
        if "signature" in source_profile["roles"] and "signature" in target_profile["roles"]:
            mechanisms.append({
                "mechanism": "DUAL_VERIFY",
                "how": f"sign with {target}, keep verifying {source} signatures until they expire"})
        mechanisms.append({
            "mechanism": "PER_CONNECTION_SWITCH",
            "how": "make the algorithm a per-connection setting so each peer and vendor moves on its "
                   "own date and can be rolled back alone"})

    # ---- 4. the plan: phases, systems in dependency order ---------------- #
    callees: dict[str, set[str]] = {sid: set() for sid in change_set}
    for edge in twin.dependencies:
        src, dst = str(edge.get("source")), str(edge.get("target"))
        if src in change and dst in change and src != dst:
            callees[src].add(dst)  # src calls dst: dst is the provider and moves first
    wave: dict[str, int] = {}
    cyclic: set[str] = set()
    for _ in range(len(change_set) + 1):
        progressed = False
        for sid in change_set:
            if sid in wave:
                continue
            if all(c in wave for c in callees[sid]):
                wave[sid] = 1 + max((wave[c] for c in callees[sid]), default=-1)
                progressed = True
        if not progressed:
            break
    for sid in change_set:
        if sid not in wave:
            cyclic.add(sid)
            wave[sid] = 1 + max(wave.values(), default=-1)
    ordered = sorted(change_set, key=lambda s: (wave[s], twin.name(s)))
    by_wave: dict[int, list[str]] = {}
    for sid in ordered:
        by_wave.setdefault(wave[sid], []).append(sid)
    report_by_id = {r["system_id"]: r for r in system_reports}

    prereq_codes = {"HARDWARE_CANNOT_RUN_TARGET", "HARDWARE_CAPABILITY_UNKNOWN", "LIBRARY_LACKS_TARGET",
                    "TLS_VERSION_TOO_OLD", "VENDOR_NOT_READY", "VENDOR_CAPABILITY_UNKNOWN",
                    "HARDCODED_KEYS", "TARGET_ROLE_MISMATCH", "LIBRARY_DEPRECATED"}
    prereqs = [f for f in findings if f["code"] in prereq_codes]
    steps: list[dict[str, Any]] = []
    if prereqs:
        steps.append({
            "phase": "PREREQUISITES", "title": "Clear what stops the migration",
            "systems": sorted({f["system"] for f in prereqs if f.get("system")}),
            "actions": [f"{f['title']} — {f['mitigation']}" for f in
                        sorted(prereqs, key=lambda f: (_SEVERITY_RANK[f["severity"]], f["code"]))][:MAX_LISTED],
            "exit_criteria": "every blocker is closed with evidence (capability list, vendor statement, "
                             "release) and recorded in the twin",
            "rollback": "nothing to roll back — no production change yet"})
    if system_reports:
        key_actions = [f"generate {target} keys for {r['name']}"
                       + (" in " + ", ".join(str(h["asset_id"]) for h in r["twin"]["hardware"][:3])
                          if r["twin"]["hardware"] else "")
                       for r in system_reports]
        cert_systems = [r["name"] for r in system_reports if r["twin"]["certificates"]]
        if cert_systems:
            key_actions.append(f"issue {target} certificates for {', '.join(cert_systems[:8])} and "
                               "distribute the new trust anchors to relying parties")
        steps.append({
            "phase": "KEYS_AND_TRUST", "title": f"Prepare {target} keys and trust",
            "systems": [r["name"] for r in system_reports],
            "actions": key_actions[:MAX_LISTED],
            "exit_criteria": "new keys exist where the system will use them; relying parties trust "
                             "the new chain",
            "rollback": "unused keys and certificates are revoked; nothing is serving them yet"})
    for number in sorted(by_wave):
        members = [report_by_id[s] for s in by_wave[number] if s in report_by_id]
        parallel = [m["name"] for m in members if m["strategy"] in ("PARALLEL", "BLOCKED")]
        direct = [m["name"] for m in members if m["strategy"] == "DIRECT"]
        if parallel:
            steps.append({
                "phase": "ENABLE_ALONGSIDE", "wave": number + 1,
                "title": f"Wave {number + 1}: enable {target} next to {source}",
                "systems": parallel,
                "actions": [f"{name}: accept and offer {target} while still accepting {source}"
                            for name in parallel],
                "exit_criteria": "both algorithms negotiate; monitoring shows which peers use which",
                "rollback": f"switch {target} off again — {source} never stopped working"})
        steps.append({
            "phase": "CUT_OVER", "wave": number + 1,
            "title": f"Wave {number + 1}: move to {target}",
            "systems": [m["name"] for m in members],
            "actions": ([f"{name}: switch to {target} in one planned window" for name in direct]
                        + [f"{name}: prefer {target}; move each connected peer and vendor once it "
                           "confirms" for name in parallel]),
            "exit_criteria": "handshakes, signatures and business transactions succeed on the new "
                             "algorithm for every listed system",
            "rollback": (f"re-enable {source} on the affected connections" if parallel else
                         f"restore the previous configuration/release with {source}"),
            "providers_first": "systems that others call move before their callers"})
    if system_reports:
        steps.append({
            "phase": "VERIFY", "title": "Verify on the twin and in production",
            "systems": [r["name"] for r in system_reports],
            "actions": ["re-scan the changed systems so the twin shows the new algorithm",
                        "run each business process's smoke test",
                        "confirm no connection still negotiates " + source],
            "exit_criteria": f"the twin no longer reports {source} on these systems",
            "rollback": "per-wave rollback above"})
        steps.append({
            "phase": "DECOMMISSION", "title": f"Retire {source}",
            "systems": [r["name"] for r in system_reports],
            "actions": [f"disable {source} once every peer and vendor has confirmed {target}",
                        *([f"keep {source} keys read-only until stored data is re-encrypted"]
                          if "encryption" in source_profile["roles"] else []),
                        *([f"keep {source} verification until old signatures expire"]
                          if "signature" in source_profile["roles"] else [])],
            "exit_criteria": f"no system, peer or vendor depends on {source}",
            "rollback": f"re-enable {source} (keys are destroyed only after a holding period)"})
    for index, step in enumerate(steps, start=1):
        step["order"] = index

    # ---- 5. vendor and connected-system impact --------------------------- #
    vendor_impact = []
    for agg in vendor_index.values():
        readiness = agg["readiness"]
        vendor_impact.append({
            "vendor_id": agg["vendor_id"], "name": agg["name"], "criticality": agg["criticality"],
            "vendor_type": agg["vendor_type"], "readiness": readiness,
            "systems": sorted(set(agg["systems"])),
            "dependency_types": sorted(agg["dependency_types"]),
            "products": agg["products"], "sub_tier": agg["sub_tier"],
            "contract_state": agg.get("contract_state"), "contract_end": agg.get("contract_end"),
            "needs_to": {
                "READY": "switch its side of each integration in the same window as the system",
                "NOT_READY": f"ship {target} support — the listed systems wait for it",
                "RELEASE_NOT_READY": f"provide (and support) the release that ships {target}; the "
                                     "deployed one does not",
                "UNKNOWN": f"state whether its product supports {target}",
                "NOT_RECORDED_FOR_TARGET": f"confirm {target} support for the products in use",
            }[readiness],
            "if_it_does_not": "its integrations with the listed systems fail at cut-over, or keep "
                              f"{source} alive indefinitely"})
    vendor_impact.sort(key=lambda v: ({"NOT_READY": 0, "RELEASE_NOT_READY": 1, "UNKNOWN": 2,
                                       "NOT_RECORDED_FOR_TARGET": 3, "READY": 4}[v["readiness"]], str(v["name"])))
    connected_impact = []
    for entry in connected_index.values():
        if entry["in_change"]:
            effect = ("also changes in this simulation — coordinate the order "
                      "(providers first)")
            action = "move in its own wave of the plan"
        elif entry["uses_target"]:
            effect = (f"already uses {target} elsewhere; its connection to the changed system "
                      "must still be confirmed to negotiate it")
            action = f"test the connection on {target} before {source} is withdrawn"
        else:
            effect = (f"keeps using {source}; if the connected system switches without it, the "
                      "connection fails")
            action = f"confirm {target} support, or keep {source} on this connection"
        connected_impact.append({**entry, "links": entry["links"][:20], "effect": effect,
                                 "action": action})
    connected_impact.sort(key=lambda c: (c["in_change"], str(c["name"])))

    # ---- 6. what the twin could not answer ------------------------------- #
    unknowns = sorted(set(unknowns))
    base_unknowns = [
        "which algorithm each connection negotiates is not recorded on dependency edges; a "
        "connected system is treated as needing the old algorithm until it confirms",
        "clients of a network endpoint are not assets in the twin, so they cannot be checked",
        "hardware and vendor capability is as recorded or declared — not independently tested",
        "performance of the new algorithm on this estate is not measured here",
    ]
    if unowned_assets or unowned_evidence:
        base_unknowns.append(
            f"{len(unowned_assets)} twin asset(s) and {unowned_evidence} evidence record(s) use "
            f"{source} but are linked to no system, so they are not in any wave")
    if unresolved_scope:
        base_unknowns.append("requested system(s) not found in the twin: " + ", ".join(unresolved_scope))
    coverage = snapshot.get("source_coverage") or {}
    truncated = sorted(name for name, row in (coverage.get("collections") or {}).items()
                       if isinstance(row, Mapping) and row.get("truncated"))
    if truncated:
        base_unknowns.append("the twin snapshot hit read limits on: " + ", ".join(truncated))
    if not twin.hardware and snapshot.get("source") == "ESTATE_GRAPH":
        base_unknowns.append("no HSM is linked to any system in the estate graph, so no key-holding "
                             "device capability could be checked")
    elif not twin.hardware:
        base_unknowns.append("the twin holds no hardware fleet, so no device capability could be checked")
    if not twin.vendor_crypto:
        base_unknowns.append("no vendor crypto inventory is recorded, so no vendor readiness is proven")
    if not twin.dependencies:
        base_unknowns.append("no system dependencies are recorded, so connected systems are unknown")

    findings_sorted = sorted(findings, key=lambda f: (_SEVERITY_RANK[f["severity"]], f["code"],
                                                      str(f.get("system")), str(f.get("subject"))))
    severity_counts = {name: sum(1 for f in findings if f["severity"] == name) for name in SEVERITIES}
    all_hw = {h["asset_id"] for r in system_reports for h in r["twin"]["hardware"]}
    all_servers = {h["asset_id"] for r in system_reports for h in r["twin"].get("platform") or []}
    all_libs = {lib["name"] for r in system_reports for lib in r["twin"]["software"]["libraries"]}
    all_peers = {c["system_id"] for r in system_reports for c in r["twin"]["connections"]}
    all_eps = {e["endpoint"] for r in system_reports for e in r["twin"]["network_endpoints"]}
    all_certs = {c["fingerprint_sha256"] for r in system_reports for c in r["twin"]["certificates"]}

    if overall == "NOT_DETERMINED":
        headline = (f"No system in the twin uses {source}" + (" within the requested scope" if scope is not None else "")
                    + " — that is not 'no impact': the twin may not have collected it")
    else:
        headline = (f"{source} → {target}: {len(system_reports)} system(s) — "
                    f"{counts['BLOCKED']} blocked, {counts['PARALLEL']} need a parallel run, "
                    f"{counts['DIRECT']} can migrate directly. Recommended: "
                    f"{overall.replace('_', ' ').lower()} migration")

    return {
        "schema": SCHEMA,
        "change": {"from": source, "to": target, "from_profile": source_profile,
                   "to_profile": target_profile,
                   "scope": sorted(scope) if scope is not None else None},
        "headline": headline,
        "strategy": {
            "recommended": overall,
            "meaning": STRATEGIES[overall],
            "systems": counts,
            "reasons": dict(sorted(reason_counts.items())),
            "parallel_mechanisms": mechanisms,
            "direct_is_safe_when": "no connected system outside the change, no network endpoint with "
                                   "unseen clients, no vendor, no stored data or signatures under the "
                                   "old algorithm, and every device's capability is recorded",
        },
        "twin_context": {
            "source": (
                "Live estate graph — the agents' observations (systems from the bank-approved "
                "mapping, hosts, services, libraries, listening endpoints and their negotiated "
                "TLS, certificates, HSMs, platform servers, vendors and their contracts, "
                "declared and observed system connections)"
                if snapshot.get("source") == "ESTATE_GRAPH" else
                "Digital Twin snapshot (systems, hardware fleet, crypto↔hardware links, "
                "system↔vendor links, vendor crypto inventory, system dependencies, observed "
                "TLS endpoints, certificate usage, library catalog, software deployments)"),
            "kind": "ESTATE_GRAPH" if snapshot.get("source") == "ESTATE_GRAPH" else "DIGITAL_TWIN",
            "systems_in_change": len(system_reports),
            "hardware": len(all_hw), "servers": len(all_servers), "software_libraries": len(all_libs),
            "connected_systems": len(all_peers), "network_endpoints": len(all_eps),
            "vendors": len(vendor_index), "certificates": len(all_certs),
            "matched": {"twin_assets": len(matched_assets), "evidence_records": len(matched_evidence),
                        "certificates": len(matched_certs), "network_endpoints": len(matched_endpoints)},
        },
        "systems": system_reports,
        "problems": findings_sorted[:MAX_LISTED * 4],
        "problem_counts": severity_counts,
        "vendor_impact": vendor_impact,
        "connected_impact": connected_impact,
        "plan": steps,
        "dependency_order": [{"wave": wave[s] + 1, "system": twin.name(s),
                              "cyclic": s in cyclic} for s in ordered],
        "unknowns": base_unknowns + unknowns[:MAX_LISTED],
        "deterministic": True,
        "mutates_nothing": True,
    }
