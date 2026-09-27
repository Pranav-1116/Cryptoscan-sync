"""Assurance & Control — VEX prioritization, xBOM correlation, admission gate, runtime drift.

Implements the capabilities the platform gap-analysis called out as missing, as
PURE deterministic functions over the same unified asset model the Technology BOM
uses (so a single asset still updates every layer):

1. **VEX enrichment** (`assess_vex`)  — turn a flat CVE/finding list into a
   priority-ranked, exploitability-aware triage with a CycloneDX VEX lifecycle
   status per item (not_affected / affected / fixed / under_review).
2. **xBOM correlation** (`correlate_xbom`) — walk ONE ``bom-ref`` (or the whole
   estate) across SBOM -> CBOM -> HBOM -> VBOM -> business process, so an
   incident operator can answer "what crypto, app, hardware, vendor and business
   process does this touch?".
3. **Admission gate** (`evaluate_admission`) — a pre-deploy PASS / FAIL / WARN
   decision over a materialized BOM, reusing the same weak-algorithm + blocking-
   purpose doctrine as the CI drift gate, but applied to the unified BOM.
4. **Runtime verification** (`runtime_drift`) — compare real runtime observations
   (TLS version, cipher, algorithm, key size) against the BOM baseline to catch
   drift the moment it happens, not on the next scheduled scan.

Every function is pure (no DB / I/O / FastAPI): it takes materialized state
and/or lists of records and returns a plain dict. The router gathers the real
rows from the inventory DB and hands them in.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# --------------------------------------------------------------------------- #
# VEX lifecycle statuses (CycloneDX 1.5 spec + NTIA VEX framework)
# --------------------------------------------------------------------------- #
VEX_STATUSES = ("not_affected", "affected", "fixed", "under_review")

# --------------------------------------------------------------------------- #
# Weak-algorithm doctrine (mirrors drift.core.gate so gate decisions agree with
# the drift gate; kept local so this engine stays import-light and unit-testable)
# --------------------------------------------------------------------------- #
BLOCKING_PURPOSES = {
    "ENCRYPTION",
    "KEY_EXCHANGE",
    "KEY_AGREEMENT",
    "SIGNING",
    "KEY_STORAGE",
}

WEAK_ALGORITHMS = {
    "DES",
    "3DES",
    "DESEDE",
    "TRIPLEDES",
    "DES-EDE3",
    "RC2",
    "RC4",
    "BLOWFISH",
    "MD5",
    "MD4",
    "SHA-1",
    "SHA1",
    "ECB",
}

WEAK_HASH_ONLY = {"MD5", "MD4", "SHA-1", "SHA1"}

#: minimum acceptable asymmetric key size (NIST SP 800-57 / 800-131A baseline)
MIN_RSA_KEY_SIZE = 2048
MIN_DH_KEY_SIZE = 2048
MIN_ECC_KEY_SIZE = 224

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "NONE": 4}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def _norm(v: Any) -> str:
    return str(v or "").upper()


def _algo(component: Mapping[str, Any]) -> str:
    return _norm(component.get("algorithm") or component.get("name")
                 or component.get("cve") or component.get("package"))


def _purpose(component: Mapping[str, Any]) -> str:
    return _norm(component.get("purpose") or component.get("mode"))


def _key_size(component: Mapping[str, Any]) -> int | None:
    v = component.get("key_size")
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def is_weak(component: Mapping[str, Any]) -> bool:
    """Deterministic weak-crypto verdict for one component (policy-adjacent)."""
    algo = _algo(component)
    mode = _norm(component.get("mode"))
    if algo in WEAK_ALGORITHMS:
        return True
    # AES-ECB is a classically-weak mode regardless of key size
    if algo.startswith("AES") and mode == "ECB":
        return True
    if algo.startswith(
        ("RSA", "ECDSA", "ECDH", "DSA", "DH-", "DH ", "ED25519", "ED448")
    ):
        ks = _key_size(component)
        if ks is not None:
            if algo.startswith(("RSA", "DSA", "DH")):
                return ks < MIN_RSA_KEY_SIZE
            if algo.startswith(("ECDSA", "ECDH", "ED")):
                return ks < MIN_ECC_KEY_SIZE
    return False


def is_blocking(component: Mapping[str, Any]) -> bool:
    """True when the component sits in a blocking-purpose site and is weak."""
    purpose = _purpose(component)
    if purpose not in BLOCKING_PURPOSES:
        return False
    algo = _algo(component)
    if algo in WEAK_HASH_ONLY:
        # hashing is not an encrypt/key-store purpose — never block
        return False
    return is_weak(component) or (algo.startswith("AES") and _norm(component.get("mode")) == "ECB")


# --------------------------------------------------------------------------- #
# 1. VEX enrichment
# --------------------------------------------------------------------------- #
def _exploitability(component: Mapping[str, Any], vuln: Mapping[str, Any]) -> tuple[float, list[str]]:
    """Best-effort, deterministic exploitability score in [0, 1] + reasons.

    Uses only data the platform already has (severity, reachability, blocking
    purpose, weak algorithm, real production usage). It is deliberately NOT EPSS:
    it is an honest in-platform heuristic that avoids claiming an external feed.
    """
    score = 0.0
    reasons: list[str] = []

    sev = _norm(vuln.get("severity") or vuln.get("status"))
    if sev in SEVERITY_RANK:
        # CRITICAL 1.0 ... LOW 0.25, UNKNOWN pins to 0.25
        score += max(0.25, 1.0 - (SEVERITY_RANK[sev] * 0.25))
        reasons.append(f"severity={sev.title()}")

    if is_blocking(component):
        score += 0.25
        reasons.append("blocking-purpose weak crypto (deploy-relevant)")
    elif is_weak(component):
        score += 0.12
        reasons.append("weak algorithm")

    if vuln.get("reachable"):
        score += 0.25
        reasons.append("reachable in production graph")
    elif vuln.get("runtime_observed"):
        score += 0.15
        reasons.append("observed in live runtime")

    if component.get("used_in_production"):
        score += 0.1
        reasons.append("used in production")

    return min(score, 1.0), reasons


def _severity_of(vuln: Mapping[str, Any], exploitability: float) -> str:
    """Combine the CVSS severity with exploitability into an action priority."""
    sev = _norm(vuln.get("severity") or "UNKNOWN")
    # P0 (fix now) when the base severity is CRITICAL/HIGH AND it is exploitable,
    # or when a weak algorithm is actually deployed in a blocking purpose.
    if sev in ("CRITICAL", "HIGH") and exploitability >= 0.5:
        return "P0"
    if sev in ("CRITICAL", "HIGH") or exploitability >= 0.5:
        return "P1"
    if sev in ("MEDIUM",) or exploitability >= 0.3:
        return "P2"
    return "P3"


def _vex_status(component: Mapping[str, Any], vuln: Mapping[str, Any]) -> str:
    """Assign the CycloneDX VEX lifecycle status for one (cve, component) pair."""
    applicable = vuln.get("applicable", True)
    if not applicable:
        return "not_affected"

    fixed = vuln.get("fixed") or vuln.get("resolved")
    if fixed:
        return "fixed"

    # A vulnerability whose component is not actually present in the BOM is
    # 'not_affected' (we can prove the component is not deployed).
    if vuln.get("component_present") is False:
        return "not_affected"

    if vuln.get("reachable") or is_blocking(component) or vuln.get("status") == "INTERESTING":
        return "affected"

    return "under_review"


def assess_vex(
    components: Iterable[Mapping[str, Any]],
    vulnerabilities: Iterable[Mapping[str, Any]],
    *,
    reachable: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Return a VEX-enriched, priority-ranked finding list + summary.

    ``components`` — the CBOM/affected component set (each has ``bom-ref``,
    ``algorithm``, ``purpose``, ``key_size``...).
    ``vulnerabilities`` — CVE/finding rows (``cve``, ``package``, ``severity``,
    ``summary``, optionally ``applicable``/``fixed``/``component_present``).
    ``reachable`` — a set of ``bom-ref`` values confirmed reachable in prod.
    """
    reachable_set = set(reachable or [])
    comps = list(components)
    by_ref = {c.get("bom-ref"): c for c in comps}
    # index by package/algorithm name too so a CVE about 'openssl' can match a
    # component whose bom-ref is `crypto:...` but package/library is openssl.
    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for c in comps:
        for key in (c.get("name"), c.get("algorithm"), c.get("library"),
                    c.get("package"), c.get("model")):
            if key:
                by_name.setdefault(_norm(key), []).append(c)

    rows: list[dict[str, Any]] = []

    for raw in vulnerabilities:
        vuln = dict(raw)
        cve = vuln.get("cve") or vuln.get("id") or "UNKNOWN"
        affect_ref = vuln.get("bom-ref") or vuln.get("package")
        match = by_ref.get(affect_ref)
        if match is None and affect_ref:
            ar = _norm(affect_ref)
            cands = by_name.get(ar, [])
            if cands:
                # choose the highest-impact match (weak/blocking first)
                cands.sort(key=lambda c: (not is_blocking(c), not is_weak(c)))
                match = cands[0]

        if match is None:
            # component not present -> provably not_affected
            component = {"bom-ref": affect_ref, "algorithm": vuln.get("package"),
                         "purpose": "", "key_size": None}
            present = False
        else:
            component = match
            present = True

        vuln["reachable"] = bool(
            vuln.get("reachable")
            or component.get("bom-ref") in reachable_set
            or component.get("used_in_production")
        )
        vuln["component_present"] = present
        vuln["status_raw"] = vuln.get("status")
        vuln["status"] = _vex_status(component, vuln)

        exploitability, reasons = _exploitability(component, vuln)
        priority = _severity_of(vuln, exploitability)

        rows.append({
            "cve": cve,
            "package": vuln.get("package") or component.get("name") or component.get("library") or component.get("algorithm"),
            "bom_ref": component.get("bom-ref"),
            "severity": _norm(vuln.get("severity") or "UNKNOWN").title(),
            "exploitability": round(exploitability, 2),
            "exploitability_reasons": reasons,
            "vex_status": vuln["status"],
            "priority": priority,
            "component_used_in_production": bool(component.get("used_in_production")),
            "component_is_blocking": is_blocking(component),
            "component_is_weak": is_weak(component),
            "summary": vuln.get("summary") or vuln.get("description") or "",
        })

    # priority rank then severity
    rows.sort(key=lambda r: (PRIORITY_RANK.get(r["priority"], 9), r["exploitability"]), reverse=False)
    by_status = {s: 0 for s in VEX_STATUSES}
    for r in rows:
        by_status[r["vex_status"]] = by_status.get(r["vex_status"], 0) + 1
    by_priority = {p: 0 for p in ("P0", "P1", "P2", "P3")}
    for r in rows:
        by_priority[r["priority"]] = by_priority.get(r["priority"], 0) + 1

    return {
        "total": len(rows),
        "affected": by_status.get("affected", 0),
        "not_affected": by_status.get("not_affected", 0),
        "fixed": by_status.get("fixed", 0),
        "under_review": by_status.get("under_review", 0),
        "by_status": by_status,
        "by_priority": by_priority,
        "top_p0": [r for r in rows if r["priority"] == "P0"],
        "findings": rows,
    }


# --------------------------------------------------------------------------- #
# 2. xBOM correlation
# --------------------------------------------------------------------------- #
def _bom_ref_short(ref: str) -> str:
    return ref.split(":", 1)[-1] if ":" in ref else ref


def correlate_xbom(
    state: Mapping[str, Any],
    *,
    bom_ref: str | None = None,
    system_assets: Iterable[Mapping[str, Any]] | None = None,
    business_processes: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Correlate the four materialized BOM layers (+ business process).

    Builds, for each crypto asset, the chain: cryptoprimitive (CBOM) -> the
    application(s) that use it (SBOM) -> the hardware it sits on (HBOM) -> the
    vendor (VBOM) -> business process. ``system_assets`` is the SystemAsset
    linkage (system_id <-> asset_id); ``business_processes`` the +revenue
    processes. When ``bom_ref`` is given, return only that component's trace.
    """
    layers = (state or {}).get("layers") or {}
    crypto = (layers.get("cbom") or {}).get("components", [])
    apps = (layers.get("sbom") or {}).get("components", [])
    hw = (layers.get("hbom") or {}).get("components", [])
    vends = (layers.get("vendor") or {}).get("components", [])
    # NBOM: what the same crypto asset is exposed as on the wire. A CBOM entry
    # says an algorithm exists in the estate; the NBOM entry says which
    # listener serves it, which is the difference between "we use RSA-1024
    # somewhere" and "api.bank.ae:443 presents it to the internet". Optional —
    # an estate with no network scan correlates exactly as before.
    net = (layers.get("nbom") or {}).get("components", [])

    # normalise system_assets: {system_id -> [asset_id, ...]}
    sa: dict[str, list[str]] = {}
    for link in system_assets or []:
        sa.setdefault(str(link.get("system_id")), []).append(str(link.get("asset_id")))

    # asset_id -> crypto component (by bom-ref suffix or asset field)
    crypto_by_asset: dict[str, Mapping[str, Any]] = {}
    for c in crypto:
        asset = str(c.get("asset") or c.get("host") or "")
        if asset:
            crypto_by_asset.setdefault(asset, c)
        ref = str(c.get("bom-ref") or "")
        crypto_by_asset.setdefault(_bom_ref_short(ref), c)

    # system_id -> app component (SBOM) ; app bom-ref suffix == system id
    app_by_system: dict[str, Mapping[str, Any]] = {}
    for a in apps:
        sid = _bom_ref_short(str(a.get("bom-ref") or ""))
        app_by_system.setdefault(sid, a)

    # crypto -> which systems use it (via system_assets) -> app
    def _app_for_crypto(c) -> list[Mapping[str, Any]]:
        used: list[Mapping[str, Any]] = []
        asset = str(c.get("asset") or c.get("host") or "")
        for sys_id, asset_ids in sa.items():
            if asset and asset in asset_ids:
                a = app_by_system.get(sys_id)
                if a:
                    used.append(a)
        # also match by asset name directly to a system name
        if not used and asset:
            for a in apps:
                if a.get("name") == asset or _bom_ref_short(a.get("bom-ref") or "") == asset:
                    used.append(a)
        return used

    def _network_for(asset: str) -> list[Mapping[str, Any]]:
        """NBOM components exposing this asset on the wire.

        Matched on the host, which is the field both layers share: an NBOM
        endpoint is named ``host:port`` and carries a ``cryptoscan:host``
        property, while a CBOM asset carries the host it was found on.
        """
        if not asset:
            return []
        out: list[Mapping[str, Any]] = []
        for n in net:
            props = {p.get("name"): p.get("value") for p in (n.get("properties") or [])}
            host = props.get("cryptoscan:host") or ""
            name = str(n.get("name") or "")
            if host == asset or name == asset or name.split(":")[0] == asset:
                out.append(n)
        return out

    traces: list[dict[str, Any]] = []
    for c in crypto:
        used_apps = _app_for_crypto(c)
        hw_for = None
        asset = str(c.get("asset") or c.get("host") or "")
        if asset:
            for h in hw:
                if str(h.get("asset") or h.get("asset_id")) == asset:
                    hw_for = h
                    break
            if hw_for is None:
                for h in hw:
                    if _bom_ref_short(str(h.get("bom-ref") or "")) == asset:
                        hw_for = h
                        break
        vendor_for = None
        if hw_for is not None:
            vendor_name = (hw_for.get("manufacturer") or "").lower()
            for v in vends:
                if str(v.get("name") or "").lower() == vendor_name:
                    vendor_for = v
                    break
        # business processes bound to the apps that use this crypto
        bps: list[Mapping[str, Any]] = []
        for bp in business_processes or []:
            links = bp.get("system_ids") or []
            if any(_bom_ref_short(str(a.get("bom-ref") or "")) in {str(x) for x in links} for a in used_apps):
                bps.append(bp)

        trace = {
            "crypto": {"bom-ref": c.get("bom-ref"), "algorithm": c.get("algorithm"),
                       "key_size": c.get("key_size"), "purpose": c.get("purpose"),
                       "weak": is_weak(c), "blocking": is_blocking(c),
                       "asset": c.get("asset") or c.get("host") or ""},
            "applications": [{"bom-ref": a.get("bom-ref"), "name": a.get("name"),
                              "version": a.get("version"), "criticality": a.get("criticality")}
                             for a in used_apps],
            "hardware": ({"bom-ref": hw_for.get("bom-ref"), "model": hw_for.get("model"),
                          "manufacturer": hw_for.get("manufacturer"),
                          "device_type": hw_for.get("device_type")} if hw_for else None),
            "vendor": ({"bom-ref": vendor_for.get("bom-ref"), "name": vendor_for.get("name"),
                        "risk_level": vendor_for.get("risk_level"),
                        "lifecycle": vendor_for.get("lifecycle")} if vendor_for else None),
            "business_processes": [{"name": bp.get("name"), "process_type": bp.get("process_type"),
                                    "revenue_daily": bp.get("revenue_daily"),
                                    "sla_uptime": bp.get("sla_uptime")} for bp in bps],
            "network": [
                {"bom-ref": n.get("bom-ref"), "name": n.get("name"),
                 "kind": next((p.get("value") for p in (n.get("properties") or [])
                               if p.get("name") == "cryptoscan:kind"), None),
                 "findings": len(n.get("cryptoscan:findings") or [])}
                for n in _network_for(asset)
            ],
            "impact_count": {
                "applications": len(used_apps),
                "hardware": 1 if hw_for else 0,
                "vendors": 1 if vendor_for else 0,
                "business_processes": len(bps),
                "network_exposure": len(_network_for(asset)),
            },
        }
        if bom_ref is None or c.get("bom-ref") == bom_ref:
            traces.append(trace)

    if bom_ref is not None:
        # also allow correlating from an SBOM/HBOM/VBOM ref directly
        filtered = [t for t in traces if t["crypto"]["bom-ref"] == bom_ref]
        if not filtered:
            filtered = [t for t in traces if t["crypto"]["bom-ref"] == f"crypto:{bom_ref}"]
        traces = filtered

    affected = sum(1 for t in traces if t["crypto"]["blocking"])
    return {
        "layer_set": ["sbom", "cbom", "hbom", "vendor"],
        "traces": traces,
        "count": len(traces),
        "deploy_relevant": affected,
        "highest_impact": max((t["impact_count"]["business_processes"] for t in traces), default=0),
    }


# --------------------------------------------------------------------------- #
# 3. Admission gate (pre-deploy)
# --------------------------------------------------------------------------- #
def evaluate_admission(
    state: Mapping[str, Any],
    *,
    require_baseline: bool = False,
    baseline: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Decide whether a materialized BOM may be admitted to production.

    Returns PASS / WARN / FAIL with per-component reasons (PASS is returned when
    no weak crypto sits in a blocking purpose; WARN for weak-but-non-blocking
    crypto; FAIL blocks whenever a blocking-purpose weak algorithm is deployed).
    """
    layers = (state or {}).get("layers") or {}
    cbom = (layers.get("cbom") or {}).get("components", [])
    blocking: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for c in cbom:
        ref = c.get("bom-ref")
        if is_blocking(c):
            blocking.append({
                "bom_ref": ref, "algorithm": c.get("algorithm"), "purpose": c.get("purpose"),
                "key_size": c.get("key_size"), "reason": f"{c.get('algorithm')} {c.get('purpose')} is weak at a blocking purpose",
            })
        elif is_weak(c):
            warnings.append({
                "bom_ref": ref, "algorithm": c.get("algorithm"), "purpose": c.get("purpose"),
                "key_size": c.get("key_size"), "reason": f"{c.get('algorithm')} is weak (non-blocking purpose)",
            })

    if require_baseline and baseline is None:
        warnings.append({"bom_ref": None, "reason": "No approved baseline — admission is not compared"})

    if blocking:
        decision = "FAIL"
    elif warnings:
        decision = "WARN"
    else:
        decision = "PASS"

    return {
        "decision": decision,
        "admitted": decision == "PASS",
        "blocking_count": len(blocking),
        "warn_count": len(warnings),
        "blocking": blocking,
        "warnings": warnings,
        "snapshot_id": state.get("snapshot_id"),
        "state_version": state.get("state_version"),
        "environment": state.get("environment"),
    }


# --------------------------------------------------------------------------- #
# 4. Runtime verification (continuous drift)
# --------------------------------------------------------------------------- #
def runtime_drift(
    state: Mapping[str, Any],
    runtime_observations: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare real runtime observations against the materialized BOM baseline.

    Runtime observations carry the actual cipher/TLS/algorithm the platform saw
    live (TLS version, cipher suite, algorithm, key size). A runtime algorithm
    that is weak, or a TLS version below 1.2, that is NOT represented in the BOM's
    CBOM layer is flagged as runtime-only drift — the gap point-in-time scans miss.
    """
    layers = (state or {}).get("layers") or {}
    cbom = (layers.get("cbom") or {}).get("components", [])
    bom_algos = {_norm(c.get("algorithm")) for c in cbom}
    bom_weak = {_norm(c.get("algorithm")) for c in cbom if is_weak(c)}

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for obs in runtime_observations or []:
        host = str(obs.get("hostname") or "")
        process = str(obs.get("process_name") or "")
        algo = _norm(obs.get("algorithm"))
        tls = _norm(obs.get("tls_version"))
        cipher = _norm(obs.get("cipher_suite"))
        key = _norm(obs.get("key_size"))
        dedup_key = (algo, host)
        if algo and dedup_key in seen:
            continue
        seen.add(dedup_key)

        weak = algo in WEAK_ALGORITHMS
        # ECDHE-RSA-AES256-GCM-SHA384 => RSA present; describe family
        family = ""
        for known in ("RSA", "ECDSA", "ECDHE", "AES", "CHACHA20", "DHE"):
            if known in cipher or known in algo:
                family = known
                break

        runtime_only = bool(algo) and algo not in bom_algos
        bom_has_weak = bool(algo) and algo in bom_weak
        tls_weak = tls in ("1.0", "1.1", "") and bool(tls)
        if not tls and "1.0" in cipher:
            tls_weak = True

        rows.append({
            "hostname": host,
            "process_name": process,
            "algorithm": algo or family,
            "key_size": key,
            "tls_version": tls or None,
            "cipher_suite": cipher or None,
            "weak": weak or tls_weak,
            "tls_weak": tls_weak,
            "runtime_only": runtime_only,
            "bom_has_weak": bom_has_weak,
            "drift": runtime_only or weak or tls_weak,
            "drift_reason": (
                "runtime-only (not in BOM)" if runtime_only else
                ("weak algorithm observed at runtime" if weak else
                 ("TLS version below 1.2" if tls_weak else "within baseline"))
            ),
        })

    drifted = [r for r in rows if r["drift"]]
    strictly_runtime_only = [r for r in rows if r["runtime_only"]]
    return {
        "observed": len(rows),
        "drifted": len(drifted),
        "runtime_only": len(strictly_runtime_only),
        "weak_at_runtime": sum(1 for r in rows if r["weak"]),
        "tls_below_1_2": sum(1 for r in rows if r["tls_weak"]),
        "drift_rows": rows,
        "halting": [r for r in drifted if r["weak"]],
    }
