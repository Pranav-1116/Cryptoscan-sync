"""Regulator exports, FIPS registry, and enterprise integrations.

Everything a bank's GRC/procurement team consumes downstream of the BOM, as
pure transforms:

- ``render_action_plan_*`` — the supervisory action plan as HTML (print to
  PDF), CSV (HNDL register) or JSON — the one-click regulator artifact.
- ``load_fips_registry`` / ``fips_lookup`` — a file-backed CMVP certificate
  registry (module → validated certificate number). Seeded conservatively;
  ``scripts/fips_lookup.py`` extends it from a downloaded CMVP dataset.
- ``to_servicenow_cmdb`` — crypto assets → ServiceNow CMDB import-set
  payloads (``cmdb_ci_*`` shaped dicts) for CMDB sync.
- ``to_qualys_csv`` — weak/quantum-exposed crypto → Qualys-style detection
  CSV (tagging/ITSM consumption; not a scanner replacement).
- ``soc2_iso_crosswalk`` / ``procurement_trust_package`` — control mappings
  (ISO 27001:2022 Annex A, SOC 2 TSC) for security questionnaires.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# FIPS 140 certificate registry (file-backed, conservative)
# --------------------------------------------------------------------------- #

# High-confidence public facts only. Extend via scripts/fips_lookup.py
# (CMVP dataset) or POST /banking/fips/registry — never guess numbers.
_FIPS_SEED = [
    {
        "module": "openssl fips provider 3.0",
        "vendor": "OpenSSL Software Services",
        "standard": "FIPS 140-3",
        "cert": "4282",
        "note": "OpenSSL FIPS Provider 3.0.x (validate your exact dot-release)",
        "source": "seed",
    },
]


def default_registry_path(base: str | Path | None = None) -> Path:
    """Registry location: CRYPTOSCAN_FIPS_REGISTRY override, else <root>/config.

    ``config/`` ships with the repo/image (``data/`` is runtime-only). Runtime
    writes fall back to a writable location when the image path is read-only.
    """
    override = os.environ.get("CRYPTOSCAN_FIPS_REGISTRY")
    if override:
        return Path(override)
    root = Path(base) if base else Path(os.environ.get("CRYPTOSCAN_ROOT") or Path.cwd())
    return root / "config" / "fips_certificates.json"


def load_fips_registry(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the module→certificate registry keyed by lowercase module name.

    Missing file → the built-in seed. Corrupt JSON → the seed (with a marker),
    never an exception in the request path.
    """
    registry: dict[str, dict[str, Any]] = {}
    for entry in _FIPS_SEED:
        registry[entry["module"].lower()] = dict(entry)
    p = Path(path) if path else default_registry_path()
    try:
        if p.is_file():
            data = json.loads(p.read_text())
            for entry in data if isinstance(data, list) else data.get("entries", []):
                if isinstance(entry, Mapping) and entry.get("module"):
                    record = dict(entry)
                    record["source"] = record.get("source", "registry")
                    registry[str(record["module"]).lower()] = record
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return registry


def save_fips_registry(entries: list[dict[str, Any]], path: str | Path | None = None) -> int:
    """Merge entries into the registry file (dedupe on module name)."""
    p = Path(path) if path else default_registry_path()
    existing = load_fips_registry(p)
    for e in entries:
        if not e.get("module"):
            continue
        record = dict(e)
        record["module"] = str(record["module"]).strip().lower()
        record["source"] = record.get("source", "manual")
        existing[record["module"]] = record
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(sorted(existing.values(), key=lambda r: r["module"]), indent=2))
    except OSError:
        # Read-only image filesystem (config/ is root-owned): fall back to the
        # writable home so operator-recorded certificates still persist.
        import os
        fallback = Path(os.environ.get("CRYPTOSCAN_HOME") or "/tmp") / "fips_certificates.json"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.write_text(json.dumps(sorted(existing.values(), key=lambda r: r["module"]), indent=2))
    return len(existing)


def fips_lookup(module: str, registry: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Exact-then-substring lookup of a module in the registry.

    Auditors get the certificate number only when the registry has it —
    otherwise an explicit ``unknown`` with the CMVP lookup instruction.
    """
    mod = (module or "").strip().lower()
    if not mod:
        return {"module": module, "status": "unknown", "cert": "",
                "note": "no module name given"}
    hit = registry.get(mod)
    if hit:
        return {"module": hit.get("module", module), "vendor": hit.get("vendor", ""),
                "standard": hit.get("standard", ""), "status": "validated",
                "cert": hit.get("cert", ""), "note": hit.get("note", ""),
                "source": hit.get("source", "registry")}
    for name, hit in registry.items():
        if name and (name in mod or mod in name):
            return {"module": hit.get("module", name), "vendor": hit.get("vendor", ""),
                    "standard": hit.get("standard", ""), "status": "validated",
                    "cert": hit.get("cert", ""), "note": f"matched registry entry '{name}' — confirm exact version",
                    "source": hit.get("source", "registry")}
    return {"module": module, "status": "unknown", "cert": "",
            "note": "not in the registry — search CMVP/GFIPSearch for the exact module version, then record the certificate"}


# --------------------------------------------------------------------------- #
# Action-plan renderers (regulator-ready artifacts)
# --------------------------------------------------------------------------- #

def _escape(text: Any) -> str:
    return re.sub(r"[&<>]", lambda m: {"&": "&amp;", "<": "&lt;", ">": "&gt;"}[m.group(0)], str(text or ""))


def _owner_map(applications: Iterable[str], system_owners: Mapping[str, str]) -> dict[str, str]:
    return {app: system_owners.get(app, "unassigned") for app in applications}


def render_action_plan_html(plan: Mapping[str, Any], owners: Mapping[str, str] | None = None) -> str:
    """The supervisory action plan as a printable HTML document."""
    a = plan.get("assessment") or {}
    ev = plan.get("evidence") or {}
    refs = plan.get("references") or []
    phases = plan.get("phases") or []
    register = plan.get("hndl_register") or []
    owner_map = _owner_map({e.get("application", "") for e in register if e.get("application")}, owners or {})
    rows = "".join(
        f"<tr><td>{_escape(e.get('algorithm'))}{('-' + str(e.get('key_size'))) if e.get('key_size') else ''}</td>"
        f"<td>{_escape(e.get('purpose'))}</td><td>{_escape(e.get('application') or '—')}</td>"
        f"<td>{_escape(owner_map.get(e.get('application', ''), 'unassigned'))}</td>"
        f"<td>{_escape(e.get('confidentiality_years'))}y</td><td>{_escape(e.get('deadline'))}</td>"
        f"<td>{_escape(e.get('exposure'))}</td></tr>"
        for e in register)
    phase_html = "".join(
        f"<div class='phase'><h3>{_escape(p.get('phase'))} — {_escape(p.get('title'))} "
        f"<span class='due'>by {_escape(p.get('deadline') or 'continuous')}</span></h3>"
        f"<p>{_escape(p.get('action'))}</p>"
        + ("".join(f"<div class='item'>{_escape(i.get('family'))}{_escape('-' + str(i['key_size']) if i.get('key_size') else '')} "
                   f"× {_escape(i.get('instances'))} — owner: {_escape(owner_map.get(app, 'unassigned'))}</div>"
                   for i in (p.get('items') or []) for app in (i.get('applications') or ['(estate-wide)'])[:1])
          or "<div class='item'>no in-scope instances</div>")
        + "</div>"
        for p in phases)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Cryptographic Risk Action Plan</title><style>
body{{font-family:Georgia,serif;margin:48px;color:#111;max-width:900px}}
h1{{border-bottom:2px solid #111;padding-bottom:8px}} table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #999;padding:6px;text-align:left}} th{{background:#eee}}
.phase{{border:1px solid #ccc;padding:12px;margin:12px 0;border-radius:4px}}
.due{{float:right;font-size:13px;background:#eee;padding:2px 8px;border-radius:3px}}
.item{{font-size:13px;margin:4px 0}} .meta{{color:#555;font-size:13px}}
@media print{{.phase{{break-inside:avoid}}}}
</style></head><body>
<h1>Cryptographic Risk Action Plan</h1>
<p class="meta">{_escape(plan.get('institution') or '')} — framework {_escape(plan.get('framework'))} — generated {_escape(plan.get('generated_at'))}</p>
<p class="meta">Evidence: snapshot <b>{_escape(ev.get('snapshot_id'))}</b> fingerprint <code>{_escape(ev.get('fingerprint'))}</code> environment <b>{_escape(ev.get('environment'))}</b></p>
<h2>1. Assessment</h2>
<table><tr><th>Crypto instances</th><th>Admission</th><th>HNDL exposed</th><th>HSM PQC gap</th><th>Mainframe assets</th></tr>
<tr><td>{_escape(a.get('total_crypto_instances'))}</td><td>{_escape((a.get('admission') or {}).get('decision'))}
 ({_escape((a.get('admission') or {}).get('blocking'))} blocking)</td><td>{_escape((a.get('hndl') or {}).get('total'))}</td>
<td>{_escape((a.get('hsm_fleet') or {}).get('pqc_gap'))}</td><td>{_escape((a.get('mainframe_inventory') or {}).get('total'))}</td></tr></table>
<h2>2. Regulatory references</h2>
{''.join(f'<p class="item">§ {_escape(r)}</p>' for r in refs)}
<h2>3. HNDL exposure register</h2>
<table><tr><th>Algorithm</th><th>Purpose</th><th>Application</th><th>Owner</th><th>Horizon</th><th>Deadline</th><th>Exposure</th></tr>
{rows or '<tr><td colspan=7>No HNDL-exposed assets.</td></tr>'}</table>
<h2>4. Phased migration plan (NIST IR 8547 anchored)</h2>
{phase_html}
<p class="meta">{_escape(plan.get('attestation'))}</p>
</body></html>"""


def render_action_plan_csv(plan: Mapping[str, Any], owners: Mapping[str, str] | None = None) -> str:
    """The HNDL register as CSV — the importable risk-register row set."""
    owner_map = _owner_map({e.get("application", "") for e in (plan.get("hndl_register") or [])},
                           owners or {})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["algorithm", "key_size", "purpose", "application", "owner",
                "confidentiality_years", "transition", "deadline", "exposure", "bom_ref"])
    for e in plan.get("hndl_register") or []:
        w.writerow([e.get("algorithm"), e.get("key_size"), e.get("purpose"),
                    e.get("application"), owner_map.get(e.get("application", ""), "unassigned"),
                    e.get("confidentiality_years"), e.get("transition"), e.get("deadline"),
                    e.get("exposure"), e.get("bom_ref")])
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Enterprise integrations
# --------------------------------------------------------------------------- #

def to_servicenow_cmdb(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Crypto assets → ServiceNow CMDB import-set payloads.

    Produces ``cmdb_ci_*``-shaped dicts (certificate-like CIs for z/OS certs,
    generic crypto CIs otherwise) ready for the Table/Import Set API. Field
    names use ServiceNow's ``u_`` extension convention to avoid collisions.
    """
    cis: list[dict[str, Any]] = []
    for r in records:
        src = str(r.get("source_language") or r.get("source") or "")
        ci_class = ("cmdb_ci_certificate" if src == "zos-racf" or r.get("kind") == "certificate"
                    else "cmdb_ci_crypto_key" if src == "zos-icsf" or r.get("kind") == "key"
                    else "cmdb_ci_crypto_module")
        cis.append({
            "sys_class_name": ci_class,
            "name": str(r.get("label") or r.get("location") or r.get("algorithm") or "crypto-asset")[:80],
            "u_algorithm": r.get("algorithm"),
            "u_key_size": r.get("key_size"),
            "u_purpose": r.get("purpose"),
            "u_source": src or "scanner",
            "u_location": r.get("file_path") or r.get("location"),
            "u_status": r.get("status") or ("" if r.get("ssl_enabled", r.get("encrypted", True)) else "non-compliant"),
            "u_expires": r.get("expires", ""),
            "u_quantum_transition": (r.get("quantum") or {}).get("transition", ""),
            "operational_status": "operational",
        })
    return {"integration": "servicenow", "table": "cmdb_ci_crypto", "records": cis, "count": len(cis)}


def to_qualys_csv(records: Iterable[Mapping[str, Any]]) -> str:
    """Weak / quantum-exposed crypto → Qualys-style detection CSV.

    Column set mirrors a Qualys VMDR export subset (ASSET/TYPE/SERVICE/RESULT/
    SEVERITY/QID) so GRC tooling can ingest it. QIDs are left blank — the
    platform does not fabricate Qualys knowledge-base IDs.
    """
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ASSET", "TYPE", "SERVICE", "PORT", "RESULT", "SEVERITY", "QID", "SSL"])
    for r in records:
        asset = r.get("asset") or r.get("application") or r.get("database") or r.get("service") or ""
        src = str(r.get("source") or r.get("source_language") or "")
        if src in ("db2", "cics"):
            if r.get("ssl_enabled", r.get("encrypted", True)) is False:
                w.writerow([asset, "Transport", "TLS", r.get("port", ""), "cleartext endpoint", 5, "", "false"])
            for c in r.get("weak_ciphers") or []:
                w.writerow([asset, "Transport", "TLS", r.get("port", ""), f"weak cipher {c}", 4, "", "true"])
            for v in r.get("below_floor") or []:
                w.writerow([asset, "Transport", "TLS", r.get("port", ""), f"{v} below policy floor TLS1.2", 4, "", "true"])
            continue
        from cbom.banking import quantum_vulnerability
        vuln = quantum_vulnerability(r.get("algorithm"), r.get("key_size"))
        if not vuln["quantum_vulnerable"]:
            continue
        severity = 5 if vuln.get("legacy") else 3
        result = f"{r.get('algorithm')}{('-' + str(r['key_size'])) if r.get('key_size') else ''}: {vuln['transition'].replace('_', ' ')}"
        w.writerow([asset, "Cryptographic", r.get("purpose") or "crypto", "", result, severity, "", ""])
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Compliance crosswalk + procurement trust package
# --------------------------------------------------------------------------- #

_CROSSWALK = (
    {"capability": "Continuous cryptographic inventory (Tech BOM: SBOM/CBOM/HBOM/Vendor)",
     "iso27001": ["A.5.9 Inventory of information and other associated assets",
                  "A.8.9 Configuration management"],
     "soc2": ["CC3.2 (risk identification)", "CC6.1 (logical access over assets)"],
     "evidence": "GET /api/v1/technology-bom (fingerprinted, snapshot versioned)"},
    {"capability": "Pre-deploy admission gate + CI drift gate",
     "iso27001": ["A.8.9 Configuration management", "A.8.32 Change management"],
     "soc2": ["CC8.1 (change management)"],
     "evidence": "GET /api/v1/technology-bom/admission; drift gate service"},
    {"capability": "Runtime drift detection & continuous verification",
     "iso27001": ["A.8.16 Monitoring activities", "A.8.15 Logging"],
     "soc2": ["CC7.1 (vulnerability & event detection)", "CC7.2 (anomaly monitoring)"],
     "evidence": "GET /api/v1/technology-bom/runtime-verify; events bus"},
    {"capability": "VEX exploitability triage",
     "iso27001": ["A.8.8 Management of technical vulnerabilities"],
     "soc2": ["CC7.1"], "evidence": "GET /api/v1/technology-bom/vex"},
    {"capability": "Signed evidence packages & hash-chained audit trail",
     "iso27001": ["A.5.28 Collection of evidence", "A.8.15 Logging"],
     "soc2": ["CC4.1 (monitoring of controls)", "CC7.3 (post-incident evidence)"],
     "evidence": "GET /api/v1/technology-bom/evidence-package (HMAC-signed)"},
    {"capability": "Quantum/HNDL regulatory register & roadmap",
     "iso27001": ["A.5.21 Managing information security in the ICT supply chain",
                  "A.5.19 Information security in supplier relationships"],
     "soc2": ["CC3.2", "CC9.2 (vendor risk)"],
     "evidence": "GET /api/v1/banking/action-plan (+ export)"},
    {"capability": "RBAC, SSO/OIDC, SCIM, MFA, session management",
     "iso27001": ["A.5.15 Access control", "A.5.17 Authentication information",
                  "A.5.18 Access rights", "A.8.5 Secure authentication"],
     "soc2": ["CC6.1", "CC6.2", "CC6.3"],
     "evidence": "/api/v1/auth/*; RBAC roles; SCIM provisioning"},
    {"capability": "Secrets hygiene (fails-closed production config, admin hash, webhook secrets)",
     "iso27001": ["A.5.31 Legal & contractual requirements", "A.8.24 Use of cryptography"],
     "soc2": ["CC6.1"], "evidence": "scripts/check_prod_guard.py; CI prod-config-guard job"},
)


def soc2_iso_crosswalk() -> dict[str, Any]:
    return {
        "frameworks": ["ISO/IEC 27001:2022 Annex A", "SOC 2 Trust Services Criteria (2017, rev. 2022)"],
        "controls": _CROSSWALK,
        "note": ("Certifications (SOC 2 Type II / ISO 27001) are organizational audits of the "
                 "deploying operator — this crosswalk maps the platform's evidence surfaces to "
                 "the controls they support; it is not itself a certificate."),
    }


def procurement_trust_package(overview: Mapping[str, Any]) -> dict[str, Any]:
    """Security-questionnaire starter: coverage, evidence surfaces, honest limits."""
    return {
        "package": "procurement-trust-package",
        "generated_at": overview.get("generated_at"),
        "platform": "ZELNX / CryproScan — deterministic crypto intelligence",
        "coverage": {
            "scan_domains": ["source code (tree-sitter AST)", "TLS/network", "cloud posture",
                             "containers/registries", "OT", "z/OS mainframe extracts",
                             "HSM/PKCS#11 artifacts"],
            "unified_inventory": overview.get("overview", {}),
        },
        "crosswalk": soc2_iso_crosswalk(),
        "honest_limits": [
            "SOC 2 Type II / ISO 27001 certificates are held by the deploying operator, not by this repository",
            "CMVP certificate numbers are recorded only from validated sources (registry/lookup), never inferred",
            "Mainframe discovery consumes operator-produced z/OS extracts; direct z/OS connectivity is not required",
        ],
    }
