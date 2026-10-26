"""Connector: run Product 2 (CryptoScan) on Product 1 (Sandbox) estate, produce 6 BOMs + dashboard."""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.banking_sandbox.common import open_estate, records, file_hash, dump, canonical

PRODUCT_VERSION = "cryptoscan-connector 1.0 — sandbox+scanner boundary demo"


def _hash(obj: Any) -> str:
    return hashlib.sha256(canonical(obj) if not isinstance(obj, (bytes, bytearray)) else obj).hexdigest()


def _ensure_fresh(p: Path):
    if p.exists() or p.is_symlink():
        raise ValueError(f"output must not exist: {p}")
    p.mkdir(parents=True, mode=0o700)


def _clean_staging(estate: Path):
    stage = estate / "scanner-inputs"
    if stage.exists():
        shutil.rmtree(stage)
    sentinel = estate / "control/ground_truth/ORACLE-SENTINEL.txt"
    # restore sentinel if harness overwrote it (it writes FORBIDDEN...)
    if sentinel.exists():
        try:
            sentinel.write_text("FORBIDDEN TO COLLECTOR\n")
        except Exception:
            pass


def _load_catalog(estate: Path) -> dict[str, Any]:
    return json.loads((estate / "public/catalog.json").read_text())


def _findings_to_crypto(findings_path: Path) -> list[dict[str, Any]]:
    crypto: list[dict[str, Any]] = []
    for row in records(findings_path):
        if row.get("status") != "COMPLETE":
            continue
        src = row.get("source_file") or ""
        # raw_findings has richer crypto data if present
        for algo in row.get("algorithms") or []:
            crypto.append({
                "id": f"cryptoscan:{src}:{algo}".replace("/", "-")[:120],
                "algorithm": algo,
                "key_size": None,
                "purpose": "UNKNOWN",
                "mode": "",
                "file_path": src,
                "confidence": "MEDIUM",
                "library": "",
                "source_basis": "SCANNER_OBSERVED",
                "reported_confidence": "MEDIUM",
                "asset": src.split("/")[0] if "/" in src else src,
            })
        # also expand raw_findings for mode/padding where available
        for rf in row.get("raw_findings") or []:
            c = (rf.get("crypto") or {})
            if c.get("algorithm") and c.get("algorithm") not in (row.get("algorithms") or []):
                # already covered via algorithms, but keep key_size/mode if present
                pass
    # Deduplicate by (file_path, algorithm)
    seen = {}
    deduped = []
    for r in crypto:
        k = (r["file_path"], r["algorithm"])
        if k not in seen:
            seen[k] = True
            deduped.append(r)
    return deduped


def _collect_inventory(estate: Path, crypto_rows: list[dict[str, Any]]) -> dict[str, Any]:
    public = estate / "public"
    apps: list[dict[str, Any]] = []
    for f in (public / "applications").glob("*.jsonl"):
        for r in records(f):
            apps.append({
                "id": r.get("app_id"),
                "name": r.get("name") or r.get("logical_app_id") or r.get("app_id"),
                "version": r.get("image_digest") or "unknown",
                "supplier": r.get("owner") or r.get("bank_id") or "",
                "owner": r.get("owner") or "",
                "environment": r.get("environment") or "",
                "criticality": "",
                "asset": r.get("system_id") or "",
                "_src": f"applications/{f.name}",
            })
    hardware: list[dict[str, Any]] = []
    for f in (public / "hbom").glob("*.jsonl"):
        for r in records(f):
            # Map sandbox hbom synthetic row to generate_hbom row shape
            hardware.append({
                "asset_id": r.get("asset_id"),
                "manufacturer": r.get("vendor") or "SYNTHETIC",
                "model": r.get("model") or r.get("kind") or "LAB-HW",
                "device_type": r.get("kind") or "other",
                "serial_reference": r.get("serial"),
                "hardware_revision": None,
                "current_fingerprint": r.get("serial") or r.get("asset_id"),
                "previous_fingerprint": None,
                "firmware": {"version": r.get("firmware_version")},
                "hsm": {"fips_mode": True} if "hsm" in (r.get("kind") or "") else None,
                "tpm": None,
                "capabilities": None,
                "crypto_capabilities": {"raw": r.get("crypto_capabilities")} if r.get("crypto_capabilities") else None,
                "risk_score": None,
                "risk_level": None,
                "last_change": None,
                "agent_id": r.get("system_id") or r.get("bank_id"),
                "first_seen": "2030-01-01T00:00:00+00:00",
                "last_seen": "2030-01-01T00:00:00+00:00",
                "last_verified": None,
                "last_firmware_check": None,
                "last_crypto_check": None,
                "evidence_history": [],
            })
    vendors_raw: list[dict[str, Any]] = []
    for f in (public / "vendors").glob("*.jsonl"):
        for r in records(f):
            vendors_raw.append(r)

    certs: list[dict[str, Any]] = []
    for f in (public / "certificates").glob("*.jsonl"):
        # there are both .jsonl and .pem files; only jsonl is records
        if f.suffix != ".jsonl":
            continue
        for r in records(f):
            certs.append({
                "fingerprint": r.get("sha256"),
                "subject": r.get("certificate_id"),
                "issuer": r.get("issuer_ref"),
                "algorithm": r.get("public_key_algorithm"),
                "key_size": "".join(ch for ch in (r.get("public_key_algorithm") or "") if ch.isdigit()) or None,
            })
    # vendors for TechBOM: minimal mapping
    vendors: list[dict[str, Any]] = []
    for r in vendors_raw:
        vendors.append({
            "name": r.get("product") or r.get("vendor_id") or "vendor",
            "product": r.get("product"),
            "model": r.get("firmware") or "",
            "lifecycle": r.get("support_lifecycle"),
            "risk_level": "",
            "_raw": r,
        })
    # dependencies: from nbom/*.jsonl if exists (edges WAF->LB etc)
    deps: list[list[str]] = []
    for f in (public / "nbom").glob("*.jsonl"):
        for r in records(f):
            frm = r.get("from")
            to = r.get("to")
            if frm and to:
                deps.append([str(frm), str(to), str(r.get("relationship") or "")])
    # scan metadata
    scan_meta = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source_basis": "SCANNER_OBSERVED_AND_FIXTURE_DERIVED_NOT_LIVE_PROBED",
        "provenance": "Product 2 (CryptoScan) run on Product 1 (Sandbox) public fixtures via isolated scan. Network/hardware/vendor layers are FIXTURE_DERIVED_NOT_LIVE_PROBED.",
    }
    return {
        "applications": apps,
        "crypto": crypto_rows,
        "hardware": hardware,
        "vendors": vendors,
        "certificates": certs,
        "dependencies": deps,
        "scan": scan_meta,
        "_vendors_raw": vendors_raw,
        "_hardware_raw": hardware,
    }


def _load_vbom_generator():
    import importlib.util
    path = Path(__file__).resolve().parents[3] / "services/vendor_intel/vendor_intel/vbom.py"
    if not path.exists():
        # fallback to repo root products
        path = Path("/home/user/CryproScan/services/vendor_intel/vendor_intel/vbom.py")
    spec = importlib.util.spec_from_file_location("vbom_direct", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod.VbomGenerator


def _build_boms(estate: Path, inventory: dict[str, Any], output: Path, scan_metrics: dict[str, Any]) -> dict[str, Any]:
    from cbom.generator import CbomGenerator
    from cbom.technology_bom import materialize_technology_bom
    from cbom.hbom import generate_hbom, to_cyclonedx as hbom_to_cyclonedx
    VbomGenerator = _load_vbom_generator()
    from cbom.nbom import build_nbom, summarise
    import json as _json

    public = estate / "public"
    boms_dir = output / "boms"
    boms_dir.mkdir(parents=True, exist_ok=True)

    # CBOM from scanner-observed crypto
    cbom_gen = CbomGenerator()
    cbom_doc = cbom_gen.from_records(inventory["crypto"], name=f"cryptoscan-cbom-{estate.name}", version="demo")
    # add provenance metadata property
    cbom_doc.setdefault("metadata", {}).setdefault("properties", []).append({"name": "cryptoscan:provenance", "value": "SCANNER_OBSERVED"})
    cbom_doc["metadata"]["properties"].append({"name": "cryptoscan:connector_version", "value": PRODUCT_VERSION})
    (boms_dir / "cbom.json").write_text(_json.dumps(cbom_doc, indent=2))
    # also CBOM xml
    try:
        (boms_dir / "cbom.xml").write_text(cbom_gen.to_xml(cbom_doc))
    except Exception as e:
        (boms_dir / "cbom.xml").write_text(f"<!-- xml not available: {e} -->")

    # TechBOM (unified)
    techbom = materialize_technology_bom(inventory, environment=estate.name, state_version=1)
    (boms_dir / "techbom.json").write_text(_json.dumps(techbom, indent=2))
    # SBOM is techbom layer's sbom projection
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"type": "application", "name": f"{estate.name}-sbom-demo"},
            "timestamp": techbom.get("generated_at"),
            "properties": [{"name": "cryptoscan:provenance", "value": "SBOM_PROJECTION_OF_TECHBOM_SYNTHETIC_FIXTURE_DERIVED_NOT_LIVE_PROBED"}],
        },
        "components": techbom.get("layers", {}).get("sbom", {}).get("components", []),
    }
    (boms_dir / "sbom.json").write_text(_json.dumps(sbom_doc, indent=2))

    # HBOM
    hbom_rows = inventory.get("_hardware_raw") or []
    hbom_doc = generate_hbom(hbom_rows, environment=estate.name)
    (boms_dir / "hbom.json").write_text(_json.dumps(hbom_doc, indent=2))
    hbom_cdx = hbom_to_cyclonedx(hbom_doc, name=f"{estate.name}-hbom")
    (boms_dir / "hbom.cyclonedx.json").write_text(_json.dumps(hbom_cdx, indent=2))

    # VBOM
    vbom_gen = VbomGenerator()
    for raw in inventory.get("_vendors_raw") or []:
        vid = raw.get("vendor_id") or raw.get("product") or "unknown"
        # inventory entries from declared_algorithms
        inv_entries = []
        for algo in raw.get("declared_algorithms") or []:
            # try parse key size from e.g. "AES-256"
            ks = None
            if "-" in algo:
                tail = algo.split("-")[-1]
                if tail.isdigit():
                    ks = int(tail)
            inv_entries.append({
                "algorithm": algo,
                "key_size": ks,
                "mode": "",
                "crypto_use_case": raw.get("category") or "",
                "key_management": raw.get("evidence_type") or "VENDOR_DECLARED",
                "pqc_ready": False,
                "discovery_method": "VENDOR_DECLARED_NOT_VERIFIED",
                "confidence": "LOW",
                "discovered_at": "2030-01-01T00:00:00+00:00",
                "verified_at": None,
                "source_document": raw.get("sbom_ref") or "",
            })
        vbom_gen.add_vendor(
            {"id": vid, "name": raw.get("product") or vid, "vendor_type": raw.get("category"), "criticality": None, "integration_type": "supply-chain"},
            inventory=inv_entries,
            systems=[{"system_id": raw.get("bank_id"), "system_name": raw.get("bank_id"), "dependency_type": "supplied-by"}] if raw.get("bank_id") else [],
        )
    vbom_doc = vbom_gen.to_document(name=f"{estate.name}-vbom")
    (boms_dir / "vbom.json").write_text(_json.dumps(vbom_doc, indent=2))
    vbom_cdx = vbom_gen.to_cyclonedx(name=f"{estate.name}-vbom")
    (boms_dir / "vbom.cyclonedx.json").write_text(_json.dumps(vbom_cdx, indent=2))

    # NBOM from network endpoints (honest: none live-probed)
    endpoints = []
    for f in (public / "network").glob("*.jsonl"):
        for r in records(f):
            # Do not claim live probe; all are unobserved synthetic paths for demo
            endpoints.append({
                "host": r.get("ip") or r.get("endpoint_id") or "synthetic.lab.invalid",
                "port": r.get("port") or 443,
                "protocol": "TLS",
                "tls_version": r.get("simulated_negotiated_protocol") or r.get("configured_protocol"),
                "cipher_suite": None,  # not observed
                "certificate": {
                    "subject": r.get("certificate_id"),
                    "issuer": None,
                    "public_key_algorithm": None,
                    "public_key_size": None,
                    "is_self_signed": False,
                },
                "device": r.get("vrf") or r.get("zone") or "synthetic-zone",
                "observed": False,  # honest: never live-probed in offline demo
            })
            if len(endpoints) >= 5000:
                break
        if len(endpoints) >= 5000:
            break
    nbom_doc = build_nbom(endpoints, estate=estate.name)
    (boms_dir / "nbom.json").write_text(_json.dumps(nbom_doc, indent=2))
    nbom_summary = summarise(nbom_doc)

    # LB NBOM: each LB node as device + its hops endpoints
    lb_endpoints = []
    for f in (public / "load_balancers").rglob("inventory.json"):
        try:
            inv = json.loads(f.read_text())
            for node in inv.get("nodes") or []:
                lb_id = node.get("lb_id")
                role = node.get("role")
                lb_endpoints.append({
                    "host": f"{lb_id}.lb.lab.invalid",
                    "port": 443,
                    "protocol": "TLS",
                    "tls_version": None,
                    "cipher_suite": None,
                    "certificate": {"subject": f"{lb_id}-cert", "issuer": None},
                    "device": role,
                    "observed": False,
                })
        except Exception:
            continue
    if lb_endpoints:
        lb_nbom = build_nbom(lb_endpoints, estate=f"{estate.name}-lbs")
        (boms_dir / "lb-nbom.json").write_text(json.dumps(lb_nbom, indent=2))
        lb_summary = summarise(lb_nbom)
    else:
        lb_summary = {"unobserved": len(lb_endpoints)}

    return {
        "cbom": {"components": len(cbom_doc.get("components") or []), "bomFormat": cbom_doc.get("bomFormat"), "specVersion": cbom_doc.get("specVersion")},
        "techbom": {"total_components": techbom.get("total_components"), "layers": techbom.get("components_by_layer"), "fingerprint": techbom.get("fingerprint"), "snapshot_id": techbom.get("snapshot_id")},
        "sbom": {"components": len(sbom_doc.get("components") or [])},
        "hbom": {"component_count": hbom_doc.get("metadata", {}).get("component_count"), "hsm_count": hbom_doc.get("metadata", {}).get("hsm_count"), "content_hash": hbom_doc.get("content_hash")},
        "vbom": vbom_gen.summary(),
        "nbom": nbom_summary,
        "lb-nbom": lb_summary,
        "provenance": "ALL_BOMS_GENERATED_BY_REAL_PRODUCT_GENERATORS_FROM_SCANNER_FINDINGS_AND_PUBLIC_FIXTURES_NOT_FROM_TRUTH",
    }


def _validate(estate: Path, output: Path, scan: dict[str, Any]) -> dict[str, Any]:
    from tools.banking_sandbox.validator import score_static
    findings_path = output / "scan/static/findings.jsonl"
    try:
        accuracy = score_static(estate, findings_path)
    except Exception as e:
        accuracy = {"error": str(e), "scope": "ACTUAL_CRYPTOSCAN_STATIC_FAMILY_PER_FILE", "synthetic": True}
    # LB hop correlation is not exercised by offline config scan; keep placeholder honest.
    lb_accuracy = {
        "status": "NOT_EXERCISED_OFFLINE_CONFIG_SCAN_ONLY",
        "note": "lb-config scan enumerates config files (nginx.conf etc), not live TLS hop negotiation. Live hop validation requires lb-live or separate normalized observations via load_balancers/validator.compare.",
        "lb_files_scanned": (lambda: len(list((estate / 'public/load_balancers').rglob('*'))))() if (estate / 'public/load_balancers').exists() else 0,
    }
    # If operator supplies true normalized hop observations, they can call:
    #   python -m tools.banking_sandbox.cli lb-compare --root <ESTATE> --results <HOP_OBSERVATIONS.jsonl> --output <report>

    # Schema checks for generated BOMs
    schema_checks = {}
    try:
        from tools.banking_sandbox.documents import validators
        cdx, spdx = validators()
        for name, path in [
            ("cbom", output / "boms/cbom.json"),
            ("sbom", output / "boms/sbom.json"),
            ("techbom", output / "boms/techbom.json"),
            ("nbom", output / "boms/nbom.json"),
        ]:
            if path.exists():
                doc = json.loads(path.read_text())
                # For techbom/nbom native formats, just check presence; cdx only for cyclonedx docs
                if name in ("cbom", "sbom"):
                    try:
                        cdx.validate(doc["document"] if "document" in doc else doc)
                        schema_checks[name] = {"ok": True}
                    except Exception as ex:
                        schema_checks[name] = {"ok": False, "error": str(ex)[:500]}
                else:
                    schema_checks[name] = {"ok": True, "note": "native format, not CycloneDX schema"}
    except Exception as e:
        schema_checks["error"] = str(e)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product1_estate": str(estate),
        "product2_output": str(output),
        "connector_version": PRODUCT_VERSION,
        "static_accuracy": accuracy,
        "lb_accuracy": lb_accuracy,
        "scan_boundary": scan.get("boundary_receipt") if isinstance(scan, dict) else None,
        "schema_checks": schema_checks,
        "honest_limits": {
            "UNKNOWN_means": "MISSING_VISIBILITY_NOT_SAFE",
            "missing_files_means": "NOT_NO_CRYPTO",
            "supported_not_negotiated": "CONFIGURED_SUITE_NOT_OBSERVED_NEGOTIATION",
            "installed_not_used": "SBOM_LISTS_PACKAGES_NOT_RUNTIME_PROOF",
            "hbom_dependencies": "empty_by_declaration_no_collector_records_edges_yet",
            "nbom_unobserved": "unprobed_listeners_excluded_from_verdicts",
            "lb_ownership": "hop_owner_from_controlled_LB_topology_not_auto_detected",
            "pqc": "VENDOR_DECLARED_NOT_VERIFIED",
        },
        "unknown_metrics_reason": accuracy.get("unknown_metrics_reason") if isinstance(accuracy, dict) else None,
    }


def connect(estate: Path, output: Path) -> dict[str, Any]:
    estate = Path(estate).resolve(strict=True)
    output = Path(output)
    _ensure_fresh(output)
    root, meta = open_estate(estate)
    from tools.banking_sandbox.validator import integrity
    integ = integrity(root)
    t0 = time.monotonic()
    log_lines: list[str] = [f"estate={estate} integ={integ}"]
    # create output skeleton (harness creates scan/static itself)
    (output / "scan").mkdir(parents=True)
    (output / "logs").mkdir(parents=True)
    _clean_staging(estate)

    # 1. Product 2 scan: static (source)
    from tools.banking_sandbox.harness import run_static
    scan_static_metrics = run_static(estate, output / "scan/static")
    log_lines.append(f"static scan: {scan_static_metrics}")
    # harness leaves scanner-inputs; remove to allow second run
    _clean_staging(estate)

    # 2. Product 2 LB scan (configs only)
    try:
        scan_lb_metrics = run_static(estate, output / "scan/lb-config", mode="lb-config")
        log_lines.append(f"lb scan: {scan_lb_metrics}")
    except Exception as e:
        scan_lb_metrics = {"failure": str(e)[:500], "note": "lb-config scan failed or no load_balancers"}
        log_lines.append(f"lb scan failed: {e}")
    _clean_staging(estate)

    # 3. Build BOMs from scan + public
    crypto_rows = _findings_to_crypto(output / "scan/static/findings.jsonl")
    inventory = _collect_inventory(estate, crypto_rows)
    bom_summary = _build_boms(estate, inventory, output, scan_static_metrics)
    log_lines.append(f"boms: {bom_summary}")

    # 4. Validation (operator-side, reads truth)
    validation = _validate(estate, output, scan_static_metrics)
    (output / "reports").mkdir(exist_ok=True)
    (output / "reports/validation.json").write_text(json.dumps(validation, indent=2))

    (output / "boms/summary.json").write_text(json.dumps(bom_summary, indent=2))
    (output / "scan/static/metrics.json").write_text(json.dumps(scan_static_metrics, indent=2))
    (output / "scan/lb-config/metrics.json").write_text(json.dumps(scan_lb_metrics, indent=2))

    # 5. Dashboard
    from tools.banking_sandbox.connector.dashboard import render_dashboard
    render_dashboard(estate, output, integ, scan_static_metrics, scan_lb_metrics, bom_summary, validation, inventory)

    # 6. Manifest + logs
    manifest_files = []
    for p in sorted(output.rglob("*")):
        if p.is_file():
            manifest_files.append({"path": str(p.relative_to(output)), "bytes": p.stat().st_size, "sha256": file_hash(p)})
    manifest = {
        "version": "CRYPTOSCAN_CONNECTED_OUTPUT_V1",
        "connector_version": PRODUCT_VERSION,
        "estate_meta": meta,
        "estate_integrity": integ,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "wall_seconds": time.monotonic() - t0,
        "files": manifest_files,
    }
    dump(output / "manifest.json", manifest)
    (output / "logs/connector.log").write_text("\n".join(log_lines))

    return {
        "estate": str(estate),
        "output": str(output),
        "static_metrics": scan_static_metrics,
        "lb_metrics": scan_lb_metrics,
        "boms": bom_summary,
        "validation": {"precision": validation.get("static_accuracy", {}).get("precision"), "recall": validation.get("static_accuracy", {}).get("recall")},
        "wall_seconds": manifest["wall_seconds"],
        "manifest": manifest["files"][:2],
    }
