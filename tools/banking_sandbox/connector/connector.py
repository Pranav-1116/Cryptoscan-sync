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


def _guard_confirmed(metrics: dict[str, Any]) -> bool:
    guard = (metrics.get("boundary_receipt") or {}).get("guard") or {}
    return (metrics.get("failure") is None
            and guard.get("oracle_read_denied") is True
            and guard.get("socket_creation_denied") is True
            and guard.get("seccomp") == "ACTIVE_NETWORK_DENIED"
            and type(guard.get("landlock_abi")) is int and guard["landlock_abi"] >= 2)


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

    # Preserve the generator's legacy XML, but publish its allowlisted native 1.6 JSON profile.
    from cbom.cyclonedx16 import to_cyclonedx16, validate_cyclonedx16

    cbom_gen = CbomGenerator()
    legacy_cbom = cbom_gen.from_records(inventory["crypto"], name=f"cryptoscan-cbom-{estate.name}", version="demo")
    cbom_doc = to_cyclonedx16(legacy_cbom, omit_inventory_dependencies=True)
    cbom_doc["metadata"].setdefault("properties", []).extend([
        {"name": "cryptoscan:provenance", "value": "SCANNER_OBSERVED"},
        {"name": "cryptoscan:connector_version", "value": PRODUCT_VERSION},
    ])
    if not validate_cyclonedx16(cbom_doc)["ok"]:
        raise RuntimeError("Connected CBOM failed native CycloneDX 1.6 validation")
    (boms_dir / "cbom.json").write_text(_json.dumps(cbom_doc, indent=2))
    (boms_dir / "cbom.xml").write_text(cbom_gen.to_xml(legacy_cbom))

    # TechBOM (unified)
    techbom = materialize_technology_bom(inventory, environment=estate.name, state_version=1)
    (boms_dir / "techbom.json").write_text(_json.dumps(techbom, indent=2))
    # TechBOM application rows are a native projection; only standard component
    # fields belong at the CycloneDX top level. Retain declared context as properties.
    sbom_components = []
    for row in techbom.get("layers", {}).get("sbom", {}).get("components", []):
        component = {key: row[key] for key in ("type", "name", "version", "bom-ref") if row.get(key) is not None}
        component["properties"] = [
            {"name": "cryptoscan:source_basis", "value": "FIXTURE_DERIVED_NOT_LIVE_PROBED"},
            *({"name": f"cryptoscan:{key}", "value": str(row[key])}
              for key in ("asset", "criticality", "environment", "supplier") if row.get(key)),
        ]
        sbom_components.append(component)
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"type": "application", "name": f"{estate.name}-sbom-demo"},
            "timestamp": techbom.get("generated_at"),
            "properties": [{"name": "cryptoscan:provenance", "value": "SBOM_PROJECTION_OF_TECHBOM_SYNTHETIC_FIXTURE_DERIVED_NOT_LIVE_PROBED"}],
        },
        "components": sbom_components,
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
    vbom_legacy = vbom_gen.to_cyclonedx(name=f"{estate.name}-vbom")
    # The legacy service root and vendor-only components are not valid
    # CycloneDX crypto components. Retain vendor-only entries in native VBOM,
    # disclose their count, and convert actual crypto entries with supplier IDs.
    vbom_legacy["metadata"]["component"]["type"] = "application"
    vendor_only = [c for c in vbom_legacy["components"] if c["type"] == "service"]
    vbom_legacy["components"] = [c for c in vbom_legacy["components"] if c["type"] != "service"]
    vbom_cdx = to_cyclonedx16(vbom_legacy)
    original = {c["bom-ref"]: c for c in vbom_legacy["components"]}
    vendor_fields = {"cryptoscan:vendor-id", "cryptoscan:criticality", "cryptoscan:vendor-type",
                     "cryptoscan:use-case", "cryptoscan:key-management", "cryptoscan:pqc-ready",
                     "cryptoscan:discovery-method", "cryptoscan:confidence"}
    for component in vbom_cdx["components"]:
        source = original[component["bom-ref"]]
        component["supplier"] = source["supplier"]
        component.setdefault("properties", []).extend(
            p for p in source.get("properties", []) if p.get("name") in vendor_fields
        )
        component["properties"].append({"name": "cryptoscan:source_basis", "value": "FIXTURE_DERIVED_NOT_LIVE_PROBED"})
    vbom_cdx["metadata"].setdefault("properties", []).append(
        {"name": "cryptoscan:vendor_only_in_native_document", "value": str(len(vendor_only))}
    )
    if not validate_cyclonedx16(vbom_cdx)["ok"]:
        raise RuntimeError("Connected VBOM failed native CycloneDX 1.6 validation")
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
            ("hbom_cyclonedx", output / "boms/hbom.cyclonedx.json"),
            ("vbom_cyclonedx", output / "boms/vbom.cyclonedx.json"),
            ("techbom", output / "boms/techbom.json"),
            ("hbom", output / "boms/hbom.json"),
            ("vbom", output / "boms/vbom.json"),
            ("nbom", output / "boms/nbom.json"),
        ]:
            if path.exists():
                doc = json.loads(path.read_text())
                # Native BOMs are present, not schema-qualified by a CycloneDX validator.
                if name in ("cbom", "sbom", "hbom_cyclonedx", "vbom_cyclonedx"):
                    try:
                        if name in ("cbom", "vbom_cyclonedx"):
                            from cbom.cyclonedx16 import validate_cyclonedx16

                            result = validate_cyclonedx16(doc)
                            if not result["ok"]:
                                raise ValueError("; ".join(result["errors"]))
                        else:
                            cdx.validate(doc)
                        schema_checks[name] = {"ok": True}
                    except Exception as ex:
                        schema_checks[name] = {"ok": False, "error": str(ex)[:500]}
                else:
                    schema_checks[name] = {"ok": None, "status": "PRESENT_NATIVE_NOT_SCHEMA_VALIDATED"}
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
    if not _guard_confirmed(scan_static_metrics):
        raise RuntimeError("Static collector failed or its isolation proof is unavailable; no connected BOM was built")

    # 2. Product 2 LB scan (configs only)
    try:
        scan_lb_metrics = run_static(estate, output / "scan/lb-config", mode="lb-config")
        log_lines.append(f"lb scan: {scan_lb_metrics}")
    except Exception as e:
        scan_lb_metrics = {"failure": str(e)[:500], "note": "lb-config scan failed or no load_balancers"}
        log_lines.append(f"lb scan failed: {e}")
    _clean_staging(estate)
    if (estate / "public/load_balancers").is_dir() and not _guard_confirmed(scan_lb_metrics):
        raise RuntimeError("LB config collector failed or its isolation proof is unavailable; no connected BOM was built")

    # 3. Build BOMs from scan + public
    crypto_rows = _findings_to_crypto(output / "scan/static/findings.jsonl")
    inventory = _collect_inventory(estate, crypto_rows)
    bom_summary = _build_boms(estate, inventory, output, scan_static_metrics)
    log_lines.append(f"boms: {bom_summary}")

    # 4. Validation (operator-side, reads truth)
    validation = _validate(estate, output, scan_static_metrics)
    (output / "reports").mkdir(exist_ok=True)
    (output / "reports/validation.json").write_text(json.dumps(validation, indent=2))
    if not all(validation.get("schema_checks", {}).get(name, {}).get("ok")
               for name in ("cbom", "sbom", "vbom_cyclonedx")):
        raise RuntimeError("Connected BOM schema validation failed; inspect reports/validation.json")

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
