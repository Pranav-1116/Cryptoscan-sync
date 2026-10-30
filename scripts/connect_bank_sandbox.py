#!/usr/bin/env python3
"""Wire the synthetic **bank** sandbox (product 1) into a running CryptoScan (product 2).

The two products stay separate. Product 1 is the banking estate laboratory in
``tools/banking_sandbox``: it generates a wholly synthetic bank — systems,
applications, endpoints, certificates, HSMs, packages, vendors, declared CBOMs —
and serves its own read-only dashboard. Product 2 is CryptoScan. This script is
the only thing that joins them, and it joins them **through CryptoScan's HTTP
backend**: no in-process scanner call, no database write, no read of the bank's
operator-only ``control/`` subtree.

Three connections, each an existing CryptoScan door:

1. ``POST /api/v1/scans/trigger`` — the bank's source tree is scanned by the real
   static pipeline, so the crypto assets, findings and cascade in the console are
   what CryptoScan observed in the bank's code.
2. ``POST /api/v1/cbom/ingest`` — each application's declared CBOM document.
   CryptoScan stores those as ``IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS``:
   a vendor's declaration is inventory, never an observation.
3. ``POST /api/v1/ingestion/observations`` — one estate observation built from
   the bank's own inventory documents (systems, applications, endpoints,
   certificates, HSMs, packages, vendors). CryptoScan stores it as a real
   discovery run and projects the six BOMs from it, so the CBOM/SBOM/HBOM/NBOM/
   VBOM/TECHBOM screens read the bank instead of an empty store.

Nothing here reads the bank's ground truth: only ``public/`` fixtures are opened,
which is exactly what the sandbox serves to a visitor. A declaration is posted as
a declaration (``IMPORTED``/``VENDOR_DECLARED``/``CONFIGURED``); the bank's own
"actual negotiation executed: false" and "actual execution: false" flags travel
with the facts instead of being rounded up to an observation.

Usage::

    .venv/bin/python scripts/connect_bank_sandbox.py --estate /home/user/.cache/bank-lab
    .venv/bin/python scripts/connect_bank_sandbox.py --estate ... --skip-scan   # observation only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from _bootstrap import bootstrap  # noqa: E402

bootstrap()

SCHEMA = "cryptoscan.bank-sandbox-connect/1"
COLLECTOR = "bank-sandbox:public-fixtures"


# --------------------------------------------------------------------------- #
# reading product 1's PUBLIC fixtures only
# --------------------------------------------------------------------------- #
def _rows(public: Path, name: str) -> list[dict[str, Any]]:
    """Every JSON line under ``public/<name>``; the control subtree is never read."""
    out: list[dict[str, Any]] = []
    for path in sorted((public / name).glob("*.jsonl")):
        if path.name.endswith("loadbalancers.jsonl"):
            continue  # LB/ADC fixtures are a separate extension; see --include-lb
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def _banks(public: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((public / "banks").glob("*.json"))]


# --------------------------------------------------------------------------- #
# the observation CryptoScan's estate engine accepts
# --------------------------------------------------------------------------- #
def build_observation(estate: Path) -> dict[str, Any]:
    from shared_models.estate_graph import asset_id as canonical

    public = estate / "public"
    banks = _banks(public)
    systems = _rows(public, "systems")
    applications = _rows(public, "applications")
    endpoints = _rows(public, "network")
    certificates = _rows(public, "certificates")
    hardware = _rows(public, "assets")
    hsm_rows = _rows(public, "hsm")
    packages = _rows(public, "techbom")
    vendors = _rows(public, "vendors")
    declared_cbom = _rows(public, "cbom")

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    def add(
        asset_type: str,
        name: str,
        identity: dict[str, Any],
        *,
        attributes: dict[str, Any],
        owner: str | None = None,
        location: str | None = None,
    ) -> str:
        ref = canonical(asset_type, identity, name=name)
        if ref not in {row["ref"] for row in assets}:
            assets.append({
                "ref": ref,
                "type": asset_type,
                "name": name,
                "identity": identity,
                "owner": owner,
                "location": location,
                "source": "bank_sandbox",
                "attributes": attributes,
            })
        return ref

    def attach(
        ref: str,
        evidence_type: str,
        facts: dict[str, Any],
        *,
        layer: str = "APPLICATION",
    ) -> str:
        evidence.append({
            "source": "bank_sandbox",
            "collector": COLLECTOR,
            "evidence_type": evidence_type,
            "target": ref,
            "layer": layer,
            "observed_at": None,
            "facts": facts,
        })
        return ref

    def link(
        subject: str,
        predicate: str,
        obj: str,
        *,
        basis: str,
        facts: dict[str, Any],
        attributes: dict[str, Any] | None = None,
        layer: str = "APPLICATION",
    ) -> None:
        """One evidence record about the edge, and the edge it establishes."""
        from shared_models.estate_graph import content_evidence_id

        record = {
            "source": "bank_sandbox",
            "collector": COLLECTOR,
            "evidence_type": basis_evidence(basis),
            "target": obj,
            "layer": layer,
            "observed_at": None,
            "facts": facts,
        }
        evidence.append(record)
        digest = content_evidence_id(
            record["evidence_type"],
            record["target"],
            record["facts"],
            record["layer"],
            record["source"],
            record["collector"],
        )
        relationships.append({
            "subject": subject,
            "predicate": predicate,
            "object": obj,
            "basis": basis,
            "evidence_ids": [digest],
            "attributes": dict(attributes or {}),
        })

    bank = banks[0] if banks else {}
    bank_label = bank.get("organization_name") or "synthetic bank"
    # The estate is a BANK, not an environment: its identity is the institution's id,
    # and the scope says plainly that this institution is synthetic.
    bank_id = str(bank.get("bank_id") or "bank-sandbox")
    evidence_ids: dict[tuple[str, str], str] = {}

    # -- systems ------------------------------------------------------------ #
    system_refs: dict[str, str] = {}
    for row in systems:
        system_id = str(row.get("system_id") or "")
        if not system_id:
            continue
        ref = add(
            "SYSTEM", system_id, {"name": system_id},
            owner=row.get("owner") or bank_label,
            location=row.get("zone"),
            attributes={
                "bank_id": row.get("bank_id"),
                "zone": row.get("zone"),
                "platform": row.get("platform"),
                "data_center": row.get("data_center"),
                "environment": row.get("environment"),
                "source_document": f"systems/{row.get('bank_id')}.jsonl",
            },
        )
        system_refs[system_id] = ref
        attach(ref, "IMPORTED", {
            "inventory_record": "system",
            "system_id": system_id,
            "zone": row.get("zone"),
            "platform": row.get("platform"),
            "data_center": row.get("data_center"),
            "note": "the bank's own inventory document declares this system; nothing was observed on it",
        }, layer="PLATFORM")

    # -- applications ------------------------------------------------------- #
    app_refs: dict[str, str] = {}
    for row in applications:
        app_id = str(row.get("app_id") or "")
        if not app_id:
            continue
        ref = add(
            "APPLICATION", str(row.get("name") or app_id),
            {"name": app_id, "system": row.get("system_id")},
            owner=row.get("owner") or bank_label,
            location=row.get("source"),
            attributes={
                "app_id": app_id,
                "system_id": row.get("system_id"),
                "language": row.get("language"),
                "environment": row.get("environment"),
                "source": row.get("source"),
                "image_digest": row.get("image_digest"),
                "source_document": f"applications/{row.get('bank_id')}.jsonl",
            },
        )
        app_refs[app_id] = ref
        attach(ref, "IMPORTED", {
            "inventory_record": "application",
            "app_id": app_id,
            "language": row.get("language"),
            "environment": row.get("environment"),
            "source": row.get("source"),
            "note": "declared by the bank's inventory; the SBOM/CBOM documents describe it",
        })
        system_ref = system_refs.get(str(row.get("system_id") or ""))
        if system_ref:
            link(system_ref, "contains", ref, basis="IMPORTED", facts={
                "source_document": "applications",
                "note": "the inventory places this application in this system",
            })
        image = str(row.get("image_digest") or "")
        if image.startswith("sha256:"):
            image_ref = add(
                "IMAGE", image[:24], {"digest": image},
                attributes={"digest": image, "app_id": app_id},
            )
            link(ref, "deployed_as", image_ref, basis="IMPORTED", facts={
                "image_digest": image,
                "note": "the image digest the inventory says this application runs; no registry was queried",
            })

    # -- endpoints ---------------------------------------------------------- #
    endpoint_refs: dict[str, str] = {}
    for row in endpoints:
        endpoint_id = str(row.get("endpoint_id") or "")
        if not endpoint_id:
            continue
        protocol = str(row.get("configured_protocol") or "UNKNOWN")
        ref = add(
            "NETWORK_ENDPOINT", endpoint_id,
            {"host": row.get("ip"), "port": row.get("port"), "protocol": protocol},
            location=f"{row.get('ip')}:{row.get('port')}",
            attributes={
                "app_id": row.get("app_id"),
                "zone": row.get("zone"),
                "transport_layer": row.get("transport_layer"),
                "configured_protocol": protocol,
                "supported_protocols": row.get("supported_protocols") or [],
                "mtls": row.get("mtls"),
                "sni": row.get("sni"),
                "actual_negotiation_executed": bool(row.get("actual_negotiation_executed")),
                "certificate_id": row.get("certificate_id"),
            },
        )
        endpoint_refs[endpoint_id] = ref
        app_ref = app_refs.get(str(row.get("app_id") or ""))
        if app_ref:
            link(app_ref, "exposes", ref, basis="CONFIGURATION", layer="NETWORK_TRANSPORT", facts={
                "protocol": protocol,
                "supported_protocols": row.get("supported_protocols") or [],
                "mtls": row.get("mtls"),
                "actual_negotiation_executed": bool(row.get("actual_negotiation_executed")),
                "note": (
                    "the endpoint is *configured* for that protocol; the bank records that no "
                    "handshake was executed, so this stays CONFIGURED and never NEGOTIATED"
                ),
            })

    # -- certificates ------------------------------------------------------- #
    cert_refs: dict[str, str] = {}
    for row in certificates:
        cert_id = str(row.get("certificate_id") or "")
        if not cert_id:
            continue
        ref = add(
            "CERTIFICATE", cert_id,
            {
                "fingerprint_sha256": row.get("sha256"),
                "serial_number": row.get("serial"),
                "subject": cert_id,
            },
            location=row.get("endpoint_id"),
            attributes={
                "app_id": row.get("app_id"),
                "system_id": row.get("system_id"),
                "issuer_ref": row.get("issuer_ref"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "public_key_algorithm": row.get("public_key_algorithm"),
                "signature_algorithm": row.get("signature_algorithm"),
                "chain_status": row.get("chain_status"),
                "in_use": row.get("in_use"),
                "clock_kind": row.get("clock_kind"),
            },
        )
        cert_refs[cert_id] = ref
        attach(ref, "IMPORTED", {
            "inventory_record": "certificate",
            "certificate_id": cert_id,
            "not_after": row.get("not_after"),
            "public_key_algorithm": row.get("public_key_algorithm"),
            "signature_algorithm": row.get("signature_algorithm"),
            "chain_status": row.get("chain_status"),
            "serial": row.get("serial"),
            "note": "certificate metadata from the bank's inventory document, not a live handshake",
        }, layer="NETWORK_TRANSPORT")
        app_ref = app_refs.get(str(row.get("app_id") or ""))
        if app_ref:
            link(app_ref, "protected_by", ref, basis="IMPORTED", layer="NETWORK_TRANSPORT", facts={
                "certificate_id": cert_id,
                "not_after": row.get("not_after"),
                "note": "the inventory ties this certificate to this application's endpoint",
            })

    # -- hardware (HBOM) ---------------------------------------------------- #
    for row in hardware:
        asset_name = str(row.get("asset_id") or "")
        if not asset_name:
            continue
        ref = add(
            "HARDWARE", asset_name,
            {"vendor": row.get("vendor"), "serial_number": row.get("serial")},
            owner=row.get("owner") or bank_label,
            location=row.get("location"),
            attributes={
                "kind": row.get("kind"),
                "model": row.get("model"),
                "firmware": row.get("firmware_version"),
                "confidence": row.get("confidence"),
                "evidence_source": row.get("evidence_source"),
                "system_id": row.get("system_id"),
                "supported_protocols": row.get("supported_protocols") or [],
                "crypto_capabilities": row.get("crypto_capabilities") or [],
                "risk_level": row.get("risk_level"),
            },
        )
        attach(ref, "IMPORTED", {
            "inventory_record": "hardware",
            "model": row.get("model"),
            "vendor": row.get("vendor"),
            "firmware": row.get("firmware_version"),
            "confidence": row.get("confidence") or "DECLARED_NOT_OBSERVED",
            "note": "a hardware record from the bank's config export; the device was not queried",
        }, layer="PLATFORM")
        attach(ref, "VENDOR_DECLARED", {
            "capabilities": row.get("crypto_capabilities") or [],
            "supported_protocols": row.get("supported_protocols") or [],
            "note": "a capability list says what the device supports, never what it executed",
        }, layer="PLATFORM")
        system_ref = system_refs.get(str(row.get("system_id") or ""))
        if system_ref:
            link(system_ref, "hosted_on", ref, basis="IMPORTED", layer="PLATFORM", facts={
                "hardware": asset_name,
                "note": "the inventory records which system this device serves",
            })

    # -- HSMs --------------------------------------------------------------- #
    for row in hsm_rows:
        hsm_id = str(row.get("hsm_id") or "")
        if not hsm_id:
            continue
        ref = add(
            "HSM", hsm_id,
            {"vendor": row.get("vendor"), "partition": row.get("kind")},
            owner=bank_label,
            location=row.get("model"),
            attributes={
                "kind": row.get("kind"),
                "model": row.get("model"),
                "firmware": row.get("firmware"),
                "lifecycle": row.get("lifecycle"),
                "interface": row.get("interface"),
                "key_refs": row.get("key_refs") or [],
                "rotation_days": row.get("rotation_days"),
                "simulated_operations": row.get("operations") or [],
                "actual_execution": bool((row.get("audit_event") or {}).get("actual_execution")),
            },
        )
        attach(ref, "CONFIGURED", {
            "operations": row.get("operations") or [],
            "key_type": row.get("key_type"),
            "key_size": row.get("key_size"),
            "lifecycle": row.get("lifecycle"),
            "actual_execution": bool((row.get("audit_event") or {}).get("actual_execution")),
            "note": (
                "configured capabilities of a simulated HSM; the bank's audit record says no "
                "operation was actually executed"
            ),
        }, layer="HSM")
        system_ref = system_refs.get(str(row.get("system_id") or ""))
        if system_ref:
            link(system_ref, "uses_hsm", ref, basis="CONFIGURATION", layer="HSM", facts={
                "hsm_id": hsm_id,
                "lifecycle": row.get("lifecycle"),
                "declared_not_observed": True,
                "note": "the config export references this HSM; no PKCS#11 session was opened",
            })
        cert_ref = cert_refs.get(str(row.get("certificate_association") or ""))
        if cert_ref:
            link(cert_ref, "managed_by", ref, basis="IMPORTED", layer="HSM", facts={
                "hsm_id": hsm_id,
                "note": "the inventory associates this certificate with this HSM",
            })

    # -- libraries and packages (SBOM) -------------------------------------- #
    library_refs: dict[tuple[str, str], str] = {}
    for doc in _rows(public, "sbom"):
        document = doc.get("document") or {}
        if document.get("bomFormat") != "CycloneDX":
            continue  # SPDX documents describe the same applications; no second reading
        meta = (document.get("metadata") or {}).get("component") or {}
        owner_app = app_refs.get(str(meta.get("bom-ref") or ""))
        by_ref: dict[str, str] = {}
        for component in document.get("components") or []:
            if component.get("type") not in {"library", "framework", "file"}:
                continue
            name = str(component.get("name") or "").strip()
            if not name:
                continue
            version = component.get("version")
            key = (name.lower(), str(version or ""))
            ref = library_refs.get(key)
            if ref is None:
                ref = add(
                    "LIBRARY", name,
                    {"name": name, "version": version, "purl": component.get("purl")},
                    attributes={
                        "declared_version": version,
                        "sbom_ref": component.get("bom-ref"),
                        "declared_in": "public/sbom (CycloneDX)",
                    },
                )
                library_refs[key] = ref
                attach(ref, "IMPORTED", {
                    "dependency": name,
                    "version": version,
                    "note": (
                        "listed as a software component in the bank's SBOM document; "
                        "listing is not loading"
                    ),
                })
            by_ref[str(component.get("bom-ref") or "")] = ref
            if owner_app:
                link(owner_app, "contains", ref, basis="IMPORTED", facts={
                    "dependency": name,
                    "version": version,
                    "sbom_ref": component.get("bom-ref"),
                    "note": "the application's SBOM document lists this component",
                })
        for dep in document.get("dependencies") or []:
            parent = by_ref.get(str(dep.get("ref") or ""))
            for child_ref in dep.get("dependsOn") or []:
                child = by_ref.get(str(child_ref))
                if parent and child and parent != child:
                    link(parent, "depends_on", child, basis="IMPORTED", facts={
                        "declared_dependency": True,
                        "note": "declared in the SBOM dependency graph of one application",
                    }, attributes={"declared_in": "SBOM dependencies"})

    package_refs: dict[tuple[str, str], str] = {}
    for row in packages:
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        version = str(row.get("declared_version") or "") or None
        key = (name.lower(), str(version or ""))
        ref = package_refs.get(key)
        if ref is None:
            ref = add(
                "PACKAGE", name,
                {"name": name, "version": version, "ecosystem": row.get("provider")},
                attributes={
                    "provider": row.get("provider"),
                    "declared_version": version,
                    "runtime_version": row.get("runtime_version"),
                    "usage": row.get("usage"),
                    "installed": row.get("installed"),
                },
            )
            package_refs[key] = ref
            attach(ref, "IMPORTED", {
                "package": name,
                "declared_version": version,
                "provider": row.get("provider"),
                "usage": row.get("usage"),
                "installed": row.get("installed"),
                "note": "declared in the bank's techbom document; usage is UNKNOWN_NOT_PROVEN",
            })
        app_ref = app_refs.get(str(row.get("app_id") or ""))
        if app_ref:
            link(app_ref, "depends_on", ref, basis="IMPORTED", facts={
                "package": name,
                "declared_version": version,
                "usage": row.get("usage"),
                "note": "the application's component list declares this package",
            })

    # -- vendors ------------------------------------------------------------ #
    for row in vendors:
        vendor_id = str(row.get("vendor_id") or row.get("product") or "")
        if not vendor_id:
            continue
        ref = add(
            "VENDOR", vendor_id,
            {"name": vendor_id, "product": row.get("product")},
            owner=row.get("owner"),
            attributes={
                "category": row.get("category"),
                "product": row.get("product"),
                "version": row.get("version"),
                "firmware": row.get("firmware"),
                "support_lifecycle": row.get("support_lifecycle"),
                "pqc_readiness": row.get("pqc_readiness"),
                "evidence_type": row.get("evidence_type"),
            },
        )
        attach(ref, "VENDOR_DECLARED", {
            "product": row.get("product"),
            "version": row.get("version"),
            "firmware": row.get("firmware"),
            "capabilities": row.get("declared_algorithms") or [],
            "support_lifecycle": row.get("support_lifecycle"),
            "pqc_ready": row.get("pqc_readiness"),
            "note": (
                "'this product supports AES-256' is a vendor statement about a product, never "
                "proof that this bank used AES-256"
            ),
        }, layer="PLATFORM")

    # -- declared application cryptography ---------------------------------- #
    for doc in declared_cbom:
        target = str(doc.get("target") or "")
        app_ref = app_refs.get(target)
        if app_ref is None:
            continue
        algorithms = []
        for component in (doc.get("document") or {}).get("components") or []:
            name = str(component.get("name") or "").strip()
            if name and name not in algorithms:
                algorithms.append(name)
        if not algorithms:
            continue
        attach(app_ref, "VENDOR_DECLARED", {
            "algorithms": algorithms,
            "declared_by": doc.get("entity_type") or "VENDOR_DECLARED",
            "note": (
                "declared in the bank's CBOM document; a declaration is capability, and only the "
                "static scan can show whether the code uses it"
            ),
        })

    coverage = [
        {
            "target": "bank public inventory documents",
            "expected": len(banks),
            "collected": len(banks),
            "status": "COMPLETE",
            "note": (
                "systems, applications, endpoints, certificates, hardware, HSMs, packages, "
                "libraries, vendors and declared CBOMs are read from public/ only"
            ),
        },
        {
            "target": "bank runtime",
            "expected": 0,
            "collected": 0,
            "status": "NOT_ATTEMPTED",
            "impact": "no process, library load or syscall was observed, so nothing exceeds CONFIGURED",
        },
        {
            "target": "bank handshakes",
            "expected": 0,
            "collected": 0,
            "status": "NOT_ATTEMPTED",
            "impact": "the bank records actual_negotiation_executed=false; NBOM rows stay CONFIGURED",
        },
    ]
    collectors = [
        {
            "plane": "INVENTORY",
            "status": "COMPLETE",
            "expected": len(systems) + len(applications),
            "collected": len(systems) + len(applications),
            "reason": "systems and applications imported from the bank's own documents",
            "impact": None,
        },
        {
            "plane": "PKI",
            "status": "COMPLETE",
            "expected": len(certificates),
            "collected": len(certificates),
            "reason": "certificate metadata imported from the bank's inventory document",
            "impact": None,
        },
        {
            "plane": "SOFTWARE",
            "status": "COMPLETE",
            "expected": len(packages),
            "collected": len(packages),
            "reason": "declared components imported from SBOM/techbom documents; nothing was loaded",
            "impact": None,
        },
        {
            "plane": "VENDOR",
            "status": "COMPLETE",
            "expected": len(vendors),
            "collected": len(vendors),
            "reason": "vendor declarations imported; capability only, never bank usage",
            "impact": None,
        },
        {
            "plane": "RUNTIME",
            "status": "NOT_ATTEMPTED",
            "expected": 0,
            "collected": 0,
            "reason": "the source scan is a separate run (POST /scans/trigger); the sandbox exposes no runtime",
            "impact": "usage above CONFIGURED must come from the static scan of public/source",
        },
    ]

    observation = {
        "estate": bank_id,
        "scope": f"{bank_label} — synthetic bank sandbox",
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "collectors": collectors,
        "coverage": coverage,
    }
    return observation


def basis_evidence(basis: str) -> str:
    """The evidence type that honestly backs each relationship basis."""
    return {
        "CONFIGURATION": "CONFIGURED",
        "DEPLOYMENT_CONFIG": "CONFIGURED",
        "RUNTIME_OBSERVATION": "RUNTIME_OBSERVED",
        "NETWORK_OBSERVATION": "NETWORK_ACTIVE_OBSERVED",
    }.get(basis, "IMPORTED")


# --------------------------------------------------------------------------- #
# talking to product 2 (CryptoScan) over HTTP only
# --------------------------------------------------------------------------- #
def _client(api: str, user: str, password: str):
    import httpx

    connection = httpx.Client(base_url=api.rstrip("/"), timeout=180.0)
    login = connection.post("/api/v1/auth/login", json={"username": user, "password": password})
    login.raise_for_status()
    connection.headers["Authorization"] = f"Bearer {login.json()['token']}"
    return connection


def connect(
    *,
    estate: Path,
    api: str,
    user: str,
    password: str,
    do_scan: bool = True,
    do_cbom: bool = True,
    do_observe: bool = True,
) -> dict[str, Any]:
    public = estate / "public"
    result: dict[str, Any] = {"schema": SCHEMA, "estate": str(estate), "api": api, "steps": {}}
    connection = _client(api, user, password)

    # 1. product 2 scans product 1's source tree ----------------------------- #
    if do_scan and (public / "source").is_dir():
        target = f"local://{public / 'source'}"
        queued = connection.post(
            "/api/v1/scans/trigger", json={"repo_url": target, "branch": "main"}
        )
        if queued.status_code != 202:
            detail = queued.text[:400]
            step: dict[str, Any] = {"queued": False, "status": queued.status_code, "detail": detail}
            if "outside the allowed source roots" in detail:
                # The scanner only reads roots the API was started with, and this
                # estate lives outside the repository. Say exactly what to set
                # rather than leaving a 400 to be decoded.
                step["hint"] = (
                    "the API is not allowed to read this estate's source tree. Start it with the "
                    f"estate as a source root, e.g. CRYPTOSCAN_SOURCE_ROOTS=\"$PWD:{public}\" "
                    "bash scripts/run_dev_stack.sh down && "
                    "CRYPTOSCAN_SOURCE_ROOTS=\"$PWD:" + str(public) + "\" bash scripts/run_dev_stack.sh up"
                )
            result["steps"]["scan"] = step
        else:
            job_id = queued.json()["job_id"]
            job: dict[str, Any] = {}
            for _ in range(120):
                job = connection.get(f"/api/v1/jobs/{job_id}").json()
                if job.get("status") in {"COMPLETED", "FAILED"}:
                    break
                time.sleep(2)
            scan_id = job.get("scan_id")
            scan: dict[str, Any] = {}
            if scan_id:
                scan = connection.get(f"/api/v1/scans/{scan_id}").json()
            result["steps"]["scan"] = {
                "queued": True,
                "job_id": job_id,
                "job_status": job.get("status"),
                "scan_id": scan_id,
                "target": target,
                "findings": (scan.get("statistics") or {}).get("total_findings"),
                "files_scanned": (scan.get("statistics") or {}).get("files_scanned"),
                "cascade": (connection.get(f"/api/v1/scans/{scan_id}/cascade").json().get("summary")
                            if scan_id else None),
            }

    # 2. declared CBOM documents per application ----------------------------- #
    if do_cbom:
        ingested: list[dict[str, Any]] = []
        hints: list[str] = []
        # A substituted check is not a failure, but it must not pass silently.
        notes: list[str] = []
        for doc in _rows(public, "cbom"):
            target = str(doc.get("target") or "")
            document = doc.get("document") or {}
            if not document.get("components"):
                continue
            response = connection.post(
                "/api/v1/cbom/ingest",
                json={
                    "bom": document,
                    "system_name": target,
                    "owner": "bank-sandbox",
                    "environment": "synthetic-lab",
                },
            )
            imported = None if response.status_code != 200 else response.json().get("imported")
            if response.status_code == 200:
                for note in (response.json().get("validation") or {}).get("warnings") or []:
                    if note not in notes:
                        notes.append(note)
            ingested.append({
                "target": target,
                "status": response.status_code,
                "imported": imported if imported is not None else response.text[:200],
            })
            if response.status_code == 503:
                detail = response.json().get("detail") if response.content else {}
                fix = detail.get("fix") if isinstance(detail, dict) else None
                fix = fix or "the API could not judge the document; check the API log for the failing check"
                if fix not in hints:
                    hints.append(fix)
        failures = [item for item in ingested if item["status"] != 200]
        result["steps"]["cbom_ingest"] = {
            "documents": len(ingested),
            "imported_assets": sum(item["imported"] for item in ingested if isinstance(item.get("imported"), int)),
            "failed": failures,
            "hint": " ".join(hints) or None,
            "validation_notes": notes or None,
        }
        if failures:
            # A refused import is a state, not a crash: say what it means for the
            # numbers below so an empty CBOM layer is not read as "the bank has
            # no cryptography".
            result["steps"]["cbom_ingest"]["consequence"] = (
                "no declared CBOM was stored, so the cbom layer and the CBOM coverage count below "
                "are empty because the import was refused — not because the bank lacks crypto"
            )

    # 3. one estate observation ---------------------------------------------- #
    if do_observe:
        observation = build_observation(estate)
        response = connection.post("/api/v1/ingestion/observations", json=observation)
        body = response.json() if response.content else {}
        result["steps"]["observation"] = {
            "status": response.status_code,
            "state": body.get("state") or body.get("detail", {}).get("error"),
            "stored": body.get("stored") or (body.get("storage") or {}).get("stored"),
            "projection_id": body.get("projection_id"),
            "counts": {
                "assets": len(observation["assets"]),
                "evidence": len(observation["evidence"]),
                "relationships": len(observation["relationships"]),
            },
            "detail": None if response.status_code < 400 else body,
        }

    # 4. read back what product 2 now knows ---------------------------------- #
    result["output"] = _read_back(connection)
    return result


def _read_back(connection) -> dict[str, Any]:
    def get(path: str) -> Any:
        response = connection.get(path)
        return response.json() if response.status_code == 200 else {"error": response.status_code, "body": response.text[:300]}

    boms = get("/api/v1/estate/evidence/boms")
    counts = boms.get("counts") if isinstance(boms, dict) else None
    technology = get("/api/v1/technology-bom")
    assets = get("/api/v1/assets?page=1&page_size=1")
    coverage = get("/api/v1/cbom/coverage")
    graph = get("/api/v1/graph/stats")
    scans = get("/api/v1/scans?limit=3")
    return {
        "six_bom_counts": counts,
        "bom_consistency": (boms.get("consistency") if isinstance(boms, dict) else None),
        "technology_bom": {
            "total_components": technology.get("total_components"),
            "by_layer": technology.get("components_by_layer"),
            "dependency_count": technology.get("dependency_count"),
        } if isinstance(technology, dict) else technology,
        "crypto_assets": assets.get("total") if isinstance(assets, dict) else assets,
        "cbom_coverage": coverage if not isinstance(coverage, dict) or "counts" in coverage else coverage,
        "graph": {key: graph.get(key) for key in ("nodes", "edges", "nodes_by_kind", "systems")} if isinstance(graph, dict) else graph,
        "scans": len(scans.get("scans") or []) if isinstance(scans, dict) else None,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--estate", type=Path, required=True, help="generated bank estate root")
    parser.add_argument("--api", default=os.environ.get("CRYPTOSCAN_API", "http://127.0.0.1:8010"))
    parser.add_argument("--user", default=os.environ.get("ADMIN_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("ADMIN_PASSWORD", ""))
    parser.add_argument("--skip-scan", action="store_true", help="do not run the source scan")
    parser.add_argument("--skip-cbom", action="store_true", help="do not import declared CBOM documents")
    parser.add_argument("--skip-observe", action="store_true", help="do not post the estate observation")
    args = parser.parse_args(list(argv) if argv is not None else None)

    estate = args.estate.resolve(strict=True)
    if not (estate / "LAB.json").is_file():
        print(f"not a generated bank estate: {estate}", file=sys.stderr)
        return 64
    password = args.password or "cryptoscan"
    value = connect(
        estate=estate,
        api=args.api,
        user=args.user,
        password=password,
        do_scan=not args.skip_scan,
        do_cbom=not args.skip_cbom,
        do_observe=not args.skip_observe,
    )
    print(json.dumps(value, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
