"""Offline deterministic synthetic estate generator. No socket/DNS/cloud access."""

from datetime import datetime, timedelta
import io
import tarfile
import time

from tools.banking_sandbox.catalog import (
    ARCHETYPES,
    PROFILES,
    ZONES,
    HARDWARE,
    VENDOR_CATEGORIES,
    ALGORITHMS,
    PURPOSES,
    LANGUAGES,
    LIBRARIES,
    STATIC_SCENARIOS,
    TEST_MODES,
)
from tools.banking_sandbox.common import (
    LABEL,
    DIRECTORIES,
    canonical,
    digest,
    number,
    identifier,
    dump,
    stream,
    private_directory,
    file_hash,
)
from tools.banking_sandbox import documents, pki
from tools.banking_sandbox.scenarios import scenarios
from tools.banking_sandbox.sources import source

SCALES = {"small": (10, 30), "medium": (30, 100), "large": (100, 500), "mega": (500, 700), "mixed": (10, 500)}


def image_layout(path, bank, app, epoch):
    """A real OCI layout with an inert layer, explicitly NOT a runnable OS image."""
    path.mkdir(parents=True)
    blobs = path / "blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(raw):
        import hashlib

        h = hashlib.sha256(raw).hexdigest()
        (blobs / h).write_bytes(raw)
        return {"digest": "sha256:" + h, "size": len(raw)}

    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        raw = b"SYNTHETIC LAB inert OCI fixture; no runnable application\n"
        item = tarfile.TarInfo("SYNTHETIC-LAB.txt")
        item.size = len(raw)
        item.mtime = 0
        item.mode = 0o444
        tar.addfile(item, io.BytesIO(raw))
    layer = blob(data.getvalue())
    config = blob(
        canonical(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {"Labels": {"synthetic": "true"}},
                "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]},
                "history": [{"created_by": "SYNTHETIC fixture generator"}],
            }
        )
    )
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", **layer}],
    }
    m = blob(canonical(manifest))
    dump(path / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    dump(
        path / "index.json",
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    **m,
                    "annotations": {"org.opencontainers.image.ref.name": bank + "-SYNTHETIC"},
                }
            ],
        },
    )
    return m["digest"]


def generate(
    output,
    banks=150,
    scale="mixed",
    profile="worst-case-bank",
    seed="ZELNX-PUBLIC-LAB-1",
    epoch="2030-01-01T00:00:00Z",
    pqc=True,
    legacy=True,
    conflicts=True,
    drift=True,
    crypto_complexity="high",
    network_complexity="high",
    vendor_complexity="high",
    max_systems=50000,
):
    if not 1 <= banks <= 2000 or scale not in SCALES or profile not in PROFILES:
        raise ValueError("invalid bounded bank/scale/profile")
    if len(seed) > 128 or max_systems > 200000 or max_systems < 1:
        raise ValueError("generation budget")
    dt = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
    if dt.utcoffset() != timedelta(0):
        raise ValueError("explicit UTC simulated epoch required")
    sizes = []
    for b in range(banks):
        profile_scale = {
            "small-bank": "small",
            "medium-bank": "medium",
            "large-bank": "large",
            "global-bank": "mega",
        }.get(profile)
        if profile == "minimal":
            low, high = 10, 10
        elif profile_scale:
            low, high = SCALES[profile_scale]
        elif scale == "mixed":
            low, high = (10, 30) if b % 5 < 2 else (50, 150) if b % 5 < 4 else (150, 500)
        else:
            low, high = SCALES[scale]
        sizes.append(low + number(seed, b, "size") % (high - low + 1))
    if sum(sizes) > max_systems:
        raise ValueError("system budget exceeded before creating output")
    root = private_directory(output)
    public = root / "public"
    control = root / "control"
    control.mkdir(mode=0o700)
    for name in DIRECTORIES:
        (public / name).mkdir(parents=True)
    for name in ("ground_truth", "expected_results", "reports"):
        (control / name).mkdir(mode=0o700)
    (root / ".gitignore").write_text("*\n")
    options = dict(
        banks=banks,
        scale=scale,
        profile=profile,
        seed=seed,
        epoch=epoch,
        pqc=pqc,
        legacy=legacy,
        conflicts=conflicts,
        drift=drift,
        crypto_complexity=crypto_complexity,
        network_complexity=network_complexity,
        vendor_complexity=vendor_complexity,
    )
    dump(
        root / "LAB.json",
        {
            "format": "ZELNX_SYNTHETIC_ESTATE_V1",
            "synthetic": True,
            "label": LABEL,
            "options": options,
            "ground_truth_scanner_access": "FORBIDDEN",
            "clock_kind": "SIMULATED",
            "network_execution": "NONE_OFFLINE_GENERATION",
        },
    )
    counts = {
        k: 0
        for k in (
            "banks",
            "systems",
            "applications",
            "services",
            "components",
            "certificates",
            "hsm",
            "kms_keys",
            "vendors",
            "evidence",
            "unknown",
            "weak",
            "deprecated",
            "pqc",
            "conflicts",
            "drift",
            "sbom",
            "cbom",
        )
    }
    bank_summary = []
    vocab = set()
    start = time.monotonic()
    cdx_validator, spdx_validator = documents.validators()
    for bi, count in enumerate(sizes):
        bank = f"bank-{bi + 1:04d}"
        archetype = {
            "legacy-bank": "legacy-heavy",
            "cloud-bank": "cloud-first",
            "crypto-heavy-bank": "hsm-heavy",
            "pqc-bank": "digital-only",
        }.get(profile, ARCHETYPES[bi % len(ARCHETYPES)])
        base = number(seed, bank)
        metadata = {
            "bank_id": bank,
            "organization_name": f"SYNTHETIC Zelnx Institution {bi + 1:04d}",
            "synthetic": True,
            "label": LABEL,
            "archetype": archetype,
            "environment_profile": f"{bank}-env-{base % 99991}",
            "infrastructure_profile": f"{archetype}-{base % 7}",
            "technology_profile": f"{bank}-tech-{base % 13}",
            "crypto_maturity_profile": int(base % 6),
            "regulatory_profile": "SYNTHETIC-policy-" + str(base % 9),
            "cloud_onprem_profile": ["onprem", "cloud-representation", "hybrid"][base % 3],
            "vendor_profile": bank + "-vendors",
            "network_topology": bank + "-vrf",
            "application_portfolio": bank + "-portfolio",
            "ownership_model": ["central", "federated", "outsourced-with-gaps"][base % 3],
            "environments": ["dev", "test", "staging", "production", "dr"],
            "data_centers": [bank + "-dc-a", bank + "-dc-b"],
        }
        dump(public / "banks" / f"{bank}.json", metadata)
        dump(public / "organizations" / f"{bank}.json", metadata)
        systems = []
        assets = []
        apps = []
        services = []
        components = []
        certs = []
        source_truth = []
        manifests = []
        sboms = []
        spdxs = []
        cboms = []
        runtime = []
        hsm = []
        kms = []
        vendors = []
        evidence = []
        cert_bundle = []
        rootpem, rootmeta = pki.certificate(seed, bank, -1, epoch)
        (public / "pki" / f"{bank}-root.pem").write_bytes(rootpem)
        for ca_index, ca_name in [(-2, "intermediate"), (-3, "issuing")]:
            ca_pem, _ = pki.certificate(seed, bank, ca_index, epoch)
            (public / "pki" / f"{bank}-{ca_name}.pem").write_bytes(ca_pem)
        for si in range(count):
            system = f"{bank}-system-{si:04d}"
            env = metadata["environments"][si % 5]
            zone_pool = (
                ZONES
                if network_complexity == "high"
                else ZONES[:18]
                if network_complexity == "medium"
                else ["dmz", "web", "application", "database", "management", "pki", "hsm", "dr"]
            )
            zone = zone_pool[(si + bi) % len(zone_pool)]
            asset = system + "-hardware"
            owner = None if si % 17 == 0 else bank + "-team-" + str(si % 9)
            vendor = f"SYNTHETIC-Vendor-{(bi * 7 + si) % 503:03d}"
            hardware = HARDWARE[si % len(HARDWARE)]
            systems.append(
                {
                    "bank_id": bank,
                    "system_id": system,
                    "asset_id": asset,
                    "environment": env,
                    "zone": zone,
                    "data_center": metadata["data_centers"][si % 2],
                    "owner": owner,
                    "platform": ["Linux-LAB", "Windows-LAB", "mainframe-LAB", "container-LAB"][
                        si % 4 if legacy else si % 1
                    ],
                    "label": LABEL,
                    "synthetic": True,
                }
            )
            assets.append(
                {
                    "asset_id": asset,
                    "bank_id": bank,
                    "system_id": system,
                    "kind": hardware,
                    "vendor": vendor,
                    "model": hardware + "-LAB",
                    "firmware_version": f"{1 + si % 7}.{si % 13}-SYNTHETIC",
                    "serial": "SYNTHETIC-" + digest([bank, si])[:20],
                    "location": bank + "-building-" + str(si % 3),
                    "data_center": metadata["data_centers"][si % 2],
                    "owner": owner,
                    "environment": env,
                    "supported_protocols": ["TLS1.2", "TLS1.3"],
                    "crypto_capabilities": ALGORITHMS[si % 20 : si % 20 + 3],
                    "key_types": ["PUBLIC_TEST_ONLY", "METADATA_REFERENCE"],
                    "key_sizes": [2048, 256],
                    "evidence_source": "generated-config-export",
                    "confidence": "DECLARED_NOT_OBSERVED",
                    "certificate_ids": [],
                    "hsm_kms_relationship": bank + "-hsm-" + str(si % 3),
                    "synthetic": True,
                }
            )
            for ai in range(2):
                idx = si * 2 + ai
                app = system + f"-app-{ai}"
                lang, ext = LANGUAGES[(idx + bi) % len(LANGUAGES)]
                scenario_pool = (
                    STATIC_SCENARIOS
                    if crypto_complexity == "high"
                    else STATIC_SCENARIOS[:14]
                    if crypto_complexity == "medium"
                    else STATIC_SCENARIOS[:2]
                )
                sc = scenario_pool[(idx // len(LANGUAGES) + bi) % len(scenario_pool)]
                text, families, materialized = source(lang, sc, idx)
                rel = f"source/{bank}/{app}{ext}"
                p = public / rel
                p.parent.mkdir(exist_ok=True)
                p.write_text(text)
                compids = [
                    bank + "-shared-lib",
                    app + "-runtime-provider",
                    app + "-internal-helper",
                    app + "-unused-crypto",
                    app + "-vendor-sdk",
                    app + "-misleading-name",
                ]
                serviceids = [app + "-tls", app + "-backend"]
                certificateids = [app + "-cert-current", app + "-cert-previous"]
                ip = f"192.0.2.{1 + (si % 250)}"
                approw = {
                    "app_id": app,
                    "logical_app_id": bank + "-portfolio-" + str(idx % 20),
                    "bank_id": bank,
                    "system_id": system,
                    "name": app + " SYNTHETIC",
                    "language": lang,
                    "owner": owner,
                    "environment": env,
                    "component_ids": compids,
                    "service_ids": serviceids,
                    "certificate_ids": certificateids,
                    "ip": ip,
                    "image_digest": "sha256:" + digest([seed, app, "image-metadata"]),
                    "source": rel,
                    "synthetic": True,
                }
                apps.append(approw)
                source_truth.append(
                    {
                        "case_id": identifier(seed, rel),
                        "bank_id": bank,
                        "source_file": rel,
                        "system_id": system,
                        "app_id": app,
                        "expected_families": families,
                        "runtime_executed": False,
                        "language": lang,
                        "scenario": materialized,
                        "expected_source_evidence_type": "STATIC_OBSERVED",
                        "owner": owner,
                        "oracle": "TEMPLATE_SEMANTICS_NOT_SCANNER_OUTPUT",
                    }
                )
                libs = []
                for ci, cid in enumerate(compids):
                    name = (
                        "OpenSSL"
                        if ci in (0, 1)
                        else "SYNTHETIC-internal-helper"
                        if ci == 2
                        else "SYNTHETIC-unused-crypto"
                        if ci == 3
                        else vendor + "-SDK"
                        if ci == 4
                        else "not-openssl-reporting"
                    )
                    c = {
                        "component_id": cid,
                        "app_id": app,
                        "bank_id": bank,
                        "name": name,
                        "declared_version": "3.0.13" if ci < 2 else None if ci == 4 and idx % 7 == 0 else "1.0-LAB",
                        "runtime_version": "3.0.11" if ci == 1 and conflicts else "3.0.13" if ci < 2 else None,
                        "installed": True,
                        "usage": "UNKNOWN" if ci != 3 else "NOT_EXECUTED_IN_SCENARIO",
                        "transitive_dependencies": compids[2:3] if ci == 1 else [],
                        "renamed_from": "SYNTHETIC-OldName" if ci == 4 else None,
                        "provider": LIBRARIES[(idx + ci) % len(LIBRARIES)],
                        "synthetic": True,
                    }
                    libs.append(c)
                    components.append(c)
                sb = documents.sbom(approw, libs, epoch)
                sd = documents.spdx(approw, libs, epoch)
                if idx == 0:
                    cdx_validator.validate(sb)
                    spdx_validator.validate(sd)
                sboms.append({"target": app, "entity_type": "application", "document": sb, "synthetic": True})
                sboms.append(
                    {
                        "target": approw["image_digest"],
                        "entity_type": "container-metadata",
                        "document": sb,
                        "synthetic": True,
                    }
                )
                spdxs.append({"target": app, "document": sd, "synthetic": True})
                algo_pool = (
                    ALGORITHMS
                    if crypto_complexity == "high"
                    else ALGORITHMS[:30]
                    if crypto_complexity == "medium"
                    else ALGORITHMS[:19]
                )
                algorithm = algo_pool[(idx + bi) % len(algo_pool)]
                if not pqc and algorithm.startswith(("ML-", "SLH-", "X25519+", "ECDSA+")):
                    algorithm = "AES-256"
                if not legacy and algorithm in (
                    "MD5",
                    "SHA-1",
                    "3DES",
                    "DES",
                    "RC4",
                    "RSA-1024",
                    "DH-768",
                    "TLS1.0",
                    "TLS1.1",
                ):
                    algorithm = "AES-256"
                cb = documents.cbom(approw, algorithm, PURPOSES[idx % len(PURPOSES)])
                if idx == 0:
                    cdx_validator.validate(cb)
                cboms.append({"target": app, "entity_type": "vendor-declaration", "document": cb, "synthetic": True})
                manifests.append(
                    {
                        "app_id": app,
                        "manifest": {"dependencies": {c["name"]: c["declared_version"] for c in libs}},
                        "lock": [
                            {"name": c["name"], "version": c["declared_version"], "integrity": "sha256-" + digest(c)}
                            for c in libs
                        ],
                        "source_repository": "https://" + app + ".lab.invalid/source",
                        "ci_pipeline": {"network_access": False, "image_ref": approw["image_digest"]},
                        "synthetic": True,
                    }
                )
                for ei, eid in enumerate(serviceids):
                    certidx = idx * 2 + ei
                    pem, certmeta = pki.certificate(seed, bank, certidx, epoch)
                    cert_bundle.append(pem)
                    certid = certificateids[ei]
                    certs.append(
                        {
                            "certificate_id": certid,
                            "bank_id": bank,
                            "system_id": system,
                            "app_id": app,
                            "endpoint_id": eid,
                            "sha256": __import__("hashlib").sha256(pem).hexdigest(),
                            "pem_bundle": f"certificates/{bank}.pem",
                            "issuer_ref": bank + "-issuing",
                            "in_use": ei == 0,
                            "chain_status": "WRONG_CHAIN_DECLARATION_FIXTURE" if certidx % 31 == 0 else "LAB_CHAIN",
                            **certmeta,
                            "synthetic": True,
                        }
                    )
                    services.append(
                        {
                            "endpoint_id": eid,
                            "bank_id": bank,
                            "system_id": system,
                            "app_id": app,
                            "ip": ip,
                            "ipv6": f"2001:db8:{bi + 1:x}:{si + 1:x}::{ei + 1}",
                            "port": 443 + idx * 2 + ei,
                            "sni": f"endpoint-{certidx}.{bank}.lab.invalid",
                            "vrf": bank + "-vrf",
                            "zone": zone,
                            "certificate_id": certid,
                            "supported_protocols": ["TLS1.2", "TLS1.3"]
                            + (["TLS1.0"] if legacy and idx % 13 == 0 else []),
                            "configured_protocol": "TLS1.2",
                            "simulated_negotiated_protocol": "TLS1.3",
                            "actual_negotiation_executed": False,
                            "actor": app + "-sidecar" if idx % 5 == 0 else "external-lb" if ei == 0 else app,
                            "transport_layer": "edge" if ei == 0 else "backend",
                            "mtls": idx % 5 == 0,
                            "synthetic": True,
                        }
                    )
                assets[-1]["certificate_ids"].extend(certificateids)
                runtime.append(
                    {
                        "bank_id": bank,
                        "system_id": system,
                        "app_id": app,
                        "process_id": "LAB-PID-" + str(1000 + idx),
                        "provider": libs[1]["provider"],
                        "version": libs[1]["runtime_version"],
                        "event": ["startup", "scheduled-job", "payment", "occasional"][idx % 4],
                        "loaded_modules": ["libcrypto.so", "SYNTHETIC-provider.so"],
                        "configured_algorithm": algorithm,
                        "simulated_operation": PURPOSES[idx % len(PURPOSES)],
                        "fixture_only": True,
                        "actual_execution": False,
                        "evidence_type": "IMPORTED",
                        "simulated_evidence_type": "RUNTIME_OBSERVED",
                        "timestamp": epoch,
                        "clock_kind": "SIMULATED",
                        "synthetic": True,
                    }
                )
                evidence.append(
                    {
                        "evidence_id": identifier(bank, app, "configured"),
                        "bank_id": bank,
                        "source": "generated-application-config",
                        "collector": "SYNTHETIC-fixture-producer",
                        "timestamp": epoch,
                        "clock_kind": "SIMULATED",
                        "target": system,
                        "system": system,
                        "application": app,
                        "process": None,
                        "network_endpoint": serviceids[0],
                        "component": compids[1],
                        "evidence_type": "CONFIGURED",
                        "raw_observation_reference": rel,
                        "normalized_fact": {"algorithm": algorithm, "purpose": PURPOSES[idx % len(PURPOSES)]},
                        "confidence": "DECLARED",
                        "provenance": "SYNTHETIC/LAB",
                        "actual_execution": False,
                    }
                )
                kms.append(
                    {
                        "key_id": app + "-kms-key",
                        "bank_id": bank,
                        "app_id": app,
                        "kind": ["AWS-KMS-like", "Azure-Key-Vault-like", "GCP-KMS-like", "onprem-KMS"][idx % 4],
                        "algorithm": "AES-256",
                        "key_size": 256,
                        "state": "DISABLED" if idx % 19 == 0 else "ENABLED",
                        "rotation_days": 90,
                        "purpose": "application-encryption",
                        "hsm_backed": idx % 2 == 0,
                        "owner": owner,
                        "environment": env,
                        "material": "METADATA_ONLY_NO_SECRET",
                        "synthetic": True,
                    }
                )
            osapp = {"app_id": system, "name": system + " OS inventory"}
            sboms.append(
                {
                    "target": system,
                    "entity_type": "server",
                    "document": documents.sbom(osapp, libs, epoch),
                    "synthetic": True,
                }
            )
        rows, truth = scenarios(bank, apps, systems, epoch, drift)
        # Materialize limited visibility; do not merely attach scenario names.
        missing_source = {
            r["subject"]
            for r in rows
            if r["scenario"] in ("network-without-source", "legacy-network-only", "appliance-config-only")
        }
        no_runtime = {
            r["subject"] for r in rows if r["scenario"] in ("source-without-runtime", "appliance-config-only")
        }
        no_sbom = {
            r["subject"]
            for r in rows
            if r["scenario"] in ("runtime-missing-sbom", "legacy-network-only", "appliance-config-only")
        }
        for a in apps:
            if a["app_id"] in missing_source:
                (public / a["source"]).unlink()
                a["source"] = None
                a["source_disposition"] = "UNKNOWN_UNAVAILABLE"
        source_truth = [t for t in source_truth if t["app_id"] not in missing_source]
        runtime = [r for r in runtime if r["app_id"] not in no_runtime]
        sboms = [r for r in sboms if r["target"] not in no_sbom]
        spdxs = [r for r in spdxs if r["target"] not in no_sbom]
        # An explicit gap record replaces unavailable documents, not an empty BOM.
        stream(
            public / "sbom" / f"{bank}-gaps.jsonl",
            (
                {"target": a, "status": "UNKNOWN", "reason": "LEGACY_OR_PARTIAL_VISIBILITY", "synthetic": True}
                for a in sorted(no_sbom)
            ),
        )
        sidecar_app = next(r["subject"] for r in rows if r["scenario"] == "sidecar-tls-not-application")
        for endpoint in services:
            if endpoint["app_id"] == sidecar_app:
                endpoint["actor"] = sidecar_app + "-sidecar"

        if not conflicts:
            for r in rows:
                r["conflicting_declaration"] = None
            for t in truth:
                t["expected_conflict"] = False
                t["same_semantic_scope_conflict"] = False
        for hi in range(5):
            hsm.append(
                {
                    "hsm_id": bank + "-hsm-" + str(hi),
                    "bank_id": bank,
                    "kind": HARDWARE[hi],
                    "vendor": f"SYNTHETIC-HSM-vendor-{bi % 73}",
                    "model": "LAB-" + str(hi),
                    "firmware": "1.0-SYNTHETIC",
                    "key_refs": [bank + f"-hsm-key-{hi}"],
                    "key_type": ["RSA", "EC", "AES"][hi % 3],
                    "key_size": [2048, 256, 256][hi % 3],
                    "operations": [
                        "RSA-PSS",
                        "ECDSA",
                        "AES-GCM",
                        "AES-CBC",
                        "HMAC",
                        "SHA-256",
                        "SHA-384",
                        "SHA-512",
                        "generate",
                        "wrap",
                        "unwrap",
                    ],
                    "lifecycle": "ACTIVE",
                    "rotation_days": 90,
                    "audit_event": {"kind": "SIMULATED_OPERATION", "actual_execution": False, "timestamp": epoch},
                    "certificate_association": certs[hi]["certificate_id"],
                    "synthetic": True,
                }
            )
        category_limit = {"low": 6, "medium": 14, "high": 23}[vendor_complexity]
        for vi, category in enumerate(VENDOR_CATEGORIES[:category_limit]):
            vendors.append(
                {
                    "vendor_id": f"SYNTHETIC-Vendor-{(bi * 7 + vi) % 503:03d}",
                    "bank_id": bank,
                    "category": category,
                    "product": f"SYNTHETIC-{category}-{bi % 19}",
                    "version": f"{1 + bi % 5}.{vi % 7}",
                    "firmware": "LAB-1.0",
                    "declared_algorithms": ALGORITHMS[vi : vi + 3],
                    "evidence_type": "VENDOR_DECLARED",
                    "owner": bank + "-vendor-team",
                    "support_lifecycle": "EXPIRED" if vi % 7 == 0 else "SUPPORTED_LAB_DECLARATION",
                    "pqc_readiness": "VENDOR_DECLARED_NOT_VERIFIED",
                    "sbom_ref": f"sbom/{bank}.jsonl",
                    "cbom_ref": f"cbom/{bank}.jsonl" if vi % 2 else None,
                    "documentation": "Fictional lab product. No real vendor certification.",
                    "synthetic": True,
                }
            )
        tables = {
            "systems": systems,
            "assets": assets,
            "applications": apps,
            "network": services,
            "certificates": certs,
            "sbom": sboms,
            "cbom": cboms,
            "runtime": runtime,
            "hsm": hsm,
            "kms": kms,
            "vendors": vendors,
            "scenarios": rows,
            "fixtures": evidence,
            "hbom": assets,
            "vbom": vendors,
            "techbom": components,
            "nbom": [
                {"bank_id": bank, "from": a, "to": b, "relationship": "ALLOWED_SYNTHETIC_PATH", "synthetic": True}
                for a, b in [
                    ("internet-simulated", "waf"),
                    ("waf", "external-lb"),
                    ("external-lb", "api-gateway"),
                    ("api-gateway", "web"),
                    ("web", "application"),
                    ("application", "microservices"),
                    ("microservices", "database"),
                    ("microservices", "message-queue"),
                    ("payment", "hsm"),
                    ("application", "pki"),
                    ("management", "monitoring"),
                ]
            ],
        }
        candidates = [
            ("api-gateway", "payment"),
            ("api-gateway", "microservices"),
            ("microservices", "hsm"),
            ("microservices", "pki"),
            ("application", "backup"),
            ("application", "dr"),
            ("branch", "api-gateway"),
            ("atm-like", "card"),
            ("partner", "api-gateway"),
            ("vendor", "management"),
        ]
        tables["nbom"].extend(
            {"bank_id": bank, "from": a, "to": b, "relationship": "APPROVED_SYNTHETIC_PATH", "synthetic": True}
            for i, (a, b) in enumerate(candidates)
            if (base >> i) & 1
        )
        dump(
            public / "network" / f"{bank}-topology.json",
            {
                "bank_id": bank,
                "synthetic": True,
                "vrf": bank + "-vrf",
                "nodes": [
                    {"zone": z, "prefix": f"2001:db8:{bi + 1:x}:{zi:x}::/64", "data_centers": metadata["data_centers"]}
                    for zi, z in enumerate(ZONES)
                ],
                "edges": tables["nbom"],
                "firewall_default": "DENY_EXCEPT_DECLARED_EDGES",
                "management_plane": "SEPARATE_DECLARED_ZONE",
                "actual_network_created": False,
            },
        )
        for name, table in tables.items():
            stream(public / name / f"{bank}.jsonl", table)
        stream(public / "sbom" / f"{bank}-spdx.jsonl", spdxs)
        stream(public / "source" / bank / "manifests.jsonl", manifests)
        (public / "certificates" / f"{bank}.pem").write_bytes(b"".join(cert_bundle))
        stream(control / "ground_truth" / f"{bank}-static.jsonl", source_truth)
        stream(control / "ground_truth" / f"{bank}-scenarios.jsonl", truth)
        stream(
            control / "ground_truth" / f"{bank}-assets.jsonl",
            (
                {
                    "bank_id": bank,
                    "system_id": s["system_id"],
                    "expected_owner": s["owner"],
                    "expected_environment": s["environment"],
                    "expected_zone": s["zone"],
                    "expected_status": "SYNTHETIC_DEFINED_ASSET",
                }
                for s in systems
            ),
        )
        from tools.banking_sandbox.exports import kubernetes

        dump(public / "kubernetes" / f"{bank}.json", kubernetes(bank, apps))
        dump(
            public / "cloud" / f"{bank}.json",
            {
                "synthetic": True,
                "bank_id": bank,
                "credential_requirement": "NONE",
                "providers": [
                    {
                        "kind": k,
                        "network": bank + "-vpc",
                        "subnets": ZONES[:8],
                        "object_store": bank + "-objects",
                        "private_endpoint": f"private.{bank}.lab.invalid",
                        "security_groups": [{"from": "application", "to": "database", "port": 5432}],
                        "kms_refs": [k["key_id"] for k in kms[:3]],
                    }
                    for k in ["AWS-like", "Azure-like", "GCP-like"]
                ],
            },
        )
        img = image_layout(public / "containers" / bank / "oci", bank, apps[0], epoch)
        stream(
            public / "containers" / f"{bank}.jsonl",
            (
                {
                    "bank_id": bank,
                    "app_id": a["app_id"],
                    "declared_image_digest": a["image_digest"],
                    "actual_fixture_image_digest": img if i == 0 else None,
                    "oci_materialized": i == 0,
                    "runnable": False,
                    "synthetic": True,
                    "sbom_ref": f"sbom/{bank}.jsonl",
                    "runtime_state": "NOT_STARTED",
                }
                for i, a in enumerate(apps)
            ),
        )
        dump(
            public / "drift" / f"{bank}.json",
            {
                "bank_id": bank,
                "enabled": drift,
                "clock_kind": "SIMULATED",
                "baseline": epoch,
                "changed_at": (dt + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
                "target": apps[0]["app_id"],
                "previous": {"protocol": "TLS1.3", "cipher": "AES-256-GCM", "certificate": "ECDSA-P256"},
                "new": {"protocol": "TLS1.2", "cipher": "AES-128-GCM", "certificate": "RSA-2048"},
                "affected_apps": [a["app_id"] for a in apps[:20]],
                "affected_dependencies": apps[0]["component_ids"],
                "affected_cbom": f"cbom/{bank}.jsonl",
                "pqc_delta": "CLASSICAL_DEPENDENCIES_REQUIRE_REVIEW",
                "actual_change_executed": False,
            },
        )
        dump(
            public / "pqc" / f"{bank}.json",
            {
                "bank_id": bank,
                "enabled": pqc,
                "level": bi % 6 if pqc else 0,
                "algorithms": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA", "X25519+ML-KEM-768"] if pqc else [],
                "implementation": "CONFIGURATION_FIXTURES_ONLY_NOT_EXECUTED",
                "migration_dependencies": ["RSA", "ECDSA", "ECDH", "DH", "TLS", "PKI", "HSM", "KMS", "vendor"],
                "production_like_means": "SYNTHETIC_DECLARATION_NOT_REAL_PRODUCTION",
                "synthetic": True,
            },
        )
        dump(
            public / "fixtures" / f"{bank}-failures.json",
            {
                "synthetic": True,
                "malformed_sbom": {"bomFormat": "NOT-CYCLONEDX"},
                "malformed_cbom": {"components": "not-an-array"},
                "corrupted_evidence": {"claimed_sha256": "0" * 64, "raw": "tampered"},
                "unavailable_dependencies": ["database", "redis", "HSM", "KMS", "Kubernetes"],
                "actual_faults_executed": False,
            },
        )
        local = {
            "banks": 1,
            "systems": count,
            "applications": len(apps),
            "services": len(services),
            "components": len(components),
            "certificates": len(certs),
            "hsm": len(hsm),
            "kms_keys": len(kms),
            "vendors": len(vendors),
            "evidence": len(evidence),
            "unknown": sum(r.get("evidence_type") == "UNKNOWN" for r in rows),
            "weak": sum(r.get("declaration") in ("RSA-1024", "TLS1.0") for r in rows),
            "deprecated": sum(r.get("declaration") == "TLS1.0" for r in rows),
            "pqc": int(pqc),
            "conflicts": sum(
                bool(r.get("conflicting_declaration")) and r.get("comparison_scope") == "SAME_SCOPE_CONFLICT"
                for r in rows
            ),
            "drift": int(drift),
            "sbom": len(sboms) + len(spdxs),
            "cbom": len(cboms),
        }
        for k, v in local.items():
            counts[k] += v
        vocab.update(v["vendor_id"] for v in vendors)
        bank_summary.append(
            {
                "bank_id": bank,
                "name": metadata["organization_name"],
                "archetype": archetype,
                "counts": local,
                "data_centers": metadata["data_centers"],
                "catalog_ref": f"applications/{bank}.jsonl",
            }
        )
    dump(
        public / "catalog.json",
        {
            "synthetic": True,
            "label": LABEL,
            "counts": counts,
            "unique_vendors": len(vocab),
            "counts_mean": "GENERATED_FIXTURE_INVENTORY_NOT_CRYPTOSCAN_DISCOVERY",
            "banks": bank_summary,
        },
    )
    dump(
        control / "expected_results" / "coverage.json",
        {
            "test_modes": TEST_MODES,
            "source": "GENERATOR_SPECIFICATION_NOT_PRODUCT_OUTPUT",
            "all_boms": ["NBOM", "CBOM", "TechBOM", "HBOM", "VBOM", "SBOM"],
            "actual_product_results": "NOT_YET_RUN",
        },
    )
    from tools.banking_sandbox.dashboard import render

    render(public)
    files = [
        {"path": str(p.relative_to(public)), "sha256": file_hash(p), "bytes": p.stat().st_size}
        for p in sorted(public.rglob("*"))
        if p.is_file()
    ]
    dump(root / "manifest.json", {"version": "SYNTHETIC_PUBLIC_MANIFEST_V1", "files": files, "synthetic": True})
    dump(
        root / "generation-metrics.json",
        {
            "wall_seconds": time.monotonic() - start,
            "counts": counts,
            "unique_vendors": len(vocab),
            "public_bytes": sum(f["bytes"] for f in files),
            "public_files": len(files),
            "actual_product_capacity_measured": False,
        },
    )
    return counts
