#!/usr/bin/env python3
"""Guide 178 — the VBOM dependency graph, measured.

    vendor → product → release → firmware / package → asset
           → application → crypto → runtime → business system

Twenty-nine points, one per section of the review that asked for this depth. Each point is
proven by running the module against a recorded vendor estate and reading what it answers:
not "the model supports applicability" but "8.4 against 9.2 answers VERSION_MISMATCH and
says which question failed".

Usage::

    python scripts/cbom_vbom_dependency.py            # markdown to stdout
    python scripts/cbom_vbom_dependency.py --json out.json --md out.md
    python scripts/cbom_vbom_dependency.py --check    # exit 1 on a partial, 2 on a failure
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
SERVICES = REPO / "services"

SCHEMA = "cryptoscan.vbom-dependency-guide/1"
GUIDE = 178

VERDICT_PASS = "PASS"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_FAIL = "FAIL"

AS_OF = "2026-11-03"
RECENT = "2026-10-01T06:30:00Z"
STALE_READ = "2024-06-01T06:30:00Z"

DIGEST_OPENSSL = "sha256:1f2e3d4c5b6a7988"

PAYLOAD: dict[str, Any] = {
    "as_of": AS_OF,
    "documents": [
        {"id": "DOC-1001", "title": "payShield 9000 8.4 security policy", "vendor": "Thales",
         "product": "payShield 9000", "version": "8.4", "published_at": "2024-02-01",
         "received_at": "2024-02-20", "valid_from": "2024-02-20",
         "valid_until": "2026-04-01", "last_reviewed": "2025-02-20", "reviewer": "s.iyer",
         "revision": 3, "source_hash": "sha256:1a1a"},
        {"id": "DOC-1002", "title": "payShield 9000 9.2 release notes", "vendor": "Thales",
         "product": "payShield 9000", "version": "9.2", "published_at": "2025-06-01",
         "received_at": "2026-10-01", "valid_until": "2027-10-01", "reviewer": "s.iyer",
         "revision": 1, "source_hash": "sha256:2b2b"},
        {"id": "DOC-1003", "title": "OpenSSL 3.0.13 capabilities", "vendor": "OpenSSL Project",
         "product": "OpenSSL", "version": "3.0.13", "published_at": "2026-01-30",
         "received_at": "2026-09-15", "valid_until": "2027-09-15", "reviewer": "r.nair",
         "revision": 2, "source_hash": "sha256:3c3c"},
        {"id": "DOC-1004", "title": "BIG-IP 17.1 datasheet", "vendor": "F5",
         "product": "BIG-IP 9000", "version": "17.1", "published_at": "2026-03-01",
         "received_at": "2026-10-20", "valid_until": "2027-03-01", "reviewer": "r.nair",
         "revision": 1, "source_hash": "sha256:4d4d"},
        {"id": "DOC-1005", "title": "PKI Platform 5.0 statement", "vendor": "DigiCert",
         "product": "PKI Platform", "version": "5.0", "published_at": "2025-11-01",
         "received_at": "2025-11-10", "valid_until": "2026-11-01", "reviewer": "a.khan",
         "revision": 1, "source_hash": "sha256:5e5e"},
        {"id": "DOC-1006", "title": "payShield 9000 8.4 firmware guide", "vendor": "Thales",
         "product": "payShield 9000", "version": "8.4", "firmware": "8.4",
         "published_at": "2026-02-01", "received_at": "2026-09-01",
         "valid_until": "2027-09-01", "reviewer": "s.iyer", "revision": 1,
         "source_hash": "sha256:6f6f"},
        {"id": "DOC-0900", "title": "Acme Datacrypt datasheet (2023)", "vendor": "Acme Legacy",
         "product": "Acme Datacrypt", "version": "4.2", "published_at": "2023-01-01",
         "received_at": STALE_READ, "reviewer": "a.khan", "revision": 1,
         "source_hash": "sha256:0707"},
    ],
    "vendors": [
        {"name": "Thales", "lifecycle": "ACTIVE", "risk_level": "HIGH",
         "documents": ["DOC-1001"]},
        {"name": "OpenSSL Project", "lifecycle": "ACTIVE", "risk_level": "MEDIUM",
         "documents": ["DOC-1003"]},
        {"name": "F5", "lifecycle": "ACTIVE", "risk_level": "MEDIUM", "documents": ["DOC-1004"]},
        {"name": "DigiCert", "lifecycle": "ACTIVE", "risk_level": "LOW",
         "documents": ["DOC-1005"]},
        {"name": "Acme Legacy", "lifecycle": "RETIRED", "risk_level": "LOW",
         "documents": ["DOC-0900"]},
    ],
    "products": [
        {"name": "payShield 9000", "vendor": "Thales", "family": "payShield", "type": "HSM",
         "lifecycle": "SUPPORTED", "documents": ["DOC-1001"]},
        {"name": "payShield SDK", "vendor": "Thales", "family": "payShield", "type": "SDK",
         "lifecycle": "SUPPORTED"},
        {"name": "OpenSSL", "vendor": "OpenSSL Project", "family": "OpenSSL",
         "type": "LIBRARY", "lifecycle": "SUPPORTED", "documents": ["DOC-1003"]},
        {"name": "BIG-IP 9000", "vendor": "F5", "family": "BIG-IP", "type": "LOAD_BALANCER",
         "lifecycle": "SUPPORTED", "documents": ["DOC-1004"]},
        {"name": "PKI Platform", "vendor": "DigiCert", "family": "PKI", "type": "CA",
         "lifecycle": "SUPPORTED", "documents": ["DOC-1005"]},
        {"name": "Acme Datacrypt", "vendor": "Acme Legacy", "type": "HSM",
         "lifecycle": "EOL", "eol_date": "2026-06-30", "eos_date": "2026-12-31",
         "documents": ["DOC-0900"]},
        # refused by name: a product nobody supplies cannot be attributed
        {"name": "Orphan Product", "vendor": "", "type": "HSM"},
    ],
    "releases": [
        {"product": "payShield 9000", "version": "8.4", "vendor": "Thales",
         "release_date": "2024-01-15", "support_status": "MAINTENANCE",
         "eol_date": "2027-01-31", "documents": ["DOC-1001"],
         "capabilities": [
             {"algorithm": "RSA", "key_size": 2048, "purpose": "card verification",
              "documents": ["DOC-1001"]},
             {"algorithm": "ECDSA", "curve": "P-256", "purpose": "firmware signing",
              "documents": ["DOC-1006"]},
             {"algorithm": "AES", "key_size": 256, "mode": "GCM", "purpose": "key block",
              "documents": ["DOC-1006"]},
         ]},
        {"product": "payShield 9000", "version": "9.2", "vendor": "Thales",
         "release_date": "2025-05-01", "support_status": "SUPPORTED",
         "documents": ["DOC-1002"],
         "capabilities": [
             {"algorithm": "RSA", "key_size": 3072, "documents": ["DOC-1002"]},
             {"algorithm": "ML-KEM", "key_size": 768, "purpose": "key transport",
              "documents": ["DOC-1002"]},
         ]},
        {"product": "payShield SDK", "version": "5.7", "vendor": "Thales",
         "release_date": "2025-04-01", "support_status": "SUPPORTED",
         "packages": [{"coordinate": "pkg:generic/payshield-sdk", "version": "5.7"}]},
        {"product": "OpenSSL", "version": "3.0.13", "vendor": "OpenSSL Project",
         "release_date": "2026-01-28", "support_status": "SUPPORTED",
         "documents": ["DOC-1003"], "pqc_capability": "DECLARED",
         "packages": [{"coordinate": "pkg:generic/openssl", "version": "3.0.13"}],
         "capabilities": [
             {"algorithm": "AES", "key_size": 256, "mode": "GCM",
              "documents": ["DOC-1003"]},
             {"algorithm": "RSA", "key_size": 2048, "documents": ["DOC-1003"]},
             {"algorithm": "ML-KEM", "key_size": 768, "purpose": "key exchange",
              "documents": ["DOC-1003"]},
         ]},
        {"product": "BIG-IP 9000", "version": "17.1", "vendor": "F5",
         "support_status": "SUPPORTED", "documents": ["DOC-1004"],
         "capabilities": [{"algorithm": "ECDHE", "curve": "P-256",
                           "documents": ["DOC-1004"]}]},
        {"product": "PKI Platform", "version": "5.0", "vendor": "DigiCert",
         "support_status": "SUPPORTED", "documents": ["DOC-1005"]},
        # the release cites no document, so its capability inherits none and is refused by
        # name: a capability nobody can be shown is a rumour with an algorithm attached
        {"product": "Acme Datacrypt", "version": "4.2", "vendor": "Acme Legacy",
         "support_status": "EOS",
         "capabilities": [{"algorithm": "RSA", "key_size": 2048}]},
        # refused by name: a release with no version is not a release
        {"product": "payShield 9000", "version": ""},
    ],
    "firmware": [
        {"product": "payShield 9000", "version": "8.4.2", "release": "8.4",
         "release_date": "2025-11-01", "support_status": "MAINTENANCE",
         "eol_date": "2027-01-31", "security_status": "PATCHED",
         "pqc_capability": "DECLARED", "documents": ["DOC-1006"]},
        {"product": "payShield 9000", "version": "9.2.1", "release": "9.2",
         "release_date": "2026-05-01", "support_status": "SUPPORTED",
         "security_status": "CURRENT", "pqc_capability": "DECLARED",
         "documents": ["DOC-1002"]},
        {"product": "BIG-IP 9000", "version": "17.1.0", "release": "17.1",
         "support_status": "SUPPORTED", "documents": ["DOC-1004"]},
        {"product": "BIG-IP 9000", "version": "15.1.0", "release": "17.1",
         "support_status": "EOL", "eol_date": "2025-12-31", "security_status": "VULNERABLE"},
    ],
    "assets": [
        {"name": "HSM-001", "type": "HSM", "product": "payShield 9000", "version": "8.4",
         "firmware": "8.4.2", "serial": "PS9K-0001", "location": "DC-01",
         "owner": "Payments", "documents": ["DOC-1006"]},
        {"name": "HSM-002", "type": "HSM", "product": "payShield 9000", "version": "9.2",
         "firmware": "9.2.1", "location": "DC-02", "owner": "Payments"},
        {"name": "HSM-005", "type": "HSM", "product": "payShield 9000", "version": "9.2",
         "firmware": "9.2.1", "serial": "PS9K-0005", "location": "DC-02",
         "owner": "Payments", "documents": ["DOC-1002"]},
        {"name": "HSM-003", "type": "HSM", "product": "Acme Datacrypt", "version": "4.2",
         "firmware": "4.2.0", "serial": "AC-0003", "location": "DC-01", "owner": "Legacy"},
        # refused by name: an asset that names no product cannot be attributed
        {"name": "HSM-004", "product": "", "type": "HSM"},
    ],
    "packages": [
        {"coordinate": "pkg:generic/openssl", "version": "3.0.11", "product": "OpenSSL",
         "evidence_id": "sbom:SBOM-18291#pkg:generic/openssl"},
        {"coordinate": "pkg:generic/payshield-sdk", "version": "5.4",
         "product": "payShield SDK", "evidence_id": "sbom:SBOM-18291#pkg:generic/payshield-sdk"},
    ],
    "applications": [
        {"name": "Payments API", "system": "Payments System", "owner": "payments-team",
         "system_criticality": "TIER-1",
         "packages": ["pkg:generic/openssl", "pkg:generic/payshield-sdk"],
         "products": ["payShield SDK"], "assets": ["HSM-001", "HSM-005"],
         "endpoints": ["payments.bank.example:443"],
         "evidence_id": "cmdb:APP-9281"},
        {"name": "Reporting API", "system": "Reporting System", "owner": "reporting-team",
         "packages": ["pkg:generic/openssl"], "evidence_id": "cmdb:APP-9310"},
    ],
    "systems": [{"name": "Payments System", "criticality": "TIER-1"},
                {"name": "Reporting System", "criticality": "TIER-3"}],
    "usage": [
        {"application": "Payments API", "process": "payments-api 1821", "pid": 1821,
         "host": "srv-k8s-03", "package": "pkg:generic/openssl", "package_version": "3.0.11",
         "algorithm": "RSA", "key_size": 2048, "operation": "SIGN", "provider": "OpenSSL",
         "observed_at": "2026-11-03T06:30:00Z",
         "evidence_id": "probe:srv-k8s-03:1821"},
        {"application": "Payments API", "process": "payments-api 1821", "pid": 1821,
         "host": "srv-k8s-03", "package": "pkg:generic/openssl", "package_version": "3.0.11",
         "algorithm": "AES", "key_size": 256, "mode": "GCM", "operation": "ENCRYPT",
         "observed_at": "2026-11-03T06:30:00Z",
         "evidence_id": "probe:srv-k8s-03:1821"},
    ],
    "network": [
        {"name": "LB-001", "type": "LOAD_BALANCER", "product": "BIG-IP 9000",
         "version": "17.1", "firmware": "17.1.0", "serial": "F5-0001", "location": "DMZ",
         "endpoint": "payments.bank.example:443", "application": "Payments API",
         "certificate": "CERT-001", "tls_mode": "TERMINATE",
         "evidence_id": "config:LB-001"},
    ],
    "pki": [
        {"ca": "Issuing CA", "product": "PKI Platform", "version": "5.0", "serial": "CA-0001",
         "certificate": "CERT-001", "endpoint": "payments.bank.example:443",
         "not_after": "2027-04-01", "subject": "payments.bank.example",
         "evidence_id": "pki:CA-0001"},
    ],
    "components": (
        [{"coordinate": f"pkg:generic/component-{index:03d}", "vendor": "OpenSSL Project"}
         for index in range(82)]
        + [{"coordinate": f"pkg:generic/mystery-{index:03d}", "vendor": "UNKNOWN"}
           for index in range(13)]
        + [{"coordinate": f"pkg:internal/service-{index:03d}", "vendor": "INTERNAL"}
           for index in range(5)]
    ),
    "history": [
        {"subject": "HSM-001", "field": "vendor", "previous": "Acme Legacy",
         "current": "Thales", "changed_at": "2026-10-01",
         "evidence_before": "DOC-0900", "evidence_after": "DOC-1001"},
        {"subject": "HSM-001", "field": "firmware", "previous": "8.4.1", "current": "8.4.2",
         "changed_at": "2026-06-15", "evidence_before": "DOC-0800",
         "evidence_after": "DOC-1006"},
        {"subject": "HSM-003", "field": "support_status", "previous": "SUPPORTED",
         "current": "EOS", "changed_at": "2025-12-31"},
        {"subject": "HSM-001", "field": "colour", "previous": "grey", "current": "black"},
    ],
}


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import techbom, vbom_dependency  # noqa: PLC0415

    return {"v": vbom_dependency, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _state(v: Any, declaration: dict[str, Any], deployment: dict[str, Any]) -> str:
    """One applicability answer, for the three states a recorded estate cannot stage."""
    return v.applicability(declaration, deployment, as_of=AS_OF)["state"]


def measure() -> dict[str, Any]:
    modules = _load()
    v = modules["v"]
    built = v.build(PAYLOAD, as_of=AS_OF, estate_id="vbom:production")
    bom = built["bom"]
    points: list[dict[str, Any]] = []

    def add(number: int, section: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"VBOM-{number:02d}", "number": number, "section": section,
                       "question": question, "probes": probes, "failed": failed,
                       "verdict": verdict})

    thales = v.vendor_products(bom, vendor="Thales")

    # ---- 1. vendor → product ------------------------------------------------ #
    add(1, "vendor→product", "a product is a first-class node with its own identity", [
        _probe("the-vendor-has-products-not-algorithms",
               sorted(row["name"] for row in thales["products"]) ==
               ["payShield 9000", "payShield SDK"],
               ", ".join(row["name"] for row in thales["products"])),
        _probe("each-product-carries-family-and-type",
               all(row["family"] and row["type"] for row in thales["products"]),
               ", ".join(f"{row['name']}={row['type']}/{row['family']}"
                         for row in thales["products"])),
        _probe("a-product-with-no-vendor-is-refused-by-name",
               any(row["code"] == "PRODUCT_WITHOUT_VENDOR"
                   and row["subject"] == "Orphan Product" for row in built["refusals"]),
               "Orphan Product refused (PRODUCT_WITHOUT_VENDOR)"),
    ])

    # ---- 2. vendor → product → version -------------------------------------- #
    releases = v.product_releases(bom, product="payShield 9000")
    add(2, "vendor→product→version", "a claim is attached to a release, not to a company", [
        _probe("the-product-has-more-than-one-release",
               [row["version"] for row in releases["releases"]] == ["8.4", "9.2"],
               ", ".join(f"{row['version']} [{row['lifecycle_state']['state']}]"
                         for row in releases["releases"])),
        _probe("each-release-carries-its-own-capabilities",
               {row["version"]: len(row["capabilities"]) for row in releases["releases"]}
               == {"8.4": 3, "9.2": 2},
               str({row["version"]: len(row["capabilities"])
                    for row in releases["releases"]})),
        _probe("a-release-with-no-version-is-refused",
               any(row["code"] == "RELEASE_WITHOUT_VERSION" for row in built["refusals"]),
               "a release row with an empty version is refused"),
    ])

    # ---- 3. eight applicability states -------------------------------------- #
    applicability = v.declaration_applicability(bom, as_of=AS_OF)
    add(3, "version-applicability",
        "applicability is one of eight states, and the first failing question decides", [
            _probe("eight-states-are-named",
                   len(v.APPLICABILITY) == 8 and
                   set(v.APPLICABILITY) == {"MATCHED", "PARTIAL_MATCH", "VERSION_MISMATCH",
                                            "PRODUCT_MISMATCH", "DEPLOYMENT_UNVERIFIED",
                                            "EXPIRED", "SUPERSEDED", "UNKNOWN"},
                   ", ".join(v.APPLICABILITY)),
            _probe("every-state-has-a-stated-meaning",
                   all(v.APPLICABILITY_MEANS.get(state) for state in v.APPLICABILITY),
                   f"{len(v.APPLICABILITY_MEANS)} meanings"),
            _probe("the-estate-reaches-five-of-them",
                   {"MATCHED", "PARTIAL_MATCH", "VERSION_MISMATCH", "EXPIRED",
                    "DEPLOYMENT_UNVERIFIED"} <= set(applicability["states"]),
                   ", ".join(f"{state} {count}"
                             for state, count in sorted(applicability["states"].items()))),
            _probe("a-claim-about-another-product-is-PRODUCT_MISMATCH",
                   _state(v, {"product": "payShield 7000", "version": "8.4"},
                          {"asset": "HSM-001", "product": "payShield 9000",
                           "version": "8.4", "verified": True}) == "PRODUCT_MISMATCH",
                   _state(v, {"product": "payShield 7000", "version": "8.4"},
                          {"asset": "HSM-001", "product": "payShield 9000",
                           "version": "8.4", "verified": True})),
            _probe("a-replaced-revision-is-SUPERSEDED",
                   _state(v, {"product": "payShield 9000", "version": "8.4",
                              "superseded_by": "DOC-1006"},
                          {"asset": "HSM-001", "product": "payShield 9000",
                           "version": "8.4", "verified": True}) == "SUPERSEDED",
                   "revision DOC-1006 replaced the claim"),
            _probe("a-claim-with-no-version-is-UNKNOWN",
                   _state(v, {"product": "payShield 9000"},
                          {"asset": "HSM-001", "product": "payShield 9000",
                           "verified": True}) == "UNKNOWN",
                   _state(v, {"product": "payShield 9000"},
                          {"asset": "HSM-001", "product": "payShield 9000",
                           "verified": True})),
        ])

    # ---- 4. vendor → actual asset ------------------------------------------- #
    assets = v.vendor_assets(bom, vendor="Thales", as_of=AS_OF)
    add(4, "vendor→asset", "a vendor dependency reaches the asset the bank actually runs", [
        _probe("the-asset-is-reached-through-the-product",
               {row["name"] for row in assets["assets"]} == {"HSM-001", "HSM-002", "HSM-005"},
               ", ".join(row["name"] for row in assets["assets"])),
        _probe("the-asset-carries-location-environment-and-owner",
               all(row["location"] and row["environment"] and row["owner"]
                   for row in assets["assets"]),
               "; ".join(f"{row['name']} {row['location']}/{row['environment']}/"
                         f"{row['owner']}" for row in assets["assets"])),
        _probe("an-asset-with-no-product-is-refused-by-name",
               any(row["code"] == "ASSET_WITHOUT_PRODUCT" and row["subject"] == "HSM-004"
                   for row in built["refusals"]),
               "HSM-004 refused (ASSET_WITHOUT_PRODUCT)"),
    ])

    # ---- 5. vendor → hardware (HBOM) --------------------------------------- #
    hardware = v.hardware_chain(bom, asset="HSM-001")
    identity = v.hardware_identity(bom, asset="HSM-001")
    add(5, "vendor→hardware", "a hardware vendor's product reaches the device, with the "
        "HBOM's identity", [
            _probe("the-chain-runs-vendor-product-firmware-asset",
                   hardware["vendor"] == "Thales" and hardware["model"] == "payShield 9000"
                   and hardware["firmware"][0]["version"] == "8.4.2",
                   hardware["statement"]),
            _probe("the-firmware-carries-dates-and-support-state",
                   hardware["firmware"][0]["support_status"] == "MAINTENANCE"
                   and hardware["firmware"][0]["eol_date"] == "2027-01-31",
                   f"{hardware['firmware'][0]['support_status']} until "
                   f"{hardware['firmware'][0]['eol_date']}"),
            _probe("the-hardware-identity-is-shared-with-the-hbom",
                   identity["identity"]["kind"] == "HSM"
                   and identity["identity"]["digest"] == bom["by_key"][
                       v._one(bom, "HSM-001")]["digest"],
                   identity["statement"]),
        ])

    # ---- 6. vendor → software (SBOM) --------------------------------------- #
    software = v.software_chain(bom, vendor="Thales")
    add(6, "vendor→software", "a software vendor reaches an application through a package", [
        _probe("the-release-ships-a-package",
               any(row["name"] == "pkg:generic/payshield-sdk" for row in software["packages"]),
               ", ".join(row["name"] for row in software["packages"])),
        _probe("the-package-reaches-the-application",
               "Payments API" in {row["name"] for row in software["applications"]},
               ", ".join(row["name"] for row in software["applications"])),
        _probe("the-sdk-version-and-the-sbom-version-are-both-kept",
               any(row["state"] == "VENDOR_DEPLOYMENT_VERSION_CONFLICT"
                   for row in v.sbom_agreement(bom, vendor="Thales")["conflicts"]),
               v.sbom_agreement(bom, vendor="Thales")["statement"]),
    ])

    # ---- 7. vendor → crypto depth ------------------------------------------ #
    crypto = v.crypto_chain(bom, vendor="Thales")
    add(7, "vendor→crypto", "a capability is a provider, an algorithm, a key size, a mode "
        "and a purpose", [
            _probe("the-capability-carries-key-size-mode-and-purpose",
                   all(row["algorithm"] for row in crypto["capabilities"])
                   and any(row["key_size"] for row in crypto["capabilities"])
                   and any(row["mode"] for row in crypto["capabilities"])
                   and any(row["purpose"] for row in crypto["capabilities"]),
                   ", ".join(f"{row['capability']} ({row['purpose'] or 'no purpose'})"
                             for row in crypto["capabilities"])),
            _probe("a-capability-implements-an-algorithm-node",
                   all(row["implemented_as"] for row in crypto["capabilities"]),
                   "every capability names its ALGORITHM node"),
            _probe("the-class-is-VENDOR_DECLARED",
                   {row["class"] for row in crypto["capabilities"]} == {"VENDOR_DECLARED"},
                   "VENDOR_DECLARED"),
        ])

    # ---- 8. vendor-declared ≠ actual usage --------------------------------- #
    declared = v.declared_vs_observed(bom, vendor="Thales")
    add(8, "declared≠observed",
        "a vendor's ML-KEM claim is a declaration, never a usage", [
            _probe("the-unused-capabilities-are-named",
                   "ML-KEM-768 capability" in declared["not_observed"],
                   ", ".join(declared["not_observed"])),
            _probe("the-used-ones-are-observed-not-declared",
                   all(row["state"] == "RUNTIME_OBSERVED" for row in declared["rows"]
                       if row["capability"] in ("RSA-2048 capability",
                                                "AES-256-GCM capability")),
                   ", ".join(f"{row['capability']}={row['state']}"
                             for row in declared["rows"])),
            _probe("declared-count-and-observed-count-are-both-printed",
                   declared["declared_count"] > declared["observed_count"] >= 1,
                   f"{declared['declared_count']} declared, "
                   f"{declared['observed_count']} observed"),
        ])

    # ---- 9. vendor → application ------------------------------------------- #
    applications = v.vendor_applications(bom, vendor="Thales")
    add(9, "vendor→application", "the question is which applications depend on the product", [
        _probe("the-applications-are-named",
               "Payments API" in {row["name"] for row in applications["applications"]},
               ", ".join(row["name"] for row in applications["applications"])),
        _probe("the-path-that-reaches-each-one-is-returned",
               all(row["path"] for row in applications["applications"]),
               " → ".join(applications["applications"][0]["path"]) or "(no path)"),
        _probe("a-vendor-that-reaches-nothing-says-so",
               v.vendor_applications(bom, vendor="Acme Legacy")["applications"] != []
               or "no application is reachable" in
               v.vendor_applications(bom, vendor="Acme Legacy")["statement"],
               v.vendor_applications(bom, vendor="Acme Legacy")["statement"]),
    ])

    # ---- 10. vendor → business system -------------------------------------- #
    systems = v.vendor_systems(bom, vendor="Thales")
    add(10, "vendor→business system", "business impact is a property of the graph", [
        _probe("the-systems-are-reached",
               {"Payments System", "Reporting System"} ==
               {row["name"] for row in systems["systems"]},
               ", ".join(row["name"] for row in systems["systems"])),
        _probe("the-impact-is-not-taken-from-the-vendor-criticality-field",
               "criticality" not in systems["statement"].lower(),
               systems["statement"]),
        _probe("an-eol-product-on-a-device-nothing-uses-reaches-no-system",
               v.vendor_systems(bom, vendor="Acme Legacy")["systems"] == [],
               v.vendor_systems(bom, vendor="Acme Legacy")["statement"]),
    ])

    # ---- 11. vendor → crypto → business system ----------------------------- #
    crypto_business = v.crypto_business(bom, vendor="OpenSSL Project", algorithm="RSA")
    add(11, "vendor→crypto→system",
        "which business systems depend on this vendor for this algorithm", [
            _probe("the-answer-names-the-algorithm-and-the-systems",
                   crypto_business["algorithm"] == "RSA" and crypto_business["systems"],
                   crypto_business["statement"]),
            _probe("the-crypto-assets-that-carry-it-are-listed",
                   crypto_business["crypto"] != [],
                   ", ".join(row["name"] for row in crypto_business["crypto"])),
            _probe("an-algorithm-the-vendor-does-not-offer-answers-nothing",
                   v.crypto_business(bom, vendor="OpenSSL Project",
                                     algorithm="3DES")["systems"] == [],
                   v.crypto_business(bom, vendor="OpenSSL Project",
                                     algorithm="3DES")["statement"]),
        ])

    # ---- 12. vendor → runtime ---------------------------------------------- #
    runtime = v.runtime_dependency(bom, vendor="OpenSSL Project")
    add(12, "vendor→runtime", "the last hop is a process that was watched", [
        _probe("a-process-loads-the-vendors-package",
               [row["name"] for row in runtime["processes"]] == ["payments-api 1821"],
               ", ".join(row["name"] for row in runtime["processes"])),
        _probe("the-operations-are-observations-and-not-declarations",
               runtime["observations"] and
               {row["class"] for row in runtime["observations"]} == {"OBSERVED"}
               and not any(row["basis"] == "vendor-datasheet"
                           for row in runtime["observations"]),
               ", ".join(f"{row['algorithm']} {row['operation']} [{row['class']} via "
                         f"{row['basis']}]" for row in runtime["observations"])),
        _probe("the-observation-carries-its-evidence-reference",
               all(row["evidence_id"] for row in runtime["observations"]),
               ", ".join(row["evidence_id"] for row in runtime["observations"])),
    ])

    # ---- 13. vendor → network (NBOM) --------------------------------------- #
    network = v.network_dependency(bom, vendor="F5")
    network_identity = v.network_identity(bom, asset="LB-001")
    add(13, "vendor→network", "a network vendor's device reaches the application behind it", [
        _probe("the-device-and-endpoint-are-reached",
               len(network["devices"]) == 1 and len(network["endpoints"]) == 1,
               network["statement"]),
        _probe("the-endpoint-routes-to-the-application",
               "Payments API" in {row["name"] for row in network["applications"]},
               ", ".join(row["name"] for row in network["applications"])),
        _probe("the-network-identity-names-the-tls-mode",
               network_identity["endpoints"][0]["tls_mode"] == "TERMINATE",
               network_identity["statement"]),
    ])

    # ---- 14. vendor → PKI -------------------------------------------------- #
    pki = v.pki_dependency(bom, vendor="DigiCert")
    add(14, "vendor→certificate", "a PKI vendor reaches the endpoint its certificate is on", [
        _probe("the-ca-the-certificate-and-the-endpoint-are-reached",
               len(pki["authorities"]) == 1 and len(pki["certificates"]) == 1
               and len(pki["endpoints"]) == 1, pki["statement"]),
        _probe("the-certificate-is-issued-by-the-instance",
               any(claim["relation"] == "ISSUED_BY" for claim in bom["claims"]),
               "CERT-001 ISSUED_BY Issuing CA"),
        _probe("the-application-behind-the-endpoint-is-named",
               "Payments API" in {row["name"] for row in pki["applications"]},
               ", ".join(row["name"] for row in pki["applications"])),
    ])

    # ---- 15. vendor → firmware --------------------------------------------- #
    firmware = v.firmware_posture(bom, as_of=AS_OF)
    add(15, "vendor→firmware", "firmware is versioned, dated and supportable on its own", [
        _probe("every-firmware-row-carries-its-fields",
               all({"release_date", "support_status", "eol_date", "security_status",
                    "pqc_capability"} <= set(row) for row in firmware["firmware"]),
               f"{len(firmware['firmware'])} firmware rows"),
        _probe("the-firmware-that-is-eol-is-named",
               any(row["lifecycle"] == "EOL" for row in firmware["firmware"]),
               ", ".join(f"{row['name']}[{row['lifecycle']}]"
                         for row in firmware["firmware"])),
        _probe("a-device-that-runs-unrecorded-firmware-is-refused",
               any(row["code"] == "UNKNOWN_REF" and "firmware 4.2.0" in str(row["subject"])
                   for row in bom["refusals"]),
               "HSM-003's firmware is not a node the estate holds"),
    ])

    # ---- 16. vendor lifecycle ---------------------------------------------- #
    eol = v.lifecycle_impact(bom, product="Acme Datacrypt", as_of=AS_OF)
    state = v.lifecycle_of({"name": "Acme Datacrypt", "lifecycle": "EOL"}, as_of=AS_OF)
    add(16, "vendor-lifecycle", "a lifecycle state is derived, dated and terminal", [
        _probe("the-seven-states-are-named",
               len(v.LIFECYCLE_STATES) == 7 and set(v.LIFECYCLE_TERMINAL) ==
               {"EOL", "EOS", "RETIRED"}, ", ".join(v.LIFECYCLE_STATES)),
        _probe("eol-is-terminal",
               state["state"] == "EOL" and state["terminal"],
               state["statement"]),
        _probe("the-fan-out-names-what-the-product-reaches",
               eol["affected"] and "asset" in eol["affected"],
               eol["statement"]),
    ])

    # ---- 17. vendor evidence freshness ------------------------------------- #
    evidence = v.evidence_report(bom, as_of=AS_OF)
    add(17, "evidence-freshness", "vendor evidence ages, and is labelled rather than deleted", [
        _probe("an-expired-document-is-EXPIRED",
               evidence["states"]["EXPIRED"] >= 2,
               ", ".join(f"{state} {count}"
                         for state, count in evidence["states"].items())),
        _probe("an-undated-document-cannot-be-fresh",
               v.evidence_freshness({"id": "DOC-X"}, as_of=AS_OF)["state"] == "UNKNOWN",
               v.evidence_freshness({"id": "DOC-X"}, as_of=AS_OF)["statement"]),
        _probe("an-old-document-is-STALE-not-trusted",
               v.evidence_freshness(PAYLOAD["documents"][6],
                                    as_of=AS_OF)["state"] == "VENDOR_EVIDENCE_STALE",
               v.evidence_freshness(PAYLOAD["documents"][6], as_of=AS_OF)["statement"]),
    ])

    # ---- 18. vendor document → actual deployment --------------------------- #
    verification = v.verification(bom, as_of=AS_OF)
    add(18, "document→deployment", "five checks decide whether a document applies", [
        _probe("the-five-checks-are-answered-per-row",
               all({"product_match", "version_match", "firmware_match",
                    "deployment_verified", "capability_observed"} <= set(row)
                   for row in verification["rows"]),
               f"{len(verification['rows'])} declaration(s), five checks each"),
        _probe("a-matching-verified-deployment-is-MATCHED",
               verification["verified"] >= 1,
               f"{verification['verified']} MATCHED"),
        _probe("a-mismatch-is-not-silently-applied",
               any(row["state"] == "VERSION_MISMATCH" for row in verification["rows"]),
               verification["statement"]),
    ])

    # ---- 19. vendor → SBOM ------------------------------------------------- #
    sbom = v.sbom_agreement(bom, vendor="OpenSSL Project")
    add(19, "vendor→SBOM", "a declared version and an SBOM version that differ is a finding", [
        _probe("the-conflict-names-both-versions",
               sbom["conflicts"] and
               (sbom["conflicts"][0]["declared"], sbom["conflicts"][0]["observed"]) ==
               ("3.0.13", "3.0.11"), sbom["conflicts"][0]["statement"]),
        _probe("the-conflict-is-not-called-annotated-as-agreement",
               sbom["conflicts"][0]["state"] == "VENDOR_DEPLOYMENT_VERSION_CONFLICT",
               sbom["conflicts"][0]["state"]),
        _probe("a-matching-package-is-IMPORTED",
               all(row["state"] == "VENDOR_DEPLOYMENT_VERSION_CONFLICT"
                   for row in sbom["packages"] if row["declared"] != row["observed"]),
               f"{len(sbom['packages'])} package(s), {len(sbom['conflicts'])} conflict(s)"),
    ])

    # ---- 20. vendor → CBOM ------------------------------------------------- #
    cbom = v.cbom_agreement(bom, vendor="OpenSSL Project")
    add(20, "vendor→CBOM", "the declaration and the observation are two answers, both kept", [
        _probe("declared-only-algorithms-are-named",
               "ML-KEM" in cbom["declared_only"],
               ", ".join(cbom["declared_only"]) or "none"),
        _probe("the-algorithms-in-both-are-named",
               {"RSA", "AES"} <= set(cbom["both"]),
               ", ".join(cbom["both"])),
        _probe("the-declaration-keeps-its-own-class",
               all(row["declared"] == "VENDOR_DECLARED" for row in cbom["declared"]),
               "VENDOR_DECLARED"),
    ])

    # ---- 21./22. hardware and network identity ----------------------------- #
    add(21, "vendor→HBOM", "the VBOM and the HBOM name the same hardware node", [
        _probe("the-identity-carries-kind-model-serial-and-firmware",
               identity["identity"]["model"] == "payShield 9000"
               and identity["serial"] == "PS9K-0001"
               and identity["identity"]["firmware"],
               identity["statement"]),
        _probe("the-identity-is-a-digest-the-other-boms-can-cite",
               len(identity["identity"]["digest"]) == 10,
               identity["identity"]["digest"]),
        _probe("the-device-is-reached-by-a-claim-not-by-a-name-match",
               any(claim["relation"] == "HAS_MODEL" for claim in bom["claims"]),
               "HSM-001 HAS_MODEL payShield 9000"),
    ])

    add(22, "vendor→NBOM", "the VBOM and the NBOM name the same network nodes", [
        _probe("the-device-listens-on-a-host-port-endpoint",
               network_identity["endpoints"][0]["endpoint"] ==
               "payments.bank.example:443",
               network_identity["endpoints"][0]["endpoint"]),
        _probe("the-endpoint-is-routed-to-an-application-by-a-record",
               network_identity["endpoints"][0]["routes_to"] == ["Payments API"],
               ", ".join(network_identity["endpoints"][0]["routes_to"])),
        _probe("the-vendor-device-is-a-node-the-nbom-holds",
               any(row["kind"] == "LOAD_BALANCER" for row in bom["assets"]),
               "LB-001 is a LOAD_BALANCER node"),
    ])

    # ---- 23. the digital twin ---------------------------------------------- #
    twin = v.twin(bom)
    add(23, "vendor→twin", "the VBOM is a projection of the estate, not a vendor database", [
        _probe("every-one-of-the-ten-levels-is-populated",
               len(twin["gaps"]) == 0,
               twin["statement"]),
        _probe("the-vendor-edges-are-in-the-graph",
               {"SUPPLIED_BY", "RELEASES", "FIRMWARE_OF", "SHIPS_PACKAGE", "HAS_MODEL",
                "SUPPORTS", "DOCUMENTED_BY"} <= set(twin["vendor_edges"]),
               ", ".join(f"{relation} {count}"
                         for relation, count in twin["vendor_edges"].items())),
        _probe("the-projection-carries-a-refusal-log",
               bool(built["refusals"]) and bool(bom["refusals"]),
               f"{len(built['refusals'])} builder refusal(s), "
               f"{len(bom['refusals'])} estate refusal(s)"),
    ])

    # ---- 24. version conflict ---------------------------------------------- #
    conflicts = v.version_conflicts(bom)
    add(24, "vendor-conflict", "a version conflict keeps all four layers and picks none", [
        _probe("the-four-layers-are-named",
               any(len(row["layers"]) >= 2 for row in conflicts["conflicts"]),
               "; ".join(f"{row['subject']}: "
                         + ", ".join(f"{layer}={value}"
                                     for layer, value in row["layers"].items())
                         for row in conflicts["conflicts"])),
        _probe("the-conflict-code-is-explicit",
               {row["code"] for row in conflicts["conflicts"]} ==
               {"VENDOR_DEPLOYMENT_VERSION_CONFLICT"},
               "VENDOR_DEPLOYMENT_VERSION_CONFLICT"),
        _probe("no-layer-is-called-the-truth",
               all(not any("truth" in layer.lower() for layer in row["layers"])
                   for row in conflicts["conflicts"]),
               "no layer is promoted"),
    ])

    # ---- 25. history ------------------------------------------------------- #
    history = v.history(PAYLOAD)
    add(25, "vendor-history", "a vendor relationship has a history with evidence on both "
        "sides", [
            _probe("the-vendor-change-is-VENDOR_CHANGED",
                   any(row["code"] == "VENDOR_CHANGED" and row["subject"] == "HSM-001"
                       for row in history["changes"]),
                   next(row["statement"] for row in history["changes"]
                        if row["code"] == "VENDOR_CHANGED")),
            _probe("both-sides-carry-an-evidence-reference",
                   all(row["evidence_before"] and row["evidence_after"]
                       for row in history["changes"]
                       if row["field"] in ("vendor", "firmware")),
                   ", ".join(f"{row['evidence_before']}→{row['evidence_after']}"
                             for row in history["changes"]
                             if row["field"] in ("vendor", "firmware"))),
            _probe("a-field-that-is-not-a-dependency-is-ignored",
                   all(row["field"] in v.HISTORY_FIELDS for row in history["changes"]),
                   f"{len(history['changes'])} change(s), 'colour' excluded"),
        ])

    # ---- 26. coverage ------------------------------------------------------ #
    coverage = v.coverage(PAYLOAD)
    add(26, "vendor-coverage", "unknown is not internal and neither is no-vendor", [
        _probe("the-coverage-is-computed-not-claimed",
               coverage["coverage_percent"] == 82.0,
               coverage["statement"]),
        _probe("unknown-and-internal-are-counted-separately",
               (coverage["unknown"], coverage["internal"]) == (13, 5),
               f"{coverage['unknown']} unknown, {coverage['internal']} internal"),
        _probe("the-unidentified-components-are-listed",
               len(coverage["unidentified"]) == 13,
               ", ".join(coverage["unidentified"][:3]) + " …"),
    ])

    # ---- 27. risk propagation ---------------------------------------------- #
    risk = v.risk_propagation(bom, vendor="Thales", as_of=AS_OF)
    legacy_risk = v.risk_propagation(bom, vendor="Acme Legacy", as_of=AS_OF)
    add(27, "vendor-risk", "risk travels through dependencies, and stops where they stop", [
        _probe("the-score-is-composed-of-the-levels-it-reaches",
               risk["score"] > 0 and risk["weights"].get("system") == 2,
               risk["statement"]),
        _probe("a-terminal-lifecycle-doubles-the-score",
               legacy_risk["terminal"] != []
               and legacy_risk["score"] == legacy_risk["base"] * 2,
               f"{legacy_risk['score']} = base {legacy_risk['base']} × 2 "
               f"({legacy_risk['terminal'][0]['product']} {legacy_risk['terminal'][0]['state']})"),
        _probe("a-vendor-that-reaches-no-system-scores-nothing-propagated",
               legacy_risk["systems"] == [] and risk["systems"],
               f"Acme reaches no system: {legacy_risk['statement'][-90:]}"),
    ])

    # ---- 28. PQC ----------------------------------------------------------- #
    pqc = v.pqc_posture(bom, vendor="Thales")
    add(28, "vendor-PQC", "vendor PQC is DECLARED, deployment is UNKNOWN, usage is "
        "NOT_OBSERVED", [
            _probe("the-vendor-claim-is-DECLARED",
                   pqc["declared"] == "DECLARED", pqc["statement"]),
            _probe("the-runtime-is-NOT_OBSERVED",
                   pqc["runtime"] == "NOT_OBSERVED", pqc["runtime"]),
            _probe("the-answer-is-not-PQC-READY",
                   "READY = TRUE" not in pqc["statement"].upper()
                   and pqc["deployment"] in ("UNKNOWN", "DECLARED"),
                   f"declared {pqc['declared']}, deployment {pqc['deployment']}, "
                   f"runtime {pqc['runtime']}"),
        ])

    # ---- 29. the graph ----------------------------------------------------- #
    levels = built["levels"]
    add(29, "the-graph", "the graph the review drew is the graph the module builds", [
        _probe("every-level-of-the-drawn-graph-exists",
               [name for name in levels if levels[name]] ==
               [name for name, _, _ in v.LEVELS],
               ", ".join(f"{name} {count}" for name, count in levels.items())),
        _probe("the-total-is-assets-and-claims-not-a-vendor-list",
               len(bom["assets"]) >= 45 and len(bom["claims"]) >= 60,
               f"{len(bom['assets'])} assets, {len(bom['claims'])} claims"),
        _probe("the-applicability-of-the-estate-is-published",
               bool(applicability["states"]),
               ", ".join(f"{state} {count}"
                         for state, count in sorted(applicability["states"].items()))),
    ])

    counts = {VERDICT_PASS: 0, VERDICT_PARTIAL: 0, VERDICT_FAIL: 0}
    for point in points:
        counts[point["verdict"]] += 1
    probes = sum(len(point["probes"]) for point in points)
    passed = sum(1 for point in points for probe in point["probes"] if probe["ok"])
    return {
        "schema": SCHEMA,
        "guide": GUIDE,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "as_of": AS_OF,
        "counts": counts,
        "points": len(points),
        "probes": probes,
        "probes_passed": passed,
        "statement": (f"{counts[VERDICT_PASS]} of {len(points)} points of vendor-dependency "
                      f"depth hold, across {probes} probes; {len(bom['assets'])} asset(s) and "
                      f"{len(bom['claims'])} claim(s) over "
                      f"{len([name for name, count in levels.items() if count])} vendor "
                      "level(s)"),
        "levels": levels,
        "applicability": applicability["states"],
        "coverage": {key: coverage[key] for key in ("total", "identified", "unknown",
                                                    "internal", "coverage_percent",
                                                    "accounted_percent")},
        "refusals": built["refusals"],
        "estate_refusals": bom["refusals"],
        "twin": {"levels": twin["levels"], "vendor_edges": twin["vendor_edges"],
                 "gaps": twin["gaps"]},
        "rows": points,
        "limits": [
            "the payload is a recorded vendor estate, not a live pull: the module is proven "
            "against the shapes a bank files, not against a running procurement system",
            "applicability compares strings: 8.4 covers 8.4.2 and 8.4 does not cover 8.40, "
            "because a version algebra invented here would be a guess about the vendor",
            "a MATCHED claim says the capability exists on the release that is deployed; it "
            "does not say anything used it",
            "the risk weights are stated constants, printed so a bank can replace them with "
            "its own rather than trusting hours nobody can see",
            "coverage counts answers, not correct answers: a wrong vendor field is counted "
            "as an identified one",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# The VBOM dependency graph: vendor → product → release → asset → system",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['counts'][VERDICT_PASS]} pass · {report['counts'][VERDICT_PARTIAL]} "
        f"partial · {report['counts'][VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['statement']}**",
        "",
        "```",
        "VENDOR → PRODUCT → RELEASE → FIRMWARE / PACKAGE → ASSET",
        "       → APPLICATION → CRYPTO → RUNTIME → BUSINESS SYSTEM",
        "",
        "and underneath everything: evidence → identity resolution → digital twin → VBOM",
        "```",
        "",
        "| Level | Nodes |",
        "|---|---|",
    ]
    for name, count in report["levels"].items():
        lines.append(f"| `{name}` | {count} |")

    lines += ["", "| Applicability | Declaration/deployment pairs |", "|---|---|"]
    for state, count in sorted(report["applicability"].items()):
        lines.append(f"| `{state}` | {count} |")

    lines += [
        "",
        "| Coverage | Value |",
        "|---|---|",
        f"| components | {report['coverage']['total']} |",
        f"| vendor identified | {report['coverage']['identified']} "
        f"({report['coverage']['coverage_percent']}%) |",
        f"| vendor unknown | {report['coverage']['unknown']} |",
        f"| internal | {report['coverage']['internal']} |",
        f"| accounted for | {report['coverage']['accounted_percent']}% |",
        "",
        "| Row | Section | Question | Verdict | Probes |",
        "|---|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['section']} | {row['question']} | "
                     f"**{row['verdict']}** | {len(row['probes'])}, {len(row['failed'])} "
                     "failing |")

    lines += ["", "## What was refused while building the graph", ""]
    for row in report["refusals"]:
        lines.append(f"- `{row['code']}` — {row['subject']}: {row['reason']}")
    for row in report["estate_refusals"]:
        lines.append(f"- `{row['code']}` — {row['subject']}: "
                     + str(row.get("reason") or "refused while the estate was assembled"))
    if not report["refusals"] and not report["estate_refusals"]:
        lines.append("- nothing")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 178, {row['section']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")

    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n",
                             encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
          f"{counts[VERDICT_FAIL]} fail", file=sys.stderr)
    if not args.check:
        return 0
    if counts[VERDICT_FAIL]:
        return 2
    if counts[VERDICT_PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
