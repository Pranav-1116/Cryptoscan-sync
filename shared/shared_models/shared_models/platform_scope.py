"""
Platform scope — single source of truth for what CryptoScan is (and is not).

This is a *product* decision set, not a technical limitation list. It exists
so that every surface that describes the platform (docs, API, tests) reads
the same boundaries: what we scan, how we may access it, what we never do,
and what we never look at. Consumers:

- ``GET /api/v1/platform/scope`` (services/api router)
- ``shared_models.tests.test_platform_scope`` (boundary enforcement tests)
- docs/architecture/platform-boundaries.md (rendered from these values)

The compliance-friendly core property: **we inspect key *metadata*, never
key material** — everything is read-only and every observation is
evidence-chained, so a bank can deploy this next to its crypto estate.
"""

from __future__ import annotations

from typing import Any

PLATFORM_NAME = "CryptoScan"

# ── What the platform IS ────────────────────────────────────────────────

MISSION = (
    "End-to-end cryptographic inventory and security-configuration posture "
    "for regulated estates (banks, healthcare, energy) and cloud platforms "
    "(AWS/Azure/GCP): deterministic scanners, hashed evidence chains, YAML "
    "policy, drift detection, CBOM/graph, PQC readiness and remediation."
)

COVERED_AREAS: list[dict[str, Any]] = [
    {
        "id": "zos-crypto-discovery",
        "label": "z/OS mainframe crypto discovery",
        "detail": "Ingest of operator-produced z/OS security extracts — RACF "
                  "RACDCERT LIST, ICSF key inventories, DB2 TLS configuration, "
                  "CICS TCPIPSERVICE definitions — into the unified crypto "
                  "inventory. Crypto inventory only; we do not scan or parse "
                  "COBOL application code.",
    },
    {
        "id": "source-tree-crypto",
        "label": "Source-tree crypto inventory",
        "detail": "Deterministic detection of cryptographic API usage "
                  "(algorithms, modes, key sizes, hardcoded keys) across "
                  "Java/C#/Go/Python/JS/etc. Crypto-only — not general SAST.",
    },
    {
        "id": "network-tls",
        "label": "Network & TLS posture",
        "detail": "Passive TLS handshake inventory, certificate posture and "
                  "expiry, weak protocol detection, DNSSEC/IPsec targets.",
    },
    {
        "id": "containers-iac",
        "label": "Containers & IaC",
        "detail": "Image layer analysis, package/manifest parsing, embedded "
                  "JARs and shared libraries, Dockerfile/IaC crypto config.",
    },
    {
        "id": "cloud-tenants",
        "label": "Cloud accounts & tenants (AWS/Azure/GCP)",
        "detail": "Read-only discovery of crypto assets inside the accounts "
                  "and tenants the operator has access to. Never 'scan the "
                  "cloud company' — only what the credentials can see.",
    },
    {
        "id": "ot-ics",
        "label": "OT/ICS passive monitoring",
        "detail": "Passive protocol inventory (OPC-UA/DNP3/Modbus/IEC 61850) "
                  "with a verified zero-packet promise to OT networks.",
    },
    {
        "id": "payment-hsm",
        "label": "Payment HSM / PCI (bank gap)",
        "detail": "HSM key inventory with ceremony provenance, TR-31 parsing, "
                  "audit-trail ingestion; PAY policy rules; key *metadata* "
                  "only — never key material.",
    },
    {
        "id": "vendor-supply-chain",
        "label": "Vendor & supply-chain crypto",
        "detail": "Vendor crypto discovery (API scan, CBOM import, "
                  "questionnaire, public posture) with 0-100 risk scores.",
    },
    {
        "id": "certs-pqc",
        "label": "Certificates & PQC readiness",
        "detail": "Certificate fingerprint inventory, quantum risk analysis "
                  "(Shor/Grover, HNDL, Mosca deadlines) and evidence-supported "
                  "PQC migration readiness — never asserted without evidence.",
    },
    {
        "id": "shared-layers",
        "label": "Shared layers",
        "detail": "Evidence chain, normalization (IANA/CBOM/SPDX), "
                  "deterministic policy, drift/gates, graph, remediation, "
                  "compliance reporting, live monitoring.",
    },
]

# ── What the platform is NOT (honest boundaries) ────────────────────────

NON_GOALS: list[dict[str, Any]] = [
    {
        "id": "no-general-sast",
        "label": "General application SAST / source-code hacking",
        "detail": "We do not hunt arbitrary application vulnerabilities "
                  "(SQLi, XSS, buffer overflows, auth flaws) in source code. "
                  "We inventory crypto usage and security configuration only.",
    },
    {
        "id": "no-malware",
        "label": "Malware analysis / detection",
        "detail": "We identify crypto *libraries and configurations* inside "
                  "binaries and containers; we do not analyze malware or "
                  "malicious behavior.",
    },
    {
        "id": "no-siem-analytics",
        "label": "SIEM behavior analytics",
        "detail": "We emit findings to SIEM/CEF as an outbound alert sink, "
                  "but we do not perform behavior analytics, correlation "
                  "hunting, or endpoint telemetry analysis.",
    },
    {
        "id": "no-cobol-app-scanning",
        "label": "COBOL / PL-I application-code scanning",
        "detail": "z/OS coverage is crypto-configuration inventory via "
                  "operator-produced extracts (RACF/ICSF/DB2/CICS); we do not "
                  "parse COBOL/PL-I application source.",
    },
    {
        "id": "no-endpoint-agents",
        "label": "Employee endpoint scanning",
        "detail": "We do not install agents on or scan employee workstations/endpoints.",
    },
    {
        "id": "no-company-wide-cloud",
        "label": "'Scan the whole cloud company'",
        "detail": "Only the accounts/tenants the operator has credentials for. "
                  "External surface is covered only via public internet "
                  "scanning of configured targets.",
    },
]

# ── Access model ────────────────────────────────────────────────────────

ACCESS_MODEL: dict[str, Any] = {
    "read_only": True,
    "scope": (
        "We connect with the operator's credentials to exactly the accounts, "
        "tenants, repos, registries and hosts they configure. Nothing is "
        "discovered beyond those boundaries; cloud inventory is the "
        "credential-visible surface, not the whole provider."
    ),
    "external_surface": (
        "Public internet scanning only for explicitly configured targets "
        "(hostnames/IP ranges). No scanning of the provider's infrastructure "
        "or other tenants."
    ),
}

# ── Invariants (tested) ─────────────────────────────────────────────────

INVARIANTS: list[dict[str, Any]] = [
    {
        "id": "read-only-collection",
        "label": "Read-only collection",
        "detail": "Every collector (source, network, container, cloud, OT, "
                  "HSM, vendor) only reads. OT scanning sends zero packets "
                  "to OT networks; nothing is modified, written or deployed.",
    },
    {
        "id": "evidence-chained",
        "label": "Evidence-chained observations",
        "detail": "Every finding carries content/chain hashes; packs and "
                  "transfers are digest-verified and tamper-evident.",
    },
    {
        "id": "metadata-only",
        "label": "Key material is never retrieved",
        "detail": "We inspect key *metadata* (algorithm, key size, purpose, "
                  "rotation, ceremony provenance) — never private keys, "
                  "secret values, key material or ciphertext-equivalent "
                  "secrets. Evidence packs use a strict field whitelist.",
    },
    {
        "id": "deterministic-policy",
        "label": "Policy is never decided by AI",
        "detail": "Rules are versioned YAML (NIST/FIPS/NSA/PCI-DSS/HIPAA/ISO); "
                  "evaluations are deterministic and auditable.",
    },
    {
        "id": "honest-status",
        "label": "Honest status, never faked",
        "detail": "Untestable or unscannable targets are reported BLOCKED / "
                  "NOT_EVALUATED — never guessed, never assumed PASS.",
    },
]

# ── Enforcement markers (used by tests; keep in sync with NON_GOALS) ────

# Banned module-path tokens: any python file under services/ or shared/
# whose path contains one of these is out of scope by construction.
BANNED_PATH_TOKENS: tuple[str, ...] = (
    "as400",
    "as_400",
    "cobol",
    "malware",
    "endpoint_agent",
    "endpoint_agents",
)

# Banned declaration phrases: a module docstring claiming one of these
# capabilities is out of scope.
BANNED_DOC_PHRASES: tuple[str, ...] = (
    "malware",
    "behavior analytics",
    "behavioral analytics",
    "endpoint agent",
    "cobol",
    "source-code hacking",
)

# Forbidden evidence fields: names that would carry key material / secret
# values must never appear in shared finding/evidence models or pack output.
FORBIDDEN_EVIDENCE_FIELDS: tuple[str, ...] = (
    "private_key",
    "privatekey",
    "secret_value",
    "key_material",
    "key_value",
    "raw_key",
    "key_bytes",
    "passphrase",
    "seed_phrase",
)


def scope_manifest() -> dict[str, Any]:
    """The complete, versioned scope statement served by the API and docs."""
    return {
        "platform": PLATFORM_NAME,
        "mission": MISSION,
        "covered_areas": COVERED_AREAS,
        "non_goals": NON_GOALS,
        "access_model": ACCESS_MODEL,
        "invariants": INVARIANTS,
        "capabilities": _capabilities(),
        "schema_version": 2,
    }


def _capabilities() -> dict[str, Any]:
    """GA / beta / preview tier of every console surface (capability_maturity)."""
    from shared_models.capability_maturity import capability_manifest

    return capability_manifest()
