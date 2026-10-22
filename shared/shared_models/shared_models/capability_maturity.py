"""
Capability maturity — which parts of the product are GA, beta or preview.

The platform ships ~50 services and ~70 console surfaces. They are not equally
proven, and presenting them as if they were is a form of fabricated data. This
module is the single source of truth for the tier of every console surface:

- ``ga``      — the deterministic core: exercised by the full pipeline, broad
                tests, documented, run in the burn-in. Supported for production.
- ``beta``    — real code, real data, real tests, but thinner coverage or a
                narrower deployment history. Usable; expect rough edges; not yet
                a contractual commitment.
- ``preview`` — a working surface over a small engine, or an analysis whose
                inputs the platform does not yet collect at scale. Shown so the
                direction is visible, labelled so nobody mistakes it for GA.

Consumers:

- ``GET /api/v1/platform/capabilities`` (and ``capabilities`` inside
  ``GET /api/v1/platform/scope``)
- ``frontend/src/lib/maturity.ts`` — the console's copy; a test asserts the
  two tables agree, route by route
- ``docs/CAPABILITY-MATURITY.md`` — rendered from these values

Tier changes are product decisions: change them here, with a rationale, and
the console, the API and the doc follow.
"""

from __future__ import annotations

from typing import Any, Literal

Tier = Literal["ga", "beta", "preview"]

TIERS: dict[str, dict[str, str]] = {
    "ga": {
        "label": "GA",
        "detail": "Production-supported. Deterministic core, broad tests, in the burn-in.",
    },
    "beta": {
        "label": "Beta",
        "detail": "Real code and real data; thinner test coverage or short deployment history.",
    },
    "preview": {
        "label": "Preview",
        "detail": "Working surface over a small engine, or analysis over inputs not yet collected at scale.",
    },
}

#: route slug (as in frontend/src/App.tsx) -> tier + why
CAPABILITIES: dict[str, dict[str, str]] = {
    # ── the deterministic core: scan → evidence → normalize → policy → CBOM ──
    "launch-readiness": {"tier": "preview", "area": "Overview", "why": "Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence."},
    "operator-decisions": {"tier": "preview", "area": "Overview", "why": "Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open."},
    "command-center": {"tier": "ga", "area": "Overview", "why": "Reads the live stats/summary endpoints; empty until a scan runs."},
    "scanners": {"tier": "ga", "area": "Discovery", "why": "Source/network/cloud/container/OT scan triggers over the worker pipeline (12 stages, 29 test files)."},
    "live-scanners": {"tier": "ga", "area": "Discovery", "why": "Live scan runner status; same orchestrator as /scanners."},
    "assets": {"tier": "ga", "area": "Discovery", "why": "Unified asset inventory (System/CryptoAsset/Certificate) backed by Alembic-managed tables."},
    "crypto-assets": {"tier": "ga", "area": "Intelligence", "why": "Crypto inventory from the normalized findings table."},
    "crypto": {"tier": "ga", "area": "Intelligence", "why": "Algorithm registry + normalized crypto view (114 normalization tests)."},
    "libraries": {"tier": "ga", "area": "Intelligence", "why": "Library fingerprint database (ADR-007)."},
    "network": {"tier": "ga", "area": "Discovery", "why": "TLS/cipher/cert probes; 15k LOC, 33 test files."},
    "certificates": {"tier": "ga", "area": "Discovery", "why": "Certificate inventory + expiry from network and source scans."},
    "cloud": {"tier": "ga", "area": "Discovery", "why": "Read-only AWS/Azure/GCP estate scan; 15k LOC, 25 test files. Needs credentials to show data."},
    "dev-sec-ops": {"tier": "ga", "area": "Discovery", "why": "SBOM/container/binary/firmware/mobile/WASM scanning, VEX, licence, gates and correlated binary BOM sidecars; bounded evidence and explicit refusal/partial states."},
    "vendor": {"tier": "ga", "area": "Discovery", "why": "68 vendor plugins across 16 categories; 14k LOC, 31 test files."},
    "vendor-due-diligence": {"tier": "preview", "area": "Discovery", "why": "Strict versioned supplier profiles and provenance metadata are implemented; approval completeness and external vendor validation still require customer qualification."},
    "cbom": {"tier": "ga", "area": "Intelligence", "why": "Shared Technology BOM (SBOM/CBOM/HBOM/VBOM), snapshots and signed exports; system CBOMs carry real estate dependency edges (SystemAsset + SystemDependency, both directions) and scan CBOMs carry the scanner's observed cascade (providers, waves); the unified cross-BOM cascade answers 'what breaks if X changes' across code, network, system graph, process, hardware, vendor and library layers over the digital-twin snapshot, with persisted run history, run-to-run diffs across every layer, migration-wave grouping, point-in-time replay over captured twin snapshots, and watched targets that alert when the blast radius changes; the Dependency Graph page manages edges and runs cascades in the UI; binary scans additionally expose static NBOM and vulnerability sidecars through Applications."},
    "live-asset-intelligence": {"tier": "ga", "area": "Intelligence", "why": "The unified BOM console: materialise → version → compare → export."},
    "drift": {"tier": "ga", "area": "Intelligence", "why": "Baseline approval + drift events + CI gate; 15 test files."},
    "findings": {"tier": "ga", "area": "Intelligence", "why": "Policy-evaluated findings with evidence links."},
    "pqc": {"tier": "ga", "area": "Intelligence", "why": "Quantum classification lives in shared_models (176 tests) and runs as a pipeline stage."},
    "security-policy": {"tier": "ga", "area": "Governance", "why": "YAML policy packs (BASELINE/PCI/NIST 131A/CNSA 2.0/FIPS/HIPAA), 82 tests, no AI."},
    "compliance": {"tier": "ga", "area": "Governance", "why": "Requirement-by-requirement reports from policy evidence, 6 templates."},
    "evidence": {"tier": "ga", "area": "Governance", "why": "SHA-256 content/chain/manifest hashes, audit packs, verify endpoint."},
    "reports": {"tier": "ga", "area": "Output", "why": "JSON/HTML/PDF reports and schedules over the evidence chain."},
    "live-stream": {"tier": "ga", "area": "Overview", "why": "SSE event stream with Last-Event-ID resume and Redis federation."},
    "alerts": {"tier": "ga", "area": "Overview", "why": "Alert stage output + monitor events."},
    "system-health": {"tier": "ga", "area": "Administration", "why": "/health, /readyz, /metrics, DB health."},
    "settings": {"tier": "ga", "area": "Administration", "why": "App settings + org profile persisted in app_settings."},
    "identity": {"tier": "ga", "area": "Administration", "why": "Users, roles, MFA, OIDC/SAML/LDAP, API keys, lockout, audit chain."},
    "admin": {"tier": "ga", "area": "Administration", "why": "Admin user management and audit trail."},
    "security-center": {"tier": "ga", "area": "Administration", "why": "Security posture of the platform itself (headers, rate limits, audit chain verify)."},
    "integrations": {"tier": "ga", "area": "Administration", "why": "GitHub webhooks, CI gate, SMTP, ITSM/SIEM connectors (burn-in covers them)."},
    "scope": {"tier": "ga", "area": "Administration", "why": "Platform scope self-description (platform_scope.py) — what we do and refuse to do."},
    "search-results": {"tier": "ga", "area": "Overview", "why": "Cross-inventory search."},
    "login": {"tier": "ga", "area": "Auth", "why": "Password + MFA + SSO login."},
    "register": {"tier": "beta", "area": "Auth", "why": "Self-service signup is for the multi-tenant SaaS mode (migration 0057), which is beta."},
    "reset-password": {"tier": "ga", "area": "Auth", "why": "Token-based reset with SMTP delivery."},
    "invite-accept": {"tier": "beta", "area": "Auth", "why": "Tenant invitations belong to the SaaS mode (beta)."},

    # ── beta: real, tested, thinner ──
    "hardware": {"tier": "beta", "area": "Discovery", "why": "HSM/TPM/firmware plugins exist (ADR-014); live hardware collection needs vendor access and has a short field history."},
    "hbom": {"tier": "beta", "area": "Intelligence", "why": "Hardware BOM view over the Technology BOM; depends on hardware scan coverage."},
    "nbom": {"tier": "preview", "area": "Intelligence", "why": "Network BOM from authorized network evidence plus static binary capability candidates. Binary-derived records are marked `observed: false` and do not prove a live listener; corroboration requires a separately authorized network probe."},
    "graph": {"tier": "beta", "area": "Intelligence", "why": "Neo4j dependency graph is optional at runtime (in-process engine is the fallback and the tenant-isolated path); 3.2k+ LOC. Edge management API with provenance (source/created_by/confidence/last_verified), discovered-edge adoption (scanner cascade + graph snapshots → operator approval), declared crypto↔hardware and vendor-of-vendor linkage, and asset-level blast radius (shared asset → union over every using system) are live with tenant-scoped tests; scale evidence on real Neo4j estates is still open."},
    "dependency-graph": {"tier": "beta", "area": "Intelligence", "why": "Same graph engine as /graph."},
    "agility": {"tier": "beta", "area": "Intelligence", "why": "Crypto-agility scoring; 900 LOC, 37 tests; scoring model still being calibrated."},
    "crypto-changes": {"tier": "beta", "area": "Intelligence", "why": "Change timeline from drift + scan history."},
    "banking-regulatory": {"tier": "beta", "area": "Governance", "why": "Banking/SWIFT CSP mapping over the policy engine; regulator-specific packs still growing."},
    "governance": {"tier": "beta", "area": "Governance", "why": "Access reviews, exceptions, sign-off; 1.9k LOC, 4 test files."},
    "telecom": {"tier": "beta", "area": "Discovery", "why": "5G NF TLS/cert posture; 1.5k LOC with 24 tests; ran against lab targets only."},
    "runtime": {"tier": "beta", "area": "Discovery", "why": "Host agent findings; agent rollout is per-deployment."},
    "live-environment": {"tier": "beta", "area": "Discovery", "why": "Live environment roll-up of runtime + network."},
    "crypto-assurance": {"tier": "beta", "area": "Governance", "why": "KeyAssure checks; 1.7k LOC but a single test module."},
    "migration": {"tier": "beta", "area": "Intelligence", "why": "Scan → project → tasks → velocity forecast; forecast model is simple."},
    "automation": {"tier": "beta", "area": "Administration", "why": "Playbooks + ITSM/SIEM delivery; 2.3k LOC, 6 test files."},
    "onboarding": {"tier": "beta", "area": "Administration", "why": "Org/connector onboarding flow for SaaS mode."},
    "organization": {"tier": "beta", "area": "Administration", "why": "Org structure + business context seed."},
    "tenancy": {"tier": "beta", "area": "Administration", "why": "Multi-tenant core landed in migration 0057; artifact tenancy sealed at rest; single-tenant is GA."},
    "cmdb": {"tier": "beta", "area": "Discovery", "why": "CMDB import/resolution; ServiceNow mapping is field-tested with one schema."},
    "catalog": {"tier": "beta", "area": "Discovery", "why": "Hardware/vendor catalog browse."},
    "priorities": {"tier": "beta", "area": "Intelligence", "why": "Deterministic prioritisation over findings + business context."},
    "remediation": {"tier": "beta", "area": "Intelligence", "why": "Owned task lifecycle with machine verification against rescan evidence; new surface over the full task API."},
    "risk": {"tier": "beta", "area": "Intelligence", "why": "Risk roll-up; weights documented but not yet regulator-validated."},
    "executive": {"tier": "beta", "area": "Overview", "why": "Executive summary over the same stats; presentation layer."},
    "notifications": {"tier": "beta", "area": "Administration", "why": "In-app notifications + SMTP; channels beyond email are connectors."},
    "sectors": {"tier": "beta", "area": "Governance", "why": "Sector profiles (bank/telecom/energy) select policy packs; 900 LOC."},
    "protocols": {"tier": "beta", "area": "Intelligence", "why": "Protocol posture view from network scans."},
    "resilience": {"tier": "beta", "area": "Administration", "why": "Backup/DR/air-gap status; scripts are tested, the page is new."},
    "security": {"tier": "beta", "area": "Administration", "why": "Security settings surface; overlaps security-center."},
    "role-dashboard": {"tier": "beta", "area": "Overview", "why": "Per-role landing view."},
    "digital-twin": {"tier": "beta", "area": "Intelligence", "why": "Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations."},

    # ── preview: shown for direction, labelled so it is not mistaken for GA ──
    "what-if": {"tier": "preview", "area": "Intelligence", "why": "Scenario simulation over the inventory; scenarios are fixed templates today."},
    "pqc-map": {"tier": "preview", "area": "Intelligence", "why": "Geographic/estate PQC map; needs location context the scanners do not collect yet."},
    "trust": {"tier": "preview", "area": "Governance", "why": "Trust-score surface; scoring inputs still being defined."},
    "accuracy": {"tier": "preview", "area": "Overview", "why": "Detector precision/recall panel; needs labelled ground truth per estate."},
    "supervision": {"tier": "preview", "area": "Governance", "why": "Supervisory-review view for regulators; a read model over evidence, early."},
    "timeline": {"tier": "preview", "area": "Overview", "why": "Estate timeline; aggregates several beta sources."},
    "security-intelligence": {"tier": "preview", "area": "Intelligence", "why": "Cross-scanner identity resolution + profiles; roadmap in SECURITY-INTELLIGENCE-ROADMAP.md."},
    "platform-p2": {"tier": "preview", "area": "Administration", "why": "Phase-2 platform features behind one page (marketplace, datalake, anomaly) — each < 700 LOC."},
}

#: sidebar entries that used to point at routes that do not exist. Kept as a
#: deny-list so a test can make sure they never come back as nav links.
RETIRED_NAV_ROUTES: tuple[str, ...] = (
    "activity", "audit-merkle", "cryptographic-digital-twin", "devsecops",
    "hsm-fleet-orchestrator", "pqc-code-signing-orchestrator", "quantum-entropy-fabric",
    "realtime-system", "telecom-signaling-analyzer", "twin-analysis-output",
    "zero-trust-crypto-enforcer",
)


def tier_of(route: str) -> Tier:
    """The tier for a console route slug; unknown surfaces are ``preview``.

    Unknown defaults *down*, never up: a route nobody classified is by
    definition not something we have decided to support.
    """
    slug = route.strip("/").split("/")[0].split("?")[0]
    entry = CAPABILITIES.get(slug)
    return entry["tier"] if entry else "preview"  # type: ignore[return-value]


def counts() -> dict[str, int]:
    out = {tier: 0 for tier in TIERS}
    for entry in CAPABILITIES.values():
        out[entry["tier"]] += 1
    return out


def capability_manifest() -> dict[str, Any]:
    """The versioned table served by the API and rendered into the doc."""
    return {
        "schema_version": 1,
        "tiers": TIERS,
        "counts": counts(),
        "capabilities": [
            {"route": f"/{slug}", **entry} for slug, entry in sorted(CAPABILITIES.items())
        ],
        "retired_nav_routes": [f"/{slug}" for slug in RETIRED_NAV_ROUTES],
        "default_for_unknown": "preview",
    }


__all__ = [
    "CAPABILITIES", "RETIRED_NAV_ROUTES", "TIERS", "Tier",
    "capability_manifest", "counts", "tier_of",
]
