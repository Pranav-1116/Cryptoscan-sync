"""
Capability maturity — the support status of every console surface.

The product ships ~50 services and ~85 console surfaces. Shipping them all as
supported does not mean they all do the same amount: a read-only surface that
states what it cannot do is a supported surface, and calling it "beta" told the
operator less than the sentence it replaced. So the tier is now a support
statement — every routed surface is ``ga`` — and the limitation lives in
``why``, which is shown next to the surface on ``/scope`` and in
``docs/CAPABILITY-MATURITY.md``.

- ``ga``      — shipped and supported. Any limit is stated with the surface.
- ``beta``    — reserved: a surface under a stated limited deployment. No
                shipped surface uses it.
- ``preview`` — what an *unclassified* route resolves to. Unknown routes
                default down, never up: a route nobody wrote a rationale for is
                not something we have decided to support.

Consumers:

- ``GET /api/v1/platform/capabilities`` (and ``capabilities`` inside
  ``GET /api/v1/platform/scope``)
- ``frontend/src/lib/maturity.ts`` — the console's copy; a test asserts the
  two tables agree, route by route
- ``docs/CAPABILITY-MATURITY.md`` — rendered from these values

Limitations are part of the surface, not of the navigation: the sidebar no
longer labels pages, because a product's navigation is not the place to
negotiate what is proven. The record itself is kept, and it is the same record
the API serves.
"""

from __future__ import annotations

from typing import Any, Literal

Tier = Literal["ga", "beta", "preview"]

TIERS: dict[str, dict[str, str]] = {
    "ga": {
        "label": "Supported",
        "detail": "Shipped and supported. Any limit is stated with the surface, not in the navigation.",
    },
    "beta": {
        "label": "Limited deployment",
        "detail": "Reserved for a surface under a stated limited deployment. No shipped surface uses it.",
    },
    "preview": {
        "label": "Unclassified",
        "detail": "What a route with no rationale resolves to. Unknown routes default down, never to supported.",
    },
}

#: route slug (as in frontend/src/App.tsx) -> tier + why
CAPABILITIES: dict[str, dict[str, str]] = {
    # ── the deterministic core: scan → evidence → normalize → policy → CBOM ──
    "launch-readiness": {"tier": "ga", "area": "Overview", "why": "Gated independent-report, operational-duty and bounded-pilot records; real assessor execution, site exercises and customer acceptance require external evidence."},
    "operator-decisions": {"tier": "ga", "area": "Overview", "why": "Exact-estate decision and condition-proof workflow; local workloads tested, site capacity and deployment acceptance remain open."},
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
    "vendor-due-diligence": {"tier": "ga", "area": "Discovery", "why": "Strict versioned supplier profiles and provenance metadata are implemented; approval completeness and external vendor validation still require customer qualification."},
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
    "register": {"tier": "ga", "area": "Auth", "why": "Self-service signup is for the multi-tenant SaaS mode (migration 0057), which is beta."},
    "reset-password": {"tier": "ga", "area": "Auth", "why": "Token-based reset with SMTP delivery."},
    "invite-accept": {"tier": "ga", "area": "Auth", "why": "Tenant invitations belong to the SaaS mode (beta)."},

    # ── surfaces whose limits are easy to over-read: the why says what each does not do ──
    "hardware": {"tier": "ga", "area": "Discovery", "why": "HSM/TPM/firmware plugins exist (ADR-014); live hardware collection needs vendor access and has a short field history."},
    "hbom": {"tier": "ga", "area": "Intelligence", "why": "Hardware BOM view over the Technology BOM; depends on hardware scan coverage."},
    "nbom": {"tier": "ga", "area": "Intelligence", "why": "Network BOM from authorized network evidence plus static binary capability candidates. Binary-derived records are marked `observed: false` and do not prove a live listener; corroboration requires a separately authorized network probe."},
    "graph": {"tier": "ga", "area": "Intelligence", "why": "Neo4j dependency graph is optional at runtime (in-process engine is the fallback and the tenant-isolated path); 3.2k+ LOC. Edge management API with provenance (source/created_by/confidence/last_verified), discovered-edge adoption (scanner cascade + graph snapshots → operator approval), declared crypto↔hardware and vendor-of-vendor linkage, and asset-level blast radius (shared asset → union over every using system) are live with tenant-scoped tests; scale evidence on real Neo4j estates is still open."},
    "dependency-graph": {"tier": "ga", "area": "Intelligence", "why": "Same graph engine as /graph."},
    "agility": {"tier": "ga", "area": "Intelligence", "why": "Crypto-agility scoring; 900 LOC, 37 tests; scoring model still being calibrated."},
    "crypto-changes": {"tier": "ga", "area": "Intelligence", "why": "Change timeline from drift + scan history."},
    "banking-regulatory": {"tier": "ga", "area": "Governance", "why": "Banking/SWIFT CSP mapping over the policy engine; regulator-specific packs still growing."},
    "governance": {"tier": "ga", "area": "Governance", "why": "Access reviews, exceptions, sign-off; 1.9k LOC, 4 test files."},
    "telecom": {"tier": "ga", "area": "Discovery", "why": "5G NF TLS/cert posture; 1.5k LOC with 24 tests; ran against lab targets only."},
    "runtime": {"tier": "ga", "area": "Discovery", "why": "Host agent findings; agent rollout is per-deployment."},
    "live-environment": {"tier": "ga", "area": "Discovery", "why": "Live environment roll-up of runtime + network."},
    "crypto-assurance": {"tier": "ga", "area": "Governance", "why": "KeyAssure checks; 1.7k LOC but a single test module."},
    "migration": {"tier": "ga", "area": "Intelligence", "why": "Scan → project → tasks → velocity forecast; forecast model is simple."},
    "automation": {"tier": "ga", "area": "Administration", "why": "Playbooks + ITSM/SIEM delivery; 2.3k LOC, 6 test files."},
    "onboarding": {"tier": "ga", "area": "Administration", "why": "Org/connector onboarding flow for SaaS mode."},
    "organization": {"tier": "ga", "area": "Administration", "why": "Org structure + business context seed."},
    "tenancy": {"tier": "ga", "area": "Administration", "why": "Multi-tenant core landed in migration 0057; artifact tenancy sealed at rest; single-tenant is GA."},
    "cmdb": {"tier": "ga", "area": "Discovery", "why": "CMDB import/resolution; ServiceNow mapping is field-tested with one schema."},
    "catalog": {"tier": "ga", "area": "Discovery", "why": "Hardware/vendor catalog browse."},
    "priorities": {"tier": "ga", "area": "Intelligence", "why": "Deterministic prioritisation over findings + business context."},
    "remediation": {"tier": "ga", "area": "Intelligence", "why": "Owned task lifecycle with machine verification against rescan evidence; new surface over the full task API."},
    "risk": {"tier": "ga", "area": "Intelligence", "why": "Risk roll-up; weights documented but not yet regulator-validated."},
    "executive": {"tier": "ga", "area": "Overview", "why": "Executive summary over the same stats; presentation layer."},
    "notifications": {"tier": "ga", "area": "Administration", "why": "In-app notifications + SMTP; channels beyond email are connectors."},
    "sectors": {"tier": "ga", "area": "Governance", "why": "Sector profiles (bank/telecom/energy) select policy packs; 900 LOC."},
    "protocols": {"tier": "ga", "area": "Intelligence", "why": "Protocol posture view from network scans."},
    "resilience": {"tier": "ga", "area": "Administration", "why": "Backup/DR/air-gap status; scripts are tested, the page is new."},
    "security": {"tier": "ga", "area": "Administration", "why": "Security settings surface; overlaps security-center."},
    "role-dashboard": {"tier": "ga", "area": "Overview", "why": "Per-role landing view."},
    "digital-twin": {"tier": "ga", "area": "Intelligence", "why": "Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations."},


    # Newly routed surfaces keep their measured gap in the why, where an operator reads it.
    "assurance-coverage": {"tier": "ga", "area": "Governance", "why": "A source register can be declared and read, but observation and revision writes still lack a console workflow; registration is not coverage."},
    "assurance-qualification": {"tier": "ga", "area": "Governance", "why": "Read-only qualification views exist; supplier and adapter approval writes require separate operator workflows."},
    "assurance-records": {"tier": "ga", "area": "Governance", "why": "Reads immutable assurance revisions, but does not originate or independently approve them."},
    "assurance-sampling": {"tier": "ga", "area": "Governance", "why": "Shows frozen predictions without a score; domain-owner sampling review is not submitted from this page."},
    "assurance-trace": {"tier": "ga", "area": "Governance", "why": "Displays retained relationship evidence and unresolved links, not a verified runtime call graph."},
    "live-monitor": {"tier": "ga", "area": "Overview", "why": "Reads actual daemon and estate streams; a live daemon with no enabled schedule does not provide collection coverage."},
    "sbom": {"tier": "ga", "area": "Intelligence", "why": "A versioned software projection over available evidence; deployments and missing component versions remain unproven."},
    "vbom": {"tier": "ga", "area": "Intelligence", "why": "A supplier projection from retained evidence and declarations, not independent supplier validation."},

    # ── heuristic or directional surfaces: supported, with the model stated ──
    "what-if": {"tier": "ga", "area": "Intelligence", "why": "Scenario simulation over the inventory; scenarios are fixed templates today."},
    "pqc-map": {"tier": "ga", "area": "Intelligence", "why": "Geographic/estate PQC map; needs location context the scanners do not collect yet."},
    "trust": {"tier": "ga", "area": "Governance", "why": "Trust-score surface; scoring inputs still being defined."},
    "accuracy": {"tier": "ga", "area": "Overview", "why": "Detector precision/recall panel; needs labelled ground truth per estate."},
    "supervision": {"tier": "ga", "area": "Governance", "why": "Supervisory-review view for regulators; a read model over evidence, early."},
    "timeline": {"tier": "ga", "area": "Overview", "why": "Estate timeline; aggregates several beta sources."},
    "security-intelligence": {"tier": "ga", "area": "Intelligence", "why": "Cross-scanner identity resolution + profiles; roadmap in SECURITY-INTELLIGENCE-ROADMAP.md."},
    "platform-p2": {"tier": "ga", "area": "Administration", "why": "Phase-2 platform features behind one page (marketplace, datalake, anomaly) — each < 700 LOC."},
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
    """The support tier for a console route slug; unknown routes are ``preview``.

    Every shipped surface is ``ga``. Unknown defaults *down*, never up: a route
    nobody wrote a rationale for is by definition not something we have decided
    to support.
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
