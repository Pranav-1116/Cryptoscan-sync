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
    "collector-depth": {"tier": "ga", "area": "Discovery", "why": "Four measured matrices compiled from the collectors present in this build: runtime observation depth per family (one family reaches call-level; installed is never reported as executed), network protocol readers per protocol (TLS/database handshakes, SSH/IPsec offers, and the protocols with no reader at all listed as absent), Windows layer-by-layer reach with the server's own NO on whether it is a complete Windows collector, and the depth of each of the six BOM projections on the stored snapshot. A fifth tab prints the maturity register: eight areas and ~46 surfaces, each carrying a readiness (OPERATIONAL, CANDIDATE or FOUNDATION) beside its coverage state, the collector behind it, the work still missing and the route that proves it, plus the claims the product may and may not make and the five capabilities it does not present as operational. A sixth tab prints the simulation boundary: the ten enterprise scenarios an engine is asked for, with EXISTS/PARTIAL/ABSENT, the scenario ids that implement each row, and what each cannot compute. Every number is echoed from the API; no percentage or score is computed anywhere."},
    "estate-twin": {"tier": "ga", "area": "Intelligence", "why": "Walks the twin's own chain over one stored snapshot: estate, assets, relationships, crypto graph, evidence graph, history, impact and simulation. Each link reports POPULATED, EMPTY, NOT_EVALUATED or AWAITING_INPUT as the server measured it, and a link the server could not read is never drawn as empty; it needs a stored discovery run and computes no score of its own."},
    "twin-walkthrough": {"tier": "ga", "area": "Intelligence", "why": "The specification's thirteen investigations on one canvas: pick an asset, then step through coverage, identity, relationships, crypto facts, network, hardware/HSM, vendors, evidence records, observation dates, drift, blast radius, the facts a scenario would read and PQC exposure. Every step reads the twin the full screen reads, a failed read is printed as a failed read rather than a zero, and nothing is written or simulated from the canvas. The network step also carries the protocol floor: pick SSLv3 through TLSv1.3 and it reports which observed handshakes negotiated below it, which protocol values this build cannot rank and which assets carry no handshake evidence — the last two published as findings, never as compliance — beside a separate DECLARED axis (what TLS configuration files allow, read from stored host snapshot imports by the HOST plane): which configurations still permit a protocol below the floor, which top out below it and the edges that would strand (an empty edge list reads \u201cnothing recorded on either side of it\u201d, not \u201cnothing would break\u201d), which declare a version this build cannot rank, and which were only partly parsed. The blind spots it cannot see lead with runtime client acceptance. The PQC step also carries the declared population: the bank supplies its own counts per asset class and the estate is measured against them, so a class with no declared count prints no percentage at all, finding more than was declared is a disagreement rather than coverage above 100%, and a declared class the estate cannot see is a collection gap rather than an empty estate; beside it the six claim types (asset presence, relationship, algorithm use, key size, certificate, ownership) are measured separately, with a claim the estate does not hold reported as missing from the estate rather than proven absent, and precision explicitly not reported."},
    "drift": {"tier": "ga", "area": "Intelligence", "why": "Baseline approval + drift events + CI gate; 15 test files."},
    "findings": {"tier": "ga", "area": "Intelligence", "why": "Policy-evaluated findings with evidence links."},
    "pqc": {"tier": "ga", "area": "Intelligence", "why": "Quantum classification lives in shared_models (176 tests) and runs as a pipeline stage."},
    "security-policy": {"tier": "ga", "area": "Governance", "why": "YAML policy packs (BASELINE/PCI/NIST 131A/CNSA 2.0/FIPS/HIPAA), 82 tests, no AI."},
    "compliance": {"tier": "ga", "area": "Governance", "why": "Requirement-by-requirement reports from policy evidence, 6 templates."},
    "audit": {"tier": "ga", "area": "Governance", "why": "Who did what, when: the hash-chained audit trail with its chain verdict, filterable by actor and action."},
    "evidence": {"tier": "ga", "area": "Governance", "why": "SHA-256 content/chain/manifest hashes, audit packs, verify endpoint."},
    "reports": {"tier": "ga", "area": "Output", "why": "JSON/HTML/PDF reports and schedules over the evidence chain."},
    "live": {"tier": "ga", "area": "Overview", "why": "Connection age, stored changes, six BOM downloads and correlated attack patterns. A quiet estate and a stopped agent look identical, so the age is stated; level 3 (incident) is never assigned by the platform, and a pattern reports which collectors corroborate it without raising its level."},
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
    "digital-twin": {"tier": "ga", "area": "Intelligence", "why": "Estate replica with measured fidelity, evidence reconciliation and ten deterministic scenario types, fed by live state, wire scans, the dependency graph and the hardware fleet; scenario models are heuristic projections, not vendor simulations. Simulation is scenario-specific: the PQC migration foundation is real, the generic enterprise engine is not implemented, and the scenario-models read states which of the ten scenarios compute and what each cannot see."},


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
    "what-if": {"tier": "ga", "area": "Intelligence", "why": "Scenario simulation over the inventory; scenarios are fixed templates today, and a question that is not one of them is answered as not modelled rather than approximated."},
    "simulation": {"tier": "ga", "area": "Intelligence", "why": "What-if workspace over the estate twin with two families and thirteen question kinds: seven built-in scenarios that edit an evidence fact on a copy (replace, retire, disable a protocol, upgrade, remove a component, resize a key, replace everything Shor-vulnerable), a custom scenario authored as a bounded expression, a COMPOSITE sequence of up to five of those applied in order to one copy (a step may name a stored twin snapshot with as_of, so a plan written against Q2 evidence is judged on Q2's evidence while its change lands on today's estate — a record that has since left the estate is counted, never resurrected, and a date is refused because a date is not evidence), and four cascades that walk a failure outward from seeds (asset unavailable, crypto compromise, algorithm breaks everywhere, a CA or PKI issuer compromised), each previewed before it runs so nothing is read as a finding before it is known to reach something, each re-projecting or explicitly not re-projecting the six BOMs, each reporting the live projection id unchanged, and each stored quarantined against the evidence state it was computed from; scenarios change evidence facts and cascades travel established edges only — neither models configuration, traffic, redundancy, approvals or a deployment plan. This is not a generic enterprise simulation engine: nine of the ten registered scenarios model only part of the mechanism and each says which part it cannot see."},
    "pqc-map": {"tier": "ga", "area": "Intelligence", "why": "Geographic/estate PQC map; needs location context the scanners do not collect yet."},
    "trust": {"tier": "ga", "area": "Governance", "why": "Trust-score surface; scoring inputs still being defined."},
    "accuracy": {"tier": "ga", "area": "Overview", "why": "Detector precision/recall panel; needs labelled ground truth per estate."},
    "supervision": {"tier": "ga", "area": "Governance", "why": "Supervisory-review view for regulators; a read model over evidence, early."},
    "timeline": {"tier": "ga", "area": "Overview", "why": "Estate timeline; aggregates several beta sources."},
    "security-intelligence": {"tier": "ga", "area": "Intelligence", "why": "Cross-scanner identity resolution + profiles; roadmap in SECURITY-INTELLIGENCE-ROADMAP.md."},
    "platform-p2": {"tier": "ga", "area": "Administration", "why": "Phase-2 platform features behind one page (marketplace, datalake, anomaly) — each < 700 LOC."},
    "security-controls": {"tier": "ga", "area": "Governance", "why": "Read-only inventory of the bank's own controls (firewall/IDS/WAF/HSM/KMS/PKI, 13 types): it records what each control enforces and exports findings; it is not a firewall, an IPS or a rate limiter, and a spec that would mutate a control is refused at registration."},
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
