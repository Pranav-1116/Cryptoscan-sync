#!/usr/bin/env python3
"""Explanatory posters 22-31 for docs/product — the platform engines behind the pages.

Companion to gen_docs_posters.py (10-21). Same helpers, same rule: every number
on an image is checked against the repository.

    python scripts/gen_docs_posters2.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_docs_posters import C, EDGE, MUTED, TXT, arrow, box, canvas, panel, save  # noqa: E402


def flow(ax, y, items, x0=0.4, gap=0.18, h=0.9, fs=8.2, tfs=None, width=15.2):
    """A left-to-right chain of boxes with arrows. items: (title, body, colour)."""
    n = len(items)
    w = (width - gap * (n - 1)) / n
    for i, it in enumerate(items):
        t, b, fc = (it + (C["panel"],))[:3]
        x = x0 + i * (w + gap)
        box(ax, x, y, w, h, t, b, fc=fc, fs=fs, tfs=tfs or fs + 0.8)
        if i < n - 1:
            arrow(ax, x + w, y + h / 2, x + w + gap, y + h / 2, lw=1.2)
    return w


# ---------------------------------------------------------------- 22. scan gate + orchestrator
def p_scan_gate():
    fig, ax = canvas(11.2, "Starting a scan safely — the unified scanner gate and the orchestrator",
                     "privacy/gate.py (fail-closed, pure) · control_plane/orchestrator.py (priority, leases, emergency stop) · privacy/ratelimit.py (four budget layers).")
    ax.text(0.4, 9.75, "Every scan request passes this chain, in order — any failure = DENY + audit record", fontsize=10, fontweight="bold", color=TXT)
    flow(ax, 8.55, [
        ("WHO", "authenticated\nprincipal", C["api"]), ("TENANT", "resolved,\nnot suspended", C["api"]),
        ("AUTHORIZATION", "RBAC + ABAC\nfor this action", C["policy"]), ("SCOPE", "target inside the\napproved scope", C["policy"]),
        ("PRIVACY POLICY", "what may be\ncollected/retained", C["policy"]), ("SCAN POLICY", "mode, depth,\nactive probing?", C["policy"]),
        ("RATE LIMIT", "four budget\nlayers", C["warn"]), ("TARGET SAFETY", "prod / HSM / OT\nfactors, windows", C["warn"]),
        ("CREDENTIAL", "vault lease,\nshort TTL", C["integrity"]), ("START", "job queued,\ngate decision\nrecorded", C["ok"]),
    ], h=1.15, fs=7.2)
    panel(ax, 0.4, 5.0, 5.0, 3.1, "Four rate-limit layers",
          "Layer 1 — user/API: 100 requests/min, 10 heavy/min, 5 exports/min.\nLayer 2 — scanner: 50 concurrent, 20 rps, 300 rpm, 100 connections, 5 s timeout, 2 retries.\nLayer 3 — target multiplier: production 0.5×, HSM 0.1×, dev 1.0× of the scanner budget.\nLayer 4 — global: 20 active scans per tenant, 5 concurrent scanners per environment, 100 targets per scanner.\nZero/None means unlimited — but never for the safety layer.", fs=8.2)
    panel(ax, 5.6, 5.0, 5.0, 3.1, "The orchestrator (control_plane)",
          "Pops the next due, highest-priority event that the safe-scan policy permits and leases it to a worker. Honours: an emergency stop (latest stop/disengage event wins, evaluated in time order), the per-scan safe policy, the concurrency cap and cancellation requests. scanner_for_event() picks the scanner deterministically from the event type and domain — the universal engine never guesses.", fs=8.2)
    panel(ax, 10.8, 5.0, 4.8, 3.1, "Vault leases (services/vaultlease)",
          "Scanner credentials are leased, never stored: a lease names a secret reference, a component and a scope, with a short TTL. Denials are explicit codes — CREDENTIAL_EXPIRED, ROTATION_OVERDUE, COMPONENT_NOT_ALLOWED, SCOPE_EXCEEDED, TTL_TOO_LONG, SECRET_MATERIAL_IN_REF (a reference that contains the secret itself is refused).", fs=8.2)
    panel(ax, 0.4, 1.6, 7.5, 3.0, "Scan modes (sector_profiles/scan_modes.py)",
          "discovery — inventory only, active but shallow · standard — the default · deep — full analysis · passive — zero packets (OT, production cores) · continuous — periodic with a default interval · targeted — one asset or finding · compliance — framework-driven rule selection · pqc — quantum-readiness focus.\nEach mode declares active_probing, depth and whether it is ever mutating, so the gate can refuse an active mode on a passive-only target.", fs=8.2)
    panel(ax, 8.1, 1.6, 7.5, 3.0, "Why the gate is pure",
          "The gate has no database and no network: it receives the resolved request, the policy bundle and the rate-limit state, and returns a GateDecision listing every check, the first denying reason and a structured audit record. That makes it unit-testable, identical in every worker, and impossible to bypass by calling a scanner directly — the worker refuses a job without a recorded decision.", fs=8.2)
    panel(ax, 0.4, 0.3, 15.2, 0.95, "",
          "Estate campaigns (api/routers/estate.py) schedule one CLOUD job per account, not per resource; live-scan (api/routers/live_scan.py) runs the real scanners on demand or on an interval and streams progress to the console. Both go through the same gate.", fs=8.4)
    save(fig, "22-scan-gate-and-orchestrator.png")


# ---------------------------------------------------------------- 23. privacy & data controls
def p_privacy():
    fig, ax = canvas(10.4, "Privacy and data controls — what the platform is allowed to keep",
                     "services/privacy: classify, redact, engine, policy, state, triggers. A scanner sees secrets; the platform must not retain them.")
    flow(ax, 7.9, [
        ("raw scan output", "may contain keys,\ntokens, PII", C["collect"]),
        ("classify", "public · sensitive\n· restricted", C["policy"]),
        ("policy", "per-organisation\nPrivacyPolicy", C["policy"]),
        ("redact / mask /\ntokenize", "per class, per\nfield", C["warn"]),
        ("retention", "what is kept,\nfor how long", C["warn"]),
        ("ScrubResult", "what was removed\nand why", C["ok"]),
        ("evidence", "only the sanctioned\nshape is hashed", C["integrity"]),
    ], h=1.1, fs=7.8)
    panel(ax, 0.4, 4.3, 5.0, 3.1, "Three data classes (classify.py)",
          "RESTRICTED — field names such as password, secret, token, api_key, private_key, client_secret, authorization, cookie, credential, pem, bearer: never retained in clear; a finding keeps the fingerprint and location, not the value.\nSENSITIVE — pii, email, phone, ssn, dob, address, health, iban, card/pan/cvv, national_id, passport, username…: masked or tokenized per policy.\nPUBLIC — everything else.\nClassification is by field name and value shape; both must agree to relax a class.", fs=8.1)
    panel(ax, 5.6, 4.3, 5.0, 3.1, "Verification and confidence (state.py)",
          "Every asset carries a verification state: VERIFIED (independently confirmed by a strong secondary source), PROBABLE, UNVERIFIED (one weak source), CONFLICTING (sources disagree), UNKNOWN, STALE (not observed for 3 days; UNKNOWN after 30). Confidence is measured — score 0..1, quality strong/medium/weak, source reliability, evidence count — 'not a number on a sticker'.", fs=8.1)
    panel(ax, 10.8, 4.3, 4.8, 3.1, "Triggers and incremental scans (triggers.py)",
          "Scans start from: a schedule (cron-like, per environment), a push/registry/CMDB event, a manual request, or a change detected by the monitor. Incremental scanning re-examines only what changed since the last verified snapshot; a full scan is forced when the baseline is older than the policy allows.", fs=8.1)
    panel(ax, 0.4, 1.1, 7.5, 2.8, "Scan profiles and the sanctioned contract",
          "A ScanProfile bundles mode, depth, collectors, allowed targets and the privacy class ceiling. A PolicyBundle = PrivacyPolicy + ScanPolicy is the per-organisation contract the gate enforces; changing it is an audited admin action. Profiles are what an auditor asks for when they want to know 'what were you allowed to look at?'", fs=8.2)
    panel(ax, 8.1, 1.1, 7.5, 2.8, "What this means in practice",
          "A hard-coded AWS key found in source produces a finding with the file, line, key id prefix and a SHA-256 fingerprint — never the key. A certificate's private key found on disk produces a finding of type restricted-material with location only. Exports and evidence packs are built from the scrubbed shape, so nothing an auditor receives contains a secret. Redaction runs before hashing, so the chain protects the sanctioned record.", fs=8.2)
    panel(ax, 0.4, 0.25, 15.2, 0.6, "", "Connector SDK (services/connector_sdk): every connector runs inside an execution context that redacts observations at the boundary — a connector cannot return a raw secret even if its author tries.", fs=8.3)
    save(fig, "23-privacy-and-data-controls.png")


# ---------------------------------------------------------------- 24. identity resolution, dedup, confidence, normalisation
def p_identity_dedup():
    fig, ax = canvas(10.6, "Many observations, one asset — normalisation, identity, dedup, confidence",
                     "services/normalization · deduplication · privacy/identity.py · control_plane/identity.py · correlation. Why a key seen by three scanners is one row.")
    flow(ax, 8.1, [
        ("scanner A\n(source)", "AES-128-CBC in\nsrc/crypto.py:42", C["collect"]),
        ("scanner B\n(runtime)", "libcrypto loads\nAES-CBC in pid 311", C["collect"]),
        ("scanner C\n(cloud)", "KMS key alias\nprod/data-enc", C["collect"]),
        ("normalise", "canonical algorithm,\nmode, key size, purpose", C["policy"]),
        ("identity key", "(type, algorithm,\nlocation, key size)\n→ SHA-256", C["integrity"]),
        ("merge", "one asset,\nthree evidence links", C["data"]),
        ("confidence", "VERIFIED — two\nindependent families", C["ok"]),
    ], h=1.2, fs=7.6)
    panel(ax, 0.4, 4.5, 5.0, 3.1, "Normalisation (services/normalization)",
          "Raw findings differ per scanner: 'aes128-cbc', 'AES/CBC/PKCS5Padding', 'AES_128'. The NormalizationEngine maps every algorithm, mode, key size, protocol and purpose to one canonical vocabulary (normalized_* columns on crypto_assets) so policy rules, dedup and reports never string-match on scanner dialects. Unknown tokens stay unknown and are flagged, not guessed.", fs=8.1)
    panel(ax, 5.6, 4.5, 5.0, 3.1, "Deduplication (services/deduplication)",
          "identity_tuple(finding) = (asset type, canonical algorithm, canonical location, key size). The fingerprint is SHA-256 over the sorted component list (fingerprinting/component_builder.py) — the same formula in every service. process_record() merges a new evidence record into existing assets or creates one; nothing is ever deleted, the evidence link is added.", fs=8.1)
    panel(ax, 10.8, 4.5, 4.8, 3.1, "Merged confidence (confidence_matrix.py)",
          "Scanner ids map to families (source, binary, runtime, network, cloud…). Two independent families agreeing → VERIFIED; one strong family → HIGH; one weak → MEDIUM/LOW. calculate_merged_confidence() takes the per-source values and the scanner count and returns one rank — visible on the asset and used by priority.", fs=8.1)
    panel(ax, 0.4, 1.2, 7.5, 2.9, "Universal asset identity (privacy/identity.py)",
          "Across domains the identity source differs: a host is its FQDN/IP + hardware id, a container its image digest, a cloud key its ARN, a certificate its SHA-256, a code asset its repo + path + symbol. canonical_id(observations) picks the strongest identifier present and records which one was used, so a CMDB import and a live scan of the same server resolve to one system (canonical_cmdb_key in control_plane/integrations.py).", fs=8.2)
    panel(ax, 8.1, 1.2, 7.5, 2.9, "Correlation engine (services/correlation)",
          "Every judgement is a formula or a table: recommend_replacement(algorithm) from a fixed catalogue; priority_score(revenue_impact, severity, agility); migration_effort(asset_count, complexity, agility); correlate(start, edges) walks the dependency graph to depth 4 to link a finding to the systems it affects; explain() renders the human sentence from the same inputs. Same input, same output, always.", fs=8.2)
    panel(ax, 0.4, 0.25, 15.2, 0.65, "", "Result: Findings and Assets pages show one row per real thing, with an evidence count, a confidence badge and the list of scanners that saw it. Reports count assets, not sightings.", fs=8.4)
    save(fig, "24-identity-dedup-confidence.png")


# ---------------------------------------------------------------- 25. PQC planning
def p_pqc():
    fig, ax = canvas(10.8, "Post-quantum planning — buckets, HNDL, Mosca, roadmap, what-if",
                     "services/quantum (risk.py, plan.py; threat year 2030 default; calc_version on every result) · services/agility (readiness, roadmap, simulation). No ML.")
    flow(ax, 8.4, [
        ("asset", "algorithm, key size,\npurpose, data class", C["data"]),
        ("classify()", "NIST IR 8547 bucket\n+ replacement", C["policy"]),
        ("hndl_risk()", "retention × exposure\n× confidentiality", C["warn"]),
        ("mosca()", "x + y > z ?", C["bad"]),
        ("migration_deadline()", "latest safe\nstart year", C["warn"]),
        ("score_asset()", "0-100, sector-\nweighted", C["analysis"]),
        ("roadmap", "wave 1 / 2 / 3\nper system", C["ok"]),
    ], h=1.1, fs=7.8)
    box(ax, 0.4, 4.8, 5.0, 3.1, "Mosca's inequality (plan.py)",
        "x = data shelf-life (retention years)\ny = migration time (an INPUT — never invented)\nz = years until a CRQC = threat_year − today\n\nx + y > z  →  'you are already late'\n\nIf retention is unknown the result is computable=false with the reason — the platform does not assume a shelf-life to make the number look better.",
        fc=C["bad"], fs=8.2, tfs=10, align="left")
    panel(ax, 5.6, 4.8, 5.0, 3.1, "Buckets and replacements (risk.py)",
          "Quantum-vulnerable public key (RSA, ECDSA, ECDH, DH, DSA) → ML-KEM / ML-DSA / SLH-DSA hybrids; symmetric needing larger keys (AES-128, 3DES) → AES-256; hashes (SHA-1, MD5) → SHA-256/384; already PQ-safe (AES-256, SHA-384, ML-KEM…) → keep. Harvest-now-decrypt-later exposure is highest for long-retention confidential data in transit today. 176 classification tests pin the table.", fs=8.1)
    panel(ax, 10.8, 4.8, 4.8, 3.1, "Sector weighting",
          "_sector_weight() adjusts the asset score using the sector profile (banking, healthcare, energy, telecom, government, manufacturing, automotive, pharmaceutical, retail, cloud_saas, generic): a payment HSM key in banking outranks the same algorithm on a marketing site. The weight and its source are returned with the score.", fs=8.1)
    panel(ax, 0.4, 1.4, 7.5, 3.0, "Agility readiness and roadmap",
          "assess_readiness() scores six factors per system — abstraction (crypto behind one wrapper?), configuration (algorithms externalised?), dependency pinning, test coverage of crypto paths, ownership, migration history — into a category. wave_for(category) places the system in migration wave 1, 2 or 3; build_roadmap() orders systems inside waves by the quantum score; portfolio_trend() shows whether the estate is getting more agile quarter over quarter.", fs=8.2)
    panel(ax, 8.1, 1.4, 7.5, 3.0, "What-if simulation (/what-if)",
          "simulate_improvements() replays the readiness formula with an action applied before anyone commits engineering time. Actions: move_to_kms, remove_hardcoded_keys, centralize_wrapper, externalize_config, add_crypto_tests, document_procedures, enable_hot_reload. The output is the new score, the delta and which evidence lines changed — so a team can see that 'centralise the wrapper' moves them from wave 3 to wave 2 before they start.", fs=8.2)
    panel(ax, 0.4, 0.3, 15.2, 0.85, "", "Console: /pqc (buckets, HNDL, deadlines), /pqc-map (estate heat map), /migration (waves and velocity), /what-if. API: /quantum, /agility, /priority. Every response carries calc_version so a number from last quarter can be reproduced.", fs=8.4)
    save(fig, "25-pqc-planning-explained.png")


# ---------------------------------------------------------------- 26. remediation, SLA, exceptions, pentest
def p_remediation():
    fig, ax = canvas(10.2, "Closing the loop — remediation, backlog, SLA, exceptions, pentest findings",
                     "services/remediation (15 templates, 60 snippets: java, python, javascript, go) · services/sla · routers exceptions, pentest. Suggestions, never determinations.")
    flow(ax, 7.9, [
        ("failing finding", "rule + algorithm\n+ location", C["bad"]),
        ("engine.py", "map to replacement\nguidance", C["policy"]),
        ("templates.py", "language-specific,\ncopy-paste fix", C["ok"]),
        ("backlog.py", "ordered by priority\n× effort", C["analysis"]),
        ("fix-branch payload", "POST /remediation/\nfix-branch", C["collect"]),
        ("SLA clock", "OPEN → ON_TRACK →\nAT_RISK → BREACHED", C["warn"]),
        ("RESOLVED", "next scan clears it;\nevidence recorded", C["ok"]),
    ], h=1.1, fs=7.8)
    panel(ax, 0.4, 4.4, 5.0, 3.0, "Remediation templates",
          "GET /remediation/templates lists the catalogue; /templates/{rule_id} returns the guide for one rule; /scans/{id}/suggestions renders every failing finding of a scan into a concrete fix in the language the finding was found in — e.g. BASELINE-001 on a Java 3DES cipher becomes the AES-256-GCM replacement with key and IV handling. The CLI (python -m remediation) works without a database for air-gapped review.", fs=8.1)
    panel(ax, 5.6, 4.4, 5.0, 3.0, "SLA tracker (services/sla/tracker.py)",
          "Deadlines by severity: CRITICAL 7 days · HIGH 30 · MEDIUM 90 · LOW 180 · INFO 365. Assets in critical tiers (SAFETY, CRITICAL, HSM, PAYMENT, TIER0, CROWN_JEWEL) shorten the clock. States: OPEN, ON_TRACK, AT_RISK (past a warning fraction), BREACHED, RESOLVED. Pure functions over timestamps — the SLA page and the alert rules agree because they call the same code.", fs=8.1)
    panel(ax, 10.8, 4.4, 4.8, 3.0, "Exceptions (api/routers/exceptions)",
          "An exception names a rule, a scope (asset, system or repo), an approver with a permitted role, a justification and an expiry. It is audited, shown on the finding and counted in reports as 'accepted risk', never as 'pass'. When it expires the finding fails again automatically. There is no way to hide a finding without leaving this trail.", fs=8.1)
    panel(ax, 0.4, 1.1, 7.5, 2.9, "Third-party pentest findings",
          "POST /pentest/findings ingests an external assessor's results (title, severity, asset, evidence reference); each is tracked to closure through /findings/{id}/status with an audited status history; /pentest/summary shows open items by severity and age. This lets the same SLA and reporting machinery cover findings the platform did not discover itself — an auditor sees one backlog.", fs=8.2)
    panel(ax, 8.1, 1.1, 7.5, 2.9, "Priority = the same formula everywhere",
          "correlation/priority.py: revenue_tier(revenue_daily, customer_count) × criticality × severity × inverse agility, with a BFS blast radius from the dependency graph. The Priorities page, the remediation backlog, the SLA clock shortening and the executive dashboard all call it; a CISO who asks 'why is this first?' gets the factors, not a score.", fs=8.2)
    panel(ax, 0.4, 0.25, 15.2, 0.6, "", "Console: /findings (fix panel), /priorities, /automation (SLA), /security-policy (exceptions). Automation playbooks can open the work order in Jira/ServiceNow; they cannot close a finding — only a scan can.", fs=8.3)
    save(fig, "26-remediation-sla-exceptions.png")


# ---------------------------------------------------------------- 27. KeyAssure
def p_keyassure():
    fig, ax = canvas(9.8, "KeyAssure — certificate, key and TLS assurance in depth",
                     "services/keyassure (8 modules) · API /crypto-assurance/* · pages /certificates, /crypto-assurance, /trust, /protocols.")
    items = [
        ("Active TLS audit", "tls_audit.py — SSLyze-style enumeration of protocol versions and cipher suites per endpoint; cipher_policy.py classifies each suite (forbidden / legacy / acceptable / preferred) against the active policy. POST /crypto-assurance/tls-audit.", C["collect"]),
        ("Certificate Transparency", "ct_monitor.py — watches CT logs for certificates issued for your domains; an unexpected issuer or SAN raises a finding. Deterministic matching, no heuristics. POST /ct-monitor.", C["collect"]),
        ("Expiry alerts + SLA", "expiry_alerts.py — fixed rules: ≤90 d RENEWAL_SCHEDULED, ≤60 d UPCOMING (MEDIUM), ≤30 d URGENT (HIGH), ≤7 d CRITICAL; each with the renewal SLA. Feeds the Alerts page and the automation engine.", C["warn"]),
        ("HSM / KMS connectivity", "hsm_connectivity.py — PKCS#11 / KMS reachability and key-residence verification: is the key really in the HSM the CMDB says? Read-only; results carry the slot/label and a timestamp. POST /hsm-check.", C["integrity"]),
        ("Trust-store inventory", "trust_store.py — parses root CA bundles (system, JVM, container images) and audits them: expired roots, weak signatures, unexpected private roots, missing expected roots. POST /trust-store.", C["data"]),
        ("Hybrid-PQC downgrade", "pqc_downgrade.py — negotiates against an endpoint and reports HYBRID_NEGOTIATED, HYBRID_PREFERRED, CLASSIC_NEGOTIATED, DOWNGRADE_DETECTED, HYBRID_NOT_ ADVERTISED or LOCAL_UNSUPPORTED. POST /pqc-downgrade-audit.", C["policy"]),
        ("Code rules", "code_rules.py — the deterministic weak-primitive rules shared with the source scanner (MD5/SHA-1 for signatures, ECB, static IVs, RSA < 2048, insecure random). POST /code-rules/scan for ad-hoc snippets.", C["policy"]),
        ("Certificate lifecycle", "api certificates group — CSR → issue → renew → revoke with an audited state machine; self-signed detection, revocation status (CRL/OCSP), chain validation; every certificate is an inventory row linked to systems.", C["ok"]),
    ]
    cw, ch = 3.7, 2.55
    for i, (t, b, fc) in enumerate(items):
        r, c = divmod(i, 4)
        box(ax, 0.4 + c * (cw + 0.133), 5.8 - r * (ch + 0.2), cw, ch, t, b, fc=fc, fs=7.6, tfs=9.4, align="left")
    panel(ax, 0.4, 0.3, 15.2, 2.3, "Why this is a separate engine",
          "Certificates and TLS are where most real-world cryptographic incidents happen — expiry outages, forgotten roots, a load balancer silently negotiating TLS 1.0, a CA issuing for your domain without your knowledge. KeyAssure treats each of these as a measurable state with a fixed rule, so the same endpoint audited twice gives the same verdict and a change between the two is a real change. Everything here is read-only against the target, produces evidence records like any other scanner, and is opt-in for active probing (CRYPTOSCAN_TLS_LIVE) so a passive-only estate is never touched.", fs=8.4)
    save(fig, "27-keyassure-explained.png")


# ---------------------------------------------------------------- 28. graph, blast radius, business context
def p_graph():
    fig, ax = canvas(9.6, "Dependency graph, blast radius and business context — turning a finding into an impact",
                     "services/graph_engine (Neo4j or in-process) · universal_platform/blast_radius.py · routers reachability, business_context · pages /graph, /dependency-graph, /risk.")
    # small graph drawing
    nodes = {"finding": (2.0, 6.7, C["bad"]), "lib": (4.2, 7.4, C["data"]), "svc A": (6.4, 8.0, C["data"]), "svc B": (6.4, 6.6, C["data"]),
             "payments API": (8.8, 7.3, C["warn"]), "customer DB": (8.8, 5.9, C["warn"]), "vendor X": (4.2, 5.6, C["policy"]), "revenue": (11.2, 6.6, C["bad"])}
    for n, (x, y, fc) in nodes.items():
        box(ax, x - 0.75, y - 0.32, 1.5, 0.64, None, n, fc=fc, fs=8, radius=0.3)
    for a, b in [("finding", "lib"), ("lib", "svc A"), ("lib", "svc B"), ("svc A", "payments API"), ("svc B", "customer DB"), ("vendor X", "svc B"), ("payments API", "revenue"), ("customer DB", "revenue")]:
        (x1, y1, _), (x2, y2, _) = nodes[a], nodes[b]
        arrow(ax, x1 + 0.75, y1, x2 - 0.75, y2, lw=1.1)
    ax.text(2.0, 5.55, "seed = the asset with the failing finding", fontsize=7.6, color=MUTED, ha="center")
    ax.text(11.2, 5.95, "impact = Σ business value reached", fontsize=7.6, color=MUTED, ha="center")
    panel(ax, 12.4, 5.3, 3.2, 3.2, "Reachability API",
          "GET /reachability/blast-radius — BFS from a seed to max_depth 10, returns reached systems, depth and impact.\n/impact — revenue and customers behind them.\n/compliance — frameworks those systems fall under.\n/vendor-path — how a vendor component reaches a system.", fs=7.8)
    panel(ax, 0.4, 2.1, 5.0, 2.9, "Graph engine",
          "Nodes: systems, assets, certificates, libraries, vendors, hosts. Edges: depends_on, uses, issued_for, supplied_by. graph_engine/core/analytics.py: find_cycles() (a cycle means no safe rotation order), certificate_exposure() (one expiring cert → which systems and how much impact), graph_stats(). graph_drift() diffs two snapshots. Neo4j is optional; the in-process engine gives identical answers for estates up to tens of thousands of nodes.", fs=8.0)
    panel(ax, 5.6, 2.1, 5.0, 2.9, "Business context (services/business_context)",
          "Systems carry revenue_daily, customer_count, criticality, business_process, owner and data classes — imported from the CMDB or entered on /cmdb. GET /business-context/impact rolls findings up to money and customers; /priorities orders them. The same fields feed the SLA clock, the quantum sector weight and the executive 'cost of inaction' panel.", fs=8.0)
    panel(ax, 10.8, 2.1, 4.8, 2.9, "Graph snapshots per scan",
          "graph_snapshots stores the graph as it was at each scan, so a blast radius computed for an audit is reproducible later even after the estate changed. Drift on the graph itself (a new edge to a payment system) is a drift event like any other.", fs=8.0)
    panel(ax, 0.4, 0.3, 15.2, 1.5, "What you see",
          "/graph and /dependency-graph render the reachable set from any node with impact colouring; /risk shows the deterministic risk register; a finding's detail panel shows 'affects 14 systems, 2 payment-critical, est. €X/day' with the path. Nothing here is a model: change an edge or a revenue figure and the number changes exactly as the formula says.", fs=8.4)
    save(fig, "28-graph-blast-radius-business.png")


# ---------------------------------------------------------------- 29. platform: tenancy, billing, marketplace, data lake, connectors, workload identity
def p_platform():
    fig, ax = canvas(11.2, "Platform services — tenancy, billing, marketplace, data lake, connectors, workload identity",
                     "routers saas, billing, marketplace, datalake, workload, notifications, onboarding · services billing, marketplace, ruleset, datalake, connector_sdk.")
    items = [
        ("Multi-tenant SaaS (api/routers/saas)", "POST /saas/signup creates an organisation and its first superadmin; /whoami returns the active tenancy (who, org, role, plan, usage); members and invites are managed per tenant (/members, /invites, /invites/accept → the InviteAccept page); superadmins see /admin/tenants and can suspend one. Every query is tenant-scoped by middleware — a row without a matching tenant is not visible, not '403'.", C["api"]),
        ("Plans and quotas (api/security/tenancy.py)", "FREE: 5 targets, 200 scans/month, 3 users · PRO: 100 targets, 20,000 scans/month, 25 users · ENTERPRISE: unlimited. quota_check(plan, kind, usage) is a pure gate; exceeding it returns 402 quota_exceeded with the limit, never a silent drop. Usage is visible on /organization and /saas/usage.", C["api"]),
        ("Billing (services/billing, api/routers/billing)", "A real Stripe gateway over the plan model: POST /billing/checkout opens a session for a plan; POST /billing/webhook ingests signed Stripe events (signature verified, idempotent) and moves the tenant plan; GET /billing/status shows the subscription. No card data touches the platform.", C["export"]),
        ("Plugin marketplace (services/marketplace, ruleset)", "Plugins (rule sets, connectors) are uploaded with a manifest, content and an Ed25519 signature from a pinned authority key. States: UPLOADED → VERIFIED → ENABLED / DISABLED; a failed verification is QUARANTINED and never executed. Content is hash-pinned; a changed byte fails verification. Ruleset plugins run in the deterministic ruleset engine — no code execution for rules.", C["policy"]),
        ("Data-lake export (services/datalake)", "Append-only, tamper-evident batches for an external lake (parquet/JSON-lines on object storage): sequential batch_id, per-record content_sha256, batch_digest over the ordered record hashes, previous_digest chaining each batch to its predecessor, optional detached Ed25519 seal. POST /datalake/export, /verify/{id} recomputes everything from the records.", C["integrity"]),
        ("Connector SDK (services/connector_sdk)", "BaseConnector is the interface every integration implements (discover, collect, test); the registry finds connectors by kind and method; Observation is the normalised envelope; the execution context is the enforcement boundary — it redacts at the edge, enforces the lease and the rate budget. A built-in Terraform IaC connector ships as the reference implementation.", C["collect"]),
        ("Workload identity (api/routers/workload)", "SPIFFE-style SVIDs: the trust-domain CA is generated at boot or supplied via WORKLOAD_CA_CERT/KEY; scanners and workers POST /workload/svid for a short-lived client certificate for mTLS to the API; /verify checks a presented chain deterministically; /ca publishes the root. Issuance needs an admin-scoped principal — the CA is a root of trust.", C["integrity"]),
        ("Notifications and routing (api/routers/notifications)", "/notifications/catalog lists every event class; /routing (GET/PUT) sets per-tenant delivery — in-app, email, webhook, SIEM — per class and severity. The catalog is generated from the event families the bus actually emits, so a new event type cannot exist without a routing entry.", C["realtime"]),
        ("Onboarding workflow (api/routers/onboarding)", "organisation → environments → scope entries → connections (with /connections/{id}/test) → agent heartbeat → discovery/start. /onboarding/state drives the Onboarding page checklist; nothing is scanned until scope and at least one tested connection exist.", C["ok"]),
    ]
    cw, ch = 4.95, 2.85
    for i, (t, b, fc) in enumerate(items):
        r, c = divmod(i, 3)
        box(ax, 0.4 + c * (cw + 0.175), 6.95 - r * (ch + 0.2), cw, ch, t, b, fc=fc, fs=7.5, tfs=9.0, align="left")
    panel(ax, 0.4, 0.3, 15.2, 0.6, "", "Maturity: tenancy, plans, notifications and onboarding are GA; billing, marketplace, data lake and workload identity are labelled beta/preview in the console and in lib/maturity.ts.", fs=8.3)
    save(fig, "29-platform-services-explained.png")


# ---------------------------------------------------------------- 30. sectors + anomaly + observability
def p_sectors_observability():
    fig, ax = canvas(10.4, "Sector profiles, anomaly detection and platform observability",
                     "services/sector_profiles (11 profiles) · services/anomaly (z-score, EWMA, rate-of-change, OLS forecast — no ML) · services/observability.")
    sectors = [("banking", "PCI-DSS, NIST-CSF, GLBA, SWIFT-CSCF, EBA-GL, ISO-27001"), ("healthcare", "HIPAA, HITECH, NIST-CSF, FDA-Premarket, ISO-27799, GDPR"),
               ("energy", "NERC-CIP, NIST-CSF, NIST-800-82, IEC-62443, ISO-27001"), ("telecom", "NIST-CSF, 3GPP-Security, GDPR, ISO-27001, CNSA-2.0"),
               ("government", "FIPS-140-3, CNSA-2.0, FedRAMP, NIST-800-53, NIST-CSF"), ("manufacturing", "IEC-62443, NIST-800-82, NIST-CSF, ISO-27001"),
               ("automotive", "ISO-21434, UNECE-R155/R156, NIST-CSF, IEC-62443"), ("pharmaceutical", "GxP, FDA-21-CFR-Part-11, HIPAA, GDP, ISO-27001, NIST-CSF"),
               ("retail", "PCI-DSS, NIST-CSF, GDPR, CCPA, ISO-27001"), ("cloud_saas", "SOC2, ISO-27001, NIST-CSF, FedRAMP, CSA-CCM, GDPR"), ("generic", "NIST-CSF, ISO-27001")]
    ax.text(0.4, 8.95, "Sector profiles — the Sector Layer (sector_profiles/catalog.py)", fontsize=10, fontweight="bold", color=TXT)
    cw, ch = 2.72, 0.95
    for i, (n, f) in enumerate(sectors):
        r, c = divmod(i, 6)
        x = 0.4 + c * (cw - 0.2 + 0.1)
        box(ax, x, 7.7 - r * (ch + 0.12), cw - 0.2, ch, n, f, fc=C["policy"], fs=6.9, tfs=8.6, align="left")
    panel(ax, 0.4, 3.9, 5.0, 2.5, "What a profile changes",
          "resolve_sector_context(sector, assets) returns the frameworks to map findings onto (compliance.py), the business-criticality tiers per asset type (criticality.py — a PLC in energy is TIER0, in retail it is not), the default scan modes allowed (passive-only for OT-heavy sectors) and the quantum sector weight. The Sectors page (/sectors) shows the active profile and lets an admin switch it — an audited change.", fs=8.0)
    panel(ax, 5.6, 3.9, 5.0, 2.5, "Anomaly detection (services/anomaly)",
          "Deterministic, explainable, no ML: zscore_anomaly() and ewma_control() on any metric series (findings per scan, cert expiries, handshake failures), rate_of_change_anomaly(), frequency_shift() for categorical shifts (a new algorithm appearing), and forecast_series() by ordinary least squares with a reported MAE. baseline.py detects crypto-posture drift statistically, complementing the exact drift engine. Every anomaly carries the threshold and the value.", fs=8.0)
    panel(ax, 10.8, 3.9, 4.8, 2.5, "Platform observability (services/observability)",
          "MetricsRegistry renders Prometheus text (/metrics); TraceStore keeps recent spans with traceparent propagation; compute_slo() evaluates availability and latency SLOs over the request window; evaluate_self_alerts() raises alerts about the platform itself (queue depth, error rate, stale workers); forecast_quota() predicts when a tenant hits its plan.", fs=8.0)
    panel(ax, 0.4, 1.0, 7.5, 2.6, "Detection accuracy is measured (/accuracy)",
          "score_predictions(cases) compares scanner output with labelled ground-truth fixtures and reports precision, recall and F1 per rule and per language. The Accuracy page shows these numbers from the last benchmark run — a real measurement of the detectors, so a claim like 'finds hard-coded keys' has a recall figure behind it rather than an adjective.", fs=8.2)
    panel(ax, 8.1, 1.0, 7.5, 2.6, "Compliance intelligence (control_plane/compliance.py)",
          "evaluate_control(control, findings, evidence) gives every framework control a traceable status: SATISFIED with the evidence ids that satisfy it, FAILING with the findings that break it, or NOT_ASSESSED when no rule covers it. This is what makes a compliance report 'requirement by requirement, each line citing the policy evidence' rather than a checklist.", fs=8.2)
    panel(ax, 0.4, 0.25, 15.2, 0.55, "", "Pages: /sectors, /accuracy, /security-intelligence, /system-health, /timeline (every event in order), /crypto-changes (what changed in the estate between two dates).", fs=8.3)
    save(fig, "30-sectors-anomaly-observability.png")


# ---------------------------------------------------------------- 31. end-to-end trace
def p_end_to_end():
    fig, ax = canvas(13.8, "End to end — one hard-coded 3DES key, from a developer's push to a regulator's PDF",
                     "Every subsystem it touches, in order, with the artefact each one leaves behind. This is the trace an auditor can replay.")
    steps = [
        ("1  Push", "Developer pushes to main. GitHub sends the webhook; HMAC verified against the per-deployment secret; the payload is an event on the bus.", "audit_log row · platform event", C["collect"]),
        ("2  Gate", "The unified scanner gate runs WHO → TENANT → AUTHZ → SCOPE → PRIVACY → SCAN POLICY → RATE LIMIT → TARGET SAFETY → CREDENTIAL. All pass; decision recorded.", "GateDecision (audit)", C["policy"]),
        ("3  Orchestrate", "The orchestrator leases the highest-priority due job to a worker under the concurrency cap; emergency stop not engaged; scanner chosen from the event type (source).", "scan_jobs row QUEUED→RUNNING", C["policy"]),
        ("4  Clone & detect", "Worker clones the commit into a workspace (cleaned afterwards — the leak found on 2026-09-23 is fixed), detects Java.", "progress stage 1-2", C["collect"]),
        ("5  Scan", "AST scanner finds Cipher.getInstance(\"DESede/CBC/PKCS5Padding\") at src/Pay.java:88 and a static key literal two lines above. Privacy engine keeps the location and a fingerprint, redacts the literal.", "raw finding (scrubbed)", C["collect"]),
        ("6  Evidence", "Canonical JSON → content_hash → chain_hash linked to the previous record → written to evidence_records; manifest updated on the scan.", "evidence_records · manifest_hash", C["integrity"]),
        ("7  Normalise & dedup", "'DESede' → canonical 3DES, mode CBC, 168-bit; identity key computed; the same key was seen by the runtime agent last week — merged into one asset with two evidence links, confidence VERIFIED.", "crypto_assets + crypto_asset_evidence", C["data"]),
        ("8  Policy", "BASELINE-001 (forbidden algorithm) → FAIL CRITICAL; PCI-DSS pack → FAIL; no approved exception. Remediation template: AES-256-GCM in Java.", "finding row · verdicts", C["policy"]),
        ("9  Drift, quantum, priority", "Baseline did not include this asset → drift ADDED. Quantum: symmetric-needs-larger-key bucket, HNDL low. Priority: system carries payments revenue → rank 1; blast radius 6 systems.", "drift_events · scores", C["analysis"]),
        ("10  Gate verdict", "Gate profile 'block on CRITICAL' → BLOCK. SARIF 2.1.0 uploaded, PR comment with rule/file:line/fix, commit status red, exit code 1.", "gate_evaluations · SARIF", C["bad"]),
        ("11  Live", "job.completed, finding.created, drift.detected, gate.blocked events persist to monitor_events and reach every open console over SSE. Alert routed: in-app + Jira ticket (idempotent). SLA clock: CRITICAL, 7 days.", "monitor_events · alert · ticket", C["realtime"]),
        ("12  Fix", "Developer applies the template, pushes; steps 1-10 repeat; verdict PASS; drift clears; asset history shows 3DES → AES-256-GCM with both evidence chains; SLA RESOLVED in 2 days.", "new scan · resolved", C["ok"]),
        ("13  Materialise", "Nightly materialise: inventory fingerprint changed → Technology BOM snapshot v42 with a per-layer diff (CBOM: −1 3DES, +1 AES-256-GCM).", "technology_bom_snapshots v42", C["bom"]),
        ("14  Prove", "Quarter end: PCI-DSS 4.0 report cites the finding, the fix, the evidence ids and the exception-free status; signed CBOM export of v42 with integrity_sha256 + JWS; audit-export pack sealed.", "report · export · audit pack", C["export"]),
        ("15  Verify", "Regulator: GET /scans/{id}/verify → PASS on both scans; re-hashes v42 and matches; checks the JWS; walks the audit chain. No dashboard trusted.", "verification_log", C["ok"]),
    ]
    cw, ch = 5.0, 2.1
    for i, (t, b, art, fc) in enumerate(steps):
        r, c = divmod(i, 3)
        x = 0.4 + c * (cw + 0.1)
        y = 10.0 - r * (ch + 0.14)
        box(ax, x, y, cw, ch, t, b, fc=fc, fs=7.4, tfs=9.2, align="left")
        ax.text(x + cw - 0.15, y + 0.13, art, fontsize=6.8, color=MUTED, ha="right", style="italic")
        if c < 2:
            arrow(ax, x + cw, y + ch / 2, x + cw + 0.1, y + ch / 2, lw=1.0)
    panel(ax, 0.4, 0.25, 15.2, 0.6, "", "Fifteen steps, eleven tables, one algorithm change — and every step can be reproduced from stored rows with public formulas. That is the product.", fs=8.6)
    save(fig, "31-end-to-end-trace.png")


if __name__ == "__main__":
    p_scan_gate()
    p_privacy()
    p_identity_dedup()
    p_pqc()
    p_remediation()
    p_keyassure()
    p_graph()
    p_platform()
    p_sectors_observability()
    p_end_to_end()
