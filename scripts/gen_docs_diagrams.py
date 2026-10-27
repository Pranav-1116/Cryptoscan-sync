#!/usr/bin/env python3
"""Render the product / architecture / dataflow diagrams under docs/product/img.

Pure matplotlib — no Graphviz or headless browser needed, so the diagrams can
be regenerated anywhere the test suite runs:

    python scripts/gen_docs_diagrams.py

Each diagram is described as boxes + arrows in this file so a change to the
architecture is a change to code, reviewed like code. Facts (stage names,
service names, page sections) are the ones in the repository at the time of
writing; the docs that embed the images cite where each comes from.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "product" / "img"
OUT.mkdir(parents=True, exist_ok=True)

# palette: one colour per layer so the same layer looks the same across diagrams
C = {
    "collect": "#DCEBFA", "integrity": "#FDE8CD", "data": "#E4F1DC", "policy": "#F3E3F5",
    "analysis": "#FFF4CC", "bom": "#D9F2EE", "export": "#FCE0E0", "realtime": "#E6E6F7",
    "api": "#E0EEF7", "ui": "#F0F0F0", "infra": "#EDEDED", "ext": "#FFFFFF",
    "ok": "#D8F0D8", "warn": "#FFF0C8", "bad": "#F8D8D8",
}
EDGE = "#4A5568"
TXT = "#1A202C"


def box(ax, x, y, w, h, title, body=None, fc="#FFFFFF", fs=9.5, tfs=10.5, bold=True, radius=0.25):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0.02,rounding_size={radius}",
                                linewidth=1.1, edgecolor=EDGE, facecolor=fc, zorder=2))
    if body:
        nt = title.count("\n") + 1
        th = 0.32 + 0.26 * nt  # space the title needs
        ax.text(x + w / 2, y + h - 0.22, title, ha="center", va="top", fontsize=tfs,
                fontweight="bold" if bold else "normal", color=TXT, zorder=3, linespacing=1.15)
        ax.text(x + w / 2, y + (h - th) / 2, body, ha="center", va="center", fontsize=fs,
                color=TXT, zorder=3, linespacing=1.35)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=tfs,
                fontweight="bold" if bold else "normal", color=TXT, zorder=3, linespacing=1.3)


def arrow(ax, x1, y1, x2, y2, label=None, style="-|>", lw=1.4, color=EDGE, rad=0.0, lfs=8.5, lpos=0.5, dx=0.0, dy=0.0):
    a = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=14, linewidth=lw,
                        color=color, connectionstyle=f"arc3,rad={rad}", zorder=1, shrinkA=2, shrinkB=2)
    ax.add_patch(a)
    if label:
        lx = x1 + (x2 - x1) * lpos + dx
        ly = y1 + (y2 - y1) * lpos + dy
        ax.text(lx, ly, label, fontsize=lfs, ha="center", va="center", color=TXT,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.9), zorder=4)


def canvas(w, h, title=None, subtitle=None):
    pad = 0.75  # room for title + subtitle above the topmost box
    fig, ax = plt.subplots(figsize=(w, h + pad), dpi=150)
    ax.set_xlim(0, w)
    ax.set_ylim(0, h + pad)
    ax.axis("off")
    if title:
        ax.text(0.3, h + pad - 0.3, title, fontsize=15, fontweight="bold", color=TXT, va="top")
    if subtitle:
        ax.text(0.3, h + pad - 0.82, subtitle, fontsize=9.2, color="#4A5568", va="top")
    return fig, ax


def save(fig, name):
    fig.savefig(OUT / name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", OUT / name)


# ---------------------------------------------------------------- 1. product overview

def product_overview():
    fig, ax = canvas(16, 9.4, "ZELNX CryptoScan — what the product does",
                     "One loop: connect an estate → collect cryptography from everything → hash it → assess it → gate it → prove it")
    y = 5.6
    steps = [
        ("1  Onboard\n& scope", "organisation\nenvironments\nconnectors\nsector profile", C["ui"]),
        ("2  Collect", "code · SBOM · TLS\ncertificates · cloud\nbinaries · containers\nOT · telecom\nhardware · payment", C["collect"]),
        ("3  Evidence", "SHA-256 content\n→ chain → manifest\ntamper-evident\nverifiable later", C["integrity"]),
        ("4  Inventory", "systems\ncrypto assets\ncertificates · vendors\nhardware\ndependencies", C["data"]),
        ("5  Assess", "normalise\n→ YAML policy\n→ drift → PQC\n→ agility → risk", C["policy"]),
        ("6  Gate & act", "CI gate verdicts\nalerts (alert-once)\nplaybooks with\nhuman approval", C["analysis"]),
        ("7  Prove", "CBOM · SBOM\nHBOM · VBOM\nsigned exports\naudit & evidence\npacks", C["export"]),
    ]
    w, gap, x = 2.0, 0.24, 0.3
    for i, (t, b, fc) in enumerate(steps):
        box(ax, x, y, w, 2.6, t, b, fc=fc, fs=8.4, tfs=10.0)
        if i < len(steps) - 1:
            arrow(ax, x + w, y + 1.3, x + w + gap, y + 1.3)
        x += w + gap
    arrow(ax, 0.3 + 6 * (w + gap) + w / 2, y, 0.3 + w / 2, y, rad=-0.22, color="#7A8797")
    ax.text(8.0, 4.15, "every export, gate verdict and drift result feeds the next scan: approved baselines, exceptions, migration progress",
            fontsize=8.6, ha="center", color=TXT, bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none"))

    # who reads what — six cells
    who = [
        ("Security / crypto team", "findings · inventory · drift\nPQC readiness · agility\nremediation work orders"),
        ("Developers", "CI gate verdict on their\nown commit · remediation\ntemplates · SBOM diff"),
        ("CISO / executive", "posture · unified risk score\nmigration roadmap\ncost of inaction"),
        ("Auditor / regulator", "hash-manifested evidence\npacks · compliance reports\nsupervisor read-only role"),
        ("Operations", "monitor daemon · alerts\nSSE feed · /health /metrics\nbackup + DR runbooks"),
        ("Machines", "CI/CD · GitHub / registry\nwebhooks · SCIM · SIEM /\nServiceNow · REST + GraphQL"),
    ]
    ax.text(0.3, 3.45, "Who reads what", fontsize=11, fontweight="bold", color=TXT)
    cw, cg, x = 2.42, 0.18, 0.3
    for t, b in who:
        box(ax, x, 0.7, cw, 2.45, t, b, fc="#FAFAFA", fs=8.2, tfs=9.4, radius=0.2)
        x += cw + cg
    save(fig, "01-product-overview.png")


# ---------------------------------------------------------------- 2. layered architecture

def layered_architecture():
    fig, ax = canvas(14, 12.4, "Layered architecture",
                     "Facts flow downward; every layer is a package under services/ with its own tests. Source: docs/END-TO-END-ARCHITECTURE.md")
    layers = [
        ("COLLECTION", C["collect"], "scanner (AST/regex, 6 first-class languages)  ·  devsecops (SBOM, 10 lockfile formats, binary/firmware parsing)  ·  network_scanner (TLS)\n"
         "cloud_scanner (AWS/Azure/GCP KMS, ACM)  ·  container_scanner  ·  ot_scanner / ot_safety (passive)  ·  telecom_scanner (5GC/EPC/IMS)\n"
         "universal_crypto (hardware/HSM/TPM)  ·  payment_crypto  ·  runtime  ·  vendor_intel  ·  identity  ·  keyassure"),
        ("INTEGRITY", C["integrity"], "evidence: content_hash → chain_hash → manifest_hash (SHA-256)  ·  verification_log  ·  audit packs  ·  transfer/verify"),
        ("DATA — unified asset model", C["data"], "database: PostgreSQL (prod) / SQLite (dev)  ·  Alembic 0001–0060  ·  102 tables\n"
         "System · CryptoAsset · Certificate · HardwareAsset · Vendor · SystemDependency · Scan · ScanJob · EvidenceRecord · Baseline · DriftEvent · TechnologyBom[Snapshot|Export] · Tenant · User"),
        ("NORMALISE + POLICY", C["policy"], "normalization (IANA / NIST / CBOM names)  →  policy: YAML rule packs (BASELINE, PCI-DSS, NIST SP 800-131A, CNSA 2.0, FIPS, HIPAA, UAE)  →  deterministic verdicts; no AI decides policy"),
        ("ANALYSIS", C["analysis"], "drift (baseline vs observed, config drift)  ·  graph_engine (dependency graph, blast radius; Neo4j or in-DB fallback)  ·  quantum (PQC readiness, HNDL)\n"
         "agility (6-factor score, migration readiness)  ·  deduplication  ·  correlation  ·  anomaly  ·  business_context (revenue × severity)  ·  compliance  ·  universal_platform (unified risk)"),
        ("TECHNOLOGY BOM", C["bom"], "cbom: materialize_technology_bom() → shared SBOM · CBOM · HBOM · VBOM state; binary scans add static NBOM + vulnerability BOM sidecars and a correlated technology snapshot  ·  fingerprint → immutable snapshot TECHBOM-YYYYMMDD-HHMMSS  ·  per-layer diff"),
        ("EXPORT + EVIDENCE PACKAGE", C["export"], "reporting / governance: validate → filter → generate → sign (HMAC + RFC 7515 JWS) → audit event\nJSON · CSV · CycloneDX 1.5 · SPDX · XML · PDF  ·  audit pack · exit report · engagement archive  ·  scheduled exports"),
        ("REAL-TIME", C["realtime"], "eventstream: emit_platform_event → persist (monitor_events) + in-process EventBus → DB tailer (cross-process) → Redis federation (multi-node) → SSE /api/v1/events/stream · WebSocket"),
        ("API GATEWAY", C["api"], "api: FastAPI /api/v1 — 642 paths / 85 tag groups  ·  auth (Argon-class hashing, TOTP MFA, OIDC/SAML/LDAP/SCIM, 9 RBAC roles, API keys)\n"
         "rate limits · security headers · request-id · ABAC · tenancy · GraphQL · /metrics · /health · /readyz  ·  control_plane · automation · observability"),
        ("CONSOLE", C["ui"], "frontend: Vite + React SPA — 71 pages in 6 sections (Overview · Discovery · Intelligence · Governance · Output · Administration)  ·  live SSE feed  ·  EN + AR  ·  GA / beta / preview badges"),
    ]
    h, gap, top = 0.98, 0.14, 11.1
    y = top
    for i, (name, fc, body) in enumerate(layers):
        hh = h + (0.28 if body.count("\n") >= 2 else 0.0)
        box(ax, 0.3, y - hh, 13.4, hh, name, body, fc=fc, fs=7.9, tfs=9.6)
        if i < len(layers) - 1:
            arrow(ax, 7.0, y - hh, 7.0, y - hh - gap)
        y -= hh + gap
    # side processes
    save(fig, "02-layered-architecture.png")


# ---------------------------------------------------------------- 3. runtime / deployment topology

def deployment_topology():
    fig, ax = canvas(14, 9.4, "Runtime topology — the processes that actually run",
                     "docker-compose.yml / deploy/staging/staging-up.sh. Production overlay publishes nginx only; ENVIRONMENT=production refuses SQLite, demo secrets, CORS=*")
    # column 1: outside world
    ext = [("Browser", "React SPA · REST + SSE"), ("CI · GitHub · registries", "webhooks, gate calls"),
           ("IdP / directory", "OIDC · SAML · LDAP · SCIM"), ("SIEM · ServiceNow · SMTP", "outbound from api / automation")]
    ys = [7.0, 5.5, 4.0, 2.5]
    for (t, b), y in zip(ext, ys):
        box(ax, 0.3, y, 2.7, 1.1, t, b, fc=C["ext"], fs=8.0, tfs=9.2)
    # column 2: edge
    box(ax, 3.6, 4.0, 1.9, 4.1, "nginx", "TLS termination\n:80 / :443\nserves the SPA\nproxies /api, /events", fc=C["infra"], fs=8.2)
    for y in (7.55, 6.05, 4.55):
        arrow(ax, 3.0, y, 3.6, y)
    # column 3: api
    box(ax, 6.1, 4.0, 2.6, 4.1, "api", "uvicorn + FastAPI\n:8000 compose · :8010 staging\n2 workers in production\n\nauth · RBAC · rate limit\n642 routes · GraphQL · SSE\nemits platform events", fc=C["api"], fs=8.2)
    arrow(ax, 5.5, 6.0, 6.1, 6.0, label="/api/v1")
    arrow(ax, 6.1, 4.4, 3.0, 3.05, rad=0.15, color="#7A8797", lw=1.1)
    # column 4: background processes
    box(ax, 9.3, 6.9, 2.7, 1.2, "worker", "BRPOP job queue → 14-stage pipeline\none workspace per job", fc=C["collect"], fs=7.9)
    box(ax, 9.3, 5.45, 2.7, 1.2, "monitor", "watch-list daemon, scheduled scans\nalert-once semantics", fc=C["analysis"], fs=7.9)
    box(ax, 9.3, 4.0, 2.7, 1.2, "automation / control plane", "playbooks, guardrails,\nhuman approval gates", fc=C["policy"], fs=7.9, tfs=9.0)
    # column 5: volumes
    box(ax, 12.4, 4.0, 1.3, 4.1, "volumes", "job\nworkspaces\n\nartifacts\n\nbackups\n\ntelecom\ndata", fc=C["infra"], fs=7.8)
    arrow(ax, 12.0, 7.5, 12.4, 7.5, lw=1.1)
    # stores row
    box(ax, 3.6, 0.7, 3.4, 2.0, "PostgreSQL 15 / 16", "all state · 102 tables\nAlembic 0001–0060\nscans, evidence, inventory, jobs,\nevents, audit, tenants", fc=C["data"], fs=8.0)
    box(ax, 7.4, 0.7, 3.0, 2.0, "Redis 7", "job queue (cryptoscan:jobs:queue)\nevent federation across processes\nrate-limit counters", fc=C["realtime"], fs=8.0)
    box(ax, 10.8, 0.7, 2.9, 2.0, "Neo4j 5.26 (optional)", "dependency graph, blast radius\nin-database fallback when absent", fc=C["infra"], fs=8.0)
    # store arrows: api
    arrow(ax, 6.6, 4.0, 5.6, 2.7, label="SQLAlchemy", lfs=7.8)
    arrow(ax, 7.9, 4.0, 8.5, 2.7, label="LPUSH job\npublish event", lfs=7.5, dx=0.55)
    # workers/monitor/automation → stores
    arrow(ax, 9.3, 7.2, 9.5, 2.7, rad=0.25, label="BRPOP", lfs=7.5, lpos=0.55, dx=-0.55)
    arrow(ax, 9.9, 4.0, 6.4, 2.7, rad=-0.1, color="#7A8797", lw=1.1)
    arrow(ax, 10.7, 4.0, 11.6, 2.7, lw=1.1, label="graph writes", lfs=7.5, dx=0.55)
    # process ordering
    arrow(ax, 10.65, 6.9, 10.65, 6.65, lw=1.0); arrow(ax, 10.65, 5.45, 10.65, 5.2, lw=1.0)
    # api ↔ bg processes via events
    arrow(ax, 8.7, 7.4, 9.3, 7.4, style="<|-|>", lw=1.1, label="events\n(DB tailer + Redis)", lfs=7.2, dy=0.55)
    ax.text(7.0, 0.2, "Everything above the store row is stateless and restartable; deploy/staging/staging-up.sh restart-apps redeploys api/worker/monitor without touching data.",
            fontsize=8.3, color="#4A5568", ha="center")
    save(fig, "03-runtime-topology.png")


# ---------------------------------------------------------------- 4. scan pipeline

def scan_pipeline():
    fig, ax = canvas(15, 8.6, "The scan pipeline — one job through the worker",
                     "services/worker/worker/pipeline/progress.py PIPELINE_STAGES. Every stage writes progress to scan_jobs.progress and emits a platform event.")
    stages = [
        ("clone", "fetch repo /\nlocal:// / upload"), ("language_\ndetect", "which parsers\nto run"), ("scan", "AST + regex\nper language"),
        ("evidence", "SHA-256 chain\nper finding"), ("load", "persist scan +\nevidence_records"), ("normalize", "IANA / NIST\nnames, sizes"),
        ("policy", "YAML rules →\nverdicts"), ("dedup", "one asset,\nN occurrences"), ("systems", "map to\nSystem/owner"),
        ("graph", "dependency\nedges"), ("cbom", "CycloneDX\nsnapshot"), ("drift", "vs approved\nbaseline"),
        ("gate", "pass / warn /\nblock"), ("alert", "channels,\nalert-once"),
    ]
    w, gap = 0.94, 0.10
    x0, y = 0.3, 4.6
    for i, (n, b) in enumerate(stages):
        x = x0 + i * (w + gap)
        fc = C["collect"] if i < 3 else C["integrity"] if i < 5 else C["policy"] if i < 7 else C["data"] if i < 10 else C["bom"] if i == 10 else C["analysis"] if i < 13 else C["export"]
        box(ax, x, y, w, 1.5, n, b, fc=fc, fs=7.0, tfs=8.4, radius=0.15)
        if i < len(stages) - 1:
            arrow(ax, x + w, y + 0.75, x + w + gap, y + 0.75, lw=1.0)
    # triggers
    ty = 6.55
    box(ax, 0.3, ty, 3.6, 0.8, "POST /scans/trigger · GitHub webhook\nschedule · CI gate call", fc=C["api"], tfs=8.4)
    box(ax, 4.2, ty, 2.6, 0.8, "scan_jobs row (QUEUED)", fc=C["data"], tfs=8.4)
    box(ax, 7.1, ty, 3.3, 0.8, "Redis LPUSH cryptoscan:jobs:queue", fc=C["realtime"], tfs=8.4)
    box(ax, 10.7, ty, 2.2, 0.8, "worker BRPOP", fc=C["collect"], tfs=8.4)
    arrow(ax, 3.9, ty + 0.4, 4.2, ty + 0.4); arrow(ax, 6.8, ty + 0.4, 7.1, ty + 0.4); arrow(ax, 10.4, ty + 0.4, 10.7, ty + 0.4)
    arrow(ax, 11.8, ty, 0.77, y + 1.5, rad=0.0, lw=1.0, color="#7A8797")
    # outputs
    box(ax, 0.3, 1.2, 3.4, 2.3, "Written to PostgreSQL", "scans · evidence_records\ncrypto_assets · crypto_asset_evidence\nsystems · system_dependencies\nbaselines · drift_events\ngate_evaluations · scan_jobs", fc=C["data"], fs=8.0)
    box(ax, 4.0, 1.2, 3.4, 2.3, "Verifiable afterwards", "GET /scans/{id}/verify\n→ chain_intact, result PASS\nGET /scans/{id}/findings\nGET /scans/{id}/cbom\nGET /jobs/{id} (stage log)", fc=C["integrity"], fs=8.0)
    box(ax, 7.7, 1.2, 3.4, 2.3, "Streamed live", "job.started / stage.* / job.completed\nfinding.new · drift.detected\n→ monitor_events (durable)\n→ EventBus → SSE → console", fc=C["realtime"], fs=8.0)
    box(ax, 11.4, 1.2, 3.3, 2.3, "Failure behaviour", "stage fails → job FAILED with\nstage name + error; retry via\nPOST /jobs/{id}/retry (new job)\nknown gap: worker crash mid-run\nleaves job QUEUED (no requeue)", fc=C["warn"], fs=8.0)
    for xx in (2.0, 5.7, 9.4, 13.05):
        arrow(ax, xx, y, xx, 3.5, lw=1.0)
    save(fig, "04-scan-pipeline.png")


# ---------------------------------------------------------------- 5. data flows A-E

def dataflows():
    fig, ax = canvas(14, 9.6, "The five data flows",
                     "docs/DATAFLOW.md. A–D run continuously; E is the only timer/event-triggered path.")
    rows = [
        ("A  INGEST", C["collect"], [("scanner facts", ""), ("evidence\nSHA-256 chain", ""), ("unified inventory\n(PostgreSQL)", "")]),
        ("B  MATERIALISE\n+ VERSION", C["bom"], [("gather inventory", ""), ("materialize\nsbom · cbom · hbom · vbom", ""), ("fingerprint\nunchanged → no-op", ""), ("snapshot vN\n+ per-layer diff", "")]),
        ("C  EXPORT\n+ AUDIT", C["export"], [("validate", ""), ("filter\n(layer, env, tenant)", ""), ("generate\njson·csv·cdx·spdx·xml·pdf", ""), ("sign\nHMAC + JWS", ""), ("audit event", "")]),
        ("D  LIVE\nDELIVERY", C["realtime"], [("emit_platform_event", ""), ("persist\nmonitor_events", ""), ("EventBus\n(in-process)", ""), ("DB tailer +\nRedis federation", ""), ("SSE / WS\n→ browser", "")]),
        ("E  SCHEDULED", C["analysis"], [("schedule\n(cron-like)", ""), ("run-due\nnext_run_at, idempotent", ""), ("export_bom", ""), ("run record\n+ event", "")]),
    ]
    y = 7.55
    for name, fc, cells in rows:
        box(ax, 0.3, y, 1.9, 1.15, name, fc=fc, tfs=9.2)
        n = len(cells)
        avail = 13.7 - 2.5
        w = (avail - (n - 1) * 0.25) / n
        x = 2.5
        for i, (t, _) in enumerate(cells):
            box(ax, x, y, w, 1.15, t, fc="#FFFFFF", tfs=8.4, bold=False, radius=0.15)
            if i < n - 1:
                arrow(ax, x + w, y + 0.575, x + w + 0.25, y + 0.575, lw=1.1)
            x += w + 0.25
        y -= 1.45
    # vertical links between flows
    for yy, lab in ((7.55, "inventory rows"), (6.1, "state or snapshot vN"), (4.65, "every operation emits")):
        arrow(ax, 1.25, yy, 1.25, yy - 0.3, lw=1.1, color="#7A8797")
        ax.text(2.35, yy - 0.15, lab, fontsize=7.4, color="#4A5568", va="center")
    arrow(ax, 1.25, 3.2, 1.25, 2.9, lw=1.1, color="#7A8797")
    ax.text(2.35, 3.05, "timer → same export path as C, streamed via D", fontsize=7.4, color="#4A5568", va="center")
    ax.text(0.3, 0.75, "Trust boundary: nothing in B–E can change what A recorded. Snapshots are immutable; exports carry the content hash they were made from;\nthe audit log is itself hash-chained. A regulator can re-verify any artefact against the chain without trusting the server.",
            fontsize=8.6, color=TXT, va="center")
    save(fig, "05-dataflows.png")


# ---------------------------------------------------------------- 6. evidence chain

def evidence_chain():
    fig, ax = canvas(14, 6.2, "Evidence chain — why a finding can be trusted later",
                     "services/evidence/evidence/hashing (canonical_serializer, content_hasher, chain_hasher). First record chains to the scan session id; the manifest seals the set; GET /scans/{id}/verify recomputes all of it.")
    x0, y = 0.3, 3.2
    for i in range(4):
        x = x0 + i * 3.35
        box(ax, x, y, 2.9, 2.1, f"evidence_record {i + 1}" if i < 3 else "evidence_record n",
            "content = finding JSON (canonical)\ncontent_hash = SHA-256(content)\nchain_hash = SHA-256(\n   content_hash ‖ prev.chain_hash)", fc=C["integrity"], fs=7.9)
        if i < 3:
            arrow(ax, x + 2.9, y + 1.05, x + 3.35, y + 1.05, label="prev", lfs=7.5)
    ax.text(0.3 + 3 * 3.35 - 0.35, y + 1.05, "…", fontsize=16, ha="center", va="center")
    box(ax, 0.3, 0.7, 4.2, 1.8, "manifest", "manifest_hash = SHA-256(all chain_hashes)\nstored on the scan; signed in exports\n(HMAC + RFC 7515 JWS)", fc=C["integrity"], fs=8.2)
    box(ax, 4.9, 0.7, 4.2, 1.8, "verify (any time)", "recompute every content_hash and chain_hash\ncompare manifest → chain_intact: true/false\nresult PASS / FAIL, first broken index\nwritten to verification_log", fc=C["ok"], fs=8.2)
    box(ax, 9.5, 0.7, 4.2, 1.8, "what tampering looks like", "edit one finding → its content_hash changes\n→ every later chain_hash changes\n→ manifest mismatch → FAIL at that index\ndeleting a record breaks the chain the same way", fc=C["bad"], fs=8.2)
    arrow(ax, 0.3 + 3 * 3.35 + 1.45, y, 2.4, 2.5, rad=0.0, lw=1.1)
    save(fig, "06-evidence-chain.png")


# ---------------------------------------------------------------- 7. console map

def console_map():
    fig, ax = canvas(14, 7.2, "Console map — 71 pages in 6 sections",
                     "Sidebar = frontend/src/components/Layout.tsx PRIMARY_SECTIONS; '+' rows are routes reached from those pages or the search. Badge = GA / beta / preview from shared_models/capability_maturity.py")
    sections = [
        ("Overview", C["ui"], "Dashboard\nLive Asset Intelligence\nActivity (live stream)\n\n+ Executive · Alerts\nSearch · Role dashboard\nTimeline"),
        ("Discovery", C["collect"], "Scan · Assets\nNetwork · Cloud\nApplications (SBOM,\nbinaries, firmware)\nHardware · Certificates\nVendors\n+ Telecom · Runtime\nCMDB · Live env · Catalog"),
        ("Intelligence", C["analysis"], "CBOM · HBOM\nDependency Graph\nCrypto Inventory\nPQC Readiness\nCrypto Agility · Drift\n+ Findings · Priorities\nRisk · Migration\nProtocols · Libraries"),
        ("Governance", C["policy"], "Banking & SWIFT\nPolicies · Compliance\nEvidence · Audit Log\n\n+ Governance (access\nreviews, exceptions)\nSectors · Assurance\nSupervision · Trust"),
        ("Output", C["export"], "Reports (JSON / HTML /\nPDF, schedules)\nWhat-If Analysis\n\n+ exports reached from\nCBOM, Evidence and\nCompliance pages"),
        ("Administration", C["infra"], "System Health\nSettings & Org\nSecurity Center\nUsers & Teams\nIntegrations & API\n+ Automation\nNotifications · Onboarding\nTenancy · Resilience"),
    ]
    w, gap = 2.1, 0.16
    for i, (t, fc, b) in enumerate(sections):
        x = 0.3 + i * (w + gap)
        box(ax, x, 3.2, w, 3.6, t, b, fc=fc, fs=7.5, tfs=9.8)
    box(ax, 0.3, 0.7, 13.4, 2.1, "Every page shares the same contract", fc="#FAFAFA", fs=8.4,
        body=("data from /api/v1 via one client (auth header, 401 → refresh, error shaping) · live updates from one SSE subscription (lib/realtime.tsx)\n"
              "renders zeros / empty / offline until a real scan produces evidence — never seeded or fabricated · EN + AR via i18n · GA / beta / preview badge in nav and header\n"
              "smoke-tested: every page mounts against a mocked API (pages.smoke.test.tsx)"))
    save(fig, "07-console-map.png")


# ---------------------------------------------------------------- 8. security & identity

def security_model():
    fig, ax = canvas(14, 7.2, "Security and identity model",
                     "services/api/api/security, middleware. Fail-closed: no permission match → 403; production guard refuses unsafe config at boot.")
    box(ax, 0.3, 4.2, 3.0, 2.5, "Who you are", "local user + TOTP MFA\nOIDC (relay, auth-code, PKCE)\nSAML 2.0 SP · LDAP/AD\nSCIM 2.0 provisioning\nscoped, rotated API keys", fc=C["api"], fs=7.9)
    box(ax, 3.7, 4.2, 3.0, 2.5, "What you may do", "9 RBAC roles (superadmin, ciso,\nanalyst, developer, auditor, owner,\nscanner, readonly, supervisor)\nrequire_permission on every route\nABAC + tenant scoping", fc=C["policy"], fs=7.9)
    box(ax, 7.1, 4.2, 3.0, 2.5, "Every request passes", "request-id → security headers\n→ rate limit (600/min/identity)\n→ auth → ABAC → tenancy\n→ route → hash-chained audit_log\n→ platform event", fc=C["realtime"], fs=7.9)
    box(ax, 10.5, 4.2, 3.2, 2.5, "Production guard (boot)", "ENVIRONMENT=production refuses\nSQLite · demo SECRET_KEY\nweak webhook secret · CORS=*\nplaintext ADMIN_PASSWORD\ntested in both directions", fc=C["bad"], fs=7.9)
    for x in (3.3, 6.7, 10.1):
        arrow(ax, x, 5.5, x + 0.4, 5.5)
    box(ax, 0.3, 0.8, 6.5, 2.9, "Integrity of what the product says", fc=C["integrity"], fs=8.2,
        body="evidence records: SHA-256 content → chain → manifest\naudit log: hash-chained, exportable as examiner pack\nexports: content hash + HMAC + RFC 7515 JWS signature\nsnapshots: immutable, fingerprint-addressed\nbackups: dump + sha256 manifest; PITR + restore drills documented")
    box(ax, 7.2, 0.8, 6.5, 2.9, "What the product never does", fc=C["ok"], fs=8.2,
        body="decide policy with AI — rules are YAML, verdicts deterministic\nsend packets on OT networks — passive only\nfabricate data — unknown is reported as unknown, with the reason\nphone home — air-gap mode: JWKS from file, feeds imported\nlet a directory (SCIM/LDAP/OIDC) mint a superadmin")
    save(fig, "08-security-model.png")


# ---------------------------------------------------------------- 9. maturity / readiness

def readiness():
    fig, ax = canvas(14, 6.0, "Scope and readiness — what is GA, what is not",
                     "shared_models/capability_maturity.py (33 GA · 30 beta · 8 preview) and docs/PRODUCTION-READINESS.md (~80 % overall, core ~92 %)")
    box(ax, 0.3, 2.3, 4.3, 2.8, "GA — 33 surfaces", "scanners · assets · certificates · network · cloud\nDevSecOps (SBOM / binary) · vendors · findings\ncrypto inventory · drift · CBOM · PQC · libraries\npolicies · compliance · evidence · reports · alerts\nidentity · integrations · security center · health",
        fc=C["ok"], fs=8.0)
    box(ax, 4.9, 2.3, 4.3, 2.8, "Beta — 30 surfaces", "hardware · telecom · runtime · CMDB · catalog\ngraph / dependency graph · HBOM · agility · risk\nmigration · priorities · protocols · executive\nbanking regulatory · governance · sectors · assurance\nautomation · onboarding · tenancy · resilience",
        fc=C["warn"], fs=8.0)
    box(ax, 9.5, 2.3, 4.2, 2.8, "Preview — 8 surfaces", "what-if analysis · PQC map\nsecurity intelligence · supervision · trust\naccuracy panel · timeline · platform P2",
        fc=C["bad"], fs=8.0)
    box(ax, 0.3, 0.5, 13.4, 1.4, "Verified on real PostgreSQL 16 + Redis 7 with production guards (2026-09-23)", fc="#FAFAFA", fs=8.4,
        body="60-migration chain applies on a fresh database · scans complete end to end with chain_intact · soak harness clean · burn-in: GitHub webhook / TLS / SMTP PASS\nStill open: the 7-day soak itself, a true capacity number, live Neo4j / cloud / container burn, crashed-job requeue — see docs/PRODUCTION-READINESS.md")
    save(fig, "09-scope-readiness.png")


if __name__ == "__main__":
    product_overview()
    layered_architecture()
    deployment_topology()
    scan_pipeline()
    dataflows()
    evidence_chain()
    console_map()
    security_model()
    readiness()
