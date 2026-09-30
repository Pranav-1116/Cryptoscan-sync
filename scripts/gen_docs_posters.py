#!/usr/bin/env python3
"""Explanatory poster diagrams for docs/product — one per topic, text on the image.

Where gen_docs_diagrams.py draws the *structure*, these posters *explain*:
each image carries a heading, a diagram, and prose panels ("what it is",
"how it works", "what you get", "limits") so it can stand alone in a slide,
a wiki page or a printed pack.

    python scripts/gen_docs_posters.py

matplotlib only. Facts are checked against the repository (see the docs
that embed them for the source of each number).
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "product" / "img"
OUT.mkdir(parents=True, exist_ok=True)

C = {
    "collect": "#DCEBFA", "integrity": "#FDE8CD", "data": "#E4F1DC", "policy": "#F3E3F5",
    "analysis": "#FFF4CC", "bom": "#D9F2EE", "export": "#FCE0E0", "realtime": "#E6E6F7",
    "api": "#E0EEF7", "ui": "#F0F0F0", "infra": "#EDEDED", "ext": "#FFFFFF",
    "ok": "#D8F0D8", "warn": "#FFF0C8", "bad": "#F8D8D8", "panel": "#FBFBFC",
}
EDGE = "#4A5568"
TXT = "#1A202C"
MUTED = "#4A5568"
W = 16  # every poster is 16 in wide; height varies


def canvas(h, title, subtitle):
    fig, ax = plt.subplots(figsize=(W, h), dpi=150)
    ax.set_xlim(0, W)
    ax.set_ylim(0, h)
    ax.axis("off")
    ax.text(0.4, h - 0.35, title, fontsize=17, fontweight="bold", color=TXT, va="top")
    ax.text(0.4, h - 0.9, subtitle, fontsize=10, color=MUTED, va="top")
    ax.plot([0.4, W - 0.4], [h - 1.15, h - 1.15], color="#CBD5E0", lw=1)
    return fig, ax


def save(fig, name):
    fig.savefig(OUT / name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", OUT / name)


def box(ax, x, y, w, h, title=None, body=None, fc="#FFFFFF", fs=9, tfs=10.5, wrap=None, align="center", radius=0.18, lw=1.1):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0.02,rounding_size={radius}",
                                linewidth=lw, edgecolor=EDGE, facecolor=fc, zorder=2))
    ty = y + h - 0.2
    if title:
        ax.text(x + w / 2 if align == "center" else x + 0.18, ty, title, ha=align, va="top",
                fontsize=tfs, fontweight="bold", color=TXT, zorder=3)
        ty -= 0.2 + 0.24 * (title.count("\n") + 1)
    if body:
        if wrap is None and align != "center":
            wrap = max(10, int((w - 0.4) * 72 / (0.67 * fs)))
        if wrap:
            body = "\n".join(textwrap.fill(par, wrap) for par in body.split("\n"))
        if align == "center":
            ax.text(x + w / 2, y + (ty - y) / 2, body, ha="center", va="center", fontsize=fs, color=TXT, zorder=3, linespacing=1.4)
        else:
            ax.text(x + 0.18, ty, body, ha="left", va="top", fontsize=fs, color=TXT, zorder=3, linespacing=1.45)


def panel(ax, x, y, w, h, title, body, fc=C["panel"], fs=8.8, wrap=None):
    """Prose panel: bold title top-left, wrapped paragraph(s) below."""
    if wrap is None:
        wrap = int((w - 0.4) * 72 / (0.67 * fs))
    box(ax, x, y, w, h, title, body, fc=fc, fs=fs, tfs=10.5, wrap=wrap, align="left", radius=0.14)


def arrow(ax, x1, y1, x2, y2, label=None, rad=0.0, lw=1.4, color=EDGE, lfs=8, style="-|>", dx=0.0, dy=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=14, linewidth=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}", zorder=1, shrinkA=2, shrinkB=2))
    if label:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, label, fontsize=lfs, ha="center", va="center", color=TXT,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.92), zorder=4)


# ============================================================ 10. collection in depth

def p_collection():
    fig, ax = canvas(12.6, "Collection — getting cryptography out of everything",
                     "Eleven collectors feed one inventory. Each is read-only and deterministic, tests without network, and reports what it could not reach instead of guessing.")
    cols = [
        ("Source code", C["collect"], "AST for Python, Java, C#, JS/TS, Go, Rust; regex for Kotlin, PHP, Ruby, config/IaC.\nFinds: hard-coded keys and PEM, weak primitives (MD5, SHA-1, DES, RC4, ECB), key sizes, IV/nonce reuse, insecure random, TLS settings.", "services/scanner · worker pipeline"),
        ("SBOM / dependencies", C["collect"], "Manifests + 10 lockfile formats (package-lock, yarn, pnpm, poetry, Pipfile, go.sum, Cargo, Gemfile, composer, packages.lock) → resolved and transitive graph, licences, crypto libraries; NTIA completeness score.", "devsecops/sbom_scan.py, sbom_lockfiles.py"),
        ("Binaries / firmware", C["collect"], "Real parsing: ELF (deps, RPATH, build-id, symbols, Go build-info + modules, hardening flags, crypto constants), PE (imports, resources, Authenticode presence, CLR), Mach-O, ar/deb/RPM/zip/WASM/class; firmware chains with offsets + entropy.", "devsecops/binary_scan.py"),
        ("Network / TLS", C["collect"], "Live handshakes: protocol + cipher posture, certificate chains, STARTTLS, weak parameters, expiry. Active probing is opt-in (CRYPTOSCAN_TLS_LIVE); passive otherwise.", "services/network_scanner"),
        ("Certificates", C["collect"], "Inventory and expiry from network and source scans; lifecycle CSR → issue → renew → revoke; self-signed, revocation status, chain validation.", "api certificates group"),
        ("Cloud", C["collect"], "AWS KMS + ACM live (fingerprint = SHA-256 of the real DER), Azure Key Vault, GCP Cloud KMS key metadata. Read-only IAM roles; credential presence checked before anything runs.", "services/cloud_scanner"),
        ("Containers / IaC", C["collect"], "Image and filesystem package inventory, crypto binaries, Dockerfile/IaC rules. Registry push webhooks (ACR, ECR, GCR, Harbor, Docker Hub) fail closed on a bad signature.", "services/container_scanner"),
        ("OT / ICS", C["collect"], "Passive — zero packets sent. PLC/RTU/SCADA crypto posture from captures and configs; safety-aware maintenance windows so nothing runs during a process-critical period.", "ot_scanner, ot_safety"),
        ("Telecom", C["collect"], "5GC / EPC / IMS / roaming verdicts, SEPP PQC readiness, per-carrier NRA packs, closed-network ingest for cores that cannot be reached from IT.", "services/telecom_scanner"),
        ("Hardware", C["collect"], "HSM / TPM / firmware registry with quantum-resistant flags cited to firmware documentation; 68 vendor plugins across 16 categories.", "universal_crypto, universal_vendor"),
        ("Payment", C["collect"], "HSM key inventory, TR-39-style ceremony provenance, dual custody, PCI attributes, ISO 20022 message crypto.", "services/payment_crypto"),
        ("Runtime · Vendors · CMDB", C["collect"], "Host agents (eBPF / LD_PRELOAD adapters) report live library use; vendor questionnaires and CBOMs → 0–100 vendor risk; ServiceNow-style CMDB resolves systems and owners.", "runtime, vendor_intel, inventory"),
    ]
    cw, ch, gap = 3.72, 2.35, 0.2
    x0, y0 = 0.4, 8.6
    for i, (t, fc, b, src) in enumerate(cols):
        r, c = divmod(i, 4)
        x = x0 + c * (cw + gap)
        y = y0 - r * (ch + gap)
        box(ax, x, y, cw, ch, t, b, fc=fc, fs=7.5, tfs=9.6, wrap=47, align="left")
        ax.text(x + 0.18, y + 0.14, src, fontsize=6.8, color=MUTED, style="italic")
    # arrows into one inventory
    ax.add_patch(FancyBboxPatch((0.4, 0.55), 15.2, 0.95, boxstyle="round,pad=0.02,rounding_size=0.14", lw=1.2, ec=EDGE, fc=C["data"], zorder=2))
    ax.text(8.0, 1.02, "→  one unified inventory: a key seen by the cloud collector and by code scanning is ONE asset with TWO evidence sources  →  evidence chain  →  policy",
            ha="center", va="center", fontsize=9.6, fontweight="bold", color=TXT, zorder=3)
    for c in range(4):
        x = x0 + c * (cw + gap) + cw / 2
        arrow(ax, x, y0 - 2 * (ch + gap), x, 1.5, lw=1.1, color="#7A8797")
    panel(ax, 0.4, 0.05, 15.2, 0.42, "", "")
    ax.text(0.5, 0.26, "Rule: unknown is reported as unknown, with the reason — unreachable host, unparsable file, un-extracted firmware (BIN-FIRMWARE-NOT-EXTRACTED), missing credentials. Nothing is inferred to fill a gap.",
            fontsize=8.2, color=TXT, va="center")
    save(fig, "10-collection-in-depth.png")


# ============================================================ 11. evidence & integrity explained

def p_evidence():
    fig, ax = canvas(10.6, "Evidence and integrity — why a regulator can trust a finding a year later",
                     "services/evidence: canonical_serializer → content_hasher → chain_hasher → manifest. The same shape protects the audit log, SBOM artifacts, exports and backups.")
    # left: the mechanism
    y = 7.4
    steps = [
        ("1  Canonicalise", "Finding → JSON with sorted keys and stable formatting. The same fact hashes the same way whoever produced it.", C["integrity"]),
        ("2  Content hash", "content_hash = SHA-256(canonical bytes). Identifies exactly this observation.", C["integrity"]),
        ("3  Chain hash", "chain_hash[n] = SHA-256(content_hash[n] ‖ chain_hash[n-1]); the first record chains to the scan session id. Order and completeness are now part of every hash.", C["integrity"]),
        ("4  Manifest", "manifest_hash = SHA-256 over all chain hashes, stored on the scan and included in every signed export made from it.", C["integrity"]),
        ("5  Verify, any time", "GET /scans/{id}/verify recomputes 1–4 from the stored rows → chain_intact, PASS/FAIL, first broken index → written to verification_log.", C["ok"]),
    ]
    for i, (t, b, fc) in enumerate(steps):
        box(ax, 0.4, y - i * 1.42, 7.4, 1.25, t, b, fc=fc, fs=8.2, tfs=9.8, wrap=86, align="left")
        if i < len(steps) - 1:
            arrow(ax, 4.1, y - i * 1.42, 4.1, y - i * 1.42 - 0.17, lw=1.1)
    # right: what it means
    panel(ax, 8.2, 5.35, 7.4, 3.3, "What tampering looks like",
          "Edit one finding → its content_hash changes → every later chain_hash changes → the manifest no longer matches → verify returns FAIL at that index.\n"
          "Delete a record → the next record's chain input no longer matches → FAIL at that index.\n"
          "Re-order records → same effect.\n"
          "The algorithm is public and the inputs are the stored rows, so an auditor can run the same computation outside the platform and does not have to trust the server's answer.", fs=8.6)
    panel(ax, 8.2, 2.55, 7.4, 2.6, "Where else the same pattern is used",
          "Audit log: every auth/admin action is a chained record; incremental verification (~213× faster than a full walk); examiner-ready ZIP export.\n"
          "SBOM / binary artifacts: stored bytes + sha256 + HMAC manifest; /sbom/{id}/verify catches byte flips and manifest edits.\n"
          "Exports: integrity_sha256 + signature_hmac + RFC 7515 JWS over the same canonical bytes.\n"
          "Backups: dump + sha256 manifest; restore and PITR drills recorded.", fs=8.4)
    panel(ax, 8.2, 0.95, 7.4, 1.45, "Measured on the Postgres staging stack (2026-09-23)",
          "Every soak scan verified PASS, chain_intact = true (14 records each). The chain is built in the worker's evidence stage and persisted in load, so a job that fails later still leaves a verifiable partial chain.", fs=8.2, fc=C["ok"])
    panel(ax, 0.4, 0.2, 15.2, 0.6, "", "")
    ax.text(0.55, 0.5, "Design note: a signature proves who said something; a chain proves nothing was removed or reordered. CryptoScan uses both (ADR-003).", fontsize=8.4, color=TXT, va="center")
    save(fig, "11-evidence-explained.png")


# ============================================================ 12. inventory & technology BOM

def p_bom():
    fig, ax = canvas(13.4, "Inventory and the Technology BOM — shared views, binary sidecars, immutable versions",
                     "services/cbom/technology_bom.py materialize_technology_bom(); services/devsecops/devsecops/binary_boms.py; tenant-scoped bounded evidence and bundle diffs. CycloneDX 1.5 for CBOM (ADR-009).")
    # source tables
    tables = [("systems", "name, owner, environment, criticality"), ("crypto_assets", "algorithm, key_size, purpose, mode, libraries, file_path, confidence"),
              ("certificates", "fingerprint_sha256, subject, expiry, self-signed, revocation"), ("hardware_live", "manufacturer, model, firmware, hsm, tpm, risk"),
              ("vendors", "name, product, lifecycle, risk_level"), ("system_dependency / system_vendor", "parent → child edges; vendor ↔ system")]
    for i, (t, b) in enumerate(tables):
        box(ax, 0.4, 10.75 - i * 1.28, 4.3, 1.12, t, b, fc=C["data"], fs=7.8, tfs=9.2, wrap=44, align="left")
    ax.text(2.55, 12.0, "unified inventory (PostgreSQL)", fontsize=9.5, fontweight="bold", ha="center")
    # materialize
    box(ax, 5.4, 6.4, 2.6, 5.5, "materialize", "gather\n(env, tenant filters)\n↓\none canonical state\n↓\nfingerprint =\nSHA-256(state)\n↓\nunchanged?\n→ no new version\nchanged?\n→ snapshot vN\n+ per-layer diff", fc=C["bom"], fs=8.2, tfs=10)
    for i in range(6):
        arrow(ax, 4.7, 10.75 - i * 1.28 + 0.56, 5.4, 9.15, lw=0.9, color="#7A8797")
    # Shared inventory views plus binary-derived sidecars.
    views = [
        ("SBOM", "systems and components,\nresolved + transitive, licences"),
        ("CBOM", "algorithms, keys, certs,\nCycloneDX crypto evidence"),
        ("HBOM", "HSMs, TPMs, devices,\nfirmware with provenance"),
        ("NBOM", "static binary capability\ncandidates; observed: false"),
        ("VBOM", "vendors, products, lifecycle,\nsupply-chain relationships"),
        ("Vulnerability BOM", "separate weak/hardening/refusal\nfindings; not the VBOM layer"),
        ("Technology snapshot", "stable refs, provenance, fingerprint,\nper-layer bundle diff"),
    ]
    for i, (t, b) in enumerate(views):
        y = 10.75 - i * 1.0
        box(ax, 8.7, y, 3.1, 0.88, t, b, fc=C["bom"], fs=7.1, tfs=8.7)
        arrow(ax, 8.0, 9.15, 8.7, y + 0.44, lw=0.9)
    ax.text(10.25, 12.0, "correlated BOM family", fontsize=9.5, fontweight="bold", ha="center")
    # snapshot + export
    box(ax, 12.5, 8.9, 3.1, 3.1, "snapshot vN", "TECHBOM-YYYYMMDD-HHMMSS\nfingerprint, parent_fingerprint\nfull state · per-layer diff\ncreated_by · environment\n\nimmutable — read paths\nnever recompute", fc=C["bom"], fs=7.9, tfs=10)
    box(ax, 12.5, 6.4, 3.1, 2.1, "signed export", "json · csv · cyclonedx ·\ncyclonedx-xml · spdx · xml · pdf\nintegrity_sha256 + HMAC + JWS\naudit event per export", fc=C["export"], fs=7.9, tfs=10)
    arrow(ax, 11.8, 8.5, 12.5, 10.4, lw=1.1); arrow(ax, 14.05, 8.9, 14.05, 8.5, lw=1.1)
    # explanatory panels
    panel(ax, 0.4, 0.35, 5.0, 3.6, "Why one model",
          "Every reviewer asks a different question of bounded evidence: PCI wants algorithms, a supply-chain review wants components, an HSM audit wants hardware, procurement wants vendors, and a binary review needs static capability and vulnerability sidecars. Shared materialization keeps the SBOM, CBOM, HBOM and VBOM correlated; binary-derived NBOM remains observed: false until a network scan corroborates it.", fs=8.4)
    panel(ax, 5.6, 0.35, 5.0, 3.6, "Why versions are immutable",
          "A snapshot is the exact state that was exported and signed. If nothing changed, materialising again makes no new version, so version numbers mean something. Compare, diff and export read snapshots and never recompute, so what a user compares on the CBOM page is what an auditor receives.", fs=8.4)
    panel(ax, 10.8, 0.35, 4.8, 3.6, "Where it shows up",
          "Console: /cbom, /hbom, /vendor, /nbom, /dev-sec-ops (SBOM + binaries), /live-asset-intelligence (materialise → version → compare → export).\nAPI: /technology-bom, /versions, /diff, /export, /schedules; binary sidecars at /binary/artifacts/{id}/bom/{type}.\nDrift, agility and PQC readiness read the shared state; binary bundle diffs preserve artifact provenance.", fs=8.4)
    save(fig, "12-technology-bom-explained.png")


# ============================================================ 13. policy & assessment

def p_policy():
    fig, ax = canvas(11.8, "Assessment — deterministic policy, drift, PQC readiness, agility, risk",
                     "services/policy (37 YAML rules across 7 packs), drift, quantum, agility, universal_platform. No model decides compliance: every verdict is a rule or a formula.")
    # rule example
    box(ax, 0.4, 7.3, 6.2, 3.1, "A rule is a YAML file — BASELINE-001", None, fc=C["policy"], tfs=10)
    ax.text(0.6, 9.85, 'rule_id: "BASELINE-001"     severity: "CRITICAL"\nstandard_reference: "Internal Baseline / NIST SP 800-131A"\ncondition:\n  type: "ALGORITHM_IN_LIST"\n  parameters:\n    algorithm_list: [DES, 3DES, RC4, MD5, SHA-1,\n                     SSLv3, TLS1.0, TLS1.1]\nevaluation:\n  result_template: "FAIL"\n  message_template: "Algorithm {algorithm} is forbidden"\nremediation: "Replace DES/3DES with AES-256-GCM, RC4 with\n  ChaCha20-Poly1305, MD5/SHA-1 with SHA-256 or SHA-512"',
            fontsize=6.9, family="monospace", va="top", color=TXT, linespacing=1.25)
    # packs
    packs = [("baseline", 5, "forbidden algorithms, min RSA size,\napproved AES modes, hard-coded keys, weak TLS"),
             ("pci_dss", 2, "forbidden legacy, strong encryption"), ("nist", 6, "SP 800-131A transitions"),
             ("cnsa", 4, "CNSA 2.0 quantum-resistant suite"), ("fips", 3, "FIPS 140-3 approved"),
             ("hipaa", 2, "ePHI protection"), ("uae", 10, "UAE IA / PDPL controls")]
    ax.text(7.2, 10.35, "7 rule packs · 37 rules", fontsize=9.5, fontweight="bold")
    for i, (n, k, d) in enumerate(packs):
        r, c = divmod(i, 2)
        x = 7.0 + c * 4.35
        y = 9.3 - r * 0.78
        box(ax, x, y, 4.15, 0.66, None, f"{n}  ({k})   {d}", fc=C["policy"], fs=7.4, align="left")
    # flow row
    y = 5.0
    flow = [("normalised\nfinding", C["data"]), ("scope\nmatch", C["policy"]), ("rule\ncondition", C["policy"]), ("verdict\nPASS/WARN/FAIL", C["policy"]),
            ("approved\nexception?", C["warn"]), ("gate\ninput", C["analysis"]), ("finding row\n+ evidence link", C["data"])]
    fw = 1.95
    for i, (t, fc) in enumerate(flow):
        x = 0.4 + i * (fw + 0.25)
        box(ax, x, y, fw, 1.0, None, t, fc=fc, fs=8.2)
        if i < len(flow) - 1:
            arrow(ax, x + fw, y + 0.5, x + fw + 0.25, y + 0.5, lw=1.1)
    ax.text(0.4, 6.25, "Evaluation, per finding", fontsize=9.5, fontweight="bold")
    # analysis panels
    panels = [
        ("Drift", C["analysis"], "Approved baseline vs observed. Added / removed / changed assets, plus configuration drift ranked by the weakness it introduces. A drift event can block the CI drift gate. Baseline approval is a recorded human action."),
        ("PQC readiness", C["analysis"], "Each asset classified into a NIST IR 8547-aligned bucket (quantum-vulnerable public-key, symmetric needing larger keys, hash, already PQ-safe) and a migration horizon; harvest-now-decrypt-later exposure for long-lived data. 176 classification tests."),
        ("Crypto agility", C["analysis"], "Six-factor score per system: abstraction, configuration, dependency pinning, test coverage of crypto paths, ownership, migration history. What-if simulates swapping an algorithm before committing."),
        ("Risk and priority", C["analysis"], "Deterministic rank = business impact (revenue × criticality from business_context) × severity × inverse agility; effort estimate; BFS blast radius over the dependency graph. Weights are documented, not learned."),
        ("Exceptions", C["warn"], "Time-boxed, approved by a permitted role, audited, shown on the finding. A silent suppression is not possible; an expired exception re-fails."),
    ]
    pw = 2.94
    for i, (t, fc, b) in enumerate(panels):
        x = 0.4 + i * (pw + 0.13)
        box(ax, x, 0.35, pw, 4.0, t, b, fc=fc, fs=7.7, tfs=9.6, wrap=40, align="left")
    save(fig, "13-assessment-explained.png")


# ============================================================ 14. gate & automation

def p_gate():
    fig, ax = canvas(10.8, "Gate and act — stopping bad change, acting only with authorisation",
                     "CI gate (scripts/ci_gate.py, api ci group), SBOM gate (devsecops.sbom_gate), monitor daemon, automation engine with fail-closed approval gates, connectors.")
    # CI gate flow
    ax.text(0.4, 9.35, "CI gate — a developer's commit", fontsize=10, fontweight="bold")
    flow = [("git push", C["ext"]), ("GitHub webhook\n(HMAC verified)", C["api"]), ("scan job\n14 stages", C["collect"]),
            ("policy verdicts\n+ drift", C["policy"]), ("gate profile\npass / warn / block", C["analysis"]), ("SARIF 2.1.0 +\nPR comment +\ncommit status", C["export"]), ("exit code\n0 / 1 / 2", C["ext"])]
    fw = 2.0
    for i, (t, fc) in enumerate(flow):
        x = 0.4 + i * (fw + 0.2)
        box(ax, x, 7.9, fw, 1.2, None, t, fc=fc, fs=8.2)
        if i < len(flow) - 1:
            arrow(ax, x + fw, 8.5, x + fw + 0.2, 8.5, lw=1.1)
    ax.text(0.4, 7.55, "The gate runs as a CLI in the pipeline with its own exit codes — a gate that only lives behind an authenticated API cannot stop a build.", fontsize=8.4, color=MUTED)
    # SBOM gate
    panel(ax, 0.4, 4.3, 5.0, 2.9, "SBOM supply-chain gate",
          "python -m devsecops.sbom_gate exits 0 ok · 1 policy fail · 2 signature/verification fail · 3 input error.\nChecks: critical/high advisory allowances (offline feed you supply), denied licences (SPDX family-aware: banning GPL-3.0-only catches -or-later), unpinned dependency limits, signature required.\nVEX: exploitable with fix; not_affected only with a justified operator statement (else 422).", fs=8.2)
    panel(ax, 5.6, 4.3, 5.0, 2.9, "Monitor daemon",
          "A watch-list of repos, hosts, endpoints and cloud accounts scanned on schedule by scripts/run_monitor.py. Alert-once semantics with cooldown: a condition raises one alert until it clears, then a recovery — not a page every cycle.\nWrites monitor_events (durable) and publishes to the live stream. Runs as its own process; restartable without losing state.", fs=8.2)
    panel(ax, 10.8, 4.3, 4.8, 2.9, "Alerts and delivery",
          "Channels: in-app, email (SMTP), webhook, SIEM. Per-tenant routing by event class.\nConnectors: ServiceNow incidents (stable correlation_id, idempotent on retry), Splunk HEC, Jira REST v3, Microsoft Sentinel. Preview endpoints build the exact payload before anything is sent; tokens never leave the process.", fs=8.2)
    # automation
    ax.text(0.4, 3.85, "Automation engine — WHEN / IF / THEN with a human in the loop", fontsize=10, fontweight="bold")
    aflow = [("WHEN\nevent", C["realtime"]), ("IF\nconditions", C["policy"]), ("safety tier\nof the action", C["warn"]), ("approval gate\n(fail-closed)", C["bad"]), ("THEN\nplaybook step", C["analysis"]), ("audit +\nevent", C["integrity"])]
    fw = 2.35
    for i, (t, fc) in enumerate(aflow):
        x = 0.4 + i * (fw + 0.22)
        box(ax, x, 2.3, fw, 1.15, None, t, fc=fc, fs=8.4)
        if i < len(aflow) - 1:
            arrow(ax, x + fw, 2.875, x + fw + 0.22, 2.875, lw=1.1)
    panel(ax, 0.4, 0.3, 15.2, 1.7, "Guardrails",
          "Nothing fires without the authorisation its safety tier requires; a missing approver blocks, it never defaults to allow. Playbooks shipped: certificate rotation, network-function-down, crypto-team notify (incl. telecom NF-unreachable). Remediation output is a suggestion and a work order, never a compliance determination. SLA tracking sets remediation deadlines by severity.", fs=8.4)
    save(fig, "14-gate-and-automation-explained.png")


# ============================================================ 15. prove: exports, reports, packs

def p_prove():
    fig, ax = canvas(10.2, "Prove — the artefacts a regulator receives",
                     "services/reporting, governance, cbom.export_service. Every artefact names the snapshot or scan it was made from and carries a hash and signature.")
    items = [
        ("Signed BOM export", C["export"], "Any layer (SBOM/CBOM/HBOM/VBOM/all) of any snapshot in json, csv, cyclonedx, cyclonedx-xml, spdx, xml or pdf.\nCarries snapshot_id, integrity_sha256, signature_hmac, signature_jws (RFC 7515). Audit event per export. Schedules produce the same artefact on a timer."),
        ("Compliance reports", C["export"], "Eight templates: PCI-DSS 4.0, DORA, NIST SP 800-131A r2, FIPS 140-3, SOC 2, ISO/IEC 27001:2022, NIST SP 800-53 r5, UAE PDPL — plus custom requirement selection.\nRequirement-by-requirement, each line citing the policy evidence. Frameworks without a native rule pack are marked 'mapped' and say so."),
        ("Evidence pack", C["integrity"], "A scan's evidence records with their content and chain hashes and the manifest, in a hash-manifested archive. The manifest is the proof; prose is commentary."),
        ("Audit pack · exit report · engagement archive", C["integrity"], "The three hash-sealed engagement deliverables: the audit-export ZIP (deterministic JSON + SHA-256 manifest of the chained audit log), the exit report with the SC-1…4 scorecard, and the archive that binds scans, snapshots, exports and reports for one engagement."),
        ("Regulatory packs", C["warn"], "Banking action plan (ECB/FCA-framed), SWIFT CSP evidence, NRA per-carrier packs (json/csv), supervisor pack for a read-only regulator role. Kuwait/UAE mappings. Beta/preview — real output, shorter history."),
        ("Dashboards", C["ui"], "Command Center, Executive (posture, risk, roadmap, cost of inaction), role workspaces (CISO / analyst / OT engineer), Security Center. English + Arabic RTL for submissions."),
    ]
    cw, ch = 4.95, 2.95
    for i, (t, fc, b) in enumerate(items):
        r, c = divmod(i, 3)
        x = 0.4 + c * (cw + 0.175)
        y = 5.75 - r * (ch + 0.2)
        box(ax, x, y, cw, ch, t, b, fc=fc, fs=7.8, tfs=9.8, wrap=None, align="left")
    panel(ax, 0.4, 0.3, 15.2, 2.0, "How an auditor checks an artefact without trusting the server",
          "1. Read snapshot_id and integrity_sha256 from the export.   2. Ask for that snapshot (GET /technology-bom/versions/{n}); re-hash it; compare.   3. Ask which scans fed the snapshot; run GET /scans/{id}/verify — or recompute the chain from the evidence records with the public algorithm.   4. Check the JWS signature against the published key.   5. Check the audit-log chain for the export event.  Every step uses stored rows and public algorithms; none requires believing a dashboard.", fs=8.4, fc=C["ok"])
    save(fig, "15-prove-explained.png")


# ============================================================ 16. real-time & console

def p_realtime():
    fig, ax = canvas(10.4, "Real-time delivery and the console — how the screen stays true without refresh",
                     "services/eventstream, api/events (bus, redis_sync), routers events/stream/ws; frontend lib/realtime.tsx, lib/api.ts, lib/maturity.ts.")
    flow = [("any operation\nemit_platform_event()", C["api"]), ("persist\nmonitor_events\n(durable, replayable)", C["data"]), ("EventBus\nin-process,\nper-subscriber queues", C["realtime"]),
            ("DB tailer\npicks up worker +\nmonitor rows", C["realtime"]), ("Redis federation\nacross api nodes", C["realtime"]), ("SSE / WebSocket\nLast-Event-ID resume", C["realtime"]), ("browser\none subscription,\nfan-out to pages", C["ui"])]
    fw = 2.0
    for i, (t, fc) in enumerate(flow):
        x = 0.4 + i * (fw + 0.2)
        box(ax, x, 7.5, fw, 1.5, None, t, fc=fc, fs=7.9)
        if i < len(flow) - 1:
            arrow(ax, x + fw, 8.25, x + fw + 0.2, 8.25, lw=1.1)
    panel(ax, 0.4, 4.6, 7.4, 2.5, "Why three hops",
          "The bus is in-process, so events from the worker and monitor processes would never reach a browser connected to the api — the DB tailer closes that gap by reading monitor_events. Several api instances behind nginx would each see only their own bus — Redis federation closes that one. Persisting first means a disconnected client can resume with Last-Event-ID and the Activity page can replay history.", fs=8.4)
    panel(ax, 8.2, 4.6, 7.4, 2.5, "Overflow is explicit",
          "A slow subscriber gets an events.dropped advice and reconnects with resume rather than silently missing events. Cooldown dedup keeps recoveries from spamming. Event families: scan.*, job.*/stage.*, finding.*, drift.*, alerts.*, live_scan.*, technology_bom.*, automation.*.", fs=8.4)
    panel(ax, 0.4, 0.3, 5.0, 4.0, "One API client",
          "lib/api.ts adds the bearer token, refreshes on 401 once, shapes errors uniformly, and is the only way pages reach /api/v1. Pages never call fetch directly, which is what makes them smoke-testable against a mocked API.", fs=8.4)
    panel(ax, 5.5, 0.3, 5.0, 4.0, "Nothing fabricated",
          "Every panel renders zero / empty / offline until a real scan produces evidence; there is no seeded demo data in the product. Unreachable services show as unreachable. This is a product rule (platform_scope.py), not a styling choice.", fs=8.4)
    panel(ax, 10.6, 0.3, 5.0, 4.0, "Labelled maturity",
          "lib/maturity.ts is generated from shared_models/capability_maturity.py. Beta and Preview badges appear in the sidebar and page header, so 33 GA surfaces are not presented as equal to 30 beta and 8 preview ones. 71 pages, 6 sections, EN + AR, all smoke-tested to mount.", fs=8.4)
    save(fig, "16-realtime-and-console-explained.png")


# ============================================================ 17. identity & access explained

def p_identity():
    fig, ax = canvas(10.6, "Identity, roles and the request path — explained",
                     "api/security (passwords, oidc, rbac, tenancy), api/middleware. Fail-closed everywhere: no permission match → 403; no approver → blocked; unsafe config → no boot.")
    # roles table
    roles = [("superadmin", "platform configuration, users, everything"), ("ciso", "all security data, API keys, approvals"), ("security_analyst", "scans, findings, drift, baselines"),
             ("developer", "own repos' scans and gate results"), ("auditor", "read-only + audit export"), ("business_owner", "own systems' posture and impact"),
             ("scanner", "machine role: submit scan results"), ("readonly", "read everything permitted, change nothing"), ("supervisor", "read-only for regulators / external review")]
    ax.text(0.4, 9.35, "9 RBAC roles (aliases: admin → superadmin, viewer → readonly)", fontsize=10, fontweight="bold")
    for i, (r, d) in enumerate(roles):
        rr, c = divmod(i, 3)
        x = 0.4 + c * 5.1
        y = 8.3 - rr * 0.85
        box(ax, x, y, 4.9, 0.72, None, f"{r}  —  {d}", fc=C["policy"], fs=7.9, align="left")
    # request path
    ax.text(0.4, 5.85, "Every request", fontsize=10, fontweight="bold")
    path = ["request-id", "security\nheaders", "rate limit\n600/min/identity", "authenticate\n(session / key / IdP)", "require_permission\n(RBAC)", "ABAC\nattributes", "tenancy\nscope", "route", "audit_log\n(chained)", "platform\nevent"]
    fw = 1.42
    for i, t in enumerate(path):
        x = 0.4 + i * (fw + 0.1)
        box(ax, x, 4.7, fw, 0.95, None, t, fc=C["api"] if i < 8 else C["integrity"], fs=7.2)
        if i < len(path) - 1:
            arrow(ax, x + fw, 5.175, x + fw + 0.1, 5.175, lw=0.9)
    panel(ax, 0.4, 0.3, 5.0, 4.05, "How people sign in",
          "Local: Argon-class password hash, TOTP MFA, lockout, self-service reset over SMTP.\nOIDC: token relay, authorization-code, and PKCE for public clients; RS256 id_tokens verified against JWKS (discovery, or a file in air-gap); issuer, audience and expiry enforced; the PKCE verifier rides a callback-scoped HttpOnly cookie, never the front-channel state.\nSAML 2.0 SP: enveloped-signature verification, InResponseTo binding.\nLDAP/AD: bind + explicit group → role map.\nSCIM 2.0: provisioning from a directory.", fs=8.0)
    panel(ax, 5.5, 0.3, 5.0, 4.05, "How machines sign in",
          "Scoped API keys with rotation and IP allow-lists (migration 0052). The scanner role can submit results and nothing else. GitHub and registry webhooks are HMAC-verified against a per-deployment secret; the production guard refuses the demo secret.\nRate limiting is per identity, so one noisy key cannot starve the console — the 20-user load test shows exactly this: 78k requests, 0 errors, the budget was the ceiling.", fs=8.0)
    panel(ax, 10.6, 0.3, 5.0, 4.05, "What no integration can do",
          "Mint a superadmin: SCIM, LDAP and OIDC auto-provision as viewer/readonly only; elevation is a superadmin action, audited.\nWeaken production: ENVIRONMENT=production refuses SQLite, demo SECRET_KEY, weak webhook secret, CORS_ORIGINS=*, plaintext ADMIN_PASSWORD — tested in both directions and runnable standalone (scripts/check_prod_guard.py).\nSkip the audit log: it is written by middleware, not by the route.", fs=8.0, fc=C["ok"])
    save(fig, "17-identity-explained.png")


# ============================================================ 18. deployment & operations explained

def p_operations():
    fig, ax = canvas(11.6, "Deployment and operations — explained",
                     "docker-compose.yml, docker-compose.prod.yml, deploy/staging/staging-up.sh, deploy/ha, scripts/db_*.sh, docs/runbooks. Postgres/Redis/Neo4j are never published in production.")
    modes = [
        ("Development", C["ui"], "docker compose up, or make api / make worker with SQLite.\nHost ports 55432 / 56379 / 57687 for tooling; docs on; admin/cryptoscan.\nNever ENVIRONMENT=production."),
        ("Staging without Docker", C["collect"], "deploy/staging/staging-up.sh up: embedded PostgreSQL 16 (pgserver) + redis-server + api :8010 + worker + monitor, ENVIRONMENT=production, ALLOW_SQLITE=false, generated secrets.\nUp in ~8 s. Target for soak, burn-in and the Postgres migration test. restart-apps redeploys code, keeps data."),
        ("Production (compose overlay)", C["ok"], "scripts/deploy_prod.sh: nginx :80/:443 only; hashed admin password; explicit CORS; 2 API workers; docs off; Secure cookies; TLS certs in deploy/nginx/certs.\nGuard check before boot; smoke test after (make smoke)."),
        ("Air-gap", C["infra"], "JWKS from file, advisory and fingerprint feeds imported, no phone-home. Same images; admin-guide/air-gap-install.md."),
        ("HA (designed)", C["warn"], "deploy/ha: readiness drains, read-only mirrors, region failover drills. Multi-active control plane not exercised without real infrastructure — stated, not claimed."),
    ]
    cw = 2.92
    for i, (t, fc, b) in enumerate(modes):
        x = 0.4 + i * (cw + 0.15)
        box(ax, x, 6.9, cw, 3.4, t, b, fc=fc, fs=7.4, tfs=9.2, wrap=None, align="left")
    ops = [
        ("Health and metrics", "/health, /readyz (drain semantics), /metrics for Prometheus; Grafana dashboard in infra/monitoring; structured logs with request-id and trace middleware; System Health page reads the same endpoints."),
        ("Backups and recovery", "scripts/db_backup.sh: pg dump + sha256 manifest + retention (systemd timer); db_restore.sh; PITR drill and restore drill with recorded results; evidence backup verify; DR runbook. A backup on the same disk is not a backup — the runbook says so."),
        ("Migrations", "Alembic 0001–0060, contiguous (release_check.py enforces). Applied and tested on a real PostgreSQL 16 (test_migration_chain_postgres.py, CI db-migration.yml). Before 2026-09-23 the chain did not apply on Postgres — found by the first staging bring-up."),
        ("Release", "scripts/release_check.py: VERSION == API version == v tag, dated CHANGELOG, migrations contiguous, prod guard intact. make security-scan (pip-audit, ruff, secret hygiene), make sbom for the platform's own SBOM."),
        ("Soak, burn-in, load", "scripts/soak.py cycles the real pipeline and samples RSS/fds/PG connections/queue; soak_report.py renders evidence. burn_in.py proves integrations. load_test.py probes the API tier. Evidence under docs/soak-evidence/."),
    ]
    for i, (t, b) in enumerate(ops):
        x = 0.4 + i * (cw + 0.15)
        box(ax, x, 2.2, cw, 4.4, t, b, fc=C["panel"], fs=7.4, tfs=9.2, wrap=None, align="left")
    panel(ax, 0.4, 0.3, 15.2, 1.6, "Operator's checklist lives in one place",
          "docs/ops/production-checklist.md — secrets and guard, transport, post-deploy verification (migrations at head, staging rehearsal, smoke), data safety, supply chain, CI activation, observability, banking readiness, soak evidence, recovery and change control. Every box links the exact command or file.", fs=8.4)
    save(fig, "18-operations-explained.png")


# ============================================================ 19. testing & quality explained

def p_testing():
    fig, ax = canvas(9.6, "Testing and quality — how the product proves itself",
                     "conftest.py, pytest.ini, Makefile, frontend/vitest.config.ts, deploy/staging, scripts/soak.py. 4,808 backend test functions + frontend suite + live PostgreSQL test + soak.")
    tiers = [
        ("make test  — the gate", C["ok"], "4,808 tests in one hermetic, parallel session (pytest-xdist, --dist loadfile), ~8 min on 2 cores.\nHermetic: pytest-socket blocks every non-loopback socket, so a test that reaches for GitHub, a cloud API or SMTP fails instantly with SocketBlockedError instead of hanging on DNS — the failure that used to keep the suite out of CI.\n--import-mode=importlib so duplicate test basenames across services do not collide; 120 s per-test timeout."),
        ("make test-frontend", C["ok"], "tsc --noEmit, then vitest + Testing Library on jsdom with fetch mocked: the app boots and routes; every one of the 71 pages mounts without throwing; ui primitives; EN/AR i18n keys resolve; api client auth/refresh/error shaping; maturity lookup matches the generated table.\nSmoke-level by design — a page that throws on mount cannot ship."),
        ("make test-live", C["warn"], "Tests marked live: real network or a real PostgreSQL. test_migration_chain_postgres.py proves the 60-revision chain applies on a fresh database, no uuid columns remain where the ORM says String(36), migrated schema == models, downgrade -1 and back. Skips without a server; staging-up.sh provides one."),
        ("Soak · burn-in · load", C["collect"], "scripts/soak.py: trigger → wait → verify chain → every dashboard → signed export → SSE probe → sample RSS / fds / PG connections / Redis queue, every cycle, for days; failures recorded, never skipped.\nscripts/burn_in.py: GitHub signed-webhook round trip, live TLS, SMTP, Neo4j, cloud, container — PASS / FAIL / honest SKIP.\nscripts/load_test.py: bank-estate-shaped traffic, honest exit on error rate."),
    ]
    cw = 3.72
    for i, (t, fc, b) in enumerate(tiers):
        x = 0.4 + i * (cw + 0.107)
        box(ax, x, 3.6, cw, 4.6, t, b, fc=fc, fs=7.7, tfs=9.6, wrap=50, align="left")
    panel(ax, 0.4, 0.3, 7.5, 3.0, "What the first real-database run found (2026-09-23)",
          "Dev and tests built the schema with create_all on SQLite, so three defects survived 4,000+ green tests: the migration chain did not apply on a fresh PostgreSQL (0011); with that patched every scan failed at the policy stage (15 uuid columns vs String(36)); and every job leaked its workspace directory. All fixed with regression tests. The lesson is encoded: the Postgres chain test exists, and the staging stack is one command.", fs=8.3, fc=C["bad"])
    panel(ax, 8.1, 0.3, 7.5, 3.0, "Quality rules the code follows",
          "No AI decides compliance. Unknowns are reported with a reason. Unchecked ≠ clean (an SBOM with no advisories says whether a feed was applied). Every claim is verifiable after the fact by someone who does not trust the platform. Repositories, not raw SQL, in routers. Injected clients so scanners test without network. ruff + pip-audit + secret hygiene in make security-scan.", fs=8.3)
    save(fig, "19-testing-explained.png")


# ============================================================ 20. personas & journeys

def p_journeys():
    fig, ax = canvas(11.2, "Who uses it and how — six journeys through the same platform",
                     "Each journey touches the same evidence and inventory; roles decide what each person can see and change.")
    journeys = [
        ("Security analyst — a new finding", C["collect"], ["Activity shows job.completed", "Findings: filter CRITICAL, open row", "Evidence link → chain record, verify PASS", "Assign remediation template → work order", "Approve or request exception (audited)", "Baseline re-approved after fix; drift clears"]),
        ("Developer — a blocked build", C["api"], ["push → CI gate runs scan", "exit 1: SARIF in GitHub code scanning", "PR comment: rule, file:line, remediation", "fix; push; gate passes", "SBOM diff shows the changed component", "nothing else in the product needed"]),
        ("CISO — quarterly posture", C["analysis"], ["Executive: unified risk, trend", "PQC Readiness: buckets, HNDL exposure", "Migration: projects, velocity", "Priorities: rank × business impact", "Compliance report per framework", "Signed export for the board pack"]),
        ("Auditor — an engagement", C["integrity"], ["supervisor / auditor role, read-only", "Evidence: scans, verify each chain", "CBOM snapshot for the period", "Compliance report, requirement by requirement", "audit-export pack (chained audit log)", "exit report with SC-1…4 scorecard"]),
        ("Operator — a normal week", C["infra"], ["System Health: /readyz, DB, queue", "Alerts: certificate expiring, drift", "monitor daemon rescans watch-list", "nightly backup + manifest; restore drill", "soak report reviewed", "release_check before upgrade"]),
        ("Machine — CI and connectors", C["realtime"], ["API key with scanner scope", "webhook (HMAC) → scan", "GraphQL / REST for inventory", "SCIM provisions users", "ServiceNow incident (idempotent)", "SIEM receives alerts.*"]),
    ]
    cw, ch = 4.95, 4.3
    for i, (t, fc, steps) in enumerate(journeys):
        r, c = divmod(i, 3)
        x = 0.4 + c * (cw + 0.175)
        y = 5.55 - r * (ch + 0.2)
        box(ax, x, y, cw, ch, t, None, fc=fc, tfs=9.8)
        for j, s in enumerate(steps):
            sy = y + ch - 0.75 - j * 0.56
            ax.add_patch(FancyBboxPatch((x + 0.25, sy - 0.2), cw - 0.5, 0.42, boxstyle="round,pad=0.01,rounding_size=0.08", lw=0.8, ec=EDGE, fc="white", zorder=3))
            ax.text(x + 0.42, sy, f"{j + 1}.  {s}", fontsize=7.8, va="center", color=TXT, zorder=4)
    panel(ax, 0.4, 0.3, 15.2, 0.6, "", "")
    ax.text(0.55, 0.6, "Every journey reads the same evidence_records, crypto_assets and snapshots. Roles change what is visible and what can be changed; nothing changes what was recorded.", fontsize=8.6, va="center", color=TXT)
    save(fig, "20-user-journeys.png")


# ============================================================ 21. data model

def p_datamodel():
    fig, ax = canvas(11.0, "Data model — the tables that matter and how they relate",
                     "services/database/db/models (102 tables). Arrows read 'references'. PostgreSQL in production; Alembic 0001–0060.")
    def t(x, y, name, cols, fc, w=3.0, h=1.45):
        box(ax, x, y, w, h, name, cols, fc=fc, fs=7.2, tfs=8.4, align="left", wrap=None)
    # row 1: jobs & scans
    t(0.4, 8.0, "scan_jobs", "id · status QUEUED/RUNNING/COMPLETED/FAILED · repo_url · branch · progress (stages, %, logs) · scan_id · error_message · created/started/completed_at", C["data"], w=3.6)
    t(4.4, 8.0, "scans", "id · repo · commit · started/completed · manifest_hash · status · finding counts · cbom", C["data"])
    t(7.8, 8.0, "evidence_records", "id · scan_id · content (canonical JSON) · content_hash · chain_hash · sequence · created_at", C["integrity"], w=3.4)
    t(11.6, 8.0, "verification_log", "id · scan_id · result PASS/FAIL · chain_intact · first_broken_index · verified_at", C["integrity"], w=4.0)
    arrow(ax, 4.0, 8.7, 4.4, 8.7); arrow(ax, 7.4, 8.7, 7.8, 8.7); arrow(ax, 11.2, 8.7, 11.6, 8.7)
    # row 2: inventory
    t(0.4, 5.8, "systems", "id · name · owner · environment · criticality · business_process", C["data"])
    t(3.8, 5.8, "crypto_assets", "id · algorithm · key_size · mode · purpose · libraries · file_path · confidence · quantum_bucket · normalized_*", C["data"], w=3.6)
    t(7.8, 5.8, "crypto_asset_evidence", "asset_id → crypto_assets · evidence_id → evidence_records (many-to-many: one asset, N observations)", C["data"], w=3.4)
    t(11.6, 5.8, "certificates · hardware · vendors", "certificate: fingerprint_sha256, subject, expiry, revocation · hardware: manufacturer, model, firmware, hsm/tpm · vendor: product, lifecycle, risk", C["data"], w=4.0)
    arrow(ax, 7.8, 6.5, 7.4, 6.5); arrow(ax, 9.5, 7.25, 9.5, 8.0)
    arrow(ax, 3.8, 6.2, 3.4, 6.2); ax.text(3.6, 6.32, "system_asset", fontsize=6.4, ha="center", color="#7A8797")
    # row 3: assessment
    t(0.4, 3.6, "baselines", "id · system/repo · approved_by · approved_at · state (fingerprint of approved assets)", C["policy"])
    t(3.8, 3.6, "drift_events", "id · baseline_id · scan_id · kind ADDED/REMOVED/CHANGED · severity · detail", C["analysis"], w=3.6)
    t(7.8, 3.6, "gate_evaluations · exceptions", "gate: scan_id, profile, verdict, blocking rules · exception: rule_id, scope, approved_by, expires_at", C["analysis"], w=3.4)
    t(11.6, 3.6, "system_dependency · graphs", "parent_id → child_id edges; blast radius; snapshot of the graph per scan", C["analysis"], w=4.0)
    arrow(ax, 3.4, 4.3, 3.8, 4.3); arrow(ax, 5.6, 5.05, 5.6, 5.8)
    # row 4: bom, events, identity
    t(0.4, 1.4, "technology_bom_snapshots", "version · snapshot_id · fingerprint · parent_fingerprint · state · diff · environment · created_by", C["bom"], w=3.6)
    t(4.4, 1.4, "tbom_export_schedules / _runs", "schedule: frequency, fmt, layer, filters, next_run_at · run: snapshot_id, content_sha256, signature_hmac, artifact, audit_event_id", C["export"], w=3.6)
    t(8.4, 1.4, "monitor_events · audit_log", "event: kind, payload, target, ts (durable stream) · audit: actor, action, prev_hash, hash (chained)", C["realtime"], w=3.4)
    t(12.2, 1.4, "users · api_keys · tenants", "user: password_hash, mfa, role, tenant · api_key: scope, allowlist, rotated_at · tenant: invites", C["api"], w=3.4)
    arrow(ax, 2.2, 2.85, 2.2, 3.6, color="#7A8797"); arrow(ax, 4.0, 2.1, 4.4, 2.1)
    ax.text(0.4, 0.55, "Reading the arrows: a scan job produces a scan; a scan owns evidence records; evidence links to assets through crypto_asset_evidence; baselines and drift reference scans; snapshots are built from the inventory; every table change emits a monitor_event and, if it is an action, an audit_log row.",
            fontsize=8.2, color=TXT, wrap=True, va="center")
    save(fig, "21-data-model.png")


if __name__ == "__main__":
    p_collection()
    p_evidence()
    p_bom()
    p_policy()
    p_gate()
    p_prove()
    p_realtime()
    p_identity()
    p_operations()
    p_testing()
    p_journeys()
    p_datamodel()
