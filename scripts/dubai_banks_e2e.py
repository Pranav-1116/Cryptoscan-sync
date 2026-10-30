#!/usr/bin/env python3
"""Dubai banks — every bank's estate through the whole product, then the CBUAE supervisory view over all of them.

    python scripts/dubai_banks_e2e.py --md docs/accuracy/DUBAI-BANKS-E2E.md --json docs/accuracy/dubai-banks-e2e.json [--backend postgresql]

What it does, for six *representative* Dubai-headquartered banks (Emirates NBD, Mashreq, Dubai Islamic Bank, Commercial
Bank of Dubai, Emirates Islamic, Commercial Bank International — plus ENBD's DIFC branch as a DFSA-regulated entity):

1. composes each bank's estate from the blind-labelled corpus waves (UAE / GCC / Saudi-profile technology / PQC pilot)
   with a bank-specific ``cryptoscan-systems.yml`` (systems, criticality, depends_on, compliance_scopes, legal_entity);
2. registers the banks in the group legal-entity registry (CBUAE / DFSA);
3. runs every estate through ``PipelineRunner`` into ONE database (SQLite or PostgreSQL);
4. scores each bank's evidence rows against the labels (precision / recall / F1, same unit as the corpus benchmark);
5. reads everything back through the real HTTP API — bank analyst: scans, findings, cascade systems; supervisor:
   ``/banking/group``, ``/banking/group/supervisor-pack``, ``/banking/group/roadmap``; a platform operator:
   ``/accuracy/field``; readonly cannot publish triage;
6. writes a Markdown + JSON report.

**Honesty.** These are synthetic estates written from public standards — not the banks' code, configuration or key
material; no bank system was accessed. The bank names only fix the *shape* (conventional / Islamic / digital / DIFC
branch). Numbers describe the product on code of that shape.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for p in ("shared/shared_models", "services/scanner", "services/scanner/tests", "services/worker", "services/database", "services/api",
          "services/policy", "services/evidence", "services/normalization", "services/cbom", "services/deduplication", "services/graph_engine",
          "services/agility", "services/drift", "services/business_context", "services/compliance", "services/control_plane"):
    if str(ROOT / p) not in sys.path:
        sys.path.insert(0, str(ROOT / p))

from accuracy.corpus import canonical_families, spec_families  # noqa: E402
from accuracy import corpus_wave16_saudi_bank, corpus_wave17_pqc, corpus_wave18_uae_bank, corpus_wave19_gcc_bank  # noqa: E402

FAIL = {"NON_COMPLIANT", "FAIL", "VIOLATION"}
JWT_EXPANSION = {"RSA", "ECDSA", "HMAC", "SHA-256", "SHA-384", "SHA-512", "ED25519"}

# ----------------------------------------------------------------------------------------------- legal entities
ENTITIES = [
    {"code": "enbd", "name": "Emirates NBD (representative estate)", "jurisdiction": "ae", "regulator": "CBUAE", "country": "AE", "notes": "conventional, group parent; PQC pilot"},
    {"code": "enbd-difc", "name": "Emirates NBD — DIFC branch (representative)", "jurisdiction": "difc", "regulator": "DFSA", "parent": "enbd", "country": "AE"},
    {"code": "mashreq", "name": "Mashreq (representative estate)", "jurisdiction": "ae", "regulator": "CBUAE", "country": "AE", "notes": "digital-forward"},
    {"code": "dib", "name": "Dubai Islamic Bank (representative estate)", "jurisdiction": "ae", "regulator": "CBUAE", "country": "AE", "notes": "Islamic"},
    {"code": "cbd", "name": "Commercial Bank of Dubai (representative estate)", "jurisdiction": "ae", "regulator": "CBUAE", "country": "AE"},
    {"code": "ei", "name": "Emirates Islamic (representative estate)", "jurisdiction": "ae", "regulator": "CBUAE", "parent": "enbd", "country": "AE"},
    {"code": "cbi", "name": "Commercial Bank International (representative estate)", "jurisdiction": "ae", "regulator": "CBUAE", "country": "AE"},
]

# ----------------------------------------------------------------------------------------------- estate shapes
# system → (path, files, scopes, criticality, entity-override?)   files are corpus file names from waves 16–19
W = {"uae": corpus_wave18_uae_bank, "gcc": corpus_wave19_gcc_bank, "sa": corpus_wave16_saudi_bank, "pqc": corpus_wave17_pqc}
BANKS: dict[str, dict[str, Any]] = {
    "enbd": {
        "systems": {
            "CARD-SWITCH": ("cards", {"UaeSwitchPinTranslator.java", "JaywanTokenizer.kt", "CBHIMPIN.cbl"}, ["CBUAE", "PAYMENT", "CARD"], "critical"),
            "AANI-IPP": ("aani", {"AaniPacs008Signer.java", "aaniProxyPay.ts", "mq-aep-channel.mqsc"}, ["CBUAE", "PAYMENT"], "critical"),
            "OPEN-FINANCE": ("open-finance", {"NebrasFapiClient.cs", "openBankingJws.js"}, ["CBUAE", "CUSTOMER-FACING"], "high"),
            "IDENTITY": ("identity", {"UaePassSamlValidator.cs", "EmiratesIdVgClient.cs", "UaePassLogin.swift"}, ["PDPL", "PERSONAL_DATA"], "high"),
            "CORE-KYC": ("core", {"T24OfsSessionCipher.java", "pkg_kyc_pii.pks", "legacy_customer_pwd.sql", "tde_uae_core.sql", "CBEIDENC.cbl", "iban_ae_validate.py"}, ["PDPL", "PERSONAL_DATA"], "critical"),
            "PQC-PILOT": ("pqc-pilot", {"HybridKemHandshake.java", "BcPqcKeyFactory.java", "openssl-pqc.cnf", "nginx-pqc.conf"}, ["CBUAE"], "medium"),
            "BRANCH-INFRA": ("infra", {"branch-sslvpn.conf", "rdgateway.reg", "cbuae-tls-baseline.conf", "f5-clientssl.tmsh"}, ["CBUAE", "REMOTE-ACCESS"], "medium"),
            "DIFC-WEALTH": ("difc-wealth", {"pkg_customer_pii.pks", "AlwaysEncryptedIban.cs", "README.ar.md"}, ["DIFC", "PERSONAL_DATA"], "high", "enbd-difc"),
        },
        "depends_on": {"CARD-SWITCH": ["CORE-KYC"], "AANI-IPP": ["CORE-KYC"], "OPEN-FINANCE": ["IDENTITY", "CORE-KYC"], "DIFC-WEALTH": ["CORE-KYC"]},
    },
    "mashreq": {
        "systems": {
            "NEO-MOBILE": ("mobile", {"SecureStore.kt", "PinnedClient.kt", "DeviceBinding.swift", "QmpDeviceBinding.swift"}, ["CBUAE", "CUSTOMER-FACING"], "high"),
            "OPEN-FINANCE": ("open-finance", {"NebrasFapiClient.cs", "openBankingBh.ts", "otpService.ts"}, ["CBUAE", "CUSTOMER-FACING"], "high"),
            "IDENTITY": ("identity", {"UaePassSamlValidator.cs", "NasOidcValidator.cs", "i18n.ar-AE.json"}, ["PDPL", "PERSONAL_DATA"], "high"),
            "AANI-IPP": ("aani", {"AaniPacs008Signer.java", "FawranIso20022Signer.java"}, ["CBUAE", "PAYMENT"], "critical"),
            "CORE": ("core", {"pkg_kyc_pii.pks", "tde_uae_core.sql", "iban_tokenizer.go", "QmpWalletTokenService.cs"}, ["PDPL", "PERSONAL_DATA"], "critical"),
            "EDGE-INFRA": ("infra", {"cbuae-tls-baseline.conf", "cisco-asa-ssl.cfg", "paloalto-ssl-decrypt.set"}, ["CBUAE", "REMOTE-ACCESS"], "medium"),
        },
        "depends_on": {"NEO-MOBILE": ["IDENTITY", "CORE"], "OPEN-FINANCE": ["IDENTITY", "CORE"], "AANI-IPP": ["CORE"]},
    },
    "dib": {
        "systems": {
            "CARD-SWITCH": ("cards", {"UaeSwitchPinTranslator.java", "HimyanPinBlockTranslator.java", "MadaCvvService.java"}, ["CBUAE", "PAYMENT", "CARD"], "critical"),
            "AANI-IPP": ("aani", {"AaniPacs008Signer.java", "mq-aep-channel.mqsc"}, ["CBUAE", "PAYMENT"], "critical"),
            "CORE-ISLAMIC": ("core", {"T24OfsSessionCipher.java", "CBEIDENC.cbl", "CBPINVER.cbl", "tde_uae_core.sql", "legacy_customer_pwd.sql"}, ["PDPL", "PERSONAL_DATA"], "critical"),
            "KYC": ("kyc", {"pkg_kyc_pii.pks", "EmiratesIdVgClient.cs", "qid_validate.py"}, ["PDPL", "PERSONAL_DATA"], "high"),
            "MOBILE": ("mobile", {"UaePassLogin.swift", "BenefitPaySdk.kt"}, ["CBUAE", "CUSTOMER-FACING"], "high"),
            "INFRA": ("infra", {"branch-sslvpn.conf", "krb5.conf", "legacy-branch-gpo.inf"}, ["CBUAE", "REMOTE-ACCESS"], "medium"),
        },
        "depends_on": {"CARD-SWITCH": ["CORE-ISLAMIC"], "AANI-IPP": ["CORE-ISLAMIC"], "MOBILE": ["KYC"]},
    },
    "cbd": {
        "systems": {
            "CARD-SWITCH": ("cards", {"UaeSwitchPinTranslator.java", "JaywanTokenizer.kt"}, ["CBUAE", "PAYMENT", "CARD"], "critical"),
            "CORE": ("core", {"pkg_kyc_pii.pks", "tde_uae_core.sql", "AlwaysEncryptedIban.cs", "iban_ae_validate.py"}, ["PDPL", "PERSONAL_DATA"], "critical"),
            "WPS-FTA": ("reg-filing", {"wps_sif_uploader.py", "fta_peppol_as4.py", "wps-schedule.yaml"}, ["CBUAE"], "medium"),
            "TREASURY": ("treasury", {"qcb_fx_report_signer.py", "SarieLauSigner.java"}, ["CBUAE", "SWIFT"], "high"),
            "INFRA": ("infra", {"rdgateway.reg", "cbuae-tls-baseline.conf", "was-ssl.properties"}, ["CBUAE", "REMOTE-ACCESS"], "medium"),
        },
        "depends_on": {"CARD-SWITCH": ["CORE"], "WPS-FTA": ["CORE"], "TREASURY": ["CORE"]},
    },
    "ei": {
        "systems": {
            "MOBILE": ("mobile", {"SecureStore.kt", "DeviceBinding.swift", "UaePassLogin.swift"}, ["CBUAE", "CUSTOMER-FACING"], "high"),
            "CARDS": ("cards", {"JaywanTokenizer.kt", "MadaPinTranslator.java"}, ["CBUAE", "PAYMENT", "CARD"], "critical"),
            "CORE": ("core", {"tde_uae_core.sql", "pkg_kyc_pii.pks", "CBEIDENC.cbl"}, ["PDPL", "PERSONAL_DATA"], "critical"),
            "INFRA": ("infra", {"cbuae-tls-baseline.conf", "mq-aep-channel.mqsc", "benefit-sftp-sshd_config"}, ["CBUAE", "REMOTE-ACCESS"], "medium"),
        },
        "depends_on": {"MOBILE": ["CORE"], "CARDS": ["CORE"]},
    },
    "cbi": {
        "systems": {
            "CORE": ("core", {"legacy_customer_pwd.sql", "legacy_cpr_hash.sql", "tde_uae_core.sql", "pkg_kyc_pii.pks"}, ["PDPL", "PERSONAL_DATA"], "critical"),
            "WPS": ("reg-filing", {"wps_sif_uploader.py", "wps-schedule.yaml"}, ["CBUAE"], "medium"),
            "IDENTITY": ("identity", {"EmiratesIdVgClient.cs"}, ["PDPL", "PERSONAL_DATA"], "high"),
            "INFRA": ("infra", {"branch-sslvpn.conf", "legacy-branch-gpo.inf", "rdgateway.reg"}, ["CBUAE", "REMOTE-ACCESS"], "medium"),
        },
        "depends_on": {"IDENTITY": ["CORE"], "WPS": ["CORE"]},
    },
}


# ----------------------------------------------------------------------------------------------- corpus access
def _all_cases() -> dict[str, tuple[str, str, set[str], str]]:
    """file name → (lang, code, expected families, category) across the four waves (names are unique across them)."""
    out: dict[str, tuple[str, str, set[str], str]] = {}
    for mod in W.values():
        mod.register(lambda lang, fname, code, expected, category="positive": out.__setitem__(fname, (lang, code.strip("\n") + "\n", set(expected), category)))
    return out


def write_estate(root: Path, bank: str, cases: dict[str, tuple[str, str, set[str], str]]) -> tuple[Path, dict[str, set[str]]]:
    spec = BANKS[bank]
    repo = root / f"{bank}-estate"
    labels: dict[str, set[str]] = {}
    lines = [f"legal_entity: {bank}", "systems:"]  # one bank per repository; a branch under another regulator overrides per system
    for name, row in spec["systems"].items():
        path, files, scopes, crit = row[0], row[1], row[2], row[3]
        entity = row[4] if len(row) > 4 else None
        for f in files:
            lang, code, expected, _cat = cases[f]
            rel = Path(path) / f
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(code, encoding="utf-8")
            labels[str(rel)] = expected
        lines.append(f"  - system: {name}\n    paths: [{path}/**]\n    criticality: {crit}\n    owner: {name.lower()}@{bank}.example\n    compliance_scopes: {scopes}" + (f"\n    legal_entity: {entity}" if entity else ""))
        if spec["depends_on"].get(name):
            lines.append(f"    depends_on: {spec['depends_on'][name]}")
    (repo / "cryptoscan-systems.yml").write_text("\n".join(lines) + "\n")
    return repo, labels


# ----------------------------------------------------------------------------------------------- scoring
def _path(row) -> str:
    return str(row.file_path).split("!", 1)[0].lstrip("./")


def _families(row) -> set[str]:
    fd = row.finding_data if isinstance(row.finding_data, dict) else {}
    crypto = fd.get("crypto") or {}
    fams = canonical_families(crypto.get("algorithm") or row.algorithm)
    lang = str(((fd.get("source") or {}).get("language")) or "").upper()
    if lang in {"JAVA", "KOTLIN", "SCALA"}:
        fams |= spec_families(crypto.get("raw_transformation"))
    return fams


def score(rows, labels: dict[str, set[str]]) -> dict[str, Any]:
    predicted: dict[str, set[str]] = {p: set() for p in labels}
    for r in rows:
        if _path(r) in predicted:
            predicted[_path(r)] |= _families(r)
    tp = fn = fp = 0
    misses = []
    for path, exp in labels.items():
        got = predicted[path]
        if "JWT" in exp:
            got = got - JWT_EXPANSION | (got & exp)
        tp += len(exp & got)
        fn += len(exp - got)
        fp += len(got - exp)
        if exp ^ got:
            misses.append({"file": path, "fn": sorted(exp - got), "fp": sorted(got - exp)})
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"files": len(labels), "tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0, "exact_files": len(labels) - len(misses), "misses": misses}


def _rules(row, status: set[str]) -> set[str]:
    ev = row.policy_evaluation or {}
    return {x["rule_id"] for x in ev.get("rules_evaluated", []) if str(x.get("evaluation_result", "")).upper() in status}


# ----------------------------------------------------------------------------------------------- run
def run(backend: str = "sqlite", workdir: Path | None = None) -> dict[str, Any]:
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from api.dependencies import get_db_session
    from db.connection.session import Base
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan
    from db.models.system import System
    from db.testing import drop_engine, estate_engine
    from worker.pipeline.pipeline_runner import PipelineRunner

    work = workdir or Path(tempfile.mkdtemp(prefix="dubai-banks-"))
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    registry = work / "group_entities.json"
    registry.write_text(json.dumps({"entities": ENTITIES}, indent=2))
    os.environ["CRYPTOSCAN_GROUP_ENTITIES"] = str(registry)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = estate_engine(backend)
    if engine is None:
        raise SystemExit("no PostgreSQL available (CRYPTOSCAN_TEST_DATABASE_URL or pip install pgserver)")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    report: dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "backend": backend, "banks": {}, "entities": ENTITIES}
    try:
        cases = _all_cases()
        runner = PipelineRunner()
        per_bank_rows: dict[str, list] = {}
        for bank in BANKS:
            repo, labels = write_estate(work, bank, cases)
            ws = work / f"ws-{bank}"
            ws.mkdir(exist_ok=True)
            scan_id = runner.run(job_id=f"job-{bank}", target_repo=f"local://{repo}", target_branch="main", triggered_by=f"{bank}-pilot", db=session, workspace_dir=str(ws))
            session.commit()
            scan = session.get(Scan, scan_id)
            rows = session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars().all()
            per_bank_rows[bank] = rows
            fails: Counter = Counter()
            fired_by_system: dict[str, set[str]] = defaultdict(set)
            for r in rows:
                for rid in _rules(r, FAIL):
                    fails[rid] += 1
                top = _path(r).split("/")[0]
                for name, row in BANKS[bank]["systems"].items():
                    if row[0] == top:
                        fired_by_system[name] |= _rules(r, {"PASS", "FAIL", "WARN"})
            cascade = (scan.statistics or {}).get("cascade") or {}
            report["banks"][bank] = {
                "scan_id": scan_id, "status": scan.status, "error": scan.error_message, "files": len(labels), "evidence_rows": len(rows),
                "accuracy": score(rows, labels), "systems": sorted(BANKS[bank]["systems"]),
                "cascade_systems": {s["system"]: {"files": s.get("files"), "algorithms": sorted(s.get("algorithms") or [])[:12], "criticality": s.get("criticality")} for s in cascade.get("systems") or []},
                "failed_rules": dict(sorted(fails.items())), "rules_applied_by_system": {k: sorted(v) for k, v in sorted(fired_by_system.items())},
            }
        # ---- API read-back ------------------------------------------------------------------------------
        from api.main import create_app
        from api.security.session_manager import SessionManager
        from db.repositories.user_repository import UserRepository

        app = create_app()
        app.dependency_overrides[get_db_session] = lambda: (yield session)

        def token(user: str, role: str, *, member_of: str | None = None) -> str:
            """A signed session for one principal.

            The pipeline writes this group's estate in the platform context, so the
            analyst who reads it back is a platform operator (``superadmin``) — a
            tenant-less analyst is refused at the door now, and that refusal read as
            a missing scan status rather than as a tenancy question. The viewer who
            must NOT publish a triage is a real tenant member with the readonly role,
            so the 403 below is RBAC's, not the tenancy gate's.
            """
            if UserRepository(session).get_by_username(user) is None:
                UserRepository(session).create_user(user, "x", roles=[role])
                session.commit()
            if member_of:
                from db.models.tenant import Tenant, TenantMembership
                from db.repositories.tenant_repository import TenantRepository

                if session.get(Tenant, member_of) is None:
                    session.add(Tenant(id=member_of, name=member_of, slug=member_of))
                    session.commit()
                if TenantRepository(session).membership(member_of, user) is None:
                    session.add(TenantMembership(tenant_id=member_of, username=user, tenant_role="viewer"))
                    session.commit()
            return SessionManager().create_session(user, roles=[role])

        async def readback() -> dict[str, Any]:
            out: dict[str, Any] = {"per_bank": {}, "supervisor": {}}
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                c.headers["Authorization"] = f"Bearer {token('bank-analyst', 'superadmin')}"
                for bank, b in report["banks"].items():
                    sid = b["scan_id"]
                    detail = (await c.get(f"/api/v1/scans/{sid}")).json()
                    total = 0
                    page = 1
                    while True:
                        body = (await c.get(f"/api/v1/scans/{sid}/findings", params={"page": page, "page_size": 200})).json()
                        total += len(body.get("findings") or [])
                        if not body.get("findings") or total >= body.get("total_count", 0):
                            break
                        page += 1
                    cas = (await c.get(f"/api/v1/scans/{sid}/cascade", params={"section": "systems"})).json()
                    out["per_bank"][bank] = {"status": detail.get("status"), "findings_via_api": total, "cascade_systems_via_api": sorted(s["system"] for s in cas.get("systems") or [])}
                # a readonly viewer cannot publish a triage
                c.headers["Authorization"] = f"Bearer {token('viewer', 'readonly', member_of='group-tenancy')}"
                any_scan = next(iter(report["banks"].values()))["scan_id"]
                out["readonly_triage_post_status"] = (await c.post(f"/api/v1/scans/{any_scan}/triage", json={"workbook": {"repo": "x", "findings": []}})).status_code
                # supervisor view over all banks
                c.headers["Authorization"] = f"Bearer {token('cbuae-supervisor', 'supervisor')}"
                group = (await c.get("/api/v1/banking/group")).json()
                pack = (await c.get("/api/v1/banking/group/supervisor-pack")).json()
                roadmap = (await c.get("/api/v1/banking/group/roadmap")).json()
                systems_list = (await c.get("/api/v1/systems", params={"page_size": 200})).json()
                out["supervisor"] = {
                    "registry_count": group.get("registry_count"), "unassigned_systems": group.get("unassigned_systems"),
                    "entities": {e["entity"]["code"]: {k: e.get(k) for k in ("systems", "crypto_instances", "weak_legacy_instances", "quantum_vulnerable_public_key")} | {"top_families": (e.get("top_families") or [])[:5], "worst_system": (e.get("worst_system") or {}).get("system")} for e in group.get("entities") or []},
                    "group_totals": group.get("group", {}).get("totals"), "by_jurisdiction": group.get("group", {}).get("by_jurisdiction"),
                    "pack_entities": len((pack.get("pack") or {}).get("entities") or []), "pack_kind": ((pack.get("pack") or {}).get("pack") or {}).get("kind"),
                    "pack_declared_limits": ((pack.get("pack") or {}).get("declared_limits") or [])[:3],
                    "roadmap_summary": roadmap.get("summary") or roadmap.get("migration_roadmap_summary"),
                    "systems_total": systems_list.get("total_count"),
                }
                # Field accuracy is tenant-scoped history. These synthetic scans live in the
                # platform estate, so a separate platform operator reads it; a supervisor
                # without tenant membership must not gain history access by role alone.
                c.headers["Authorization"] = f"Bearer {token('field-operator', 'superadmin')}"
                field_response = await c.get("/api/v1/accuracy/field")
                field_response.raise_for_status()
                field = field_response.json()
                out["field_accuracy_status"] = field["status"]
                out["field_accuracy_f1"] = field["f1"]
                out["field_accuracy_triages"] = field["triages"]
            return out

        report["api"] = asyncio.run(readback())
        persisted = {s.name: s for s in session.execute(select(System)).scalars().all()}
        report["persisted_systems"] = len(persisted)
        report["entity_of_system_sample"] = {n: (s.extra or {}).get("legal_entity") for n, s in list(persisted.items())[:8]}
        # ---- overall --------------------------------------------------------------------------------------
        tp = sum(b["accuracy"]["tp"] for b in report["banks"].values())
        fp = sum(b["accuracy"]["fp"] for b in report["banks"].values())
        fn = sum(b["accuracy"]["fn"] for b in report["banks"].values())
        p = tp / (tp + fp) if tp + fp else 1.0
        r = tp / (tp + fn) if tp + fn else 1.0
        report["overall"] = {"banks": len(BANKS), "files": sum(b["files"] for b in report["banks"].values()), "evidence_rows": sum(b["evidence_rows"] for b in report["banks"].values()),
                             "tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
                             "exact_files": sum(b["accuracy"]["exact_files"] for b in report["banks"].values())}
    finally:
        session.close()
        drop_engine(engine)
    return report


# ----------------------------------------------------------------------------------------------- report
def render_md(rep: dict[str, Any]) -> str:
    o = rep["overall"]
    ent = {e["code"]: e for e in rep["entities"]}
    L = [
        "# Dubai banks — every estate through the whole product, plus the supervisory view",
        "",
        f"_Generated {rep['generated_at']} by `scripts/dubai_banks_e2e.py` on **{rep['backend']}**._",
        "",
        "**What this is.** Six representative Dubai-headquartered bank estates (conventional, Islamic, digital-forward, a DIFC branch under",
        "the DFSA) composed from the blind-labelled corpus waves, each with its own `cryptoscan-systems.yml` (systems, criticality,",
        "dependencies, compliance scopes, legal entity), run through the full pipeline into one database, scored against the labels,",
        "and read back through the HTTP API as a bank analyst and as a CBUAE supervisor.",
        "",
        "**What this is not.** Not the banks' code, configuration or key material — no bank system was accessed. The names fix the",
        "*shape* of each estate. Numbers describe the product on code of that shape.",
        "",
        "## Overall",
        "",
        "| banks | files | evidence rows | precision | recall | F1 | files exact |",
        "|---|---|---|---|---|---|---|",
        f"| {o['banks']} | {o['files']} | {o['evidence_rows']} | {o['precision']:.3f} | {o['recall']:.3f} | **{o['f1']:.3f}** | {o['exact_files']}/{o['files']} |",
        "",
        "## Per bank (through pipeline + database)",
        "",
        "| bank | entity | systems | files | rows | P | R | F1 | exact | failing rules (instances) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for bank, b in rep["banks"].items():
        a = b["accuracy"]
        fails = ", ".join(f"{k} ({v})" for k, v in b["failed_rules"].items() if not k.startswith("BASELINE")) or "—"
        L.append(f"| {bank} | {ent[bank]['name'].replace(' (representative estate)', '')} | {len(b['systems'])} | {b['files']} | {b['evidence_rows']} | {a['precision']:.3f} | {a['recall']:.3f} | {a['f1']:.3f} | {a['exact_files']}/{a['files']} | {fails} |")
    L += ["", "### Files not exact", ""]
    any_miss = False
    for bank, b in rep["banks"].items():
        for m in b["accuracy"]["misses"]:
            any_miss = True
            L.append(f"- **{bank}** `{m['file']}` FN={m['fn']} FP={m['fp']}")
    if not any_miss:
        L.append("_none_")
    L += ["", "### Jurisdiction rules applied per system (PASS/FAIL/WARN — out-of-scope rules are NOT_APPLICABLE and omitted)", ""]
    for bank, b in rep["banks"].items():
        for sysname, rules in b["rules_applied_by_system"].items():
            juris = [r for r in rules if r.split("-")[0] in {"CBUAE", "DIFC", "PDPL", "ADGM", "QCB", "CBB", "PDPPL", "BHPDPL"}]
            L.append(f"- {bank} / {sysname}: {', '.join(juris) or '—'}")
    api = rep.get("api") or {}
    sup = api.get("supervisor") or {}
    L += ["", "## Through the API", "", "| bank | scan status | findings via API | cascade systems via API |", "|---|---|---|---|"]
    for bank, x in (api.get("per_bank") or {}).items():
        L.append(f"| {bank} | {x['status']} | {x['findings_via_api']} | {len(x['cascade_systems_via_api'])} |")
    L += ["", f"Readonly session posting a triage → HTTP {api.get('readonly_triage_post_status')}. Platform operator reading field accuracy → `{api.get('field_accuracy_status')}` (no bank has published a review; nothing is invented).", "",
          "## Supervisor view (`/api/v1/banking/group`, `/group/supervisor-pack`, `/group/roadmap`, role `supervisor`)", "",
          f"Registry entities: {sup.get('registry_count')} · systems total: {sup.get('systems_total')} · unassigned to an entity: {sup.get('unassigned_systems')} · pack: `{sup.get('pack_kind')}` over {sup.get('pack_entities')} entities", "",
          "| entity | regulator | systems | crypto instances | weak / legacy | quantum-vulnerable public-key | worst system | top families |", "|---|---|---|---|---|---|---|---|"]
    for code, e in (sup.get("entities") or {}).items():
        L.append(f"| {code} | {ent.get(code, {}).get('regulator', '')} | {e.get('systems')} | {e.get('crypto_instances')} | {e.get('weak_legacy_instances')} | {e.get('quantum_vulnerable_public_key')} | {e.get('worst_system') or '—'} | {', '.join(f'{f} {n}' for f, n in (e.get('top_families') or []))} |")
    L += ["", f"Group totals: `{json.dumps(sup.get('group_totals'))}` · by jurisdiction: `{json.dumps(sup.get('by_jurisdiction'))}` · roadmap: `{json.dumps(sup.get('roadmap_summary'))}`", "",
          "## How to read this", "",
          "- Accuracy is scored per file × algorithm family on the evidence rows the pipeline persisted — after dedup, normalisation and the database round-trip — against labels written before any scan.",
          "- Each system's `legal_entity` in `cryptoscan-systems.yml` is what puts it under a bank in the supervisor view; `compliance_scopes` is what selects the CBUAE / DFSA (DIFC) / PDPL rules. Both are declarations a bank makes, not inferences.",
          "- The supervisor sees posture per legal entity and the group; a bank analyst sees its scans and findings. Publishing a triage review needs an analyst/CISO/auditor role.",
          "- Regenerate: `python scripts/dubai_banks_e2e.py --md docs/accuracy/DUBAI-BANKS-E2E.md --json docs/accuracy/dubai-banks-e2e.json [--backend postgresql]`.",
          ""]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", default="sqlite", choices=["sqlite", "postgresql"])
    ap.add_argument("--md")
    ap.add_argument("--json")
    ap.add_argument("--min-f1", type=float, default=0.95)
    args = ap.parse_args(argv)
    rep = run(args.backend)
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=2, default=str))
    if args.md:
        Path(args.md).write_text(render_md(rep))
    o = rep["overall"]
    print(f"{o['banks']} banks, {o['files']} files, {o['evidence_rows']} rows: P {o['precision']:.3f} R {o['recall']:.3f} F1 {o['f1']:.3f} ({o['exact_files']}/{o['files']} exact) on {rep['backend']}")
    for bank, b in rep["banks"].items():
        a = b["accuracy"]
        print(f"  {bank:8s} {b['status']:10s} files={b['files']:3d} rows={b['evidence_rows']:4d} F1={a['f1']:.3f} fails={sum(b['failed_rules'].values())}")
    sup = (rep.get("api") or {}).get("supervisor") or {}
    print(f"  supervisor: {sup.get('registry_count')} entities, {sup.get('systems_total')} systems, unassigned={sup.get('unassigned_systems')}")
    return 0 if o["f1"] >= args.min_f1 and all(b["status"] == "COMPLETED" for b in rep["banks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
