#!/usr/bin/env python3
"""Seed a realistic *fictional* banking estate into CryptoScan.

What it writes (all rows stamped ``provenance.seed = "sandbox-bank"``):

* 10 banking systems (internet banking, mobile, SWIFT/ISO-20022 hub, cards,
  core ledger, ATM fleet, treasury, CRM, data warehouse, legacy branch)
* ~85 cryptographic assets across those systems (TLS, signing, storage,
  PIN/EMV keys — including the weak ones a real audit would surface)
* 14 X.509 certificate records (valid, expiring-soon, expired, self-signed)
* 12 scans (10 COMPLETED, 1 FAILED, 1 QUEUED) with evidence hash-chained
  exactly the way the pipeline does (db/loader/chain.py)
* drift events, baselines and certificate usages so CommandCenter, CBOM,
  drift and renewal dashboards all have data on first login

Usage:
    python scripts/seed_sandbox_bank.py            # uses DATABASE_URL or local sqlite
    python scripts/seed_sandbox_bank.py --reset    # wipe sandbox rows, then reseed

Safe by construction: every identity here is invented, and rows are tagged so
``--reset`` deletes exactly what it created and nothing else.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for extra in ("services/database", "shared/shared_models"):
    path = os.path.join(REPO, extra)
    if path not in sys.path:
        sys.path.insert(0, path)

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from db.models.baseline import Baseline  # noqa: E402
from db.models.certificate import Certificate  # noqa: E402
from db.models.certificate_usage import CertificateUsage  # noqa: E402
from db.models.crypto_asset import CryptoAsset  # noqa: E402
from db.models.drift_event import DriftEvent  # noqa: E402
from db.models.evidence_record import EvidenceRecord  # noqa: E402
from db.models.scan import Scan  # noqa: E402
from db.models.system import System  # noqa: E402

SEED_TAG = "sandbox-bank"
NOW = datetime.now(timezone.utc)


def _canonical(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _content_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical(payload).encode()).hexdigest()


# ── fictional bank systems ────────────────────────────────────────────────────
SYSTEMS = [
    # (key, name, unit, owner-tech, owner-sec, environment, criticality, target)
    ("ibank",   "Internet Banking Portal",  "Digital Channels",  "Priya Suresh",    "CISO — D. Varma",    "Production", "CRITICAL", "/estate/ibank-portal"),
    ("mobile",  "Mobile Banking Backend",   "Digital Channels",  "Arun Daniel",     "CISO — D. Varma",    "Production", "CRITICAL", "/estate/mobile-api"),
    ("swift",   "SWIFT / ISO20022 Hub",     "Payments",          "Meera Krishnan",  "Risk — S. Rao",      "Production", "CRITICAL", "/estate/swift-hub"),
    ("cards",   "Card Management (CMS)",    "Cards & ATM",       "Joseph Mathew",   "Risk — S. Rao",      "Production", "CRITICAL", "/estate/cms"),
    ("core",    "Core Banking Ledger",      "Core Banking",      "Lakshmi Narayan", "CISO — D. Varma",    "Production", "CRITICAL", "/estate/core-ledger"),
    ("atm",     "ATM Switch & Fleet",       "Cards & ATM",       "Joseph Mathew",   "Risk — S. Rao",      "Production", "HIGH",     "/estate/atm-switch"),
    ("treas",   "Treasury & FX Platform",   "Treasury",          "Karthik Menon",   "Risk — S. Rao",      "Production", "HIGH",     "/estate/treasury"),
    ("crm",     "Customer CRM",             "Retail Ops",        "Sana Begum",      "CISO — D. Varma",    "Production", "MEDIUM",   "/estate/crm"),
    ("dwh",     "Data Warehouse / MIS",     "Enterprise Data",   "Vikram Joshi",    "CISO — D. Varma",    "Production", "MEDIUM",   "/estate/dwh"),
    ("legacy",  "Legacy Branch Concentrator", "Branch Network",  "Unassigned",      "Risk — S. Rao",      "Production", "HIGH",     "/estate/legacy-branch"),
]

# banking-plausible file paths per system
PATHS = {
    "ibank":  ["portal/src/main/java/com/meridian/ibank/tls/TlsContextFactory.java", "portal/config/nginx/ibank.conf", "portal/src/main/resources/keystore/ibank-wildcard.p12"],
    "mobile": ["mobile-api/internal/tls/server.go", "mobile-api/deploy/k8s/tls-secret.yaml", "mobile-api/pkg/crypto/jwt_signer.go"],
    "swift":  ["swift-hub/src/main/java/com/meridian/payments/laul/LaulSigner.java", "swift-hub/config/rma/rma-relationships.properties", "swift-hub/src/main/resources/keys/swift-bic-keystore.jks"],
    "cards":  ["cms/src/hsm/payshield_commands.py", "cms/src/main/java/com/meridian/cards/pin/PinBlockService.java", "cms/config/emv/ca-public-keys.xml"],
    "core":   ["core-ledger/src/main/cobol/cics/ENCRYPT.cbl", "core-ledger/config/db/ledger-tde.properties", "core-ledger/src/main/java/com/meridian/core/audit/AuditChainSigner.java"],
    "atm":    ["atm-switch/src/iso8583/field52_pin.cpp", "atm-switch/config/terminal-keys/TPK-MERIDIAN-042.txt", "atm-switch/src/dukpt/bdk_loader.cpp"],
    "treas":  ["treasury/src/main/java/com/meridian/fx/settlement/ClsConnector.java", "treasury/config/bloomberg/vault-agent.hcl"],
    "crm":    ["crm/src/main/python/integrations/ldap_bind.py", "crm/config/smtp/tls.yml"],
    "dwh":    ["dwh/etl/spark/jobs/nightly_kms_decrypt.scala", "dwh/config/warehouse/columnar-tde.conf"],
    "legacy": ["branch-hub/config/stunnel/legacy-tls.conf", "branch-hub/src/isa95/session_keys.c"],
}

# crypto findings: (algorithm, key_size, purpose, confidence, hardcoded?, compliant?)
FINDINGS = [
    ("TLS",      None, "TRANSPORT",   "HIGH", False, "PASS"),
    ("RSA",      4096, "SIGNING",     "HIGH", False, "PASS"),
    ("RSA",      2048, "KEY_EXCHANGE","HIGH", False, "PASS"),
    ("ECDSA",    256,  "SIGNING",     "HIGH", False, "PASS"),
    ("AES",      256,  "STORAGE",     "HIGH", False, "PASS"),
    ("AES",      128,  "STORAGE",     "HIGH", False, "PASS"),
    ("SHA-256",  None, "HASHING",     "HIGH", False, "PASS"),
    ("HMAC-SHA256", None, "INTEGRITY","HIGH", False, "PASS"),
    ("RSA",      2048, "SIGNING",     "MEDIUM", True, "FAIL"),   # hardcoded key
    ("3DES",     112,  "PIN_CRYPTO",  "HIGH", False, "FAIL"),     # NIST disallowed
    ("3DES",     168,  "PIN_CRYPTO",  "MEDIUM", False, "FAIL"),
    ("DES",      56,   "LEGACY",      "HIGH", False, "FAIL"),     # broken
    ("MD5",      None, "HASHING",     "HIGH", False, "FAIL"),     # broken
    ("SHA-1",    None, "SIGNING",     "HIGH", False, "FAIL"),     # deprecated
    ("RC4",      None, "LEGACY",      "MEDIUM", False, "FAIL"),
    ("RSA",      1024, "KEY_EXCHANGE","HIGH", False, "FAIL"),     # weak size
    ("DHE",      1024, "KEY_EXCHANGE","MEDIUM", False, "FAIL"),   # weak group
    ("ML-KEM",   768,  "PQC_PILOT",   "HIGH", False, "PASS"),     # PQC pilot on mobile API
    ("ECDH",     384,  "KEY_AGREEMENT","HIGH", False, "PASS"),
    ("AES-GCM",  256,  "STORAGE",     "HIGH", False, "PASS"),
]

CERTS = [
    # (cn, issuer, pk_alg, pk_size, days_left, self_signed, status)
    ("*.meridianbank.example",         "CN=DigiCert TLS RSA SHA256 2024 CA1",  "RSA",   2048, 214, False, "VALID"),
    ("mobile-api.meridianbank.example","CN=Entrust OV TLS CA",                 "ECDSA", 256,  189, False, "VALID"),
    ("swift-hub.meridianbank.example", "CN=Meridian Enterprise TLS CA G2",     "RSA",   3072, 340, False, "VALID"),
    ("cms.meridianbank.example",       "CN=Meridian Enterprise TLS CA G2",     "RSA",   2048,  22, False, "EXPIRING_SOON"),
    ("crm.meridianbank.example",       "CN=Meridian Enterprise TLS CA G2",     "RSA",   2048,  12, False, "EXPIRING_SOON"),
    ("dwh.meridianbank.example",       "CN=Meridian Enterprise TLS CA G2",     "RSA",   2048,   5, False, "EXPIRING_SOON"),
    ("legacy-branch.meridianbank.example","CN=legacy-branch.meridianbank.example","RSA",1024,  31, True,  "SELF_SIGNED"),
    ("atm-switch-dr.meridianbank.example","CN=Meridian Enterprise TLS CA G1",  "RSA",   2048, -14, False, "EXPIRED"),
    ("hsm-admin.meridianbank.example", "CN=Thales payShield Self-Signed",      "RSA",   2048,  700, True, "SELF_SIGNED"),
    ("treasury.meridianbank.example",  "CN=Entrust OV TLS CA",                 "RSA",   2048,  96, False, "VALID"),
    ("api.meridianbank.example",       "CN=DigiCert TLS RSA SHA256 2024 CA1",  "RSA",   2048, 166, False, "VALID"),
    ("openbanking.meridianbank.example","CN=DigiCert TLS RSA SHA256 2024 CA1", "ECDSA", 384,  250, False, "VALID"),
    ("dr-site.meridianbank.example",   "CN=Meridian Enterprise TLS CA G2",     "RSA",   4096,  390, False, "VALID"),
    ("dev.meridianbank.example",       "CN=Meridian Dev CA (Sandbox)",         "RSA",   2048,  180, True,  "SELF_SIGNED"),
]

# one scan series per week pattern: 12 scans over 45 days
SCAN_STORY = []
for i, (key, name, *_rest) in enumerate(SYSTEMS[:10]):
    started = NOW - timedelta(days=45 - i * 4, hours=i % 7)
    SCAN_STORY.append({
        "system_key": key,
        "location": f"git://meridianbank.internal/{name.lower().replace(' ', '-')}.git",
        "operator": ["p.suresh", "a.daniel", "m.krishnan", "j.mathew", "l.narayan"][i % 5],
        "started": started,
        "failed": name == "Legacy Branch Concentrator" and False,  # completed but with findings
    })
SCAN_STORY.append({"system_key": "dwh", "location": "git://meridianbank.internal/data-warehouse-mis.git",
                   "operator": "v.joshi", "started": NOW - timedelta(days=2), "failed": True})
SCAN_STORY.append({"system_key": "ibank", "location": "git://meridianbank.internal/internet-banking-portal.git",
                   "operator": "p.suresh", "started": NOW, "failed": None})  # QUEUED


def _engine_with_retry(db_url: str, attempts: int = 20, delay_s: float = 3.0):
    """Wait out a fresh stack: Postgres healthy != API migrations finished."""
    import time
    from sqlalchemy.exc import SQLAlchemyError
    engine = create_engine(db_url)
    for attempt in range(1, attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                return engine
        except SQLAlchemyError as exc:
            if attempt == attempts:
                raise
            print(f"database not ready ({exc.__class__.__name__}); retry {attempt}/{attempts}", flush=True)
            time.sleep(delay_s)
    return engine


def _ensure_schema(engine) -> None:
    """Bootstrap the schema if empty (fresh local stacks).

    Production Postgres is migrated by alembic; this is only a safety net for
    sandboxes where the API never came up. create_all() is a no-op when the
    tables already exist, so it is safe to call unconditionally.
    """
    from db.connection.session import Base
    import db.models.scan  # noqa: F401 - register models on the metadata
    import db.models.evidence_record  # noqa: F401
    import db.models.crypto_asset  # noqa: F401
    import db.models.certificate  # noqa: F401
    import db.models.certificate_usage  # noqa: F401
    import db.models.drift_event  # noqa: F401
    import db.models.baseline  # noqa: F401
    import db.models.system  # noqa: F401
    Base.metadata.create_all(engine)
    print("schema ensured (existing tables untouched)")


def seed(db_url: str, reset: bool) -> None:
    engine = _engine_with_retry(db_url)
    _ensure_schema(engine)
    with Session(engine) as db:
        if reset:
            # remove exactly what this script created, youngest dependency first
            db.query(CertificateUsage).filter(
                CertificateUsage.fingerprint_sha256.in_(
                    [hashlib.sha256(f"{cn}|{issuer}".encode()).hexdigest() for cn, issuer, *_ in CERTS])
            ).delete(synchronize_session=False)
            for model in (DriftEvent, Baseline, EvidenceRecord, CryptoAsset, Certificate, Scan):
                rows = db.query(model).all()
                for row in rows:
                    blob = json.dumps(
                        getattr(row, "extra", None) or getattr(row, "finding_data", None)
                        or getattr(row, "drift_details", None) or getattr(row, "provenance", None)
                        or {}
                    ) + str(getattr(row, "notes", "") or "") + str(getattr(row, "target_location", "") or "")
                    if SEED_TAG in blob or "meridianbank.internal" in blob:
                        db.delete(row)
            db.query(System).filter(System.business_unit.in_([s[2] for s in SYSTEMS])).delete(synchronize_session=False)
            db.commit()
            print("sandbox rows wiped")

        marker = db.execute(
            text("SELECT id FROM crypto_assets WHERE file_path LIKE '%MERIDIAN-SANDBOX-MARKER%'")
        ).first()
        if marker:
            print("sandbox estate already seeded — pass --reset to rebuild")
            return

        systems = {}
        for key, name, unit, tech, sec, env, crit, target in SYSTEMS:
            s = System(
                name=name, description=f"{name} — Meridian Bank (fictional sandbox estate)",
                owner=unit, technical_owner=tech, security_owner=sec,
                environment=env, compliance_scopes=["PCI-DSS", "RBI-IT-Framework", "ISO27001"],
                business_unit=unit, criticality=crit,
                coverage_status="CURRENT", scan_target=target, last_scanned_at=NOW - timedelta(days=3),
                current_agility_score={"ibank": 82, "mobile": 90, "swift": 55, "cards": 41, "core": 38,
                                       "atm": 33, "treas": 61, "crm": 58, "dwh": 47, "legacy": 12}[key],
                agility_category={"ibank": "GOOD", "mobile": "GOOD", "swift": "MODERATE", "cards": "MODERATE",
                                  "core": "MODERATE", "atm": "POOR", "treas": "MODERATE", "crm": "MODERATE",
                                  "dwh": "MODERATE", "legacy": "POOR"}[key],
                migration_readiness_score={"ibank": 74, "mobile": 88, "swift": 49, "cards": 30, "core": 26,
                                           "atm": 18, "treas": 57, "crm": 52, "dwh": 40, "legacy": 8}[key],
                extra={"seed": SEED_TAG, "system_key": key},
            )
            db.add(s)
            systems[key] = s
        db.flush()

        # ── scans + hash-chained evidence ────────────────────────────────
        scan_objs = []
        for story in SCAN_STORY:
            scan = Scan(
                scan_start=story["started"],
                scan_end=(story["started"] + timedelta(minutes=6 + len(story["system_key"]))) if story["failed"] is not None else None,
                scanner_id="cryptoscan-estate-scanner-v1.4",
                scanner_version="1.4.2",
                target_type="GIT_REPOSITORY",
                target_location=story["location"],
                operator=story["operator"],
                status="QUEUED" if story["failed"] is None else ("FAILED" if story["failed"] else "COMPLETED"),
                statistics=None,
                error_message="manifest unpack failed at 42%: estate volume unreachable" if story["failed"] else None,
            )
            db.add(scan)
            db.flush()

            # distribute findings across systems: legacy/atm get the weak stuff,
            # modern channels get the strong set
            if story["failed"] is None:
                continue
            sys_key = story["system_key"]
            if sys_key in ("legacy", "atm", "core"):
                picks = FINDINGS  # everything incl. DES/MD5/1024
            elif sys_key in ("swift", "cards"):
                picks = [f for f in FINDINGS if f[0] != "ML-KEM" and not (f[0] == "DES")]
            else:
                picks = [f for f in FINDINGS if f[5] == "PASS"]

            pos = 0
            prev = None
            stats = {"files_scanned": 0, "assets_found": 0, "algorithm_counts": {}}
            for (alg, ksize, purpose, conf, hard, verdict) in picks:
                reps = 2 if sys_key in ("legacy", "atm") and verdict == "FAIL" else 1
                for r in range(reps):
                    path = PATHS[sys_key][(pos + r) % len(PATHS[sys_key])]
                    line = 10 + ((pos * 37 + r * 13) % 400)
                    finding = {
                        "algorithm": alg, "key_size": ksize, "purpose": purpose,
                        "file_path": path, "line_number": line,
                        "confidence": conf, "is_hardcoded_key": hard,
                        "seed": SEED_TAG,
                    }
                    ch = _content_hash(finding)
                    anchor = (scan.id if isinstance(scan.id, str) else str(scan.id)) if pos == 0 else prev
                    chain = hashlib.sha256((ch + (anchor or "")).encode()).hexdigest()
                    ev = EvidenceRecord(
                        scan_id=scan.id,
                        content_hash=ch, chain_hash=chain, chain_position=pos,
                        previous_hash=anchor, algorithm=alg, key_size=ksize,
                        purpose=purpose, confidence=conf, is_hardcoded_key=hard,
                        file_path=path, line_number=line,
                        finding_data=finding,
                        policy_evaluation={"ruleset": "pci-dss-4.0+rbi-it", "result": verdict,
                                           "rule_id": f"CRYPTO-{'OK' if verdict == 'PASS' else 'VIOLATION'}-{alg}"},
                        compliance_status=verdict,
                        normalized_crypto={"family": alg, "strength": ksize},
                        provenance={"collector": "sandbox-seed", "seed": SEED_TAG},
                    )
                    db.add(ev)
                    prev = chain
                    pos += 1
                    stats["files_scanned"] += 11
                    stats["assets_found"] += 1
                    stats["algorithm_counts"][alg] = stats["algorithm_counts"].get(alg, 0) + 1

            scan.statistics = stats
            scan.manifest_hash = hashlib.sha256(_canonical(stats).encode()).hexdigest()
            system = systems[story["system_key"]]
            system.last_scan_id = scan.id
            system.last_scanned_at = scan.scan_end or NOW
            scan_objs.append((story, scan, pos))
        db.flush()

        n_evidence = sum(p for _, _, p in scan_objs)
        print(f"seeded {len(scan_objs)} scans / {n_evidence} hash-chained evidence records")

        # ── deduped crypto assets (the inventory table) ─────────────────
        asset_count = 0
        for key, paths in PATHS.items():
            per_system = FINDINGS if key in ("legacy", "atm", "core") else (
                [f for f in FINDINGS if f[5] == "PASS"] + FINDINGS[8:11] if key in ("swift", "cards")
                else [f for f in FINDINGS if f[5] == "PASS"])
            for i, (alg, ksize, purpose, conf, hard, _v) in enumerate(per_system):
                path = paths[i % len(paths)]
                db.add(CryptoAsset(
                    algorithm=alg, purpose=purpose, mode=("GCM" if "AES" in alg else None),
                    key_size=ksize, file_path=path,
                    line_number=10 + ((i * 37) % 400),
                    source_language={"ibank": "java", "mobile": "go", "swift": "java", "cards": "java",
                                     "core": "cobol", "atm": "cpp", "treas": "java", "crm": "python",
                                     "dwh": "scala", "legacy": "c"}[key],
                    confidence=conf, is_hardcoded_key=hard,
                    occurrence_count=1 + (i % 3),
                    scanner_ids=["cryptoscan-estate-scanner-v1.4"],
                    libraries=[{"name": "BouncyCastle", "version": "1.78"}] if alg in ("RSA", "ECDSA") else [],
                    extra={"seed": SEED_TAG, "system_key": key},
                    lifecycle_state="ACTIVE" if conf == "HIGH" else "DISCOVERED",
                    owner=systems[key].technical_owner, technical_owner=systems[key].technical_owner,
                    security_owner=systems[key].security_owner,
                ))
                asset_count += 1
        # marker row so re-running is idempotent
        db.add(CryptoAsset(algorithm="MARKER", purpose="seed", file_path="/MERIDIAN-SANDBOX-MARKER",
                           line_number=0, confidence="LOW", extra={"seed": SEED_TAG}))
        print(f"seeded {asset_count} crypto assets (+1 marker)")

        # ── certificates ─────────────────────────────────────────────────
        cert_objs = []
        for cn, issuer, alg, size, days, self_signed, status in CERTS:
            fp = hashlib.sha256(f"{cn}|{issuer}".encode()).hexdigest()
            cert = Certificate(
                fingerprint_sha256=fp, subject=f"CN={cn}, O=Meridian Bank (Sandbox), C=IN",
                issuer=issuer, serial_number=fp[:32].upper(),
                not_before=NOW - timedelta(days=max(1, 365 - days)) if days > 0 else NOW - timedelta(days=380),
                not_after=NOW + timedelta(days=days),
                public_key_algorithm=alg, public_key_size=size,
                expiry_status=status, days_until_expiry=days,
                is_self_signed=self_signed,
                san=[cn, cn.replace("*.", "www.")],
                usages=["SERVER_AUTH"], revocation_status="GOOD" if not self_signed else "UNKNOWN",
                renewal_status="PLANNED" if status == "EXPIRING_SOON" else "NONE",
                renewal_ticket=(f"CHG-{4000 + len(cert_objs)}" if status == "EXPIRING_SOON" else None),
                owner="PKI Team — R. Pillai", technical_contact="pki@meridianbank.example",
                extra={"seed": SEED_TAG},
            )
            db.add(cert)
            db.flush()
            cert_objs.append((cn, cert))
        print(f"seeded {len(cert_objs)} certificates")

        # attach usage: each cert observed on matching sandbox endpoint:443
        for cn, cert in cert_objs:
            host = cn.replace("*.meridianbank.example", "internet-banking.bank.sandbox") \
                     .replace(".meridianbank.example", ".bank.sandbox")
            db.add(CertificateUsage(
                fingerprint_sha256=cert.fingerprint_sha256,
                usage_type="TLS_SERVER", location=f"{host}:443",
                last_seen=NOW,
            ))

        # ── drift events + baselines ──────────────────────────────────────
        drift_specs = [
            ("alg_downgrade", "CRITICAL", "cards", "3DES reintroduced for terminal TPK rotation (2 hosts)"),
            ("new_weak_key", "HIGH", "legacy", "RSA-1024 certificate still served by branch concentrator"),
            ("cert_expiry", "HIGH", "crm", "crm.meridianbank.example expires in 12 days — CHG raised"),
            ("hardcoded_secret", "CRITICAL", "swift", "Hardcoded RSA-2048 private key in swift-hub keystore properties"),
            ("protocol_drift", "MEDIUM", "dwh", "TLS 1.1 accepted on warehouse listener (policy: 1.2+)"),
            ("alg_downgrade", "MEDIUM", "atm", "DHE-1024 negotiated by 4 terminals"),
        ]
        scan_by_key = {st["system_key"]: sc for st, sc, _p in scan_objs if sc.status == "COMPLETED"}
        fallback_scan = next(iter(scan_by_key.values()))
        for dtype, sev, key, notes in drift_specs:
            anchor = scan_by_key.get(key, fallback_scan)
            d = DriftEvent(
                current_scan_id=anchor.id,
                detected_at=NOW - timedelta(days=2 + len(drift_specs)),
                drift_type=dtype, severity=sev, drift_details={"notes": notes, "seed": SEED_TAG},
                resolution_status="OPEN",
            )
            db.add(d)
        print(f"seeded {len(drift_specs)} open drift events")

        base_completed = [sc for (_st, sc, _p) in scan_objs if sc.status == "COMPLETED"]
        for (st, sc, _p) in [(None, base_completed[0], None), (None, base_completed[2] if len(base_completed) > 2 else base_completed[0], None)]:
            db.add(Baseline(
                system_identifier=sc.target_location, environment="Production",
                approved_scan_id=sc.id, approved_by="ciso-office",
                approved_at=NOW - timedelta(days=30), status="ACTIVE",
                notes=f"Sandbox baseline seeded {SEED_TAG}",
            ))
        db.commit()
        print("sandbox bank estate seeded OK")


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed a fictional banking estate into CryptoScan")
    ap.add_argument("--reset", action="store_true", help="delete prior sandbox rows first")
    ap.add_argument("--db", default=os.environ.get("DATABASE_URL", "sqlite:///./data/cryptoscan.db"),
                    help="SQLAlchemy URL (default: env DATABASE_URL or local sqlite file)")
    args = ap.parse_args()
    seed(args.db, args.reset)


if __name__ == "__main__":
    main()
