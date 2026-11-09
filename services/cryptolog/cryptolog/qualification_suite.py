"""Phase-8 qualification harness (docs/cryptolog/01_PRODUCT_SPEC.md).

Runs the qualification checks against a real in-memory store with the
real contracts — ordering, duplicates, tampering, deletion, volume — and
reports machine-readable results. Everything measured here uses the
SYNTHETIC corpus: synthetic results never qualify a real-environment act,
and the external acts stay register-only.
"""

from __future__ import annotations

import time
from typing import Any


SCHEMA = "cryptoscan.cryptolog-qualification/1"

#: Phase-8 acts the platform cannot perform itself. Register-only: the
#: platform never marks these done from inside the repo.
EXTERNAL_ACTS = (
    ("collector-integration-against-real-bank-sources",
     "integrating the collectors with real bank sources is a real-environment act"),
    ("high-volume-performance-on-a-real-estate",
     "performance on a real banking estate is measured there, not here"),
    ("real-bank-pilot-acceptance",
     "pilot acceptance is the bank's act; the platform can only register it"),
)


def _store():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from db.connection.session import Base
    from db.models.cryptolog import (
        CryptoLogAlert, CryptoLogCheckpoint, CryptoLogCorrection, CryptoLogEvent,
    )
    from db.repositories.cryptolog_repository import (
        CryptoLogAlertRepository, CryptoLogRepository,
    )

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        CryptoLogEvent.__table__, CryptoLogCorrection.__table__,
        CryptoLogAlert.__table__, CryptoLogCheckpoint.__table__])
    session = sessionmaker(bind=engine)()
    return CryptoLogRepository(session), CryptoLogAlertRepository(session), session


def run_suite(*, corpus_size: int = 120, volume_size: int = 1500) -> dict[str, Any]:
    """Run every check. Deterministic in its verdicts; timings are returned
    separately as labelled SYNTHETIC benchmarks."""
    from shared_models.cryptolog_corpus import (
        SYNTHETIC_COLLECTOR, generate_corpus,
    )
    from shared_models.cryptolog_events import validate_event
    from shared_models.cryptolog_integrity import (
        build_chain, chain_genesis, make_checkpoint, merkle_root, verify_range,
    )
    from cryptolog.collectors.qualification import QualificationRegistry

    checks: list[dict[str, Any]] = []
    timings: dict[str, Any] = {"label": "SYNTHETIC benchmark — never a real-estate measurement"}

    def record(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    events = generate_corpus(corpus_size)
    for event in events:
        validate_event(dict(event))
    record("synthetic-corpus-contract", "PASS",
           f"{corpus_size} generated events all pass validate_event and are "
           f"labelled synthetic (collector {SYNTHETIC_COLLECTOR})")

    # ---- ordering: the ledger order verifies; a reordered chain breaks ----
    events_repo, alerts_repo, session = _store()
    stored = [events_repo.insert_event(dict(e)) for e in events]
    inserted = sum(1 for s in stored if s["outcome"] == "INSERTED")
    record("event-ordering-insert", "PASS" if inserted == corpus_size else "FAIL",
           f"{inserted}/{corpus_size} synthetic events inserted in ledger order")

    records = alerts_repo.events_in_range(tenant_id="tenant_synthetic")
    hashes = [r["event_hash"] for r in records]
    partition = records[0]["partition_id"] if records else "tenant_synthetic:empty"
    chain = build_chain(partition, hashes)
    entries = [{"event_id": r["event"]["event_id"], "event_hash": h, "chain_hash": c}
               for r, h, c in zip(records, hashes, chain)]
    checkpoint = make_checkpoint(
        partition_id=partition, sequence=0,
        chain_hash=chain[-1] if chain else chain_genesis(partition),
        merkle_root_hash=merkle_root(hashes), event_count=len(records),
        created_at="2026-11-07T12:00:00+00:00",
        retention_ref="WORM:qualification", signer_id="qualification-harness",
        sign=lambda payload: "qualification-signature")
    verification = verify_range(
        partition_id=partition, entries=entries,
        events_by_id={r["event"]["event_id"]: r["event"] for r in records},
        checkpoint=checkpoint,
        verify=lambda signature, payload: True)
    record("event-ordering-verify", "PASS" if verification["overall_state"] == "VERIFIED"
           else "FAIL",
           f"ledger-ordered chain over {len(records)} events: "
           f"{verification['overall_state']}")

    shuffled = [entries[i] for i in (1, 0, *range(2, len(entries)))]
    broken = verify_range(
        partition_id=partition, entries=shuffled,
        events_by_id={r["event"]["event_id"]: r["event"] for r in records},
        checkpoint=checkpoint, verify=lambda signature, payload: True)
    named_broken = broken["overall_state"] in ("CHAIN_BROKEN", "INVALID_HASH") or \
        any(r["state"] in ("CHAIN_BROKEN", "INVALID_HASH") for r in broken["results"])
    record("event-ordering-tamper-named", "PASS" if named_broken else "FAIL",
           f"a reordered ledger is not silently accepted: "
           f"{broken['overall_state']} / first entry "
           f"{broken['results'][0]['state'] if broken['results'] else 'none'}")

    # ---- duplicates: re-ingestion never double-counts ----
    again = [events_repo.insert_event(dict(e)) for e in events]
    duplicated = sum(1 for s in again if s["outcome"] == "DUPLICATE")
    record("duplicate-idempotency", "PASS" if duplicated == corpus_size else "FAIL",
           f"{duplicated}/{corpus_size} re-ingested events resolved to DUPLICATE — "
           "a duplicate is never counted twice")

    # ---- tampering: a changed row is INVALID_HASH ----
    from db.models.cryptolog import CryptoLogEvent
    victim = session.query(CryptoLogEvent).filter(
        CryptoLogEvent.event_id == events[5]["event_id"]).one()
    victim.severity = "LOW" if victim.severity != "LOW" else "INFO"
    session.flush()
    tampered = verify_range(
        partition_id=partition, entries=entries,
        events_by_id={r["event"]["event_id"]: r["event"] for r in alerts_repo.events_in_range(tenant_id="tenant_synthetic")},
        checkpoint=checkpoint, verify=lambda signature, payload: True)
    record("tampering-detected", "PASS"
           if any(r["state"] in ("INVALID_HASH", "CHAIN_BROKEN", "ARTIFACT_MISSING")
                  for r in tampered["results"]) else "FAIL",
           f"a changed stored row never verifies: {tampered['overall_state']}")

    # ---- deletion: a removed row is ARTIFACT_MISSING ----
    victim2 = session.query(CryptoLogEvent).filter(
        CryptoLogEvent.event_id == events[7]["event_id"]).one()
    session.delete(victim2)
    session.flush()
    remaining = {r["event"]["event_id"]: r["event"]
                 for r in alerts_repo.events_in_range(tenant_id="tenant_synthetic")}
    deleted = verify_range(
        partition_id=partition, entries=entries,
        events_by_id=remaining,
        checkpoint=checkpoint, verify=lambda signature, payload: True)
    record("deletion-detected", "PASS"
           if any(r["state"] == "ARTIFACT_MISSING" for r in deleted["results"]) else "FAIL",
           "a removed artifact is named ARTIFACT_MISSING — unverifiable, never "
           "silently absent")

    # ---- volume: a larger synthetic run completes honestly ----
    volume_events = generate_corpus(volume_size, seed=20261108)
    start = time.monotonic()
    volume_repo, volume_alerts, volume_session = _store()
    for event in volume_events:
        volume_repo.insert_event(dict(event))
    ingest_seconds = time.monotonic() - start
    start = time.monotonic()
    v_records = volume_alerts.events_in_range(tenant_id="tenant_synthetic")
    v_hashes = [r["event_hash"] for r in v_records]
    v_partition = v_records[0]["partition_id"]
    v_chain = build_chain(v_partition, v_hashes)
    v_entries = [{"event_id": r["event"]["event_id"], "event_hash": h, "chain_hash": c}
                 for r, h, c in zip(v_records, v_hashes, v_chain)]
    v_checkpoint = make_checkpoint(
        partition_id=v_partition, sequence=0,
        chain_hash=v_chain[-1], merkle_root_hash=merkle_root(v_hashes),
        event_count=len(v_records), created_at="2026-11-07T12:00:00+00:00",
        retention_ref="WORM:qualification", signer_id="qualification-harness",
        sign=lambda payload: "qualification-signature")
    v_verify = verify_range(
        partition_id=v_partition, entries=v_entries,
        events_by_id={r["event"]["event_id"]: r["event"] for r in v_records},
        checkpoint=v_checkpoint, verify=lambda signature, payload: True)
    verify_seconds = time.monotonic() - start
    timings["ingest_seconds"] = round(ingest_seconds, 3)
    timings["verify_seconds"] = round(verify_seconds, 3)
    timings["events"] = volume_size
    record("synthetic-volume-run", "PASS" if v_verify["overall_state"] == "VERIFIED" else "FAIL",
           f"{volume_size} synthetic events ingested and verified: "
           f"{v_verify['overall_state']} — timings are measured per run and "
           "reported separately; synthetic timings, never a real-estate claim")

    # ---- collector integration: presence is not qualification ----
    registry = QualificationRegistry()
    for adapter_id in ("nbom", "cbom", "certificates", "hsm_metadata", "sbom", "runtime"):
        registry.register(adapter_id)
    statuses = registry.snapshot()
    record("collector-integration-status", "REGISTERED",
           "every adapter is REGISTERED, none auto-QUALIFIED: a fixture is not "
           "support, and real-source integration is an external act")

    external = [
        {"act": act, "reason": reason,
         "status": "EXTERNAL — NOT DONE (register only)"}
        for act, reason in EXTERNAL_ACTS
    ]
    return {
        "schema": SCHEMA,
        "corpus": {"size": corpus_size, "label": "SYNTHETIC"},
        "checks": checks,
        "timings": timings,
        "collector_qualification": statuses,
        "external_acts": external,
        "note": "every check ran against the SYNTHETIC corpus and in-memory "
                "store: synthetic results never qualify a real-environment act",
    }
