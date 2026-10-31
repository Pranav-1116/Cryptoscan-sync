"""Evidence integrity: what corruption the chain actually catches.

The review's fourth blocker is the one that matters most, because evidence is
the source of truth and everything above it — Twin, BOM, intelligence — is
derived. The failure to prevent is:

    evidence corruption → Twin corruption → BOM corruption

This harness tampers with a real stored scan (SQLite, the real ORM rows, the
real chain and manifest) and asks what each consumer does: the verifier, the
scan-verify route, the evidence pack, and the digital twin.

Every attack is applied to a fresh store and graded by execution:

    DETECTED      the consumer reported the tamper
    UNDETECTED    the consumer accepted the tampered evidence as fact
    UNDETECTABLE  documented as beyond what this scheme can prove (a full
                  rewrite by someone with write access to the whole scan)

A `UNDETECTABLE` row is not an excuse: it names the missing control (a signing
key or an off-site anchor) so nobody reads "DETECTED" everywhere as "tamper
proof".

Run::

    python scripts/evidence_integrity_drill.py \\
        --json docs/bank-environment/112-evidence-integrity.json \\
        --md   docs/bank-environment/112-evidence-integrity.md
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

SCHEMA = "cryptoscan.evidence-integrity/1"
VERSION = "evidence-integrity/1.0"

DETECTED = "DETECTED"
UNDETECTED = "UNDETECTED"
UNDETECTABLE = "UNDETECTABLE"
CONTROL_OK = "CONTROL_OK"
CONTROL_FAILED = "CONTROL_FAILED"

RECORDS = 6


# ------------------------------------------------------------------ fixture --- #
@dataclass
class Store:
    session: Any
    engine: Any
    scan: Any
    rows: list[Any]

    def close(self) -> None:
        self.session.close()
        self.engine.dispose()


def _manifest(rows: list[Any]) -> str:
    """The anchor a stored scan commits to: a hash over its sorted record ids."""
    return hashlib.sha256("".join(sorted(str(row.id) for row in rows)).encode()).hexdigest()


def build_store(*, completed: bool = True, manifest: bool = True) -> Store:
    """A completed scan with a gapless, manifest-anchored chain of real rows."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers the metadata
    from db.models.base import Base
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    now = datetime.now(timezone.utc)
    scan = Scan(
        tenant_id="tenant-a", scan_start=now, scan_end=now, scanner_id="integrity-drill",
        scanner_version="1.0", target_location="https://example/bank.git",
        operator="drill", status="COMPLETED" if completed else "FAILED",
    )
    session.add(scan)
    session.flush()

    findings = [
        {"file": f"src/payments/Pay{i}.java", "line": 10 + i, "algorithm": "RSA" if i % 2 else "AES",
         "key_size": 2048 if i % 2 else 128, "note": f"observation {i}"}
        for i in range(RECORDS)
    ]
    content_hashes = [ContentHasher.compute_hash(finding) for finding in findings]
    chain = ChainHasher.compute_chain(content_hashes, scan.id)
    rows = []
    for position, (finding, content_hash, chain_hash) in enumerate(zip(findings, content_hashes, chain)):
        row = EvidenceRecord(
            tenant_id="tenant-a", scan_id=scan.id, content_hash=content_hash, chain_hash=chain_hash,
            chain_position=position, previous_hash=chain[position - 1] if position else None,
            algorithm=str(finding["algorithm"]), key_size=int(finding["key_size"]),
            confidence="HIGH", file_path=str(finding["file"]), line_number=int(finding["line"]),
            finding_data=finding,
        )
        session.add(row)
        rows.append(row)
    session.flush()
    if manifest:
        scan.manifest_hash = _manifest(rows)
    session.commit()
    return Store(session=session, engine=engine, scan=scan, rows=rows)


def _fresh(store: Store) -> Store:
    store.close()
    return build_store()


# ------------------------------------------------------------------ attacks --- #
def attack_baseline(store: Store) -> dict[str, Any]:
    """Control: nothing altered. A scheme that flags this is useless in the other direction."""
    return {"mutate": lambda: None, "expect": "PASS", "control": True}


def attack_payload_tamper(store: Store) -> dict[str, Any]:
    """The finding body is edited (RSA-2048 becomes something weak) and nothing else."""
    def mutate() -> None:
        row = store.rows[2]
        data = dict(row.finding_data)
        data["algorithm"] = "DES"
        data["key_size"] = 56
        row.finding_data = data
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_content_hash_rewrite(store: Store) -> dict[str, Any]:
    """The content hash is replaced to match a tampered body, but the chain is untouched."""
    def mutate() -> None:
        row = store.rows[1]
        row.content_hash = "0" * 64
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_chain_link_rewrite(store: Store) -> dict[str, Any]:
    """A chain link is rewritten in place."""
    def mutate() -> None:
        store.rows[3].chain_hash = "f" * 64
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_delete_middle(store: Store) -> dict[str, Any]:
    """A record is deleted from the middle of the chain."""
    def mutate() -> None:
        store.session.delete(store.rows[2])
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_delete_tail(store: Store) -> dict[str, Any]:
    """The last record is deleted.

    This is the attack a naive chain misses: the remaining prefix still
    recomputes correctly, so only an anchor (the scan manifest) can tell that
    something is gone.
    """
    def mutate() -> None:
        store.session.delete(store.rows[-1])
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_reorder(store: Store) -> dict[str, Any]:
    """Two records swap positions."""
    def mutate() -> None:
        first, second = store.rows[1], store.rows[2]
        first.chain_position, second.chain_position = 2, 1
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_append_forged(store: Store) -> dict[str, Any]:
    """A forged record is appended with a correctly computed link.

    It extends the chain consistently, so only the manifest can tell it was not
    part of what the scan committed to.
    """
    from db.models.evidence_record import EvidenceRecord
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher

    def mutate() -> None:
        finding = {"file": "src/forged.java", "line": 1, "algorithm": "MD5", "key_size": 128}
        content_hash = ContentHasher.compute_hash(finding)
        previous = store.rows[-1].chain_hash
        chain_hash = ChainHasher.compute_chain_hash(content_hash, previous)
        store.session.add(EvidenceRecord(
            tenant_id="tenant-a", scan_id=store.scan.id, content_hash=content_hash,
            chain_hash=chain_hash, chain_position=len(store.rows), previous_hash=previous,
            algorithm="MD5", key_size=128, confidence="HIGH", file_path="src/forged.java",
            line_number=1, finding_data=finding,
        ))
        store.session.commit()

    return {"mutate": mutate, "expect": "FAIL"}


def attack_manifest_absent(store: Store) -> dict[str, Any]:
    """No manifest: truncation is no longer detectable, so the answer must not be PASS."""
    def mutate() -> None:
        store.scan.manifest_hash = None
        store.session.commit()

    return {"mutate": mutate, "expect": "UNVERIFIABLE"}


def attack_rebuild_manifest(store: Store) -> dict[str, Any]:
    """The attacker also rewrites the manifest to match what is left.

    The manifest is the anchor for truncation, and nothing signs it. An
    attacker who can delete a row can recompute the anchor over what remains,
    and the scan then verifies PASS — correctly, because it now matches the
    commitment the database holds. This is the boundary of what an
    unsigned hash chain can prove, and it is why the row is graded
    UNDETECTABLE rather than counted as a miss.
    """
    def mutate() -> None:
        store.session.delete(store.rows[-1])
        store.session.flush()
        remaining = [row for row in store.rows[:-1]]
        store.scan.manifest_hash = _manifest(remaining)
        store.session.commit()

    return {"mutate": mutate, "expect": "UNDETECTABLE_BY_DESIGN"}


ATTACKS: tuple[tuple[str, str, Callable[[Store], dict[str, Any]]], ...] = (
    ("none", "control — nothing altered, the chain must read PASS", attack_baseline),
    ("payload_tamper", "the finding body is edited, hashes untouched", attack_payload_tamper),
    ("content_hash_rewrite", "the content hash is replaced to match a tampered body",
     attack_content_hash_rewrite),
    ("chain_link_rewrite", "a chain link is rewritten in place", attack_chain_link_rewrite),
    ("delete_middle", "a record is deleted from the middle", attack_delete_middle),
    ("delete_tail", "the last record is deleted", attack_delete_tail),
    ("reorder", "two records swap positions", attack_reorder),
    ("append_forged", "a forged record is appended with a consistent link", attack_append_forged),
    ("manifest_absent", "the manifest anchor is removed", attack_manifest_absent),
    ("delete_tail_and_rebuild_manifest", "the tail is deleted and the manifest rewritten to match",
     attack_rebuild_manifest),
)


# --------------------------------------------------------------- consumers --- #
def consume_verifier(store: Store) -> dict[str, Any]:
    """`verify_stored_scan` — the same function the export and audit paths call."""
    from evidence.verification.stored_scan import verify_stored_scan

    rows = (store.session.query(type(store.rows[0]))
            .filter_by(scan_id=store.scan.id).order_by("chain_position").all())
    store.session.refresh(store.scan)
    return dict(verify_stored_scan(store.scan, rows))


def consume_scan_verify_route(store: Store) -> dict[str, Any]:
    """`GET /scans/{id}/verify` — the route's own logic, with its repositories faked."""
    from api.routers import export as export_router

    class _Scans:
        def get_by_id(self, scan_id: str) -> Any:
            store.session.refresh(store.scan)
            return store.scan if scan_id == store.scan.id else None

    class _Evidence:
        def get_all_for_scan(self, scan_id: str, owner: str | None = None) -> list[Any]:
            return (store.session.query(type(store.rows[0]))
                    .filter_by(scan_id=scan_id).order_by("chain_position").all())

    verdict = export_router.verify_scan(
        store.scan.id, user="auditor",
        ctx=SimpleNamespace(tenant_id=store.scan.tenant_id),
        scans=_Scans(), evidence=_Evidence(),
    )
    return dict(verdict)


def consume_twin(store: Store) -> dict[str, Any]:
    """`GET /digital-twin` — the snapshot the engine and the console read."""
    from api.routers.digital_twin import _evidence_integrity
    from db.models.evidence_record import EvidenceRecord

    rows = store.session.query(EvidenceRecord).filter_by(scan_id=store.scan.id).all()
    return _evidence_integrity(store.session, rows)


def consume_pack(store: Store) -> dict[str, Any]:
    """`build_evidence_pack` — what an export ships to the bank."""
    from evidence.pack.evidence_pack import build_evidence_pack
    from db.models.evidence_record import EvidenceRecord

    rows = store.session.query(EvidenceRecord).filter_by(scan_id=store.scan.id).all()
    records = [
        {"id": row.id, "evidence_id": row.id, "chain_position": row.chain_position,
         "algorithm": row.algorithm, "content_hash": row.content_hash,
         "chain_hash": row.chain_hash, "file_path": row.file_path,
         "line_number": row.line_number}
        for row in rows
    ]
    pack = build_evidence_pack(scan={"scan_id": store.scan.id, "status": store.scan.status,
                                     "manifest_hash": store.scan.manifest_hash},
                               records=records)
    return dict(pack["integrity"])


ATTACKS_BY_NAME = {name: fn for name, _description, fn in ATTACKS}

CONSUMERS: tuple[tuple[str, str, Callable[[Store], dict[str, Any]], str], ...] = (
    ("verifier", "verify_stored_scan (export, audit, rescan, host-evidence)", consume_verifier,
     "the chain and manifest are recomputed from the stored payload"),
    ("scan_verify_route", "GET /scans/{id}/verify", consume_scan_verify_route,
     "the same verifier behind the route"),
    ("twin", "digital-twin snapshot", consume_twin,
     "the twin reports chain status before projecting evidence as fact"),
    ("pack", "build_evidence_pack", consume_pack,
     "the pack ships stored commitments; it is not an enforcement point on its own"),
)


def _verdict_of(name: str, observed: dict[str, Any]) -> str:
    """Normalise each consumer's answer into PASS / FAIL / UNVERIFIABLE."""
    if name == "pack":
        return "PASS" if observed.get("chain_ok") else "FAIL"
    return str(observed.get("result") or "UNKNOWN")


def measure() -> dict[str, Any]:
    attacks: list[dict[str, Any]] = []
    for name, description, apply_attack in ATTACKS:
        store = build_store()
        try:
            spec = apply_attack(store)
            spec["mutate"]()
            outcomes = {}
            for consumer, _label, consume, _note in CONSUMERS:
                try:
                    outcomes[consumer] = _verdict_of(consumer, consume(store))
                except Exception as exc:  # noqa: BLE001 — a consumer that raises is a finding
                    outcomes[consumer] = f"ERROR: {type(exc).__name__}: {exc}"[:120]
            observed = outcomes["verifier"]
            expected = spec["expect"]
            control = bool(spec.get("control"))
            if expected == "UNDETECTABLE_BY_DESIGN":
                verdict = UNDETECTABLE
            elif control:
                verdict = CONTROL_OK if observed == "PASS" else CONTROL_FAILED
            else:
                verdict = DETECTED if observed == expected else UNDETECTED
            attacks.append({
                "attack": name,
                "description": description,
                "expected": expected,
                "observed": observed,
                "verdict": verdict,
                "control": control,
                "consumers": outcomes,
            })
        finally:
            store.close()

    read_paths = []
    for consumer, label, consume, note in CONSUMERS:
        store = build_store()
        try:
            clean = _verdict_of(consumer, consume(store))
            spec = attack_payload_tamper(store)
            spec["mutate"]()
            tampered = _verdict_of(consumer, consume(store))
        finally:
            store.close()
        read_paths.append({
            "path": consumer,
            "surface": label,
            "clean": clean,
            "payload_tamper": tampered,
            "verdict": DETECTED if tampered != "PASS" else UNDETECTED,
            "enforcement_point": consumer != "pack",
            "note": note,
        })

    tampering = [attack for attack in attacks if not attack["control"]]
    caught = sum(1 for attack in tampering if attack["verdict"] == DETECTED)
    undetectable = sum(1 for attack in tampering if attack["verdict"] == UNDETECTABLE)
    missed = sum(1 for attack in tampering if attack["verdict"] == UNDETECTED)
    control_ok = all(attack["verdict"] == CONTROL_OK for attack in attacks if attack["control"])
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records_per_scan": RECORDS,
        "attacks": attacks,
        "attacks_detected": caught,
        "attacks_total": len(tampering),
        "attacks_undetectable_by_design": undetectable,
        "attacks_undetected": missed,
        "control_ok": control_ok,
        "read_paths": read_paths,
        "read_paths_enforcing": sum(1 for path in read_paths
                                    if path["enforcement_point"] and path["verdict"] == DETECTED),
        "read_paths_total": sum(1 for path in read_paths if path["enforcement_point"]),
        "complete": caught + undetectable == len(tampering)
        and missed == 0 and control_ok
        and all(p["verdict"] == DETECTED for p in read_paths if p["enforcement_point"]),
        "limits": [
            "The scan manifest is an unsigned hash over record ids: it catches truncation only "
            "while the attacker does not rewrite it. Deleting a record and re-anchoring the "
            "manifest verifies PASS, so the anchor needs a signature or an off-site copy to "
            "survive an attacker with write access to the scans table.",
            "No signing key and no off-site anchor: an attacker with write access to the whole "
            "scan (payload, content hashes, chain, manifest) can produce a self-consistent "
            "forgery that this scheme cannot distinguish from the original.",
            "The pack carries the stored commitments, not the payload it claims they cover; it "
            "is a transport, not a verifier. Enforcement is `verify_stored_scan` at the route.",
            "A tombstoned (soft-deleted) record stays in the chain by design, so retraction does "
            "not read as deletion — that is covered by the disposition path, not this one.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Evidence integrity — what corruption the chain catches",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{report['attacks_detected']} / {report['attacks_total']} tampering attacks detected** · "
        f"**{report['attacks_undetectable_by_design']} undetectable by design** · "
        f"**{report['read_paths_enforcing']} / {report['read_paths_total']} enforcement points "
        "reject tampered evidence**",
        "",
        "Each attack is applied to a real stored scan — the real ORM rows, chain and scan "
        "manifest — and every consumer is asked what it does with the result.",
        "",
        "| Attack | What was altered | Expected | Verifier | Verdict |",
        "|---|---|---|---|---|",
    ]
    for attack in report["attacks"]:
        lines.append(f"| `{attack['attack']}` | {attack['description']} | {attack['expected']} | "
                     f"{attack['observed']} | **{attack['verdict']}** |")

    lines += ["", "## Read paths — does each consumer refuse tampered evidence?", "",
              "| Surface | Function | Clean | After a payload tamper | Verdict |",
              "|---|---|---|---|---|"]
    for path in report["read_paths"]:
        lines.append(f"| {path['surface']} | `{path['path']}` | {path['clean']} | "
                     f"{path['payload_tamper']} | **{path['verdict']}** |")

    lines += ["", "## Per-consumer detail", ""]
    for attack in report["attacks"]:
        consumer_cell = ", ".join(f"{key}={value}" for key, value in attack["consumers"].items())
        lines.append(f"- `{attack['attack']}`: {consumer_cell}")

    lines += ["", "## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "- The store is a fresh SQLite database written by this harness. It does not prove that a "
        "bank's PostgreSQL deployment has the same constraint behaviour, that every writer computes "
        "the chain the same way, or that a *reader* outside these four paths verifies anything.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Evidence integrity, measured against tampering.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--min-detected", type=int, default=0,
                        help="exit non-zero when fewer than this many attacks are detected")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for attack in report["attacks"]:
            print(f"{attack['verdict']:<11} {attack['attack']:<32} "
                  f"verifier={attack['observed']:<12} {attack['description'][:50]}")
        print(f"\n{report['attacks_detected']}/{report['attacks_total']} tampering attacks detected, "
              f"{report['attacks_undetectable_by_design']} undetectable by design, "
              f"{report['attacks_undetected']} missed; "
              f"{report['read_paths_enforcing']}/{report['read_paths_total']} enforcement points reject")
    return 0 if report["attacks_detected"] >= args.min_detected else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
