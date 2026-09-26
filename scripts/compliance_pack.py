#!/usr/bin/env python3
"""Assemble the SOC 2 evidence pack — one hash-verified ZIP for the auditor.

At the start (and end) of a Type II observation window the auditor wants
one artifact that contains everything the platform can show: the policy
pack, the signed production-evidence record + chain, recorded external
evidence (drills, restore verifications, pen-test reports), the access-
review minutes, the SBOM, the DR runbook and the current self-assessment.

This script assembles exactly that — nothing more — with a top-level
``manifest.json`` whose SHA-256s cover every file, so the recipient can
verify integrity with the same check used for the audit pack:

    python scripts/compliance_pack.py --verify pack.zip

Every piece that is *absent* is represented by an honest ``NO_*.txt`` note
stating what it is and how to produce it — never silently omitted, never
faked. The pack is written to ``data/evidence/compliance-pack/`` (gitignored;
the evidence dir follows the production-evidence conventions).

Access-review minutes live in the database; pass ``--db-url`` to include
them, or the pack carries a NO_ACCESS_REVIEWS note. The SBOM is produced by
``make sbom`` and included when present.

    python scripts/compliance_pack.py --db-url "postgresql+psycopg://..."
    python scripts/compliance_pack.py --verify data/evidence/compliance-pack/....zip
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import production_evidence as pe  # noqa: E402  (identity() + chain helpers)

PACK_DIR = ROOT / "data" / "evidence" / "compliance-pack"


def _note(text: str) -> bytes:
    return text.encode("utf-8")


def _collect_static(files: dict[str, bytes], notes: list[str]) -> None:
    """Repo-resident exhibits: policies, records, runbooks, self-assessment."""
    policies = ROOT / "docs" / "policies"
    if policies.is_dir():
        for p in sorted(policies.iterdir()):
            if p.suffix == ".md":
                files[f"policies/{p.name}"] = p.read_bytes()
    else:
        notes.append("NO_POLICIES: docs/policies/ missing")

    for dest, src, note in (
        ("evidence/production-evidence.md", ROOT / "docs" / "production-evidence.md",
         "NO_PRODUCTION_EVIDENCE_RECORD: docs/production-evidence.md missing"),
        ("runbooks/dr-recovery.md", ROOT / "docs" / "runbooks" / "dr-recovery.md",
         "NO_DR_RUNBOOK: docs/runbooks/dr-recovery.md missing"),
        ("self-assessment/soc2-readiness-gap-analysis.md",
         ROOT / "docs" / "soc2-readiness-gap-analysis.md",
         "NO_GAP_ANALYSIS: docs/soc2-readiness-gap-analysis.md missing"),
        ("evidence/backup-drill.md", ROOT / "docs" / "backup-drill.md",
         "NO_BACKUP_DRILL_REPORT: docs/backup-drill.md missing"),
    ):
        if src.exists():
            files[dest] = src.read_bytes()
        else:
            notes.append(note)

    # operational + org exhibits (on-call/comms, sub-service matrix,
    # rep letters, risk register, board report, training, JML)
    for section in ("ops", "compliance", "org"):
        base = ROOT / "docs" / section
        if base.is_dir():
            for p in sorted(base.iterdir()):
                if p.suffix == ".md":
                    files[f"{section}/{p.name}"] = p.read_bytes()
        else:
            notes.append(f"NO_{section.upper()}_DOCS: docs/{section}/ missing")

    # the signed production-evidence chain + standalone artifacts
    ev_dir = pe.EVIDENCE_DIR
    chain = ev_dir / "chain.jsonl"
    if chain.exists():
        files["evidence/chain.jsonl"] = chain.read_bytes()
        entries = pe.verify_chain([json.loads(ln) for ln in
                                   chain.read_text().splitlines() if ln.strip()])
        files["evidence/chain-verification.txt"] = _note(
            f"chain verification at pack time: {entries['result']} "
            f"(entries={entries['entries']}, {entries['message']})\n")
    else:
        notes.append("NO_EVIDENCE_CHAIN: no data/evidence/production-evidence/chain.jsonl "
                     "yet — run the production evidence runner "
                     "(`python scripts/production_evidence.py`) on a host that can serve "
                     "the staging estate, then re-pack")
    for artifact in sorted(ev_dir.glob("*.json")) if ev_dir.is_dir() else []:
        files[f"evidence/artifacts/{artifact.name}"] = artifact.read_bytes()

    sbom = ROOT / "dist" / "cryptoscan-sbom.cdx.json"
    if sbom.exists():
        files["sbom/cryptoscan-sbom.cdx.json"] = sbom.read_bytes()
    else:
        notes.append("NO_SBOM: dist/cryptoscan-sbom.cdx.json not generated — "
                     "run `make sbom` (scripts/generate_own_sbom.py), then re-pack")


def _collect_access_reviews(files: dict[str, bytes], notes: list[str],
                            db_url: str | None) -> None:
    if not db_url:
        notes.append("NO_ACCESS_REVIEWS: no --db-url supplied — the quarterly "
                     "access-review minutes (access_reviews table) live in the "
                     "database; re-pack with --db-url to include them")
        return
    try:
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import sessionmaker
        from db.models.access_review import AccessReviewRecord

        engine = create_engine(db_url)
        session = sessionmaker(bind=engine)()
        rows = session.execute(
            select(AccessReviewRecord).order_by(AccessReviewRecord.created_at)
        ).scalars().all()
        payload = {
            "source": "access_reviews table",
            "count": len(rows),
            "reviews": [r.to_dict() for r in rows],
        }
        files["access-reviews/reviews.json"] = json.dumps(
            payload, indent=2, sort_keys=True, default=str).encode("utf-8")
        if not rows:
            notes.append("NO_ACCESS_REVIEWS: access_reviews table is empty — "
                         "no quarterly review has been recorded yet (POST "
                         "/api/v1/audit-export/access-reviews)")
    except Exception as exc:  # honest, never a silent empty file
        notes.append(f"NO_ACCESS_REVIEWS: could not read the access_reviews "
                     f"table via {db_url.split('@')[-1]}: {exc}")


def _collect_pentest(files: dict[str, bytes], notes: list[str],
                     db_url: str | None) -> None:
    if not db_url:
        notes.append("NO_PENTEST_FINDINGS: no --db-url supplied — ingested "
                     "pen-test findings (pentest_findings table) live in the "
                     "database; re-pack with --db-url to include them")
        return
    try:
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import sessionmaker
        from db.models.pentest_finding import PentestFinding

        engine = create_engine(db_url)
        session = sessionmaker(bind=engine)()
        rows = session.execute(select(PentestFinding)).scalars().all()
        open_rows = [r for r in rows if r.status in ("OPEN", "IN_PROGRESS")]
        payload = {
            "source": "pentest_findings table",
            "reports": sorted({r.report for r in rows}),
            "total": len(rows),
            "open": len(open_rows),
            "open_critical_high": sum(
                1 for r in open_rows if r.severity in ("CRITICAL", "HIGH")),
            "findings": [r.to_dict() for r in rows],
        }
        files["pentest-findings.json"] = json.dumps(
            payload, indent=2, sort_keys=True, default=str).encode("utf-8")
        if not rows:
            notes.append("NO_PENTEST_FINDINGS: pentest_findings table is "
                         "empty — no independent pen test has been ingested "
                         "yet (POST /api/v1/pentest/findings); the scope "
                         "brief is docs/security/pen-test-scope.md")
    except Exception as exc:
        notes.append(f"NO_PENTEST_FINDINGS: could not read pentest_findings "
                     f"via {db_url.split('@')[-1]}: {exc}")


def _collect_policy_signoff(files: dict[str, bytes], notes: list[str]) -> None:
    """The pack always carries the CURRENT sign-off state — an honest
    measurement, not a claim. Open items become a named gap note."""
    import policy_signoff_check as psc

    try:
        signoff = psc.scan(ROOT / "docs" / "policies")
        files["policy-signoff.json"] = json.dumps(
            signoff, indent=2, sort_keys=True).encode("utf-8")
        if not signoff["signed"]:
            notes.append(f"POLICY_SIGNOFF_PENDING: {signoff['total_open']} [ORG:] "
                         "placeholders open across the policy pack — see "
                         "policy-signoff.json; close them (and countersign) "
                         "before presenting the pack as approved")
    except Exception as exc:
        notes.append(f"NO_POLICY_SIGNOFF_REPORT: could not scan docs/policies/: {exc}")


def _collect_org_readiness(files: dict[str, bytes], notes: list[str]) -> None:
    import org_readiness_check as orc

    try:
        report = orc.scan(ROOT / "docs")
        files["org-readiness.json"] = json.dumps(
            report, indent=2, sort_keys=True).encode("utf-8")
        if not report["ready"]:
            pending = ", ".join(d["file"] for d in report["documents"]
                                if d["status"] != "READY")
            notes.append(f"ORG_READINESS_PENDING: {report['failed']} of "
                         f"{report['total_checks']} org checks open — see "
                         f"org-readiness.json ({pending})")
    except Exception as exc:
        notes.append(f"NO_ORG_READINESS_REPORT: could not scan org docs: {exc}")


def build(out_dir: Path | None, db_url: str | None) -> Path:
    files: dict[str, bytes] = {}
    notes: list[str] = []

    _collect_static(files, notes)
    _collect_access_reviews(files, notes, db_url)
    _collect_pentest(files, notes, db_url)
    _collect_policy_signoff(files, notes)
    _collect_org_readiness(files, notes)

    generated_at = datetime.now(timezone.utc)
    idt = pe.identity()

    manifest = {
        "kind": "cryptoscan-compliance-pack",
        "version": "1.0.0",
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "identity": idt,
        "purpose": "SOC 2 Type II evidence pack — platform-side exhibits",
        "verification": "SHA-256 per file; verify with "
                        "`python scripts/compliance_pack.py --verify <zip>`",
        "files": {
            name: {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            for name, payload in sorted(files.items())
        },
        "missing": sorted(notes),
    }
    manifest["pack_hash"] = hashlib.sha256(json.dumps(
        {k: v for k, v in manifest.items() if k != "pack_hash"},
        indent=2, sort_keys=True).encode()).hexdigest()
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    # recompute: the manifest file's own hash is listed in the manifest, so
    # pack it after the manifest is final (manifest hashes all OTHER files)
    # — files added after manifest.json were excluded by construction.

    dest_dir = out_dir or PACK_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    out_file = dest_dir / f"compliance-pack-{stamp}-{idt.get('git_commit', 'nogit')}.zip"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, payload in sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=generated_at.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    out_file.write_bytes(buffer.getvalue())

    print(f"\nSOC 2 compliance pack built — {len(files)} files")
    print(f"  identity : {idt.get('version') or 'n/a'} @ {idt.get('git_commit') or 'n/a'}"
          f"{' (dirty)' if idt.get('git_dirty') else ''}")
    print(f"  pack_hash: {manifest['pack_hash']}")
    for section in ("policies", "evidence", "access-reviews", "sbom",
                    "runbooks", "self-assessment"):
        count = sum(1 for n in files if n.startswith(section + "/"))
        print(f"  {section:16}: {count} file(s)")
    if notes:
        print(f"  honest gaps ({len(notes)}):")
        for n in notes:
            print(f"    - {n.split(':')[0]}: {n.split(':', 1)[1].strip()[:100]}")
    print(f"\npack: {out_file}")
    print(f"verify: python scripts/compliance_pack.py --verify {out_file}")
    return out_file


def verify(pack: str | Path) -> int:
    pack = Path(pack)
    if not pack.exists():
        print(f"error: {pack} not found", file=sys.stderr)
        return 2
    with zipfile.ZipFile(pack) as archive:
        names = archive.namelist()
        if "manifest.json" not in names:
            print("INVALID — no manifest.json in pack")
            return 1
        manifest = json.loads(archive.read("manifest.json"))
        errors = []
        for name, meta in manifest["files"].items():
            if name not in names:
                errors.append(f"{name}: listed in manifest but missing from pack")
                continue
            actual = hashlib.sha256(archive.read(name)).hexdigest()
            if actual != meta["sha256"]:
                errors.append(f"{name}: hash mismatch (manifest {meta['sha256'][:12]}… "
                              f"vs actual {actual[:12]}…)")
        for name in names:
            if name != "manifest.json" and name not in manifest["files"]:
                errors.append(f"{name}: in pack but not in manifest (extra file)")
        body = {k: v for k, v in manifest.items() if k != "pack_hash"}
        recomputed = hashlib.sha256(json.dumps(body, indent=2,
                                               sort_keys=True).encode()).hexdigest()
        if recomputed != manifest["pack_hash"]:
            errors.append("pack_hash mismatch — manifest altered after packing")

    if errors:
        print("INVALID — " + f" {len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"VALID — {len(manifest['files'])} files, pack_hash "
          f"{manifest['pack_hash'][:16]}…, generated {manifest['generated_at']} "
          f"@ {manifest['identity'].get('git_commit')}")
    if manifest.get("missing"):
        print(f"  (pack carries {len(manifest['missing'])} honest gap note(s): "
              + ", ".join(m.split(':')[0] for m in manifest["missing"]) + ")")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="zelnx compliance-pack",
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", metavar="ZIP", help="verify an existing pack")
    ap.add_argument("--out", help="output directory (default: data/evidence/compliance-pack)")
    ap.add_argument("--db-url", help="database URL for the access-review minutes")
    args = ap.parse_args(argv)

    if args.verify:
        return verify(Path(args.verify))
    build(Path(args.out) if args.out else None, args.db_url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
