#!/usr/bin/env python3
"""One-command full-estate scan — the end-to-end pipeline in a single run.

Runs the *real* worker pipeline (the same code path used by queue jobs and
the 24/7 live monitor) against a local directory tree, then exports the
end-to-end deliverables: evidence pack, tamper-evident transfer payload,
CycloneDX CBOM, and the compliance report (JSON + HTML + PDF).

Everything the platform promises in one command:

    source-tree crypto  -> scanner  (Java/C#/Go/Python/JS/...)
    containers/IaC      -> container + cloud stages (Dockerfile, package
                           manifests, Terraform/CloudFormation/K8s in the tree)
    TLS/certificates    -> network + cert-inventory stages (certs in tree)
    OT (optional)       -> place an OT capture (*.log, e.g. opcua.log) in the
                           tree; the OT stage parses it passively, zero packets
    evidence chain      -> hashed records + manifest
    normalize + policy  -> CBOM-normalized algorithms, deterministic rules
    PQC + gate          -> quantum risk, agility score, CI gate decision

Read-only: the scanned tree is copied into a workspace (like the worker does);
nothing in the source tree is modified, no packets are sent.

Usage:
    python scripts/scan_estate.py --dir /path/to/authorized-source-tree --out /tmp/estate-out
    python scripts/scan_estate.py --dir . --template iso-27001 --keep-workspace
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

from _bootstrap import bootstrap  # noqa: E402

bootstrap()

from sqlalchemy import create_engine, select  # noqa: E402

from db.connection.session import SessionLocal, configure_session, init_db  # noqa: E402
from db.models.scan import Scan  # noqa: E402
from db.models.evidence_record import EvidenceRecord  # noqa: E402


def _policy_engine():
    from pathlib import Path as _P

    from policy.core.engine import PolicyEngine

    settings_dir = None
    try:
        from worker.config.settings import get_settings

        settings_dir = get_settings().POLICY_RULES_DIR or ""
    except Exception:
        settings_dir = ""
    rules_dir = settings_dir or str(
        _P(__file__).resolve().parents[1] / "services" / "policy" / "rule_definitions"
    )
    return PolicyEngine(rules_dir)


def _build_artifacts(out_dir: Path, session, scan_id: str, template: str) -> dict:
    from api.intelligence.payloads import evidence_to_dict, scan_to_dict
    from cbom.generator import CbomGenerator
    from drift.core.gate import evaluate_gate
    from evidence.intelligence.agility import compute_agility
    from evidence.pack.evidence_pack import build_evidence_pack
    from evidence.pack.scan_transfer import export_transfer
    from quantum.risk import analyze_quantum_risk
    from reporting.compliance_report import render_html, render_json
    from reporting.pdf_export import render_report_pdf

    out_dir.mkdir(parents=True, exist_ok=True)
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise RuntimeError(f"scan {scan_id} not found after pipeline run")
    rows = list(
        session.execute(
            select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id).order_by(EvidenceRecord.chain_position)
        ).scalars()
    )
    records = [evidence_to_dict(row) for row in rows]
    scan_payload = scan_to_dict(scan)
    [
        {k: row[k] for k in ("algorithm", "key_size", "mode", "purpose",
                             "compliance_status", "file_path", "line_number",
                             "policy_evaluation", "is_hardcoded_key") if k in row}
        for row in records
    ]

    engine = _policy_engine()
    pack = build_evidence_pack(
        scan=scan_payload,
        records=records,
        policy=engine.pack_descriptor(),
        secret=None,  # unsigned by default; HMAC is an instance secret
    )
    transfer = export_transfer(scan=scan_payload, records=records)

    bom = CbomGenerator().from_records(
        records,
        name=scan_payload.get("target_location") or scan_id,
        version=scan_payload.get("target_commit") or "unknown",
    )

    report = render_json(
        scan=scan_payload,
        findings=records,
        agility=compute_agility(records),
        quantum=analyze_quantum_risk(records),
        gate=evaluate_gate(records, []),
        template_id=template,
        policy_pack_hash=engine.pack_hash(),
    )

    paths: dict[str, str] = {}
    for name, data in (
        ("evidence-pack.json", pack),
        ("transfer.json", transfer),
        ("cbom.json", bom),
        ("report.json", report),
    ):
        target = out_dir / name
        target.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        paths[name] = str(target)
    (out_dir / "report.html").write_text(render_html(report), encoding="utf-8")
    paths["report.html"] = str(out_dir / "report.html")
    (out_dir / "report.pdf").write_bytes(bytes(render_report_pdf(report)))
    paths["report.pdf"] = str(out_dir / "report.pdf")

    summary = {
        "scan_id": scan_id,
        "findings": len(records),
        "gate": (report.get("gate") or {}).get("decision"),
        "quantum_vulnerable": (report.get("quantum") or {}).get("vulnerable_count"),
        "artifacts": paths,
        "generated_at": report.get("generated_at"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, help="local directory tree to scan")
    parser.add_argument("--out", default=None, help="output directory for artifacts")
    parser.add_argument("--db", default=None, help="sqlite URL (default: temp file, kept with --keep-db)")
    parser.add_argument("--template", default="pci-dss-4.0",
                        help="compliance report template id (default pci-dss-4.0)")
    parser.add_argument("--keep-workspace", action="store_true",
                        help="keep the pipeline workspace and DB instead of cleaning up")
    parser.add_argument("--name", default=None, help="job name shown in the pipeline")
    args = parser.parse_args()

    root = Path(args.dir).resolve()
    if not root.is_dir():
        print(f"error: --dir must be an existing directory: {root}", file=sys.stderr)
        return 2

    keep = args.keep_workspace
    state_dir = Path(tempfile.mkdtemp(prefix="cryptoscan-estate-"))
    db_url = args.db or f"sqlite:///{state_dir / 'scan.db'}"
    workspace = str(state_dir / "workspace")

    engine = create_engine(db_url)
    configure_session(engine)
    init_db(engine)
    session = SessionLocal()
    try:
        from worker.pipeline.pipeline_runner import PipelineRunner

        job_id = f"estate-{uuid.uuid4().hex[:8]}"
        scan_id = PipelineRunner().run(
            job_id=job_id,
            target_repo=f"local://{root}",
            target_branch="local",
            triggered_by="cli",
            workspace_dir=workspace,
            db=session,
        )
        session.commit()
        out = Path(args.out) if args.out else state_dir / "out"
        summary = _build_artifacts(out, session, scan_id, args.template)

        print(f"\nFull-estate scan complete: {summary['findings']} findings "
              f"(gate={summary['gate']}, quantum_vulnerable={summary['quantum_vulnerable']})")
        print(f"scan_id: {summary['scan_id']}")
        for name, path in summary["artifacts"].items():
            print(f"  {name}: {path}")
        return 0
    finally:
        session.close()
        if not keep:
            import shutil

            shutil.rmtree(state_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
