#!/usr/bin/env python3
"""Record externally-run evidence into the tamper-evident production chain.

The production evidence runner (``scripts/production_evidence.py``) executes
the full guard/drill/smoke/load suite itself. This companion records
evidence that was produced *elsewhere* — a DR drill run directly on the
docker host, a backup-restore verification, a pen-test report, a
third-party assessment — into the same WORM-style hash chain with the same
content hashing, same chain linking and the same optional JWS signing.

Usage:
    # record a drill result, attaching its raw output
    python scripts/record_evidence.py \
        --label "DR drill" --kind drill --result PASS \
        --file /var/log/dr-drill-20260921.log \
        --summary "Failover to standby in 22m; RTO 4h met, RPO 1h met"

    # record a pen-test report without the full file (hash only)
    python scripts/record_evidence.py \
        --label "Annual pen test" --kind pentest --result PASS \
        --file reports/pen-test-2026-08.pdf --attach-no \
        --summary "2 medium findings, remediation tracked to 2026-09-30"

Chain and dir: by default this appends to the production chain
(data/evidence/production-evidence/chain.jsonl), continuing its chain_id —
the same behaviour as the runner. Use --evidence-dir / --chain-id to record
against a different chain (e.g. a sandbox test chain) without touching
production evidence.

Signing: with CRYPTOSCAN_EVIDENCE_KEY set (or --key), the report is signed
JWS HS256 over its canonical JSON, exactly like the runner. Without a key
the entry is digest-only: the digest proves integrity, a key proves origin.

Verify afterwards:
    python scripts/production_evidence.py --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import production_evidence as pe  # noqa: E402  (reuse the runner's primitives)

MAX_EMBED_BYTES = 8 * 1024  # embed attached output up to this size


def _phase(name: str, status: str, detail: dict) -> dict:
    return {
        "name": name, "status": status, "ms": None,
        "detail": detail, "error": None if status == "PASS" else detail.get("reason"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="zelnx record-evidence",
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True, help="human name, e.g. 'DR drill'")
    ap.add_argument("--kind", required=True,
                    choices=["drill", "restore", "pentest", "assessment", "other"],
                    help="what kind of external evidence this is")
    ap.add_argument("--result", required=True, choices=["PASS", "FAIL"],
                    help="outcome — a FAIL is recorded exactly like the runner "
                         "records a failed phase; it is not hidden")
    ap.add_argument("--summary", default="", help="one-line outcome summary")
    ap.add_argument("--file", help="raw output file to attach (hash always "
                                   "recorded; content embedded if <= 8 KB "
                                   "unless --attach-no)")
    ap.add_argument("--attach-no", action="store_true",
                    help="record the file's hash/size but not its content")
    ap.add_argument("--chain-id", default=None,
                    help="continue this chain (default: the production "
                         "chain's chain_id, like the runner)")
    ap.add_argument("--evidence-dir", default=None,
                    help="evidence directory (default: the production one) — "
                         "use a separate dir for test chains")
    ap.add_argument("--key", default=None, help="JWS signing key "
                    "(default: $CRYPTOSCAN_EVIDENCE_KEY; unset = digest-only)")
    args = ap.parse_args(argv)

    evidence_dir = Path(args.evidence_dir) if args.evidence_dir else pe.EVIDENCE_DIR
    chain_file = evidence_dir / "chain.jsonl"

    # attached file ---------------------------------------------------------
    attach: dict = {}
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"error: attached file not found: {path}", file=sys.stderr)
            return 2
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        attach = {
            "filename": path.name,
            "bytes": len(raw),
            "sha256": digest,
        }
        if not args.attach_no and len(raw) <= MAX_EMBED_BYTES:
            attach["content"] = raw.decode("utf-8", errors="replace")
        elif not args.attach_no:
            attach["content"] = None
            attach["note"] = "content not embedded (file > 8 KB); hash only"

    # chain selection --------------------------------------------------------
    chain_id = args.chain_id
    entries: list[dict] = []
    if chain_file.exists():
        entries = [json.loads(ln) for ln in chain_file.read_text().splitlines()
                   if ln.strip()]
    if not chain_id:
        # the file's chain_id is authoritative when --chain-id is omitted
        chain_id = entries[0]["chain_id"] if entries else str(uuid.uuid4())

    # report — same schema and shape as the runner's report so downstream
    # consumers and auditors see one format
    idt = pe.identity(release="")
    phase = _phase("external", args.result, {
        "source": "external",
        "kind": args.kind,
        "label": args.label,
        "summary": args.summary,
        **({"attachment": attach} if attach else {}),
    })
    report = {
        "schema": pe.SCHEMA,
        "evidence_id": str(uuid.uuid4()),
        "created_at": pe.utcnow(),
        "identity": idt,
        "phases": {f"external.{args.kind}": phase},
        "overall": args.result,
        "summary": {"pass": 1 if args.result == "PASS" else 0,
                    "fail": 0 if args.result == "PASS" else 1, "skip": 0},
        "chain": {"chain_id": chain_id, "entries_before": len(entries)},
        "provenance": "scripts/record_evidence.py (external evidence recorder)",
    }

    signature, signing = pe.sign_report(report, args.key or os.environ.get("CRYPTOSCAN_EVIDENCE_KEY"))

    # append with the platform's hashing primitives (same content hash, same
    # chain link as the runner)
    from evidence.hashing.chain_hasher import ChainHasher
    from evidence.hashing.content_hasher import ContentHasher
    content_hash = ContentHasher.compute_hash(report)
    chain_hash = ChainHasher.compute_chain(
        [e["content_hash"] for e in entries] + [content_hash], chain_id)[-1]
    entry = {
        "seq": len(entries),
        "chain_id": chain_id,
        "evidence_id": report["evidence_id"],
        "created_at": report["created_at"],
        "content_hash": content_hash,
        "chain_hash": chain_hash,
        "report": report,
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with chain_file.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    chain_status = pe.verify_chain(entries + [entry])

    artifact = {
        **report,
        "content_hash": entry["content_hash"],
        "chain": {**report["chain"], "seq": entry["seq"], "chain_hash": entry["chain_hash"],
                  "verified_after_append": chain_status["result"] == "VALID"},
        "signature": signature,
        "signing": signing,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_file = evidence_dir / f"external-evidence-{stamp}-{entry['seq']}.json"
    out_file.write_text(json.dumps(artifact, indent=2, sort_keys=True))

    # human summary ----------------------------------------------------------
    print(f"\nexternal evidence recorded — {args.result}")
    print(f"  kind     : {args.kind} ({args.label})")
    print(f"  identity : {idt.get('version') or 'n/a'} @ {idt.get('git_commit') or 'n/a'}"
          f"{' (dirty)' if idt.get('git_dirty') else ''} on {idt.get('host')}")
    if attach:
        print(f"  attached : {attach['filename']} sha256={attach['sha256'][:16]}… "
              f"({attach['bytes']} bytes)")
    print(f"  chain    : {chain_status['result']} entries={chain_status['entries']} "
          f"(seq {entry['seq']}, chain {chain_id[:8]}…)  "
          f"digest={entry['content_hash'][:16]}…")
    print(f"  signing  : {signing}")
    print(f"\nartifact : {out_file}")
    verify_cmd = "python scripts/production_evidence.py --verify"
    if evidence_dir != pe.EVIDENCE_DIR:
        verify_cmd = (f"python -c \"import sys; sys.path.insert(0,'scripts'); "
                      f"from _bootstrap import bootstrap; bootstrap(); "
                      f"import production_evidence as pe, json; "
                      f"entries=[json.loads(l) for l in open('{chain_file}') if l.strip()]; "
                      f"print(pe.verify_chain(entries))\"")
    print(f"verify   : {verify_cmd}"
          + (" --key $CRYPTOSCAN_EVIDENCE_KEY" if signature else ""))
    if chain_status["result"] != "VALID":
        print("ERROR: chain verification failed after append — investigate", file=sys.stderr)
        return 1
    return 0 if args.result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
