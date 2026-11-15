#!/usr/bin/env python3
"""Signed evidence-chain checkpoints — the operator's external anchor.

The evidence chains are honestly ``anchoring: local-database-only``: they
prove their own continuity, not that the database alone did not rewrite
all of it. This command signs the current chain head (an operator-held
key: EVIDENCE_CHECKPOINT_KEY) into a checkpoint document the bank
archives — later, anyone holding the key can prove the chain was exactly
this long, with exactly this head, at checkpoint time.

    export EVIDENCE_CHECKPOINT_KEY=...   # operator-held; NEVER a default
    python3 scripts/evidence_checkpoint.py sign --stream network --tenant t1
    python3 scripts/evidence_checkpoint.py verify --file checkpoint.json
    python3 scripts/evidence_checkpoint.py match --file checkpoint.json \
        --stream network --tenant t1     # has the chain moved since?

Exit codes: 0 the operation succeeded (signature valid / head matches);
1 the checkpoint is invalid or the chain has drifted; 2 the operation
could not run (missing key, unknown stream) — fail loud, never fake.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STREAMS = {
    "network": ("api.security.network_evidence_chain",
                ("NETWORK_CHAIN", "SPEC", "CHAIN")),
    "runtime": ("api.security.runtime_evidence_chain",
                ("RUNTIME_CHAIN", "SPEC", "CHAIN")),
}


def _load(stream: str):
    import importlib

    module_name, spec_names = STREAMS[stream]
    module = importlib.import_module(module_name)
    spec = next((getattr(module, name) for name in spec_names
                 if hasattr(module, name)), None)
    if spec is None:
        raise RuntimeError(f"{module_name} exposes no chain spec")
    return module, spec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["sign", "verify", "match"])
    ap.add_argument("--stream", choices=sorted(STREAMS))
    ap.add_argument("--tenant", default=None)
    ap.add_argument("--file", default=None, help="checkpoint JSON path")
    ap.add_argument("--signer-id", default="operator")
    args = ap.parse_args()

    from api.security import evidence_chain as ec

    if args.mode == "sign":
        if not args.stream:
            ap.error("sign needs --stream")
        module, spec = _load(args.stream)
        from db.connection.session import SessionLocal

        with SessionLocal() as db:
            chain = module.read_chain(db, tenant_id=args.tenant)
        try:
            doc = ec.checkpoint(chain, spec=spec, tenant_id=args.tenant,
                                signer_id=args.signer_id)
        except RuntimeError as exc:
            print(json.dumps({"error": type(exc).__name__, "detail": str(exc)},
                             indent=2))
            return 2
        out = Path(args.file or f"evidence-checkpoint-{args.stream}.json")
        out.write_text(json.dumps(doc, indent=2, default=str))
        print(json.dumps({"out": str(out), "head_hash": doc["head_hash"],
                          "entry_count": doc["entry_count"]}, indent=2))
        return 0

    # verify / match: the document is the input
    if not args.file:
        ap.error(f"{args.mode} needs --file")
    doc = json.loads(Path(args.file).read_text())
    if args.mode == "verify":
        try:
            result = ec.verify_checkpoint(doc)
        except RuntimeError as exc:
            print(json.dumps({"error": type(exc).__name__, "detail": str(exc)},
                             indent=2))
            return 2
        print(json.dumps(result, indent=2))
        return 0 if result.get("valid") else 1

    if not args.stream:
        ap.error("match needs --stream")
    module, _spec = _load(args.stream)
    from db.connection.session import SessionLocal

    with SessionLocal() as db:
        chain = module.read_chain(db, tenant_id=args.tenant)
    result = ec.match_head(chain, doc)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "MATCH" else 1


if __name__ == "__main__":
    raise SystemExit(main())
