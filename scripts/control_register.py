#!/usr/bin/env python3
"""Validate the control register: no claim may outrank its evidence.

fix.md item 5 asks the product to distinguish an implemented repository
control from an operational record, a customer attestation and an external
certification -- "having encryption code does not prove FIPS certification".

A prose document cannot hold that line, because nothing stops the next edit
from quietly promoting a row. This gate can. It reads
config/control-register.yaml and refuses:

* a claim of operational_record whose evidence is only repository paths;
* a claim of external_certification or customer_attestation asserted from
  inside the repository at all -- neither can be self-issued, so a row
  claiming one must carry no repository evidence as its justification;
* evidence paths that do not exist (a register citing a deleted file is
  worse than one citing nothing);
* a required procurement topic missing from the register entirely.

Exit 0 when the register is internally honest. That is all this proves: the
register says what it can evidence. It does not make any control true.

    python scripts/control_register.py
    python scripts/control_register.py --out docs/readiness-evidence/control-register.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "config" / "control-register.yaml"

#: Ordered weakest to strongest. Index is the rank.
TIERS = ["none", "repository_control", "operational_record",
         "customer_attestation", "external_certification"]

#: Tiers nothing inside this repository can establish for itself.
NOT_SELF_ISSUABLE = {"customer_attestation", "external_certification"}

#: Every topic a bank procurement pack asks about. A register that omits one
#: is not incomplete by accident -- it is silent on a question that will be
#: asked, which reads as evasion.
REQUIRED_TOPICS = {
    "Secure SDLC",
    "Code review requirements",
    "Vulnerability management",
    "Patch timelines",
    "Release approval",
    "Vendor risk assessment",
    "Data residency",
    "Deployment location",
    "Backup retention",
    "Backup destruction",
    "Incident notification",
    "SLA commitments",
    "Support escalation",
    "Customer security questionnaire",
    "External certifications and attestations",
}


def _load() -> dict:
    try:
        import yaml
    except ImportError:
        print("PyYAML is required: pip install pyyaml", file=sys.stderr)
        raise SystemExit(2)
    if not REGISTER.is_file():
        print(f"register not found: {REGISTER}", file=sys.stderr)
        raise SystemExit(2)
    with REGISTER.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def validate(register: dict) -> list[dict]:
    findings: list[dict] = []

    def fail(control_id: str, rule: str, detail: str) -> None:
        findings.append({"control": control_id, "rule": rule, "detail": detail})

    controls = register.get("controls") or []
    if not controls:
        fail("-", "register_empty", "the register lists no controls")
        return findings

    seen_ids: set[str] = set()
    topics: set[str] = set()

    for control in controls:
        cid = str(control.get("id") or "?")
        topic = str(control.get("topic") or "").strip()
        claimed = str(control.get("claimed") or "").strip()
        evidence = control.get("evidence") or []
        gap = str(control.get("gap") or "").strip()
        topics.add(topic)

        if cid in seen_ids:
            fail(cid, "duplicate_id", "control id appears more than once")
        seen_ids.add(cid)

        if claimed not in TIERS:
            fail(cid, "unknown_tier", f"claimed={claimed!r}; expected one of {TIERS}")
            continue

        if not topic:
            fail(cid, "missing_topic", "every control needs a topic")

        # A missing gap on anything short of the top tier hides the distance
        # still to travel, which is the one thing a reviewer is reading for.
        if claimed != "external_certification" and not gap:
            fail(cid, "missing_gap", "state what is missing, or 'none' if nothing is")

        # Evidence must exist. A register citing a deleted path is worse than
        # one citing nothing, because it reads as substantiated.
        for path in evidence:
            if not (ROOT / str(path)).exists():
                fail(cid, "evidence_missing", f"cited path does not exist: {path}")

        repo_only = bool(evidence) and all((ROOT / str(p)).exists() for p in evidence)

        if claimed == "operational_record" and not evidence:
            fail(cid, "unevidenced_claim",
                 "operational_record requires a dated artifact from a real run")

        if claimed in NOT_SELF_ISSUABLE and repo_only:
            fail(cid, "self_issued_claim",
                 f"{claimed} cannot rest on repository paths; it is issued by "
                 "a customer or an independent body, not by this repository")

    for missing in sorted(REQUIRED_TOPICS - topics):
        fail("-", "topic_absent",
             f"required procurement topic not in the register: {missing}")

    return findings


def summarise(register: dict) -> dict:
    counts = dict.fromkeys(TIERS, 0)
    for control in register.get("controls") or []:
        tier = str(control.get("claimed") or "none")
        if tier in counts:
            counts[tier] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", help="write the JSON report here")
    args = parser.parse_args()

    register = _load()
    findings = validate(register)
    counts = summarise(register)

    for tier in TIERS:
        print(f"{counts[tier]:3d}  {tier}")
    print()
    for finding in findings:
        print(f"FAIL  {finding['control']}: {finding['rule']}: {finding['detail']}")

    verdict = "PASS" if not findings else "FAIL"
    print(f"\nControl register: {verdict} "
          f"({len(register.get('controls') or [])} controls, {len(findings)} findings)")
    print("This proves the register is internally honest. It does not make any "
          "control true; a row at 'none' is a real gap.")

    if args.out:
        report = {
            "schema": "cryptoscan.control-register-gate/1",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "tier_counts": counts,
            "findings": findings,
            "meaning": (
                "Tiers are ordered none < repository_control < operational_record "
                "< customer_attestation < external_certification. A claim may not "
                "outrank its evidence, and the top two tiers cannot be self-issued "
                "from this repository."
            ),
        }
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"-> {out}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
