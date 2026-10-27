#!/usr/bin/env python3
"""Qualify every scanner family against a deterministic fixture.

update.md section 3: "A scanner being registered in the API is not the same
as being production-qualified. Each family needs an acceptance test with
either a real authorized target or a deterministic operator-owned fixture."

This runs the fixture half. It produces one qualification record per family
with the fields section 3 lists, and enforces the status discipline that
section calls the "important rule":

  * every run resolves to one of PASS / DEGRADED / FAIL / BLOCKED /
    UNAVAILABLE / UNCONFIGURED / SKIP / PREFLIGHT
  * an unavailable scanner is never reported PASS
  * an empty result is never assumed to be success
  * a finding does not become a CBOM algorithm without an explicit crypto
    field
  * evidence references are present for real observations
  * no secret or private key material appears in the output

Two fields are deliberately left empty: `authorization_reference` and
`operator_signoff`. Neither can be generated -- an authorization that the
tool writes for itself is not an authorization. A record without them is a
fixture result, not a qualification, and the report says so per row.

A family with no uniform entrypoint is recorded UNCONFIGURED rather than
omitted. A matrix that silently drops the families nobody wired up is the
thing section 3 is arguing against.

    python scripts/scanner_qualification.py
    python scripts/scanner_qualification.py --family network --json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
for d in sorted(ROOT.glob("shared/*/")) + sorted(ROOT.glob("services/*/")):
    sys.path.insert(0, str(d))

VALID_STATUSES = {
    "PASS", "DEGRADED", "FAIL", "BLOCKED",
    "UNAVAILABLE", "UNCONFIGURED", "SKIP", "PREFLIGHT",
}

#: Statuses that assert the scan actually did its job. Anything else must not
#: be presented as a successful run.
SUCCESS_STATUSES = {"PASS", "DEGRADED"}

#: Patterns that must never reach a scan result. Matching material in output
#: is a hard failure of the run regardless of its status.
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),              # AWS access key id
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),           # GitHub PAT
    re.compile(r'"private_key"\s*:\s*"[^"]{32,}"'),
]


def _secret_leak(payload: Any) -> str | None:
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    for pattern in _SECRET_PATTERNS:
        hit = pattern.search(text)
        if hit:
            return hit.group(0)[:40]
    return None


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

def _fixture_source(tmp: Path) -> str:
    """A tiny source tree with one unambiguous weak algorithm."""
    d = tmp / "src"
    d.mkdir(parents=True, exist_ok=True)
    (d / "crypto_use.py").write_text(
        "import hashlib\n"
        "def digest(b):\n"
        "    return hashlib.md5(b).hexdigest()\n",
        encoding="utf-8",
    )
    (d / "requirements.txt").write_text("cryptography==42.0.0\n", encoding="utf-8")
    return str(d)


def _fixture_missing(tmp: Path) -> str:
    return str(tmp / "definitely" / "not" / "here.bin")


# --------------------------------------------------------------------------- #
# family runners
# --------------------------------------------------------------------------- #
# Each returns (status, result-dict). They call the real code path, never a
# mock: a qualification run against a stub proves the stub.

def _run_devsecops_source(tmp: Path) -> tuple[str, dict]:
    from devsecops import realtime_cli

    result = realtime_cli.run({"source": _fixture_source(tmp)})
    return result.get("scan_status", "?"), result


def _run_devsecops_missing(tmp: Path) -> tuple[str, dict]:
    from devsecops import realtime_cli

    result = realtime_cli.run({"binary": _fixture_missing(tmp)})
    return result.get("scan_status", "?"), result


def _run_keyassure(tmp: Path) -> tuple[str, dict]:
    from keyassure import realtime_cli

    result = realtime_cli.run({})
    return result.get("scan_status", "?"), result


def _run_network_unconfigured(tmp: Path) -> tuple[str, dict]:
    """No target supplied: must be SKIP/UNCONFIGURED, never PASS."""
    out = subprocess.run(
        [sys.executable, "-m", "network_scanner.realtime_cli"],
        capture_output=True, text=True, timeout=120,
        env={**_env(), "PYTHONPATH": _pypath()},
    )
    body = _first_json(out.stdout) or {"stderr": out.stderr[-300:]}
    return str(body.get("scan_status") or "PREFLIGHT"), body


def _run_universal_source(tmp: Path) -> tuple[str, dict]:
    from scanner.core.scanner import Scanner

    result = Scanner().scan(_fixture_source(tmp))
    findings = getattr(result, "findings", [])
    payload = {
        "scanner": "universal-source",
        "scan_status": "PASS" if findings else "FAIL",
        "findings": [
            {
                "algorithm": f.crypto.algorithm,
                "file": f.source.file_path,
                "line": f.source.line_number,
                "has_crypto_field": bool(f.crypto.algorithm),
            }
            for f in findings
        ],
    }
    return payload["scan_status"], payload


def _run_payment_fixture(tmp: Path) -> tuple[str, dict]:
    """TR-31 header parsing: metadata only, never key material."""
    try:
        from payment_crypto.keyblocks import parse_tr31_header
    except Exception as exc:  # noqa: BLE001
        return "UNAVAILABLE", {"scanner": "payment", "error": f"{type(exc).__name__}: {exc}"}
    # A TR-31 block header: version B, key usage P0 (PIN encryption), TDEA.
    header = parse_tr31_header("B0096P0TE00E0000")
    payload = header.__dict__ if hasattr(header, "__dict__") else {"header": str(header)}
    return "PASS", {"scanner": "payment", "scan_status": "PASS", "header": payload}


def _env() -> dict:
    import os

    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"} | {"ENVIRONMENT": "test"}


def _pypath() -> str:
    import os

    return os.pathsep.join(
        str(p) for p in sorted(ROOT.glob("services/*/")) + sorted(ROOT.glob("shared/*/"))
    )


def _first_json(text: str) -> dict | None:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                # Not the JSON line: a scanner may print progress before its
                # result. Narrow to ValueError (JSONDecodeError subclasses it)
                # so a real error here is not mistaken for a log line.
                continue
    return None


#: family -> (what it demonstrates, runner or None)
#: None means no uniform entrypoint exists yet; recorded UNCONFIGURED.
MATRIX: dict[str, tuple[str, Callable[[Path], tuple[str, dict]] | None]] = {
    "universal-source": ("real source tree produces crypto observations", _run_universal_source),
    "devsecops-source": ("source/SBOM mode over a real tree", _run_devsecops_source),
    "devsecops-missing-target": ("a missing target is FAIL, not empty success", _run_devsecops_missing),
    "keyassure": ("per-mode statuses with nothing configured", _run_keyassure),
    "network-tls": ("unconfigured network scan does not report PASS", _run_network_unconfigured),
    "payment-hsm": ("TR-31 metadata parsed, no key material returned", _run_payment_fixture),
    "runtime": ("process/library observation incl. unavailable agent", None),
    "hardware-hsm-tpm": ("real metadata, no private key material", None),
    "ipsec-ike": ("explicit authorization, probe, timeout, unavailable", None),
    "dnssec": ("signed, unsigned, malformed, resolver-unavailable", None),
    "cloud": ("read-only IAM, KMS scans, denied-permission behaviour", None),
    "container-image": ("filesystem, image/tar, missing runtime", None),
    "ot-ics": ("passive-only input, malformed logs, stale feed", None),
    "telecom-5g": ("SBA/TLS results, N3/N9 unknown states", None),
    "binary": ("real firmware, bounded and truncated states", None),
    "universal-vendor": ("connector discovery, polling failure", None),
}


def qualify(family: str, describe: str, runner, tmp: Path) -> dict:
    record: dict[str, Any] = {
        "family": family,
        "demonstrates": describe,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "scanner_version": "1.0.0",
        # Not generatable. An authorization the tool writes for itself is not
        # an authorization, and a signature it writes for itself is not a
        # sign-off. Both stay empty until a person fills them in.
        "authorization_reference": "",
        "operator_signoff": "",
        "target_identity": None,
        "status": "UNCONFIGURED",
        "violations": [],
        "findings_count": 0,
        "evidence_references": 0,
    }
    if runner is None:
        record["violations"].append(
            "no uniform entrypoint: cannot be qualified by fixture yet")
        return record

    try:
        status, result = runner(tmp)
    except Exception as exc:  # noqa: BLE001
        record["status"] = "FAIL"
        record["violations"].append(f"runner raised {type(exc).__name__}: {exc}")
        return record

    record["status"] = str(status).upper()
    record["target_identity"] = result.get("target") or result.get("scanner") or family
    findings = result.get("findings") or []
    record["findings_count"] = len(findings) if isinstance(findings, list) else 0
    record["evidence_references"] = sum(
        1 for f in findings if isinstance(f, dict) and f.get("evidence_reference")
    ) if isinstance(findings, list) else 0

    # ---- the important rule ------------------------------------------- #
    if record["status"] not in VALID_STATUSES:
        record["violations"].append(
            f"status {record['status']!r} is outside the agreed vocabulary")

    if record["status"] == "PASS" and record["findings_count"] == 0:
        observed = result.get("observations") or result.get("header") or result.get("modes")
        if not observed:
            record["violations"].append(
                "PASS with no findings and no observations: an empty result "
                "is being treated as success")

    modes = result.get("modes") or {}
    if isinstance(modes, dict):
        unavailable = [m for m, s in modes.items()
                       if str(s).upper() in {"UNAVAILABLE", "BLOCKED", "FAIL"}]
        if unavailable and record["status"] == "PASS":
            record["violations"].append(
                f"overall PASS while modes are unavailable/failed: {unavailable}")

    for f in findings if isinstance(findings, list) else []:
        if isinstance(f, dict) and f.get("cbom_algorithm") and not f.get("has_crypto_field") \
                and not f.get("algorithm"):
            record["violations"].append(
                "a finding became a CBOM algorithm without an explicit crypto field")
            break

    leak = _secret_leak(result)
    if leak:
        record["violations"].append(f"secret material in output: {leak}")

    record["result_excerpt"] = json.dumps(result, default=str)[:400]
    return record


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--family")
    p.add_argument("--json", action="store_true")
    p.add_argument("--out")
    args = p.parse_args()

    selected = {k: v for k, v in MATRIX.items() if args.family in (None, k)}
    if not selected:
        raise SystemExit(f"unknown family {args.family!r}; known: {', '.join(MATRIX)}")

    records = []
    with tempfile.TemporaryDirectory(prefix="cryptoscan-qual-") as td:
        tmp = Path(td)
        for family, (describe, runner) in selected.items():
            records.append(qualify(family, describe, runner, tmp))

    qualified = [r for r in records if r["status"] in SUCCESS_STATUSES and not r["violations"]]
    violating = [r for r in records if r["violations"] and r["status"] != "UNCONFIGURED"]
    unwired = [r for r in records if r["status"] == "UNCONFIGURED"]

    report = {
        "schema": "cryptoscan.scanner-qualification/1",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "records": records,
        "families_total": len(records),
        "fixture_qualified": len(qualified),
        "with_violations": len(violating),
        "no_entrypoint": len(unwired),
        "verdict": "FAIL" if violating else "PASS",
        "scope": (
            "Fixture qualification only. Every record has an empty "
            "authorization_reference and operator_signoff, so none of these "
            "is a qualification in section 3's sense -- they establish that "
            "the family runs, reports a legal status, and does not leak key "
            "material. A family marked UNCONFIGURED has no uniform entrypoint "
            "and is listed so it cannot be quietly forgotten."
        ),
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for r in records:
            flag = "  <-- " + "; ".join(r["violations"]) if r["violations"] else ""
            print(f"{r['status']:13s} {r['family']:26s} findings={r['findings_count']:<4d}{flag}")
        print(f"\nFamilies: {report['families_total']}  "
              f"fixture-qualified: {report['fixture_qualified']}  "
              f"violations: {report['with_violations']}  "
              f"no entrypoint: {report['no_entrypoint']}")
        print(f"Verdict: {report['verdict']}")
        print("\n" + report["scope"])

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"-> {out}")

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
