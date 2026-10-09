"""Evidence-based remediation verification (audit 62 / GAP-006).

Pure comparison logic — no database, no clock, no network. The router feeds
it the snapshotted original finding, the remediation rule, and the evidence
records of the original + rescan; it returns a deterministic verdict:

* ``VERIFIED``      — the violation is gone and nothing new took its place
* ``PARTIAL``       — the site changed but is still non-compliant
* ``FAILED``        — the original violation is still there, unchanged
* ``REGRESSION``    — the fix (or the attempt) introduced new violations
* ``INCONCLUSIVE``  — no usable rescan evidence to compare against

Every verdict carries the full machine-readable comparison so an auditor can
replay the decision without trusting the label.
"""

from __future__ import annotations

from typing import Any, Iterable

VERIFIED = "VERIFIED"
PARTIAL = "PARTIAL"
FAILED = "FAILED"
REGRESSION = "REGRESSION"
INCONCLUSIVE = "INCONCLUSIVE"

NON_COMPLIANT = {"FAIL", "WARN"}


def _norm(algorithm: Any) -> str:
    return str(algorithm or "UNKNOWN").upper().replace("_", "-").strip()


def _fingerprint(finding: dict[str, Any]) -> tuple[str, int, str]:
    return (
        str(finding.get("file_path") or ""),
        int(finding.get("line_number") or 0),
        _norm(finding.get("algorithm")),
    )


def _is_non_compliant(finding: dict[str, Any]) -> bool:
    return str(finding.get("compliance_status") or "").upper() in NON_COMPLIANT


def verify_remediation(
    original: dict[str, Any],
    rule: dict[str, Any] | None,
    rescan_findings: Iterable[dict[str, Any]] | None,
    original_scan_findings: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare one remediated finding against rescan evidence.

    ``original``      — finding snapshot stored on the task at creation
    ``rule``          — remediation rule (``replace_with``) or None (manual)
    ``rescan_findings``— evidence records of the rescan of the same target;
                        ``None`` means "no rescan evidence available"
    ``original_scan_findings`` — full evidence of the original scan, used to
                        tell *new* violations (regression) from old ones
    """
    if rescan_findings is None:
        return {
            "result": INCONCLUSIVE,
            "reason": "no rescan evidence available — run a scan of the same target and re-verify",
            "comparison": {"original": original},
        }

    rescan = [dict(f) for f in rescan_findings]
    if not rescan:
        return {
            "result": INCONCLUSIVE,
            "reason": "rescan produced no evidence for the target — scan may have failed or scanned nothing",
            "comparison": {"original": original, "rescan_record_count": 0},
        }

    file_path = str(original.get("file_path") or "")
    original_algo = _norm(original.get("algorithm"))
    replace_with = _norm((rule or {}).get("replace_with")) if rule else ""
    if replace_with in ("", "REVIEW", "UNKNOWN"):
        replace_with = ""

    in_file = [f for f in rescan if str(f.get("file_path") or "") == file_path]
    same_algo = [f for f in in_file if _norm(f.get("algorithm")) == original_algo]
    replacement = [f for f in in_file if replace_with and _norm(f.get("algorithm")) == replace_with]

    details: dict[str, Any] = {
        "original": original,
        "rescan_record_count": len(rescan),
        "file_present_in_rescan": bool(in_file),
        "same_algorithm_remaining": [
            {"line_number": f.get("line_number"), "compliance_status": f.get("compliance_status"),
             "key_size": f.get("key_size")}
            for f in same_algo
        ],
        "replacement_found": bool(replacement),
        "replacement_algorithm": replace_with or None,
    }

    # -- 1) is the original violation still there? -------------------------- #
    if same_algo:
        still_bad = [f for f in same_algo if _is_non_compliant(f)]
        if not still_bad:
            result, reason = VERIFIED, (
                f"{original_algo} now passes policy at the original site "
                "(parameters or policy changed)")
        else:
            improved = any(
                (f.get("key_size") or 0) > (original.get("key_size") or 0)
                or (f.get("is_hardcoded_key") and not original.get("is_hardcoded_key"))
                for f in still_bad
            )
            if improved:
                result, reason = PARTIAL, (
                    f"{original_algo} improved (key size / hardcoded key) "
                    "but still fails policy at the original site")
            else:
                result, reason = FAILED, (
                    f"{original_algo} still present and non-compliant at the original site")
    # -- 2) original algorithm gone: was it replaced or removed? ------------ #
    elif replacement:
        if any(_is_non_compliant(f) for f in replacement):
            result, reason = PARTIAL, (
                f"replaced with {replace_with} but the replacement still fails policy")
        else:
            result, reason = VERIFIED, f"replaced with {replace_with} at the original site"
    elif in_file:
        # file still scanned, neither the old algorithm nor the suggested one
        if all(not _is_non_compliant(f) for f in in_file):
            result, reason = VERIFIED, (
                "original algorithm gone and the file is fully compliant in the rescan")
        else:
            result, reason = PARTIAL, (
                "original algorithm gone but the file still holds non-compliant crypto")
    else:
        result, reason = VERIFIED, "original file no longer present in the rescan evidence"

    # -- 3) regression: new non-compliance that was not in the original scan - #
    if original_scan_findings is not None:
        known = {_fingerprint(f) for f in original_scan_findings}
        scope = rescan
    else:
        # without the original scan's full evidence, only same-file statements
        # can be attributed to this remediation
        known = {_fingerprint(original)}
        scope = in_file
    new_violations = [
        {"file_path": f.get("file_path"), "line_number": f.get("line_number"),
         "algorithm": _norm(f.get("algorithm"))}
        for f in scope
        if _is_non_compliant(f) and _fingerprint(f) not in known
    ]
    details["new_violations"] = new_violations
    details["regression_scope"] = "target" if original_scan_findings is not None else "file"

    if new_violations and result == VERIFIED:
        result = REGRESSION
        reason = (
            "the original site is fixed but the rescan shows new non-compliant "
            f"crypto ({len(new_violations)} new site(s)) — likely introduced by the change")
    elif new_violations and result in (PARTIAL, FAILED):
        reason += f"; {len(new_violations)} new non-compliant site(s) appeared as well"

    return {"result": result, "reason": reason, "comparison": details}


def apply_result_to_status(result: str) -> str:
    """Map a verification result onto the task lifecycle status.

    INCONCLUSIVE deliberately leaves the task COMPLETED — it is a statement
    about missing evidence, not about the remediation itself.
    """
    if result in (VERIFIED, PARTIAL, FAILED, REGRESSION):
        return result
    return "COMPLETED"
