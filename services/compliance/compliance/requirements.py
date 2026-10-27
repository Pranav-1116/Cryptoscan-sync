"""Requirements register — requirement → evidence / gaps / expiry / sign-off.

§4.3: a compliance claim is only as good as its mapping. This register makes
the mapping explicit for every requirement the platform claims to address:

* ``mapped_controls`` — the EXACT control checks in an evidence pack that
  provide evidence for the requirement (nothing implied by name similarity).
* ``evidence_source`` — where that evidence comes from, so an auditor can
  re-derive it independently.
* ``gap`` — what the evidence does NOT prove. A requirement whose check
  passed is still not "closed" if the gap says the check is partial.
* ``freshness_days`` — how long a collected pack stays valid evidence for
  this requirement; older evidence is EXPIRED, not quietly still-green.
* ``sign_off_required`` + ``sign_off_scope`` — whether a reviewer signature
  (a persisted attestation over the exact pack) is required to close it.

Requirements with NO mapped controls (PCI-DSS segmentation, NIST quantum
inventory) stay in the register on purpose: they render as UNEVALUATED —
visible, not hidden, and never turned into a pass by a green score.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

REGISTER: list[dict[str, Any]] = [
    {
        "requirement": "SOC2-CC6.1",
        "framework": "SOC 2 (Trust Services Criteria)",
        "title": "Logical access controls over systems and data",
        "mapped_controls": ["access.session_config"],
        "evidence_source": (
            "Control check 'access.session_config' in the evidence pack: live "
            "auth configuration (cookie_secure, environment) observed at "
            "collection time via GET /api/v1/compliance/evidence."
        ),
        "gap": (
            "Collection-time snapshot of platform auth configuration only. "
            "Per-user access reviews, MFA enrollment coverage and client-side "
            "session handling are NOT evaluated by this check."
        ),
        "freshness_days": 90,
        "sign_off_required": True,
        "sign_off_scope": "SOC2-CC6.1",
    },
    {
        "requirement": "SOC2-CC6.6",
        "framework": "SOC 2 (Trust Services Criteria)",
        "title": "Protection against threats from outside system boundaries",
        "mapped_controls": ["config.production_gate"],
        "evidence_source": (
            "Control check 'config.production_gate': whether the production "
            "secrets gate is engaged and fails closed on demo secrets "
            "(validates live runtime settings in production environments)."
        ),
        "gap": (
            "The gate is dormant outside production; perimeter controls "
            "beyond API settings (network, WAF, host hardening) are NOT "
            "evaluated by this check."
        ),
        "freshness_days": 90,
        "sign_off_required": True,
        "sign_off_scope": "SOC2-CC6.6",
    },
    {
        "requirement": "SOC2-CC6.8",
        "framework": "SOC 2 (Trust Services Criteria)",
        "title": "Prevention and detection of misuse / abuse (DoS protection)",
        "mapped_controls": ["protection.rate_limits"],
        "evidence_source": (
            "Control check 'protection.rate_limits': the rate-limit rule set configured in the running API middleware."
        ),
        "gap": (
            "Configuration presence only — live enforcement behavior under "
            "load (actual throttling, alerting on abuse) is NOT measured."
        ),
        "freshness_days": 90,
        "sign_off_required": True,
        "sign_off_scope": "SOC2-CC6.8",
    },
    {
        "requirement": "SOC2-CC7.2",
        "framework": "SOC 2 (Trust Services Criteria)",
        "title": "Audit trail integrity — monitoring inputs are complete and tamper-evident",
        "mapped_controls": ["audit.chain_integrity"],
        "evidence_source": (
            "Control check 'audit.chain_integrity': every raw audit-log line "
            "is HMAC-verified on replay and the verified count is compared "
            "against the on-disk line count."
        ),
        "gap": (
            "Verifies the local audit chain at collection time; log shipping "
            "to a SIEM, retention outside this store and alert coverage are "
            "NOT evaluated."
        ),
        "freshness_days": 30,
        "sign_off_required": True,
        "sign_off_scope": "SOC2-CC7.2",
    },
    {
        "requirement": "SOC2-CC8.1",
        "framework": "SOC 2 (Trust Services Criteria)",
        "title": "Change management — authorized, tested, approved changes",
        "mapped_controls": ["deploy.schema_in_sync"],
        "evidence_source": (
            "Control check 'deploy.schema_in_sync': live drift report between "
            "deployed database schema and the code's ORM models."
        ),
        "gap": (
            "Schema drift only. Release-pipeline approvals, test evidence "
            "per change and rollback records are NOT evaluated."
        ),
        "freshness_days": 30,
        "sign_off_required": True,
        "sign_off_scope": "SOC2-CC8.1",
    },
    {
        "requirement": "RETENTION-WORM",
        "framework": "Platform record-retention stance (supports SOC 2 CC7 series retention points)",
        "title": "Records are retained under a WORM policy before any deletion",
        "mapped_controls": ["retention.worm_policy"],
        "evidence_source": (
            "Control check 'retention.worm_policy': the configured retention "
            "policy read live from the settings store (or the platform "
            "default, stated as such)."
        ),
        "gap": (
            "Policy presence and the deterministic can_delete gate. Actual "
            "deletion events in production have NOT been tested against the "
            "gate by this check."
        ),
        "freshness_days": 365,
        "sign_off_required": True,
        "sign_off_scope": "RETENTION-WORM",
    },
    # ---- requirements with NO automated mapping: visible as unevaluated ----
    {
        "requirement": "PCI-DSS-4.2.1",
        "framework": "PCI-DSS v4.0.1",
        "title": "Network segmentation between the CDE and other networks",
        "mapped_controls": [],
        "evidence_source": None,
        "gap": (
            "No control in the platform evidence engine maps to "
            "cardholder-data segmentation. Manual network-scope review is "
            "required; this register keeps the requirement visible and "
            "UNEVALUATED rather than letting it pass silently."
        ),
        "freshness_days": None,
        "sign_off_required": True,
        "sign_off_scope": "PCI-DSS-4.2.1",
    },
    {
        "requirement": "NIST-IR-8547-A",
        "framework": "NIST IR 8547 / SP 1800-38 (quantum readiness)",
        "title": "Cryptographic inventory is current across the estate",
        "mapped_controls": [],
        "evidence_source": None,
        "gap": (
            "CBOM coverage lives in the scanning pipeline (scans → facts → "
            "CBOM), which this platform-control register does not yet read. "
            "Estate-wide scan freshness must be reviewed on the scan/CBOM "
            "surfaces until the mapping exists — it is NOT evidenced here."
        ),
        "freshness_days": None,
        "sign_off_required": True,
        "sign_off_scope": "NIST-IR-8547-A",
    },
]


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _evaluate_one(
    req: dict[str, Any], pack: dict | None, by_scope: dict[str, list[dict]], now: datetime
) -> dict[str, Any]:
    mapped: list[str] = req["mapped_controls"]
    pack_controls: dict[str, dict] = {}
    generated_at: datetime | None = None
    if pack is not None:
        pack_controls = {str(c.get("control")): c for c in (pack.get("controls") or []) if isinstance(c, dict)}
        generated_at = _parse_iso(pack.get("generated_at"))

    # ---- exact evidence: one row per mapped control, missing stays missing
    evidence_controls = [
        {
            "control": key,
            "status": (pack_controls[key].get("status") if key in pack_controls else "missing"),
            "checked_at": (pack_controls[key].get("checked_at") if key in pack_controls else None),
        }
        for key in mapped
    ]

    # ---- evidence state (never invented from absence)
    if pack is None:
        evidence_state = "no_evidence"
    elif not mapped:
        evidence_state = "unevaluated"
    elif any(c["status"] == "missing" for c in evidence_controls):
        evidence_state = "missing_evidence"
    elif any(c["status"] == "fail" for c in evidence_controls):
        evidence_state = "gap"
    elif any(c["status"] not in ("pass", "fail") for c in evidence_controls):
        evidence_state = "not_evaluable"
    else:
        evidence_state = "pass"

    # ---- expiry: evidence age against the requirement's freshness window
    if pack is None or not mapped:
        expiry_state: str | None = "no_evidence" if pack is None else "not_applicable"
        age_days = None
    elif generated_at is None:
        expiry_state, age_days = "unknown", None
    else:
        age_days = (now - generated_at).total_seconds() / 86400
        window = req["freshness_days"]
        expiry_state = ("expired" if age_days > float(window) else "fresh") if window is not None else "unknown"

    # ---- reviewer sign-off: persisted attestations over THIS pack
    records = by_scope.get(req["sign_off_scope"], [])
    if not req["sign_off_required"]:
        sign_off_state = "not_required"
    elif any(r.get("jws_valid") for r in records):
        sign_off_state = "signed"
    elif records:
        sign_off_state = "invalid"  # signatures exist but none verify
    else:
        sign_off_state = "unsigned"

    # ---- combined standing — the honest verdict, precedence matters
    if evidence_state == "no_evidence":
        standing = "no_evidence"
    elif evidence_state == "unevaluated":
        # a manual sign-off NEVER turns an unmapped requirement into evidence
        standing = "unevaluated"
    elif evidence_state in ("missing_evidence", "gap", "not_evaluable"):
        standing = evidence_state
    elif expiry_state == "expired":
        standing = "expired"
    elif sign_off_state in ("unsigned", "invalid"):
        standing = "awaiting_sign_off"
    else:
        standing = "evidenced"

    return {
        "requirement": req["requirement"],
        "framework": req["framework"],
        "title": req["title"],
        "mapped_controls": mapped,
        "evidence_source": req["evidence_source"],
        "gap": req["gap"],
        "freshness_days": req["freshness_days"],
        "sign_off_required": req["sign_off_required"],
        "sign_off_scope": req["sign_off_scope"],
        "evidence_controls": evidence_controls,
        "evidence_state": evidence_state,
        "expiry": {
            "state": expiry_state,
            "age_days": (round(age_days, 1) if age_days is not None else None),
        },
        "sign_off": {
            "required": req["sign_off_required"],
            "state": sign_off_state,
            "records": records,
        },
        "standing": standing,
        "closed": standing == "evidenced",
    }


def evaluate_requirements(
    pack: dict | None, attestations: list[dict] | None, *, now: datetime | None = None
) -> dict[str, Any]:
    """Evaluate the register against ONE pack and its attestations.

    ``pack`` is an evidence pack dict (with ``pack_sha256``) or None when no
    pack has been pinned — every requirement then reports ``no_evidence``.
    ``attestations`` are already-verified records (``jws_valid`` flag) for
    that pack; attestations over a DIFFERENT pack never sign this one off.
    """
    pack_sha = (pack or {}).get("pack_sha256")
    by_scope: dict[str, list[dict]] = {}
    for att in attestations or []:
        if pack_sha is not None and att.get("pack_sha256") != pack_sha:
            continue  # a signature over other evidence never signs this pack
        by_scope.setdefault(str(att.get("scope")), []).append(att)

    now = now or datetime.now(timezone.utc)
    rows = [_evaluate_one(req, pack, by_scope, now) for req in REGISTER]
    by_standing: dict[str, int] = {}
    for row in rows:
        by_standing[row["standing"]] = by_standing.get(row["standing"], 0) + 1
    return {
        "requirements": rows,
        "summary": {
            "requirements": len(rows),
            "denominator": len(rows),  # explicit: the score's denominator
            "closed": sum(1 for r in rows if r["closed"]),
            "by_standing": by_standing,
            "sign_off_required": sum(1 for r in rows if r["sign_off_required"]),
            "signed": sum(1 for r in rows if r["sign_off"]["state"] == "signed"),
        },
    }
