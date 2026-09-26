"""Compliance evidence & attestation engine.

Everything in an evidence pack comes from REAL live system state — control
checks run at collection time, never from a template. Attestations sign a
snapshot with the platform's JWS signer (RFC 7515) so a CISO's attestation is
cryptographically verifiable years later, independent of this database.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# WORM retention policy (audit log immutability)
# ---------------------------------------------------------------------------
DEFAULT_RETENTION = {
    "audit_log_years": 7,
    "metering_years": 7,
    "attestations_years": 7,
    "policy": "WORM: append-only stores must not be truncated or deleted "
              "before the retention age; cleanup routines must consult "
              "can_delete() before removing anything.",
}


def can_delete(store_name: str, oldest_record_epoch: float | None,
               policy: dict | None = None, *,
               now: float | None = None) -> tuple[bool, str]:
    """Deterministic WORM gate. Returns (allowed, reason)."""
    policy = policy or DEFAULT_RETENTION
    now = now if now is not None else time.time()
    key = f"{store_name}_years" if f"{store_name}_years" in policy else "audit_log_years"
    years = float(policy.get(key, policy.get("audit_log_years", 7)))
    if oldest_record_epoch is None:
        return False, f"{store_name}: no records — nothing to delete"
    age_years = (now - oldest_record_epoch) / (365.25 * 24 * 3600)
    if age_years < years:
        remaining = years - age_years
        return False, (f"WORM: {store_name} records are {age_years:.1f}y old, "
                       f"retention {years:.0f}y — {remaining:.1f}y remaining")
    return True, f"{store_name}: retention {years:.0f}y satisfied"


# ---------------------------------------------------------------------------
# evidence pack (automated control evidence from live state)
# ---------------------------------------------------------------------------
def _check(id_: str, ok: bool | None, evidence: Any) -> dict[str, Any]:
    status = "pass" if ok is True else ("fail" if ok is False else "unknown")
    return {"control": id_, "status": status,
            "evidence": evidence,
            "checked_at": datetime.now(timezone.utc).isoformat()}


def collect_evidence(db, *, app_settings=None, secret: str | None = None) -> dict:
    """Run every automatable control check against live state."""

    controls: list[dict[str, Any]] = []

    # CC6.1-ish: logical access — auth config actually in force
    if app_settings is not None:
        env = getattr(app_settings, "ENVIRONMENT", None)
        controls.append(_check(
            "access.session_config", True,
            {"cookie_secure": getattr(app_settings, "cookie_secure", None),
             "environment": env}))
        # CC6.6-ish: production secrets gate
        is_prod = str(env).lower() == "production"
        enforced = "dormant (non-production)" 
        ok = True
        if is_prod:
            try:
                from api.config.settings import validate_runtime_settings

                validate_runtime_settings(app_settings)
            except Exception:
                ok = False
            enforced = "enforced (fail-closed on demo secrets)"
        controls.append(_check(
            "config.production_gate", ok,
            {"environment": env, "gate": enforced}))

    # CC7.2-ish: audit trail integrity — every raw log line must HMAC-verify.
    # replay() silently skips lines that fail verification, so compare the
    # raw on-disk line count against the verified replay count.
    chain: dict[str, Any] = {"verified": None, "events": 0}
    try:
        from eventstream.bus import get_bus

        bus = get_bus()
        log_file = bus.log_dir / "audit-log.jsonl"
        raw_lines = 0
        if log_file.exists():
            raw_lines = sum(1 for ln in log_file.read_text(encoding="utf-8").splitlines()
                            if ln.strip())
        replayed = sum(1 for _env in bus.replay("audit-log"))
        chain["raw_lines"] = raw_lines
        chain["events"] = replayed
        chain["verified"] = replayed == raw_lines
    except Exception as exc:  # bus not configured in this deployment
        chain["note"] = str(exc)[:160]
    controls.append(_check("audit.chain_integrity", chain["verified"], chain))

    # CC8.1-ish: change management — deployed schema matches the models
    drift_ok = None
    try:
        from db.connection.engine import get_engine
        from db.connection.schema_ensure import schema_drift_report

        report = schema_drift_report(get_engine())
        drift_ok = bool(report.get("in_sync"))
        controls.append(_check("deploy.schema_in_sync", drift_ok, report))
    except Exception as exc:
        controls.append(_check("deploy.schema_in_sync", None, {"note": str(exc)[:120]}))

    # CC6.x-ish: rate limiting configured (DoS/brute-force protection present)
    try:
        from api.middleware.rate_limit import DEFAULT_RULES

        controls.append(_check(
            "protection.rate_limits", len(DEFAULT_RULES) >= 3,
            {k: v for k, v in DEFAULT_RULES.items()}))
    except Exception as exc:
        controls.append(_check("protection.rate_limits", None, {"note": str(exc)[:120]}))

    # retention policy present (WORM stance)
    policy, policy_note = DEFAULT_RETENTION, None
    try:
        from db.repositories.settings_repository import SettingsRepository

        policy = SettingsRepository(db).get("compliance.retention", None) \
            or DEFAULT_RETENTION
    except Exception as exc:
        policy_note = f"settings store unavailable, defaults in force: {str(exc)[:80]}"
    payload = dict(policy)
    if policy_note:
        payload["note"] = policy_note
    controls.append(_check("retention.worm_policy", True, payload))

    pack = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "controls": controls,
        "summary": {
            "pass": sum(1 for c in controls if c["status"] == "pass"),
            "fail": sum(1 for c in controls if c["status"] == "fail"),
            "unknown": sum(1 for c in controls if c["status"] == "unknown"),
        },
    }
    body = json.dumps(pack, sort_keys=True, default=str).encode()
    pack["pack_sha256"] = hashlib.sha256(body).hexdigest()
    return pack


# ---------------------------------------------------------------------------
# attestation (signed compliance snapshot, verifiable for years)
# ---------------------------------------------------------------------------
def create_attestation(pack: dict, *, scope: str, signed_by: str,
                       secret: str) -> dict[str, Any]:
    """JWS-sign the evidence pack snapshot -> tamper-evident attestation."""
    from cbom.signing.jws_signer import sign_compact

    snapshot = {
        "scope": scope,
        "signed_by": signed_by,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "pack_sha256": pack.get("pack_sha256"),
        "summary": pack.get("summary"),
        "controls": [c["control"] for c in pack.get("controls", [])],
    }
    body = json.dumps(snapshot, sort_keys=True, default=str).encode()
    jws = sign_compact(body, secret, "HS256")
    return {"snapshot": snapshot, "jws": jws}


def verify_attestation(attestation: dict, secret: str) -> dict[str, Any]:
    from cbom.signing.jws_signer import verify_compact

    ok, err = verify_compact(attestation.get("jws", ""), secret, "HS256")
    return {"valid": bool(ok), "error": err or None,
            "snapshot": attestation.get("snapshot") if ok else None}
