"""Inbound ChatOps slash commands (deep/31, round 38).

The workspace-facing half of ChatOps: a ``POST /chatops/command``
endpoint a Slack/Mattermost outgoing-webhook or slash command calls
with a text command, HMAC-verified with the ChatOps secret (the token
in the payload is compared constantly; the signature covers the body).

Only read-only commands exist — ChatOps is a window onto the platform,
never a write path:

* ``status``      — estate pulse (systems, assets, advisories, scans)
* ``fact <ALGO>`` — cryptographic fact store lookup (top facts)
* ``advisories <ALGO>`` — active threat-intel advisories for one algorithm

Every response is Slack/Mattermost-compatible ``{"text": ...}`` with an
honest "not configured / nothing found" answer instead of an error. A
misconfigured secret disables the surface with a 503, never an
unauthenticated 200.
"""

from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.dependencies import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chatops", tags=["chatops"])

_MAX_FACTS = 5
_MAX_ADVISORIES = 5


def _constant_eq(left: str, right: str) -> bool:
    return hmac.compare_digest(str(left or ""), str(right or ""))


def _verify_signature(secret: str, raw: bytes, signature: str) -> bool:
    digest = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", str(signature or ""))


async def _parse_command(request: Request) -> dict[str, str]:
    """Slack/Matterboth post form-encoded; accept JSON too (proxies)."""
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
            return {k: str(v) for k, v in (body or {}).items()}
        except Exception:  # noqa: BLE001 — malformed body is a 400
            raise HTTPException(status_code=400, detail="malformed JSON body")
    form = await request.form()
    return {k: str(v) for k, v in form.items()}


@router.post("/command")
async def chatops_command(
    request: Request,
    db: Session = Depends(get_db_session),
):
    """Execute one read-only ChatOps command (never a write path)."""
    from api.config.settings import get_settings

    settings = get_settings()
    secret = (settings.ALERT_CHATOPS_SECRET or "").strip()
    if len(secret.encode()) < 8:
        raise HTTPException(status_code=503,
                            detail="chatops commands not configured "
                                   "(ALERT_CHATOPS_SECRET missing)")
    expected_token = (settings.ALERT_CHATOPS_COMMAND_TOKEN or "").strip()

    raw = await request.body()
    signature = request.headers.get("X-CryptoScan-Signature", "")
    if not _verify_signature(secret, raw, signature):
        raise HTTPException(status_code=401, detail="invalid command signature")

    fields = await _parse_command(request)
    if expected_token and not _constant_eq(fields.get("token", ""),
                                           expected_token):
        raise HTTPException(status_code=401, detail="invalid command token")

    text = str(fields.get("text") or "").strip()
    parts = text.split()
    command = (parts[0] or "").lower() if parts else ""
    argument = parts[1].strip() if len(parts) > 1 else ""

    from db.models.crypto_asset import CryptoAsset
    from db.models.scan import Scan
    from db.models.system import System
    from db.models.threat_advisory import AlgorithmAdvisory
    from db.models.cryptographic_fact import CryptographicFact

    if command in ("", "help"):
        return {"text": "CryptoScan commands (read-only): `status`, "
                        "`fact <ALGORITHM>`, `advisories <ALGORITHM>`"}
    if command == "status":
        systems = db.execute(select(func.count(System.id))).scalar() or 0
        assets = db.execute(select(func.count(CryptoAsset.id))).scalar() or 0
        advisories = db.execute(
            select(func.count(AlgorithmAdvisory.id))).scalar() or 0
        scans = db.execute(select(func.count(Scan.id))).scalar() or 0
        return {"text": f"CryptoScan estate: {systems} systems, "
                        f"{assets} crypto assets, {advisories} advisories, "
                        f"{scans} scans recorded"}
    if command == "fact":
        if not argument:
            return {"text": "usage: `fact <ALGORITHM>` (e.g. `fact RSA-2048`)"}
        rows = db.execute(
            select(CryptographicFact)
            .where(CryptographicFact.algorithm == argument.upper())
            .order_by(CryptographicFact.observation_count.desc())
            .limit(_MAX_FACTS)).scalars().all()
        if not rows:
            return {"text": f"no facts recorded for {argument.upper()!r} "
                            f"(the fact store is rebuilt after each scan)"}
        lines = [f"top {len(rows)} fact(s) for {argument.upper()}:"]
        for row in rows:
            where = str(row.file_path or "unknown file")
            lines.append(f"• {row.observation_count} observation(s) — "
                         f"{row.purpose or 'unknown purpose'} — {where}")
        return {"text": "\n".join(lines)}
    if command == "advisories":
        if not argument:
            return {"text": "usage: `advisories <ALGORITHM>` "
                            "(e.g. `advisories SHA-1`)"}
        rows = db.execute(
            select(AlgorithmAdvisory)
            .where(AlgorithmAdvisory.algorithm == argument.upper())
            .order_by(AlgorithmAdvisory.severity)
            .limit(_MAX_ADVISORIES)).scalars().all()
        if not rows:
            return {"text": f"no advisories recorded for {argument.upper()!r}"}
        lines = [f"advisories for {argument.upper()}:"]
        for row in rows:
            lines.append(f"• [{row.severity}] {row.advisory_id}: {row.title}")
        return {"text": "\n".join(lines)}

    logger.info("chatops_command_rejected", extra={"command": command[:40]})
    return {"text": f"unknown command {command!r} — try `help`"}
