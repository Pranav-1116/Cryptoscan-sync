"""Notify business owners of P0 crypto risk. SMTP optional; always logs."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def render_template(name: str, **values: Any) -> str:
    path = TEMPLATE_DIR / name
    text = path.read_text(encoding="utf-8") if path.exists() else "{message}"
    payload = {key: ("" if value is None else value) for key, value in values.items()}
    try:
        return text.format_map(_Default(payload))
    except Exception:
        return text


class _Default(dict):
    def __missing__(self, key: str) -> str:
        return ""


def notify_stakeholders(assets: Iterable[Mapping[str, Any]], *, smtp_host: str | None = None) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    for asset in assets:
        ctx = (asset.get("extra") or {}).get("business_context") or asset.get("business_context") or {}
        if ctx.get("priority") != "P0":
            continue
        owners = ctx.get("business_owners") or []
        processes = ctx.get("affected_processes") or []
        body = render_template(
            "business_owner_alert.txt",
            owner_name=owners[0] if owners else "owner",
            process_name=processes[0] if processes else "unknown process",
            system_name=asset.get("system_id") or "system",
            algorithm=asset.get("algorithm"),
            file_path=asset.get("file_path"),
            compliance_status=asset.get("compliance_status") or "FAIL",
            revenue_daily=ctx.get("total_revenue_at_risk"),
            customer_count=ctx.get("total_customers_at_risk"),
            scopes=", ".join(ctx.get("compliance_scopes") or []),
        )
        exec_body = None
        html_body = render_template(
            "business_owner_alert.html",
            owner_name=owners[0] if owners else "owner",
            process_name=processes[0] if processes else "unknown process",
            system_name=asset.get("system_id") or "system",
            algorithm=asset.get("algorithm"),
            file_path=asset.get("file_path"),
            compliance_status=asset.get("compliance_status") or "FAIL",
            revenue_daily=ctx.get("total_revenue_at_risk"),
            customer_count=ctx.get("total_customers_at_risk"),
            scopes=", ".join(ctx.get("compliance_scopes") or []),
        )
        if float(ctx.get("total_revenue_at_risk") or 0) >= 1_000_000:
            exec_body = render_template(
                "executive_alert.txt",
                sponsor_role="CFO",
                process_name=processes[0] if processes else "unknown process",
                revenue_daily=ctx.get("total_revenue_at_risk"),
                customer_count=ctx.get("total_customers_at_risk"),
                owner_name=owners[0] if owners else "owner",
                algorithm=asset.get("algorithm"),
                compliance_status=asset.get("compliance_status") or "FAIL",
            )
            exec_html = render_template(
                "executive_alert.html",
                sponsor_role="CFO",
                process_name=processes[0] if processes else "unknown process",
                revenue_daily=ctx.get("total_revenue_at_risk"),
                customer_count=ctx.get("total_customers_at_risk"),
                owner_name=owners[0] if owners else "owner",
                algorithm=asset.get("algorithm"),
                compliance_status=asset.get("compliance_status") or "FAIL",
            )
        else:
            exec_html = None
        payload = {
            "algorithm": asset.get("algorithm"),
            "file_path": asset.get("file_path"),
            "owners": owners,
            "revenue": ctx.get("total_revenue_at_risk"),
            "message": body.splitlines()[0] if body else f"P0 crypto risk: {asset.get('algorithm')}",
            "body": body,
            "html_body": html_body,
            "executive_body": exec_body,
            "executive_html": exec_html,
        }
        logger.warning("stakeholder_alert %s", payload.get("headline") or payload.get("algorithm"))
        sent.append(payload)
    return sent
