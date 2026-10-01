"""Read-only realtime payment/HSM audit scanner adapter.

The monitor/API runner supplies an operator-owned JSON configuration containing
an audit-feed path or URL.  This command never returns raw audit lines or key
material; it emits normalized event metadata, a content-derived evidence
reference, and an opaque feed cursor.  An empty but successfully polled feed
is ``PASS`` with zero observations, while feed errors remain ``FAIL`` or
``DEGRADED`` and are never converted into an empty success.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from payment_crypto.connectors import connector_from_config


_SECRET_NAMES = {"token", "secret", "password", "private_key", "key_material", "raw"}


def _safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _safe(item)
            for key, item in value.items()
            if str(key).lower() not in _SECRET_NAMES
        }
    if isinstance(value, list):
        return [_safe(item) for item in value]
    return value


def _observation(record: Any) -> dict[str, Any]:
    data = _safe(record.to_dict())
    data.pop("raw", None)
    data["evidence_reference"] = "sha256:" + hashlib.sha256(
        json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    return data


def run(config: dict[str, Any]) -> dict[str, Any]:
    connector = connector_from_config(config)
    if connector is None:
        return {
            "scanner": "payment",
            "scan_status": "BLOCKED",
            "error": "payment audit feed requires config.path or config.url",
            "observations": [],
            "findings": [],
            "cursor": None,
        }
    polled = connector.poll()
    observations = [_observation(record) for record in polled.records]
    status = "FAIL" if polled.errors and not observations else "DEGRADED" if polled.errors else "PASS"
    return {
        "scanner": "payment",
        "scan_status": status,
        "observations": observations,
        "findings": [
            {"kind": "audit_feed", "severity": "HIGH", "message": error,
             "evidence_reference": None}
            for error in polled.errors
        ],
        "cursor": polled.cursor,
        "accepted": len(observations),
        "errors": list(polled.errors),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Poll an operator-supplied payment/HSM audit feed")
    parser.add_argument("--config", required=True, help="JSON file with path or URL for the audit feed")
    args = parser.parse_args(argv)
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("payment config must be a JSON object")
        result = run(config)
    except Exception as exc:  # noqa: BLE001 — preserve an honest scanner failure
        result = {
            "scanner": "payment", "scan_status": "FAIL", "observations": [],
            "findings": [], "cursor": None, "error": f"payment scanner error: {exc}",
        }
    print(json.dumps(result, sort_keys=True, default=str))
    return 0 if result.get("scan_status") in {"PASS", "DEGRADED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
