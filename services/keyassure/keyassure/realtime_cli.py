"""Realtime key-assurance adapter for the common live-scan pipeline.

It runs the existing deterministic TLS audit against an operator-supplied
host/port JSON configuration and emits its observed protocols, ciphers,
certificate metadata, and findings unchanged. No certificate/private-key
material is returned.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from keyassure.tls_audit import audit_tls_endpoint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a key-assurance TLS audit")
    parser.add_argument("--config", required=True, help="JSON with host, optional port/sni/timeout")
    args = parser.parse_args(argv)
    try:
        config: dict[str, Any] = json.loads(Path(args.config).read_text(encoding="utf-8"))
        host = str(config.get("host") or "").strip()
        if not host:
            raise ValueError("key-assurance config requires host")
        result = audit_tls_endpoint(
            host,
            int(config.get("port") or 443),
            sni=config.get("sni"),
            timeout=float(config.get("timeout") or 6.0),
        )
        result["scanner"] = "keyassure"
        result["scan_status"] = "PASS" if result.get("reachable") else "DEGRADED"
        print(json.dumps(result, sort_keys=True, default=str))
        return 0
    except Exception as exc:  # noqa: BLE001 — preserve an honest failed audit
        print(json.dumps({
            "scanner": "keyassure", "scan_status": "FAIL", "findings": [],
            "error": f"key-assurance audit failed: {exc}",
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
