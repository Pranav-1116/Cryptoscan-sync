#!/usr/bin/env python3
"""CryptoScan Telecom realtime crypto scanner.

Continuously classifies the cryptographic posture of 3GPP network functions
(5G SBA, EPC, IMS, signaling, NDS/IP gateways) across an international
carrier estate:

  python -m telecom_scanner.main --json          # probe the registry, print snapshot
  python -m telecom_scanner.main --only amf-01   # one NF
  python -m telecom_scanner.main --state PATH    # state file for realtime diffs

TLS probing composes ``network_scanner.probing.probe_endpoint`` (the same
primitives the network scanner uses); IPsec/IKE classification is taken from
operator-side ingest — never faked from this vantage. Realtime events are
the diff against the persisted previous state (telecom_scanner.realtime).
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_state(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return raw.get("state") or {}


def probe_one(endpoint: str, *, timeout: float = 4.0) -> dict[str, Any]:
    """One TLS probe via the network_scanner primitives (in-process)."""
    from network_scanner.probing.active_prober import probe_endpoint

    return probe_endpoint(endpoint, timeout=timeout, check_http=False)


def probe_registry(
    registry: dict[str, Any],
    *,
    only: list[str] | None = None,
    timeout: float = 4.0,
    max_workers: int = 8,
) -> list[dict[str, Any]]:
    """Probe all registered TLS-bearing targets; returns classify rows.

    IPsec gateways are classified as IPSEC_UNKNOWN (ingest path) — the
    scanner never fabricates IKE results it did not observe.
    """
    from telecom_scanner.classify import classify_target
    from telecom_scanner.registry import NF_CATALOG

    targets = registry.get("targets") or {}
    if only:
        wanted = {n.strip().lower() for n in only}
        targets = {k: v for k, v in targets.items() if k in wanted}

    def _run(target: dict[str, Any]) -> dict[str, Any]:
        if NF_CATALOG.get(target.get("nf_type"), {}).get("transport") == "ipsec":
            return classify_target(target, None)
        try:
            probe = probe_one(str(target.get("endpoint")), timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — a probe must never abort the pass
            probe = {"status": "CONNECT_ERROR", "error": str(exc)}
        return classify_target(target, probe)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        rows = list(pool.map(_run, list(targets.values())))
    rows.sort(key=lambda r: str(r.get("nf_id")))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the snapshot as JSON to stdout")
    parser.add_argument("--registry", default=None, help="registry path (default: CRYPTOSCAN_TELECOM_REGISTRY / config)")
    parser.add_argument("--state", default=None, help="previous-state file for realtime diffs")
    parser.add_argument("--only", default="", help="comma-separated nf_id list")
    parser.add_argument("--timeout", type=float, default=4.0, help="per-endpoint TLS timeout seconds")
    args = parser.parse_args(argv)

    from telecom_scanner.realtime import evaluate_changes
    from telecom_scanner.registry import default_registry_path, load_registry
    from telecom_scanner.rollup import posture_rollup

    registry = load_registry(args.registry or default_registry_path())
    only = [n for n in (args.only or "").split(",") if n.strip()]
    rows = probe_registry(registry, only=only or None, timeout=args.timeout)

    state_path = Path(args.state) if args.state else None
    previous = _load_state(state_path)
    events = evaluate_changes(previous, rows)

    state = {row["nf_id"]: {k: row[k] for k in ("status", "severity", "fingerprint", "cert_not_after")} for row in rows}
    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "telecom-scanner-v1.0",
        "targets_registered": len(registry.get("targets") or {}),
        "rows": rows,
        "events": events,
        "state": state,
        "rollup": posture_rollup(rows, registry.get("carriers") or {}),
    }
    if state_path is not None:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps({"generated_at": snapshot["generated_at"], "state": state}, indent=2))
    if args.json or not sys.stdout.isatty():
        print(json.dumps(snapshot, indent=2))
    else:
        print(f"targets={len(rows)} critical={snapshot['rollup']['totals']['critical']} "
              f"events={len(events)} (use --json for the full snapshot)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
