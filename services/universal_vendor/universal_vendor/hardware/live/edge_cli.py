"""Edge hardware agent CLI (§21).

A deployable edge agent for 24/7 distributed hardware monitoring:

    python -m universal_vendor.hardware.live.edge_cli \\
        --agent-id edge-a --queue-dir /var/lib/zelinx-edge ingest event.json
    python -m universal_vendor.hardware.live.edge_cli \\
        --agent-id edge-a --queue-dir /var/lib/zelinx-edge sync --url http://central:8010
    python -m universal_vendor.hardware.live.edge_cli \\
        --agent-id edge-a --queue-dir /var/lib/zelinx-edge status

Behavior (§21):
- ingest  → local durable queue + local chained evidence (works offline)
- sync    → POST pending events to the control plane's /hardware/edge/sync;
            the local queue is drained ONLY after an HTTP 2xx ACK
- status  → queue depth, evidence records, last sync, failure count

No third-party dependencies: urllib + the stdlib JSONL store.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from universal_vendor.hardware.live.edge import EdgeHardwareAgent
from universal_vendor.hardware.live.events import HardwareEvent


def _agent(args: argparse.Namespace) -> EdgeHardwareAgent:
    queue_dir = Path(args.queue_dir)
    return EdgeHardwareAgent(
        args.agent_id,
        queue_path=queue_dir / "events.jsonl",
        evidence_path=queue_dir / "evidence.jsonl",
    )


def _read_event(source: str) -> HardwareEvent:
    if source == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(source).read_text(encoding="utf-8")
    data = json.loads(raw)
    return HardwareEvent(**data)


def cmd_ingest(args: argparse.Namespace) -> int:
    agent = _agent(args)
    event = _read_event(args.file)
    agent.ingest(event)
    print(json.dumps({
        "agent_id": agent.agent_id,
        "ingested": event.event_type.value,
        "asset_id": event.asset_id,
        "queue_depth": agent.pending_count(),
        "evidence_records": agent.evidence_count(),
    }))
    return 0


def cmd_sync(args: argparse.Namespace) -> int:
    agent = _agent(args)

    def flush(payload: list[dict[str, Any]]) -> None:
        body = json.dumps({
            "agent_id": agent.agent_id,
            "events": payload,
        }).encode("utf-8")
        request = urllib.request.Request(
            args.url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=args.timeout) as response:
                if not (200 <= response.status < 300):
                    raise RuntimeError(f"control plane returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:  # urllib raises on >=400
            raise RuntimeError(f"control plane returned HTTP {exc.code}") from exc

    result = agent.sync(flush)
    print(json.dumps(result))
    return 0 if result.get("synced") else 1


def cmd_status(args: argparse.Namespace) -> int:
    agent = _agent(args)
    print(json.dumps(agent.state()))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zelinx-hardware-edge",
        description="24/7 hardware edge agent — durable local queue + central sync (§21).")
    parser.add_argument("--agent-id", required=True, help="unique edge agent id")
    parser.add_argument("--queue-dir", default="/tmp/zelinx-edge-hardware",
                        help="directory for the durable queue + evidence store")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="enqueue one hardware event (JSON file or '-')")
    p_ingest.add_argument("file", help="path to event JSON, or '-' for stdin")
    p_ingest.set_defaults(func=cmd_ingest)

    p_sync = sub.add_parser("sync", help="flush the queue to the control plane")
    p_sync.add_argument("--url", required=True,
                        help="control plane endpoint, e.g. http://central:8010/api/v1/hardware/edge/sync")
    p_sync.add_argument("--timeout", type=int, default=30)
    p_sync.set_defaults(func=cmd_sync)

    p_status = sub.add_parser("status", help="queue depth, evidence, last sync")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
