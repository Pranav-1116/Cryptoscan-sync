"""HSM audit-feed connectors: pull, don't guess.

Three real connectors plus a drill simulator, all normalized through
``HsmAuditParser``:

- ``HttpJsonlConnector`` — polls any HTTP endpoint that returns JSONL audit
  lines (SIEM export, vendor log gateway). ``?since=`` is appended when the
  endpoint supports it; dedupe by timestamp happens in the parser/runner.
- ``SyslogFileConnector`` — tails a file with a persistent byte-offset
  cursor, so nothing is re-read after a restart and rotation (shrink) is
  detected honestly.
- ``PayshieldSimulator`` — deterministic payShield-shaped audit generator
  for DR drills and demos, clearly labeled SIMULATOR in every line. It is
  never a substitute for a real device: no vendor protocol is guessed here.

Adding a real device later means writing one ``poll()`` that yields lines
from it — the parsing, dedupe, inventory and policy layers stay unchanged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib import request as urlrequest

from payment_crypto.auditlog import HsmAuditParser


@dataclass
class ConnectorResult:
    records: list = field(default_factory=list)
    cursor: str | None = None       # opaque (offset, etag, timestamp) — pass back on next poll
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class HttpJsonlConnector:
    """Poll an HTTP JSONL audit export (SIEM gateway / vendor web API)."""

    def __init__(self, url: str, *, token: str = "", timeout: float = 10.0,
                 fetch: Callable[[str, dict], tuple[int, str]] | None = None):
        self.url = url
        self.token = token
        self.timeout = timeout
        self._fetch = fetch or self._http_get

    def poll(self, since: datetime | None = None) -> ConnectorResult:
        url = self.url
        if since is not None:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}since={since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        status, body = self._fetch(url, {"Authorization": f"Bearer {self.token}"} if self.token else {})
        if status != 200:
            return ConnectorResult(errors=[f"HTTP {status} from {self.url}"])
        parsed = HsmAuditParser().parse_jsonl(body)
        if parsed.rejected and not parsed.records:
            return ConnectorResult(errors=[f"unparsable feed: {parsed.rejected[0]['reason']}"])
        newest = max((record.occurred_at for record in parsed.records), default=None)
        result = ConnectorResult(records=parsed.records, cursor=newest.isoformat() if newest else None,
                                 errors=[f"rejected {len(parsed.rejected)} line(s)"] if parsed.rejected else [])
        return result

    @staticmethod
    def _http_get(url: str, headers: dict) -> tuple[int, str]:
        req = urlrequest.Request(url, headers=headers)
        with urlrequest.urlopen(req, timeout=10) as response:  # operator-configured URL
            return response.status, response.read().decode("utf-8", errors="replace")


class SyslogFileConnector:
    """Tail a syslog/JSONL audit file with a durable byte-offset cursor."""

    def __init__(self, path: str | Path, *, cursor_path: str | Path | None = None):
        self.path = Path(path)
        self.cursor_path = Path(cursor_path) if cursor_path else self.path.with_suffix(self.path.suffix + ".cursor")

    def poll(self) -> ConnectorResult:
        if not self.path.is_file():
            return ConnectorResult(errors=[f"audit file not found: {self.path}"])
        offset = self._read_cursor()
        size = self.path.stat().st_size
        if offset > size:  # rotated/truncated: start over, say so
            offset = 0
            rotated = True
        else:
            rotated = False
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            fresh = handle.read()
        new_offset = offset + len(fresh.encode("utf-8"))
        parsed = HsmAuditParser().autodetect(fresh) if fresh.strip() else HsmAuditParser().parse_jsonl("")
        self._write_cursor(new_offset)
        errors = list(parsed.rejected[0:1] and [f"rejected {len(parsed.rejected)} line(s)"]) if parsed.rejected else []
        if rotated:
            errors.append("audit file rotated/truncated — re-reading from start")
        return ConnectorResult(records=parsed.records, cursor=str(new_offset), errors=errors)

    def _read_cursor(self) -> int:
        try:
            return int(self.cursor_path.read_text().strip() or 0)
        except (OSError, ValueError):
            return 0

    def _write_cursor(self, offset: int) -> None:
        self.cursor_path.write_text(str(offset))


class PayshieldSimulator:
    """Deterministic payShield-style audit stream for drills (NOT a real HSM).

    Generates a realistic day: PIN verifications/translations on ZPKs, MAC
    generation, an occasional auth-failure burst, rare ceremony/clear-export
    events when seeded. Every line is tagged ``sim=hsm-simulator``.
    """

    def __init__(self, seed: int = 1337):
        self.seed = seed

    def day(self, day: datetime, *, transactions: int = 10_000_000, devices: tuple[str, ...] = ("hsm-sim-1",)) -> str:
        rng = _Seeded(self.seed + day.toordinal())
        int(transactions * 1.08)  # ~1.08 HSM ops per transaction (verify + some translates)
        lines = []
        device = devices[rng.below(len(devices))]
        for _ in range(3):  # sampled usage events (a full day would be millions)
            minute = rng.below(24 * 60)
            stamp = day.replace(hour=minute // 60, minute=minute % 60, second=rng.below(60), tzinfo=timezone.utc)
            key = f"ZPK-SIM-{1 + rng.below(3):02d}"
            op = ("pin_verify", "pin_translate", "mac_generate")[rng.below(3)]
            lines.append(json.dumps({
                "occurred_at": stamp.isoformat(), "device": device, "event_type": "KEY_USED",
                "key_id": key, "actor": "switch", "detail": {"op": op, "sim": "hsm-simulator"},
            }))
        if rng.below(10) == 0:  # ~10% of days: an auth-failure burst
            lines.append(json.dumps({
                "occurred_at": (day + timedelta(hours=3, tzinfo=timezone.utc)).isoformat(),
                "device": device, "event_type": "AUTH_FAILURE", "actor": "unknown",
                "detail": {"sim": "hsm-simulator"},
            }))
        return "\n".join(lines)

    def summary(self, day: datetime, *, transactions: int = 10_000_000) -> dict:
        """Aggregate op count a drill records for the day (10M tx -> ~10.8M ops)."""
        return {"date": day.date().isoformat(), "hsm_ops": int(transactions * 1.08),
                "simulator": True}


class _Seeded:
    """Tiny deterministic PRNG (no external deps)."""

    def __init__(self, seed: int):
        self.state = (seed or 1) & 0x7FFFFFFF

    def below(self, bound: int) -> int:
        self.state = (1103515245 * self.state + 12345) & 0x7FFFFFFF
        return self.state % max(1, bound)


def connector_from_config(config: dict):
    """Build a connector from monitor-target config (PAYMENT runner)."""
    if config.get("url"):
        return HttpJsonlConnector(str(config["url"]), token=str(config.get("token") or ""))
    if config.get("path"):
        return SyslogFileConnector(str(config["path"]))
    return None


def audit_lines_to_records(text: str) -> list:
    parsed = HsmAuditParser().autodetect(text)
    return parsed.records


# keep flake-free re-export used by docs
SIMULATOR_NOTE = "PayshieldSimulator generates synthetic audit data for drills only — never for production evidence."
