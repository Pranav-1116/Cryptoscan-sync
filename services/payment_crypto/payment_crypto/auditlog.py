"""HSM audit-trail ingestion: one taxonomy, whatever the vendor exports.

Banks rarely get a clean API out of their HSMs; they get audit trails —
syslog streams, CSV exports, or SIEM-forwarded JSON. This module normalizes
three *documented* input shapes into one event model:

1. **JSONL** — one event per line, our canonical ingest schema (the shape
   SIEM forwarders produce after transforming vendor logs);
2. **CSV with a column map** — ``columns={"ts": 0, "event": 3, ...}`` so an
   operator maps their HSM export without code changes;
3. **syslog key=value lines** — ``<PRI>date host app: key=value key=value``,
   the common shape of Thales/Utimaco-style syslog exports once they reach a
   collector.

The taxonomy is operational, not vendor: key lifecycle (generated, imported,
exported, rotated, component injected, destroyed/zeroized), ceremony and
dual-control signals, clear-key exports, auth failures, firmware changes.

Anything unparsable is *rejected with a reason* — never silently dropped and
never guessed.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

EVENT_TYPES = {
    "KEY_GENERATED",
    "KEY_IMPORTED",
    "KEY_EXPORTED",
    "KEY_ROTATED",
    "KEY_COMPONENT_INJECTED",
    "KEY_DESTROYED",
    "CLEAR_KEY_EXPORT",
    "CEREMONY_STARTED",
    "CEREMONY_COMPLETED",
    "AUTH_FAILURE",
    "AUTH_SUCCESS",
    "FIRMWARE_UPDATED",
    "ZEROIZED",
    "CONFIG_CHANGED",
    "UNKNOWN_EVENT",
}

# Operator-declared meaning for free-form event codes in CSV/syslog sources.
ALIAS_MAP = {
    "key_gen": "KEY_GENERATED",
    "generate": "KEY_GENERATED",
    "key_import": "KEY_IMPORTED",
    "import": "KEY_IMPORTED",
    "key_export": "KEY_EXPORTED",
    "export": "KEY_EXPORTED",
    "rotate": "KEY_ROTATED",
    "key_inject": "KEY_COMPONENT_INJECTED",
    "component": "KEY_COMPONENT_INJECTED",
    "destroy": "KEY_DESTROYED",
    "zeroize": "ZEROIZED",
    "clear_export": "CLEAR_KEY_EXPORT",
    "clear_key": "CLEAR_KEY_EXPORT",
    "auth_fail": "AUTH_FAILURE",
    "login_failure": "AUTH_FAILURE",
    "auth_ok": "AUTH_SUCCESS",
    "firmware": "FIRMWARE_UPDATED",
    "config": "CONFIG_CHANGED",
}

_SYSLOG_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def _canonical_event(raw: str | None) -> str:
    token = (raw or "").strip()
    upper = token.upper().replace("-", "_").replace(" ", "_")
    if upper in EVENT_TYPES:
        return upper
    return ALIAS_MAP.get(token.lower(), "UNKNOWN_EVENT")


def _parse_ts(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:  # epoch first: collectors love epoch millis
        if text.isdigit():
            return datetime.fromtimestamp(
                int(text) / (1000 if len(text) > 10 else 1), tz=timezone.utc
            )
    except (OverflowError, OSError, ValueError):
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(text.replace("Z", "+0000") if fmt.endswith("z") else text, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@dataclass
class HsmEventRecord:
    occurred_at: datetime
    device: str
    event_type: str
    key_id: str | None = None
    actor: str | None = None
    severity: str = "INFO"          # INFO | WARNING | CRITICAL
    detail: dict = field(default_factory=dict)
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "occurred_at": self.occurred_at.isoformat(),
            "device": self.device,
            "event_type": self.event_type,
            "key_id": self.key_id,
            "actor": self.actor,
            "severity": self.severity,
            "detail": self.detail,
            "raw": self.raw[:2000],
        }


@dataclass
class IngestResult:
    records: list[HsmEventRecord] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.records) and not self.rejected

    def counts(self) -> dict:
        by_type: dict[str, int] = {}
        for record in self.records:
            by_type[record.event_type] = by_type.get(record.event_type, 0) + 1
        return {"accepted": len(self.records), "rejected": len(self.rejected), "by_type": by_type}


class HsmAuditParser:
    """Normalize JSONL / CSV / syslog key=value HSM audit lines."""

    def parse_jsonl(self, text: str) -> IngestResult:
        result = IngestResult()
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                result.rejected.append({"line": number, "reason": f"invalid JSON: {exc}"})
                continue
            if not isinstance(payload, dict):
                result.rejected.append({"line": number, "reason": "JSONL line is not an object"})
                continue
            record = self._from_mapping(payload, raw=line)
            if record is None:
                result.rejected.append({"line": number, "reason": "missing occurred_at/device/event_type"})
                continue
            result.records.append(record)
        return result

    def parse_csv(self, text: str, columns: dict[str, int]) -> IngestResult:
        """``columns`` maps canonical field -> CSV column index (ts, device, event, key_id, actor, severity, detail)."""
        result = IngestResult()
        reader = csv.reader(io.StringIO(text))
        for number, row in enumerate(reader, start=1):
            if not row or (len(row) == 1 and not row[0].strip()):
                continue
            try:
                payload = {name: row[idx] for name, idx in columns.items() if idx < len(row)}
            except (TypeError, IndexError):
                result.rejected.append({"line": number, "reason": "column map out of range"})
                continue
            record = self._from_mapping(
                {
                    "occurred_at": payload.get("ts"),
                    "device": payload.get("device"),
                    "event_type": payload.get("event"),
                    "key_id": payload.get("key_id"),
                    "actor": payload.get("actor"),
                    "severity": payload.get("severity"),
                },
                raw=",".join(row),
            )
            if record is None:
                result.rejected.append({"line": number, "reason": "missing ts/device/event"})
                continue
            if payload.get("detail"):
                try:
                    record.detail.update(json.loads(payload["detail"]))
                except json.JSONDecodeError:
                    record.detail["detail_text"] = payload["detail"]
            result.records.append(record)
        return result

    def parse_syslog(self, text: str) -> IngestResult:
        """Lines like ``<30>2026-08-30T12:00:00Z hsm-1 crypto: event=key_export key_id=ZMK-01 ...``."""
        result = IngestResult()
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            body = re.sub(r"^<\d+>", "", line)
            match = re.match(r"^(\S+\s+\S+|\S+)\s+(\S+)\s+([^:]+):\s*(.*)$", body)
            if match is None:
                result.rejected.append({"line": number, "reason": "not a syslog app/message line"})
                continue
            timestamp_text, device, _app, message = match.groups()
            fields = {key: value.strip('"') for key, value in _SYSLOG_KV.findall(message)}
            occurred = _parse_ts(fields.pop("ts", None) or timestamp_text)
            if occurred is None:
                result.rejected.append({"line": number, "reason": f"unparsable timestamp '{timestamp_text}'"})
                continue
            record = HsmEventRecord(
                occurred_at=occurred,
                device=device,
                event_type=_canonical_event(fields.pop("event", None)),
                key_id=fields.pop("key_id", None) or fields.pop("key", None),
                actor=fields.pop("actor", None) or fields.pop("user", None),
                severity=(fields.pop("severity", None) or "INFO").upper(),
                detail=fields,
                raw=line,
            )
            if record.severity not in {"INFO", "WARNING", "CRITICAL"}:
                record.severity = "INFO"
            result.records.append(record)
        return result

    def autodetect(self, text: str) -> IngestResult:
        """Try JSONL, then syslog, and report which shape fit."""
        jsonl = self.parse_jsonl(text)
        if jsonl.records and not jsonl.rejected:
            return jsonl
        syslog = self.parse_syslog(text)
        if syslog.records and not syslog.rejected:
            return syslog
        return jsonl if jsonl.rejected else syslog

    # ------------------------------------------------------------------ core

    def _from_mapping(self, payload: dict, *, raw: str) -> HsmEventRecord | None:
        occurred = _parse_ts(payload.get("occurred_at") or payload.get("ts"))
        device = str(payload.get("device") or payload.get("hsm") or "").strip()
        if occurred is None or not device:
            return None
        event_type = _canonical_event(str(payload.get("event_type") or payload.get("event") or ""))
        detail = dict(payload.get("detail") or {})
        for extra in ("key_name", "key_usage", "algorithm", "components", "outcome", "reason"):
            if payload.get(extra) is not None:
                detail[extra] = payload[extra]
        severity = str(payload.get("severity") or "INFO").upper()
        return HsmEventRecord(
            occurred_at=occurred,
            device=device,
            event_type=event_type,
            key_id=(str(payload.get("key_id")).strip() if payload.get("key_id") else None),
            actor=(str(payload.get("actor")).strip() if payload.get("actor") else None),
            severity=severity if severity in {"INFO", "WARNING", "CRITICAL"} else "INFO",
            detail=detail,
            raw=raw,
        )
