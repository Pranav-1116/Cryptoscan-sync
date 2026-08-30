"""Key-usage analytics and transaction-volume correlation.

Inventory says what keys exist; the audit trail says what is actually used.
This module joins them with the bank's daily transaction counts — the
"10M transactions a day" lens:

- which keys carry the traffic (ops per day, per operation type, last used);
- **dormant** ACTIVE keys (PAY-011) — retirement candidates;
- usage of a COMPROMISED/DESTROYED key (PAY-012) — must be impossible;
- **shadow keys** (PAY-013) — key ids the HSM uses that are in no inventory;
- crypto-ops-per-transaction deviation (PAY-014) — a 40% drop in HSM work
  per transaction can mean a software fallback is doing PIN/crypto work
  outside the HSM; a spike can mean an attack or a broken retry loop.

Honesty: PAY-014 needs both series and a baseline — with fewer than
``min_days`` overlapping days it reports ``insufficient_data``, never a
guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Iterable

DORMANCY_DAYS_DEFAULT = 90
DEAD_STATES = {"COMPROMISED", "DESTROYED"}
USAGE_EVENT_TYPES = {"KEY_USED"}
OPERATION_KEYS = ("op", "operation", "command")


def _day(value) -> date | None:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    text = str(value or "")[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _as_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


@dataclass
class UsageFinding:
    rule_id: str
    severity: int
    blocking: bool
    key_id: str | None
    message: str
    evidence: dict

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "severity": self.severity, "blocking": self.blocking,
            "key_id": self.key_id, "message": self.message, "evidence": self.evidence,
        }


class UsageAnalyzer:
    def __init__(self, *, dormancy_days: int = DORMANCY_DAYS_DEFAULT, now: datetime | None = None):
        self.dormancy_days = dormancy_days
        self._now = now or datetime.now(timezone.utc)

    def analyze(self, keys: Iterable[dict], events: Iterable[dict]) -> dict:
        keys = [dict(key) for key in keys]
        events = [dict(event) for event in events]
        known = {str(key.get("key_id") or "") for key in keys}

        per_key: dict[str, dict] = {}
        by_day: dict[date, int] = {}
        shadow: set[str] = set()
        for event in events:
            if str(event.get("event_type") or "") not in USAGE_EVENT_TYPES:
                continue
            occurred = _as_datetime(event.get("occurred_at"))
            key_id = str(event.get("key_id") or "") or "?"
            if key_id not in known:
                shadow.add(key_id)
            detail = event.get("detail") or {}
            weight = int(detail.get("count") or 1)  # aggregated rows carry an op count
            bucket = per_key.setdefault(key_id, {"ops": 0, "last_used_at": None, "by_op": {}})
            bucket["ops"] += weight
            op = next((str(detail[k]) for k in OPERATION_KEYS if detail.get(k)), "UNKNOWN")
            bucket["by_op"][op] = bucket["by_op"].get(op, 0) + weight
            if occurred is not None:
                if bucket["last_used_at"] is None or occurred > _as_datetime(bucket["last_used_at"]):
                    bucket["last_used_at"] = occurred
                day = occurred.date()
                by_day[day] = by_day.get(day, 0) + weight

        findings: list[UsageFinding] = list(self._shadow_findings(shadow))
        for key in keys:
            findings.extend(self._key_findings(key, per_key.get(str(key.get("key_id")), {"ops": 0, "last_used_at": None, "by_op": {}})))

        return {
            "as_of": self._now.isoformat(),
            "keys_with_usage": sum(1 for key_id in per_key if key_id in known),
            "total_usage_events": sum(bucket["ops"] for bucket in per_key.values()),
            "usage_by_day": {day.isoformat(): count for day, count in sorted(by_day.items())},
            "per_key": {
                key_id: {"ops": bucket["ops"],
                         "last_used_at": bucket["last_used_at"].isoformat() if bucket["last_used_at"] else None,
                         "by_op": bucket["by_op"]}
                for key_id, bucket in sorted(per_key.items())
            },
            "findings": [finding.to_dict() for finding in findings],
        }

    # ------------------------------------------------------------- findings

    def _shadow_findings(self, shadow: set[str]) -> list[UsageFinding]:
        return [
            UsageFinding(
                "PAY-013", 4, False, key_id,
                f"HSM uses key '{key_id}' which is not in the payment key inventory (shadow key)",
                {"key_id": key_id},
            )
            for key_id in sorted(shadow)
        ]

    def _key_findings(self, key: dict, usage: dict) -> list[UsageFinding]:
        findings: list[UsageFinding] = []
        key_id = str(key.get("key_id") or "")
        state = str(key.get("state") or "").upper()
        last_used = _as_datetime(usage.get("last_used_at"))

        if state in DEAD_STATES and usage["ops"] > 0 and last_used is not None:
            days_ago = (self._now - last_used).days
            if days_ago <= 30:  # recent use of a key that must be unusable
                findings.append(UsageFinding(
                    "PAY-012", 5, True, key_id,
                    f"key in state {state} was used {days_ago}d ago — it must not be operable",
                    {"state": state, "last_used_at": last_used.isoformat(), "ops": usage["ops"]},
                ))

        if state == "ACTIVE" and (last_used is None or (self._now - last_used).days > self.dormancy_days):
            activated = _as_datetime(key.get("activation_at"))
            if activated is None or (self._now - activated).days > self.dormancy_days:
                findings.append(UsageFinding(
                    "PAY-011", 3, False, key_id,
                    f"ACTIVE key dormant > {self.dormancy_days}d — retirement candidate",
                    {"last_used_at": last_used.isoformat() if last_used else None,
                     "activation_at": activated.isoformat() if activated else None},
                ))
        return findings


class TransactionCorrelator:
    """Crypto-ops per transaction: is the HSM doing the work?"""

    def __init__(self, *, deviation: float = 0.4, min_days: int = 14, baseline_days: int = 30):
        self.deviation = deviation
        self.min_days = min_days
        self.baseline_days = baseline_days

    def evaluate(self, transactions: dict, usage_by_day: dict) -> dict:
        tx = {_day(day): int(count) for day, count in (transactions or {}).items() if _day(day) and int(count or 0) > 0}
        ops = {_day(day): int(count) for day, count in (usage_by_day or {}).items() if _day(day)}
        overlapping = sorted(set(tx) & set(ops))
        if len(overlapping) < self.min_days:
            return {
                "status": "insufficient_data",
                "detail": f"{len(overlapping)}/{self.min_days} days with both transaction and usage data",
                "ratio_by_day": {},
                "findings": [],
            }

        ratios: dict[str, float] = {}
        anomalies: list[dict] = []
        for index, day in enumerate(overlapping):
            ratio = ops[day] / tx[day]
            ratios[day.isoformat()] = round(ratio, 6)
            history = [ops[prior] / tx[prior] for prior in overlapping[max(0, index - self.baseline_days):index] if tx[prior] > 0]
            if len(history) < max(3, self.min_days // 2):
                continue  # not enough baseline for this day yet
            history.sort()
            baseline = history[len(history) // 2]  # median: robust to spikes
            if baseline > 0 and abs(ratio - baseline) / baseline > self.deviation:
                anomalies.append({
                    "date": day.isoformat(), "ratio": round(ratio, 6),
                    "baseline": round(baseline, 6),
                    "deviation_pct": round(100.0 * (ratio - baseline) / baseline, 1),
                    "transactions": tx[day], "hsm_ops": ops[day],
                })

        findings = [
            UsageFinding(
                "PAY-014", 4, False, None,
                "crypto-ops-per-transaction deviates >{:.0%} from the 30-day median — verify no "
                "software fallback is doing payment crypto outside the HSM".format(self.deviation),
                anomaly,
            ).to_dict()
            for anomaly in anomalies[-5:]  # most recent five
        ]
        return {
            "status": "ok" if not anomalies else "anomalies",
            "days_correlated": len(overlapping),
            "anomaly_days": len(anomalies),
            "ratio_by_day": ratios,
            "findings": findings,
        }
