"""Performance metric schema (docs/performance/01_PRODUCT_SPEC.md, §5).

The typed contract every measurement obeys. The success criteria from
§10 are construction rules here, not aspirations:

- every metric carries a unit, a source and an observation timestamp;
- missing telemetry is marked unknown or stale — a stale or missing
  sample carries NO value, and is never drawn as a zero;
- labels are bounded (cardinality is a budget, not a right);
- no customer payloads, passwords, tokens or private keys in metrics.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

METRIC_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
METRIC_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
LABEL_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

MAX_LABELS = 16
MAX_LABEL_VALUE_LENGTH = 120
#: max distinct label values per key per tenant — bounded cardinality
MAX_LABEL_VALUE_CARDINALITY = 256

#: never in labels or any metric text field (§9: no customer payloads,
#: passwords, tokens or private keys in metrics)
PROHIBITED_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "privatekey", "payload", "authorization", "cookie",
    "credential", "credentials", "session", "seed",
})


class MetricType(str, Enum):
    GAUGE = "gauge"
    COUNTER = "counter"
    HISTOGRAM = "histogram"


class QualityStatus(str, Enum):
    VALID = "valid"
    STALE = "stale"
    PARTIAL = "partial"
    MISSING = "missing"


#: qualities that describe measurements the source did NOT deliver —
#: they carry no value, and are never interpreted as zero
NO_VALUE_QUALITIES = frozenset({QualityStatus.STALE, QualityStatus.MISSING})


def _reject_prohibited(where: str, text: str) -> None:
    lowered = text.lower()
    for banned in PROHIBITED_KEYS:
        if banned in lowered:
            raise ValueError(
                f"prohibited content in {where}: a performance metric never "
                "carries payloads, passwords, tokens or private keys"
            )


class PerformanceMetric(BaseModel):
    """One measurement row — the §5 `performance_metrics` field table."""

    metric_id: str = Field(..., description="Unique measurement ID.")
    tenant_id: str = Field(..., description="Bank/customer boundary.")
    asset_id: str = Field(..., description="Linked Digital Twin asset.")
    metric_name: str = Field(..., description="e.g. network.rtt_ms")
    metric_type: MetricType
    metric_value: Optional[float] = Field(
        None,
        description="Numeric value — absent for missing/stale telemetry, "
        "which is never drawn as a zero.",
    )
    unit: str = Field(..., min_length=1, max_length=32,
                      description="ms, bytes, Mbps, percent, requests/sec")
    source_id: str = Field(..., min_length=1, max_length=120,
                           description="Collector or exporter.")
    observed_at: datetime = Field(..., description="Actual observation time.")
    interval_seconds: Optional[float] = Field(
        None, gt=0, le=86400, description="Collection interval.")
    labels: Mapping[str, str] = Field(
        default_factory=dict, description="Bounded dimensions.")
    evidence_id: Optional[str] = Field(
        None, description="Optional provenance reference.")
    quality_status: QualityStatus = QualityStatus.VALID

    class Config:
        extra = "forbid"

    @field_validator("metric_id")
    @classmethod
    def _metric_id_shape(cls, value: str) -> str:
        if not METRIC_ID_PATTERN.match(value):
            raise ValueError("metric_id is not a well-formed identifier")
        return value

    @field_validator("metric_name")
    @classmethod
    def _metric_name_shape(cls, value: str) -> str:
        if not METRIC_NAME_PATTERN.match(value):
            raise ValueError(
                "metric_name must be a dotted, lowercase metric name "
                "(e.g. network.rtt_ms)")
        return value

    @field_validator("unit")
    @classmethod
    def _unit_is_plain(cls, value: str) -> str:
        _reject_prohibited("unit", value)
        return value

    @field_validator("observed_at")
    @classmethod
    def _not_the_future(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must carry its timezone")
        if value > datetime.now(timezone.utc):
            raise ValueError(
                "observed_at is in the future — a measurement is never "
                "pre-dated; check the collector clock")
        return value

    @field_validator("labels")
    @classmethod
    def _labels_bounded(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        if len(value) > MAX_LABELS:
            raise ValueError(
                f"labels are bounded: at most {MAX_LABELS} keys "
                f"(got {len(value)}) — bounded cardinality is a success "
                "criterion (docs/performance/01_PRODUCT_SPEC.md §10)")
        for key, val in value.items():
            if not LABEL_KEY_PATTERN.match(key):
                raise ValueError(f"label key {key!r} is not a bounded key")
            if len(val) > MAX_LABEL_VALUE_LENGTH:
                raise ValueError(
                    f"label {key!r} exceeds {MAX_LABEL_VALUE_LENGTH} chars")
            _reject_prohibited(f"label {key!r}", f"{key}={val}")
        return dict(value)

    @model_validator(mode="after")
    def _value_and_quality_agree(self) -> "PerformanceMetric":
        missing = self.quality_status in NO_VALUE_QUALITIES
        if missing and self.metric_value is not None:
            raise ValueError(
                f"quality_status={self.quality_status.value} describes "
                "telemetry the source did not deliver — it carries no value "
                "and is never drawn as a zero or any other number")
        if not missing and self.metric_value is None:
            raise ValueError(
                "metric_value is required unless quality_status is "
                "'missing' or 'stale' — a measurement without a value is "
                "unknown telemetry, not a valid sample")
        return self

    def value_or_unknown(self) -> Optional[float]:
        """The honest accessor: None means unknown, never zero."""
        return self.metric_value
