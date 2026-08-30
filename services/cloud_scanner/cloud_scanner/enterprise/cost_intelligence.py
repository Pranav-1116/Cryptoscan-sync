"""ZELNX Cloud Discovery Engine — cloud cost intelligence (spec §18).

Estimates the cost of a PQC / hybrid migration across nine components:

    Compute | Storage | Network | HSM | Key Management | Certificate |
    Logging | Migration Engineering | Vendor

Supports AWS / Azure / GCP pricing models, regional assumptions and
multiple currencies.  Every figure is explicitly labelled:

    MEASURED | PROVIDER_REPORTED | ESTIMATED | ASSUMED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MEASURED = "MEASURED"
PROVIDER_REPORTED = "PROVIDER_REPORTED"
ESTIMATED = "ESTIMATED"
ASSUMED = "ASSUMED"

COST_COMPONENTS = (
    "compute", "storage", "network", "hsm", "key_management",
    "certificate", "logging", "migration_engineering", "vendor",
)

# conservative USD unit costs (per month unless noted) — all ESTIMATED
# unless overridden; regional multipliers approximate price variance
DEFAULT_UNIT_COSTS: dict[str, float] = {
    "compute": 50.0,        # per workload-month
    "storage": 0.023,       # per GB-month
    "network": 0.09,        # per GB egress
    "hsm": 1.5,             # per key-month (HSM custody)
    "key_management": 1.0,  # per key-month
    "certificate": 0.75,    # per certificate-month (private CA)
    "logging": 0.5,         # per GB-month log ingest
    "migration_engineering": 120.0,  # per engineer-hour
    "vendor": 0.0,          # vendor license delta per month
}

REGION_MULTIPLIERS: dict[str, float] = {
    "us-east-1": 1.0, "us-east-2": 1.0, "us-west-1": 1.08, "us-west-2": 1.0,
    "eu-west-1": 1.12, "eu-central-1": 1.16, "ap-southeast-1": 1.24,
    "ap-northeast-1": 1.28, "sa-east-1": 1.44, "global": 1.0, "": 1.0,
}

CURRENCIES = ("USD", "EUR", "GBP", "INR")
CURRENCY_RATES = {"USD": 1.0, "EUR": 0.92, "GBP": 0.79, "INR": 84.0}


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class CostLine:
    """One cost component with its confidence label."""

    component: str
    amount: float = 0.0
    unit: str = "USD"
    confidence: str = ESTIMATED
    quantity: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "amount": round(self.amount, 2),
            "unit": self.unit,
            "confidence": self.confidence,
            "quantity": self.quantity,
            "note": self.note,
        }


@dataclass
class CostEstimate:
    """Full migration cost estimate."""

    lines: list[CostLine] = field(default_factory=list)
    currency: str = "USD"
    assumptions: list[str] = field(default_factory=list)

    def total(self) -> float:
        return sum(line.amount for line in self.lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "currency": self.currency,
            "total": round(self.total(), 2),
            "total_usd": round(self._to_usd(self.total()), 2),
            "lines": [line.to_dict() for line in self.lines],
            "assumptions": list(self.assumptions),
        }

    def _to_usd(self, amount: float) -> float:
        rate = CURRENCY_RATES.get(self.currency, 1.0)
        return amount / rate if rate else amount


class CostIntelligenceEngine:
    """Estimate migration cost from inventory counts + pricing model.

    ``pricing_model`` overrides unit costs per component
    (``{"compute": 60.0, ...}``) — anything custom is labelled
    PROVIDER_REPORTED when ``provider_reported`` is true, else ASSUMED.
    """

    def __init__(
        self,
        *,
        pricing_model: dict[str, float] | None = None,
        provider_reported: bool = False,
        currency: str = "USD",
        region_multipliers: dict[str, float] | None = None,
        max_region: str | None = None,
    ) -> None:
        self._pricing = dict(DEFAULT_UNIT_COSTS)
        self._pricing.update(pricing_model or {})
        self._provider_reported = bool(provider_reported)
        self._currency = currency if currency in CURRENCIES else "USD"
        self._region_multipliers = dict(REGION_MULTIPLIERS)
        self._region_multipliers.update(region_multipliers or {})
        self._max_region = max_region or ""

    # ------------------------------------------------------------------

    def estimate(
        self,
        *,
        workloads: int = 0,
        storage_gb: float = 0.0,
        egress_gb: float = 0.0,
        hsm_keys: int = 0,
        kms_keys: int = 0,
        certificates: int = 0,
        log_gb: float = 0.0,
        engineering_hours: float = 0.0,
        vendor_delta: float = 0.0,
        region: str | None = None,
    ) -> CostEstimate:
        multiplier = self._region_multipliers.get(region or self._max_region, 1.0)
        quantities = {
            "compute": workloads,
            "storage": storage_gb,
            "network": egress_gb,
            "hsm": hsm_keys,
            "key_management": kms_keys,
            "certificate": certificates,
            "logging": log_gb,
            "migration_engineering": engineering_hours,
            "vendor": 1.0 if vendor_delta else 0.0,
        }
        estimate = CostEstimate(currency=self._currency)
        for component in COST_COMPONENTS:
            quantity = float(quantities.get(component, 0.0) or 0.0)
            if quantity <= 0:
                continue
            unit_cost = self._pricing.get(component, 0.0) * multiplier
            custom = component in self._pricing and component in DEFAULT_UNIT_COSTS \
                and self._pricing[component] != DEFAULT_UNIT_COSTS[component]
            confidence = self._confidence(component, custom)
            estimate.lines.append(CostLine(
                component=component,
                amount=unit_cost * quantity,
                unit=self._currency,
                confidence=confidence,
                quantity=quantity,
                note=(f"unit {round(unit_cost, 4)} {self._currency} x {quantity}"
                      + (f" (region {region})" if region else "")),
            ))
        estimate.assumptions.extend([
            f"currency={self._currency}",
            f"region_multiplier={multiplier}",
            "figures labelled MEASURED/PROVIDER_REPORTED/ESTIMATED/ASSUMED",
        ])
        return estimate

    def _confidence(self, component: str, custom: bool) -> str:
        if component == "migration_engineering":
            return ASSUMED
        if custom:
            return PROVIDER_REPORTED if self._provider_reported else ASSUMED
        return ESTIMATED
