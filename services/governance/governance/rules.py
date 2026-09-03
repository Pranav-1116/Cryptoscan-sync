"""Deterministic governance / approval policy engine (no AI).

Change requests (enable a risky plugin, open a firewall/SIEM integration,
grant scope, apply a policy exception, push a config change outside a
maintenance window) are evaluated by an explicit, ordered set of policy
rules. Each rule contributes a requirement or a hard veto. The engine returns
a structured decision with the exact rules that drove it — fully auditable and
reproducible. Policy is never decided by a model.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    AUTO_APPROVED = "AUTO_APPROVED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    DENIED = "DENIED"


@dataclass
class ChangeRequest:
    request_type: str
    requested_by: str
    requester_roles: list[str] = field(default_factory=list)
    payload: dict = field(default_factory=dict)
    in_maintenance_window: bool = False
    has_valid_ticket: bool = False


@dataclass
class PolicyResult:
    decision: Decision
    risk_level: RiskLevel
    required_approvers: list[str] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)
    rationale: str = ""

    def as_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "risk_level": self.risk_level.value,
            "required_approvers": self.required_approvers,
            "rules": self.rules,
            "rationale": self.rationale,
        }


Rule = Callable[[ChangeRequest, PolicyResult], None]

#: request types and their base risk tier.
RISK_BY_TYPE = {
    "plugin_enable_executable": RiskLevel.HIGH,
    "scope_grant": RiskLevel.HIGH,
    "policy_exception": RiskLevel.HIGH,
    "integration_outside_window": RiskLevel.MEDIUM,
    "credential_reference_change": RiskLevel.MEDIUM,
    "plugin_enable_data": RiskLevel.MEDIUM,
    "config_change": RiskLevel.MEDIUM,
    "report_export": RiskLevel.LOW,
}


def _rule(name: str):
    def deco(fn: Rule) -> Rule:
        fn.__rule_name__ = name  # type: ignore[attr-defined]
        return fn
    return deco


@_rule("risk-tier")
def _risk_tier(req: ChangeRequest, result: PolicyResult) -> None:
    result.risk_level = RISK_BY_TYPE.get(req.request_type, RiskLevel.MEDIUM)
    result.rules.append({"rule": "risk-tier", "tier": result.risk_level.value})


@_rule("no-secret-material")
def _no_secrets(req: ChangeRequest, result: PolicyResult) -> None:
    secret_hints = ("secret", "password", "token", "private_key", "access_key",
                    "client_secret", "key_material")
    for key in req.payload:
        lk = str(key).lower()
        if any(h in lk for h in secret_hints) and not lk.endswith(("_ref", "_id", "_provider")):
            result.decision = Decision.DENIED
            result.rules.append({"rule": "no-secret-material", "veto": True,
                                 "detail": f"field {key!r} looks like secret material"})
            return


@_rule("maintenance-window")
def _maintenance(req: ChangeRequest, result: PolicyResult) -> None:
    if result.decision == Decision.DENIED:
        return
    risky = req.request_type in (
        "config_change", "integration_outside_window", "plugin_enable_executable",
    )
    if risky and not req.in_maintenance_window:
        # out-of-window production changes need approval, not an auto-deny
        result.required_approvers.append("change-manager")
        result.rules.append({"rule": "maintenance-window", "requires_window": True})


@_rule("ticket-required")
def _ticket(req: ChangeRequest, result: PolicyResult) -> None:
    if result.decision == Decision.DENIED:
        return
    if result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and not req.has_valid_ticket:
        result.decision = Decision.REQUIRES_APPROVAL
        result.required_approvers.append("risk-officer")
        result.rules.append({"rule": "ticket-required", "satisfied": False})


@_rule("segregation-of-duties")
def _sod(req: ChangeRequest, result: PolicyResult) -> None:
    if result.decision == Decision.DENIED:
        return
    if result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        # the requester cannot be the sole approver for high risk
        result.required_approvers.append("security-approver")
        result.rules.append({"rule": "segregation-of-duties",
                             "note": "requester cannot self-approve high-risk change"})


@_rule("critical-two-person")
def _two_person(req: ChangeRequest, result: PolicyResult) -> None:
    if result.decision == Decision.DENIED:
        return
    if result.risk_level is RiskLevel.CRITICAL:
        if "risk-officer" not in result.required_approvers:
            result.required_approvers.append("risk-officer")
        result.required_approvers.append("ciso")
        result.rules.append({"rule": "critical-two-person", "approvers": 2})


_ORDERED_RULES: list[Rule] = [
    _risk_tier,
    _no_secrets,
    _maintenance,
    _ticket,
    _sod,
    _two_person,
]


def evaluate(req: ChangeRequest) -> PolicyResult:
    result = PolicyResult(
        decision=Decision.AUTO_APPROVED,
        risk_level=RiskLevel.LOW,
    )
    for rule in _ORDERED_RULES:
        rule(req, result)

    # dedupe approvers, preserving order
    seen: set[str] = set()
    result.required_approvers = [
        a for a in result.required_approvers if not (a in seen or seen.add(a))
    ]

    if result.decision == Decision.DENIED:
        vetoes = [r for r in result.rules if r.get("veto")]
        result.rationale = "Denied: " + "; ".join(v.get("detail", "policy veto") for v in vetoes)
    elif result.required_approvers or result.decision == Decision.REQUIRES_APPROVAL:
        result.decision = Decision.REQUIRES_APPROVAL
        result.rationale = (
            f"{result.risk_level.value}-risk change requires approval from: "
            + ", ".join(result.required_approvers)
        )
    else:
        result.rationale = f"Auto-approved {result.risk_level.value}-risk change"
    return result


def can_decide(approver_roles: list[str], required: list[str]) -> bool:
    """True if the approver set collectively covers every required role."""
    role_set = {r.lower() for r in approver_roles}
    # admin/superadmin satisfy any single approver role
    if role_set & {"admin", "superadmin", "ciso"}:
        return True
    return all(req in role_set for req in required)
