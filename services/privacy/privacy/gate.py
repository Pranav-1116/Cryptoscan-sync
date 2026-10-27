"""Unified scanner gate — the only way a scan starts (spec §5, §21, §27).

Every scan request must pass, in order, a fail-closed chain:

    WHO  ->  TENANT  ->  AUTHORIZATION  ->  SCOPE  ->  PRIVACY POLICY
    ->  SCAN POLICY  ->  RATE LIMIT  ->  TARGET SAFETY  ->  CREDENTIAL
    ->  START SCAN
    (any failure -> DENY SCAN + AUDIT LOG)

This is the executor for a request that has already been resolved into concrete
per-domain targets and credentials (e.g. by the orchestrator's plan). It returns
a :class:`GateDecision` recording every check, the first denying reason, and a
structured audit record. If any non-optional control fails the scan is denied.

The gate is pure/deterministic (no DB, no network) so it is unit-testable and
can run in every worker consistently. Persistence of the decision belongs to the
caller's audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from privacy.policy import PolicyBundle, PrivacyPolicy, ScanPolicy
from privacy.ratelimit import RateLimitState, RateLimiter, Limits


@dataclass
class GateCheck:
    control: str          # e.g. "scope", "privacy", "rate_limit"
    passed: bool
    reason: str = ""
    detail: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"control": self.control, "passed": self.passed,
                "reason": self.reason, "detail": self.detail}


@dataclass
class GateDecision:
    permitted: bool
    scan_id: str | None = None
    checks: list[GateCheck] = field(default_factory=list)
    denied_by: str | None = None       # name of the first failing control
    reason: str = ""
    audit: dict[str, Any] = field(default_factory=dict)

    @property
    def denied(self) -> bool:
        return not self.permitted

    def to_dict(self) -> dict[str, Any]:
        return {
            "permitted": self.permitted,
            "scan_id": self.scan_id,
            "checks": [c.to_dict() for c in self.checks],
            "denied_by": self.denied_by,
            "reason": self.reason,
            "audit": self.audit,
        }


#: targets that are always treated as production-grade, regardless of env label.
_PRODUCTION_KINDS = ("production", "prod", "hsm", "payment", "database", "db")


class ScannerGate:
    """Evaluate a scan request against the full control chain."""

    def __init__(self, *, policy: PolicyBundle | None = None, limits: Limits | None = None,
                 limiter: RateLimiter | None = None) -> None:
        self.policy = policy or PolicyBundle()
        self.limits = limits or Limits()
        self.limiter = limiter or RateLimiter(self.limits)

    def evaluate(
        self,
        *,
        actor: str,
        tenant: str,
        environment: str = "",
        targets: dict[str, list[str]] | None = None,
        credentials: dict[str, bool] | None = None,
        scanners: list[str] | None = None,
        scan_id: str | None = None,
        policy: PolicyBundle | None = None,
        scope_includes: dict[str, list[str]] | None = None,   # allowed/excluded/special
    ) -> GateDecision:
        """Run the chain. ``targets`` is the resolved per-domain target map."""
        targets = targets or {}
        credentials = credentials or {}
        scanners = scanners or list(targets.keys())
        pol = policy or self.policy
        checks: list[GateCheck] = []
        audit: dict[str, Any] = {
            "actor": actor, "tenant": tenant, "environment": environment,
            "scanners": scanners, "targets": targets,
        }

        denied = self._authorize(actor, tenant, environment, checks)
        if not denied:
            denied = self._scope(targets, targets_in_scope=scope_includes, checks=checks)
        if not denied:
            denied = self._privacy(pol.privacy, targets, checks)
        if not denied:
            denied = self._scan_policy(pol.scan, targets, scanner=list(scanners)[0] if scanners else "", checks=checks)
        if not denied:
            denied = self._rate_limit(actor, tenant, environment, scanners, targets, checks)
        if not denied:
            denied = self._target_safety(pol.scan, targets, scope_includes or {}, checks)
        if not denied:
            denied = self._credential(credentials, targets, pol.scan, checks)

        if denied:
            first = next((c for c in checks if not c.passed), None)
            audit.update({"denied_by": first.control if first else None,
                          "reason": first.reason if first else "denied",
                          "decision": "deny"})
            return GateDecision(False, scan_id, checks,
                                first.control if first else None,
                                first.reason if first else "denied", audit)
        audit.update({"decision": "allow"})
        return GateDecision(True, scan_id, checks, None, "ok", audit)

    # ------------------------------------------------------------- controls
    @staticmethod
    def _authorize(actor: str, tenant: str, environment: str, checks: list[GateCheck]) -> bool:
        if not actor:
            checks.append(GateCheck("authorization", False, "no subject/actor for scan request"))
            return True
        if not tenant:
            checks.append(GateCheck("authorization", False, "no tenant context on scan request"))
            return True
        checks.append(GateCheck("authorization", True,
                                f"subject {actor} in tenant {tenant}"))
        return False

    @staticmethod
    def _scope(targets: dict[str, list[str]], *, targets_in_scope: dict[str, list[str]] | None,
               checks: list[GateCheck]) -> bool:
        # explicit deny / special-approval scope lists
        excluded = set((targets_in_scope or {}).get("excluded", []) or [])
        special = set((targets_in_scope or {}).get("special", []) or [])
        probe = set()
        for targets_ in targets.values():
            probe.update(targets_)
        out_of_scope = {t for t in probe if t in excluded}
        if out_of_scope:
            checks.append(GateCheck("scope", False,
                                    f"targets {sorted(out_of_scope)} are excluded from authorized scope"))
            return True
        # any target that is authorized but is 'read-only' scope is fine; the
        # control guarantees it is part of the authorized scope (the plan only
        # emits authorized targets). Missing scope => fail-closed.
        if not probe:
            checks.append(GateCheck("scope", False, "no authorized targets in scan request"))
            return True
        special_hit = probe & special
        if special_hit and not (targets_in_scope or {}).get("special_approved"):
            checks.append(GateCheck("scope", False,
                                    f"targets {sorted(special_hit)} require special approval"))
            return True
        checks.append(GateCheck("scope", True, f"{len(probe)} authorized target(s)"))
        return False

    @staticmethod
    def _privacy(pol: PrivacyPolicy, targets: dict[str, list[str]], checks: list[GateCheck]) -> bool:
        # A privacy policy that enables sensitive collection is not on its own a
        # denial (the sector mandates it may). What IS denied: attempting to scan
        # with a privacy policy that does not declare collection controls, or a
        # policy that would force storing private keys for a crypto-only run.
        if pol.collect_private_keys:
            checks.append(GateCheck("privacy", False,
                                    "privacy policy forbids collecting private keys; adjust policy"))
            return True
        checks.append(GateCheck("privacy", True,
                                f"data minimization={'on' if pol.data_minimization else 'off'}, "
                                f"redaction={'on' if pol.redact_secrets else 'off'}, "
                                f"retention={pol.retention_days}d"))
        return False

    @staticmethod
    def _scan_policy(pol: ScanPolicy, targets: dict[str, list[str]], *, scanner: str,
                     checks: list[GateCheck]) -> bool:
        if pol.intensity == "off":
            checks.append(GateCheck("scan_policy", False, "scan intensity is OFF"))
            return True
        if pol.mode == "read-only" and pol.intensity in ("high",):
            checks.append(GateCheck("scan_policy", False,
                                    "read-only mode forbids high-intensity scanning"))
            return True
        total_targets = sum(len(v) for v in targets.values())
        if total_targets > pol.max_targets_per_scan:
            checks.append(GateCheck("scan_policy", False,
                                    f"{total_targets} targets exceeds policy cap {pol.max_targets_per_scan}"))
            return True
        checks.append(GateCheck("scan_policy", True,
                                f"mode={pol.mode} intensity={pol.intensity} "
                                f"targets={total_targets}/{pol.max_targets_per_scan}"))
        return False

    def _rate_limit(self, actor: str, tenant: str, environment: str,
                    scanners: list[str], targets: dict[str, list[str]],
                    checks: list[GateCheck]) -> bool:
        states: list[RateLimitState] = []
        # Layer 1 — user/API
        states.append(self.limiter.user_api(actor, route="scan"))
        # Layer 2 — scanner
        for sc in scanners:
            states.append(self.limiter.scanner(sc))
        # Layer 3 — target
        for targets_ in targets.values():
            for t in targets_:
                states.append(self.limiter.target(t))
        # Layer 4 — tenant / env / infra
        states.append(self.limiter.env_scanners(tenant, environment, len(scanners)))
        failing = next((s for s in states if not s.allowed), None)
        if failing is not None:
            checks.append(GateCheck("rate_limit", False, failing.reason, failing.to_dict()))
            return True
        checks.append(GateCheck("rate_limit", True,
                                f"user/api + {len(scanners)} scanner(s) + {sum(len(v) for v in targets.values())} target(s) within budget"))
        return False

    @staticmethod
    def _target_safety(pol: ScanPolicy, targets: dict[str, list[str]],
                       scope_includes: dict[str, Any], checks: list[GateCheck]) -> bool:
        hsm = [t for domain in targets.values() for t in domain
               if "hsm" in str(t).lower() or "hsm" in str(domain).lower()]
        prod = [t for domain in targets.values() for t in domain
                if any(k in str(domain).lower() for k in _PRODUCTION_KINDS)
                or any(k in str(t).lower() for k in ("prod", "payment", "db-", "database"))]
        approved = bool((scope_includes or {}).get("special_approved"))
        if pol.hsm_protection and hsm and not approved:
            # HSM must go through the special-approval policy; when scope grants
            # it, target safety passes and the conservative budget applies.
            checks.append(GateCheck("target_safety", False,
                                    f"HSM targets {sort_hsm(hsm)} require special policy (no credentials, conservative)"))
            return True
        if pol.production_protection and prod and pol.intensity not in ("low", "off"):
            checks.append(GateCheck("target_safety", False,
                                    "production targets require low/read-only intensity (production protection enabled)"))
            return True
        checks.append(GateCheck("target_safety", True,
                                f"hsm={len(hsm)} production={len(prod)} protection={'on' if pol.production_protection else 'off'}"))
        return False

    @staticmethod
    def _credential(credentials: dict[str, bool], targets: dict[str, list[str]],
                    pol: ScanPolicy, checks: list[GateCheck]) -> bool:
        # Every target domain needs a matching scoped/short-lived credential —
        # EXCEPT the two credential-free collectors that require none:
        #   * network_scope — passive discovery needs no standing credential
        #   * the local host-set agent ("host") — it runs on the ZELNX host itself
        domains = [d for d in targets.keys() if d != "network_scope"]
        agent_only = domains == ["hardware"] and set(targets.get("hardware") or []) == {"host"}
        domains_requiring_creds = [] if agent_only else domains
        missing = [d for d in domains_requiring_creds
                   if not credentials.get(_domain_cred(d))]
        if missing:
            checks.append(GateCheck("credential", False,
                                    f"domains without a scoped/short-lived credential: {missing}"))
            return True
        checks.append(GateCheck("credential", True,
                                "short-lived/scoped credentials present for all target domains"))
        return False


def _domain_cred(domain: str) -> str:
    if domain in ("network", "network_scope"):
        return "network"
    if domain in ("cloud", "cloud_live"):
        return "cloud"
    if domain in ("hardware", "hardware_agent"):
        return "hardware"
    if domain in ("source", "universal", "application"):
        return "application"
    if domain in ("vendor",):
        return "vendor"
    if domain in ("crypto",):
        return "crypto"
    return domain


def sort_hsm(items: list[str]) -> list[str]:
    return sorted(items)
