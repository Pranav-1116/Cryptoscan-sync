"""Scanning & privacy policy — the sanctioned, per-organization contract.

Two distinct concerns the spec keeps separate (and so do we):

* :class:`ScanPolicy` — "what am I allowed to scan, and how aggressively?"
  (mode, intensity, windows, rate caps, concurrency, production/HSM protection).
* :class:`PrivacyPolicy` — "what am I allowed to store, expose and retain?"
  (data minimization, redaction, PII/secret/private-key collection, retention).

Both are immutable dataclasses with fail-safe defaults: everything sensitive is
**off** by default and rate/intensity starts at its most conservative value.
Building a policy never raises on unknown keys (it ignores them), so a client
that sends extra settings is still served deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: ordered least -> most intrusive scan intensity (matches the safe-scan engine).
INTENSITY_ORDER = ("off", "low", "medium", "high")

#: which observation fields the privacy engine may retain, per observation_type.
#: This is the "data minimization" allowlist — everything else is dropped.
MINIMALLY_REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "*": ("asset", "source", "observation_type", "method", "confidence",
          "asset_type", "scanner", "first_seen", "last_seen"),
    "crypto": ("asset", "source", "observation_type", "algorithm", "key_size",
               "purpose", "confidence", "pqc_status", "fingerprint"),
    "certificate": ("asset", "subject", "issuer", "public_key_algorithm",
                    "public_key_size", "expiry_status", "days_until_expiry"),
    "asset": ("asset", "asset_type", "name", "manufacturer", "model", "firmware",
              "environment", "criticality", "owner", "business_unit"),
}

#: data classes (public / sensitive / restricted) reflected back to the caller.
DATA_CLASSES = ("public", "sensitive", "restricted")


@dataclass(frozen=True)
class PrivacyPolicy:
    """"What may I retain?" — fail-safe on, sensitive collection off."""

    collect_pii: bool = False
    collect_private_keys: bool = False
    collect_secrets: bool = False
    redact_secrets: bool = True
    mask_sensitive_fields: bool = True
    tokenize_identifiers: bool = True
    enforce_payload_limits: bool = True
    max_payload_bytes: int = 64 * 1024          # per-observation cap
    redact_cert_private: bool = True            # never keep cert private key
    retention_days: int = 90
    allow_evidence_metadata: bool = True        # store hash/source, not content
    data_minimization: bool = True              # enforce the field allowlist
    alert_on_private_key: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}


@dataclass(frozen=True)
class ScanPolicy:
    """"What am I allowed to scan, how aggressively?" — conservative defaults."""

    mode: str = "read-only"                     # read-only | controlled_active
    intensity: str = "low"                      # off | low | medium | high
    max_concurrent_jobs: int = 20
    max_targets_per_scan: int = 200
    max_connections: int = 50
    rate_limit_qps: int = 5
    rate_limit_per_minute: int = 300
    scan_timeout_seconds: int = 300
    retry_limit: int = 2
    production_protection: bool = True          # production scope -> read-only low
    hsm_protection: bool = True                 # HSM -> most conservative, no creds
    require_special_approval: bool = True       # HSM/production-db need approval
    maintenance_window_start: str = "22:00"
    maintenance_window_end: str = "05:00"

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}


@dataclass(frozen=True)
class PolicyBundle:
    """The pair the gate evaluates together."""
    scan: ScanPolicy = field(default_factory=ScanPolicy)
    privacy: PrivacyPolicy = field(default_factory=PrivacyPolicy)

    def to_dict(self) -> dict[str, Any]:
        return {"scan": self.scan.to_dict(), "privacy": self.privacy.to_dict()}


#: sector-specific policy profiles. Same platform, different policy profile (§26).
SECTOR_PROFILES: dict[str, dict[str, dict[str, Any]]] = {
    "banking": {
        "scan": {"mode": "read-only", "intensity": "low", "production_protection": True,
                 "hsm_protection": True, "require_special_approval": True,
                 "rate_limit_qps": 3, "max_connections": 25},
        "privacy": {"collect_pii": False, "collect_private_keys": False,
                    "collect_secrets": False, "redact_secrets": True,
                    "retention_days": 180, "tokenize_identifiers": True},
    },
    "healthcare": {
        "scan": {"mode": "read-only", "intensity": "low", "production_protection": True,
                 "require_special_approval": True, "rate_limit_qps": 2, "max_connections": 20},
        "privacy": {"collect_pii": False, "collect_private_keys": False,
                    "collect_secrets": False, "redact_secrets": True,
                    "retention_days": 365, "mask_sensitive_fields": True},
    },
    "energy": {
        "scan": {"mode": "read-only", "intensity": "low", "production_protection": True,
                 "hsm_protection": True, "require_special_approval": True,
                 "rate_limit_qps": 2, "max_connections": 20},
        "privacy": {"collect_pii": False, "collect_private_keys": False,
                    "collect_secrets": False, "redact_secrets": True},
    },
    "telecom": {
        "scan": {"mode": "read-only", "intensity": "low", "production_protection": True,
                 "require_special_approval": False, "rate_limit_qps": 5, "max_connections": 50},
        "privacy": {"collect_pii": False, "collect_private_keys": False,
                    "collect_secrets": False, "redact_secrets": True},
    },
    "government": {
        "scan": {"mode": "read-only", "intensity": "low", "production_protection": True,
                 "hsm_protection": True, "require_special_approval": True,
                 "rate_limit_qps": 2, "max_connections": 20},
        "privacy": {"collect_pii": False, "collect_private_keys": False,
                    "collect_secrets": False, "redact_secrets": True,
                    "retention_days": 365, "tokenize_identifiers": True},
    },
}


def build_policy(
    scan: dict[str, Any] | None = None,
    privacy: dict[str, Any] | None = None,
    *,
    sector: str | None = None,
) -> PolicyBundle:
    """Build a :class:`PolicyBundle` from partial dicts.

    ``sector`` seeds the defaults (from :data:`SECTOR_PROFILES`) and the provided
    dicts override them. Unknown keys are ignored so extra client settings do
    not break the deterministic policy. Values outside the valid domain clamp to
    the safe end (fail toward conservative).
    """
    scan_defaults: dict[str, Any] = {}
    privacy_defaults: dict[str, Any] = {}
    if sector and sector in SECTOR_PROFILES:
        scan_defaults = dict(SECTOR_PROFILES[sector].get("scan") or {})
        privacy_defaults = dict(SECTOR_PROFILES[sector].get("privacy") or {})

    s = {**ScanPolicy().to_dict(), **scan_defaults, **(scan or {})}
    p = {**PrivacyPolicy().to_dict(), **privacy_defaults, **(privacy or {})}

    # unknown keys are ignored (deterministic policy never breaks on extras)
    scan_fields = {f.name for f in dataclasses.fields(ScanPolicy)}
    privacy_fields = {f.name for f in dataclasses.fields(PrivacyPolicy)}
    s = {k: v for k, v in s.items() if k in scan_fields}
    p = {k: v for k, v in p.items() if k in privacy_fields}

    # clamp intensity / mode to a known-safe value
    if s["intensity"] not in INTENSITY_ORDER:
        s["intensity"] = "low"
    if s["mode"] not in ("read-only", "controlled_active"):
        s["mode"] = "read-only"
    # boolean-privacy settings that gate collection must coerce to bool
    for key in ("collect_pii", "collect_private_keys", "collect_secrets",
                "redact_secrets", "mask_sensitive_fields", "tokenize_identifiers",
                "enforce_payload_limits", "data_minimization", "alert_on_private_key"):
        p[key] = bool(p.get(key))

    return PolicyBundle(scan=ScanPolicy(**s), privacy=PrivacyPolicy(**p))


def apply_sector_overrides(policy: PolicyBundle, sector: str) -> PolicyBundle:
    """Override a policy with the sector profile's strictest union of settings.

    Never loosens a security/privacy control: an explicit profile flag that is
    stricter than the current policy wins; a looser one is ignored.
    """
    if sector not in SECTOR_PROFILES:
        return policy
    prof = SECTOR_PROFILES[sector]
    s = policy.scan.to_dict()
    p = policy.privacy.to_dict()
    for k, v in (prof.get("scan") or {}).items():
        # clamp numeric caps downward (never raise) and keep read-only
        if isinstance(v, bool) and v is False and k in ("production_protection", "hsm_protection", "require_special_approval"):
            continue  # never weaken a protection flag
        if isinstance(v, (int, float)) and isinstance(s.get(k), (int, float)):
            s[k] = min(v, s[k])
        else:
            s[k] = v
    for k, v in (prof.get("privacy") or {}).items():
        if k in ("collect_pii", "collect_private_keys", "collect_secrets",
                 "collect_secrets"):
            # sector profiles are fail-safe: sensitive collection is never enabled
            p[k] = False
        elif isinstance(v, bool):
            # redaction / masking / tokenization toggle ON; a True keeps it on
            p[k] = p.get(k, True) or bool(v)
        elif isinstance(v, (int, float)) and isinstance(p.get(k), (int, float)):
            # retention only ever extends (never shortens what a tenant set)
            p[k] = v if v > p.get(k) else p.get(k)
        else:
            p[k] = v
    return PolicyBundle(scan=ScanPolicy(**s), privacy=PrivacyPolicy(**p))


import dataclasses  # noqa: E402  (used by the to_dict helpers)
