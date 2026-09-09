"""ZELNX privacy engine + unified scanner gate.

Spec: for banks, healthcare, energy, telecom, government and large enterprises
the scanner must enforce explicit authorization, least privilege, continuous
verification and resource controls (NIST Zero Trust). The three concepts are
kept separate:

* **Scanner**  — "what can I discover?"
* **Policy engine** — "what am I allowed to discover, and how aggressively?"
  (see :mod:`privacy.policy` + the control-plane safe-scan policy)
* **Privacy engine** — "what am I allowed to store, expose, and retain?"
  (this package: :mod:`privacy.classify`, :mod:`privacy.redact`)

:mod:`privacy.gate` composes authorization -> scope -> privacy -> scan policy
-> rate limit -> target safety -> credential into ONE fail-closed decision for
a scan request, before any scanner runs.

The security/privacy sub-applications ("what may I retain?") are deliberately
separate from the scanner ("what can I see?") so a scanner can never decide on
its own that it is allowed to store sensitive data.
"""

from __future__ import annotations

from privacy.policy import PrivacyPolicy, ScanPolicy, PolicyBundle, build_policy
from privacy.classify import classify_value, DataClass
from privacy.redact import RedactionEngine, RedactionResult
from privacy.gate import GateCheck, GateDecision, ScannerGate
from privacy.ratelimit import RateLimitState, RateLimiter, Limits, BucketStore, MemoryBucketStore, RedisBucketStore
from privacy.identity import AssetObservation, IdentityResolution, resolve_identities, infer_asset_type
from privacy.profiles import ScanProfile, SCAN_PROFILES, get_profile, resolve_profile
from privacy.state import Confidence, confidence_from_sources, staleness, health_for_asset, verification_state, coerce_verification_state
from privacy.correlation import CorrelatedFinding, correlate_findings, build_chain, finding_fingerprint
from privacy.triggers import Schedule, resolve_schedule, event_for_change, is_incremental, IncrementalDecision

__all__ = [
    "PrivacyPolicy",
    "ScanPolicy",
    "PolicyBundle",
    "build_policy",
    "classify_value",
    "DataClass",
    "RedactionEngine",
    "RedactionResult",
    "GateCheck",
    "GateDecision",
    "ScannerGate",
    "RateLimitState",
    "RateLimiter",
    "Limits",
    "BucketStore",
    "MemoryBucketStore",
    "RedisBucketStore",
    "AssetObservation",
    "IdentityResolution",
    "resolve_identities",
    "infer_asset_type",
    "ScanProfile",
    "SCAN_PROFILES",
    "get_profile",
    "resolve_profile",
    "Confidence",
    "confidence_from_sources",
    "staleness",
    "health_for_asset",
    "verification_state",
    "coerce_verification_state",
    "CorrelatedFinding",
    "correlate_findings",
    "build_chain",
    "finding_fingerprint",
    "Schedule",
    "resolve_schedule",
    "event_for_change",
    "is_incremental",
    "IncrementalDecision",
]
