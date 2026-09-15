"""Real-time attack detection: 13 deterministic rules, no ML.

Every rule is a pure function of (current observation, baseline/state) —
same input, same detection, always. Stateful rules keep their windows in
`AttackState` (rate baseline via 3-sigma over a bounded window, endpoint
universe, key/cert sightings, pins, trusted CAs) and that state can be
snapshotted/restored as JSON so a restarted processor keeps its memory.

Severity table (platform contract, pinned by tests):
  crypto downgrade        ALERT
  algorithm downgrade     CRITICAL
  key size reduction      ALERT
  MITM indicator          CRITICAL
  unexpected CA           HIGH
  key reuse               HIGH
  weak entropy            MEDIUM
  protocol violation      ALERT
  rate anomaly            MEDIUM
  new endpoint            MEDIUM
  cert near expiry        MEDIUM
  revoked cert in use     CRITICAL
  HSM/KMS policy change   HIGH
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

TLS_RANK = {"TLSv1": 1, "TLSv1.0": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4}
BROKEN_ALGOS = {"DES", "3DES", "RC4", "MD5"}
WEAK_ENTROPY_BITS_PER_BYTE = 4.5
CERT_EXPIRY_WARN_DAYS = 30


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits/byte over the byte distribution."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if not raw:
        return 0.0
    counts: dict[int, int] = defaultdict(int)
    for b in raw:
        counts[b] += 1
    total = len(raw)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _detection(rule: str, severity: str, detail: str, **evidence: Any) -> dict[str, Any]:
    det = {"rule": rule, "severity": severity, "detail": detail,
           "detected_at": datetime.now(timezone.utc).isoformat()}
    det.update(evidence)
    return det


class AttackState:
    """Stateful memory for the detection rules (JSON-snapshot-able)."""

    def __init__(self) -> None:
        self.baselines: dict[str, dict[str, Any]] = {}       # endpoint -> known-good crypto
        self.pinned_fingerprints: dict[str, str] = {}        # endpoint -> pinned cert fp
        self.trusted_cas: set[str] = set()
        self.known_endpoints: dict[str, set[str]] = defaultdict(set)  # system -> endpoints
        self.key_sightings: dict[str, set[str]] = defaultdict(set)    # fingerprint -> systems
        self.rate_windows: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=200))

    def snapshot(self) -> dict[str, Any]:
        return {
            "baselines": self.baselines,
            "pinned_fingerprints": dict(self.pinned_fingerprints),
            "trusted_cas": sorted(self.trusted_cas),
            "known_endpoints": {s: sorted(e) for s, e in self.known_endpoints.items()},
            "key_sightings": {k: sorted(v) for k, v in self.key_sightings.items()},
            "rate_windows": {k: list(v) for k, v in self.rate_windows.items()},
        }

    @classmethod
    def restore(cls, snap: dict[str, Any]) -> "AttackState":
        st = cls()
        st.baselines = dict(snap.get("baselines", {}))
        st.pinned_fingerprints = dict(snap.get("pinned_fingerprints", {}))
        st.trusted_cas = set(snap.get("trusted_cas", []))
        st.known_endpoints = defaultdict(set, {s: set(v) for s, v in snap.get("known_endpoints", {}).items()})
        st.key_sightings = defaultdict(set, {k: set(v) for k, v in snap.get("key_sightings", {}).items()})
        st.rate_windows = defaultdict(lambda: deque(maxlen=200),
                                      {k: deque(v, maxlen=200) for k, v in snap.get("rate_windows", {}).items()})
        return st


class AttackDetector:
    """Runs the applicable rules for one canonical observation."""

    def __init__(self, state: AttackState | None = None):
        self.state = state or AttackState()

    # ------------------------------------------------------------------ rules

    def _rule_crypto_downgrade(self, c: dict[str, Any], b: dict[str, Any] | None) -> list[dict[str, Any]]:
        cur, base = c.get("tls_version"), (b or {}).get("tls_version")
        if cur and base and TLS_RANK.get(cur, 0) < TLS_RANK.get(base, 0):
            return [_detection("crypto_downgrade", "ALERT",
                               f"tls version regressed {base} -> {cur}",
                               endpoint=c.get("endpoint"), before=base, after=cur)]
        return []

    def _rule_algorithm_downgrade(self, c: dict[str, Any], b: dict[str, Any] | None) -> list[dict[str, Any]]:
        cur = str(c.get("algorithm") or "").upper()
        base = str((b or {}).get("algorithm") or "").upper()
        if cur in BROKEN_ALGOS and base and base not in BROKEN_ALGOS:
            return [_detection("algorithm_downgrade", "CRITICAL",
                               f"broken algorithm introduced: {base} -> {cur}",
                               endpoint=c.get("endpoint"), before=base, after=cur)]
        return []

    def _rule_key_size_reduction(self, c: dict[str, Any], b: dict[str, Any] | None) -> list[dict[str, Any]]:
        cur, base = c.get("key_size"), (b or {}).get("key_size")
        if cur and base and int(cur) < int(base):
            return [_detection("key_size_reduction", "ALERT",
                               f"key size reduced {base} -> {cur} bits",
                               endpoint=c.get("endpoint"), before=base, after=cur)]
        return []

    def _rule_mitm(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        ep, fp = c.get("endpoint"), c.get("cert_fingerprint")
        pinned = self.state.pinned_fingerprints.get(str(ep))
        if ep and fp and pinned and fp != pinned:
            return [_detection("mitm_indicator", "CRITICAL",
                               "certificate fingerprint differs from pin",
                               endpoint=ep, pinned=pinned, observed=fp)]
        return []

    def _rule_unexpected_ca(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        issuer, fp = c.get("issuer"), c.get("cert_fingerprint")
        if issuer and fp and self.state.trusted_cas and str(issuer) not in self.state.trusted_cas:
            return [_detection("unexpected_ca", "HIGH",
                               "certificate issuer is not in the trusted CA list",
                               endpoint=c.get("endpoint"), issuer=issuer)]
        return []

    def _rule_key_reuse(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        fp, system = c.get("cert_fingerprint"), c.get("system") or c.get("host")
        if not fp or not system:
            return []
        seen = self.state.key_sightings[str(fp)]
        seen.add(str(system))
        if len(seen) > 1:
            return [_detection("key_reuse", "HIGH",
                               "same key material observed on multiple systems",
                               fingerprint=str(fp), systems=sorted(seen))]
        return []

    def _rule_weak_entropy(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        seed = c.get("extra", {}).get("entropy_sample")
        if seed is None:
            return []
        ent = shannon_entropy(seed)
        if ent < WEAK_ENTROPY_BITS_PER_BYTE:
            return [_detection("weak_entropy", "MEDIUM",
                               f"shannon entropy {ent:.2f} < {WEAK_ENTROPY_BITS_PER_BYTE} bits/byte",
                               endpoint=c.get("endpoint"), entropy=round(ent, 3))]
        return []

    def _rule_protocol_violation(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        # deterministic state machine per protocol: valid version progressions
        prev = c.get("extra", {}).get("prev_state")
        cur_state = c.get("extra", {}).get("state")
        if not prev or not cur_state:
            return []
        valid = {("ESTABLISHED", "DOWNGRADED"), ("DOWNGRADED", "ESTABLISHED"),
                 ("ESTABLISHED", "ESTABLISHED"), ("HANDSHAKE", "ESTABLISHED")}
        if (prev, cur_state) not in valid:
            return [_detection("protocol_violation", "ALERT",
                               f"invalid transition {prev} -> {cur_state}",
                               endpoint=c.get("endpoint"), proto=c.get("proto"))]
        return []

    def _rule_rate_anomaly(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        key = str(c.get("system") or c.get("host") or "?")
        now_ts = c.get("observed_at")
        try:
            ts = datetime.fromisoformat(now_ts) if now_ts else datetime.now(timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        window = self.state.rate_windows[key]
        window.append(ts.timestamp())
        if len(window) < 10:
            return []  # baseline still forming — honest, no guess
        # per-second counts across the window; the current second is judged
        # against the 3-sigma baseline of all earlier seconds
        counts: dict[int, int] = defaultdict(int)
        for t in window:
            counts[int(t)] += 1
        current_second = int(ts.timestamp())
        baseline_counts = [n for sec, n in counts.items() if sec != current_second]
        if len(baseline_counts) < 8:
            return []
        mean = statistics.fmean(baseline_counts)
        stdev = statistics.pstdev(baseline_counts)
        current = counts.get(current_second, 0)
        if current < 2 or current <= mean + 3 * stdev:
            return []
        return [_detection("rate_anomaly", "MEDIUM",
                           f"{current} events/s exceeds 3-sigma baseline ({mean:.2f}±{stdev:.2f})",
                           system=key)]

    def _rule_new_endpoint(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        system, ep = c.get("system") or c.get("host"), c.get("endpoint")
        if not system or not ep or c.get("proto") != "tls":
            return []
        known = self.state.known_endpoints[str(system)]
        if ep in known:
            return []
        known.add(str(ep))
        return [_detection("new_endpoint", "MEDIUM",
                           "TLS handshake from an endpoint never seen for this system",
                           system=str(system), endpoint=str(ep))]

    def _rule_cert_near_expiry(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        days = c.get("extra", {}).get("days_until_expiry")
        if days is None:
            return []
        try:
            days = float(days)
        except (TypeError, ValueError):
            return []
        if 0 <= days < CERT_EXPIRY_WARN_DAYS:
            return [_detection("cert_near_expiry", "MEDIUM",
                               f"certificate expires in {days:.0f} days",
                               endpoint=c.get("endpoint"),
                               fingerprint=c.get("cert_fingerprint"))]
        return []

    def _rule_revoked_cert(self, c: dict[str, Any]) -> list[dict[str, Any]]:
        ocsp = c.get("extra", {}).get("ocsp")
        if ocsp == "REVOKED":
            return [_detection("revoked_cert_in_use", "CRITICAL",
                               "revoked certificate is in active use",
                               endpoint=c.get("endpoint"),
                               fingerprint=c.get("cert_fingerprint"))]
        return []

    def _rule_kms_policy_change(self, c: dict[str, Any], b: dict[str, Any] | None) -> list[dict[str, Any]]:
        if c.get("kind") != "kms_policy":
            return []
        current = c.get("extra", {}).get("policy")
        baseline = (b or {}).get("policy") or (b or {}).get("extra", {}).get("policy")
        if baseline is not None and current != baseline:
            return [_detection("hsm_kms_policy_change", "HIGH",
                               "KMS/HSM policy differs from baseline",
                               system=c.get("system"))]
        return []

    # ----------------------------------------------------------------- driver

    def evaluate(self, canonical: dict[str, Any]) -> list[dict[str, Any]]:
        endpoint = str(canonical.get("endpoint") or "")
        system = str(canonical.get("system") or "")
        baseline = self.state.baselines.get(endpoint) or self.state.baselines.get(system)
        detections: list[dict[str, Any]] = []
        detections += self._rule_crypto_downgrade(canonical, baseline)
        detections += self._rule_algorithm_downgrade(canonical, baseline)
        detections += self._rule_key_size_reduction(canonical, baseline)
        detections += self._rule_mitm(canonical)
        detections += self._rule_unexpected_ca(canonical)
        detections += self._rule_key_reuse(canonical)
        detections += self._rule_weak_entropy(canonical)
        detections += self._rule_protocol_violation(canonical)
        detections += self._rule_rate_anomaly(canonical)
        detections += self._rule_new_endpoint(canonical)
        detections += self._rule_cert_near_expiry(canonical)
        detections += self._rule_revoked_cert(canonical)
        detections += self._rule_kms_policy_change(canonical, baseline)
        # baseline learning: a clean observation (no serious detections)
        # becomes the known-good for its endpoint — deterministic, never
        # auto-overwritten. Benign informational rules (new_endpoint,
        # rate_anomaly, cert_near_expiry) do not block learning.
        benign = {"new_endpoint", "rate_anomaly", "cert_near_expiry"}
        if endpoint and canonical.get("tls_version") and \
                all(d["rule"] in benign for d in detections):
            self.state.baselines.setdefault(endpoint, {
                "tls_version": canonical.get("tls_version"),
                "algorithm": canonical.get("algorithm"),
                "key_size": canonical.get("key_size"),
            })
        return detections


def attach_baseline(detector: AttackState, endpoint: str, *, tls_version: str,
                    algorithm: str | None = None, key_size: int | None = None) -> None:
    """Operator-pinned baseline (beats any learned baseline)."""
    detector.baselines[endpoint] = {"tls_version": tls_version, "algorithm": algorithm,
                                    "key_size": key_size}
