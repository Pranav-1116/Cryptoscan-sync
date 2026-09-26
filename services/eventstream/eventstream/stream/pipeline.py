"""The deterministic stream processor.

One pass over a raw event, all steps pure:

  a. normalize      -> canonical CBOM schema
  b. deduplicate    -> content-identity merge (seen_count/last_seen)
  c. policy eval    -> deterministic rule catalog (reuses cbom.banking catalogs)
  d. attack detect  -> the 13 stateful deterministic rules
  e. evidence chain -> every processed event extends a SHA-256 chain
  f. fan-out        -> normalized-events / policy-results / attack-detections
                       / cbom-updates / graph-sync / audit-log / alerts

Every step is auditable: the audit-log topic carries the chain (seq, input
hash, outputs, chain_hash) so the processing itself is replay-able evidence.
"""

from __future__ import annotations

import hashlib
from typing import Any

from eventstream.bus import StreamBus
from eventstream.envelope import content_hash
from eventstream.stream.attack_rules import AttackDetector, AttackState
from eventstream.stream.dedup import DedupIndex
from eventstream.stream.normalize import normalize

# deterministic policy catalog: disallowed/legacy algorithms (aligned with the
# cbom banking catalog by name) — evaluated on every normalized event
DISALLOWED_ALGORITHMS = {"DES", "3DES", "RC4", "MD5", "SHA1", "NULL", "EXPORT"}
DEPRECATED_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1"}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "ALERT": 3, "MEDIUM": 2, "LOW": 1}


def policy_evaluate(canonical: dict[str, Any]) -> list[dict[str, Any]]:
    """Deterministic policy verdicts for one canonical event."""
    results: list[dict[str, Any]] = []
    algo = str(canonical.get("algorithm") or "").upper()
    if algo in DISALLOWED_ALGORITHMS:
        results.append({"policy": "disallowed_algorithm", "verdict": "FAIL",
                        "detail": f"{algo} is disallowed by policy", "field": "algorithm"})
    tls = str(canonical.get("tls_version") or "")
    if tls in DEPRECATED_TLS:
        results.append({"policy": "deprecated_tls", "verdict": "FAIL",
                        "detail": f"{tls} is deprecated by policy", "field": "tls_version"})
    issues = canonical.get("extra", {}).get("policy_issues") or []
    for issue in issues:
        results.append({"policy": str(issue), "verdict": "FAIL",
                        "detail": f"scanner policy issue {issue}", "field": "tls"})
    if not results:
        results.append({"policy": "baseline", "verdict": "PASS", "detail": "no policy failures",
                        "field": None})
    return results


class StreamProcessor:
    def __init__(self, bus: StreamBus, *, state: AttackState | None = None,
                 dedup: DedupIndex | None = None):
        self.bus = bus
        self.detector = AttackDetector(state or AttackState())
        self.dedup = dedup or DedupIndex()
        self.chain_hash: str = "0" * 64
        self.processed = 0

    # ------------------------------------------------------------------ ingest

    def ingest(self, raw: dict[str, Any], *, key: str = "default",
               source: str = "unknown") -> dict[str, Any]:
        """External entry point: an observation from any collector."""
        env = self.bus.publish_raw(raw, key=key, source=source)
        return env

    def process(self, env: dict[str, Any]) -> dict[str, Any]:
        """Full deterministic pass for one raw-event envelope."""
        raw = env["payload"]
        canonical = normalize(raw, source=env.get("source", "unknown"),
                              observed_at=env.get("ts"))
        is_new, merged = self.dedup.merge(canonical)
        canonical.setdefault("extra", {})["dedup_key"] = merged["dedup_key"]

        policy = policy_evaluate(canonical)
        detections = self.detector.evaluate(canonical)

        out: dict[str, Any] = {
            "input_hash": env.get("payload_hash"),
            "dedup_key": merged["dedup_key"],
            "is_new": is_new,
            "seen_count": merged["seen_count"],
            "canonical": canonical,
            "policy": policy,
            "detections": detections,
        }

        self.bus.publish("normalized-events", out["canonical"],
                         key=str(merged["dedup_key"][:16]), source="stream-processor")
        self.bus.publish("policy-results", {
            "dedup_key": merged["dedup_key"], "results": policy,
            "fails": sum(1 for r in policy if r["verdict"] == "FAIL"),
        }, key=str(merged["dedup_key"][:16]), source="stream-processor")

        for det in detections:
            self.bus.publish("attack-detections", {
                "dedup_key": merged["dedup_key"], "canonical": canonical, **det},
                key=str(merged["dedup_key"][:16]), source="stream-processor")
            # deterministic alert fan-out: CRITICAL/HIGH become alert events
            if SEVERITY_ORDER.get(det["severity"], 0) >= 3:
                self.bus.publish("alerts", {
                    "severity": det["severity"], "rule": det["rule"],
                    "detail": det["detail"], "endpoint": canonical.get("endpoint"),
                    "system": canonical.get("system"),
                }, key=str(merged["dedup_key"][:16]), source="stream-processor")

        if is_new and canonical.get("kind") in {"tls_finding", "telecom_nf", "cert"}:
            self.bus.publish("cbom-updates", {
                "action": "add", "dedup_key": merged["dedup_key"],
                "asset": canonical,
            }, key=str(canonical.get("system") or "default"), source="stream-processor")
            self.bus.publish("graph-sync", {
                "op": "merge_node", "label": canonical["kind"],
                "key": merged["dedup_key"], "props": {
                    "endpoint": canonical.get("endpoint"),
                    "system": canonical.get("system"),
                    "algorithm": canonical.get("algorithm"),
                    "tls_version": canonical.get("tls_version"),
                },
            }, key=str(canonical.get("system") or "default"), source="stream-processor")

        # evidence chain: this event's chain entry covers input + verdicts
        entry = content_hash({
            "prev": self.chain_hash,
            "input": env.get("payload_hash"),
            "dedup_key": merged["dedup_key"],
            "fails": sum(1 for r in policy if r["verdict"] == "FAIL"),
            "detections": [d["rule"] for d in detections],
        })
        self.chain_hash = hashlib.sha256(entry.encode()).hexdigest()
        self.processed += 1
        self.bus.publish("audit-log", {
            "seq": self.processed, "input_hash": env.get("payload_hash"),
            "dedup_key": merged["dedup_key"], "is_new": is_new,
            "detections": [d["rule"] for d in detections],
            "chain_hash": self.chain_hash,
        }, key="processor", source="stream-processor")
        return out

    def drain(self, *, limit: int = 200) -> int:
        """Consume pending raw events as the 'stream-processor' group."""
        events = self.bus.read("raw-events", "stream-processor", limit=limit)
        for env in events:
            self.process(env)
            self.bus.commit("raw-events", "stream-processor", int(env["seq"]))
        return len(events)
