"""Topic registry for the CryptoScan event stream.

Eight topics, exactly the platform contract — producers/consumers are part
of the schema so a topic is never invented ad hoc.
"""

from __future__ import annotations

TOPICS = (
    "raw-events",         # all scanner/agent/daemon output (HMAC-signed)
    "normalized-events",  # canonical CBOM schema
    "policy-results",     # deterministic rule evaluations
    "attack-detections",  # real-time threat events (13 deterministic rules)
    "cbom-updates",       # CBOM change stream (drives the Live CBOM service)
    "graph-sync",         # graph node/relationship updates
    "audit-log",          # immutable, hash-chained processing trail
    "alerts",             # outbound notifications (SIEM/webhook fan-out)
)

# who writes / who reads what (part of the contract, validated in tests)
PRODUCERS = {
    "raw-events": {"scanners", "agents", "monitor-daemon", "telecom-probes", "cloud-connectors", "api"},
    "normalized-events": {"stream-processor"},
    "policy-results": {"stream-processor"},
    "attack-detections": {"stream-processor"},
    "cbom-updates": {"stream-processor"},
    "graph-sync": {"stream-processor"},
    "audit-log": {"stream-processor"},
    "alerts": {"stream-processor", "alert-engine"},
}

CONSUMERS = {
    "raw-events": {"stream-processor"},
    "normalized-events": {"cbom-service", "graph-sync", "audit"},
    "policy-results": {"alert-engine", "audit"},
    "attack-detections": {"alert-engine", "siem", "dashboard"},
    "cbom-updates": {"cbom-service", "dashboard"},
    "graph-sync": {"graph-service"},
    "audit-log": {"audit", "siem"},
    "alerts": {"siem", "pagerduty"},
}


def validate_topic(topic: str) -> str:
    if topic not in TOPICS:
        raise ValueError(f"unknown topic '{topic}' — must be one of {', '.join(TOPICS)}")
    return topic
