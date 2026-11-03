"""IDS: alerts, signatures and flow metadata — the bank's intrusion detection, read.

An IDS alert is metadata about a flow: signature id and revision, source and destination,
protocol, port, timing, and the TLS parameters that were visible on the wire. This collector
keeps exactly that and nothing else: no payload, no HTTP body, no decrypted bytes. What it
adds on top of the device is the *question the estate needs answered* — which cryptographic
assets and critical systems are involved — which lives in :mod:`..correlate`.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, OBSERVED, DeviceCollector

CONTROL = "IDS"

COLLECTS: tuple[str, ...] = (
    "alerts", "signature_ids_and_revisions", "protocol_metadata", "flow_metadata",
    "event_timestamps",
)
MUST_NOT: tuple[str, ...] = (
    "capture_or_store_payloads", "store_http_bodies", "decrypt_traffic",
    "replace_the_banks_ids", "block_traffic",
)

#: fields that make an event useful for crypto correlation without carrying content
FLOW_FIELDS: tuple[str, ...] = ("src", "dst", "protocol", "port", "tls_version",
                                "cipher_suite", "sni", "alpn", "timestamp")


class IdsCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def alerts(self) -> list[dict[str, Any]]:
        """Alerts, one row per event, with the flow it describes — never its bytes."""
        return [row for row in self.collect_security_events()
                if row["kind"] in {"ALERT", "EVENT", "DROP", "BLOCK"}]

    def signatures(self) -> list[dict[str, Any]]:
        rows = self._section_rows("signatures")
        signatures: list[dict[str, Any]] = []
        for raw in rows:
            signature = self._field(raw, "signature") or self._field(raw, "sid")
            signatures.append({
                "signature": str(signature),
                "revision": self._field(raw, "signature_revision") or self._field(raw, "rev"),
                "classification": self._field(raw, "classification"),
                "enabled": bool(self._field(raw, "enabled", True)),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("SIGNATURE", signature, raw),
            })
        return signatures

    def flow_metadata(self) -> list[dict[str, Any]]:
        """The correlation input: address, port, protocol and TLS parameters, no content."""
        return [{key: event.get(key) for key in FLOW_FIELDS} | {
            "evidence_id": event["evidence_id"], "fact": OBSERVED}
            for event in self.alerts()]


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> IdsCollector:
    from .vendors import spec_for

    return IdsCollector(spec_for(vendor), feed)
