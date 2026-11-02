"""Correlating network hardware with the certificates it terminates (phase H6).

A switch or a load balancer in the estate is useful; a load balancer nobody has
tied to the certificates it terminates is a box with a management IP. This module
is the tie: it turns a TLS observation taken from a device into a typed,
evidence-backed edge, using the same rules
:mod:`~universal_vendor.hardware.relationships` applies to applications.

Three rules, all of them inherited rather than invented here:

* **Evidence first.** ``TERMINATES_TLS`` is only produced when something names
  both ends: a TLS handshake recorded against that device (``OBSERVED``), a
  device configuration that names the certificate or trustpoint (``CONFIG``), or
  a CMDB row that says so (``DECLARED``, capped at MEDIUM). A device with a
  management IP and no certificate produces no edge.
* **The weakest citation decides.** A config file plus a stale CMDB row is a
  config edge with a stale row attached, not a strong edge — that is
  :class:`~universal_vendor.hardware.relationships.HardwareEdge`'s rule and this
  module does not get its own.
* **A certificate is identified by its fingerprint** where one exists. Two
  devices terminating the same certificate is a fact worth surfacing (an HA
  pair), and it is only visible if the identity is the certificate and not the
  device.

What this module deliberately does not do: it does not parse X.509 (the network
scanner already does, via ``certificates/cert_parser.py``), it does not fetch
anything, and it does not decide whether a certificate is *good* — expiry,
revocation and hostname matching are the TLS probe's job, and duplicating them
would give the platform two verdicts on one certificate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from universal_vendor.hardware.relationships import (
    EDGE_KINDS,
    Evidence,
    HardwareEdge,
    blast_radius,
    derive_edges,
)

SCHEMA = "cryptoscan.network-correlation/1"

#: Edge kinds this module adds on top of the base set. They are registered in
#: :mod:`~universal_vendor.hardware.relationships` too, so one validator governs
#: every edge in the twin.
NETWORK_EDGE_KINDS = ("TERMINATES_TLS", "FRONTS")

#: A device certificate reference in a configuration. Cisco, Juniper and F5 all
#: name the trustpoint or the certificate profile; the window is bounded so an
#: unrelated line far below does not attach itself.
_CONFIG_CERT_SIGNALS: tuple[tuple[str, str], ...] = (
    (r"crypto\s+pki\s+trustpoint\s+([A-Za-z0-9_.:-]+)", "trustpoint"),
    (r"(?:ssl|crypto)\s+(?:certificate|profile)\s+([A-Za-z0-9_.:-]+)", "certificate profile"),
    (r"ssl-?cert(?:ificate)?\s*(?:name)?\s*[=:]?\s*([A-Za-z0-9_.:-]+)", "ssl certificate"),
)

_NOT_A_NAME = re.compile(r"^(\d+|true|false|on|off|none)$", re.IGNORECASE)


class CertificateNotIdentified(ValueError):
    """A certificate was supplied with neither a fingerprint nor a subject."""


@dataclass(frozen=True)
class CertificateRef:
    """The identity of a certificate, from whatever the TLS probe produced.

    ``fingerprint`` is the sha256 of the DER body when available: two devices
    presenting the same certificate must collapse to one asset, and a subject
    name alone cannot do that (SANs overlap, reissues repeat names).
    """

    fingerprint: str | None = None
    subject: str | None = None
    issuer: str | None = None
    san: tuple[str, ...] = ()
    not_after: str | None = None

    def __post_init__(self) -> None:
        if not (self.fingerprint or self.subject):
            raise CertificateNotIdentified(
                "a certificate needs a fingerprint or a subject; a port number is not a "
                "certificate")

    @property
    def asset_id(self) -> str:
        if self.fingerprint:
            return f"cert:{self.fingerprint.lower()}"
        return f"cert:{self.subject}"

    @classmethod
    def from_probe(cls, payload: Mapping[str, Any]) -> "CertificateRef":
        """Build from the network scanner's parsed certificate dict."""
        fingerprint = _text(payload.get("fingerprint_sha256"))
        sans = payload.get("san") or payload.get("subject_alt_name") or []
        if isinstance(sans, str):
            sans = [part for part in sans.split(",") if part.strip()]
        return cls(
            fingerprint=fingerprint,
            subject=_text(payload.get("subject")) or _text(payload.get("common_name")),
            issuer=_text(payload.get("issuer")),
            san=tuple(str(item) for item in sans),
            not_after=_text(payload.get("not_after")) or _text(payload.get("notAfter")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "fingerprint_sha256": self.fingerprint,
                "subject": self.subject, "issuer": self.issuer, "san": list(self.san),
                "not_after": self.not_after}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _days_until(value: str | None, *, now: datetime | None = None) -> int | None:
    """Whole days until ``not_after``; ``None`` when the date cannot be read."""
    if not value:
        return None
    moment = _parse_moment(value)
    if moment is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return int((moment - reference).total_seconds() // 86400)


def _parse_moment(text: str) -> datetime | None:
    candidate = text.strip().replace("Z", "+00:00")
    for pattern in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                    "%b %d %H:%M:%S %Y %Z"):
        try:
            parsed = datetime.strptime(candidate, pattern)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# edge derivation
# --------------------------------------------------------------------------- #

def _merged(edges: Iterable[HardwareEdge]) -> list[HardwareEdge]:
    merged: dict[tuple[str, str, str], HardwareEdge] = {}
    for edge in edges:
        key = (edge.subject, edge.hardware, edge.kind)
        if key in merged:
            previous = merged[key]
            merged[key] = HardwareEdge(previous.subject, previous.hardware,
                                       previous.kind,
                                       previous.evidence + edge.evidence)
        else:
            merged[key] = edge
    return list(merged.values())


def derive_network_edges(
    device: str,
    *,
    tls_observations: Iterable[Mapping[str, Any]] = (),
    config_text: str | None = None,
    config_reference: str | None = None,
    declared_certificates: Iterable[str] = (),
    fronts: Iterable[str] = (),
) -> list[HardwareEdge]:
    """Every edge a device earns, and nothing it has not earned.

    ``tls_observations`` are the TLS probe's records for *this* device; each must
    name a certificate (fingerprint or subject). A record from another device is
    rejected rather than silently attributed — attributing a certificate to the
    wrong load balancer is worse than missing the edge.
    """
    edges: list[HardwareEdge] = []

    for index, observation in enumerate(tls_observations):
        observed_device = _text(observation.get("device")) or _text(observation.get("host"))
        if observed_device and observed_device != device:
            raise ValueError(
                f"TLS observation for {observed_device!r} was passed with device={device!r}: "
                "a certificate seen on one appliance must not be attributed to another")
        certificate = CertificateRef.from_probe(observation)
        port = observation.get("port")
        reference = f"tls-probe:{device}:{port if port is not None else 443}" \
                    f"#{certificate.fingerprint or certificate.subject}"
        edges.append(HardwareEdge(subject=certificate.asset_id, hardware=device,
                                  kind="TERMINATES_TLS",
                                  evidence=(Evidence("OBSERVED", reference),)))

    if config_text:
        reference = config_reference or "device config (location not recorded)"
        for pattern, label in _CONFIG_CERT_SIGNALS:
            for match in re.finditer(pattern, config_text, re.IGNORECASE):
                name = match.group(1)
                if _NOT_A_NAME.match(name):
                    continue
                edges.append(HardwareEdge(
                    subject=f"cert:{name}", hardware=device, kind="TERMINATES_TLS",
                    evidence=(Evidence("CONFIG", f"{reference}#{label}:{name}"),)))
        # A device that names an HSM token for its keys is a device that uses the
        # HSM; reuse the base rule rather than writing a second one.
        edges.extend(derive_edges(device, config_text=config_text,
                                  config_reference=config_reference))

    for name in sorted({_text(item) for item in declared_certificates if _text(item)}):
        edges.append(HardwareEdge(
            subject=f"cert:{name}", hardware=device, kind="TERMINATES_TLS",
            evidence=(Evidence("DECLARED", f"cmdb:device/{device}/certificate/{name}"),)))

    for upstream in sorted({_text(item) for item in fronts if _text(item)}):
        if upstream == device:
            raise ValueError(f"{device!r} cannot front itself")
        edges.append(HardwareEdge(
            subject=device, hardware=upstream, kind="FRONTS",
            evidence=(Evidence("DECLARED", f"topology:device/{device}/fronts/{upstream}"),)))

    return _merged(edge for edge in edges if edge.kind in EDGE_KINDS + NETWORK_EDGE_KINDS)


# --------------------------------------------------------------------------- #
# what the estate can now be asked
# --------------------------------------------------------------------------- #

def shared_certificates(edges: Iterable[HardwareEdge]) -> dict[str, list[str]]:
    """Certificates terminated by more than one device — an HA pair, or a gap.

    Two load balancers presenting the same certificate is normal. Two *unrelated*
    devices presenting it is a finding, and either way the estate should be able
    to say which devices share a key.
    """
    devices_of: dict[str, set[str]] = {}
    for edge in edges:
        if edge.kind != "TERMINATES_TLS":
            continue
        devices_of.setdefault(edge.subject, set()).add(edge.hardware)
    return {certificate: sorted(devices)
            for certificate, devices in sorted(devices_of.items()) if len(devices) > 1}


def device_blast_radius(device: str, edges: Iterable[HardwareEdge],
                        *, system_of: Mapping[str, str] | None = None,
                        business_system_of: Mapping[str, str] | None = None) -> dict[str, Any]:
    """If this appliance failed, which certificates and services would go with it.

    Uses the base blast radius unchanged: a device is a piece of hardware, and
    the walk is the same walk. What it adds is the certificate list, because
    "the load balancer is down" and "card-auth TLS is down" is the difference a
    reader cares about.
    """
    radius = blast_radius(device, edges, system_of=system_of,
                          business_system_of=business_system_of)
    radius["certificates_at_risk"] = sorted(
        edge.subject for edge in edges
        if edge.kind == "TERMINATES_TLS" and edge.hardware == device)
    return radius


def certificate_exposure(edges: Iterable[HardwareEdge],
                         certificates: Iterable[CertificateRef],
                         *, within_days: int = 90,
                         now: datetime | None = None) -> dict[str, Any]:
    """Which terminated certificates expire soon, and on which device.

    A certificate nobody has tied to a device cannot appear here, which is the
    point: an expiring certificate the estate cannot place is a certificate it
    cannot plan around.
    """
    devices_of = {edge.subject: edge.hardware for edge in edges
                  if edge.kind == "TERMINATES_TLS"}
    expiring: list[dict[str, Any]] = []
    unknown_dates: list[str] = []
    for certificate in certificates:
        days = _days_until(certificate.not_after, now=now)
        if days is None:
            unknown_dates.append(certificate.asset_id)
            continue
        if days <= within_days:
            expiring.append({
                "certificate": certificate.asset_id,
                "device": devices_of.get(certificate.asset_id),
                "placed": certificate.asset_id in devices_of,
                "days_remaining": days,
                "not_after": certificate.not_after,
                "severity": "HIGH" if days <= 14 else "MEDIUM" if days <= 45 else "LOW",
            })
    expiring.sort(key=lambda item: item["days_remaining"])
    return {
        "schema": SCHEMA,
        "within_days": within_days,
        "expiring": expiring,
        "unplaced": [item for item in expiring if not item["placed"]],
        "unknown_expiry": unknown_dates,
        "count": len(expiring),
    }


def correlate(device: str, *, tls_observations: Iterable[Mapping[str, Any]] = (),
              config_text: str | None = None, config_reference: str | None = None,
              declared_certificates: Iterable[str] = (), fronts: Iterable[str] = ()
              ) -> dict[str, Any]:
    """One device's correlation result, ready to store or render."""
    edges = derive_network_edges(
        device, tls_observations=tls_observations, config_text=config_text,
        config_reference=config_reference,
        declared_certificates=declared_certificates, fronts=fronts)
    certificates = [CertificateRef.from_probe(observation)
                    for observation in tls_observations]
    return {
        "schema": SCHEMA,
        "device": device,
        "edges": [edge.to_dict() for edge in edges],
        "certificates": [certificate.to_dict() for certificate in certificates],
        "shared_with_other_devices": shared_certificates(edges),
        "edge_count": len(edges),
        "by_kind": {kind: sum(1 for edge in edges if edge.kind == kind)
                    for kind in sorted({edge.kind for edge in edges})},
    }


__all__ = [
    "NETWORK_EDGE_KINDS",
    "CertificateNotIdentified",
    "CertificateRef",
    "certificate_exposure",
    "correlate",
    "derive_network_edges",
    "device_blast_radius",
    "shared_certificates",
]
