"""Cryptava's planes. Each collector reads the host and writes into one Observation.

Order matters and is fixed in :func:`collect_all`: hardware first (it names the host),
then software (the package database — the crypto plane resolves library files to the
package that installed them), then network (services, listeners, TLS), then crypto
configuration and certificates, then vendors (derived from everything before it).
A collector that raises never sinks the run: its plane is reported FAILED with the
reason, and the remaining planes still report.
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptava.observation import Observation
from cryptava.util import HostView


@dataclass
class Context:
    """What one collection cycle knows, shared across planes."""

    view: HostView
    config: dict[str, Any]
    obs: Observation = field(default_factory=Observation)
    hostname: str = ""
    fqdn: str = ""
    primary_ip: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    machine_key: str = ""
    os_release: dict[str, str] = field(default_factory=dict)
    host_ref: str = "host"
    host_evidence: str | None = None
    #: package name -> {"version", "ecosystem", "ref", "maintainer", "files"?}
    packages: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: absolute file path -> package name (from dpkg *.list / apk R: lines)
    file_owner: dict[str, str] = field(default_factory=dict)
    #: library ref by resolved .so path
    libraries: dict[str, str] = field(default_factory=dict)
    #: service ref by executable name
    services: dict[str, str] = field(default_factory=dict)
    #: pid -> {"comm", "exe", "uid"} for every readable process (never the command line)
    processes: dict[int, dict[str, Any]] = field(default_factory=dict)
    #: (port, protocol label) -> endpoint ref for local listeners
    endpoints: dict[tuple[int, str], str] = field(default_factory=dict)
    #: certificate fingerprint -> endpoint refs that served it
    served_certificates: dict[str, list[str]] = field(default_factory=dict)
    #: certificate ref by sha256 fingerprint
    certificates: dict[str, str] = field(default_factory=dict)
    #: CA ref by issuer DN
    cas: dict[str, str] = field(default_factory=dict)
    #: vendor ref by (name, product)
    vendors: dict[tuple[str, str], str] = field(default_factory=dict)
    #: things the vendor plane links: (subject_ref, vendor_name, product, version, basis_note)
    vendor_links: list[tuple[str, str, str, str | None, str]] = field(default_factory=list)
    #: hardware system ref (for component edges)
    system_ref: str | None = None
    system_evidence: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def environment(self) -> str | None:
        return (self.config.get("tags") or {}).get("environment")


def collect_all(ctx: Context) -> Context:
    from cryptava.collectors import crypto, hardware, network, software, topology, vendor

    steps: list[tuple[str, Callable[[Context], None]]] = [
        ("HBOM · hardware", hardware.collect),
        ("SBOM · software", software.collect),
        ("NBOM · network", network.collect),
        ("CBOM · cryptography", crypto.collect),
        ("VBOM · vendors", vendor.collect),
        ("TechBOM · topology", topology.collect),
    ]
    for plane, step in steps:
        try:
            step(ctx)
        except Exception as exc:  # noqa: BLE001 — one plane failing must not sink the others
            detail = traceback.format_exception_only(type(exc), exc)[-1].strip()
            ctx.obs.plane(plane, "FAILED", f"collector error: {detail}", expected=1, collected=0)
            if plane.startswith("HBOM") and not ctx.obs.has(ctx.host_ref):
                # every other plane hangs off the host node; without it nothing can attach
                raise
    return ctx
