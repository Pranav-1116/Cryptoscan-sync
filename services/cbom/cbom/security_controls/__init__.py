"""Security control integration — read-only collectors over the bank's existing controls.

CryptoScan integrates with the bank's existing network and security controls to build an
evidence-backed cryptographic and security estate model. It is not a firewall, an IPS, a
WAF, a rate limiter or an API gateway, and nothing in this package can become one: a
collector declares read operations only, and a spec that names a mutating operation is
refused when the adapter is registered rather than when someone calls it.

The whole layer is one contract, applied to every control type and every vendor:

    Vendor Adapter → Common Collector Contract → Normalized Evidence
                   → Canonical Asset Identity → Digital Twin

so a vendor is a *dialect row* (:mod:`cbom.security_controls.firewall.vendors`), never a new
architecture. :class:`~cbom.security_controls.base.SecurityControlCollector` has six verbs —
``discover_assets``, ``collect_configuration``, ``collect_crypto_metadata``,
``collect_relationships``, ``collect_security_events``, ``health`` — and none of them writes.

Two invariants are enforced here rather than documented here:

* **no prohibited value survives a collection cycle.** Private keys, HSM key material,
  passwords, API secrets, session tokens, customer payloads, HTTP bodies, decrypted traffic,
  payment data, credentials, cookies and authorization headers are redacted by field name and
  by content shape, and the redaction is itself recorded as evidence;
* **three facts stay apart.** What a control is configured to do, what the network observed
  and what the application actually did are three records with three evidence ids, never one
  verdict.
"""

from __future__ import annotations

from .audit import audit_rate_limits
from .drivers import DRIVERS, live_snapshot
from .base import (
    CONFIGURED,
    CONTROL_TYPES,
    OBSERVED,
    READ_OPERATIONS,
    REDACTED,
    RUNTIME_OBSERVED,
    AdapterSpec,
    ControlRefused,
    DeviceCollector,
    EvidenceBook,
    SecurityControlCollector,
    fact_class,
    read_only_violations,
    scrub,
    separate_facts,
)
from .correlate import correlate_event
from .facade import FACADES, facade_spec
from .observation import (AccessLog, CounterAPI, LimitViolations, WindowModel, audit_limits,
                          observation_report)
from .project import project
from .registry import (FACADE_CONTROLS, PACKAGES, adapters, collector, controls, fleet,
                       read_only_audit, spec_for)
from .resolver import (InventoryResolver, SqlResolver, StaticResolver, Window,
                       correlate_from_inventory)
from .store import EvidenceStore, content_digest
from .transport import (Credential, FileTail, HttpTransport, RecordedTransport, SecretSource,
                        TransportResult)

CONTRACT_VERSION = "cryptoscan.security-controls/1"

__all__ = [
    "AccessLog",
    "AdapterSpec",
    "CONFIGURED",
    "CounterAPI",
    "Credential",
    "CONTRACT_VERSION",
    "CONTROL_TYPES",
    "ControlRefused",
    "DeviceCollector",
    "DRIVERS",
    "EvidenceBook",
    "EvidenceStore",
    "FACADES",
    "FACADE_CONTROLS",
    "FileTail",
    "HttpTransport",
    "InventoryResolver",
    "LimitViolations",
    "RecordedTransport",
    "SecretSource",
    "SqlResolver",
    "StaticResolver",
    "TransportResult",
    "Window",
    "WindowModel",
    "OBSERVED",
    "PACKAGES",
    "READ_OPERATIONS",
    "REDACTED",
    "RUNTIME_OBSERVED",
    "SecurityControlCollector",
    "adapters",
    "audit_limits",
    "audit_rate_limits",
    "collector",
    "content_digest",
    "controls",
    "correlate_from_inventory",
    "correlate_event",
    "fact_class",
    "facade_spec",
    "fleet",
    "live_snapshot",
    "observation_report",
    "project",
    "read_only_audit",
    "read_only_violations",
    "scrub",
    "separate_facts",
    "spec_for",
]
