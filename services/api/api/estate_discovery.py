"""One estate-discovery job that fans out to every plane (spec 93 §1-§15).

The directive's central correction is *not six scanners*. One job discovers the
estate once; the six BOMs are projections of the single evidence graph it built.
``shared_models/estate_graph.py`` already does the joining and projection, and
``POST /estate/evidence/discover`` accepts a payload — but a payload has to come
from somewhere. This module is that somewhere: it reads every plane's *already
collected and persisted* evidence and folds it into one graph.

What "fan-out" means here, precisely
------------------------------------
Each plane has a **collector adapter** that reads persisted rows (never probes,
never scans, never needs credentials of its own):

``NETWORK``    network evidence records from stored observation runs
``RUNTIME``    runtime crypto events from stored ingest runs
``STATIC``     crypto assets found by static scanning (algorithm, key size, location)
``PKI``        certificate inventory (public metadata only)
``HARDWARE``   hardware/host crypto capability inventory (metadata only)
``VENDOR``     vendor-declared crypto (capability only — never bank usage)

Active collection itself stays where it already lives, behind its own approved
scope (`/network/crypto-observe`, `/runtime/crypto-events`). The estate job is
the *join*, and it is deliberately read-only: re-running it costs no packets and
cannot breach a scan scope.

Failure semantics (§15) — the part that must not be softened
------------------------------------------------------------
A collector that raises does **not** become an empty plane. It is recorded as
``FAILED`` with the exception as the reason and an impact statement naming the
BOMs that lose coverage. A plane that holds zero rows is ``COMPLETE`` with
``expected=0`` and an explicit note that an empty store is not evidence that the
estate contains no crypto. Nothing in the report ever says "no crypto found".

Every response carries its own limitations, and ``lifecycle`` states which
phases actually ran, in the spec's order (§18), so a reader can see that
"policy" or "PQC" did not run rather than assume it passed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from shared_models.estate_graph import build_graph, collector_outcome

MODEL = "cryptoscan.estate-discovery-job/1"
#: per-BOM component identities kept in a stored run (enough to diff, not a copy)
MAX_STORED_BOM_COMPONENTS = 4000
SCHEMA_EVIDENCE = "cryptoscan.estate-evidence/1"

#: §13 discovery planes this repository can actually read today.
PLANES: tuple[str, ...] = (
    "NETWORK", "CLOUD", "KUBERNETES", "CMDB", "KMS", "HSM", "RUNTIME", "STATIC", "PKI", "HARDWARE", "VENDOR"
)

PLANE_DETAIL: dict[str, dict[str, str]] = {
    "NETWORK": {
        "source": "stored network observation runs",
        "boms": "NBOM, CBOM (NETWORK_TRANSPORT layer), TechBOM",
        "limitation": "only endpoints already observed under an approved scope; unprobed endpoints are NOT_OBSERVED",
    },
    "CLOUD": {
        "source": "live AWS control plane (ELBv2, ACM, RDS, KMS, API Gateway)",
        "boms": "NBOM, CBOM (transport and storage configuration), VBOM (managed services)",
        "limitation": "control-plane configuration only: a listener policy or key spec is what the service "
                      "allows, not what a client negotiated, and KMS only shows capability",
    },
    "CMDB": {
        "source": "live ServiceNow Table API (servers, business services, applications, relationships)",
        "boms": "SBOM (application inventory), TechBOM, VBOM (vendors the bank records)",
        "limitation": "CMDB records are declared (IMPORTED, LOW confidence): ownership and existence, never "
                      "cryptography in use",
    },
    "KMS": {
        "source": "live KMS usage from the provider audit trail (CloudTrail)",
        "boms": "CBOM (KMS layer, observed use), HBOM (key custody), TechBOM",
        "limitation": "an audit trail only covers its retention window: a key last used before it is "
                      "NOT_OBSERVED, never 'unused'",
    },
    "HSM": {
        "source": "live KMIP read-only (Locate + GetAttributes on the appliance)",
        "boms": "HBOM, CBOM (HSM layer)",
        "limitation": "state and usage counters only: key material is never read, and a zero counter means "
                      "'not counted', not 'unused'",
    },
    "KUBERNETES": {
        "source": "live cluster API (namespaces, ingresses, services, pods)",
        "boms": "NBOM, SBOM (images), TechBOM",
        "limitation": "read-only and CONFIGURED only: an Ingress TLS block is a declaration, and secrets are "
                      "never read",
    },
    "RUNTIME": {
        "source": "stored runtime crypto events",
        "boms": "CBOM (RUNTIME_OBSERVED), TechBOM",
        "limitation": "only processes inside an approved runtime scope; unattributed evidence stays Level 6",
    },
    "STATIC": {
        "source": "static crypto asset inventory",
        "boms": "CBOM (APPLICATION layer), SBOM, TechBOM",
        "limitation": "a static hit proves the algorithm is present in code, not that it runs",
    },
    "PKI": {
        "source": "certificate inventory",
        "boms": "CBOM (PLATFORM), HBOM context",
        "limitation": "public certificate metadata only — never private keys",
    },
    "HARDWARE": {
        "source": "hardware and host crypto capability inventory",
        "boms": "HBOM",
        "limitation": "declared/detected capability only; HSM contents remain UNKNOWN (metadata-only by policy)",
    },
    "VENDOR": {
        "source": "vendor crypto declarations",
        "boms": "VBOM, CBOM (capability only)",
        "limitation": "vendor-declared capability is never proof of bank usage",
    },
}

#: §18 lifecycle in the spec's order. Each phase reports whether it actually ran.
LIFECYCLE_PHASES: tuple[str, ...] = (
    "SCOPE_RESOLVED",
    "COLLECTORS_PLANNED",
    "EVIDENCE_COLLECTED",
    "NORMALIZED",
    "IDENTITY_RESOLVED",
    "CORRELATED",
    "EVIDENCE_VALIDATED",
    "COVERAGE_ASSESSED",
    "BOMS_PROJECTED",
)


# --------------------------------------------------------------------------- #
# collector adapters
# --------------------------------------------------------------------------- #
def _result_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        return value.to_dict() or {}
    return {}


def _iso(value: Any) -> str | None:
    return str(value) if value else None


def collect_network(db: Any, *, limit: int = 5) -> dict[str, Any]:
    """Read stored network evidence records; no probing happens here."""
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import current_tenant

    kinds = ("crypto-observe", "crypto-probe", "crypto-passive", "crypto-watch", "ipsec-observe",
             "message-layer", "device-inventory")
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    seen: set[str] = set()
    runs = 0
    for kind in kinds:
        rows = ScanRunRepository(db).list_runs(limit=limit, target_kind=kind, owner=current_tenant())
        for row in rows:
            runs += 1
            result = _result_dict(row).get("result") or {}
            for record in result.get("network_evidence") or []:
                endpoint = str((record.get("target") or {}).get("endpoint") or "")
                key = str(record.get("evidence_id") or endpoint)
                if key in seen:
                    continue
                seen.add(key)
                if not endpoint:
                    continue
                target = record.get("target") or {}
                assets.append({
                    "ref": f"network:{endpoint}",
                    "type": "NETWORK_ENDPOINT",
                    "name": endpoint,
                    "identity": {"endpoint": endpoint},
                    "location": target.get("ip_address") or target.get("host"),
                    "source": "network_scanner",
                    "attributes": {
                        "protocol": record.get("protocol"),
                        "port": target.get("port"),
                        "evidence_type": record.get("evidence_type"),
                        "observation_status": record.get("observation_status"),
                        "limitations": list(record.get("limitations") or []),
                    },
                })
                evidence.append({
                    "source": "network_scanner",
                    "collector": f"network:{record.get('protocol') or 'TLS'}",
                    "evidence_type": str(record.get("evidence_type") or "UNKNOWN").upper(),
                    "target": f"network:{endpoint}",
                    "layer": "NETWORK_TRANSPORT",
                    "observed_at": _iso(record.get("observed_at")),
                    "facts": {
                        "protocol": record.get("protocol"),
                        "tls_version": record.get("tls_version"),
                        "cipher_suite": record.get("cipher_suite"),
                        "decomposition": record.get("decomposition") or {},
                        "certificate_fingerprint_sha256": (record.get("certificate") or {}).get("fingerprint_sha256"),
                        "mutual_tls": record.get("mutual_tls"),
                        "policy_issues": list(record.get("policy_issues") or []),
                        "network_evidence_id": record.get("evidence_id"),
                        "layer_note": "network transport crypto is not application crypto",
                    },
                })
    expected = runs
    return {
        "plane": "NETWORK",
        "expected": expected,
        "collected": len({asset["ref"] for asset in assets}),
        "assets": assets,
        "evidence": evidence,
        "note": None if runs else "no network observation run is stored (NOT_OBSERVED, not 'no crypto')",
    }


def collect_runtime(db: Any, *, limit: int = 5) -> dict[str, Any]:
    """Read stored runtime crypto events; attribution level is preserved verbatim."""
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import current_tenant

    rows = ScanRunRepository(db).list_runs(limit=limit, target_kind="runtime-crypto", owner=current_tenant())
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    seen_assets: set[str] = set()
    seen_events: set[str] = set()
    events_total = 0
    for row in rows:
        result = _result_dict(row).get("result") or {}
        for event in result.get("runtime_events") or []:
            events_total += 1
            event_id = str(event.get("event_id") or "")
            if event_id and event_id in seen_events:
                continue
            seen_events.add(event_id)
            identity = event.get("identity") or {}
            label = (identity.get("application") or identity.get("executable")
                     or identity.get("executable_digest") or event.get("process") or "")
            host = identity.get("host") or event.get("host")
            if not label:
                continue
            ref = f"runtime:{host or 'unknown-host'}:{label}"
            if ref not in seen_assets:
                seen_assets.add(ref)
                assets.append({
                    "ref": ref,
                    "type": "APPLICATION",
                    "name": str(label),
                    "identity": {"application": str(label)},
                    "location": _iso(host),
                    "source": "runtime_agent",
                    "attributes": {"attribution_level": event.get("attribution_level")},
                })
            evidence.append({
                "source": "runtime_agent",
                "collector": "runtime:crypto-events",
                "evidence_type": "RUNTIME_OBSERVED",
                "target": ref,
                "layer": "APPLICATION",
                "observed_at": _iso(event.get("observed_at")),
                "facts": {
                    "operation": event.get("operation"),
                    "algorithm": event.get("algorithm"),
                    "key_size": event.get("key_size"),
                    "decomposition": event.get("decomposition") or {},
                    "attribution_level": event.get("attribution_level"),
                    "runtime_event_id": event_id or None,
                    "layer_note": (
                        "runtime observation of this process only; level "
                        f"{event.get('attribution_level') or 6} means attribution is "
                        f"{'unresolved' if (event.get('attribution_level') or 6) >= 5 else 'resolved'}"
                    ),
                },
            })
    return {
        "plane": "RUNTIME",
        "expected": events_total,
        "collected": len(evidence),
        "assets": assets,
        "evidence": evidence,
        "note": None if events_total else "no runtime crypto event is stored (NOT_OBSERVED, not 'no crypto')",
    }


def collect_static(db: Any, *, page_size: int = 500) -> dict[str, Any]:
    """Read the static crypto asset inventory (algorithm present in code)."""
    from db.repositories.asset_repository import AssetRepository

    repository = AssetRepository(db)
    rows, total = repository.list_assets(page=1, page_size=page_size)
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for row in rows:
        asset_id = str(getattr(row, "id", "") or getattr(row, "asset_key", "") or "")
        file_path = str(getattr(row, "file_path", "") or "")
        name = asset_id or file_path or "static-crypto-asset"
        ref = f"static:{name}"
        assets.append({
            "ref": ref,
            "type": "LIBRARY" if getattr(row, "libraries", None) else "APPLICATION",
            "name": name,
            "identity": {"name": name},
            "location": file_path or None,
            "owner": getattr(row, "owner", None),
            "source": "static_scanner",
            "attributes": {"algorithm": getattr(row, "algorithm", None), "file_path": file_path},
        })
        evidence.append({
            "source": "static_scanner",
            "collector": "static:crypto-assets",
            "evidence_type": "STATIC_OBSERVED",
            "target": ref,
            "layer": "APPLICATION",
            "observed_at": _iso(getattr(row, "created_at", None)),
            "facts": {
                "algorithm": getattr(row, "algorithm", None),
                "key_size": getattr(row, "key_size", None),
                "mode": getattr(row, "mode", None),
                "purpose": getattr(row, "purpose", None),
                "confidence": getattr(row, "confidence", None),
                "file_path": file_path,
                "usage_state_hint": "STATIC_PRESENCE_ONLY",
                "layer_note": "a static hit proves the algorithm is present in code, not that it is used at runtime",
            },
        })
    status_note = None
    if total and len(rows) < total:
        status_note = f"read {len(rows)} of {int(total)} static assets (page limit)"
    return {
        "plane": "STATIC",
        "expected": int(total),
        "collected": len(rows),
        "assets": assets,
        "evidence": evidence,
        "note": status_note,
    }


def collect_pki(db: Any, *, limit: int = 2000) -> dict[str, Any]:
    """Certificate inventory — public metadata only."""
    from db.repositories.certificate_repository import CertificateRepository

    rows = CertificateRepository(db).list_all()
    rows = rows[:limit]
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for row in rows:
        fingerprint = str(getattr(row, "fingerprint_sha256", "") or "")
        subject = str(getattr(row, "subject", "") or fingerprint or "certificate")
        ref = f"pki:{fingerprint or subject}"
        assets.append({
            "ref": ref,
            "type": "CERTIFICATE",
            "name": subject,
            "identity": {"fingerprint_sha256": fingerprint} if fingerprint else {"name": subject},
            "owner": getattr(row, "owner", None),
            "location": getattr(row, "issuer", None),
            "source": "pki_inventory",
            "attributes": {
                "issuer": getattr(row, "issuer", None),
                "not_after": _iso(getattr(row, "not_after", None)),
                "expiry_status": getattr(row, "expiry_status", None),
            },
        })
        evidence.append({
            "source": "pki_inventory",
            "collector": "pki:certificates",
            "evidence_type": "CERTIFICATE_OBSERVED",
            "target": ref,
            "layer": "PLATFORM",
            "observed_at": _iso(getattr(row, "updated_at", None) or getattr(row, "created_at", None)),
            "facts": {
                "subject": subject,
                "issuer": getattr(row, "issuer", None),
                "public_key_algorithm": getattr(row, "public_key_algorithm", None),
                "public_key_size": getattr(row, "public_key_size", None),
                "not_after": _iso(getattr(row, "not_after", None)),
                "days_until_expiry": getattr(row, "days_until_expiry", None),
                "expiry_status": getattr(row, "expiry_status", None),
                "is_self_signed": bool(getattr(row, "is_self_signed", False)),
                "fingerprint_sha256": fingerprint or None,
                "layer_note": "certificate metadata only — no private key material is read or stored",
            },
        })
    return {
        "plane": "PKI",
        "expected": len(rows),
        "collected": len(evidence),
        "assets": assets,
        "evidence": evidence,
        "note": None,
    }


def collect_hardware(db: Any, *, limit: int = 2000) -> dict[str, Any]:
    """Hardware/host crypto capability inventory — metadata only, HSM contents UNKNOWN."""
    from db.repositories.hardware_repository import HardwareRepository

    rows = HardwareRepository(db).list_assets()[:limit]
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for row in rows:
        asset_key = str(getattr(row, "asset_id", "") or "")
        vendor = str(getattr(row, "manufacturer", "") or "")
        model = str(getattr(row, "model", "") or "")
        name = asset_key or f"{vendor}:{model}" or "hardware"
        ref = f"hardware:{name}"
        hsm = getattr(row, "hsm", None) or {}
        assets.append({
            "ref": ref,
            "type": "HSM" if hsm else "HARDWARE",
            "name": name,
            "identity": {"asset_id": asset_key} if asset_key else {"name": name},
            "location": _iso(getattr(row, "agent_id", None)),
            "source": "hardware_inventory",
            "attributes": {"vendor": vendor, "model": model, "device_type": getattr(row, "device_type", None)},
        })
        evidence.append({
            "source": "hardware_inventory",
            "collector": "hardware:capabilities",
            "evidence_type": "CONFIGURED",
            "target": ref,
            "layer": "HSM" if hsm else "PLATFORM",
            "observed_at": _iso(getattr(row, "last_crypto_check", None) or getattr(row, "last_seen", None)),
            "facts": {
                "vendor": vendor,
                "model": model,
                "crypto_capabilities": getattr(row, "crypto_capabilities", None) or {},
                "tpm": getattr(row, "tpm", None) or {},
                "hsm_metadata": hsm,
                "usage_state_hint": "SUPPORTED",
                "layer_note": (
                    "a capability inventory says the device supports an algorithm; what the HSM actually "
                    "holds and uses remains UNKNOWN (metadata-only by policy)"
                ),
            },
        })
    return {
        "plane": "HARDWARE",
        "expected": len(rows),
        "collected": len(evidence),
        "assets": assets,
        "evidence": evidence,
        "note": None,
    }


def collect_vendor(db: Any, *, limit: int = 2000) -> dict[str, Any]:
    """Vendor-declared crypto — capability only, never bank usage."""
    from sqlalchemy import select

    from db.models.vendor_crypto import VendorCryptoInventory

    # VendorCryptoInventory is tenant-scoped: the tenancy mixin applies the
    # tenant predicate, so this read never crosses a tenant boundary.
    rows = list(db.execute(select(VendorCryptoInventory)).scalars())[:limit]
    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for row in rows:
        vendor_id = str(getattr(row, "vendor_id", "") or "")
        if not vendor_id:
            continue
        ref = f"vendor:{vendor_id}"
        if not any(asset["ref"] == ref for asset in assets):
            assets.append({
                "ref": ref,
                "type": "VENDOR",
                "name": vendor_id,
                "identity": {"vendor_id": vendor_id},
                "source": "vendor_intel",
                "attributes": {"discovery_method": getattr(row, "discovery_method", None)},
            })
        evidence.append({
            "source": "vendor_intel",
            "collector": "vendor:declarations",
            "evidence_type": "VENDOR_DECLARED",
            "target": ref,
            "layer": "APPLICATION",
            "observed_at": _iso(getattr(row, "discovered_at", None)),
            "facts": {
                "algorithm": getattr(row, "algorithm", None),
                "key_size": getattr(row, "key_size", None),
                "mode": getattr(row, "mode", None),
                "key_management": getattr(row, "key_management", None),
                "pqc_ready": bool(getattr(row, "pqc_ready", False)),
                "use_case": getattr(row, "crypto_use_case", None),
                "usage_state_hint": "SUPPORTED_ONLY",
                "layer_note": "vendor-declared capability is not evidence that this bank uses it",
            },
        })
    return {
        "plane": "VENDOR",
        "expected": len(rows),
        "collected": len(evidence),
        "assets": assets,
        "evidence": evidence,
        "note": None,
    }


def collect_kms_plane(db: Any, **kwargs: Any) -> dict[str, Any]:
    """Adapter for :mod:`api.estate_kms` (audit-trail usage, read-only)."""
    from api.estate_kms import collect_kms_usage

    return collect_kms_usage(db, **kwargs)


def collect_hsm_plane(db: Any, **kwargs: Any) -> dict[str, Any]:
    """Adapter for :mod:`api.hsm_usage` (KMIP read-only)."""
    from api.hsm_usage import collect_hsm_usage

    return collect_hsm_usage(db, **kwargs)


def collect_cmdb_plane(db: Any, **kwargs: Any) -> dict[str, Any]:
    """Adapter for :mod:`api.estate_cmdb` (live, read-only ServiceNow Table API)."""
    from api.estate_cmdb import collect_cmdb

    return collect_cmdb(db, **kwargs)


def collect_cloud_plane(db: Any, **kwargs: Any) -> dict[str, Any]:
    """Adapter for :mod:`api.estate_cloud` (live, read-only cloud control plane)."""
    from api.estate_cloud import collect_cloud

    return collect_cloud(db, **kwargs)


def collect_kubernetes_plane(db: Any, **kwargs: Any) -> dict[str, Any]:
    """Adapter for :mod:`api.estate_kubernetes` (live, read-only cluster API)."""
    from api.estate_kubernetes import collect_kubernetes

    return collect_kubernetes(db, **kwargs)


DEFAULT_COLLECTORS: dict[str, Callable[..., dict[str, Any]]] = {
    "NETWORK": collect_network,
    "CLOUD": collect_cloud_plane,
    "CMDB": collect_cmdb_plane,
    "KMS": collect_kms_plane,
    "HSM": collect_hsm_plane,
    "KUBERNETES": collect_kubernetes_plane,
    "RUNTIME": collect_runtime,
    "STATIC": collect_static,
    "PKI": collect_pki,
    "HARDWARE": collect_hardware,
    "VENDOR": collect_vendor,
}


# --------------------------------------------------------------------------- #
# job execution
# --------------------------------------------------------------------------- #
def plan(*, planes: Iterable[str] | None = None) -> dict[str, Any]:
    """Which planes will run, from which source, and what each one cannot see."""
    requested = [str(item).upper() for item in (planes or PLANES)]
    unknown = [item for item in requested if item not in PLANES]
    if unknown:
        raise ValueError(f"unknown plane(s) {', '.join(sorted(unknown))}; expected a subset of {', '.join(PLANES)}")
    rows = [
        {
            "plane": plane,
            **PLANE_DETAIL[plane],
            "enabled": plane in requested,
            "status": "PLANNED" if plane in requested else "NOT_ATTEMPTED",
            "impact": None if plane in requested else (
                f"{plane} was not requested, so its estate is NOT_OBSERVED and "
                f"{PLANE_DETAIL[plane]['boms']} are incomplete"
            ),
        }
        for plane in PLANES
    ]
    return {
        "model": "cryptoscan.estate-collector-plan/1",
        "planes": rows,
        "enabled": [row["plane"] for row in rows if row["enabled"]],
        "skipped": [row["plane"] for row in rows if not row["enabled"]],
        "note": "active observation keeps its own approved scope; this job only joins what was already collected",
    }


def _collect(plane: str, collector: Callable[..., dict[str, Any]], db: Any, **kwargs: Any) -> dict[str, Any]:
    """Run one collector; a raise becomes FAILED with its impact, never an empty plane.

    "No credentials for this source" is different from "the source failed": an
    unconfigured live collector is ``NOT_ATTEMPTED`` (nothing was asked), while a
    configured source that errors is ``FAILED``.
    """
    from api.estate_planes import PlaneNotConfigured

    try:
        result = collector(db, **kwargs) or {}
    except PlaneNotConfigured as exc:
        return {
            "plane": plane,
            "status": "NOT_ATTEMPTED",
            "expected": 0,
            "collected": 0,
            "assets": [],
            "evidence": [],
            "reason": str(exc),
            "impact": (
                f"{plane} was not attempted because this deployment has no credentials for it: its estate is "
                f"NOT_OBSERVED and {PLANE_DETAIL[plane]['boms']} are incomplete"
            ),
        }
    except Exception as exc:  # noqa: BLE001 - a plane failure must be reported, not raised
        return {
            "plane": plane,
            "status": "FAILED",
            "expected": 0,
            "collected": 0,
            "assets": [],
            "evidence": [],
            "reason": f"{type(exc).__name__}: {exc}",
            "impact": (
                f"{plane} could not be read, so its inventory is UNKNOWN: "
                f"{PLANE_DETAIL[plane]['boms']} are incomplete and no absence of crypto may be inferred"
            ),
        }
    expected = int(result.get("expected") or 0)
    collected = int(result.get("collected") or 0)
    if expected and collected >= expected:
        status = "COMPLETE"
    elif collected:
        status = "PARTIAL"
    elif expected:
        status = "PARTIAL"
    else:
        status = "COMPLETE"
    return {
        "plane": plane,
        "status": status,
        "expected": expected,
        "collected": collected,
        "assets": list(result.get("assets") or []),
        "evidence": list(result.get("evidence") or []),
        "relationships": list(result.get("relationships") or []),
        "reason": result.get("note") if status == "PARTIAL" else None,
        "note": result.get("note"),
        "impact": (
            None if status == "COMPLETE" else (
                f"{plane} is PARTIAL: {collected} of {expected} targets were collected, so the remainder is "
                f"NOT_OBSERVED and {PLANE_DETAIL[plane]['boms']} under-report"
            )
        ),
    }


def run(
    db: Any,
    *,
    estate: str = "default",
    scope: str | None = None,
    planes: Iterable[str] | None = None,
    collectors: Mapping[str, Callable[..., dict[str, Any]]] | None = None,
    persist: bool = True,
    include_boms: bool = True,
    on_event: Callable[[str, Mapping[str, Any]], Any] | None = None,
    trigger: str = "manual",
    previous: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Discover the estate once and project every BOM from the same snapshot.

    ``collectors`` replaces the adapter registry entirely when supplied (the
    default registry is the six database adapters). A plane with no registered
    adapter is reported ``NOT_ATTEMPTED`` rather than silently skipped, so a
    deployment that overrides the registry cannot accidentally claim coverage it
    never had.

    ``on_event(event_type, payload)`` makes the run observable while it runs —
    the daemon and the API pass an :class:`api.estate_events.EventSink`. It is
    optional on purpose: a scan must behave identically with no subscriber, and
    the sink never raises into the run (a dead feed cannot fail a scan).
    ``trigger`` records what started the run (``manual``, ``schedule``).

    ``previous`` is the previous discovery report; when given, this run is
    compared with it (``api.estate_watch``) and a ``CRITICAL``/``WARNING`` change
    is published as ``estate.change.detected``. A 24/7 product detects change on
    every run — asking an operator to open a drift endpoint is not monitoring.
    Without ``previous`` the report says ``NO_BASELINE`` rather than claiming
    nothing moved.
    """
    emitted: list[tuple[str, dict[str, Any]]] = []

    def emit(event_type: str, payload: Mapping[str, Any]) -> None:
        body = dict(payload)
        emitted.append((event_type, body))
        if on_event is not None:
            on_event(event_type, body)

    moment = datetime.now(timezone.utc)
    collection_plan = plan(planes=planes)
    enabled = collection_plan["enabled"]
    emit("estate.run.started", {
        "estate": estate,
        "scope": scope,
        "planes": list(enabled),
        "skipped_planes": list(collection_plan["skipped"]),
        "trigger": trigger,
        "started_at": moment.isoformat(),
    })
    registry = dict(collectors) if collectors is not None else dict(DEFAULT_COLLECTORS)
    lifecycle: list[dict[str, Any]] = [
        {"phase": "SCOPE_RESOLVED", "status": "COMPLETE",
         "detail": f"estate={estate} scope={scope or 'unspecified'}; {len(enabled)} plane(s) planned"},
        {"phase": "COLLECTORS_PLANNED", "status": "COMPLETE", "detail": collection_plan["enabled"]},
    ]

    outcomes: list[dict[str, Any]] = []
    plane_results: dict[str, dict[str, Any]] = {}
    for plane in enabled:
        collector = registry.get(plane)
        if collector is None:
            outcomes.append(collector_outcome(
                plane, "NOT_ATTEMPTED",
                impact=f"no adapter is registered for {plane}: its estate is NOT_OBSERVED"))
            lifecycle.append({"phase": f"COLLECT:{plane}", "status": "NOT_ATTEMPTED",
                              "detail": "no adapter registered"})
            emit("estate.plane.finished", {
                "estate": estate,
                "plane": plane,
                "status": "NOT_ATTEMPTED",
                "expected": 0,
                "collected": 0,
                "reason": "no adapter registered",
                "impact": f"no adapter is registered for {plane}: its estate is NOT_OBSERVED",
                "at": datetime.now(timezone.utc).isoformat(),
            })
            continue
        outcome = _collect(plane, collector, db)
        plane_results[plane] = outcome
        outcomes.append(collector_outcome(
            plane,
            outcome["status"],
            expected=outcome.get("expected", 0),
            collected=outcome.get("collected", 0),
            reason=outcome.get("reason") or outcome.get("note"),
            impact=outcome.get("impact"),
        ))
        lifecycle.append({
            "phase": f"COLLECT:{plane}",
            "status": outcome["status"],
            "detail": outcome.get("reason") or outcome.get("note") or "collected",
        })
        emit("estate.plane.finished", {
            "estate": estate,
            "plane": plane,
            "status": outcome["status"],
            "expected": outcome.get("expected"),
            "collected": outcome.get("collected"),
            "reason": outcome.get("reason"),
            "impact": outcome.get("impact"),
            "at": datetime.now(timezone.utc).isoformat(),
        })
    for plane in collection_plan["skipped"]:
        outcomes.append(collector_outcome(
            plane, "NOT_ATTEMPTED",
            impact=f"{plane} was not requested: its estate is NOT_OBSERVED and its BOM section is incomplete"))

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for result in plane_results.values():
        assets.extend(result.get("assets") or [])
        evidence.extend(result.get("evidence") or [])
        relationships.extend(result.get("relationships") or [])

    coverage_rows = [
        {
            "target": outcome["plane"],
            "expected": outcome["expected"],
            "collected": outcome["collected"],
            "status": outcome["status"],
            "reason": outcome.get("reason"),
            "impact": outcome.get("impact"),
            "note": f"source: {PLANE_DETAIL[outcome['plane']]['source']}",
        }
        for outcome in (item for item in outcomes if item["plane"] in PLANES)
    ]

    payload = {
        "estate": estate,
        "scope": scope,
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "collectors": outcomes,
        "coverage": coverage_rows,
    }
    try:
        graph = build_graph(payload)
    except Exception as exc:  # noqa: BLE001 — announce the failure, then let it propagate
        emit("estate.run.failed", {
            "estate": estate,
            "scope": scope,
            "stage": "GRAPH",
            "error": f"{type(exc).__name__}: {exc}",
            "planes_read": [outcome["plane"] for outcome in outcomes],
            "at": datetime.now(timezone.utc).isoformat(),
        })
        raise
    emit("estate.phase.finished", {
        "estate": estate, "phase": "EVIDENCE_COLLECTED", "status": "COMPLETE",
        "detail": {"assets": len(assets), "evidence": len(evidence), "relationships": len(relationships)},
    })
    lifecycle.extend([
        {"phase": "EVIDENCE_COLLECTED", "status": "COMPLETE",
         "detail": {"assets": len(assets), "evidence": len(evidence), "relationships": len(relationships)}},
        {"phase": "NORMALIZED", "status": "COMPLETE", "detail": graph.summary().get("assets")},
        {"phase": "IDENTITY_RESOLVED", "status": "COMPLETE",
         "detail": {"merged_identities": len(graph.merged_identities())}},
        {"phase": "CORRELATED", "status": "COMPLETE",
         "detail": {"relationships": graph.summary().get("relationships"),
                    "unresolved": len(graph.unresolved_relationships())}},
        {"phase": "EVIDENCE_VALIDATED", "status": "COMPLETE",
         "detail": {"conflicts": len(graph.conflicts())}},
        {"phase": "COVERAGE_ASSESSED", "status": "COMPLETE",
         "detail": graph.coverage()["summary"]},
    ])

    projections = graph.project_all() if include_boms else None
    if include_boms:
        lifecycle.append({"phase": "BOMS_PROJECTED", "status": "COMPLETE",
                          "detail": projections["counts"] if projections else None})
    emit("estate.phase.finished", {
        "estate": estate,
        "phase": "BOMS_PROJECTED" if include_boms else "CORRELATED",
        "status": "COMPLETE",
        "projection_id": graph.fingerprint(),
        "bom_counts": (projections or {}).get("counts"),
        "coverage": graph.coverage()["summary"],
        "at": datetime.now(timezone.utc).isoformat(),
    })

    change: dict[str, Any] | None = None
    if projections:
        # A stored run must be comparable with the next one. The full BOMs are a
        # response object and would double the row size, so store the component
        # identity (bom_ref) each projection produced: enough to diff the estate
        # across runs, nothing more.
        payload["boms"] = {
            kind: {"components": [
                {"bom_ref": component.get("bom_ref"), "name": component.get("name")}
                for component in (bom.get("components") or [])[:MAX_STORED_BOM_COMPONENTS]
            ]}
            for kind, bom in projections["boms"].items()
        }

    from api import estate_watch

    change = estate_watch.compare_reports(previous, {
        "estate": estate,
        "scope": scope,
        "run_id": None,
        "projection_id": graph.fingerprint(),
        "summary": graph.summary(),
        "coverage": coverage_rows,
        "boms": payload.get("boms") or {},
        "collectors": outcomes,
    })
    payload["change"] = change

    run_id = None
    if persist:
        from db.repositories.scan_run_repository import ScanRunRepository

        row = ScanRunRepository(db).create_run(
            {
                "estate_discovery": payload,
                "estate_summary": graph.summary(),
                "coverage": graph.coverage(),
                "collector_plan": collection_plan,
                "lifecycle": lifecycle,
            },
            target_kind="estate-discovery",
        )
        db.commit()
        run_id = row.id

    # -- live change detection ------------------------------------------------ #
    # Change detection is a consequence of observing, not a button: the twin-level
    # detector turns this run and the one before it into named claims ("Payment API
    # AES-256-GCM: OBSERVED -> SUPPORTED"), ranks the consequence, and appends it to
    # the feed. It never raises into the run — a broken feed must not cost a scan —
    # and it stores nothing when the two observations are identical.
    detection: dict[str, Any] | None = None
    detection_error: str | None = None
    try:
        from api import estate_change_feed
        from db.tenancy import current_tenant

        before_graph = build_graph(previous) if previous else None
        detection = estate_change_feed.observe(
            db,
            before_graph,
            graph,
            tenant_id=current_tenant(),
            run_id=run_id,
            trigger=trigger,
        )
        payload["change_detail"] = {
            "verdict": detection["verdict"],
            "severity": detection["severity"],
            "headline": detection["headline"],
            "counts": detection["counts"],
            "event_id": (detection.get("recorded") or {}).get("event_id"),
            "stored": bool((detection.get("recorded") or {}).get("created")),
            "announced": (detection.get("announced") or {}).get("event_types"),
        }
    except Exception as exc:  # noqa: BLE001 — detection must never fail a scan
        detection_error = f"{type(exc).__name__}: {exc}"
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            try:
                rollback()
            except Exception:  # noqa: BLE001 — a failed rollback cannot fail the scan either
                pass

    if detection_error:
        payload["change_detail"] = {"error": detection_error}

    # -- durable catalogue ---------------------------------------------------- #
    # The twin's memory: materialise this observation into the asset / relationship /
    # crypto records so "when did we first see this" and "is this stale or gone" are
    # answerable later. Best-effort for the same reason as detection: the observation
    # already happened, and a catalogue failure must not erase it.
    catalog: dict[str, Any] | None = None
    catalog_error: str | None = None
    history: dict[str, Any] | None = None
    history_error: str | None = None

    def _guard() -> None:
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            try:
                rollback()
            except Exception:  # noqa: BLE001
                pass

    try:
        from api import estate_catalog
        from db.tenancy import current_tenant

        catalog = estate_catalog.sync(db, graph, tenant_id=current_tenant(), run_id=run_id)
    except Exception as exc:  # noqa: BLE001 — a catalogue write cannot fail the scan
        catalog_error = f"{type(exc).__name__}: {exc}"
        _guard()

    # The record of what each fact *said* — the catalogue's observation_count can say an
    # asset was seen 40 times and cannot say its algorithm changed on the 31st. Separate
    # guard, so a history write failing does not discard a good catalogue.
    try:
        from api import estate_observations
        from db.tenancy import current_tenant

        history = estate_observations.sync_all(db, graph, tenant_id=current_tenant())
    except Exception as exc:  # noqa: BLE001 — history is a record, not a gate
        history_error = f"{type(exc).__name__}: {exc}"
        _guard()

    failed = [item["plane"] for item in outcomes if item["status"] == "FAILED"]
    partial = [item["plane"] for item in outcomes if item["status"] == "PARTIAL"]
    skipped = collection_plan["skipped"]
    # a plane that was requested but had no adapter is coverage debt, not a skip
    not_attempted = [item["plane"] for item in outcomes
                     if item["status"] == "NOT_ATTEMPTED" and item["plane"] not in skipped]
    unanswered = failed + partial + not_attempted
    report: dict[str, Any] = {
        "model": MODEL,
        "run_id": run_id,
        "estate": estate,
        "scope": scope,
        "projection_id": graph.fingerprint(),
        "collector_plan": collection_plan,
        "collectors": outcomes,
        "lifecycle": lifecycle,
        "summary": graph.summary(),
        "coverage": graph.coverage(),
        "unknown": graph.unknown_inventory(),
        "unknown_workflow": graph.unknown_workflow(),
        "pqc": graph.pqc_readiness(),
        "conflicts": graph.conflicts(),
        "unresolved_relationships": graph.unresolved_relationships(),
        "merged_identities": graph.merged_identities(),
        "failed_planes": failed,
        "partial_planes": partial,
        "skipped_planes": skipped,
        "not_attempted_planes": not_attempted,
        "coverage_gaps": unanswered,
        "verdict": "PARTIAL_COVERAGE" if unanswered else "COMPLETE",
        "verdict_detail": (
            f"{len(unanswered)} requested plane(s) are FAILED, PARTIAL or NOT_ATTEMPTED: "
            f"{', '.join(unanswered) or 'none'}. "
            f"{len(skipped)} plane(s) were not requested and are NOT_OBSERVED: {', '.join(skipped) or 'none'}"
        ),
        "meaning": (
            "one discovery job, six BOM projections of one evidence graph. Coverage is attempted/expected "
            "targets, never 'percent of crypto discovered'; a FAILED plane is UNKNOWN, not empty"
        ),
        "limitations": sorted({detail["limitation"] for detail in PLANE_DETAIL.values()}) + [
            "the persisted planes read stored evidence; the live planes (NETWORK, CLOUD, KUBERNETES, CMDB, KMS, "
            "HSM) query a system — KMS/HSM report observed *use* from the provider's own audit/usage counters, "
            "the rest read configuration or declarations, never a negotiated session",
            "planes that were not requested or that failed are NOT_OBSERVED — never 'no crypto found'",
            "policy evaluation and PQC scoring are separate endpoints; their absence here is not a pass",
        ],
    }
    if projections is not None:
        report["boms"] = projections["boms"]
        report["bom_counts"] = projections["counts"]
        report["consistency"] = projections["consistency"]
    emit("estate.run.finished", {
        "estate": estate,
        "scope": scope,
        "trigger": trigger,
        "run_id": report["run_id"],
        "projection_id": report["projection_id"],
        "verdict": report["verdict"],
        "verdict_detail": report["verdict_detail"],
        "coverage_state": report["coverage"]["summary"].get("coverage_state"),
        "attempted": report["coverage"]["summary"].get("attempted"),
        "collected": report["coverage"]["summary"].get("collected"),
        "failed_planes": failed,
        "partial_planes": partial,
        "not_attempted_planes": not_attempted,
        "summary": report["summary"],
        "bom_counts": report.get("bom_counts"),
        "duration_seconds": round((datetime.now(timezone.utc) - moment).total_seconds(), 3),
        "at": datetime.now(timezone.utc).isoformat(),
    })
    report["change"] = change
    report["detection"] = detection or ({"error": detection_error} if detection_error else None)
    report["catalog"] = catalog or ({"error": catalog_error} if catalog_error else None)
    report["history"] = history or ({"error": history_error} if history_error else None)
    if change["severity"] in {"WARNING", "CRITICAL"}:
        emit("estate.change.detected", {
            "estate": estate,
            "run_id": report["run_id"],
            "projection_id": report["projection_id"],
            "severity": change["severity"],
            "headline": change["headline"],
            "findings": change["findings"],
            "next_action": change["next_action"],
            "baseline_projection_id": change["baseline_projection_id"],
            "at": datetime.now(timezone.utc).isoformat(),
        })
        if on_event is not None:
            report["events"] = {"emitted": len(emitted), "types": sorted({item[0] for item in emitted})}

    if on_event is not None and "events" not in report:
        # only reported when someone was actually subscribed: a run with no
        # consumer makes no claim about a feed it never published to
        report["events"] = {"emitted": len(emitted), "types": sorted({item[0] for item in emitted})}
    return report


def previous_report(db: Any, *, tenant_id: str | None = None) -> dict[str, Any] | None:
    """The payload of the most recent stored estate run, for change comparison."""
    try:
        from db.repositories.scan_run_repository import ScanRunRepository

        runs = ScanRunRepository(db).list_runs(limit=1, target_kind="estate-discovery", owner=tenant_id)
        if not runs:
            return None
        return (runs[0].result or {}).get("estate_discovery") or None
    except Exception:  # noqa: BLE001 — a missing baseline must not fail a scan
        return None
