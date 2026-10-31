"""Bounded monitor network plans and execution receipts (not plugin discovery).

No executor is constructed during validation/admission. Destination validation
is constrained to qualified TCP CIDRs and the address forms the UDP SDKs use.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import re

from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

from api.security.network_collection import admit_network, checked_hosts, persist_network
from sqlalchemy import select
from db.repositories.job_repository import JobRepository
from db.models.monitor import MonitorTarget
from db.models.tenant import Tenant
from db.tenancy import current_tenant

_ACTIVE = ContextVar("monitor_network_execution", default=None)


class Profile(BaseModel):
    timeout: float = Field(default=5.0, gt=0, le=30, allow_inf_nan=False)
    workers: int = Field(default=8, ge=1, le=32, strict=True)
    expiry_alert_days: int = Field(default=30, ge=0, le=36500)


def _refuse(reason):
    raise HTTPException(422, detail=reason)


def _items(value, name):
    if not isinstance(value, list) or len(value) > 256 or any(not isinstance(v, str) or not v.strip() for v in value):
        _refuse(f"{name} must be a list of at most 256 nonempty strings")
    return list(dict.fromkeys(v.strip() for v in value))


@dataclass
class Plan:
    config: dict
    specs: dict
    units: list

    def admit(self, phase=None, *, execution_range=None):
        if "scope" in self.specs:
            from worker.monitor.scope_discovery import authorize_scopes

            authorize_scopes(
                {**self.config, "scope": [execution_range]} if execution_range is not None else self.config
            )
        decisions = []
        for name, specs in self.specs.items():
            if phase is not None and phase != name:
                continue
            for spec in specs:
                if name == "scope" and execution_range is not None:
                    spec = {**spec, "targets": [execution_range]}
                decision = admit_network(
                    spec["targets"], ports=spec.get("ports"), protocol=spec["protocol"], transport=spec["transport"]
                )
                decisions.append({"phase": name, "purpose": spec["purpose"], "admission": decision})
        if not decisions:
            _refuse("No supported monitor network phase configured")
        return {
            "schema": "cryptoscan.monitor-network-admission/1",
            "checked_targets": len(self.units),
            "phases": decisions,
        }


def prepare(config):
    if any(key in config and config[key] is not True for key in ("live", "persist_run")):
        _refuse("Monitor collection requires live=true and mandatory persistence")
    if config.get("scan_mode") or any(
        config.get(key)
        for key in (
            "sni",
            "starttls",
            "scan_versions",
            "scan_ciphers",
            "check_renegotiation",
            "check_chain_sent",
            "live_revocation",
        )
    ):
        _refuse("Requested mode/extended TLS option is not qualified for this bounded monitor profile")
    if config.get("plugins"):
        raise HTTPException(
            409,
            detail="Monitor discovery plugins are not qualified for bounded phase admission; no monitor probes executed",
        )
    try:
        clean = Profile(**{k: config[k] for k in Profile.model_fields if k in config}).model_dump()
    except ValidationError as exc:
        raise HTTPException(422, detail="Invalid bounded network monitor profile") from exc
    specs, units = {}, []
    if config.get("scope"):
        from worker.monitor.scope_discovery import prepare_scope

        scope_config, scope_spec, scope_units = prepare_scope(config)
        clean.update(scope_config)
        specs["scope"] = [scope_spec]
        units.extend(scope_units)
    elif config.get("scope_profile"):
        _refuse("scope_profile requires a nonempty scope")
    endpoints = _items(config.get("endpoints", []), "endpoints")
    if config.get("endpoint"):
        if endpoints:
            _refuse("Use endpoint or endpoints, not both")
        endpoints = _items([config["endpoint"]], "endpoint")
    if endpoints:
        endpoints = checked_hosts(endpoints)
        clean["endpoints"] = endpoints
        units.extend(endpoints)
        specs["tls"] = [{"targets": endpoints, "protocol": "tls", "transport": "tcp", "purpose": "destination"}]
    hosts = _items(config.get("ipsec", []), "ipsec")
    if hosts:
        raw = str(config.get("ike_ports", "500,4500")).split(",")
        if not 1 <= len(raw) <= 16 or any(not p.strip().isdigit() or not 1 <= int(p) <= 65535 for p in raw):
            _refuse("ike_ports must contain 1-16 valid numeric UDP ports")
        ports = list(dict.fromkeys(int(p) for p in raw))
        if any(":" in h or "[" in h or "]" in h for h in hosts):
            _refuse("IPsec requires bare IPv4/DNS hosts; ports belong in ike_ports; IPv6 SDK form is unqualified")
        hosts = [e.rsplit(":", 1)[0] for e in checked_hosts([f"{h}:{ports[0]}" for h in hosts])]
        clean.update(ipsec=hosts, ike_ports=",".join(map(str, ports)))
        units.extend(hosts)
        specs["ipsec"] = [
            {"targets": hosts, "ports": ports, "protocol": "ike", "transport": "udp", "purpose": "destination"}
        ]
    zones = _items(config.get("dnssec", []), "dnssec")
    if zones:
        zones = list(dict.fromkeys(z.lower().rstrip(".") for z in zones))
        if any(
            len(z) > 253
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", z)
            for z in zones
        ):
            _refuse("Invalid DNSSEC zone label")
        checked_hosts([f"{z}:53" for z in zones])
        resolver = config.get("dns_resolver")
        if not isinstance(resolver, str) or not resolver.strip() or resolver.count(":") > 1 or "[" in resolver:
            _refuse(
                "DNSSEC monitor requires an explicit IPv4/DNS resolver (optional :port); IPv6 resolver SDK form is unqualified"
            )
        resolver = checked_hosts([resolver if ":" in resolver else resolver + ":53"])[0]
        port = int(resolver.rsplit(":", 1)[1])
        transfer = config.get("check_zone_transfer", True)
        if type(transfer) is not bool:
            _refuse("check_zone_transfer must be a boolean")
        clean.update(dnssec=zones, dns_resolver=resolver, check_zone_transfer=transfer)
        units.extend(zones)
        specs["dnssec"] = []
        for transport, protocol in [("udp", "dns")] + ([("tcp", "dns-tcp")] if transfer else []):
            specs["dnssec"].extend(
                [
                    {
                        "targets": [resolver],
                        "protocol": protocol,
                        "transport": transport,
                        "purpose": "resolver-destination",
                    },
                    {
                        "targets": [f"{z}:{port}" for z in zones],
                        "protocol": protocol,
                        "transport": transport,
                        "purpose": "zone-policy-subject",
                    },
                ]
            )
    if not units or len(units) > 256:
        _refuse("Monitor requires 1-256 combined TCP discovery candidates/TLS hosts/IPsec hosts/DNS zones per pass")
    return Plan(clean, specs, units)


class Execution:
    def __init__(self, db, plan, run, target_id):
        self.db, self.plan, self.run, self.target_id = db, plan, run, target_id
        self.receipts, self.result = [], None

    def before_phase(self, phase, *, execution_range=None):
        owner = current_tenant()
        # populate_existing=True is deliberate: this re-read exists to detect a
        # concurrent change of owner or target authority, so it must bypass the
        # identity map. It must not bypass the tenant filter, which is why the
        # load is a filtered SELECT rather than db.get().
        target = self.db.execute(
            select(MonitorTarget)
            .where(MonitorTarget.id == self.target_id)
            .execution_options(populate_existing=True)
        ).scalars().first()
        tenant = self.db.get(Tenant, owner, populate_existing=True) if owner is not None else None
        if (
            target is None
            or target.tenant_id != owner
            or not target.enabled
            or owner is not None
            and (tenant is None or tenant.status != "ACTIVE")
        ):
            raise HTTPException(409, detail="Monitor owner/target authority changed before phase execution")
        if prepare(dict(target.config or {})).config != self.plan.config:
            raise HTTPException(
                409, detail="Monitor profile changed before phase execution; retry from current configuration"
            )
        if execution_range is not None and (
            phase != "scope" or execution_range not in self.plan.config.get("scope", [])
        ):
            raise RuntimeError("Scope execution range was not admitted")
        receipt = self.plan.admit(phase, execution_range=execution_range)
        if execution_range is not None:
            receipt["execution_range"] = execution_range
        self.receipts.append(receipt)
        repo = JobRepository(self.db)
        job = repo.get_by_id(self.run.job_id)
        progress = {**(job.progress or {}), "phase_admission": list(self.receipts)}
        if repo.update_status(job.id, "RUNNING", progress=progress) is None:
            raise RuntimeError("Monitor phase receipt was refused")
        # No result/projection writes exist yet: only bounded job progress.
        self.db.commit()

    def persist(self, result):
        payload = dict(result.get("data") or {})
        complete = result.get("observation_complete") is True
        phase_telemetry = {
            "tls": payload.get("probe_telemetry") or {},
            "ipsec": (payload.get("ipsec") or {}).get("probe_telemetry") or {},
            "dnssec": {"coverage": "NOT_ESTABLISHED"} if "dnssec" in self.plan.specs else {},
            "scope": {"coverage": "TCP_CONNECT_ONLY_TLS_NOT_EVALUATED"} if "scope" in self.plan.specs else {},
        }
        payload["monitor"] = {
            "target_id": self.target_id,
            "observation_complete": complete,
            "phase_telemetry": phase_telemetry,
        }
        if set(self.plan.specs) != {"tls"}:
            # Do not present one TLS subphase's counts/verdict as full mixed
            # coverage, or fabricate TLS counts for a UDP-only collection.
            payload["probe_telemetry"] = {"status": "OK" if complete and not result.get("degraded") else "PARTIAL"}
            if set(self.plan.specs) == {"scope"}:
                payload["probe_telemetry"] = {"status": "NOT_EVALUATED"}
        self.result = persist_network(self.db, payload, self.run, kind="monitor", phase_admission=list(self.receipts))
        result["data"] = self.result
        result["summary"] = {
            **(result.get("summary") or {}),
            "job_id": self.run.job_id,
            "run_id": self.result["run_id"],
        }


@contextmanager
def executing(execution):
    token = _ACTIVE.set(execution)
    try:
        yield execution
    finally:
        _ACTIVE.reset(token)


def before_phase(phase):
    execution = _ACTIVE.get()
    if execution is not None:
        execution.before_phase(phase)
    return execution


def current_execution():
    """Internal adapter hook; a bounded scope cannot execute without this context."""
    return _ACTIVE.get()
