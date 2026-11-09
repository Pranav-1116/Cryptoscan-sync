"""OS & Kernel Intelligence repository
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §10).

Persistence for the read-only OS collection: one collection_id groups
one snapshot (identity, capabilities, modules, config flags, storage
facts, trust facts, findings, coverage). Every child row belongs to
exactly one collection; collection rows are never overwritten — a new
collection is a new collection_id (§7 evidence preservation).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.os_intelligence import (
    OSAssetCertificate, OSCoverageRecord, OSCryptoCapability,
    OSConfigFlag, OSFindingRecord,
    OSModuleRecord, OSRuntimeEvent, OSRuntimeSession, OSStorageFact,
    OSTrustFact, OSAsset, OSTwinEdge,
)
from os_intelligence.bom import build_bom
from db.repositories.performance_repository import _aware


class OSIntelligenceRepository:

    def __init__(self, db: Session) -> None:
        self.db = db

    # --- collections -------------------------------------------------

    def record_collection(self, *, tenant_id: str, asset_id: str,
                          inventory: Dict[str, Any],
                          collected_at: Optional[datetime] = None
                          ) -> Dict[str, Any]:
        """Persist one complete OS inventory snapshot.

        `inventory` is the normalized dict from
        os_intelligence.collector.OSInventory.as_dict() (or an
        equivalent signed collection package). Every row is written
        under one fresh collection_id; nothing is merged into or
        overwrites a previous collection."""
        collection_id = f"oscol-{uuid.uuid4().hex[:16]}"
        identity = inventory.get("identity", {})
        coverage = inventory.get("coverage", {})
        now = _aware(collected_at) if collected_at else _aware(
            datetime.now(timezone.utc))

        asset_row = OSAsset(
            tenant_id=tenant_id,
            asset_id=asset_id,
            collection_id=collection_id,
            kernel_name=str(identity.get("kernel_name", "unknown"))[:40],
            kernel_release=str(identity.get("kernel_release",
                                            "unknown"))[:80],
            kernel_version=(identity.get("kernel_version") or None),
            machine=(identity.get("machine") or None),
            os_pretty_name=(identity.get("os_pretty_name") or None),
            os_id=(identity.get("os_id") or None),
            os_version_id=(identity.get("os_version_id") or None),
            arch=(identity.get("arch") or None),
            # Never persist caller-supplied kernel boot arguments: they may
            # contain passwords, tokens or key material, even when the
            # inventory came from an external signed collection package.
            cmdline="withheld (kernel boot parameters may contain secrets)",
            tainted_flags=(identity.get("tainted_flags") or None),
            tainted_meanings=identity.get("tainted_meanings"),
            environment_development_only=bool(
                identity.get("environment_development_only", True)),
            qualification_note=(identity.get("qualification_note")
                                or None),
            collector_version=str(
                inventory.get("collector_version", "unknown"))[:80],
            notes=identity.get("notes"),
            collected_at=now)
        self.db.add(asset_row)

        for entry in inventory.get("crypto_api", []) or []:
            key_range = entry.get("key_size_range")
            self.db.add(OSCryptoCapability(
                tenant_id=tenant_id,
                collection_id=collection_id,
                asset_id=asset_id,
                algorithm=str(entry.get("algorithm", ""))[:120],
                driver=(entry.get("driver") or None),
                implementation_type=(entry.get("type") or None),
                module=(entry.get("module") or None),
                priority=entry.get("priority"),
                blocksize=entry.get("blocksize"),
                digestsize=entry.get("digestsize"),
                min_keysize=(key_range[0] if key_range else None),
                max_keysize=(key_range[1] if key_range else None),
                selftest=(entry.get("selftest") or None),
                hardware_accelerated=entry.get("hardware_accelerated"),
                runtime_usage_confirmed=bool(
                    entry.get("runtime_usage_confirmed", False)),
                parse_notes=entry.get("parse_notes")))

        for mod in inventory.get("modules", []) or []:
            self.db.add(OSModuleRecord(
                tenant_id=tenant_id,
                collection_id=collection_id,
                asset_id=asset_id,
                name=str(mod.get("name", ""))[:120],
                size=mod.get("size"),
                refcount=mod.get("refcount"),
                used_by=mod.get("used_by"),
                state=(mod.get("state") or None)))

        for flag, value in (inventory.get("config_flags", {}) or {}).items():
            self.db.add(OSConfigFlag(
                tenant_id=tenant_id,
                collection_id=collection_id,
                asset_id=asset_id,
                flag=str(flag)[:120],
                value=str(value)[:200],
                explicitly_disabled=(value == "not_set")))

        for fact in inventory.get("storage", []) or []:
            self.db.add(OSStorageFact(
                tenant_id=tenant_id,
                collection_id=collection_id,
                asset_id=asset_id,
                device=str(fact.get("device", ""))[:120],
                fstype=(fact.get("fstype") or None),
                metadata_=fact.get("metadata"),
                notes=fact.get("notes")))

        for fact in inventory.get("hardware_trust", []) or []:
            self.db.add(OSTrustFact(
                tenant_id=tenant_id,
                collection_id=collection_id,
                asset_id=asset_id,
                subject=str(fact.get("subject", ""))[:80],
                state=str(fact.get("state", ""))[:40],
                evidence_class=str(
                    fact.get("evidence_class", "unknown"))[:30],
                metadata_=fact.get("metadata"),
                notes=fact.get("notes")))

        for finding in inventory.get("findings", []) or []:
            self.db.add(OSFindingRecord(
                tenant_id=tenant_id,
                collection_id=collection_id,
                asset_id=asset_id,
                finding_type=str(finding.get("finding_type", ""))[:120],
                subject=(finding.get("host_id") or finding.get("subject")
                         or None),
                algorithm=(finding.get("algorithm") or None),
                implementation=(finding.get("implementation") or None),
                evidence_source=(finding.get("evidence_source") or None),
                observation_type=str(finding.get(
                    "observation_type", "registered_capability"))[:60],
                runtime_usage_confirmed=bool(
                    finding.get("runtime_usage_confirmed", False)),
                evidence_class=str(finding.get(
                    "evidence_class", "unknown"))[:30],
                severity_label=(finding.get("severity_label") or None),
                severity_factors=finding.get("severity_factors"),
                risk_model_version=(finding.get("risk_model_version")
                                    or None),
                details=finding.get("details"),
                limitations=finding.get("limitations")))

        self.db.add(OSCoverageRecord(
            tenant_id=tenant_id,
            collection_id=collection_id,
            asset_id=asset_id,
            sources_attempted=coverage.get("sources_attempted"),
            sources_collected=coverage.get("sources_collected"),
            sources_unavailable=coverage.get("sources_unavailable"),
            source_digests=inventory.get("source_digests"),
            note=(coverage.get("note") or None)))

        # Certificate metadata (OS-CRYPTO-008's source, §7): public
        # attributes only — private key material is NEVER stored.
        cert_seq = 0
        for cert in (inventory.get("certificates") or [])[:2000]:
            self.db.add(OSAssetCertificate(
                tenant_id=tenant_id,
                certificate_id=f"cert-{collection_id}-{cert_seq}",
                collection_id=collection_id,
                asset_id=asset_id,
                subject=str(cert.get("subject") or "unknown"),
                issuer=str(cert.get("issuer") or "unknown"),
                not_before=cert.get("not_before"),
                not_after=cert.get("not_after"),
                thumbprint_sha256=cert.get("thumbprint_sha256"),
                public_key_algorithm=cert.get("public_key_algorithm"),
                public_key_bits=cert.get("public_key_bits"),
                evidence_class=str(cert.get("evidence_class")
                                   or "observed"),
                evidence_source=cert.get("evidence_source"),
                limitations=list(cert.get("limitations") or []),
                collected_at=now,
            ))
            cert_seq += 1

        # Digital-twin edges (§8): derived from the BOM relationships —
        # provides/contains/anchors only, every edge evidence-backed.
        # Same-host co-location never creates an edge.
        edge_seq = 0
        for rel in build_bom("techbom", {
                "host_id": asset_id,
                "identity": inventory.get("identity", {}),
                "crypto_api": inventory.get("crypto_api", []),
                "modules": inventory.get("modules", []),
                "hardware_trust": inventory.get("hardware_trust", []),
                "coverage": coverage}).as_dict()["relationships"]:
            edge_seq += 1
            self.db.add(OSTwinEdge(
                tenant_id=tenant_id,
                edge_id=f"osedg-{uuid.uuid4().hex[:16]}",
                run_id=collection_id,
                asset_id=asset_id,
                source=str(rel["source"])[:160],
                predicate=str(rel["relationship"])[:40],
                target=str(rel["target"])[:160],
                provenance=str(rel["provenance"])[:40],
                evidence_class="observed",
                evidence_source="OS read-only collection (Tier 1, §11)",
                limitations=rel.get("limitations")))

        self.db.commit()
        return {"collection_id": collection_id, "asset_id": asset_id,
                "outcome": "recorded"}

    def record_runtime_session(self, *, tenant_id: str,
                               asset_id: str,
                               session: Dict[str, Any]
                               ) -> Dict[str, Any]:
        """Persist one Tier-2 runtime session and its metadata events
        (spec §3). METADATA ONLY — the event schema has no field for
        plaintext, keys, passwords, tokens or crypto I/O buffers; the
        bounded filter at ingestion refuses those and refusals are
        counted, never drawn as truths."""
        now = datetime.now(timezone.utc)
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            raise ValueError("runtime session requires a session_id")
        existing = self.db.scalar(
            select(OSRuntimeSession).where(
                OSRuntimeSession.tenant_id == tenant_id,
                OSRuntimeSession.session_id == session_id))
        if existing is not None:
            return {"session_id": session_id, "status": "already_recorded",
                    "events_recorded": 0}
        self.db.add(OSRuntimeSession(
            tenant_id=tenant_id,
            session_id=session_id,
            asset_id=asset_id,
            boot_id=session.get("boot_id"),
            collection_profile=str(session.get("collection_profile")
                                   or "tier2-approved-tracepoints"),
            evidence_source=session.get("evidence_source"),
            started_at=session.get("started_at"),
            ended_at=session.get("ended_at"),
            attached_points=list(session.get("attached_points") or []),
            events_accepted=int(session.get("events_accepted") or 0),
            events_lost=int(session.get("events_lost") or 0),
            refusals=list(session.get("refusals") or [])[:1000],
            notes=list(session.get("notes") or []),
            collected_at=now,
        ))
        count = 0
        for i, ev in enumerate(
                (session.get("events") or [])[:50000]):
            self.db.add(OSRuntimeEvent(
                tenant_id=tenant_id,
                session_id=session_id,
                asset_id=asset_id,
                event_id=str(ev.get("event_id") or
                             f"rt-{session_id}-{i}"),
                boot_id=ev.get("boot_id"),
                process_id=ev.get("process_id"),
                process_start_time=ev.get("process_start_time"),
                executable_digest=ev.get("executable_digest"),
                operation_category=str(ev.get("operation_category")
                                       or "unclassified"),
                algorithm_identifier=ev.get("algorithm_identifier"),
                provider_identifier=ev.get("provider_identifier"),
                kernel_or_userspace=ev.get("kernel_or_userspace"),
                interface=ev.get("interface"),
                timestamp=ev.get("timestamp"),
                evidence_source=ev.get("evidence_source"),
                collection_profile=ev.get("collection_profile"),
                collected_at=now,
            ))
            count += 1
        self.db.commit()
        return {"session_id": session_id, "status": "recorded",
                "events_recorded": count}

    def list_runtime_sessions(self, tenant_id: str, asset_id: str
                              ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSRuntimeSession).where(
                OSRuntimeSession.tenant_id == tenant_id,
                OSRuntimeSession.asset_id == asset_id).order_by(
                OSRuntimeSession.collected_at.desc())).all()
        return [{
            "session_id": r.session_id,
            "boot_id": r.boot_id,
            "collection_profile": r.collection_profile,
            "evidence_source": r.evidence_source,
            "started_at": r.started_at,
            "ended_at": r.ended_at,
            "attached_points": list(r.attached_points or []),
            "events_accepted": r.events_accepted,
            "events_lost": r.events_lost,
            "refusals": list(r.refusals or []),
            "notes": list(r.notes or []),
            "collected_at": _aware(r.collected_at).isoformat(),
        } for r in rows]

    def list_runtime_events(self, tenant_id: str, asset_id: str,
                            session_id: str = ""
                            ) -> List[Dict[str, Any]]:
        stmt = select(OSRuntimeEvent).where(
            OSRuntimeEvent.tenant_id == tenant_id,
            OSRuntimeEvent.asset_id == asset_id)
        if session_id:
            stmt = stmt.where(OSRuntimeEvent.session_id == session_id)
        rows = self.db.scalars(stmt.order_by(
            OSRuntimeEvent.collected_at.desc()).limit(2000)).all()
        return [{
            "event_id": r.event_id,
            "session_id": r.session_id,
            "boot_id": r.boot_id,
            "process_id": r.process_id,
            "process_start_time": r.process_start_time,
            "executable_digest": r.executable_digest,
            "operation_category": r.operation_category,
            "algorithm_identifier": r.algorithm_identifier,
            "provider_identifier": r.provider_identifier,
            "kernel_or_userspace": r.kernel_or_userspace,
            "interface": r.interface,
            "timestamp": r.timestamp,
            "evidence_source": r.evidence_source,
            "collection_profile": r.collection_profile,
            "collected_at": _aware(r.collected_at).isoformat(),
        } for r in rows]

    def runtime_usage_confirmations(self, tenant_id: str,
                                    asset_id: str
                                    ) -> List[Dict[str, Any]]:
        """Serve-time usage confirmations derived from recorded
        runtime events. These RAISE runtime_usage_confirmed and never
        overwrite the static registration row (§2.2): each record
        names the confirming events and the observed process
        identity."""
        rows = self.db.scalars(
            select(OSRuntimeEvent).where(
                OSRuntimeEvent.tenant_id == tenant_id,
                OSRuntimeEvent.asset_id == asset_id,
                OSRuntimeEvent.operation_category.in_([
                    "crypto_api_allocation", "algorithm_selection",
                    "key_generation_request",
                    "encrypt_decrypt_operation", "hash_operation",
                    "signature_generate_verify"])).order_by(
            OSRuntimeEvent.collected_at).limit(20000)).all()
        groups: Dict[tuple, Dict[str, Any]] = {}
        for r in rows:
            algorithm = r.algorithm_identifier or ""
            if not algorithm:
                continue
            key = (algorithm, r.provider_identifier or r.interface
                   or "unknown")
            entry = groups.setdefault(key, {
                "algorithm": key[0],
                "implementation": key[1],
                "runtime_usage_confirmed": True,
                "evidence_class": "observed",
                "observed_processes": set(),
                "confirmed_by_events": [],
            })
            if r.process_id or r.executable_digest:
                digest = (f" digest={r.executable_digest}"
                          if r.executable_digest else "")
                entry["observed_processes"].add(
                    f"pid={r.process_id or '?'}{digest}")
            if len(entry["confirmed_by_events"]) < 20:
                entry["confirmed_by_events"].append(r.event_id)
        out = []
        for entry in groups.values():
            entry["observed_processes"] = sorted(
                entry["observed_processes"])
            entry["note"] = (
                "raised ONLY by observed runtime events (§2.2) — the "
                "static registration row is never overwritten; the "
                "confirmation is scoped to the observed process "
                "identity and is never inferred from co-location")
            out.append(entry)
        return out

    def list_certificates(self, tenant_id: str, asset_id: str
                          ) -> List[Dict[str, Any]]:
        """Certificate metadata rows for one asset (§7: public
        attributes only — private key material is never stored).
        Unknown dates stay UNKNOWN — never 'not expired' (§2.1)."""
        rows = self.db.scalars(
            select(OSAssetCertificate).where(
                OSAssetCertificate.tenant_id == tenant_id,
                OSAssetCertificate.asset_id == asset_id).order_by(
                OSAssetCertificate.collected_at.desc())).all()
        return [{
            "certificate_id": r.certificate_id,
            "collection_id": r.collection_id,
            "subject": r.subject,
            "issuer": r.issuer,
            "not_before": r.not_before,
            "not_after": r.not_after,
            "thumbprint_sha256": r.thumbprint_sha256,
            "public_key_algorithm": r.public_key_algorithm,
            "public_key_bits": r.public_key_bits,
            "evidence_class": r.evidence_class,
            "evidence_source": r.evidence_source,
            "limitations": list(r.limitations or []),
            "collected_at": _aware(r.collected_at).isoformat(),
        } for r in rows]

    def list_twin_edges(self, tenant_id: str, collection_id: str
                        ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSTwinEdge).where(
                OSTwinEdge.tenant_id == tenant_id,
                OSTwinEdge.run_id == collection_id)).all()
        return [{
            "edge_id": r.edge_id,
            "asset_id": r.asset_id,
            "source": r.source,
            "predicate": r.predicate,
            "target": r.target,
            "provenance": r.provenance,
            "evidence_class": r.evidence_class,
            "evidence_source": r.evidence_source,
            "limitations": r.limitations or [],
        } for r in rows]

    # --- queries -----------------------------------------------------

    def list_assets(self, tenant_id: str) -> List[Dict[str, Any]]:
        # Retain all snapshots, but the estate view shows one latest snapshot
        # per host. The collection_id still addresses immutable child evidence.
        rows = self.db.scalars(
            select(OSAsset).where(OSAsset.tenant_id == tenant_id)
            .order_by(OSAsset.collected_at.desc(), OSAsset.id.desc())).all()
        latest: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            if row.asset_id not in latest:
                latest[row.asset_id] = self._asset_dict(row)
        return list(latest.values())

    def get_asset(self, tenant_id: str, asset_id: str
                  ) -> Optional[Dict[str, Any]]:
        row = self.db.scalars(
            select(OSAsset).where(OSAsset.tenant_id == tenant_id,
                                  OSAsset.asset_id == asset_id)
            .order_by(OSAsset.collected_at.desc(), OSAsset.id.desc())
            .limit(1)).first()
        return self._asset_dict(row) if row else None

    def latest_collection(self, tenant_id: str, asset_id: str
                          ) -> Optional[str]:
        row = self.db.scalars(
            select(OSAsset).where(OSAsset.tenant_id == tenant_id,
                                  OSAsset.asset_id == asset_id)
            .order_by(OSAsset.collected_at.desc(), OSAsset.id.desc())
            .limit(1)).first()
        return row.collection_id if row else None

    def list_capabilities(self, tenant_id: str, collection_id: str
                          ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSCryptoCapability).where(
                OSCryptoCapability.tenant_id == tenant_id,
                OSCryptoCapability.collection_id == collection_id
            ).order_by(OSCryptoCapability.algorithm)).all()
        return [{
            "algorithm": r.algorithm,
            "driver": r.driver,
            "type": r.implementation_type,
            "module": r.module,
            "priority": r.priority,
            "blocksize": r.blocksize,
            "digestsize": r.digestsize,
            "key_size_range": ([r.min_keysize, r.max_keysize]
                               if r.min_keysize is not None
                               or r.max_keysize is not None else None),
            "selftest": r.selftest,
            "hardware_accelerated": r.hardware_accelerated,
            "runtime_usage_confirmed": r.runtime_usage_confirmed,
            "parse_notes": r.parse_notes,
        } for r in rows]

    def list_modules(self, tenant_id: str, collection_id: str
                     ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSModuleRecord).where(
                OSModuleRecord.tenant_id == tenant_id,
                OSModuleRecord.collection_id == collection_id
            ).order_by(OSModuleRecord.name)).all()
        return [{"name": r.name, "size": r.size, "refcount": r.refcount,
                 "used_by": r.used_by or [], "state": r.state or "unknown"}
                for r in rows]

    def list_config_flags(self, tenant_id: str, collection_id: str
                          ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSConfigFlag).where(
                OSConfigFlag.tenant_id == tenant_id,
                OSConfigFlag.collection_id == collection_id
            ).order_by(OSConfigFlag.flag)).all()
        return [{"flag": r.flag, "value": r.value,
                 "explicitly_disabled": r.explicitly_disabled}
                for r in rows]

    def list_storage(self, tenant_id: str, collection_id: str
                     ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSStorageFact).where(
                OSStorageFact.tenant_id == tenant_id,
                OSStorageFact.collection_id == collection_id)).all()
        return [{"device": r.device, "fstype": r.fstype or "unavailable",
                 "metadata": r.metadata_ or {}, "notes": r.notes or []}
                for r in rows]

    def list_trust(self, tenant_id: str, collection_id: str
                   ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSTrustFact).where(
                OSTrustFact.tenant_id == tenant_id,
                OSTrustFact.collection_id == collection_id)).all()
        return [{"subject": r.subject, "state": r.state,
                 "evidence_class": r.evidence_class,
                 "metadata": r.metadata_ or {}, "notes": r.notes or []}
                for r in rows]

    def list_findings(self, tenant_id: str, collection_id: str
                      ) -> List[Dict[str, Any]]:
        rows = self.db.scalars(
            select(OSFindingRecord).where(
                OSFindingRecord.tenant_id == tenant_id,
                OSFindingRecord.collection_id == collection_id
            ).order_by(OSFindingRecord.finding_type)).all()
        return [{
            "finding_type": r.finding_type,
            "host_id": r.subject,
            "algorithm": r.algorithm or "",
            "implementation": r.implementation or "",
            "evidence_source": r.evidence_source or "",
            "observation_type": r.observation_type,
            "runtime_usage_confirmed": r.runtime_usage_confirmed,
            "evidence_class": r.evidence_class,
            "severity_label": r.severity_label,
            "severity_factors": r.severity_factors,
            "risk_model_version": r.risk_model_version,
            "details": r.details or {},
            "limitations": r.limitations or [],
        } for r in rows]

    def get_coverage(self, tenant_id: str, collection_id: str
                     ) -> Optional[Dict[str, Any]]:
        row = self.db.scalars(
            select(OSCoverageRecord).where(
                OSCoverageRecord.tenant_id == tenant_id,
                OSCoverageRecord.collection_id == collection_id
            ).limit(1)).first()
        if row is None:
            return None
        return {
            "sources_attempted": row.sources_attempted or [],
            "sources_collected": row.sources_collected or [],
            "sources_unavailable": row.sources_unavailable or [],
            "source_digests": row.source_digests or {},
            "note": row.note,
        }

    # --- helpers -----------------------------------------------------

    @staticmethod
    def _asset_dict(r: OSAsset) -> Dict[str, Any]:
        return {
            "asset_id": r.asset_id,
            "collection_id": r.collection_id,
            "kernel_name": r.kernel_name,
            "kernel_release": r.kernel_release,
            "kernel_version": r.kernel_version or "unknown",
            "machine": r.machine or "unknown",
            "os_pretty_name": r.os_pretty_name or "unknown",
            "os_id": r.os_id or "unknown",
            "os_version_id": r.os_version_id or "unknown",
            "arch": r.arch or "unknown",
            "cmdline": r.cmdline or "unavailable",
            "tainted_flags": r.tainted_flags or "0",
            "tainted_meanings": r.tainted_meanings or [],
            "environment_development_only":
                r.environment_development_only,
            "qualification_note": r.qualification_note,
            "collector_version": r.collector_version,
            "notes": r.notes or [],
            "collected_at": r.collected_at.isoformat(),
        }
