"""Hash-covered, two-human associations over existing six-BOM identities.

Uses the existing bom_relationship history, never creates inventory or operational
edges. Every read revalidates the full imported host closure and target identity.
"""

import json
from datetime import datetime, timedelta
from urllib.parse import quote
from fastapi import HTTPException
from db.models.assurance import AssuranceRevision, CollectionPhaseReceipt
from db.models.base import utcnow
from db.models.hardware_live import HardwareAsset
from db.models.scan_job import ScanJob
from db.models.software_supply_chain import SoftwareArtifact, SoftwareDeployment, ReleaseSbomBinding
from db.models.vendor import Vendor
from db.models.system import System
from db.repositories.execution_control import aware, required
from db.models.user import AuditLog
from db.repositories.user_repository import UserRepository, audit_entry_hash
from shared_models.host_associations import SCHEMA, GRAPH_SCHEMA, DOMAINS
from shared_models.host_collection import digest
from shared_models.software_identity import package_identity as normalize_package
from . import store, relationships

MODELS = {
    "sbom_binding": ReleaseSbomBinding,
    "phase_receipt": CollectionPhaseReceipt,
    "hardware": HardwareAsset,
    "vendor": Vendor,
    "deployment": SoftwareDeployment,
}
MAX_ASSOCIATIONS = 50
MAX_HISTORY = 200
MAX_GRAPH_BYTES = 4 * 1024 * 1024


def source(db, owner, approval_id):
    if required():
        raise HTTPException(409, "Host association adapter is not qualified for controlled production")
    from api.routers.host_evidence import _check

    intake = store.latest(db, owner, "host_intake", approval_id)
    snapshot, scan, records, _ = _check(db, owner, intake)
    approval = store.latest(db, owner, "host_approval", approval_id)
    system = store.exact(db, System, owner, intake.payload["system_id"])
    if not relationships.active(system):
        raise HTTPException(409, "Host scope system is inactive")
    return intake, snapshot, scan, records, approval


def target(db, owner, system_id, target_type, target_id, package=None, *, environment=None):
    if target_type not in MODELS:
        raise HTTPException(422, "Unsupported typed association endpoint")
    row = store.exact(db, MODELS[target_type], owner, target_id)
    if not relationships.active(row):
        raise HTTPException(409, "Association target is inactive, expired or retracted")
    fields = {
        "hardware": ("asset_id", "manufacturer", "model", "device_type", "hardware_revision", "current_fingerprint"),
        "vendor": ("name", "vendor_type", "contract_end_date"),
        "deployment": ("artifact_id", "system_id", "environment", "deployment_key", "assertion_source", "evidence_ref"),
        "sbom_binding": ("artifact_id", "sbom_artifact_id", "sbom_sha256", "assertion_source", "evidence_ref"),
        "phase_receipt": (
            "job_id",
            "ordinal",
            "endpoint",
            "phase",
            "state",
            "observation_succeeded",
            "observation_sha256",
            "started_at",
        ),
    }
    data = row.to_dict()
    identity = {"target_type": target_type, "target_id": row.id, **{k: data.get(k) for k in fields[target_type]}}
    if target_type == "hardware":
        identity["hardware_metadata_sha256"] = store.digest(
            {
                k: data.get(k)
                for k in (
                    "agent_id",
                    "serial_reference",
                    "firmware",
                    "tpm",
                    "hsm",
                    "capabilities",
                    "crypto_capabilities",
                )
            }
        )
    if target_type == "vendor":
        identity["supplier_metadata_sha256"] = store.digest(row.extra_json)
    for key in ("lifecycle_state", "lifecycle_revision", "valid_until"):
        if key in data:
            identity[key] = data[key]
    if target_type in {"deployment", "sbom_binding"}:
        artifact = store.exact(db, SoftwareArtifact, owner, row.artifact_id)
        identity["artifact_digest"] = artifact.digest
        if target_type == "deployment" and (row.system_id != system_id or row.environment != environment):
            raise HTTPException(409, "Deployment belongs to a different system/environment")
    if target_type == "sbom_binding":
        canonical = normalize_package(package)
        components = relationships.current_components(row, owner)
        if (
            not canonical
            or canonical != package
            or canonical not in {normalize_package(c.get("package_identity")) for c in components}
        ):
            raise HTTPException(409, "Exact versioned package is not resolved in retained original SBOM")
        deployments = (
            store.rows(db, SoftwareDeployment, owner)
            .filter_by(artifact_id=row.artifact_id, system_id=system_id, environment=environment)
            .limit(101)
            .all()
        )
        if len(deployments) > 100:
            raise HTTPException(409, "Association deployment scope exceeds budget")
        active = [d for d in deployments if relationships.active(d)]
        if not active:
            raise HTTPException(409, "No active explicit deployment binds this release to the host scope system")
        identity["deployment_references"] = sorted(
            [
                {
                    "id": d.id,
                    "revision": d.lifecycle_revision,
                    "environment": d.environment,
                    "evidence_ref": d.evidence_ref,
                    "assertion_source": d.assertion_source,
                    "valid_until": d.to_dict().get("valid_until"),
                }
                for d in active
            ],
            key=lambda d: d["id"],
        )
        identity["package_identity"] = canonical
    elif package is not None:
        raise HTTPException(422, "Package identity only belongs on an SBOM association")
    if target_type == "phase_receipt":
        job = store.exact(db, ScanJob, owner, row.job_id)
        if (
            job.system_id not in {None, system_id}
            or job.status != "COMPLETED"
            or row.started_at is None
            or not timedelta(0) <= utcnow() - aware(row.started_at) <= timedelta(days=7)
            or row.state != "COMPLETED"
            or row.observation_succeeded is not True
            or not isinstance(row.observation, dict)
            or row.observation_sha256 != store.digest(row.observation)
            or row.phase != "host_keys"
            or row.observation.get("status") != "OK"
            or row.observation.get("endpoint") != row.endpoint
            or not isinstance(row.observation.get("keys"), list)
            or not 0 < len(row.observation["keys"]) <= 64
            or not all(
                isinstance(k, dict) and isinstance(k.get("key_type"), str) and 0 < len(k["key_type"]) <= 128
                for k in row.observation["keys"]
            )
        ):
            raise HTTPException(
                409, "Failed, stale, unsupported or inconsistent endpoint evidence cannot identify a host endpoint"
            )
        identity["job_system_id"] = job.system_id
        identity["scope_binding"] = "DECLARED_ASSOCIATION_NOT_ENDPOINT_ATTESTATION"
        identity["job_status"] = job.status
    if target_type == "vendor" and row.contract_end_date and aware(row.contract_end_date) <= utcnow():
        raise HTTPException(409, "Supplier association target contract has expired")
    return {
        "target_type": target_type,
        "target_id": row.id,
        "bom": DOMAINS[target_type],
        "target_sha256": store.digest(identity),
        "package_identity": package,
        "identity": identity,
        "evidence_status": "DECLARED",
        "runtime_use": "UNKNOWN",
    }


def fact_source(bundle, input_id, ordinal):
    intake, snapshot, _, records, _ = bundle
    receipt = next((r for r in snapshot.receipts if r.input_id == input_id), None)
    if receipt is None or receipt.status != "PARSED" or ordinal >= len(receipt.facts) or ordinal < 0:
        raise HTTPException(409, "Association requires a parsed, explicitly selected host fact")
    fact = receipt.facts[ordinal]
    evidence = next(
        (
            r
            for r in records
            if r.finding_data["host_evidence"]["input_id"] == input_id
            and r.finding_data["host_evidence"]["fact_ordinal"] == ordinal
        ),
        None,
    )
    if evidence is None:
        evidence = next(
            r
            for r in records
            if r.finding_data["host_evidence"]["input_id"] == input_id
            and r.finding_data["host_evidence"]["fact_ordinal"] == -1
        )
    return {
        "input_id": input_id,
        "fact_ordinal": ordinal,
        "fact_kind": fact.kind,
        "fact_sha256": digest(fact),
        "evidence_id": evidence.id,
        "content_hash": evidence.content_hash,
        "snapshot_sha256": intake.payload["snapshot_sha256"],
        "scan_id": intake.payload["scan_id"],
        "observed_at": snapshot.finished_at.isoformat(),
        "source_revision": None,
    }


def history(db, owner, approval_id):
    rows = (
        store.rows(db, AssuranceRevision, owner)
        .filter_by(kind="bom_relationship")
        .filter(
            AssuranceRevision.payload["schema_version"].as_string() == SCHEMA,
            AssuranceRevision.payload["approval_id"].as_string() == approval_id,
        )
        .order_by(AssuranceRevision.subject_id, AssuranceRevision.revision)
        .limit(MAX_HISTORY + 1)
        .all()
    )
    if len(rows) > MAX_HISTORY:
        raise HTTPException(409, "Host association history exceeds bounded graph budget")
    latest = {}
    for row in rows:
        store.verify(row)
        old = latest.get(row.subject_id)
        if row.revision != (old.revision + 1 if old else 1) or row.previous_sha256 != (
            old.payload_sha256 if old else None
        ):
            raise HTTPException(409, "Host association revision history is incomplete or inconsistent")
        latest[row.subject_id] = row
    if len(latest) > MAX_ASSOCIATIONS:
        raise HTTPException(409, "Host association count exceeds complete graph budget")
    if latest:
        stamps = (
            db.query(AuditLog)
            .filter(
                AuditLog.target_type == "bom_relationship",
                AuditLog.target_id.in_(latest),
                AuditLog.action.in_(
                    ["host.association.propose", "host.association.review", "host.association.retract"]
                ),
            )
            .limit(MAX_HISTORY + 1)
            .all()
        )
        if len(stamps) != len(rows):
            raise HTTPException(409, "Host association audit/revision closure is incomplete")
        expected = {(r.subject_id, r.revision): r for r in rows}
        seen = set()
        for stamp in stamps:
            try:
                detail = json.loads(stamp.detail)
                key = (stamp.target_id, detail["revision"])
                row = expected[key]
                action = {"PROPOSED": "propose", "REVIEWED": "review", "RETRACTED": "retract"}[row.payload["state"]]
                valid = (
                    key not in seen
                    and stamp.action == "host.association." + action
                    and stamp.outcome == "SUCCESS"
                    and stamp.entry_hash == audit_entry_hash(stamp, previous_hash=stamp.previous_hash)
                    and detail["scope_key"] == row.scope_key
                    and detail["actor_id"] == row.created_by
                    and detail["approval_id"] == approval_id
                    and detail["payload_sha256"] == row.payload_sha256
                    and detail["snapshot_sha256"] == row.payload["source"]["snapshot_sha256"]
                )
            except (ValueError, KeyError, TypeError):
                valid = False
            if not valid:
                raise HTTPException(409, "Host association audit commitment is inconsistent")
            seen.add(key)
    return latest


def _save(db, owner, identifier, expected, payload, actor, username, action):
    try:
        row = store.append(db, owner, "bom_relationship", identifier, expected, payload, actor, commit=False)
        UserRepository(db).audit(
            username,
            action,
            target_type="bom_relationship",
            target_id=identifier,
            detail={
                "approval_id": payload["approval_id"],
                "scope_key": row.scope_key,
                "actor_id": actor,
                "revision": row.revision,
                "payload_sha256": row.payload_sha256,
                "snapshot_sha256": payload["source"]["snapshot_sha256"],
                "evidence_status": "DECLARED",
            },
        )
        db.commit()
        return store.public(row)
    except Exception:
        db.rollback()
        raise


def propose(db, owner, approval_id, body, actor, username):
    bundle = source(db, owner, approval_id)
    # Serialize the per-approval count on PostgreSQL, without a new table/queue.
    store.rows(db, AssuranceRevision, owner).filter_by(
        kind="host_approval", subject_id=approval_id, revision=1
    ).with_for_update().one()
    if len(history(db, owner, approval_id)) >= MAX_ASSOCIATIONS:
        raise HTTPException(409, "Host association count exceeds bounded graph budget")
    proof = fact_source(bundle, body.input_id, body.fact_ordinal)
    resolved = target(
        db,
        owner,
        bundle[0].payload["system_id"],
        body.target_type,
        body.target_id,
        body.package_identity,
        environment=bundle[1].manifest.environment,
    )
    if body.expected_target_sha256 != resolved["target_sha256"]:
        raise HTTPException(409, "Target identity changed; inspect it before proposing again")
    if not utcnow() < body.expires_at <= utcnow() + timedelta(days=7):
        raise HTTPException(422, "Association freshness must expire within seven days")
    identifier = store.subject(
        SCHEMA,
        approval_id,
        body.input_id,
        body.fact_ordinal,
        body.target_type,
        body.target_id,
        body.package_identity,
    )
    value = body.model_dump(mode="json", exclude={"expected_target_sha256"})
    payload = {
        **value,
        "schema_version": SCHEMA,
        "relation": "HOST_METADATA_ASSOCIATION",
        "approval_id": approval_id,
        "system_id": bundle[0].payload["system_id"],
        "target_sha256": resolved["target_sha256"],
        "bom": resolved["bom"],
        "source": proof,
        "state": "PROPOSED",
        "proposed_by": actor,
        "evidence_status": "DECLARED",
        "source_basis": "IMPORTED",
        "runtime_use": "UNKNOWN",
        "operational_dependency_verified": False,
        "pqc_use": "UNKNOWN",
    }
    return _save(db, owner, identifier, 0, payload, actor, username, "host.association.propose")


def current(db, owner, bundle, value):
    if value["system_id"] != bundle[0].payload["system_id"] or value["source"] != fact_source(
        bundle, value["input_id"], value["fact_ordinal"]
    ):
        raise HTTPException(409, "Association source commitment mismatch")
    resolved = target(
        db,
        owner,
        value["system_id"],
        value["target_type"],
        value["target_id"],
        value["package_identity"],
        environment=bundle[1].manifest.environment,
    )
    if resolved["target_sha256"] != value["target_sha256"]:
        raise HTTPException(409, "Association target identity changed")
    if aware(datetime.fromisoformat(value["expires_at"])) <= utcnow():
        raise HTTPException(409, "Association freshness expired")
    return resolved


def decide(db, owner, approval_id, identifier, body, actor, username, *, retract=False):
    bundle = source(db, owner, approval_id)
    row = history(db, owner, approval_id).get(identifier)
    if row is None:
        raise HTTPException(404, "Host association not found in this approval scope")
    if row.revision != body.expected_revision:
        raise HTTPException(409, "Association revision changed")
    if retract:
        if row.payload["state"] == "RETRACTED":
            raise HTTPException(409, "Association is already retracted")
        value = {**row.payload, "state": "RETRACTED", "retracted_by": actor}
    else:
        if row.payload["state"] != "PROPOSED" or row.created_by == actor:
            raise HTTPException(409, "A different human must review a pending association")
        current(db, owner, bundle, row.payload)
        value = {**row.payload, "state": "REVIEWED", "proposed_by": row.created_by, "reviewed_by": actor}
    value["decision_evidence_ref"], value["decision_reason"] = body.evidence_ref, body.reason
    return _save(
        db,
        owner,
        identifier,
        row.revision,
        value,
        actor,
        username,
        "host.association.retract" if retract else "host.association.review",
    )


def graph(db, owner, approval_id):
    bundle = source(db, owner, approval_id)
    intake, snapshot, scan, records, approval = bundle
    nodes, edges, assertions = [], [], []
    system_ref, report_ref = "system:" + intake.payload["system_id"], "host-report:" + approval_id
    nodes += [
        {"id": system_ref, "bom": "TechBOM", "kind": "SYSTEM_SCOPE", "evidence_status": "DECLARED"},
        {"id": report_ref, "bom": "TechBOM", "kind": "IMPORTED_HOST_REPORT", "evidence_status": "IMPORTED"},
    ]
    edges.append(
        {
            "from": system_ref,
            "to": report_ref,
            "predicate": "APPROVED_COLLECTION_SCOPE",
            "evidence_status": "DECLARED",
            "provenance": {
                "approval_id": approval_id,
                "approval_sha256": approval.payload_sha256,
                "created_by": approval.created_by,
            },
            "runtime_use": "UNKNOWN",
            "operational_dependency_verified": False,
        }
    )
    fact_refs = {}
    for receipt in snapshot.receipts:
        receipt_ref = report_ref + ":input:" + quote(receipt.input_id, safe="")
        anchor = next(
            r
            for r in records
            if r.finding_data["host_evidence"]["input_id"] == receipt.input_id
            and r.finding_data["host_evidence"]["fact_ordinal"] == -1
        )
        nodes.append(
            {
                "id": receipt_ref,
                "bom": "TechBOM",
                "kind": "COLLECTION_RECEIPT",
                "status": receipt.status,
                "reason": receipt.reason,
                "evidence_status": "IMPORTED",
            }
        )
        edges.append(
            {
                "from": report_ref,
                "to": receipt_ref,
                "predicate": "REPORT_CONTAINS_RECEIPT",
                "evidence_status": "IMPORTED",
                "provenance": {
                    "evidence_id": anchor.id,
                    "content_hash": anchor.content_hash,
                    "snapshot_sha256": intake.payload["snapshot_sha256"],
                },
                "runtime_use": "UNKNOWN",
                "operational_dependency_verified": False,
            }
        )
        for ordinal, fact in enumerate(receipt.facts):
            ref = receipt_ref + ":fact:" + str(ordinal)
            fact_refs[(receipt.input_id, ordinal)] = ref
            domain = (
                "CBOM"
                if fact.kind in {"CERTIFICATE", "TLS_CONFIGURATION"}
                else "SBOM"
                if fact.kind in {"SOFTWARE", "BINARY"}
                else "TechBOM"
            )
            nodes.append(
                {
                    "id": ref,
                    "bom": domain,
                    "kind": fact.kind,
                    "evidence_status": "IMPORTED",
                    "local_basis": fact.local_basis,
                    "metadata": fact.model_dump(mode="json"),
                }
            )
            edges.append(
                {
                    "from": receipt_ref,
                    "to": ref,
                    "predicate": "RECEIPT_CONTAINS_METADATA",
                    "evidence_status": "IMPORTED",
                    "provenance": fact_source(bundle, receipt.input_id, ordinal),
                    "runtime_use": "UNKNOWN",
                    "operational_dependency_verified": False,
                }
            )
    for identifier, row in history(db, owner, approval_id).items():
        value = row.payload
        state, reason, resolved = value["state"], None, None
        if state != "RETRACTED":
            try:
                resolved = current(db, owner, bundle, value)
            except HTTPException as exc:
                if exc.status_code not in {404, 409}:
                    raise
                state, reason = "STALE", "SOURCE_OR_TARGET_UNAVAILABLE_CHANGED_OR_EXPIRED"
        public = {
            "id": identifier,
            "revision": row.revision,
            "state": state,
            "reason": reason,
            "payload_sha256": row.payload_sha256,
            "target_type": value["target_type"],
            "target_id": value["target_id"],
            "bom": value["bom"],
            "input_id": value["input_id"],
            "fact_ordinal": value["fact_ordinal"],
            "evidence_status": "DECLARED",
            "evidence_ref": value["evidence_ref"],
            "proposal_reason": value["reason"],
            "target_sha256": value["target_sha256"],
            "package_identity": value["package_identity"],
            "source": value["source"],
            "expires_at": value["expires_at"],
            "created_by": row.created_by,
            "proposed_by": value.get("proposed_by", row.created_by),
            "reviewed_by": value.get("reviewed_by"),
            "decision_reason": value.get("decision_reason"),
            "decision_evidence_ref": value.get("decision_evidence_ref"),
        }
        assertions.append(public)
        if state == "REVIEWED":
            ref = value["target_type"] + ":" + value["target_id"]
            if value["target_type"] == "sbom_binding":
                ref += ":package:" + quote(value["package_identity"], safe="")
            if not any(n["id"] == ref for n in nodes):
                nodes.append(
                    {
                        "id": ref,
                        "bom": resolved["bom"],
                        "kind": value["target_type"],
                        "package_identity": value["package_identity"],
                        "target_sha256": value["target_sha256"],
                        "evidence_status": "DECLARED",
                    }
                )
            edges.append(
                {
                    "from": fact_refs[(value["input_id"], value["fact_ordinal"])],
                    "to": ref,
                    "predicate": "CUSTOMER_REVIEWED_METADATA_ASSOCIATION",
                    "evidence_status": "DECLARED",
                    "provenance": {
                        **value["source"],
                        "relationship_id": identifier,
                        "revision": row.revision,
                        "relationship_sha256": row.payload_sha256,
                        "target_sha256": value["target_sha256"],
                        "target_type": value["target_type"],
                        "target_id": value["target_id"],
                        "package_identity": value["package_identity"],
                        "proposed_by": value["proposed_by"],
                        "reviewed_by": value["reviewed_by"],
                        "evidence_ref": value["evidence_ref"],
                        "decision_evidence_ref": value["decision_evidence_ref"],
                        "expires_at": value["expires_at"],
                    },
                    "runtime_use": "UNKNOWN",
                    "operational_dependency_verified": False,
                }
            )
    result = {
        "schema_version": GRAPH_SCHEMA,
        "approval_id": approval_id,
        "system_id": intake.payload["system_id"],
        "environment": snapshot.manifest.environment,
        "collected_at": snapshot.finished_at.isoformat(),
        "scan_id": scan.id,
        "snapshot_sha256": intake.payload["snapshot_sha256"],
        "nodes": nodes,
        "edges": edges,
        "associations": assertions,
        "domains": {
            d: {"represented": any(n["bom"] == d for n in nodes), "operational_use": "UNKNOWN"}
            for d in ["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"]
        },
        "evaluated_at": utcnow().isoformat(),
        "whole_host_coverage_verified": False,
        "host_identity_attested": False,
        "operational_dependency_verified": False,
        "pqc_use": "UNKNOWN",
    }
    if len(store.encoded(result)) > MAX_GRAPH_BYTES:
        raise HTTPException(409, "Host graph exceeds complete projection byte budget")
    return {**result, "graph_sha256": store.digest(result)}
