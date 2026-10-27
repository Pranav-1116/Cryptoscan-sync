"""Assigned-human qualification intake on existing append-only assurance storage.

No notification/host execution, private signer, new secure-channel provisioning
or production enablement. Uploaded native reports remain operator assertions.
"""

import hashlib
import re
from fastapi import HTTPException
from api.assurance import store
from api.security.rbac import normalize_roles, PERMISSION_MATRIX
from db.models.assurance import AssuranceRevision, AssuranceBlob
from db.models.user import User
from db.models.tenant import Tenant, TenantMembership
from db.repositories.user_repository import UserRepository
from shared_models.chrono import utcnow
from shared_models.qualification_acceptance import (
    AcceptancePolicy,
    EvidenceIndex,
    SignedReview,
    NativeEvidence,
    verify_evidence,
    verify_signed_review,
    verify_acceptance,
    evaluate_native,
)
from shared_models.qualified_export import bounded_json
from shared_models.tpm_quote_verification import sha, Reader

KIND = "host_qualification"
ROLES = {"linux_operator", "windows_operator", "verifier", "independent_assessor", "bank_acceptor"}
REVIEWERS = {"independent_assessor", "bank_acceptor"}
MAX_REV = 320
MAX_FILE = 2 * 1048576
MAX_TOTAL = 16 * 1048576


def chain(db, owner, identifier):
    rows = (
        store.rows(db, AssuranceRevision, owner)
        .filter_by(kind=KIND, subject_id=identifier)
        .order_by(AssuranceRevision.revision)
        .limit(MAX_REV + 1)
        .all()
    )
    if not rows:
        raise HTTPException(404, "Qualification campaign not found")
    if len(rows) > MAX_REV:
        raise HTTPException(409, "Qualification history budget exhausted")
    previous = None
    for number, row in enumerate(rows, 1):
        store.verify(row)
        if row.revision != number or row.previous_sha256 != previous:
            raise HTTPException(409, "Qualification history incomplete")
        previous = row.payload_sha256
    return rows


def load(db, owner, identifier, *, lock=False):
    if lock:
        root = (
            store.rows(db, AssuranceRevision, owner)
            .filter_by(kind=KIND, subject_id=identifier, revision=1)
            .with_for_update()
            .first()
        )
        if root is None:
            raise HTTPException(404, "Qualification campaign not found")
    return chain(db, owner, identifier)[-1]


def save(db, owner, identifier, row, value, actor, user, action):
    revision = row.revision if row else 0
    # Reserve the last revision for an explicit stop, even when a normal
    # mutation has exhausted the campaign history budget.
    if revision >= MAX_REV or (action != "withdrawn" and revision >= MAX_REV - 1):
        raise HTTPException(409, "Qualification history budget exhausted; reserved withdrawal remains available")
    result = store.append(db, owner, KIND, identifier, revision, value, actor, commit=False)
    UserRepository(db).audit(
        user,
        "qualification." + action,
        target_type=KIND,
        target_id=identifier,
        detail={"revision": result.revision, "payload_sha256": result.payload_sha256, "actor_id": actor},
    )
    return result


def atomic(db, fn):
    try:
        result = fn()
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise


def expected(row, revision):
    if row.revision != revision:
        raise HTTPException(409, "Qualification revision changed; reload")
    if row.payload["withdrawn"]:
        raise HTTPException(409, "Qualification campaign withdrawn")


def person(db, owner, user_id, role):
    user = db.get(User, user_id)
    if not user or not user.is_active or user.deleted_at:
        raise HTTPException(409, "Assigned user unavailable")
    permission = "assurance.review" if role in REVIEWERS else "assurance.manage"
    roles = set(normalize_roles(user.role_list))
    if not roles & PERMISSION_MATRIX[permission]:
        raise HTTPException(409, "Assigned user authority changed")
    if owner is None:
        if "superadmin" not in roles:
            raise HTTPException(409, "Platform assignment requires platform authority")
    else:
        tenant = db.get(Tenant, owner)
        member = db.query(TenantMembership).filter_by(tenant_id=owner, username=user.username).one_or_none()
        if not tenant or tenant.status != "ACTIVE" or not member or member.tenant_role == "viewer":
            raise HTTPException(409, "Assigned user does not currently own selected estate")
    return user


def validate_assignments(db, owner, value, *, complete=False):
    assignments = value["assignments"]
    policy = AcceptancePolicy.model_validate(value["policy"])
    if complete and set(assignments) != ROLES:
        raise HTTPException(409, "All five human responsibility slots must be assigned")
    for role, a in assignments.items():
        person(db, owner, a["user_id"], role)
        if role in REVIEWERS and not any(
            r.reviewer_id == a["reviewer_id"] and r.role == role for r in policy.reviewers
        ):
            raise HTTPException(409, "Reviewer assignment does not match pinned key and role")
    reviewers = [a["user_id"] for role, a in assignments.items() if role in REVIEWERS]
    operators = {a["user_id"] for role, a in assignments.items() if role not in REVIEWERS}
    if len(set(reviewers)) != len(reviewers) or set(reviewers) & (operators | {value["policy_approved_by"]}):
        raise HTTPException(409, "Reviewers must be separate from each other, policy approver and operators")


def role_for(db, owner, row, actor, allowed):
    validate_assignments(db, owner, row.payload, complete=True)
    roles = {role for role, a in row.payload["assignments"].items() if a["user_id"] == actor} & set(allowed)
    if not roles:
        raise HTTPException(403, "Current human is not assigned this responsibility")
    return sorted(roles)


def artifacts(db, owner, row):
    result = {}
    for digest, entry in row.payload["artifacts"].items():
        blob = store.blob(db, owner, entry["blob_id"])
        if blob.sha256 != digest:
            raise HTTPException(409, "Qualification artifact reference changed")
        result[digest] = bytes(blob.data)
    return result


def status(db, owner, row):
    value = row.payload
    blockers = []
    state = "WAITING_FOR_ASSIGNMENTS"
    report = None
    if value["withdrawn"]:
        state = "WITHDRAWN"
    else:
        try:
            validate_assignments(db, owner, value, complete=True)
        except HTTPException as exc:
            blockers.append(exc.detail)
            if set(value["assignments"]) == ROLES:
                state = "BLOCKED"
        if not blockers:
            state = "WAITING_FOR_OPERATOR_EVIDENCE"
            if value["index"] is not None:
                policy = AcceptancePolicy.model_validate(value["policy"])
                index = EvidenceIndex.model_validate(value["index"])
                data = artifacts(db, owner, row)
                try:
                    verify_evidence(policy, index, data)
                    state = "WAITING_FOR_SEPARATE_SIGNED_REVIEWS"
                    proofs = [SignedReview.model_validate(p) for p in value["reviews"].values()]
                    for proof in proofs:
                        verify_signed_review(policy, index, proof, utcnow())
                        if proof.statement.decision != "ACCEPT_SCOPED_EVIDENCE" or any(
                            v != "PASS" for v in proof.statement.checks.values()
                        ):
                            blockers.append("A signed review rejects or has unresolved checks")
                    if len(proofs) == 2 and not blockers:
                        report = verify_acceptance(policy, index, proofs, data, utcnow())
                        state = "SCOPED_EXTERNAL_RECORD_VERIFIED"
                except ValueError:
                    blockers.append("Evidence or review verification failed/expired")
            if blockers:
                state = "BLOCKED"
    return {
        "assignees": {
            role: {
                "user_id": a["user_id"],
                "username": u.username if u else None,
                "display_name": u.display_name if u else None,
            }
            for role, a in value["assignments"].items()
            for u in [db.get(User, a["user_id"])]
        },
        "record": store.public(row),
        "evaluated_at": utcnow().isoformat(),
        "state": state,
        "blockers": blockers,
        "verification": report,
        "dispatch": "NOT_DISPATCHED_NO_REMOTE_EXECUTION",
        "channel": "AUTHENTICATED_API_REQUIRES_BANK_APPROVED_TRANSPORT",
        "host_identity_attested": False,
        "full_worker_production_clearance": False,
        "production_execution_qualified": False,
    }


def create(db, owner, body, actor, user):
    if body.policy.tenant_id != owner or len(body.policy.reviewers) != 2:
        raise HTTPException(422, "Exact selected tenant and two pinned reviewer roles required")
    identifier = store.subject("qualification-campaign/v1", store.scope_key(owner), body.policy.campaign_id)
    value = {
        "schema_version": "cryptoscan.qualification-campaign/v1",
        "policy": body.policy.model_dump(mode="json"),
        "policy_approved_by": actor,
        "return_channel_reference": body.return_channel_reference,
        "evidence_reference": body.evidence_reference,
        "assignments": {},
        "artifacts": {},
        "index": None,
        "reviews": {},
        "withdrawn": False,
    }

    def operation():
        if store.latest(db, owner, KIND, identifier, required=False):
            raise HTTPException(409, "Campaign identity already exists; use fresh campaign scope")
        return status(db, owner, save(db, owner, identifier, None, value, actor, user, "created"))

    return atomic(db, operation)


def assign(db, owner, identifier, body, actor, user):
    def operation():
        row = load(db, owner, identifier, lock=True)
        expected(row, body.expected_revision)
        if row.payload["artifacts"] or row.payload["index"] is not None:
            raise HTTPException(
                409, "Assignments are frozen after first evidence; withdraw and explicitly reauthorize a new campaign"
            )
        value = {
            **row.payload,
            "assignments": {
                **row.payload["assignments"],
                **{r: a.model_dump(mode="json") for r, a in body.assignments.items()},
            },
            "evidence_reference": body.evidence_reference,
        }
        validate_assignments(db, owner, value)
        return status(db, owner, save(db, owner, identifier, row, value, actor, user, "assigned"))

    return atomic(db, operation)


def public_json(data):
    value = bounded_json(data, max_bytes=MAX_FILE)
    if not isinstance(value, (dict, list)):
        raise ValueError("Structured public JSON required")
    banned = {
        "password",
        "passwd",
        "privatekey",
        "secret",
        "clientsecret",
        "accesstoken",
        "refreshtoken",
        "authorization",
        "credentials",
        "apikey",
    }

    def inspect(item):
        if isinstance(item, dict):
            for key, v in item.items():
                if re.sub("[^a-z]", "", key.lower()) in banned:
                    raise ValueError("Credential/private material not accepted")
                inspect(v)
        elif isinstance(item, list):
            for v in item:
                inspect(v)
        elif isinstance(item, str) and (
            re.search(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH)", item)
            or re.search(r"(?i)\bBearer\s+\S+", item)
            or re.search(r"://[^\s/@:]+:[^\s/@]+@", item)
        ):
            raise ValueError("Credential/private material not accepted")

    inspect(value)
    return value


def validate_public(kind, data):
    if kind in {"native", "public_json"}:
        value = public_json(data)
        return NativeEvidence.model_validate(value) if kind == "native" else None
    r = Reader(data, 4096 if kind == "tpm_attest" else 1024)
    if kind == "tpm_attest":
        if r.number("I") != 0xFF544347 or r.number("H") != 0x8018:
            raise ValueError("Raw public quote required")
        r.sized(68)
        r.sized(64)
        r.take(25)
        if r.number("I") != 1 or r.number("H") != 0x000B or r.number("B") != 3:
            raise ValueError("SHA256 quote selection required")
        r.take(3)
        r.sized(64)
    else:
        alg = r.number("H")
        if r.number("H") != 0x000B:
            raise ValueError("SHA256 public signature required")
        if alg == 0x0014:
            r.sized(512)
        elif alg == 0x0018:
            r.sized(32)
            r.sized(32)
        else:
            raise ValueError("Supported public quote signature required")
    r.end()
    return None


def upload(db, owner, identifier, revision, kind, data, evidence_ref, actor, user):
    try:
        native = validate_public(kind, data)
    except (ValueError, UnicodeError, TypeError):
        raise HTTPException(422, "Invalid or non-public qualification artifact; content not retained") from None

    def operation():
        row = load(db, owner, identifier, lock=True)
        expected(row, revision)
        if row.payload["index"] is not None:
            raise HTTPException(409, "Original evidence is frozen")
        allowed = (
            {"linux_operator"}
            if native and native.category != "windows"
            else {"windows_operator"}
            if native
            else {"linux_operator", "windows_operator", "verifier"}
        )
        roles = role_for(db, owner, row, actor, allowed)
        if native:
            policy = AcceptancePolicy.model_validate(row.payload["policy"])
            if (
                sha(native.plan) != policy.native_plan_sha256[native.category]
                or native.source_lock_sha256 != policy.native_source_lock_sha256[native.category]
            ):
                raise HTTPException(409, "Native plan/platform release not approved")
            try:
                native_status = evaluate_native(native)["verdict"]
            except ValueError:
                raise HTTPException(422, "Native scope/truth contract invalid") from None
        else:
            native_status = None
        digest = hashlib.sha256(data).hexdigest()
        current = row.payload["artifacts"]
        if digest in current:
            raise HTTPException(409, "Exact artifact already retained")
        if len(current) >= 256 or sum(v["bytes"] for v in current.values()) + len(data) > MAX_TOTAL:
            raise HTTPException(413, "Campaign artifact count/total size bound")
        blob = AssuranceBlob(
            tenant_id=owner,
            scope_key=store.scope_key(owner),
            sha256=digest,
            byte_count=len(data),
            data=data,
            created_by=actor,
        )
        db.add(blob)
        db.flush()
        entry = {
            "blob_id": blob.id,
            "bytes": len(data),
            "kind": kind,
            "category": native.category if native else None,
            "native_result": native_status,
            "submitted_by": actor,
            "assigned_roles": roles,
            "evidence_reference": evidence_ref,
            "provenance": "IMPORTED_ASSIGNED_OPERATOR_ARTIFACT_NOT_REMOTE_EXECUTION",
        }
        value = {**row.payload, "artifacts": {**current, digest: entry}}
        return status(db, owner, save(db, owner, identifier, row, value, actor, user, "artifact_received"))

    return atomic(db, operation)


def freeze(db, owner, identifier, body, actor, user):
    def operation():
        row = load(db, owner, identifier, lock=True)
        expected(row, body.expected_revision)
        role_for(db, owner, row, actor, {"verifier"})
        if row.payload["index"] is not None:
            raise HTTPException(409, "Evidence index already frozen")
        policy = AcceptancePolicy.model_validate(row.payload["policy"])
        try:
            verify_evidence(policy, body.index, artifacts(db, owner, row))
        except ValueError:
            raise HTTPException(
                409, "Required original native/worker artifacts are missing, changed or not qualified"
            ) from None
        value = {
            **row.payload,
            "index": body.index.model_dump(mode="json"),
            "evidence_reference": body.evidence_reference,
        }
        return status(db, owner, save(db, owner, identifier, row, value, actor, user, "evidence_frozen"))

    return atomic(db, operation)


def review(db, owner, identifier, body, actor, user):
    def operation():
        row = load(db, owner, identifier, lock=True)
        expected(row, body.expected_revision)
        roles = role_for(db, owner, row, actor, REVIEWERS)
        if row.payload["index"] is None:
            raise HTTPException(409, "Freeze and verify original evidence before independent review")
        role = roles[0]
        assignment = row.payload["assignments"][role]
        if body.review.statement.reviewer_id != assignment["reviewer_id"]:
            raise HTTPException(403, "Signed key identity is not assigned to this human")
        if role in row.payload["reviews"]:
            raise HTTPException(409, "Reviewer decision already retained; cannot overwrite signed history")
        try:
            verify_signed_review(
                AcceptancePolicy.model_validate(row.payload["policy"]),
                EvidenceIndex.model_validate(row.payload["index"]),
                body.review,
                utcnow(),
            )
        except ValueError:
            raise HTTPException(422, "Review signature/scope/time invalid") from None
        value = {
            **row.payload,
            "reviews": {**row.payload["reviews"], role: body.review.model_dump(mode="json")},
            "evidence_reference": body.evidence_reference,
        }
        return status(db, owner, save(db, owner, identifier, row, value, actor, user, "signed_review_received"))

    return atomic(db, operation)


def withdraw(db, owner, identifier, body, actor, user):
    def operation():
        row = load(db, owner, identifier, lock=True)
        expected(row, body.expected_revision)
        return status(
            db,
            owner,
            save(
                db,
                owner,
                identifier,
                row,
                {**row.payload, "withdrawn": True, "evidence_reference": body.evidence_reference},
                actor,
                user,
                "withdrawn",
            ),
        )

    return atomic(db, operation)
