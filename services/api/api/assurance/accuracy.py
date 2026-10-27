"""Approved frozen samples, immutable first pass, held-out repeat, regression seeds."""
from collections import Counter, defaultdict
from fastapi import HTTPException
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.repositories.execution_control import aware
from shared_models.assurance import SOURCE_CLASSES
from . import store


def scans(db, owner, identifiers):
    if len(set(identifiers)) != len(identifiers):
        raise HTTPException(422, "Duplicate scan ids")
    result = [store.exact(db, Scan, owner, identifier) for identifier in identifiers]
    if any(s.status != "COMPLETED" or not s.scan_end or aware(s.scan_end) > utcnow() or aware(s.scan_start) > aware(s.scan_end) for s in result):
        raise HTTPException(409, "Only durable completed scans can freeze predictions")
    return result


def predictions(db, owner, scan_rows, units):
    # Bounded units/predictions; no caller-submitted TP/FP/FN totals are accepted.
    evidence = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == owner,
        EvidenceRecord.scan_id.in_([s.id for s in scan_rows]), EvidenceRecord.deleted_at.is_(None),
        EvidenceRecord.file_path.in_([u["file"] for u in units])).limit(10001).all()
    if len(evidence) > 10000:
        raise HTTPException(409, "Sample evidence exceeds bound; select a smaller representative sample")
    hits = defaultdict(list)
    for e in evidence:
        hits[(e.scan_id, e.file_path, e.algorithm.upper())].append({"evidence_id": e.id, "scan_id": e.scan_id,
            "content_hash": e.content_hash, "chain_hash": e.chain_hash, "algorithm": e.algorithm,
            "purpose": e.purpose, "file": e.file_path, "line": e.line_number})
    result = []
    for unit in units:
        proofs = prove_file(scan_rows, unit["file"], unit["fixture_sha256"])
        scan_id = proofs[0][0].id
        observations = hits[(scan_id, unit["file"], unit["algorithm"].upper())]
        result.append({**unit, "source_scan_id": scan_id, "predicted": bool(observations), "observations": observations})
    return result


def propose(db, owner, identifier, body, actor):
    scan_rows = scans(db, owner, body.scan_ids)
    from db.models.user import User
    from db.models.tenant import TenantMembership
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX
    domain = db.query(User).filter_by(id=body.domain_owner_user_id, is_active=True, deleted_at=None).one_or_none()
    roles = set(normalize_roles(domain.role_list)) if domain else set()
    member = bool(domain and ("superadmin" in roles or owner is None or db.query(TenantMembership).filter_by(tenant_id=owner, username=domain.username).first()))
    if not domain or not roles & PERMISSION_MATRIX["assurance.review"] or not member:
        raise HTTPException(404, "Active selected-estate domain-owner reviewer not found")
    units, hashes = [], {}
    for unit in body.units:
        b = store.blob(db, owner, unit.fixture_blob_id)
        if b.sha256 in hashes and hashes[b.sha256] != unit.split:
            raise HTTPException(409, "Fixture bytes cannot cross first-pass and held-out partitions")
        hashes[b.sha256] = unit.split
        prove_file(scan_rows, unit.file, b.sha256)
        units.append({**unit.model_dump(), "unit_id": store.subject(identifier, unit.file, unit.algorithm.upper()),
                      "fixture_sha256": b.sha256})
    held = [u["fixture_sha256"] for u in units if u["split"] == "HOLDOUT"]
    reject_contaminated(db, owner, held)
    return store.append(db, owner, "accuracy_sample", identifier, 0,
        {**body.model_dump(mode="json", exclude={"units"}), "state": "PROPOSED",
         "scan_receipts": [{"id": s.id, "scanner_version": s.scanner_version, "manifest_hash": s.manifest_hash,
                            "target": s.target_location, "commit": s.target_commit} for s in scan_rows],
         "units": predictions(db, owner, scan_rows, units)}, actor)


def approve(db, owner, identifier, body, actor):
    sample = store.latest(db, owner, "accuracy_sample", identifier)
    if sample.payload["state"] != "PROPOSED" or sample.created_by == actor or actor != sample.payload["domain_owner_user_id"]:
        raise HTTPException(409, "Representative sample needs a different human approver; approval is write-once")
    return store.append(db, owner, "accuracy_sample", identifier, body.expected_revision,
        {**sample.payload, "state": "APPROVED", "proposed_by": sample.created_by,
         "approved_by": actor, "approval_evidence_ref": body.evidence_ref, "approval_reason": body.reason}, actor)


def approved(db, owner, identifier):
    sample = store.latest(db, owner, "accuracy_sample", identifier)
    if sample.payload["state"] != "APPROVED":
        raise HTTPException(409, "Customer representative sample not yet approved")
    return sample


def reject_contaminated(db, owner, hashes):
    if store.rows(db, AssuranceRevision, owner).filter(AssuranceRevision.kind == "regression_case",
            AssuranceRevision.payload["fixture_sha256"].as_string().in_(hashes)).first():
        raise HTTPException(409, "Held-out bytes already exist in the regression/training register")


def repeat(db, owner, identifier, body, actor):
    sample = approved(db, owner, identifier)
    first = store.latest(db, owner, "accuracy_review", store.subject(identifier, "FIRST_PASS"))
    new_scans = scans(db, owner, body.scan_ids)
    if set(body.scan_ids) & set(sample.payload["scan_ids"]):
        raise HTTPException(409, "Repeat must use new scan receipts, not first-pass predictions")
    if any(aware(s.scan_start) < aware(first.created_at) for s in new_scans):
        raise HTTPException(409, "Held-out repeat must run after the preserved first review")
    old_targets = {s["target"] for s in sample.payload["scan_receipts"]}
    if any(s.target_location not in old_targets for s in new_scans):
        raise HTTPException(409, "Repeat target is outside the approved sample scope")
    units = [u for u in sample.payload["units"] if u["split"] == "HOLDOUT"]
    reject_contaminated(db, owner, [u["fixture_sha256"] for u in units])
    for unit in units:
        prove_file(new_scans, unit["file"], unit["fixture_sha256"])
    return store.append(db, owner, "accuracy_repeat", identifier, 0,
        {"sample_id": identifier, "sample_revision": sample.revision,
         "scan_ids": body.scan_ids, "scanner_versions": [s.scanner_version for s in new_scans],
         "evidence_ref": body.evidence_ref, "units": predictions(db, owner, new_scans, units)}, actor)


def review(db, owner, identifier, body, actor):
    sample = approved(db, owner, identifier)
    if actor == sample.payload["proposed_by"] or actor != sample.payload["domain_owner_user_id"]:
        raise HTTPException(409, "Sample proposer cannot be its domain-owner reviewer")
    if body.domain_owner != sample.payload["domain_owner"]:
        raise HTTPException(409, "Review must identify the approved domain owner")
    if body.phase == "HOLDOUT":
        source = store.latest(db, owner, "accuracy_repeat", identifier)
        units = source.payload["units"]
        reject_contaminated(db, owner, [u["fixture_sha256"] for u in units])
    else:
        source = sample
        units = [u for u in sample.payload["units"] if u["split"] == "FIRST_PASS"]
    verdicts = {u.unit_id: u for u in body.units}
    if len(verdicts) != len(body.units) or set(verdicts) != {u["unit_id"] for u in units}:
        raise HTTPException(422, "Review every frozen unit once (UNREVIEWED is explicit); no invented units")
    counts, by_class, reviewed = Counter(), defaultdict(Counter), []
    for unit in units:
        verdict = verdicts[unit["unit_id"]]
        label = "UNREVIEWED" if verdict.truth == "UNREVIEWED" else (
            ("TP" if unit["predicted"] else "FN") if verdict.truth == "PRESENT" else ("FP" if unit["predicted"] else "TN"))
        counts[label] += 1
        by_class[unit["source_class"]][label] += 1
        reviewed.append({**unit, "truth": verdict.truth, "verdict": label, "explanation": verdict.explanation})
    if counts["UNREVIEWED"] == len(units):
        raise HTTPException(422, "No reviewed units")
    def metrics(c):
        tp, fp, fn = c["TP"], c["FP"], c["FN"]
        return {**{k: c[k] for k in ("TP", "FP", "FN", "TN", "UNREVIEWED")},
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
                "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}
    return store.append(db, owner, "accuracy_review", store.subject(identifier, body.phase), 0,
        {"sample_id": identifier, "sample_sha256": source.payload_sha256, "phase": body.phase,
         "domain_owner": body.domain_owner, "evidence_ref": body.evidence_ref,
         "scope_description": sample.payload["scope_description"], "metrics": metrics(counts),
         "by_source_class": {k: metrics(v) for k, v in by_class.items()},
         "uncovered_source_classes": sorted(set(SOURCE_CLASSES) - set(by_class)),
         "blind_spots": sample.payload["blind_spots"], "global_accuracy_claim": False,
         "ground_truth_basis": "CUSTOMER_DOMAIN_OWNER_REVIEW_NOT_INDEPENDENT_CERTIFICATION", "units": reviewed}, actor)


def seed_regressions(db, owner, identifier, actor):
    review_row = store.latest(db, owner, "accuracy_review", store.subject(identifier, "FIRST_PASS"))
    result = []
    for unit in review_row.payload["units"]:
        if unit["verdict"] not in {"FP", "FN", "TN"}:
            continue
        case_id = store.subject(identifier, unit["unit_id"], "regression")
        previous = store.latest(db, owner, "regression_case", case_id, required=False)
        if previous:
            result.append(previous.subject_id)
            continue
        row = store.append(db, owner, "regression_case", case_id, 0,
            {"sample_id": identifier, "review_sha256": review_row.payload_sha256,
             "unit_id": unit["unit_id"], "file": unit["file"], "algorithm": unit["algorithm"],
             "fixture_blob_id": unit["fixture_blob_id"], "fixture_sha256": unit["fixture_sha256"],
             "truth": unit["truth"], "original_verdict": unit["verdict"], "source_class": unit["source_class"],
             "explanation": unit["explanation"], "state": "CUSTOMER_CONFIRMED_SEED_NOT_YET_EXECUTED_BY_SCANNER"}, actor, commit=False)
        result.append(row.subject_id)
    db.commit()
    return {"case_ids": result, "executed_regression_tests": False,
            "next_step": "Export approved de-identified fixtures to scanner regression CI; seed registration is not a passing test"}


def prove_file(scan_rows, filename, expected_sha256):
    proofs = [(scan, p) for scan in scan_rows
              for p in (scan.statistics or {}).get("file_observation_receipts", [])
              if p.get("file") == filename]
    if len(proofs) != 1 or any(p.get("sha256") != expected_sha256 or p.get("parser_completed") is not True for _, p in proofs):
        raise HTTPException(409, "No unambiguous matching parsed-file byte receipt; recollect with a current scanner before scoring negatives or held-out units")
    return proofs


def regression_result(db, owner, identifier, body, actor):
    case = store.latest(db, owner, "regression_case", identifier)
    scan = scans(db, owner, [body.scan_id])[0]
    if aware(scan.scan_start) < aware(case.created_at):
        raise HTTPException(409, "Regression scan predates the confirmed customer seed")
    prove_file([scan], case.payload["file"], case.payload["fixture_sha256"])
    unit = {**case.payload, "predicted": False}
    actual = predictions(db, owner, [scan], [unit])[0]
    expected = case.payload["truth"] == "PRESENT"
    return store.append(db, owner, "regression_result", store.subject(identifier, scan.id), 0,
        {"case_id": identifier, "case_sha256": case.payload_sha256, "scan_id": scan.id,
         "scanner_version": scan.scanner_version, "fixture_sha256": case.payload["fixture_sha256"],
         "file": case.payload["file"], "algorithm": case.payload["algorithm"], "expected_present": expected,
         "actual_present": actual["predicted"], "passed": actual["predicted"] == expected,
         "observations": actual["observations"], "evidence_ref": body.evidence_ref,
         "scope": "EXACT_CUSTOMER_CONFIRMED_FILE_ALGORITHM_REGRESSION_NOT_GLOBAL_ACCURACY"}, actor)
