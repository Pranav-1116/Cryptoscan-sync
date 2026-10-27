"""Signed fixture registers do not establish actual estate/native completeness."""

import base64
from datetime import datetime, timezone, timedelta
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from shared_models.software_estate import (
    EstateAssetRegister,
    SoftwareEstatePlan,
    SoftwareEstatePacket,
    EstateSurfaceStatement,
    SignedEstateSurface,
    SURFACES,
    reconcile_estate,
)
from shared_models.tpm_quote_verification import canonical, sha


def fixture():
    now = datetime.now(timezone.utc)
    keys = {name: Ed25519PrivateKey.generate() for name in ["asset-a", "asset-b"]}
    register = EstateAssetRegister(
        estate_id="owned-fixture",
        register_reference="expected-register/not-independent",
        assets=[
            {
                "asset_id": name,
                "platform": "linux",
                "producer_public_key": base64.b64encode(
                    key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                ).decode(),
            }
            for name, key in keys.items()
        ],
    )
    scopes = []
    artifacts = {}
    for asset in keys:
        for surface in sorted(SURFACES):
            data = canonical({"fixture": asset, "surface": surface})
            digest = hashlib.sha256(data).hexdigest()
            artifacts[digest] = data
            scopes.append(
                {
                    "asset_id": asset,
                    "surface": surface,
                    "expected_source_sha256": digest,
                    "scope_reason": "fixture-explicit-surface",
                    "expected_records": [{"identity": asset + "/" + surface, "version": "1", "content_sha256": None}],
                }
            )
    plan = SoftwareEstatePlan(
        asset_register=register,
        asset_register_sha256=sha(register),
        release_sha256="a" * 64,
        reviewer_reference="fixture/not-independent",
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        scopes=scopes,
    )
    returns = []
    for scope in plan.scopes:
        statement = EstateSurfaceStatement(
            plan_sha256=sha(plan),
            release_sha256=plan.release_sha256,
            asset_id=scope.asset_id,
            surface=scope.surface,
            source_sha256=scope.expected_source_sha256,
            captured_at=now,
            status="MEASURED",
            records=scope.expected_records,
        )
        returns.append(
            SignedEstateSurface(
                statement=statement,
                signature=base64.b64encode(keys[scope.asset_id].sign(canonical(statement))).decode(),
            )
        )
    return plan, SoftwareEstatePacket(returns=returns), artifacts, now


def test_all_assets_six_surfaces_reconcile_without_global_or_native_claim():
    p, e, a, now = fixture()
    r = reconcile_estate(p, e, a, now)
    assert r["registered_assets"] == 2 and r["total_surface_units"] == r["matched_units"] == 12
    assert r["agreed_register_record_sets_matched"] and not r["whole_estate_software_complete"]
    assert r["source_basis"] == "IMPORTED_SIGNED_CLAIMS" and not r["producer_measurement_truth_independently_verified"]


def test_missing_returns_are_unknown_not_absence():
    p, _, _, now = fixture()
    r = reconcile_estate(p, SoftwareEstatePacket(returns=[]), {}, now)
    assert not r["agreed_register_record_sets_matched"] and r["matched_units"] == 0
    assert all(row["observed_records"] is None for row in r["units"])


@pytest.mark.parametrize("mode", ["omit-asset", "omit-surface", "duplicate", "wrong-register", "all-na"])
def test_denominator_cannot_shrink_or_hide_unknowns(mode):
    p, _, _, _ = fixture()
    data = p.model_dump(mode="python")
    if mode == "omit-asset":
        data["scopes"] = data["scopes"][6:]
    elif mode == "omit-surface":
        data["scopes"] = data["scopes"][1:]
    elif mode == "duplicate":
        data["scopes"].append(data["scopes"][0])
    elif mode == "wrong-register":
        data["asset_register_sha256"] = "f" * 64
    else:
        for s in data["scopes"]:
            s.update(applicability="NOT_APPLICABLE", expected_records=[])
    with pytest.raises(ValueError):
        SoftwareEstatePlan.model_validate(data)


@pytest.mark.parametrize(
    "mode",
    [
        "duplicate",
        "wrong-signature",
        "wrong-plan",
        "wrong-release",
        "future",
        "changed-source",
        "extra-source",
        "foreign-asset",
        "expired",
    ],
)
def test_replayed_cross_scope_or_untrusted_returns_refused(mode):
    p, e, artifacts, now = fixture()
    first = e.returns[0]
    if mode == "duplicate":
        e = e.model_copy(update={"returns": [*e.returns, first]})
    elif mode == "wrong-signature":
        e = e.model_copy(
            update={
                "returns": [
                    first.model_copy(update={"signature": base64.b64encode(b"0" * 64).decode()}),
                    *e.returns[1:],
                ]
            }
        )
    elif mode in {"wrong-plan", "wrong-release", "future", "foreign-asset"}:
        field = {
            "wrong-plan": "plan_sha256",
            "wrong-release": "release_sha256",
            "future": "captured_at",
            "foreign-asset": "asset_id",
        }[mode]
        value = now + timedelta(seconds=1) if mode == "future" else "foreign" if mode == "foreign-asset" else "f" * 64
        e = e.model_copy(
            update={
                "returns": [
                    first.model_copy(update={"statement": first.statement.model_copy(update={field: value})}),
                    *e.returns[1:],
                ]
            }
        )
    elif mode == "changed-source":
        artifacts[first.statement.source_sha256] = b"changed"
    elif mode == "extra-source":
        artifacts[hashlib.sha256(b"extra").hexdigest()] = b"extra"
    else:
        now = p.expires_at
    with pytest.raises(ValueError):
        reconcile_estate(p, e, artifacts, now)


def test_failed_or_declared_input_cannot_claim_empty_measured_success():
    p, e, _, _ = fixture()
    data = e.returns[0].statement.model_dump(mode="python")
    for change in [{"status": "MEASURED", "records": []}, {"status": "FAILED"}, {"status": "DECLARED_ONLY"}]:
        with pytest.raises(ValueError):
            EstateSurfaceStatement.model_validate({**data, **change})
