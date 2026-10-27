"""SOC 2 compliance pack (scripts/compliance_pack.py): build, verify, tamper."""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[4] / "scripts"))
import db.models  # noqa: F401
from db.connection.session import Base
from db.models.access_review import AccessReviewRecord

import compliance_pack as cp


def _zip_files(pack: str) -> dict[str, bytes]:
    with zipfile.ZipFile(pack) as z:
        return {n: z.read(n) for n in z.namelist()}


def _rewrite(pack: str, target: str, replacement: bytes) -> str:
    data = _zip_files(pack)
    data[target] = replacement
    out = pack + ".mod"
    with zipfile.ZipFile(out, "w") as z:
        for n, b in data.items():
            z.writestr(n, b)
    return out


@pytest.fixture()
def pack(tmp_path):
    out = cp.build(tmp_path, db_url=None)
    assert out.exists()
    return out


def test_pack_builds_and_verifies(pack):
    assert cp.verify(pack) == 0
    data = _zip_files(str(pack))
    manifest = json.loads(data["manifest.json"])

    # every manifest entry is present with the exact hash; nothing extra
    for name, meta in manifest["files"].items():
        assert name in data, f"{name} missing from pack"
        assert hashlib.sha256(data[name]).hexdigest() == meta["sha256"]
    assert set(data) == set(manifest["files"]) | {"manifest.json"}

    # the policy pack is always part of the exhibit set (committed docs)
    policies = [n for n in data if n.startswith("policies/")]
    assert len(policies) >= 11

    # identity is stamped so the auditor knows exactly what code state this is
    assert manifest["identity"]["git_commit"]

    # pack_hash covers the manifest body (minus pack_hash itself)
    body = {k: v for k, v in manifest.items() if k != "pack_hash"}
    assert hashlib.sha256(json.dumps(body, indent=2,
                                     sort_keys=True).encode()).hexdigest() \
        == manifest["pack_hash"]


def test_pack_is_honest_about_gaps(pack):
    data = _zip_files(str(pack))
    manifest = json.loads(data["manifest.json"])
    # this checkout has no live DB — access reviews must be an honest note,
    # never an empty file pretending otherwise
    missing = " ".join(manifest["missing"])
    assert "NO_ACCESS_REVIEWS" in missing
    assert "access-reviews/" not in "".join(data)


def test_tampered_file_fails_verification(pack):
    data = _zip_files(str(pack))
    policy = next(n for n in data if n.startswith("policies/"))
    mod = _rewrite(str(pack), policy, data[policy] + b"  \nEDITED\n")
    assert cp.verify(mod) == 1


def test_extra_file_fails_verification(pack):
    data = _zip_files(str(pack))
    out = str(pack) + ".extra"
    with zipfile.ZipFile(out, "w") as z:
        for n, b in data.items():
            z.writestr(n, b)
        z.writestr("sneaky.txt", b"not in manifest")
    assert cp.verify(out) == 1


def test_missing_file_fails_verification(pack):
    data = _zip_files(str(pack))
    out = str(pack) + ".dropped"
    with zipfile.ZipFile(out, "w") as z:
        for n, b in data.items():
            if n != "policies/README.md":
                z.writestr(n, b)
    assert cp.verify(out) == 1


def test_access_reviews_from_database(tmp_path):
    db_file = tmp_path / "reviews.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(AccessReviewRecord(period="2026-Q2", report_hash="a" * 64,
                                   estate_unchanged=True, reviewer="ciso",
                                   findings=[{"signal": "stale_accounts",
                                              "subject": "old", "action": "deactivate"}],
                                   notes="Q2"))
    session.commit()

    out = cp.build(tmp_path / "out", db_url=f"sqlite:///{db_file}")
    data = _zip_files(str(out))
    assert cp.verify(out) == 0

    reviews = json.loads(data["access-reviews/reviews.json"])
    assert reviews["count"] == 1
    assert reviews["reviews"][0]["period"] == "2026-Q2"
    assert "NO_ACCESS_REVIEWS" not in json.loads(data["manifest.json"])["missing"]


def test_empty_access_reviews_table_is_an_honest_note(tmp_path):
    db_file = tmp_path / "empty.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)

    out = cp.build(tmp_path / "out", db_url=f"sqlite:///{db_file}")
    data = _zip_files(str(out))
    manifest = json.loads(data["manifest.json"])
    assert "NO_ACCESS_REVIEWS" in " ".join(manifest["missing"])
    assert "access-reviews/reviews.json" not in data or \
        json.loads(data["access-reviews/reviews.json"])["count"] == 0
