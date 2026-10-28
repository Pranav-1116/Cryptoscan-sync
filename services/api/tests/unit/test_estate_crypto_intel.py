"""What the estate's cryptography actually is (spec 94 §12, §24, §26).

Three readings of the same artefacts: weak, unknown, and post-quantum. The tests below
hold the module to the distinctions that make those three usable:

* **capability is not use** — a library that supports DES has not used DES, and the two
  are counted separately so a PQC programme is not started from a feature list;
* **an unknown algorithm is not a compliant one** — it is reported as unknown;
* **a version string is not an algorithm** — `OpenSSL 3.0.13` in an algorithm fact is a
  data-quality finding about the collector, not unidentified cryptography, and the two
  need different people to fix them;
* **a verdict is an opinion** — the status comes from this product's registry and is
  labelled as such, so it is never mistaken for evidence.

Also covered: the §26 question ("who holds RSA-2048") answered by asset type with in-use
and capability kept apart, and the refusal to turn "no observation" into "nothing uses it".
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import estate_crypto_intel as intel
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"
INTEL_URL = f"{BASE}/twin/intel"
ALGORITHM_URL = f"{BASE}/twin/algorithm"


def _payload() -> dict:
    """A small estate with one of each thing these lists exist to tell apart."""
    return {
        "estate": "Synthetic Bank",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "Payment API",
             "environment": "production"},
            {"ref": "hsm", "type": "HSM", "name": "HSM-04", "environment": "production"},
            {"ref": "legacy", "type": "APPLICATION", "name": "Legacy Ledger",
             "environment": "production"},
            {"ref": "lb", "type": "LOAD_BALANCER", "name": "LB-07",
             "environment": "production"},
            {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "environment": "production"},
        ],
        "evidence": [
            # in use, and disallowed
            {"evidence_id": "ev-1", "source": "runtime", "collector": "runtime-probe",
             "evidence_type": "RUNTIME_OBSERVED", "target": "legacy", "layer": "APPLICATION",
             "facts": {"algorithm": "DES"}},
            # capability only, and disallowed — a finding about a library, not about use
            {"evidence_id": "ev-2", "source": "sbom", "collector": "sbom-parser",
             "evidence_type": "STATIC_OBSERVED", "target": "ossl", "layer": "APPLICATION",
             "facts": {"supported_algorithms": ["DES", "AES-256-GCM"]}},
            # deprecated, in use, configured
            {"evidence_id": "ev-3", "source": "/etc/tls.conf", "collector": "config",
             "evidence_type": "CONFIGURED", "target": "lb", "layer": "NETWORK_TRANSPORT",
             "facts": {"algorithm": "3DES"}},
            # post-quantum exposure on something a vendor has to replace
            {"evidence_id": "ev-4", "source": "hsm-audit", "collector": "hsm-audit",
             "evidence_type": "AUDIT_OBSERVED", "target": "hsm", "layer": "HSM",
             "facts": {"algorithm": "RSA-2048"}},
            # post-quantum exposure that a recompile can fix
            {"evidence_id": "ev-5", "source": "runtime", "collector": "runtime-probe",
             "evidence_type": "RUNTIME_OBSERVED", "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "ECDSA-P256"}},
            # a version string where an algorithm belongs
            {"evidence_id": "ev-6", "source": "sbom", "collector": "sbom-parser",
             "evidence_type": "STATIC_OBSERVED", "target": "api", "layer": "PLATFORM",
             "facts": {"algorithm": "OpenSSL 3.0.13"}},
            # genuinely unidentified
            {"evidence_id": "ev-7", "source": "cmdb", "collector": "cmdb-import",
             "evidence_type": "IMPORTED", "target": "legacy", "layer": "PLATFORM",
             "facts": {"algorithm": "cryptomodule-v2"}},
        ],
    }


@pytest.fixture()
def graph():
    return build_graph(_payload())


@pytest.fixture()
def db():
    from db.models.base import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def test_a_disallowed_algorithm_is_read_from_the_registry_with_its_source_named():
    reading = intel.classify("DES")

    assert reading["status"] == "DISALLOWED"
    assert reading["reading"] == "ALGORITHM"
    assert reading["verdict_source"] == "algorithm_registry"


def test_a_version_string_is_not_reported_as_unidentified_cryptography():
    version = intel.classify("OpenSSL 3.0.13")
    unknown = intel.classify("cryptomodule-v2")

    assert version["reading"] == "NOT_AN_ALGORITHM"
    assert "version" in version["notes"]
    assert unknown["reading"] == "UNRECOGNIZED"
    assert version["recognized"] is False and unknown["recognized"] is False


def test_weak_capability_is_counted_apart_from_weak_use(graph):
    body = intel.survey(graph)
    weak = body["weak"]

    assert weak["in_use_count"] == 2  # DES on the ledger, 3DES on the load balancer
    assert weak["capability_only_count"] == 1  # DES in OpenSSL's supported list
    assert {entry["asset_name"] for entry in weak["assets"]} == {"Legacy Ledger", "LB-07"}
    assert all(entry["in_use"] for entry in weak["entries"] if entry["asset_name"] == "Legacy Ledger"
               and entry["algorithm"] == "DES")
    capability = weak["capability_only"][0]
    assert capability["asset_name"] == "OpenSSL"
    assert "Capability is not use" in capability["note"]
    assert weak["by_status"]["DISALLOWED"] >= 1
    assert weak["by_status"]["DEPRECATED"] >= 1


def test_an_unidentified_algorithm_is_reported_as_unknown_rather_than_compliant(graph):
    unknown = intel.survey(graph)["unknown"]

    assert unknown["unrecognised_count"] >= 1
    assert unknown["mislabelled_count"] >= 1
    assert any(entry["algorithm"] == "cryptomodule-v2" for entry in unknown["entries"])
    assert any("never as compliant" in line for line in intel.survey(graph)["limits"])


def test_pqc_exposure_separates_what_a_config_can_fix_from_what_a_vendor_must(graph):
    pqc = intel.survey(graph)["pqc"]

    assert pqc["vulnerable_artifacts"] >= 2  # RSA-2048 and ECDSA-P256
    assert pqc["by_algorithm"]["RSA"] == 1
    assert pqc["vendor_bound_blocker_count"] == 1
    assert [asset["asset_name"] for asset in pqc["vendor_bound_blockers"]] == ["HSM-04"]
    assert "procurement conversation" in intel.survey(graph)["next_action"]


def test_the_survey_says_its_verdicts_are_not_evidence(graph):
    body = intel.survey(graph)

    assert any("algorithm registry" in line for line in body["limits"])
    assert "not a readiness score" in body["pqc"]["meaning"]
    assert "vendor to ship a version" in body["pqc"]["meaning"]
    assert body["weak"]["meaning"].startswith("an algorithm this product")
    assert body["pqc"]["meaning"].startswith("artefacts whose algorithm")


def test_one_algorithm_in_use_and_capability_are_not_added_together(graph):
    body = intel.algorithm(graph, "DES")

    assert body["found"] is True
    assert body["status"] == "DISALLOWED"
    assert body["in_use"] == 1
    assert body["capability_only"] == 1
    assert body["by_asset_type_in_use"] == {"APPLICATION": 1}
    assert body["quantum_vulnerable"] is False
    assert "and not in in_use" in " ".join(body["limits"])


def test_an_algorithm_query_by_family_says_that_is_what_it_did(graph):
    body = intel.algorithm(graph, "RSA")

    assert body["found"] is True
    assert body["quantum_vulnerable"] is True
    assert body["by_asset_type"] == {"HSM": 1}
    assert body["algorithm"].startswith("RSA")


def test_an_algorithm_nobody_observed_refuses_to_mean_nothing_uses_it(graph):
    body = intel.algorithm(graph, "MD5")

    assert body["found"] is False
    assert "not that the estate does not use it" in " ".join(body["limits"])


def test_an_empty_query_is_refused(graph):
    with pytest.raises(ValueError):
        intel.algorithm(graph, "   ")


def test_the_intel_endpoint_refuses_to_answer_without_an_observation(api):
    client, session = api

    response = client.get(INTEL_URL)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "NOT_OBSERVED"
    assert "not an empty answer and not a clean one" in body["detail"]


def test_the_algorithm_endpoint_refuses_the_same_way(api):
    client, session = api

    body = client.get(f"{ALGORITHM_URL}/RSA-2048").json()

    assert body["status"] == "NOT_OBSERVED"
    assert body["found"] is False
    assert "different from 'nothing uses it'" in body["detail"]
