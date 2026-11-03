"""Guide 165 tests — the questions a TechBOM answers, and the rules its answers inherit."""

from __future__ import annotations

import pytest

from cbom import techbom as t
from cbom import techbom_queries as q


def asset(kind, name, **kwargs):
    kwargs.setdefault("evidence_ids", [f"EVD-{name}"])
    return {"kind": kind, "name": name, **kwargs}


def claim(source, relation, target, basis="config-parse", **kwargs):
    return {"from": source, "relation": relation, "to": target, "basis": basis,
            "evidence_ids": kwargs.pop("evidence_ids", ["EVD-1"]), **kwargs}


def estate(openssl="3.0.13", certificate="CERT-9281", hsm_supports=("RSA-2048",),
           **kwargs):
    return {
        "schema": t.ESTATE_SCHEMA, "estate_id": f"EST-{openssl}",
        "expected": {"BUSINESS_SYSTEM": 1, "APPLICATION": 2, "HSM": 2},
        "gaps": [{"kind": "HSM", "reason": "1 HSM collector unavailable"}],
        "assets": [
            asset("BUSINESS_SYSTEM", "Payments", criticality="CRITICAL",
                  owner="Payments Platform"),
            asset("APPLICATION", "Payments API", version="2026.11.02"),
            asset("APPLICATION", "Payments Batch", version="2026.10.01",
                  status="LEGACY"),
            asset("IMAGE", "payments-api:2026.11.02", version="sha256:ABC"),
            asset("PACKAGE", "openssl", version=openssl),
            asset("CRYPTO_ASSET", "AES-256-GCM", evidence_type="RUNTIME_OBSERVED"),
            asset("CRYPTO_ASSET", "RSA-2048", evidence_type="STATIC_OBSERVED"),
            asset("NETWORK_ENDPOINT", "payments.bank.example:443",
                  tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                  sni="payments.bank.example", alpn="h2", mtls=True),
            asset("WAF", "waf-01"),
            asset("LOAD_BALANCER", "External-LB-01", tls_version="TLSv1.2"),
            asset("API_GATEWAY", "payments-gw", tls_version="TLSv1.3"),
            asset("SERVICE_MESH", "payments-mesh", mtls=True),
            asset("CERTIFICATE", certificate, not_after="2028-04-01T00:00:00Z"),
            asset("PUBLIC_KEY", f"{certificate}-key"),
            asset("ALGORITHM", "ECDSA P-256"),
            asset("HSM", "HSM-01"),
            asset("FIRMWARE", "HSM fw 8.4", version="8.4", supports=list(hsm_supports)),
            asset("VENDOR_PRODUCT", "HSM-9000", version="8.4"),
            asset("VENDOR", "Vendor X"),
            asset("DATABASE", "payments-db"),
        ],
        "claims": [
            claim("Payments", "CONTAINS", "Payments API", basis="agent-inventory"),
            claim("Payments", "CONTAINS", "Payments Batch", basis="cmdb-import"),
            claim("Payments API", "PROVIDES", "payments-api"),
            claim("payments-api", "RUNS", "payments-api-7f9", basis="api-poll"),
            claim("payments-api-7f9", "FROM_IMAGE", "payments-api:2026.11.02",
                  basis="api-poll"),
            claim("payments-api:2026.11.02", "SHIPS", "openssl", basis="sbom-import"),
            claim("Payments API", "USES_CRYPTO", "AES-256-GCM", basis="runtime-probe"),
            claim("Payments API", "USES_CRYPTO", "RSA-2048", basis="sbom-import"),
            claim("Payments API", "EXPOSES", "payments.bank.example:443"),
            claim("Payments API", "USES_HSM", "HSM-01"),
            claim("Payments API", "STORES_IN", "payments-db"),
            claim("payments.bank.example:443", "PROTECTED_BY", "waf-01"),
            claim("waf-01", "FORWARDS_TO", "External-LB-01"),
            claim("External-LB-01", "FORWARDS_TO", "payments-gw"),
            claim("payments-gw", "FORWARDS_TO", "payments-mesh"),
            claim("payments-mesh", "ROUTES_TO", "Payments API"),
            claim("payments.bank.example:443", "PRESENTS", certificate,
                  basis="packet-capture"),
            claim(certificate, "CONTAINS_KEY", f"{certificate}-key",
                  basis="packet-capture"),
            claim(f"{certificate}-key", "USES_ALGORITHM", "ECDSA P-256",
                  basis="packet-capture"),
            claim("HSM-01", "RUNS_FIRMWARE", "HSM fw 8.4", basis="api-poll"),
            claim("HSM-01", "HAS_MODEL", "HSM-9000", basis="vendor-datasheet"),
            claim("HSM-9000", "SUPPLIED_BY", "Vendor X", basis="vendor-datasheet"),
        ],
    }


@pytest.fixture()
def clean_bom():
    return t.build(estate())


# --------------------------------------------------------------------------- #
# roll-up
# --------------------------------------------------------------------------- #

def test_a_rollup_counts_the_technology_a_system_actually_holds(clean_bom):
    profile = q.rollup(clean_bom, system="Payments")["systems"][0]
    assert profile["criticality"] == "CRITICAL"
    assert profile["counts"]["APPLICATION"] == 2  # Payments API proven, Batch declared
    assert profile["counts"]["CERTIFICATE"] == 1
    assert profile["counts"]["HSM"] == 1
    assert profile["proven_assets"] >= 8
    assert profile["by_confidence"]["PROVEN"] == profile["proven_assets"]
    assert "2 applications" in profile["statement"]
    assert "certificates" not in profile["statement"].split(":")[-1].split(";")[0]


def test_a_rollup_counts_the_declared_assets_and_says_which_they_are(clean_bom):
    profile = q.rollup(clean_bom, system="Payments")["systems"][0]
    # Payments Batch is connected by a CMDB import: it is in the system, and the profile
    # says the containment is declared rather than proven
    assert profile["counts"]["APPLICATION"] == 2
    assert profile["declared_only"]["APPLICATION"] == 1
    assert profile["by_confidence"]["DECLARED"] == profile["declared_only_assets"]
    assert "declared only" in profile["statement"]


def test_taint_propagates_so_a_declared_hop_makes_everything_above_it_declared():
    data = {
        "schema": t.ESTATE_SCHEMA,
        "assets": [asset("BUSINESS_SYSTEM", "Payments"),
                   asset("APPLICATION", "Payments API"),
                   asset("CRYPTO_ASSET", "RSA-2048", evidence_type="STATIC_OBSERVED")],
        "claims": [claim("Payments", "CONTAINS", "Payments API", basis="cmdb-import"),
                   claim("Payments API", "USES_CRYPTO", "RSA-2048",
                         basis="sbom-import")],
    }
    profile = q.rollup(t.build(data), system="Payments")["systems"][0]
    assert profile["counts"] == {"APPLICATION": 1, "CRYPTO_ASSET": 1}
    assert profile["declared_only"] == {"APPLICATION": 1, "CRYPTO_ASSET": 1}
    assert profile["proven_assets"] == 0
    assert "0 proven" in profile["statement"]


def test_a_rollup_refuses_something_that_is_not_a_business_system(clean_bom):
    with pytest.raises(ValueError, match="not a business system"):
        q.rollup(clean_bom, system="Payments API")
    with pytest.raises(ValueError, match="not a business system"):
        q.rollup(clean_bom, system="nothing-here")


def test_a_portfolio_rollup_lists_every_system_with_its_size(clean_bom):
    body = q.rollup(clean_bom)
    assert len(body["systems"]) == 1
    assert "Payments" in body["statement"]


# --------------------------------------------------------------------------- #
# request paths
# --------------------------------------------------------------------------- #

def test_a_path_carries_the_crypto_each_hop_negotiates(clean_bom):
    body = q.path(clean_bom, source="payments.bank.example:443",
                  target="Payments API")
    route = body["paths"][0]
    names = [hop["name"] for hop in route["hops"]]
    assert names == ["payments.bank.example:443", "waf-01", "External-LB-01",
                     "payments-gw", "payments-mesh", "Payments API"]
    start = route["hops"][0]
    assert start["crypto"]["tls_version"] == "TLSv1.3"
    assert start["crypto"]["alpn"] == "h2"
    assert start["certificate"] == "TECH-CERT-001"
    assert route["statement"].startswith("payments.bank.example:443 → waf-01")


def test_a_hop_with_no_crypto_recorded_says_so_instead_of_looking_clean(clean_bom):
    route = q.path(clean_bom, source="payments.bank.example:443",
                   target="Payments API")["paths"][0]
    waf = next(hop for hop in route["hops"] if hop["name"] == "waf-01")
    assert waf["crypto"] == {}
    assert waf["crypto_recorded"] is False
    assert waf["note"] == "NOT_RECORDED"
    assert route["crypto_recorded"].endswith("/6")


def test_a_path_reports_its_weakest_edge(clean_bom):
    route = q.path(clean_bom, source="payments.bank.example:443",
                   target="Payments API")["paths"][0]
    assert route["weakest"] == "CONFIGURED"
    assert route["unproven_edges"] == 0


def test_a_path_refuses_an_asset_the_bom_does_not_hold(clean_bom):
    with pytest.raises(ValueError, match="not in this TechBOM"):
        q.path(clean_bom, source="nowhere.example:443")
    with pytest.raises(ValueError, match="not in this TechBOM"):
        q.path(clean_bom, source="payments.bank.example:443", target="nowhere")


def test_a_path_with_no_route_says_so(clean_bom):
    body = q.path(clean_bom, source="Vendor X", target="Payments API")
    assert body["paths"] == []
    assert "no route" in body["statement"]


def test_a_path_does_not_wander_into_the_key_layer(clean_bom):
    body = q.path(clean_bom, source="Payments API")
    kinds = {hop["kind"] for route in body["paths"] for hop in route["hops"]}
    assert "HSM" not in kinds and "CERTIFICATE" not in kinds


# --------------------------------------------------------------------------- #
# impact
# --------------------------------------------------------------------------- #

def test_impact_counts_the_vocabulary_an_owner_asks_for(clean_bom):
    body = q.impact(clean_bom, query="AES-256-GCM")
    assert body["counts"]["APPLICATION"] == 1
    assert body["counts"]["BUSINESS_SYSTEM"] == 1
    assert body["critical_systems"] == ["TECH-SYS-001"]
    assert body["systems"] == ["TECH-SYS-001"]
    assert body["seeds"] == ["TECH-CRY-001"]
    assert "1 critical system(s)" in body["statement"]


def test_impact_separates_what_is_only_declared(clean_bom):
    body = q.impact(clean_bom, query="RSA-2048")
    # the application's use of RSA-2048 is a manifest row, so the application and the
    # system above it are declared rather than counted
    assert "APPLICATION" not in body["counts"]
    assert body["systems"] == []
    assert body["declared_only"]


def test_impact_names_a_blocker_where_it_sits(clean_bom):
    body = q.impact(clean_bom, query="AES-256-GCM",
                    required_algorithms=["ML-KEM-768"])
    codes = {row["code"] for row in body["pqc_blockers"]}
    assert "HSM_PQC_CAPABILITY_UNKNOWN" in codes
    assert "FIRMWARE_UPGRADE_REQUIRED" in codes
    assert body["blocker_counts"]["FIRMWARE_UPGRADE_REQUIRED"] == 1
    assert all(row["who_acts"] for row in body["pqc_blockers"])


def test_impact_does_not_invent_an_hsm_blocker_without_a_requirement(clean_bom):
    body = q.impact(clean_bom, query="AES-256-GCM")
    assert body["pqc_blockers"] == []


def test_impact_flags_a_certificate_that_outlives_the_migration(clean_bom):
    body = q.impact(clean_bom, query="ECDSA P-256", deadline="2027-01-01")
    codes = {row["code"] for row in body["pqc_blockers"]}
    assert "CERTIFICATE_LIFECYCLE_INCOMPATIBLE" in codes


def test_impact_flags_an_application_whose_crypto_is_unknown(clean_bom):
    body = q.impact(clean_bom, query="Payments Batch")
    codes = {row["code"] for row in body["pqc_blockers"]}
    assert "LEGACY_APPLICATION_UNKNOWN" in codes


def test_impact_for_nothing_says_so(clean_bom):
    body = q.impact(clean_bom, query="quantum-toaster")
    assert body["counts"] == {}
    assert "matches" in body["statement"]
    assert body["not_proven"]


# --------------------------------------------------------------------------- #
# time
# --------------------------------------------------------------------------- #

def test_one_snapshot_is_not_a_timeline():
    body = q.timeline([t.build(estate())])
    assert body["measurable"] is False
    assert body["changes"] == []
    assert "state, not a series" in body["statement"]


def test_a_timeline_names_each_change_in_its_own_category():
    body = q.timeline([t.build(estate(openssl="3.0.13")),
                       t.build(estate(openssl="3.0.11")),
                       t.build(estate(openssl="3.0.11", certificate="CERT-9821"))])
    assert body["measurable"] is True
    assert body["by_change"]["TECHNOLOGY_VERSION_CHANGED"] == 1
    assert body["by_category"]["CERTIFICATE_CHANGED"] >= 1
    version = next(row for row in body["changes"]
                   if row["change"] == "TECHNOLOGY_VERSION_CHANGED")
    assert version["detail"] == "openssl: 3.0.13 → 3.0.11"
    assert version["step"] == 1
    assert [row["assets"] for row in body["series"]] == [20, 20, 20]


def test_a_timeline_refuses_a_document_that_is_not_a_snapshot():
    with pytest.raises(ValueError, match="snapshots"):
        q.timeline([{"schema": "something/else"}])


# --------------------------------------------------------------------------- #
# threat context
# --------------------------------------------------------------------------- #

def _event(**overrides):
    return {"kind": "TLS_DOWNGRADE", "asset": "payments.bank.example:443",
            "before": "TLSv1.3", "after": "TLSv1.2", "evidence_ids": ["EV-1"],
            **overrides}


def test_a_threat_event_becomes_a_correlated_pattern_with_the_estate_behind_it(clean_bom):
    body = q.threat_context(clean_bom, _event())
    assert body["pattern"] == "CORRELATED_PATTERN"
    assert body["event"]["asset"] == "TECH-EP-001"
    assert body["systems"] == [{"id": "TECH-SYS-001", "name": "Payments",
                                "criticality": "CRITICAL"}]
    assert body["technology"][0]["name"] == "Payments API"
    assert body["change"] == {"attribute": "tls_version", "from": "TLSv1.3",
                              "to": "TLSv1.2"}
    assert body["event"]["evidence_ids"] == ["EV-1"]
    assert "business system Payments" in body["statement"]


def test_a_certificate_change_names_the_certificate_attribute(clean_bom):
    body = q.threat_context(clean_bom, _event(kind="CERTIFICATE_CHANGE",
                                              before="CERT-9281", after="CERT-9821"))
    assert body["change"]["attribute"] == "certificate"
    assert {row["relation"] for row in body["related"]} >= {"PRESENTS"}


def test_a_threat_context_will_not_name_an_asset_it_does_not_hold(clean_bom):
    with pytest.raises(ValueError, match="not in this TechBOM"):
        q.threat_context(clean_bom, _event(asset="external-lb-99"))


def test_an_event_without_evidence_or_a_known_kind_is_refused(clean_bom):
    with pytest.raises(ValueError, match="rumour"):
        q.threat_context(clean_bom, _event(evidence_ids=[]))
    with pytest.raises(ValueError, match="not one of"):
        q.threat_context(clean_bom, _event(kind="VIBES"))


def test_a_context_says_what_it_cannot_prove(clean_bom):
    body = q.threat_context(clean_bom, _event())
    assert any("caused" in line for line in body["not_proven"])


# --------------------------------------------------------------------------- #
# promotion
# --------------------------------------------------------------------------- #

def test_imported_becomes_observed_with_new_evidence_and_keeps_its_history(clean_bom):
    imported = next(row for row in clean_bom["claims"]
                    if row["confidence"] == "IMPORTED"
                    and row["relation"] == "USES_CRYPTO")
    body = q.verify(imported, basis="runtime-probe", evidence_ids=["EV-PROBE-1"],
                    at="2026-11-03T00:00:00Z")
    assert body["confidence"] == "OBSERVED"
    assert body["promoted_from"] == "IMPORTED"
    assert body["history"][0]["confidence"] == "IMPORTED"
    assert "EV-PROBE-1" in body["evidence_ids"]
    assert "kept in the history" in body["statement"]


def test_a_promotion_needs_a_stronger_basis(clean_bom):
    imported = next(row for row in clean_bom["claims"]
                    if row["confidence"] == "IMPORTED")
    with pytest.raises(t.ClaimRefused) as caught:
        q.verify(imported, basis="cmdb-import", evidence_ids=["EV-2"])
    assert caught.value.code == "NOT_A_VERIFICATION"


def test_a_promotion_needs_evidence_the_claim_did_not_already_have(clean_bom):
    imported = next(row for row in clean_bom["claims"]
                    if row["confidence"] == "IMPORTED")
    with pytest.raises(t.ClaimRefused) as caught:
        q.verify(imported, basis="runtime-probe",
                 evidence_ids=imported["evidence_ids"])
    assert caught.value.code == "NO_NEW_EVIDENCE"


def test_a_promotion_cannot_be_built_on_proximity(clean_bom):
    imported = next(row for row in clean_bom["claims"]
                    if row["confidence"] == "IMPORTED")
    with pytest.raises(t.ClaimRefused) as caught:
        q.verify(imported, basis="co-occurrence", evidence_ids=["EV-3"])
    assert caught.value.code == "CO_OCCURRENCE_NOT_EVIDENCE"


# --------------------------------------------------------------------------- #
# the whole module refuses a foreign document
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("call", [
    lambda doc: q.rollup(doc),
    lambda doc: q.path(doc, source="x"),
    lambda doc: q.impact(doc, query="x"),
    lambda doc: q.threat_context(doc, _event()),
])
def test_every_answer_refuses_a_document_that_is_not_a_techbom(call):
    with pytest.raises(ValueError, match="techbom/1"):
        call({"schema": "cryptoscan.something/1", "by_key": {}})
