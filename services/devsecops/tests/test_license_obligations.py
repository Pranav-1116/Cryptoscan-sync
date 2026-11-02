"""Distribution-model licence obligations.

The review's point is that a licence inventory answers the wrong question: a
GPL-3.0 library used inside the bank obliges nothing, the same library shipped in
a binary obliges a great deal, and offered as a service under AGPL obliges
something else again. These tests pin the model, the families and the fact that
the engine never returns "compliant".
"""

from __future__ import annotations

import pytest

from devsecops.license_obligations import (DISTRIBUTION_MODELS, FAMILIES, OBLIGATIONS,
                                           family_for_licence, obligations_for,
                                           portfolio_obligations)


def _open(licence, *, model, family=None, modified=False):
    result = obligations_for(licence, family=family or family_for_licence(licence), model=model,
                             modified=modified)
    return set(result["open"])


def test_every_obligation_cites_a_clause():
    for duty, row in OBLIGATIONS.items():
        assert row.title and row.cite, duty


def test_the_four_distribution_models_are_the_ones_that_change_an_answer():
    assert set(DISTRIBUTION_MODELS) == {"INTERNAL", "SAAS", "BINARY_SHIPPED",
                                        "SOURCE_DISTRIBUTED"}
    with pytest.raises(ValueError, match="distribution model"):
        obligations_for("MIT", family="PERMISSIVE", model="PILOT")


@pytest.mark.parametrize("licence,family", [
    ("MIT", "PERMISSIVE"), ("Apache-2.0", "PERMISSIVE"), ("BSD-3-Clause", "PERMISSIVE"),
    ("GPL-3.0-only", "STRONG_COPYLEFT"), ("AGPL-3.0-only", "NETWORK_COPYLEFT"),
    ("LGPL-2.1-only", "WEAK_COPYLEFT"), ("MPL-2.0", "WEAK_COPYLEFT"),
    ("Unlicense", "PUBLIC_DOMAIN"), ("CC-BY-NC-4.0", "NON_COMMERCIAL"),
    ("LicenseRef-Proprietary", "PROPRIETARY"), ("", "UNKNOWN"),
])
def test_licence_families(licence, family):
    assert family_for_licence(licence) == family


def test_families_are_a_closed_set():
    for licence in ("MIT", "GPL-3.0-only", "AGPL-3.0-or-later", "LGPL-3.0", "Apache-2.0",
                    "MPL-2.0", "EPL-2.0", "CC-BY-4.0", "Weird-1.0", ""):
        assert family_for_licence(licence) in FAMILIES


def test_permissive_internal_is_not_obligation_free():
    # attribution still applies when a colleague consumes the library
    assert _open("MIT", model="INTERNAL") == {"PATENT_GRANT"}
    assert obligations_for("MIT", family="PERMISSIVE", model="INTERNAL")["verdict"] == "REVIEW"


def test_permissive_shipped_binary_triggers_attribution_and_notice():
    duties = _open("MIT", model="BINARY_SHIPPED")
    assert duties == {"ATTRIBUTION", "NOTICE_FILE", "NOTICE_PRESERVATION", "PATENT_GRANT"}


def test_apache_shipped_adds_the_patent_termination_duty():
    duties = _open("Apache-2.0", model="BINARY_SHIPPED")
    assert {"PATENT_GRANT", "NOTICE_FILE", "ATTRIBUTION", "NOTICE_PRESERVATION"} <= duties
    # Apache only demands change notices for a component the bank has modified
    assert "MODIFICATION_DISCLOSURE" not in duties
    assert "MODIFICATION_DISCLOSURE" in _open("Apache-2.0", model="BINARY_SHIPPED",
                                              modified=True)


def test_gpl_right_held_internal_triggers_nothing():
    result = obligations_for("GPL-3.0-only", family="STRONG_COPYLEFT", model="INTERNAL")
    assert result["open"] == []
    assert result["verdict"] == "NO_ACTION"
    assert "no duties identified" in result["statement"]


def test_gpl_shipped_binary_triggers_source_disclosure():
    duties = _open("GPL-3.0-only", model="BINARY_SHIPPED")
    assert {"SOURCE_DISCLOSURE", "DERIVATIVE_SCOPE", "NOTICE_FILE", "ATTRIBUTION"} <= duties


def test_gpl_shipped_and_modified_adds_the_modification_duty():
    unmodified = _open("GPL-3.0-only", model="BINARY_SHIPPED")
    modified = _open("GPL-3.0-only", model="BINARY_SHIPPED", modified=True)
    assert modified - unmodified == {"MODIFICATION_DISCLOSURE"}
    assert "RELINKING" not in modified


def test_lgpl_shipped_modified_requires_relinking_and_the_library_source():
    duties = _open("LGPL-2.1-only", model="BINARY_SHIPPED", modified=True)
    assert "RELINKING" in duties
    # conveying object code means the LGPL library's own source travels too; what
    # LGPL does *not* do is reach the bank's own work the way the GPL would
    assert "SOURCE_DISCLOSURE" in duties
    assert "DERIVATIVE_SCOPE" in duties


def test_agpl_offered_as_a_service_triggers_the_network_offer():
    duties = _open("AGPL-3.0-only", model="SAAS")
    assert duties == {"DERIVATIVE_SCOPE", "NETWORK_SOURCE_OFFER"}


def test_agpl_internal_asks_about_derivatives_but_not_the_network_offer():
    duties = _open("AGPL-3.0-only", model="INTERNAL")
    assert duties == {"DERIVATIVE_SCOPE", "MODIFICATION_DISCLOSURE"} - {"MODIFICATION_DISCLOSURE"}
    assert "NETWORK_SOURCE_OFFER" not in duties


def test_gpl_as_a_service_is_not_a_distribution():
    # SaaS is not conveyance: GPL duties do not fire, AGPL's do
    assert "SOURCE_DISCLOSURE" not in _open("GPL-3.0-only", model="SAAS")


def test_source_distribution_adds_the_source_form_duty():
    duties = _open("GPL-3.0-only", model="SOURCE_DISTRIBUTED")
    assert {"SOURCE_DISCLOSURE", "NOTICE_FILE", "DERIVATIVE_SCOPE", "ATTRIBUTION"} <= duties


def test_mpl_requires_file_level_source_not_whole_work():
    duties = _open("MPL-2.0", model="BINARY_SHIPPED", modified=True)
    assert "SOURCE_DISCLOSURE" in duties
    assert "DERIVATIVE_SCOPE" in duties


def test_a_non_commercial_licence_is_flagged_for_counsel_in_every_model():
    for model in DISTRIBUTION_MODELS:
        result = obligations_for("CC-BY-NC-4.0", family="NON_COMMERCIAL", model=model)
        assert result["verdict"] == "NEEDS_LEGAL", model
        # a bank's internal use is commercial use, so INTERNAL is not a safe harbour
        assert result["open"] == ["NC_USE_RESTRICTION"], model


def test_a_proprietary_licence_under_a_shipped_model_needs_legal_review():
    result = obligations_for("LicenseRef-Acme-EULA", family="PROPRIETARY",
                             model="BINARY_SHIPPED")
    assert result["verdict"] == "NEEDS_LEGAL"


def test_an_unidentified_licence_is_never_assumed_permissive():
    result = obligations_for("", family="UNKNOWN", model="INTERNAL")
    assert result["open"] == ["TERMS_UNKNOWN"]
    assert result["verdict"] == "NEEDS_LEGAL"
    assert "TERMS_UNKNOWN" in result["statement"]


def test_the_engine_never_returns_compliant():
    for model in DISTRIBUTION_MODELS:
        for licence in ("MIT", "Apache-2.0", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-3.0",
                        "MPL-2.0", "", "LicenseRef-X"):
            verdict = obligations_for(licence, family=family_for_licence(licence),
                                      model=model)["verdict"]
            assert verdict in {"NO_ACTION", "REVIEW", "NEEDS_LEGAL"}


def test_an_unknown_family_falls_back_to_classification_by_identifier():
    # a caller that passes a family *name* by mistake gets the identifier path,
    # not an empty obligation list
    result = obligations_for("GPL-3.0-only", family="strong_copyleft", model="BINARY_SHIPPED")
    assert "SOURCE_DISCLOSURE" in result["open"]


def test_obligation_rows_carry_their_title_and_clause():
    result = obligations_for("GPL-3.0-only", family="STRONG_COPYLEFT", model="BINARY_SHIPPED")
    for row in result["obligations"]:
        assert row["id"] in OBLIGATIONS
        assert row["title"] and row["cite"]
        assert row["state"] in {"TRIGGERED", "NOT_TRIGGERED"}


def _portfolio(model):
    return portfolio_obligations([
        {"name": "requests", "licence": "Apache-2.0"},
        {"name": "openssl", "licence": "Apache-2.0"},
        {"name": "busybox", "licence": "GPL-2.0-only", "modified": True},
        {"name": "mystery", "licence": ""},
    ], model=model)


def test_portfolio_groups_duties_across_components():
    report = _portfolio("BINARY_SHIPPED")
    counts = report["counts"]
    assert counts["ATTRIBUTION"] == 3          # two Apache, one GPL
    assert counts["SOURCE_DISCLOSURE"] == 1
    assert report["unknown_components"] == ["mystery"]
    assert report["verdict"] == "NEEDS_LEGAL"


def test_portfolio_internal_reports_no_distribution_duties():
    report = _portfolio("INTERNAL")
    assert set(report["counts"]) == {"PATENT_GRANT", "TERMS_UNKNOWN"}
    assert report["verdict"] == "NEEDS_LEGAL"       # the unlabelled component still blocks


def test_portfolio_classifies_when_no_family_mapper_is_given():
    report = _portfolio("BINARY_SHIPPED")
    families = {row["component"]: row["family"] for row in report["components"]}
    assert families["busybox"] == "STRONG_COPYLEFT"
    assert families["mystery"] == "UNKNOWN"


def test_portfolio_accepts_an_external_family_mapper():
    report = portfolio_obligations([{"name": "x", "licence": "LicenseRef-Inhouse"}],
                                   model="INTERNAL",
                                   family_of=lambda _licence: "permissive")
    assert report["unknown_components"] == []
    assert report["components"][0]["family"] == "PERMISSIVE"


def test_portfolio_counts_distinct_duties_not_rows():
    report = portfolio_obligations([{"name": f"c{index}", "licence": "MIT"}
                                    for index in range(5)], model="BINARY_SHIPPED")
    assert len(report["duties"]) == len(report["counts"]) == 4
    assert report["counts"]["ATTRIBUTION"] == 5
    assert report["statement"].startswith("5 component(s) under BINARY_SHIPPED")
