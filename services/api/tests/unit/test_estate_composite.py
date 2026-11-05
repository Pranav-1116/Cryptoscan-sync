"""COMPOSITE simulation: a sequence of changes, applied once, in order.

One scenario answers one question. A migration is usually three, and running them
separately leaves the operator to reconcile three BOM diffs by hand — with the
middle step's diff computed against an estate that no longer exists. ``COMPOSITE``
applies a bounded list of primitive scenarios to *one* copy, in the order given, and
reports the BOM diff of the whole sequence.

The failure modes this file guards against:

* a sequence that behaves like a script. Branching, loops, a clock and nesting are
  refused with a reason, not approximated;
* a preview read as a prediction. Steps are previewed independently, against the
  evidence as it stands, and the payload says so — a later step sees what an earlier
  step wrote only when the run happens;
* "step 2 matched nothing" read as "step 2 was skipped". It is reported with the run,
  because an unmatched step is a fact about the estate.
"""
from __future__ import annotations

import pytest

from shared_models import estate_twin as twin
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api
from test_estate_twin import _payload

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"

# The estate from test_estate_twin: `api` holds AES-256-GCM, `lb` holds AES-256-GCM over
# TLSv1.3 and AES-128-GCM over TLSv1.2, `ossl` lists supported_algorithms only.
SEQUENCE = [
    {"kind": "REPLACE_ALGORITHM", "from": "AES-128-GCM", "to": "AES-256-GCM"},
    {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM"},
]


@pytest.fixture()
def graph():
    return build_graph(_payload())


def _payload_with_extra_evidence(*records: dict) -> dict:
    """``_payload()`` plus evidence today's estate no longer holds."""
    payload = _payload()
    payload["evidence"] = [*payload["evidence"], *records]
    return payload


def _discover(http) -> dict:
    created = http.post(f"{BASE}/discover", json=_payload())
    assert created.status_code == 200, created.text
    return created.json()


# -- order is the point ----------------------------------------------------- #


def test_a_later_step_sees_the_facts_an_earlier_step_wrote(graph):
    result = twin.simulate(graph, {"kind": "COMPOSITE", "steps": SEQUENCE})

    assert result["status"] == "SIMULATED"
    report = {row["step"]: row for row in result["steps"]}
    # step 1 rewrites the TLSv1.2 record to AES-256-GCM; step 2 retires AES-256-GCM,
    # so it matches that record *because* step 1 moved it there
    assert report[1]["matched_evidence"] == 1
    assert report[2]["matched_evidence"] == 3


def test_every_effect_says_which_step_produced_it(graph):
    result = twin.simulate(graph, {"kind": "COMPOSITE", "steps": SEQUENCE})

    effects = result["effects"]
    assert effects
    assert {effect["step"] for effect in effects} == {1, 2}
    first = next(effect for effect in effects if effect["step"] == 1)
    assert first["before"]["algorithm"] == "AES-128-GCM"
    assert first["after"]["algorithm"] == "AES-256-GCM"
    assert first["step_kind"] == "REPLACE_ALGORITHM"


def test_the_bom_diff_is_the_whole_sequence_not_one_diff_per_step(graph):
    result = twin.simulate(graph, {"kind": "COMPOSITE", "steps": SEQUENCE})

    # the answer is the state after the last step: a half-migrated estate is not
    # something anyone asked about, so intermediate BOMs are not projected
    assert result["bom_changes"] is True
    assert result["bom_diff"]
    assert "steps" in result and len(result["steps"]) == 2


def test_a_composite_changes_nothing_live(graph):
    before = graph.fingerprint()

    result = twin.simulate(graph, {"kind": "COMPOSITE", "steps": SEQUENCE})

    assert result["live_state_modified"] is False
    assert result["live_projection_unchanged"] is True
    assert graph.fingerprint() == before


def test_a_step_that_matches_nothing_is_reported_and_does_not_abort_the_sequence(graph):
    result = twin.simulate(
        graph,
        {
            "kind": "COMPOSITE",
            "steps": [
                {"kind": "DISABLE_PROTOCOL", "from": "SSLv3"},  # the estate holds no such protocol
                {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM"},
            ],
        },
    )

    assert result["status"] == "SIMULATED", "one empty step does not empty the answer"
    report = {row["step"]: row for row in result["steps"]}
    assert report[1]["matched_nothing"] is True
    # two, not three: nothing rewrote the TLSv1.2 record on the way, so it still
    # holds AES-128-GCM when step 2 looks at it
    assert report[2]["matched_evidence"] == 2


def test_a_composite_whose_steps_all_match_nothing_is_no_match_not_no_impact(graph):
    result = twin.simulate(
        graph,
        {"kind": "COMPOSITE", "steps": [{"kind": "DISABLE_PROTOCOL", "from": "SSLv3"}]},
    )

    assert result["status"] == "NO_MATCH"
    assert "not 'no impact'" in result["detail"]
    assert result["steps"][0]["matched_nothing"] is True


def test_a_custom_expression_can_be_a_step(graph):
    result = twin.simulate(
        graph,
        {
            "kind": "COMPOSITE",
            "steps": [
                {
                    "kind": "CUSTOM",
                    "expression": {
                        "when": {"fact": "algorithm", "op": "eq", "value": "AES-128-GCM"},
                        "then": {"set": {"algorithm": "AES-256-GCM"}},
                    },
                },
                {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM"},
            ],
        },
    )

    assert result["status"] == "SIMULATED"
    report = {row["step"]: row for row in result["steps"]}
    assert report[1]["kind"] == "CUSTOM"
    assert report[1]["matched_evidence"] == 1


# -- what a sequence refuses to be ------------------------------------------ #


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        (None, "needs 'steps'"),
        ([], "asks nothing"),
        ([{"kind": "DISABLE_PROTOCOL", "from": "TLSv1.0"}] * 6, "exceeds the 5-step bound"),
        ([{"kind": "CASCADE_ALGORITHM_BREAK", "from": "RSA"}], "Cascades and composites do not nest"),
        ([{"kind": "COMPOSITE", "steps": []}], "Cascades and composites do not nest"),
        ([{"kind": "INVENT_A_SCENARIO"}], "must be one of"),
        ([{"kind": "CHANGE_KEY_SIZE", "from": "AES-128-GCM"}], "step 1 (CHANGE_KEY_SIZE)"),
        (["not a scenario"], "step 1 is not a scenario object"),
    ],
)
def test_a_sequence_outside_the_grammar_is_refused(graph, steps, expected):
    result = twin.simulate(graph, {"kind": "COMPOSITE", "steps": steps})

    assert result["status"] == "INVALID_SCENARIO"
    assert expected in result["detail"], result["detail"]


def test_the_step_bound_is_stated_rather_than_implied(graph):
    result = twin.simulate(graph, {"kind": "COMPOSITE", "steps": [{"kind": "RETIRE_ALGORITHM", "from": "x"}] * 6})

    assert "migration plan, not a simulation" in result["detail"]


# -- preview ---------------------------------------------------------------- #


def test_the_preview_counts_each_step_and_says_they_were_counted_independently(graph):
    preview = twin.preview(graph, {"kind": "COMPOSITE", "steps": SEQUENCE})

    assert preview["status"] == "WOULD_MATCH"
    counts = [row["matched_evidence"] for row in preview["steps"]]
    # step 2 counts the two records that already hold AES-256-GCM — not the TLSv1.2
    # record that step 1 will turn into one, because that copy does not exist yet
    assert counts == [1, 2]
    assert preview["matched_evidence"] == 3
    assert "can match more than this preview counts" in preview["note"]


def test_a_preview_names_the_steps_that_would_match_nothing(graph):
    preview = twin.preview(
        graph,
        {
            "kind": "COMPOSITE",
            "steps": [
                {"kind": "DISABLE_PROTOCOL", "from": "SSLv3"},
                {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM"},
            ],
        },
    )

    assert preview["steps_matching_nothing"] == [1]


# -- the served workspace --------------------------------------------------- #


def test_the_catalog_lists_the_composite_as_a_scenario_family(api):
    http, _session = api
    _discover(http)

    body = http.get(f"{BASE}/simulation/catalog").json()
    entry = {row["kind"]: row for row in body["kinds"]}["COMPOSITE"]

    assert entry["mode"] == "SCENARIO"
    assert entry["inputs"] == ["steps"]
    assert entry["does_not_answer"]


def test_the_workspace_runs_and_returns_the_sequence(api):
    http, _session = api
    _discover(http)

    response = http.post(
        f"{BASE}/simulation/run",
        json={"kind": "COMPOSITE", "steps": SEQUENCE, "persist": False},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "SIMULATED"
    assert [row["kind"] for row in body["steps"]] == ["REPLACE_ALGORITHM", "RETIRE_ALGORITHM"]
    assert body["plan"]["status"] == "WOULD_MATCH"


def test_the_workspace_refuses_an_invalid_sequence_before_it_runs(api):
    http, _session = api
    _discover(http)

    response = http.post(
        f"{BASE}/simulation/plan",
        json={"kind": "COMPOSITE", "steps": [{"kind": "CASCADE_ALGORITHM_BREAK", "from": "RSA"}]},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "invalid_scenario"


def test_the_twin_route_accepts_a_sequence(api):
    http, _session = api
    _discover(http)

    response = http.post(
        f"{BASE}/twin/simulate",
        json={"kind": "COMPOSITE", "steps": SEQUENCE, "persist": False},
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "SIMULATED"


def test_the_workspace_carries_a_custom_expression_to_the_engine(api):
    """The console posts to /simulation/run; that request model has to carry the query.

    It once did not, and the route silently dropped ``expression`` — the engine then
    refused a CUSTOM scenario the console had filled in correctly.
    """
    http, _session = api
    _discover(http)

    response = http.post(
        f"{BASE}/simulation/run",
        json={
            "kind": "CUSTOM",
            "expression": {
                "when": {"fact": "algorithm", "op": "eq", "value": "AES-128-GCM"},
                "then": {"set": {"algorithm": "AES-256-GCM"}},
            },
            "persist": False,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "SIMULATED", body.get("detail")
    assert body["effects"][0]["before"]["algorithm"] == "AES-128-GCM"


# -- an ordered migration across time, from stored snapshots ---------------- #
#
# "Apply step 1 to today's estate, then step 2 to the Q2 snapshot" is a real migration
# shape, and the only honest way to model it is to evaluate each step against *stored
# evidence*. There is still no clock: the step names a captured snapshot, and a step
# whose snapshot cannot be found is refused rather than quietly evaluated against today.


def test_an_as_of_step_is_matched_against_its_snapshot_and_applied_to_the_estate(graph):
    # the snapshot holds a record today's estate does not: TLSv1.1 on the load balancer
    historical = build_graph(_payload_with_extra_evidence(
        {"evidence_id": "ev-old", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
         "target": "lb", "layer": "NETWORK_TRANSPORT",
         "facts": {"protocol": "TLSv1.1"}}
    ))
    result = twin.simulate(
        graph,
        {"kind": "COMPOSITE", "steps": [
            {"kind": "REPLACE_ALGORITHM", "from": "AES-128-GCM", "to": "AES-256-GCM"},
            {"kind": "DISABLE_PROTOCOL", "from": "TLSv1.1", "as_of": "twin:q2"},
        ]},
        as_of_graphs={"twin:q2": historical},
    )

    assert result["status"] == "SIMULATED"
    steps = {row["step"]: row for row in result["steps"]}
    assert steps[1]["as_of"] is None
    # step 2 matches the snapshot's TLSv1.1 record, which today's estate no longer holds
    assert steps[2]["as_of"] == "twin:q2"
    assert steps[2]["evaluated_against_snapshot"] is True
    assert steps[2]["not_in_current_estate"] == 1
    assert steps[2]["matched_evidence"] == 0
    # and the copy is untouched by a record that has left: retired, never resurrected
    assert result["as_of"]["not_in_current_estate"] == 1
    assert "never resurrected" in result["as_of"]["meaning"]


def test_an_as_of_step_that_still_exists_edits_todays_record(graph):
    # the snapshot recorded AES-128-GCM on the load balancer; today's estate still does,
    # so the plan is evaluated against the snapshot and the edit lands on today's record
    historical = build_graph(_payload())
    result = twin.simulate(
        graph,
        {"kind": "COMPOSITE", "steps": [
            {"kind": "REPLACE_ALGORITHM", "from": "AES-128-GCM", "to": "AES-256-GCM",
             "as_of": "twin:q2"},
        ]},
        as_of_graphs={"twin:q2": historical},
    )

    assert result["status"] == "SIMULATED"
    assert result["steps"][0]["matched_from_snapshot"] == 1
    effect = next(item for item in result["effects"] if item["step"] == 1)
    assert effect["evaluated_against"] == "twin:q2"
    assert effect["before"]["algorithm"] == "AES-128-GCM"
    assert effect["after"]["algorithm"] == "AES-256-GCM"
    assert result["as_of"]["snapshots"] == ["twin:q2"]


def test_an_as_of_naming_a_snapshot_this_run_does_not_hold_is_refused(graph):
    result = twin.simulate(
        graph,
        {"kind": "COMPOSITE", "steps": [
            {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM", "as_of": "twin:never-captured"},
        ]},
        as_of_graphs={},
    )

    assert result["status"] == "UNKNOWN_SNAPSHOT"
    assert result["unknown_as_of"] == [{"step": 1, "as_of": "twin:never-captured"}]
    assert "not 'the estate looked the same then'" in result["detail"]
    # nothing was applied, and the refusal says why in terms of the evidence
    assert result["live_state_modified"] is False


def test_as_of_must_name_a_snapshot_and_not_a_date(graph):
    result = twin.simulate(
        graph,
        {"kind": "COMPOSITE", "steps": [
            {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM", "as_of": "2026-06-30"},
        ]},
        as_of_graphs={},
    )

    # a date is not evidence: it is refused as unresolvable, not evaluated as if it were
    assert result["status"] == "UNKNOWN_SNAPSHOT"

    malformed = twin.simulate(
        graph,
        {"kind": "COMPOSITE", "steps": [
            {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM", "as_of": 20260630},
        ]},
    )
    assert malformed["status"] == "INVALID_SCENARIO"
    assert "a date is not evidence" in malformed["detail"]


def test_the_preview_counts_an_as_of_step_against_its_snapshot(graph):
    historical = build_graph(_payload_with_extra_evidence(
        {"evidence_id": "ev-old", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
         "target": "lb", "layer": "NETWORK_TRANSPORT", "facts": {"protocol": "TLSv1.1"}}
    ))
    result = twin.preview(
        graph,
        {"kind": "COMPOSITE", "steps": [
            {"kind": "DISABLE_PROTOCOL", "from": "TLSv1.1", "as_of": "twin:q2"},
        ]},
        as_of_graphs={"twin:q2": historical},
    )

    assert result["status"] == "WOULD_NOT_MATCH"
    assert result["steps"][0]["evaluated_against_snapshot"] is True
    assert result["steps"][0]["not_in_current_estate"] == 1
    assert result["as_of"]["snapshots"] == ["twin:q2"]
    assert "a step with 'as_of' reads its snapshot" in result["note"]
    assert "describe an estate that no longer exists" in result["note"]


def test_the_api_resolves_as_of_against_stored_snapshots(api):
    http, _session = api
    _discover(http)
    captured = http.post(f"{BASE}/twin/snapshots", json={"note": "q2 baseline"})
    assert captured.status_code == 201, captured.text
    identifier = captured.json()["snapshot"]["snapshot_id"]

    run = http.post(f"{BASE}/simulation/run", json={
        "kind": "COMPOSITE",
        "steps": [
            {"kind": "REPLACE_ALGORITHM", "from": "AES-128-GCM", "to": "AES-256-GCM"},
            {"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM", "as_of": identifier},
        ],
    })

    assert run.status_code == 200, run.text
    body = run.json()
    assert body["status"] == "SIMULATED"
    assert body["as_of"]["snapshots"] == [identifier]
    assert body["steps"][1]["as_of"] == identifier


def test_the_api_refuses_an_as_of_this_tenant_has_never_captured(api):
    http, _session = api
    _discover(http)

    run = http.post(f"{BASE}/simulation/run", json={
        "kind": "COMPOSITE",
        "steps": [{"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM", "as_of": "twin:not-captured"}],
    })

    assert run.status_code == 404, run.text
    detail = run.json()["detail"]
    assert detail["error"] == "unknown_snapshot"
    assert detail["missing"] == ["twin:not-captured"]
    assert "not 'the estate looked the same then'" in detail["reason"]


def test_the_plan_route_resolves_the_same_snapshots(api):
    http, _session = api
    _discover(http)
    identifier = http.post(f"{BASE}/twin/snapshots", json={}).json()["snapshot"]["snapshot_id"]

    plan = http.post(f"{BASE}/simulation/plan", json={
        "kind": "COMPOSITE",
        "steps": [{"kind": "RETIRE_ALGORITHM", "from": "AES-256-GCM", "as_of": identifier}],
    })

    assert plan.status_code == 200, plan.text
    assert plan.json()["as_of"]["snapshots"] == [identifier]


# -- a protocol floor is a check, not a scenario ---------------------------- #
#
# "If we only accepted TLS 1.2 from Friday, what is already below it?" is answered
# from observed handshakes and edits nothing, so it has no copy, no BOM diff and no
# run record. What it must never do is let a bucket it cannot judge look compliant:
# an unrankable protocol value and an asset with no handshake evidence are published
# as their own findings.


def test_the_floor_check_ranks_observed_handshakes_against_the_floor(graph):
    result = twin.protocol_floor(graph, {"floor": "TLSv1.2"})

    assert result["status"] == "AT_OR_ABOVE_FLOOR"
    # the estate's two protocol records sit at and above TLSv1.2
    assert result["counts"]["at_floor"] == 1
    assert result["counts"]["above_floor"] == 1
    assert result["counts"]["below_floor"] == 0
    assert result["counts"]["protocol_records"] == 2
    assert result["live_state_modified"] is False
    assert "nothing is edited and no copy is made" in result["note"]


def test_a_floor_above_what_the_estate_negotiates_reports_every_record_below_it(graph):
    result = twin.protocol_floor(graph, {"floor": "TLSv1.3"})

    assert result["status"] == "BELOW_FLOOR_PRESENT"
    assert result["counts"]["below_floor"] == 1
    assert [row["negotiated"] for row in result["below_floor"]] == ["TLSv1.2"]
    # and the asset is named, because "one record" is not actionable
    assert result["counts"]["assets_below_floor"] == 1
    assert result["below_floor"][0]["asset_name"] == "LB-07"


def test_an_unrankable_protocol_value_is_published_as_unrecognised_not_compliant(graph):
    payload = _payload()
    payload["evidence"] = [*payload["evidence"], {
        "evidence_id": "ev-future", "source": "probe", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
        "target": "lb", "layer": "NETWORK_TRANSPORT", "facts": {"protocol": "TLS_FUTURE"},
    }]
    result = twin.protocol_floor(build_graph(payload), {"floor": "TLSv1.2"})

    assert result["counts"]["unrecognised"] == 1
    assert result["unrecognised"][0]["negotiated"] == "TLS_FUTURE"
    assert result["unrecognised"][0]["position"] == "UNRECOGNISED"
    # it is in neither the below bucket nor the above one
    assert all(row["negotiated"] != "TLS_FUTURE" for row in result["above_floor"])


def test_an_asset_with_no_handshake_evidence_is_counted_rather_than_assumed_compliant(graph):
    result = twin.protocol_floor(graph, {"floor": "TLSv1.2"})

    assert result["counts"]["assets_without_negotiated_evidence"] > 0
    assert "application:aaa" not in result["without_negotiated_evidence"]
    assert result["blind_spots"]


def test_the_floor_must_be_a_version_this_build_can_rank(graph):
    missing = twin.protocol_floor(graph, {})
    assert missing["status"] == "INVALID_SCENARIO"
    assert "needs a 'floor'" in missing["detail"]

    unknown = twin.protocol_floor(graph, {"floor": "TLSv9.9"})
    assert unknown["status"] == "INVALID_SCENARIO"
    assert "is not a protocol version this build can rank" in unknown["detail"]
    assert unknown["choices"] == ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def test_five_spellings_of_the_same_version_are_one_rung():
    from shared_models.estate_twin import _protocol_key

    for spelling in ("TLSv1.2", "TLS 1.2", "TLS1.2", "tlsv1_2", "TLSV1.2"):
        assert _protocol_key(spelling) == "TLSV1.2", spelling
    # a protocol with no version is not a rung
    assert _protocol_key("TLS") is None


def test_the_api_serves_the_floor_check_and_refuses_an_unrankable_floor(api):
    http, _session = api
    _discover(http)

    ok = http.get(f"{BASE}/twin/protocol-floor", params={"floor": "TLSv1.2"})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["schema"] == "cryptoscan.estate-twin-protocol-floor/1"
    assert body["status"] in {"AT_OR_ABOVE_FLOOR", "BELOW_FLOOR_PRESENT", "INSUFFICIENT_EVIDENCE"}
    assert body["live_state_modified"] is False
    # the declared axis is served beside the negotiated one, never merged into it
    assert body["declared"]["basis"] == "DECLARED"
    assert "counts" in body["declared"]

    refused = http.get(f"{BASE}/twin/protocol-floor", params={"floor": "TLSv9.9"})
    assert refused.status_code == 422
    assert refused.json()["detail"]["error"] == "invalid_floor"


# -- the declared axis: what a configuration allows, which is not a negotiation ------ #


def _with_declarations(graph_payload, *records):
    return build_graph({**graph_payload, "evidence": [*graph_payload["evidence"], *records]})


def test_a_configuration_that_still_permits_an_older_protocol_is_a_declared_finding(graph):
    payload = {
        "evidence_id": "ev-cfg", "source": "host", "collector": "host",
        "evidence_type": "CONFIGURED", "target": "lb", "layer": "NETWORK_TRANSPORT",
        "facts": {"protocols": ["TLSv1.0", "TLSv1.2"]},
        "observed_at": "2026-11-01T00:00:00Z",
    }
    result = twin.protocol_floor(_with_declarations(_payload(), payload), {"floor": "TLSv1.2"})

    declared = result["declared"]
    assert declared["counts"]["declares_below_floor"] == 1
    row = declared["declares_below_floor"][0]
    assert row["asset_name"] == "LB-07"
    assert row["basis"] == "DECLARED"
    assert row["position"] == "DECLARES_BELOW_FLOOR"
    assert row["declared"] == ["TLSV1.0", "TLSV1.2"]
    # and it is kept apart from the negotiated bucket: no handshake went below TLSv1.2
    assert result["counts"]["below_floor"] == 0


def test_a_declaration_below_the_floor_with_no_handshake_below_it_changes_the_verdict(graph):
    payload = {
        "evidence_id": "ev-cfg", "source": "host", "collector": "host",
        "evidence_type": "CONFIGURED", "target": "lb", "layer": "NETWORK_TRANSPORT",
        "facts": {"protocols": ["TLSv1.0", "TLSv1.2"]},
        "observed_at": "2026-11-01T00:00:00Z",
    }
    graph_declared = _with_declarations(_payload(), payload)

    assert twin.protocol_floor(graph_declared, {"floor": "TLSv1.2"})["status"] == "BELOW_FLOOR_DECLARED"
    # at TLSv1.3 the observed handshake itself is below, so the measurement wins the status
    assert twin.protocol_floor(graph_declared, {"floor": "TLSv1.3"})["status"] == "BELOW_FLOOR_PRESENT"


def test_a_declared_ceiling_below_the_floor_names_the_edges_it_would_strand(graph):
    payload = {
        "evidence_id": "ev-old", "source": "host", "collector": "host",
        "evidence_type": "CONFIGURED", "target": "host", "layer": "PLATFORM",
        "facts": {"protocols": ["TLSv1.1"]},
        "observed_at": "2026-11-01T00:00:00Z",
    }
    result = twin.protocol_floor(_with_declarations(_payload(), payload), {"floor": "TLSv1.2"})

    ceiling = result["declared"]["declared_ceiling_below_floor"]
    assert len(ceiling) == 1
    assert ceiling[0]["asset_name"] == "payment-prod-01"
    assert ceiling[0]["declared_ceiling"] == "TLSV1.1"
    assert ceiling[0]["position_ceiling"] == "CEILING_BELOW_FLOOR"
    # the host is served by the api; nothing in this estate reaches *out* from it
    assert ceiling[0]["edges"] == []
    assert "records nothing on that asset either way" in result["declared"]["meaning"]


def test_a_minimum_version_with_no_enumerable_set_is_judged_on_the_minimum(graph):
    payload = {
        "evidence_id": "ev-min", "source": "cloud", "collector": "cloud",
        "evidence_type": "CONFIGURED", "target": "pg", "layer": "STORAGE",
        "facts": {"min_tls_version": "TLSv1.0"},
        "observed_at": "2026-11-01T00:00:00Z",
    }
    result = twin.protocol_floor(_with_declarations(_payload(), payload), {"floor": "TLSv1.2"})

    row = result["declared"]["declares_below_floor"][0]
    assert row["asset_name"] == "PostgreSQL"
    assert row["declared_floor"] == "TLSV1.0"
    assert row["declared"] == []


def test_a_declaration_with_no_rankable_protocol_is_not_filed_as_compliant(graph):
    payload = {
        "evidence_id": "ev-future", "source": "host", "collector": "host",
        "evidence_type": "CONFIGURED", "target": "ossl", "layer": "APPLICATION",
        "facts": {"protocols": ["TLS_FUTURE"]},
        "observed_at": "2026-11-01T00:00:00Z",
    }
    result = twin.protocol_floor(_with_declarations(_payload(), payload), {"floor": "TLSv1.2"})

    unrankable = result["declared"]["declared_without_a_rankable_floor"]
    assert [row["asset_name"] for row in unrankable] == ["OpenSSL"]
    assert unrankable[0]["unrecognised"] == ["TLS_FUTURE"]
    assert all(row["asset_name"] != "OpenSSL" for row in result["declared"]["declares_below_floor"])


def test_a_half_parsed_configuration_says_it_was_only_half_parsed(graph):
    payload = {
        "evidence_id": "ev-part", "source": "host", "collector": "host",
        "evidence_type": "CONFIGURED", "target": "ossl", "layer": "APPLICATION",
        "facts": {"protocols": ["TLSv1.2"], "unparsed_directives": True},
        "observed_at": "2026-11-01T00:00:00Z",
    }
    result = twin.protocol_floor(_with_declarations(_payload(), payload), {"floor": "TLSv1.2"})

    partial = result["declared"]["partially_parsed"]
    assert [row["asset_name"] for row in partial] == ["OpenSSL"]
    assert result["declared"]["counts"]["partially_parsed"] == 1


def test_the_floor_check_states_that_a_declaration_is_not_a_handshake(graph):
    result = twin.protocol_floor(graph, {"floor": "TLSv1.2"})

    assert result["declared"]["basis"] == "DECLARED"
    assert "It is not a negotiation" in result["declared"]["meaning"]
    assert any("runtime client acceptance" in spot for spot in result["blind_spots"])
    assert any("declarations are read from TLS configuration evidence only" in limit
               for limit in result["limits"])
