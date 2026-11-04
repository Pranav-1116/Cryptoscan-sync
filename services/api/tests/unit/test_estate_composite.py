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
