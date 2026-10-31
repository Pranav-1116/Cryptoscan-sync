"""Every collector family the vision names, and what this build actually reaches.

Gap A is "complete production collectors for twenty families". The temptation is to
answer it with a table someone typed. This register answers it with a table the
build *computes*: each family declares the module:entrypoint that would have to
exist, and the status is decided by importing them.

The tests below pin the property that makes the table trustworthy:

* a family cannot be SHIPPED unless every entrypoint resolves — simulated by an
  importer that refuses one module;
* a family with nothing behind it must carry a reason, so absence is stated rather
  than left as an empty box;
* ``production`` is stricter than ``shipped``: parsing data an operator supplies, or
  collecting this platform instead of the estate, does not count;
* the twenty families the vision names are all present, in its order.
"""

from __future__ import annotations


from shared_models import collector_families as cf

#: the vision's families, in the order it names them
VISION = (
    "WINDOWS",
    "LINUX",
    "KUBERNETES",
    "CLOUD",
    "HSM",
    "KMS",
    "PKI",
    "DATABASES",
    "LOAD_BALANCERS",
    "API_GATEWAYS",
    "VPN",
    "NETWORK_DEVICES",
    "MESSAGE_QUEUES",
    "SERVICE_MESH",
    "STORAGE",
    "BACKUP",
    "LEGACY",
    "VENDOR",
)

#: the two this build reaches under its own names
EXTRA = ("CONTAINERS", "RUNTIME")


def _refusing(*missing: str):
    """An importer that fails for named modules and defers to the real one otherwise."""
    import importlib

    def load(module: str):
        if module in missing:
            raise ModuleNotFoundError(f"no module named {module!r}")
        return importlib.import_module(module)

    return load


def test_the_register_covers_the_vision_and_names_every_family():
    ids = tuple(family.id for family in cf.FAMILIES)
    assert ids == VISION[:2] + EXTRA[:1] + VISION[2:] + EXTRA[1:], (
        "the register must contain every family the vision names, in its order; "
        f"got {ids}"
    )
    assert set(VISION) <= set(ids)


def test_every_family_names_an_entrypoint_to_be_measured_against():
    for family in cf.FAMILIES:
        assert family.entrypoints, f"{family.id} declares no entrypoint, so nothing can be measured"
        for module, attribute in family.entrypoints:
            assert module and attribute and "." not in attribute
        assert family.limit, f"{family.id} states no limit — a shipped collector always has one"
        assert family.evidence in cf.EVIDENCE_RANK


def test_a_family_that_cannot_import_its_entrypoint_is_not_shipped():
    family = next(f for f in cf.FAMILIES if f.id == "KUBERNETES")
    module = family.entrypoints[0][0]
    row = family.measured(importer=_refusing(module))
    assert row["status"] == cf.ABSENT
    assert row["entrypoints"] == []
    assert any(module in item for item in row["missing"])
    assert row["production"] is False


def test_partial_is_distinct_from_absent():
    family = next(f for f in cf.FAMILIES if f.id == "LINUX")
    module = family.entrypoints[-1][0]
    row = family.measured(importer=_refusing(module))
    assert row["status"] == cf.PARTIAL
    assert row["entrypoints"], "the entrypoints that did resolve are still reported"
    assert row["production"] is False, "a half-measured family is never a production collector"


def test_an_absent_family_must_say_why():
    """Absence is a finding, and a finding without a reason is a blank cell."""
    for family in cf.FAMILIES:
        row = family.measured()
        if row["status"] == cf.ABSENT:
            assert row["reason"], f"{family.id} is absent with no stated reason"
        if row["input"] != cf.LIVE:
            assert row["limit"], f"{family.id} is not live and states no limit"


def test_production_is_stricter_than_shipped():
    """Parsing an operator's file is real code and not unattended collection."""
    document = cf.register()
    by_id = {row["id"]: row for row in document["families"]}
    assert by_id["NETWORK_DEVICES"]["status"] == cf.SHIPPED
    assert by_id["NETWORK_DEVICES"]["input"] == cf.INJECTED
    assert by_id["NETWORK_DEVICES"]["production"] is False
    assert by_id["NETWORK_DEVICES"]["id"] in document["production_gap"]

    # protecting this platform's own database is not collecting a bank's backup estate
    assert by_id["BACKUP"]["scope"] == cf.PLATFORM
    assert by_id["BACKUP"]["production"] is False

    # a live KLM/cloud collector that only reads configuration is still production
    assert by_id["KUBERNETES"]["production"] is True


def test_the_counts_are_counts_of_rows_not_a_score():
    document = cf.register()
    rows = document["families"]
    assert document["counts"] == {
        state: sum(1 for row in rows if row["status"] == state)
        for state in (cf.SHIPPED, cf.PARTIAL, cf.ABSENT)
    }
    assert sum(document["counts"].values()) == len(rows)
    assert document["production"] == sum(1 for row in rows if row["production"])
    assert document["production"] <= len(rows)
    assert "not a coverage or maturity score" in document["claim"]
    assert "%" not in document["claim"]


def test_the_production_gap_is_named_rather_than_implied():
    document = cf.register()
    gap = set(document["production_gap"])
    assert gap
    # each gap row is either not shipped, not live, or not about the estate
    for row in document["families"]:
        if row["id"] in gap:
            assert not row["production"]
        else:
            assert row["status"] == cf.SHIPPED and row["input"] == cf.LIVE
            assert row["scope"] == cf.ESTATE


def test_the_measured_matrix_is_stable():
    """Re-measuring must not change the answer: the register is a fact, not a run."""
    first = cf.register()
    second = cf.register()
    assert first["counts"] == second["counts"]
    assert [row["status"] for row in first["families"]] == [row["status"] for row in second["families"]]
    assert first["production"] == second["production"]


def test_the_endpoint_serves_the_same_document():
    """The route must not re-implement the register or restate it more strongly."""
    import inspect

    from api.routers import collector_depth

    source = inspect.getsource(collector_depth.collector_family_matrix)
    assert "collector_families.register()" in source
    assert "SHIPPED" not in source, "the route must not hardcode a status"


def test_the_committed_register_matches_a_fresh_render():
    """The document is generated, so it cannot describe a build it was not rendered from."""
    from pathlib import Path

    import gen_collector_families as gen

    committed = Path(__file__).resolve().parents[2] / "docs" / "bank-environment" / (
        "105-collector-family-register.md"
    )
    assert committed.is_file(), "regenerate with: scripts/gen_collector_families.py --write"
    assert committed.read_text() == gen.render(cf.register()), (
        "the committed collector-family register does not match this build — regenerate it "
        "and read the diff"
    )
