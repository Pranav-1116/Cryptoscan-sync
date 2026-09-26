"""Dubai banks: six representative bank estates through the pipeline, read back per bank and as the CBUAE supervisor.

Runs `scripts/dubai_banks_e2e.py::run` (the same code that writes docs/accuracy/DUBAI-BANKS-E2E.md) on SQLite and on a
real PostgreSQL, and asserts what a supervisory pilot would check:

* every bank's scan completes and its evidence rows match the blind labels at F1 ≥ 0.95 (overall ≥ 0.98);
* each bank's systems are attributed to *its* legal entity even when banks reuse system names (CORE, INFRA …) —
  the cross-entity name-collision guard — and the DIFC branch rolls up under the DFSA entity;
* no system is left unassigned when the map declares a legal entity;
* the supervisor endpoints return one row per registry entity; a readonly session cannot publish triage;
* field accuracy stays NO_FIELD_DATA (nothing invented).

Synthetic estates — not the banks' code; see the script docstring.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import dubai_banks_e2e as e2e  # noqa: E402


@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
def test_dubai_banks_end_to_end(tmp_path, monkeypatch, backend):
    from db.testing import estate_engine

    if backend == "postgresql":
        probe = estate_engine(backend)
        if probe is None:
            pytest.skip("no PostgreSQL: set CRYPTOSCAN_TEST_DATABASE_URL or pip install pgserver")
        from db.testing import drop_engine

        drop_engine(probe)
    rep = e2e.run(backend, workdir=tmp_path)

    banks = rep["banks"]
    assert set(banks) == set(e2e.BANKS)
    for bank, b in banks.items():
        assert b["status"] == "COMPLETED", (bank, b["error"])
        assert b["accuracy"]["f1"] >= 0.95, (bank, b["accuracy"]["misses"])
        assert b["evidence_rows"] > 0
        assert set(b["cascade_systems"]) == set(e2e.BANKS[bank]["systems"]), bank
        # CBUAE rules fire for every bank (each has at least one CBUAE-scoped system with weak/legacy crypto)
        assert any(r.startswith("CBUAE") for r in b["failed_rules"]), (bank, b["failed_rules"])
    assert rep["overall"]["f1"] >= 0.98, rep["overall"]
    # DIFC rules only in ENBD's DIFC-branch system
    difc_fired = {(bank, s) for bank, b in banks.items() for s, rules in b["rules_applied_by_system"].items() if any(r.startswith("DIFC") for r in rules)}
    assert difc_fired == {("enbd", "DIFC-WEALTH")}, difc_fired

    api = rep["api"]
    for bank, x in api["per_bank"].items():
        assert x["status"] == "COMPLETED"
        assert x["findings_via_api"] == banks[bank]["evidence_rows"], bank
        assert set(x["cascade_systems_via_api"]) == set(e2e.BANKS[bank]["systems"])
    assert api["readonly_triage_post_status"] == 403
    assert api["field_accuracy_status"] == "NO_FIELD_DATA"

    sup = api["supervisor"]
    assert sup["registry_count"] == len(e2e.ENTITIES)
    assert sup["unassigned_systems"] == 0
    assert set(sup["entities"]) == {e["code"] for e in e2e.ENTITIES}
    declared = sum(len(s["systems"]) for s in e2e.BANKS.values())
    assert sup["systems_total"] == declared + len(e2e.BANKS)  # declared systems + one repository-level system per bank
    # per-entity system counts: declared under that entity (+ the repo-level system for the bank) — the collision guard
    # keeps "CORE"/"INFRA" declared by several banks apart instead of merging them under whichever bank scanned last
    for bank, spec in e2e.BANKS.items():
        own = sum(1 for row in spec["systems"].values() if (row[4] if len(row) > 4 else bank) == bank)
        assert sup["entities"][bank]["systems"] == own + 1, (bank, sup["entities"][bank])
        assert sup["entities"][bank]["crypto_instances"] > 0, bank
        # no double counting: the repo-level container must not re-count the assets its declared systems own
        assert sup["entities"][bank]["crypto_instances"] <= banks[bank]["evidence_rows"], (bank, sup["entities"][bank])
    assert sup["entities"]["dib"]["worst_system"].endswith("CARD-SWITCH")  # 3DES PIN blocks, not the "dib-estate" container
    assert sup["entities"]["enbd-difc"]["systems"] == 1
    assert sup["entities"]["enbd-difc"]["worst_system"] == "DIFC-WEALTH"
    assert sup["pack_entities"] == len(e2e.ENTITIES)
    assert sup["by_jurisdiction"] and set(sup["by_jurisdiction"]) >= {"ae", "difc"}
    assert sup["group_totals"]["systems"] == sup["systems_total"]
