from graph_engine.core.migration import apply_import_constraints, merge_cycle_constraints


def test_import_constraints_propagate_transitively_and_never_lower_waves():
    rows = [{"system_id": "A", "name": "A", "wave": 1}, {"system_id": "B", "name": "B", "wave": 1}, {"system_id": "C", "name": "C", "wave": 3}, {"system_id": "D", "name": "D", "wave": 2}]
    info = apply_import_constraints(rows, [("system:A", "system:B"), ("system:B", "system:C"), ("system:D", "system:A"), ("system:X", "system:A"), ("system:C", "system:C")])
    waves = {r["system_id"]: r["wave"] for r in rows}
    assert waves == {"A": 3, "B": 3, "C": 3, "D": 3}  # D→A→B→C chain all held to C's wave
    assert info["import_edges"] == 3 and info["systems_delayed_by_imports"] == ["A", "B", "D"]
    assert next(r for r in rows if r["system_id"] == "A")["constrained_by"] == ["B"]
    out = merge_cycle_constraints(rows, [])
    assert "imports crypto from B" in next(r for r in out["waves"]["3"] if r["system_id"] == "A")["rationale"]
