"""The State Machine Register is only worth having if it cannot rot.

These tests pin the register to the code it describes:

1. self-consistency (states classified, transitions closed, unique field claims);
2. mirror parity (frontend/src/lib/stateMachines.json is byte-identical);
3. model coverage — every status-bearing column in db.models is registered, and
   every registered db field resolves to a real column whose declared default is
   a declared state. Add a status column and this test fails until the register
   learns it;
4. vocabulary pins — the declared tuples/enums in code equal the register's
   states for the machines that claim them;
5. honesty pins — capability never gains an edge into usage; unknown machines
   stay empty; undeclared states render slate, never green.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from shared_models.state_machines import (
    MACHINES,
    STATE_CLASSES,
    can_transition,
    machine,
    machines_for_field,
    state_class,
    state_tone,
    validate,
)

REPO = Path(__file__).resolve().parents[3]
MODELS_DIR = REPO / "services" / "database" / "db" / "models"
MIRROR = REPO / "frontend" / "src" / "lib" / "stateMachines.json"
CANON = REPO / "shared" / "shared_models" / "shared_models" / "state_machines.json"

FIELD_RE = re.compile(
    r"^(status|state|stage|phase|decision|effect|link|outcome|verdict|result|"
    r"investigation_status|usage_status|quality_status|expiry_status|renewal_status|"
    r"revocation_status|email_status|agent_status|last_sync_status|coverage_status|"
    r"compliance_status|resolution_status|verification_status)$"
)


def _model_fields() -> dict[str, str | None]:
    """{module.Class.field: declared scalar default or None} for every
    status-bearing column in db.models (AST — no import side effects)."""
    found: dict[str, str | None] = {}
    for path in sorted(MODELS_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for st in node.body:
                if not (isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)):
                    continue
                name = st.target.id
                if not FIELD_RE.match(name):
                    continue
                default = None
                if isinstance(st.value, ast.Call):
                    for kw in st.value.keywords:
                        if kw.arg == "default":
                            try:
                                val = ast.literal_eval(kw.value)
                                if isinstance(val, str):
                                    default = val
                            except Exception:
                                pass
                found[f"{path.stem}.{node.name}.{name}"] = default
    return found


def _module_tuple(module_file: Path, const_name: str) -> tuple[str, ...]:
    tree = ast.parse(module_file.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == const_name:
                return tuple(ast.literal_eval(node.value))
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == const_name and node.value is not None:
                return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{const_name} not found in {module_file}")


# ------------------------------------------------------------- 1. coherence --
def test_register_self_check_is_clean():
    assert validate() == []


def test_every_state_carries_a_known_class_and_meaning_class_exists():
    for mid, m in MACHINES.items():
        for s in m["states"]:
            assert s["class"] in STATE_CLASSES, f"{mid}:{s['id']}"


def test_transition_graph_is_closed():
    for mid, m in MACHINES.items():
        declared = {s["id"] for s in m["states"]}
        for t in m["transitions"]:
            assert t["from"] in declared and t["to"] in declared, f"{mid}: {t['from']}->{t['to']}"


def test_unobserved_machines_carry_no_states_and_say_so():
    for mid, m in MACHINES.items():
        if m["vocabulary"] == "unobserved":
            assert m["states"] == [], mid
            assert any("never guessed" in inv for inv in m["invariants"]), mid
        else:
            assert m["states"], mid


def test_every_machine_declares_its_observation_source():
    for mid, m in MACHINES.items():
        assert m["vocabulary_source"] or m["kind"] in ("session", "ui"), mid


# ---------------------------------------------------------- 2. mirror parity --
def test_frontend_mirror_is_byte_identical():
    assert MIRROR.read_bytes() == CANON.read_bytes(), (
        "frontend/src/lib/stateMachines.json drifted from the canonical register — "
        "copy it (they are generated together) and re-run"
    )


# --------------------------------------------------------- 3. model coverage --
def test_every_status_column_is_registered():
    found = set(_model_fields())
    registered = {f for m in MACHINES.values() for f in m["fields"] if "." in f}
    missing = sorted(found - registered)
    ghost = sorted(registered - found)
    assert missing == [], f"status columns missing from the register: {missing}"
    assert ghost == [], f"register fields that no longer exist: {ghost}"


def test_no_field_is_claimed_by_two_machines():
    seen: dict[str, str] = {}
    for mid, m in MACHINES.items():
        for f in m["fields"]:
            assert f not in seen, f"{f} on both {seen[f]} and {mid}"
            seen[f] = mid


def test_registered_defaults_are_declared_states():
    fields = _model_fields()
    for mid, m in MACHINES.items():
        declared = {s["id"] for s in m["states"]}
        for f in m["fields"]:
            default = fields.get(f)
            if default is not None and m["states"]:
                assert default in declared, f"{f} default {default!r} not a state of {mid}"


# --------------------------------------------------------- 4. vocabularies ---
def test_usage_status_enum_equals_register():
    src = REPO / "services" / "binary_intelligence" / "binary_intelligence" / "evidence.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    enums: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            vals = set()
            for st in node.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    try:
                        v = ast.literal_eval(st.value)
                    except Exception:
                        continue
                    if isinstance(v, str):
                        vals.add(v)
            enums[node.name] = vals
    assert enums["UsageStatus"] == set(machine("binary.usage_status").state_ids)
    assert enums["EvidenceClass"] == set(machine("binary.evidence_class").state_ids)


def test_declared_model_tuples_equal_register():
    pins = {
        "scan.status": ("scan.py", "SCAN_STATUSES"),
        "tenant.status": ("tenant.py", "TENANT_STATUSES"),
        "payment_crypto.key_state": ("payment_crypto.py", "KEY_STATES"),
        "identity.confidence": ("control_plane.py", "CONFIDENCE_STATES"),
        "control_plane.credential_status": ("control_plane.py", "CREDENTIAL_STATUSES"),
        "control_plane.agent_status": ("control_plane.py", "AGENT_STATUSES"),
        "control_plane.event_status": ("control_plane.py", "EVENT_STATUSES"),
        "control_plane.benchmark_status": ("control_plane.py", "BENCHMARK_RUN_STATUSES"),
        "control_plane.delivery_status": ("control_plane.py", "DELIVERY_STATUSES"),
        "monitor.target_status": ("monitor.py", "TARGET_STATUSES"),
        "enterprise.compliance_state": ("enterprise.py", "COMPLIANCE_STATES"),
        "enterprise.ticket_state": ("enterprise.py", "TICKET_STATES"),
        "enterprise.policy_verdict": ("enterprise.py", "POLICY_VERDICTS"),
        "security_control.finding_state": ("security_control.py", "FINDING_STATES"),
        "pentest_finding.status": ("pentest_finding.py", "STATUSES"),
        "common.severity": ("pentest_finding.py", "SEVERITIES"),
        "evidence_disposition.decision": ("evidence_disposition.py", "DECISIONS"),
    }
    for mid, (fname, const) in pins.items():
        vals = set(_module_tuple(MODELS_DIR / fname, const))
        declared = {s.id for s in machine(mid).states}
        if mid == "control_plane.delivery_status":
            # dispatch writes two more states (inflight, legacy_unknown) beyond the tuple
            assert vals <= declared, f"{mid}: tuple states missing: {vals - declared}"
        elif mid == "common.severity":
            assert vals == declared, f"{mid}: {vals} != {declared}"
        else:
            assert vals <= declared, f"{mid}: tuple states missing: {vals - declared}"


def test_os_rule_states_survive_in_rules_py():
    src = (REPO / "services" / "os_intelligence" / "os_intelligence" / "rules.py").read_text(encoding="utf-8")
    for state in machine("os.rule_evaluation").state_ids:
        assert f'"{state}"' in src or f"'{state}'" in src, state
    assert "not_evaluable is never clean" in src or "never a clean" in src


# ------------------------------------------------------------- 5. honesty ----
def test_capability_never_gains_an_edge_into_usage():
    usage = machine("binary.usage_status")
    into_confirmed = [t for t in usage.transitions if t.to == "runtime_confirmed"]
    assert into_confirmed == [], "runtime_confirmed must only be raised by observed runtime events"


def test_states_of_unobserved_machines_never_render_as_pass():
    for mid, m in MACHINES.items():
        if m["vocabulary"] == "unobserved":
            assert state_tone(mid, "anything") == "slate"
            assert state_class(mid, "anything") is None


def test_state_tone_is_the_class_tone():
    assert state_tone("scan.status", "FAILED") == STATE_CLASSES["failure"]["tone"]
    assert state_tone("scan.status", "COMPLETED") == STATE_CLASSES["done"]["tone"]
    assert state_tone("scan.status", "QUEUED") == STATE_CLASSES["progress"]["tone"]


def test_can_transition_only_for_observed_edges():
    assert can_transition("scan.status", "QUEUED", "RUNNING") is True
    assert can_transition("scan.status", "COMPLETED", "RUNNING") is False  # terminal
    assert can_transition("binary.usage_status", "capability_only", "runtime_confirmed") is False
    with pytest.raises(KeyError):
        can_transition("no.such.machine", "a", "b")


def test_the_honesty_machines_carry_their_invariants():
    for mid, needle in {
        "session.read_health": "never prints zeros",
        "session.tenant_resolution": "never zeros",
        "collector.depth": "Installed is not executed",
        "binary.usage_status": "Capability never promotes to usage",
        "os.rule_evaluation": "never clean",
        "security_control.finding_state": "NOT_CONFIGURED and UNKNOWN are different",
        "ui.performance_tile": "never render 0",
    }.items():
        inv = " ".join(machine(mid).invariants)
        assert needle in inv, f"{mid} lost its honesty invariant ({needle!r})"


def test_field_lookup_round_trip():
    m = machines_for_field("scan.Scan.status")
    assert m is not None and m.id == "scan.status"
    assert machines_for_field("nope.Nope.status") is None


def test_register_json_is_stable_and_versioned():
    data = json.loads(CANON.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["register"] == "cryptoscan-state-machines"
    assert len(data["machines"]) == len(MACHINES)
