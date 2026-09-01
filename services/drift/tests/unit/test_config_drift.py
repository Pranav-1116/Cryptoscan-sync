"""Config drift (Drift v2.0) — facts extraction, detection, gate blocking."""

from __future__ import annotations

import pytest

from drift.core.config_detector import detect_config_drift
from drift.core.config_facts import ConfigFact, extract_config_facts
from drift.core.gate import evaluate_gate


def _finding(
    *,
    algorithm: str = "TLS1.2",
    library: str = "nginx",
    raw: str = "TLSv1.2",
    purpose: str = "NETWORK_ENCRYPTION",
    file_path: str = "nginx.conf",
    line: int = 3,
    is_hardcoded: bool = False,
) -> dict:
    data = {
        "source": {"language": "CONFIG", "scanner_id": "static-config-scanner-v1.0", "file_path": file_path},
        "crypto": {
            "algorithm": algorithm,
            "purpose": purpose,
            "raw_transformation": raw,
            "api_type": "HARDCODED_KEY" if is_hardcoded else "KEY_AGREEMENT",
        },
        "metadata": {"library": library, "is_hardcoded_key": is_hardcoded},
    }
    return {
        "algorithm": algorithm,
        "purpose": purpose,
        "file_path": file_path,
        "line_number": line,
        "is_hardcoded_key": is_hardcoded,
        "finding_data": data,
    }


def test_extract_facts_from_config_findings():
    facts = extract_config_facts([_finding()])
    assert len(facts) == 1
    fact = facts[0]
    assert fact.library == "nginx"
    assert fact.config_key == "nginx:TLSv1.2"
    assert fact.value == "TLS1.2::"
    assert not fact.secret_present


def test_secret_value_never_leaves_estate():
    facts = extract_config_facts(
        [_finding(algorithm="JWT", library="config-secret", raw="super-secret-value-123", is_hardcoded=True)]
    )
    fact = facts[0]
    assert fact.secret_present
    assert fact.secret_length == len("super-secret-value-123")
    assert fact.secret_hash == "d6a7efe516c30500"  # sha256(...)[:16]
    assert "super-secret-value-123" not in fact.value
    assert "super-secret-value-123" not in fact.to_dict().values()
    assert "super-secret-value-123" not in fact.config_key


def test_code_findings_are_ignored():
    code = {
        "algorithm": "AES",
        "purpose": "ENCRYPTION",
        "file_path": "src/Main.java",
        "line_number": 1,
        "finding_data": {"source": {"language": "JAVA", "scanner_id": "static-java-scanner-v1.0"}},
    }
    assert extract_config_facts([code]) == []


def test_detector_added_removed_changed():
    baseline = [
        ConfigFact(config_key="nginx:TLSv1.2", file_path="nginx.conf", library="nginx", algorithm="TLS1.2", value="TLS1.2::"),
        ConfigFact(config_key="nginx:TLSv1.0", file_path="nginx.conf", library="nginx", algorithm="TLS1.0", value="TLS1.0::"),
    ]
    current = [
        ConfigFact(config_key="nginx:TLSv1.2", file_path="nginx.conf", library="nginx", algorithm="TLS1.2", value="TLS1.2::"),
        ConfigFact(config_key="nginx:TLSv1.0", file_path="nginx.conf", library="nginx", algorithm="TLS1.0", value="TLS1.0::"),
        ConfigFact(config_key="nginx:TLSv1.3", file_path="nginx.conf", library="nginx", algorithm="TLS1.3", value="TLS1.3::"),
    ]
    result = detect_config_drift(baseline, current)
    types = {c.change_type for c in result.changes}
    assert types == {"CONFIG_ADDED"}
    assert result.changes[0].config_key == "nginx:TLSv1.3"

    removed = detect_config_drift(current, baseline)
    assert {c.change_type for c in removed.changes} == {"CONFIG_REMOVED"}


def test_detector_weakening_is_critical():
    baseline = [
        ConfigFact(config_key="nginx:TLSv1.2", file_path="nginx.conf", library="nginx", algorithm="TLS1.2", value="TLS1.2::"),
    ]
    current = [
        ConfigFact(config_key="nginx:TLSv1.2", file_path="nginx.conf", library="nginx", algorithm="TLS1.2", value="TLS1.2::"),
        ConfigFact(config_key="nginx:TLSv1.0", file_path="nginx.conf", library="nginx", algorithm="TLS1.0", value="TLS1.0::"),
    ]
    # TLS1.0 appears as a *new* weak fact
    result = detect_config_drift(baseline, current)
    weak = [c for c in result.changes if c.algorithm == "TLS1.0"]
    assert weak and weak[0].severity == "CRITICAL"

    # Direct downgrade of the same key: TLS1.2 -> TLS1.0
    downgrade = [
        ConfigFact(config_key="nginx:min", file_path="nginx.conf", library="nginx", algorithm="TLS1.2", value="TLS1.2::"),
    ]
    current2 = [
        ConfigFact(config_key="nginx:min", file_path="nginx.conf", library="nginx", algorithm="TLS1.0", value="TLS1.0::"),
    ]
    result2 = detect_config_drift(downgrade, current2)
    assert result2.changes[0].change_type == "CONFIG_CHANGED"
    assert result2.changes[0].severity == "CRITICAL"
    assert "weakened" in result2.changes[0].reason


def test_detector_secret_length_decrease_is_high():
    baseline = [
        ConfigFact(
            config_key="config-secret:JWT_SECRET", file_path=".env", library="config-secret",
            algorithm="JWT", value="secret:32", secret_present=True, secret_length=32,
            secret_hash="a" * 16,
        ),
    ]
    current = [
        ConfigFact(
            config_key="config-secret:JWT_SECRET", file_path=".env", library="config-secret",
            algorithm="JWT", value="secret:8", secret_present=True, secret_length=8,
            secret_hash="b" * 16,
        ),
    ]
    result = detect_config_drift(baseline, current)
    assert result.changes[0].change_type == "CONFIG_CHANGED"
    assert result.changes[0].severity == "HIGH"
    assert result.changes[0].secret_hash == "b" * 16  # hash only — never the value


def test_gate_blocks_critical_config_drift():
    events = [
        {
            "drift_type": "CONFIG_DEGRADED",
            "severity": "CRITICAL",
            "reason": "crypto configuration weakened",
            "algorithm": "TLS1.0",
            "file_path": "nginx.conf",
        }
    ]
    gate = evaluate_gate([], events)
    assert gate["decision"] == "FAIL"
    assert any(b["code"] == "DRIFT_CONFIG_DEGRADED" for b in gate["blocking"])


def test_gate_warns_on_hardening():
    events = [
        {
            "drift_type": "CONFIG_CHANGED",
            "severity": "INFO",
            "reason": "crypto configuration hardened",
            "algorithm": "TLS1.3",
            "file_path": "nginx.conf",
        }
    ]
    gate = evaluate_gate([], events)
    assert gate["decision"] != "FAIL"
    assert any(w["code"] == "DRIFT_CONFIG_CHANGED" for w in gate["warnings"])


def test_facts_are_deterministic():
    f1 = extract_config_facts([_finding()])
    f2 = extract_config_facts([_finding()])
    assert [f.to_dict() for f in f1] == [f.to_dict() for f in f2]
