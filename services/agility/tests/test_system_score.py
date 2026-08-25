from agility.readiness import assess_readiness
from agility.system_score import calculate_agility_score


def test_modern_microservice_is_excellent():
    evidence = [
        {
            "algorithm": "AES",
            "file_path": "config/crypto.yaml",
            "finding_data": {"metadata": {"library": "aws_kms", "confidence_reason": "config-driven"}},
        }
    ]
    system = {
        "environment": "KUBERNETES",
        "extra": {
            "kms": True,
            "configmap": True,
            "hot_reload": True,
            "crypto_tests": True,
            "parameterized_crypto_tests": True,
            "has_crypto_docs": True,
            "has_crypto_inventory_docs": True,
            "has_dr_plan": True,
            "key_management": "AWS_KMS",
        },
    }
    result = calculate_agility_score(evidence, system)
    assert result["agility_score"] >= 80
    assert result["category"] == "EXCELLENT"


def test_legacy_monolith_is_critical():
    evidence = [
        {
            "algorithm": "DES",
            "file_path": "src/PaymentService.java",
            "is_hardcoded_key": True,
            "finding_data": {"metadata": {"confidence_reason": "literal-api"}},
        }
        for _ in range(6)
    ]
    system = {"extra": {"no_tests": True, "static_binary": True, "secrets_in_git": True}}
    result = calculate_agility_score(evidence, system)
    assert result["agility_score"] <= 20
    assert result["category"] == "CRITICAL"
    assert result["recommendations"]


def test_readiness_waves():
    ready = assess_readiness(agility_score=90, dependency_count=0, has_crypto_tests=True, team_capacity="HIGH")
    blocked = assess_readiness(agility_score=10, dependency_count=20, has_crypto_tests=False, team_capacity="LOW")
    assert ready["readiness_category"] == "READY_NOW"
    assert blocked["readiness_category"] == "BLOCKED"
    assert ready["wave"] == 1
    assert blocked["wave"] == 3
