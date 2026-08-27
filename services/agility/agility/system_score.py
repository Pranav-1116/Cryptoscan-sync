"""Six-factor crypto agility score. Deterministic. Policy is never decided here."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

CONFIG_SUFFIXES = (".yaml", ".yml", ".properties", ".env", ".conf", ".toml", ".ini", ".json")
CONFIG_NAMES = ("cryptoconfig", "constants", "config", "settings", "application")
WRAPPER_NAMES = (
    "cryptoservice",
    "encryptionutil",
    "encryptionmanager",
    "ciphermanager",
    "securityhelper",
    "cryptofacade",
)
KMS_HINTS = ("aws_kms", "kms_key", "keyvault", "key_vault", "google_kms", "hashicorp", "vault", "hsm")
HARDCODED_REASONS = ("literal-api", "hardcoded-transformation", "string-literal", "hardcoded")
FACTORY_REASONS = ("factory", "variable-algorithm", "config-driven", "provider-lookup")
HOT_RELOAD = ("watchdog", "file watcher", "sighup", "hot-reload", "hot_reload", "reloadconfig")
TEST_TOKENS = ("test", "spec", "pytest", "unittest")
CRYPTO_WORDS = ("encrypt", "decrypt", "cipher", "crypto", "aes", "rsa", "hmac")
DOC_WORDS = ("crypto migration", "algorithm rotation", "key rotation", "crypto change")


def normalize_score(raw: float, *, maximum: float = 145.0) -> int:
    if raw <= 0:
        return 0
    return min(100, int(round((raw / maximum) * 100)))


def categorize_score(score: int) -> dict[str, str]:
    if score >= 80:
        return {"category": "EXCELLENT", "description": "Highly agile. Crypto changes are safe, fast, and low-risk."}
    if score >= 60:
        return {"category": "GOOD", "description": "Agile with minor friction. Some manual steps required."}
    if score >= 40:
        return {"category": "MODERATE", "description": "Limited agility. Crypto changes require significant effort."}
    if score >= 20:
        return {"category": "POOR", "description": "Low agility. Crypto changes are high-risk and time-consuming."}
    return {"category": "CRITICAL", "description": "Crypto is hardcoded and scattered. Migration extremely difficult."}


def _path(finding: Mapping[str, Any]) -> str:
    return str(finding.get("file_path") or (finding.get("source") or {}).get("file_path") or "").lower()


def _reason(finding: Mapping[str, Any]) -> str:
    metadata = (finding.get("finding_data") or {}).get("metadata") or finding.get("metadata") or {}
    return str(finding.get("confidence_reason") or metadata.get("confidence_reason") or "").lower()


def _library(finding: Mapping[str, Any]) -> str:
    metadata = (finding.get("finding_data") or {}).get("metadata") or finding.get("metadata") or {}
    crypto = (finding.get("finding_data") or {}).get("crypto") or finding.get("crypto") or {}
    return str(finding.get("library") or metadata.get("library") or crypto.get("library") or "").lower()


def _text_blob(system: Mapping[str, Any] | None) -> str:
    extra = (system or {}).get("extra") or {}
    parts = [
        str((system or {}).get("description") or ""),
        str(extra.get("docs") or extra.get("documentation") or ""),
        " ".join(str(item) for item in extra.get("doc_hits") or []),
    ]
    return " ".join(parts).lower()


def score_algorithm_configurability(evidence: list[Mapping[str, Any]]) -> int:
    if not evidence:
        return 20
    paths = [_path(row) for row in evidence]
    config_hits = sum(1 for path in paths if path.endswith(CONFIG_SUFFIXES) or "/config/" in path or path.endswith(".env"))
    if config_hits and config_hits >= max(1, len(evidence) // 2):
        score = 30
    elif any(any(token in path for token in CONFIG_NAMES) for path in paths):
        score = 20
    elif any(any(token in _reason(row) for token in FACTORY_REASONS) for row in evidence):
        score = 10
    else:
        score = 0
    if any(any(token in _reason(row) for token in HARDCODED_REASONS) for row in evidence):
        score -= 10
    if any(row.get("is_hardcoded_key") for row in evidence):
        score -= 10
    algos = [str(row.get("algorithm") or "") for row in evidence]
    scattered = any(algos.count(algo) > 5 for algo in set(algos) if algo)
    if scattered:
        score -= 10
    return score


def score_key_management(evidence: list[Mapping[str, Any]], system: Mapping[str, Any] | None = None) -> int:
    blob = " ".join(_library(row) for row in evidence) + " " + _text_blob(system)
    extra = (system or {}).get("extra") or {}
    if extra.get("kms") or extra.get("key_management") in {"KMS", "AWS_KMS", "AZURE_KEY_VAULT", "GCP_KMS"}:
        score = 30
    elif any(hint in blob for hint in ("aws kms", "azure key vault", "gcp kms", "cloud kms")):
        score = 30
    elif any(hint in blob for hint in ("hsm",)):
        score = 25
    elif any(hint in blob for hint in ("vault", "hashicorp")):
        score = 20
    elif any(hint in blob for hint in KMS_HINTS):
        score = 30
    elif extra.get("key_management") == "ENV":
        score = 0
    else:
        score = 10 if evidence else 0
    if any(row.get("is_hardcoded_key") for row in evidence):
        score -= 30
    if extra.get("secrets_in_git"):
        score -= 50
    return score


def score_abstraction_layer(evidence: list[Mapping[str, Any]]) -> int:
    if not evidence:
        return 10
    libraries = {lib for row in evidence if (lib := _library(row))}
    paths = [_path(row) for row in evidence]
    wrapper_hits = sum(1 for path in paths if any(name in path.replace("\\", "/") for name in WRAPPER_NAMES))
    if wrapper_hits and wrapper_hits >= max(1, len(evidence) // 2):
        score = 25
    elif any(token in " ".join(libraries) for token in ("commons.crypto", "springframework.security", "fernet")):
        score = 20
    elif len(libraries) == 1:
        score = 10
    elif len(libraries) > 3:
        score = -10
    else:
        score = 0
    return score


def score_deployment_architecture(system: Mapping[str, Any] | None, evidence: list[Mapping[str, Any]] | None = None) -> int:
    extra = (system or {}).get("extra") or {}
    env = str((system or {}).get("environment") or extra.get("deployment_type") or "").upper()
    blob = _text_blob(system)
    if extra.get("hot_reload") or any(token in blob for token in HOT_RELOAD):
        return 25
    if env in {"KUBERNETES", "K8S"} or extra.get("configmap") or extra.get("external_config"):
        return 20
    if extra.get("twelve_factor") or extra.get("config_externalized"):
        return 15
    if extra.get("blue_green"):
        return 10
    if extra.get("static_binary"):
        return -20
    if extra.get("config_baked_in_image"):
        return -10
    paths = [_path(row) for row in (evidence or [])]
    if any("configmap" in path or "secret.yaml" in path or "/k8s/" in path for path in paths):
        return 20
    return 0


def score_testing(system: Mapping[str, Any] | None, evidence: list[Mapping[str, Any]] | None = None) -> int:
    extra = (system or {}).get("extra") or {}
    if extra.get("crypto_tests") or extra.get("has_crypto_test_suite"):
        score = 20
        if extra.get("parameterized_crypto_tests"):
            score += 15
        return min(35, score)
    paths = [_path(row) for row in (evidence or [])]
    test_hits = [path for path in paths if any(token in path for token in TEST_TOKENS)]
    if test_hits:
        return 20 if any(any(word in path for word in CRYPTO_WORDS) for path in test_hits) else 10
    if extra.get("has_tests"):
        return 10
    if extra.get("no_tests"):
        return -10
    return 0


def score_documentation(system: Mapping[str, Any] | None) -> int:
    extra = (system or {}).get("extra") or {}
    blob = _text_blob(system)
    score = 0
    if extra.get("has_crypto_docs") or extra.get("has_crypto_change_procedure") or any(word in blob for word in DOC_WORDS):
        score += 15
    if extra.get("has_crypto_inventory_docs"):
        score += 10
    if extra.get("has_dr_plan"):
        score += 10
    return score


FACTOR_META = (
    ("factor1", "Algorithm Configurability", 30),
    ("factor2", "Key Management", 30),
    ("factor3", "Abstraction Layer", 25),
    ("factor4", "Deployment Architecture", 25),
    ("factor5", "Testing", 35),
    ("factor6", "Documentation", 35),
)

# Post-quantum relevance (indicator only — never feeds the agility score):
# Shor breaks every deployed asymmetric construction; symmetric hashes/MACs
# and block ciphers only lose half their security margin to Grover.
QUANTUM_VULNERABLE_TOKENS = (
    "rsa", "ec", "ecc", "ecdh", "ecdsa", "ed25519", "ed448", "dsa", "dh",
    "diffie", "hellman", "x25519", "secp", "elliptic", "p-256", "p-384",
)
QUANTUM_RESISTANT_TOKENS = ("aes", "hmac", "sha", "chacha", "poly1305", "salsa")
HYBRID_TOKENS = ("ml-kem", "mlkem", "kyber", "dilithium", "falcon", "sphincs", "hqc", "composite", "hybrid")


def classify_quantum(algorithm: str) -> str:
    """Classify an algorithm name: QUANTUM_VULNERABLE / QUANTUM_RESISTANT / UNKNOWN."""
    token = str(algorithm or "").lower()
    if not token:
        return "UNKNOWN"
    if any(word in token for word in QUANTUM_VULNERABLE_TOKENS):
        return "QUANTUM_VULNERABLE"
    if any(word in token for word in QUANTUM_RESISTANT_TOKENS):
        return "QUANTUM_RESISTANT"
    return "UNKNOWN"


def pqc_exposure(evidence: list[Mapping[str, Any]], system: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Post-quantum exposure indicators from observed algorithms.

    Honest by design: hybrid_support is None (unknown) when no hybrid/PQC
    signal exists — absence of evidence is not evidence of absence.
    """
    vulnerable: set[str] = set()
    resistant: set[str] = set()
    unknown: set[str] = set()
    vulnerable_sites = 0
    for row in evidence:
        algorithm = str(row.get("algorithm") or "")
        verdict = classify_quantum(algorithm)
        if verdict == "QUANTUM_VULNERABLE":
            vulnerable.add(algorithm)
            vulnerable_sites += 1
        elif verdict == "QUANTUM_RESISTANT":
            resistant.add(algorithm)
        else:
            unknown.add(algorithm)
    blob = " ".join(_library(row) for row in evidence) + " " + _text_blob(system)
    hybrid_signals = sorted({token for token in HYBRID_TOKENS if token in blob}) or None
    return {
        "quantum_vulnerable_sites": vulnerable_sites,
        "quantum_vulnerable_algorithms": sorted(vulnerable),
        "quantum_resistant_algorithms": sorted(resistant),
        "unknown_algorithms": sorted(unknown - {""}),
        "hybrid_signals": hybrid_signals,
        "hybrid_support": bool(hybrid_signals) if hybrid_signals else None,
        "note": "indicators only: asymmetric crypto needs PQC migration, symmetric only widens key/MAC sizes",
    }


def collect_signals(evidence: list[Mapping[str, Any]], system: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Deterministic audit trail of the inputs each factor scored against."""
    paths = [_path(row) for row in evidence]
    reasons = [_reason(row) for row in evidence]
    libraries = {lib for row in evidence if (lib := _library(row))}
    algos = [str(row.get("algorithm") or "") for row in evidence if row.get("algorithm")]
    extra = (system or {}).get("extra") or {}
    blob = _text_blob(system)
    return {
        "total_sites": len(evidence),
        "distinct_algorithms": sorted({a for a in algos}),
        "max_algorithm_reuse": max((algos.count(a) for a in set(algos)), default=0),
        "config_file_hits": sum(1 for path in paths if path.endswith(CONFIG_SUFFIXES) or "/config/" in path),
        "hardcoded_key_sites": sum(1 for row in evidence if row.get("is_hardcoded_key")),
        "hardcoded_reason_sites": sum(1 for reason in reasons if any(t in reason for t in HARDCODED_REASONS)),
        "factory_reason_sites": sum(1 for reason in reasons if any(t in reason for t in FACTORY_REASONS)),
        "distinct_libraries": sorted(libraries),
        "wrapper_hits": sum(1 for path in paths if any(name in path.replace("\\", "/") for name in WRAPPER_NAMES)),
        "kms_hint": next((hint for hint in KMS_HINTS if hint in " ".join(libraries) + " " + blob), None),
        "test_hits": sum(1 for path in paths if any(token in path for token in TEST_TOKENS)),
        "crypto_test_hits": sum(
            1
            for path in paths
            if any(token in path for token in TEST_TOKENS) and any(word in path for word in CRYPTO_WORDS)
        ),
        "hot_reload": bool(extra.get("hot_reload")) or any(token in blob for token in HOT_RELOAD),
        "doc_flags": sorted(
            flag
            for flag, present in (
                ("has_crypto_docs", extra.get("has_crypto_docs") or extra.get("has_crypto_change_procedure")),
                ("has_crypto_inventory_docs", extra.get("has_crypto_inventory_docs")),
                ("has_dr_plan", extra.get("has_dr_plan")),
            )
            if present
        ),
        "secrets_in_git": bool(extra.get("secrets_in_git")),
    }


def _recommendations(factors: dict[str, int]) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    if factors["factor1"] < 15:
        recs.append(
            {
                "factor": "Algorithm Configurability",
                "issue": "Algorithms are hardcoded",
                "recommendation": "Move algorithm selection to a config file",
                "effort": "MEDIUM",
                "impact": "+20 agility points",
                "factor_key": "factor1",
                "impact_points": 20,
            }
        )
    if factors["factor2"] < 0:
        recs.append(
            {
                "factor": "Key Management",
                "issue": "Hardcoded keys detected",
                "recommendation": "Migrate to AWS KMS, Azure Key Vault, or HashiCorp Vault",
                "effort": "HIGH",
                "impact": "+30 agility points",
                "urgency": "CRITICAL",
                "factor_key": "factor2",
                "impact_points": 30,
            }
        )
    if factors["factor3"] < 10:
        recs.append(
            {
                "factor": "Abstraction Layer",
                "issue": "Direct crypto API calls are scattered",
                "recommendation": "Introduce a CryptoService wrapper",
                "effort": "HIGH",
                "impact": "+25 agility points",
                "factor_key": "factor3",
                "impact_points": 25,
            }
        )
    if factors["factor4"] < 10:
        recs.append(
            {
                "factor": "Deployment Architecture",
                "issue": "Crypto config is baked into the deployment",
                "recommendation": "Use Kubernetes ConfigMaps/Secrets or external config",
                "effort": "LOW",
                "impact": "+15 agility points",
                "factor_key": "factor4",
                "impact_points": 15,
            }
        )
    if factors["factor5"] < 10:
        recs.append(
            {
                "factor": "Testing",
                "issue": "No crypto-specific tests",
                "recommendation": "Add a parameterized crypto test suite",
                "effort": "MEDIUM",
                "impact": "+15 agility points",
                "factor_key": "factor5",
                "impact_points": 15,
            }
        )
    if factors["factor6"] < 10:
        recs.append(
            {
                "factor": "Documentation",
                "issue": "No crypto change procedure",
                "recommendation": "Document algorithm and key rotation steps",
                "effort": "LOW",
                "impact": "+15 agility points",
                "factor_key": "factor6",
                "impact_points": 15,
            }
        )
    return recs


def calculate_agility_score(
    evidence: Iterable[Mapping[str, Any]],
    system: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    rows = list(evidence)
    factors = {
        "factor1": score_algorithm_configurability(rows),
        "factor2": score_key_management(rows, system),
        "factor3": score_abstraction_layer(rows),
        "factor4": score_deployment_architecture(system, rows),
        "factor5": score_testing(system, rows),
        "factor6": score_documentation(system),
    }
    raw = sum(factors.values())
    score = normalize_score(raw)
    meta = categorize_score(score)
    recs = _recommendations(factors)
    estimated = min(100, score + sum(int(r.get("impact_points") or 0) for r in recs))
    factor_details = []
    for key, name, maximum in FACTOR_META:
        value = factors[key]
        ratio = (value / maximum) if maximum else 0.0
        if value < 0 or ratio < 0.33:
            status = "CRITICAL"
        elif ratio < 0.66:
            status = "AT_RISK"
        else:
            status = "OK"
        factor_details.append(
            {"key": key, "name": name, "score": value, "maximum": maximum, "utilization": round(max(0.0, ratio), 3), "status": status}
        )
    return {
        "agility_score": score,
        "score": score,
        "raw_score": raw,
        "category": meta["category"],
        "description": meta["description"],
        "factor_scores": factors,
        "recommendations": recs,
        "estimated_final_score": estimated,
        "factor_details": factor_details,
        "factor_signals": collect_signals(rows, system),
        "pqc_exposure": pqc_exposure(rows, system),
        "calculation_version": "agility-v1.1",
        "total_sites": len(rows),
    }
