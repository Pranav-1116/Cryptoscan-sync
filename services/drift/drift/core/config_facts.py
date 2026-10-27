"""Config facts — stable identities for configuration-level crypto state.

The code drift detector compares *code findings*. Configuration drift needs
its own first-class facts: a cryptographic *setting* (TLS version in nginx,
a JWT secret in .env, a Terraform KMS key spec) identified by a stable key
that does not move when unrelated lines change.

Two hard rules, enforced by tests:

1. **Secrets never leave the estate.** For hardcoded keys found in config
   files, the fact stores only ``secret_present``, ``secret_length`` and a
   truncated SHA-256 of the value — never the value itself.
2. **Facts are deterministic.** The same config produces the same fact, so
   baseline vs. current comparison is meaningful.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable

CONFIG_LANGUAGES = {"CONFIG", "TERRAFORM", "K8S", "DOCKERFILE", "CLOUDFORMATION"}

_WEAK_TLS = {"SSLV2", "SSLV3", "TLS1.0", "TLS1.1"}
_WEAK_ALGOS = {"DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1"}


@dataclass(frozen=True)
class ConfigFact:
    """One immutable cryptographic configuration setting."""

    config_key: str            # stable identity across scans
    file_path: str             # repo-relative path
    library: str               # nginx / apache / openssl.cnf / config-secret / terraform ...
    algorithm: str
    value: str                 # normalized value (never a secret)
    key_size: int | None = None
    mode: str | None = None
    purpose: str = "UNKNOWN"
    line_number: int = 0
    secret_present: bool = False
    secret_length: int | None = None
    secret_hash: str | None = None   # sha256(value)[:16] — never the value

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_key": self.config_key,
            "file_path": self.file_path,
            "library": self.library,
            "algorithm": self.algorithm,
            "value": self.value,
            "key_size": self.key_size,
            "mode": self.mode,
            "purpose": self.purpose,
            "line_number": self.line_number,
            "secret_present": self.secret_present,
            "secret_length": self.secret_length,
            "secret_hash": self.secret_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConfigFact":
        return cls(**{k: data.get(k) for k in cls.__dataclass_fields__ if k in data})  # type: ignore[arg-type]


def _nested(data: dict[str, Any], *keys: str) -> Any:
    """Look up a value across flat and nested (crypto./metadata.) shapes."""
    for key in keys:
        if data.get(key) not in (None, ""):
            return data.get(key)
        for section in ("crypto", "metadata", "source"):
            section_data = data.get(section)
            if isinstance(section_data, dict) and section_data.get(key) not in (None, ""):
                return section_data.get(key)
    return None


def _finding_language(finding: dict[str, Any]) -> str:
    data = finding.get("finding_data") or {}
    if not isinstance(data, dict):
        data = {}
    return str(_nested(data, "language") or finding.get("language") or "").upper()


def _finding_scanner(finding: dict[str, Any]) -> str:
    data = finding.get("finding_data") or {}
    if not isinstance(data, dict):
        data = {}
    return str(_nested(data, "scanner_id") or finding.get("scanner_id") or "")


def _finding_library(finding: dict[str, Any]) -> str:
    data = finding.get("finding_data") or {}
    if not isinstance(data, dict):
        data = {}
    return str(_nested(data, "library") or finding.get("library") or "")


def _finding_raw(finding: dict[str, Any]) -> str:
    data = finding.get("finding_data") or {}
    if not isinstance(data, dict):
        data = {}
    return str(_nested(data, "raw_transformation") or finding.get("raw_transformation") or "")


def _is_config_finding(finding: dict[str, Any]) -> bool:
    language = _finding_language(finding)
    scanner = _finding_scanner(finding)
    library = _finding_library(finding)
    if language in CONFIG_LANGUAGES:
        return True
    if "static-config-scanner" in scanner:
        return True
    return bool(library)


def _secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def extract_config_facts(findings: Iterable[dict[str, Any]]) -> list[ConfigFact]:
    """Derive first-class config facts from evidence-row-shaped findings.

    Accepts the shapes produced by the worker pipeline (evidence rows with
    ``algorithm``/``key_size``/``mode``/``purpose``/``file_path`` plus
    ``finding_data`` carrying source/language/library/raw_transformation).
    """
    facts: dict[str, ConfigFact] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if not _is_config_finding(finding):
            continue
        data = finding.get("finding_data") or {}
        if not isinstance(data, dict):
            data = {}
        algorithm = str(finding.get("algorithm") or _nested(data, "algorithm") or "UNKNOWN")
        key_size = finding.get("key_size") or _nested(data, "key_size")
        mode = finding.get("mode") or _nested(data, "mode")
        purpose = str(finding.get("purpose") or _nested(data, "purpose") or "UNKNOWN")
        file_path = str(finding.get("file_path") or _nested(data, "file_path") or "config")
        line_number = int(finding.get("line_number") or _nested(data, "line_number") or 0)
        library = _finding_library(finding) or "config"
        raw = _finding_raw(finding)
        is_hardcoded = bool(
            finding.get("is_hardcoded_key")
            or _nested(data, "is_hardcoded_key")
            or _nested(data, "api_type") == "HARDCODED_KEY"
        )
        secret_value = str(raw) if is_hardcoded and raw not in {"secret", ""} else ""
        # Stable key: library + algorithm + purpose + raw token (secrets keyed
        # by their variable name only — the value never participates).
        if is_hardcoded:
            # The config key for a secret must never contain the secret's
            # value — it is derived from the library + algorithm + the
            # *variable name* only. The value never participates.
            variable = _nested(data, "variable_name") or ""
            token = variable if variable else algorithm
            config_key = f"{library}:{token}"
            value = f"secret:{len(secret_value)}" if secret_value else f"secret:{algorithm}"
            facts[config_key] = ConfigFact(
                config_key=config_key,
                file_path=file_path,
                library=library,
                algorithm=algorithm,
                value=value,
                key_size=key_size,
                mode=mode,
                purpose=purpose,
                line_number=line_number,
                secret_present=True,
                secret_length=len(secret_value) if secret_value else None,
                secret_hash=_secret_hash(secret_value) if secret_value else None,
            )
        else:
            token = raw or f"{algorithm}:{key_size}:{mode}"
            config_key = f"{library}:{token}"
            value = f"{algorithm}:{key_size or ''}:{mode or ''}"
            facts[config_key] = ConfigFact(
                config_key=config_key,
                file_path=file_path,
                library=library,
                algorithm=algorithm,
                value=value,
                key_size=key_size,
                mode=mode,
                purpose=purpose,
                line_number=line_number,
            )
    return list(facts.values())


def fact_weakness_rank(fact: ConfigFact) -> int:
    """Higher rank = weaker crypto posture (deterministic ordering)."""
    algo = (fact.algorithm or "").upper()
    value = (fact.value or "").upper()
    rank = 0
    if algo in _WEAK_ALGOS:
        rank += 3
    if algo in _WEAK_TLS or any(value.startswith(t) for t in _WEAK_TLS):
        rank += 2
    return rank
