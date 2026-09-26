"""Sensitive-data controls — redaction, masking, tokenization and retention.

Spec §13: the crypto scanner may record ``algorithm = RSA`` / ``key_size = 2048``
/ certificate metadata, but it must NOT copy private keys, user passwords,
customer documents, personal data or full database contents. When a private key
is detected the rule is: DO NOT STORE the key; store algorithm / key size /
fingerprint / evidence metadata and alert.

A :class:`RedactionEngine` applies a :class:`~privacy.policy.PrivacyPolicy` to a
single observation, returning a :class:`RedactionResult` with the sanitized
payload, what was dropped/redacted, whether a private key was detected, and the
retention decision. Pure / deterministic — unit-testable without I/O.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from privacy.classify import DataClass, classify_value
from privacy.policy import MINIMALLY_REQUIRED_FIELDS, PrivacyPolicy


@dataclass
class RedactionResult:
    observation: dict[str, Any]          # sanitized observation (stored shape)
    dropped_fields: list[str] = field(default_factory=list)
    redacted_fields: list[str] = field(default_factory=list)
    tokenized_fields: list[str] = field(default_factory=list)
    truncated_payload: bool = False
    private_key_detected: bool = False
    should_store: bool = True
    retention_days: int | None = None
    alerts: list[str] = field(default_factory=list)
    classification: str = "public"

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation": self.observation,
            "dropped_fields": self.dropped_fields,
            "redacted_fields": self.redacted_fields,
            "tokenized_fields": self.tokenized_fields,
            "truncated_payload": self.truncated_payload,
            "private_key_detected": self.private_key_detected,
            "should_store": self.should_store,
            "retention_days": self.retention_days,
            "alerts": self.alerts,
            "classification": self.classification,
        }


#: long-lived secret / credential value detectors (value-level, not field-level).
_SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|"
    r"AIza[0-9A-Za-z_-]{35}|-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(\+?\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


class RedactionEngine:
    """Apply a :class:`PrivacyPolicy` to one observation dict."""

    def __init__(self, policy: PrivacyPolicy) -> None:
        self.policy = policy

    def process(self, observation: dict[str, Any]) -> RedactionResult:
        """Return the sanitation result for ``observation``.

        The observation is treated as an already-normalized map (the same shape
        a connector emits). First the whole object is classified; then each
        value is classified and subjected to the policy controls.
        """
        res = RedactionResult(observation={})
        data = dict(observation or {})
        if not data:
            res.should_store = False
            return res

        # classify the whole observation from the most restrictive value
        classes = [classify_value(k, v) for k, v in data.items()]
        top = max(classes, key=lambda c: {DataClass.PUBLIC: 0, DataClass.SENSITIVE: 1, DataClass.RESTRICTED: 2}[c])
        res.classification = top.value

        out: dict[str, Any] = {}
        for key, value in data.items():
            cls = classify_value(key, value)

            if cls is DataClass.RESTRICTED or self._is_secret_value(value):
                # RESTRICTED -> never store the value itself. Drop it, keep
                # only a fingerprint/identifier if the policy permits metadata.
                res.dropped_fields.append(key)
                if self.policy.alert_on_private_key and self._is_private_key_value(value):
                    res.private_key_detected = True
                    res.alerts.append(f"PRIVATE_KEY_DETECTED:{key}")
                elif self.policy.redact_secrets or cls is DataClass.RESTRICTED:
                    res.alerts.append(f"SENSITIVE_DROPPED:{key}")
                if self.policy.allow_evidence_metadata:
                    out[key + "_fp"] = self._fingerprint(value)
                continue

            if cls is DataClass.SENSITIVE:
                if self.policy.tokenize_identifiers and self._is_identifier(key):
                    out[key] = self._tokenize(value)
                    res.tokenized_fields.append(key)
                    continue
                if self.policy.mask_sensitive_fields:
                    out[key] = self._mask(value)
                    res.redacted_fields.append(key)
                    continue
                # policy says we may store it (e.g. certificate metadata)
                if self.policy.enforce_payload_limits and self._too_big(value):
                    out[key] = self._truncate(value)
                    res.truncated_payload = True
                    continue
                out[key] = value
                continue

            # public -> store as-is, subject to field allowlist + payload cap
            if self.policy.enforce_payload_limits and self._too_big(value):
                out[key] = self._truncate(value)
                res.truncated_payload = True
                continue
            out[key] = value

        # data minimization: drop fields not on the allowlist for this type
        if self.policy.data_minimization:
            res.dropped_fields.extend(self._drop_non_allowed(out, data))
            out = {k: v for k, v in out.items() if k in self._allowed(data)}
            # keep token/fingerprint companions that reference allowed fields
            out = {k: v for k, v in out.items()
                   if k in self._allowed(data) or k.endswith("_fp")}

        # private key present -> explicitly refuse to store (spec §13)
        if res.private_key_detected and not self.policy.collect_private_keys:
            res.should_store = False
            res.observation = {
                "dropped_private_key": True,
                "fingerprint": self._fingerprint(data),
                "alert": "private_key_detected_not_stored",
                **(self._allowed_meta(data)),
            }
            res.retention_days = 0
            return res

        res.observation = out
        res.retention_days = self.policy.retention_days
        return res

    # ----------------------------------------------------------- helpers

    def _allowed(self, obs: dict[str, Any]) -> set[str]:
        otype = str(obs.get("observation_type") or "*")
        base = set(MINIMALLY_REQUIRED_FIELDS.get(otype, MINIMALLY_REQUIRED_FIELDS["*"]))
        for k in obs:
            if k.endswith("_fp"):
                base.add(k)
        return base | set(MINIMALLY_REQUIRED_FIELDS["*"])

    def _drop_non_allowed(self, out: dict[str, Any], orig: dict[str, Any]) -> list[str]:
        allowed = self._allowed(orig)
        return [k for k in out if k not in allowed]

    def _allowed_meta(self, data: dict[str, Any]) -> dict[str, Any]:
        allowed = self._allowed(data)
        return {k: v for k, v in data.items() if k in allowed
                and classify_value(k, v) is not DataClass.RESTRICTED}

    def _is_identifier(self, key: str) -> bool:
        return bool(re.search(r"(id|identifier|uuid|asset|hostname|fqdn|serial|email|phone)$", key, re.I))

    def _is_secret_value(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return bool(_SECRET_RE.search(value))

    def _is_private_key_value(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return bool(re.search(r"-----\s*BEGIN.*PRIVATE KEY|ssh-rsa|ssh-ed25519", value, re.I))

    def _fingerprint(self, value: Any) -> str:
        return hashlib.sha256(repr(value).encode("utf-8", "replace")).hexdigest()[:24]

    def _tokenize(self, value: Any) -> str:
        if not isinstance(value, str):
            return value
        return "tok_" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]

    def _mask(self, value: Any) -> str:
        if isinstance(value, bool) or value is None:
            return value
        s = str(value)
        if _EMAIL_RE.fullmatch(s):
            local, _, domain = s.partition("@")
            return f"{local[0]}***@{domain}"
        if _SSN_RE.fullmatch(s):
            return "***-**-****"
        if _CARD_RE.fullmatch(s):
            return "**** " + s.replace(" ", "")[-4:]
        if len(s) <= 3:
            return "***"
        return s[0] + "*" * max(0, len(s) - 2) + s[-1]

    def _too_big(self, value: Any) -> bool:
        size = len(getattr(value, "encode", lambda: str(value).encode())())
        return size > self.policy.max_payload_bytes

    def _truncate(self, value: Any) -> str:
        if isinstance(value, str):
            return value[: self.policy.max_payload_bytes] + "…(truncated)"
        if isinstance(value, dict):
            return {"truncated_payload": True, "keys": list(value.keys())[:20]}
        return str(value)[: self.policy.max_payload_bytes]
