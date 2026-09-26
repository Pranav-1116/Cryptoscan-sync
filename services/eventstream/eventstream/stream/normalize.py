"""Normalization: raw scanner/daemon/telecom events -> canonical CBOM schema.

Pure and deterministic: the same raw event always normalizes to the same
canonical event. Unknown raw kinds are passed through with kind="unknown"
and an honest `unmapped: true` flag — never silently reshaped.
"""

from __future__ import annotations

from typing import Any

from eventstream.envelope import canonical_bytes

CANONICAL_FIELDS = (
    "kind", "system", "host", "endpoint", "proto",
    "algorithm", "key_size", "tls_version", "cert_fingerprint",
    "issuer", "observed_at", "source", "extra",
)


def _base(kind: str, source: str, observed_at: str | None) -> dict[str, Any]:
    return {
        "kind": kind, "system": None, "host": None, "endpoint": None, "proto": None,
        "algorithm": None, "key_size": None, "tls_version": None,
        "cert_fingerprint": None, "issuer": None,
        "observed_at": observed_at, "source": source, "extra": {},
    }


def normalize(raw: dict[str, Any], *, source: str = "unknown",
              observed_at: str | None = None) -> dict[str, Any]:
    """Map one raw event onto the canonical schema.

    Output contract: always a JSON-serializable canonical event (envelopes are
    HMAC-signed over canonical JSON). Typed loaders for known kinds; anything
    else is an honest `unknown` with `unmapped: true` and the original payload
    preserved (non-serializable values in visible string form)."""
    kind = str(raw.get("kind") or raw.get("event_type") or "").strip()
    if kind == "tls_finding" or "endpoint" in raw and "crypto" in raw:
        return _json_safe(_tls_finding(raw, source, observed_at))
    if kind == "monitor_pass" or "target_type" in raw and "summary" in raw:
        return _json_safe(_monitor_pass(raw, source, observed_at))
    if kind == "telecom_nf":
        return _json_safe(_telecom_nf(raw, source, observed_at))
    if kind == "cert":
        return _json_safe(_cert(raw, source, observed_at))
    if kind in {"diameter", "gtpc", "sip"}:
        return _json_safe(_telecom_passive(raw, source, observed_at))
    out = _base("unknown", source, observed_at)
    out["extra"] = _json_safe(dict(raw))
    out["extra"]["reported_kind"] = str(raw.get("kind") or raw.get("event_type")) or None
    out["extra"]["unmapped"] = True
    return out


def _json_safe(value: Any) -> Any:
    """Best-effort coercion keeping the event JSON-serializable (envelopes are
    HMAC-signed over canonical JSON). Visible repr, never silent data loss —
    the unmapped event still carries everything, in string form."""
    try:
        canonical_bytes(value)
        return value
    except (TypeError, ValueError):
        pass
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return f"bytes:{len(value)}:{bytes(value).hex()[:64]}"
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _dict_field(raw: dict[str, Any], key: str) -> dict[str, Any]:
    """Typed loaders only fold dict-shaped fields; junk shapes are ignored
    here (the raw payload still reaches extra/unmapped via the caller)."""
    value = raw.get(key)
    return value if isinstance(value, dict) else {}


def _tls_finding(raw: dict[str, Any], source: str, observed_at: str | None) -> dict[str, Any]:
    out = _base("tls_finding", source, observed_at)
    out["system"] = raw.get("system")
    out["endpoint"] = raw.get("endpoint")
    out["host"] = str(raw.get("endpoint") or "").rsplit(":", 1)[0] or None
    out["proto"] = "tls"
    crypto = _dict_field(raw, "crypto")
    out["tls_version"] = crypto.get("tls_version") or raw.get("tls_version")
    out["algorithm"] = crypto.get("algorithm") or raw.get("algorithm")
    out["key_size"] = crypto.get("key_size") or raw.get("key_size")
    out["cert_fingerprint"] = raw.get("fingerprint_sha256")
    out["issuer"] = raw.get("issuer")
    out["extra"] = {"policy_issues": raw.get("policy_issues") or [], "status": raw.get("status")}
    return out


def _monitor_pass(raw: dict[str, Any], source: str, observed_at: str | None) -> dict[str, Any]:
    out = _base("monitor_pass", source, observed_at)
    out["system"] = raw.get("target_name")
    out["proto"] = str(raw.get("target_type") or "").lower() or None
    summary = _dict_field(raw, "summary")
    out["extra"] = {"status": raw.get("status"), "summary": summary,
                    "tenant_id": raw.get("tenant_id")}
    return out


def _telecom_nf(raw: dict[str, Any], source: str, observed_at: str | None) -> dict[str, Any]:
    out = _base("telecom_nf", source, observed_at)
    out["system"] = raw.get("nf_name")
    out["endpoint"] = raw.get("endpoint")
    out["proto"] = raw.get("proto") or "sba"
    crypto = _dict_field(raw, "crypto") or _dict_field(raw, "pqc")
    out["algorithm"] = crypto.get("kex") or crypto.get("algorithm")
    out["tls_version"] = crypto.get("tls_version")
    out["cert_fingerprint"] = crypto.get("cert_fingerprint")
    out["extra"] = {"pqc_ready": crypto.get("pqc_ready"), "plmn": raw.get("plmn")}
    return out


def _cert(raw: dict[str, Any], source: str, observed_at: str | None) -> dict[str, Any]:
    out = _base("cert", source, observed_at)
    out["cert_fingerprint"] = raw.get("fingerprint_sha256")
    out["issuer"] = raw.get("issuer")
    out["algorithm"] = raw.get("algorithm") or raw.get("sig_alg")
    out["key_size"] = raw.get("key_size")
    out["endpoint"] = raw.get("location") or raw.get("endpoint")
    out["extra"] = {"not_after": raw.get("not_after"), "subject": raw.get("subject")}
    return out


def _telecom_passive(raw: dict[str, Any], source: str, observed_at: str | None) -> dict[str, Any]:
    out = _base(str(raw.get("kind")), source, observed_at)
    out["proto"] = raw.get("proto")
    out["system"] = raw.get("origin_host") or raw.get("system")
    out["endpoint"] = raw.get("endpoint")
    out["algorithm"] = raw.get("algorithm")
    out["key_size"] = raw.get("key_size")
    out["extra"] = {k: v for k, v in raw.items()
                    if k not in CANONICAL_FIELDS and k not in {"kind"}}
    return out
