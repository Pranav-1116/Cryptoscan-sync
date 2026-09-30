"""Normalized, redacted evidence and release identity for static binary analysis.

This module is deliberately independent of the format parsers.  Parsers emit
slightly different names (``import_symbols`` for PE, ``member_names`` for Java,
DEX ``method_names`` and so on); the API, BOMs and persistence layers need one
contract.  The contract is evidence of what was present in bytes, not evidence
that a method ran at runtime.

No function in this module executes, emulates, disassembles, validates a
certificate chain, or treats a cryptographic marker as a live network
observation.  Values are bounded and sensitive key material is dropped before a
record can be returned to a caller or persisted in the read model.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

MODEL_VERSION = "1.0"
MAX_EVIDENCE_ROWS = 600
MAX_EVIDENCE_VALUE = 300
MAX_GRAPH_NODES = 5000
MAX_GRAPH_EDGES = 10000

EVIDENCE_KINDS = frozenset({
    "import", "export", "symbol", "api", "class", "method", "constant",
    "string", "library_match", "manifest", "certificate", "metadata", "unknown",
})

_SECRET_KEY_RE = re.compile(
    r"(?:private.?key|secret|password|passphrase|token|credential|key.?material|"
    r"raw.?bytes|certificate.?der|signature.?blob)", re.IGNORECASE,
)
_CRYPTO_STRING_RE = re.compile(
    r"(?:aes|des|3des|chacha|poly1305|rsa|ecdsa|ed25519|x25519|sha(?:1|2|3)?|"
    r"md5|hmac|hkdf|pbkdf|argon|scrypt|tls|ssl|openssl|bouncycastle|crypto|"
    r"cryptography|sodium|secure.?random|drbg)", re.IGNORECASE,
)


def _text(value: Any, limit: int = MAX_EVIDENCE_VALUE) -> str:
    return str(value).replace("\x00", "")[:limit]


def _redact(value: Any, *, depth: int = 0) -> Any:
    """Remove secret-shaped fields from arbitrary parser metadata.

    This is a second safety boundary.  The key parser already returns hashes and
    public certificate metadata, but future parsers must not accidentally make a
    PEM body or a decoded secret part of a normalized evidence row.
    """
    if depth > 4:
        return "[truncated]"
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            name = _text(key, 100)
            if _SECRET_KEY_RE.search(name):
                continue
            cleaned = _redact(item, depth=depth + 1)
            if cleaned is not None:
                output[name] = cleaned
        return output
    if isinstance(value, (list, tuple, set)):
        return [_redact(item, depth=depth + 1) for item in list(value)[:80]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return _text(value) if isinstance(value, str) else value
    return _text(value)


def _confidence(value: Any, default: float = 0.4) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return round(max(0.0, min(1.0, number)), 3)


def _location(record: Mapping[str, Any], *, offset: Any = None,
              section: Any = None, member: Any = None) -> dict[str, Any]:
    """Return relative/member provenance only; never expose an absolute target path."""
    path = record.get("path") or record.get("file_name") or record.get("name")
    location: dict[str, Any] = {}
    if path:
        location["file"] = _text(path)
    if member:
        location["member"] = _text(member)
    if section:
        location["section"] = _text(section)
    if isinstance(offset, int) and offset >= 0:
        location["offset"] = offset
    return location


def _row(kind: str, value: Any, *, record: Mapping[str, Any], source: str,
         confidence: Any = 0.4, offset: Any = None, section: Any = None,
         member: Any = None, caveat: str | None = None, **extra: Any) -> dict[str, Any]:
    if kind not in EVIDENCE_KINDS:
        kind = "unknown"
    # Parser adapters historically called this keyword ``runtime_caveat``;
    # consume it here so it becomes the canonical field instead of a second,
    # ambiguous caveat key.
    if extra.get("runtime_caveat"):
        caveat = str(extra.pop("runtime_caveat"))
    result: dict[str, Any] = {
        "evidence_kind": kind,
        "value": _text(value),
        "source": _text(source),
        "location": _location(record, offset=offset, section=section, member=member),
        "confidence": _confidence(confidence),
        # Static symbol/API presence must never be promoted to an execution claim.
        "runtime_behavior_proven": False,
        "runtime_behavior_caveat": caveat or (
            "static presence only; this observation does not prove runtime execution, "
            "reachability, exploitability, or trust validation"),
    }
    for key, value in extra.items():
        if value is not None and key not in {"private_key", "secret", "material"}:
            result[key] = _redact(value)
    return result


def _append(rows: list[dict[str, Any]], kind: str, values: Iterable[Any], *,
            record: Mapping[str, Any], source: str, confidence: Any = 0.4,
            caveat: str | None = None) -> None:
    for value in values:
        if value in (None, ""):
            continue
        detail: dict[str, Any] = {}
        display = value
        if isinstance(value, Mapping):
            display = value.get("algorithm") or value.get("name") or value.get("table") or value.get("kind")
            detail["detail"] = value
        rows.append(_row(kind, display, record=record, source=source,
                         confidence=confidence, caveat=caveat, **detail))
        if len(rows) >= MAX_EVIDENCE_ROWS:
            return


def _parser_state(record: Mapping[str, Any]) -> str:
    """Explicit parser state used by both API and persistence projections."""
    if record.get("refused") or record.get("refused_by_limit"):
        return "REFUSED_BY_LIMIT"
    note = _text(record.get("parse_error") or record.get("parse_note") or "").lower()
    if record.get("parsed") is False:
        if "unsupported" in note or "unrecognised" in note or "not parsed" in note:
            return "UNSUPPORTED"
        return "MALFORMED"
    if record.get("parsed") is not True:
        return "UNKNOWN"
    nested = record.get("embedded") or []
    tables = (record.get("dex") or {}, record.get("python") or {}, record.get("wasm") or {})
    if record.get("packer") or any(isinstance(item, Mapping) and item.get("truncated") for item in tables):
        return "PARTIAL"
    if record.get("containers_followed") and any(
            isinstance(item, Mapping) and (item.get("refused") or item.get("truncated"))
            for item in record.get("containers_followed") or []):
        return "PARTIAL"
    if any(_parser_state(item) != "COMPLETE" for item in nested if isinstance(item, Mapping)):
        return "PARTIAL"
    return "COMPLETE"


def _algorithm_source(strongest: str, record: Mapping[str, Any]) -> str:
    level = _text(strongest or "unknown").lower().replace(" ", "_")
    return f"{_text(record.get('format') or 'binary')}.crypto.{level}"


def normalize_evidence(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize parser output into bounded, provenance-carrying evidence rows."""
    rows: list[dict[str, Any]] = []
    fmt = _text(record.get("format") or "unknown")
    _append(rows, "import", record.get("imports") or [], record=record,
            source=f"{fmt}.import_table", confidence=0.8)
    _append(rows, "export", record.get("exports") or [], record=record,
            source=f"{fmt}.export_table", confidence=0.8)
    _append(rows, "api", (record.get("import_symbols") or []) +
            (record.get("delay_import_symbols") or []), record=record,
            source=f"{fmt}.api_table", confidence=0.75)
    _append(rows, "symbol", record.get("symbols") or [], record=record,
            source=f"{fmt}.symbol_table", confidence=0.7)

    java = record.get("java") or {}
    if isinstance(java, Mapping):
        _append(rows, "class", java.get("classes") or [], record=record,
                source=f"{fmt}.class_constant_pool", confidence=0.8)
        _append(rows, "method", java.get("member_names") or java.get("method_names") or [],
                record=record, source=f"{fmt}.method_constant_pool", confidence=0.65)
    dex = record.get("dex") or {}
    if isinstance(dex, Mapping):
        _append(rows, "class", dex.get("classes") or [], record=record,
                source="dex.class_defs", confidence=0.9)
        _append(rows, "method", dex.get("method_names") or [], record=record,
                source="dex.method_ids", confidence=0.8)
    python = record.get("python") or {}
    if isinstance(python, Mapping):
        _append(rows, "method", python.get("names") or [], record=record,
                source="python.code_object.names", confidence=0.65)

    string_values: list[str] = []
    for table in (java, dex, python, record.get("wasm") or {}):
        if isinstance(table, Mapping):
            string_values.extend(_text(item) for item in (table.get("strings") or [])
                                if isinstance(item, str))
    string_values.extend(_text(item) for item in (record.get("string_evidence") or [])
                         if isinstance(item, str))
    crypto_value = record.get("crypto") or {}
    crypto_string_values = (crypto_value.get("string_evidence") or []
                            if isinstance(crypto_value, Mapping) else [])
    if isinstance(crypto_string_values, (list, tuple)):
        string_values.extend(_text(item) for item in crypto_string_values if isinstance(item, str))
    safe_strings = [value for value in dict.fromkeys(string_values)
                    if _CRYPTO_STRING_RE.search(value) and not _SECRET_KEY_RE.search(value)]
    _append(rows, "string", safe_strings, record=record,
            source=f"{fmt}.crypto_relevant_strings", confidence=0.45,
            caveat="crypto-relevant string only; the string does not prove a code path or runtime use")

    crypto = record.get("crypto") or {}
    if isinstance(crypto, Mapping):
        for library in crypto.get("libraries") or []:
            if isinstance(library, Mapping):
                name = library.get("library") or library.get("name")
                if name:
                    rows.append(_row(
                        "library_match", name, record=record,
                        source=f"{fmt}.library_fingerprint",
                        confidence=0.9 if library.get("evidence_classes") else 0.6,
                        version=library.get("version"),
                        evidence_classes=library.get("evidence_classes"),
                        verdict=library.get("verdict"),
                    ))
        for algorithm in crypto.get("algorithm_evidence") or []:
            if not isinstance(algorithm, Mapping):
                continue
            name = algorithm.get("name") or algorithm.get("algorithm")
            if not name:
                continue
            rows.append(_row(
                "metadata", name, record=record,
                source=_algorithm_source(str(algorithm.get("strongest_evidence")), record),
                confidence=algorithm.get("confidence"),
                evidence_sources=algorithm.get("sources"),
                verdict=algorithm.get("verdict"),
                linkage="static-algorithm-evidence",
            ))
        _append(rows, "constant", crypto.get("constants_found") or [], record=record,
                source=f"{fmt}.constant_table", confidence=0.85)
        # Transformation strings are more useful than a raw string dump, and are
        # already bounded by the parser's crypto detector.
        for algorithm in crypto.get("algorithms") or []:
            if not any(row.get("value") == _text(algorithm) and
                       row.get("evidence_kind") == "metadata" for row in rows):
                rows.append(_row("metadata", algorithm, record=record,
                                 source=f"{fmt}.crypto.catalog", confidence=0.55))

    for key in (record.get("embedded_keys") or {}).get("keys") or []:
        if not isinstance(key, Mapping):
            continue
        kind = "certificate" if key.get("kind") == "certificate" else "metadata"
        detail = key.get("detail") if isinstance(key.get("detail"), Mapping) else {}
        rows.append(_row(
            kind, key.get("name") or key.get("format") or key.get("kind"),
            record=record, source=f"{fmt}.embedded_key_inventory",
            confidence=0.95 if kind == "certificate" else 0.8,
            key_kind=key.get("kind"), key_type=key.get("key_type"),
            key_bits=key.get("key_bits"), curve=key.get("curve"),
            material_sha256=key.get("material_sha256"),
            certificate_subject=detail.get("subject"), certificate_issuer=detail.get("issuer"),
            certificate_not_after=detail.get("not_after"),
        ))

    android = record.get("android") or {}
    manifest = android.get("manifest") if isinstance(android, Mapping) else None
    if isinstance(manifest, Mapping):
        for permission in manifest.get("permissions") or []:
            rows.append(_row("manifest", permission, record=record,
                             source="android.manifest.permission", confidence=0.95,
                             runtime_caveat="manifest declaration only; grant and runtime use are not proven"))
        for component in manifest.get("components") or []:
            if isinstance(component, Mapping):
                rows.append(_row("manifest", component.get("name") or component.get("type"),
                                 record=record, source="android.manifest.component", confidence=0.9,
                                 exported=component.get("exported"),
                                 runtime_caveat=("manifest component declaration only; launch and "
                                                 "reachability are not proven")))

    for key, source in (("libraries", f"{fmt}.metadata.libraries"),
                        ("sections", f"{fmt}.metadata.sections"),
                        ("relocations", f"{fmt}.relocation_table"),
                        ("got_sections", f"{fmt}.got_metadata")):
        _append(rows, "metadata", record.get(key) or [], record=record,
                source=source, confidence=0.6)
    for key in ("build_id", "uuid", "compiler", "platform", "minimum_os", "dotnet", "go"):
        value = record.get(key)
        if value not in (None, "", [], {}):
            rows.append(_row("metadata", value if not isinstance(value, Mapping) else key,
                             record=record, source=f"{fmt}.header_metadata", confidence=0.9,
                             detail=value))

    state = _parser_state(record)
    if state != "COMPLETE":
        rows.append(_row(
            "unknown", state, record=record, source=f"{fmt}.parser_state", confidence=1.0,
            parser_state=state,
            runtime_caveat="analysis coverage is incomplete; absence of a finding is not a clean result"))
    return rows[:MAX_EVIDENCE_ROWS]


def _canonical(value: Any) -> str:
    return json.dumps(_redact(value), sort_keys=True, separators=(",", ":"), default=str)


def release_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a stable identity suitable for release comparison and dedupe."""
    fingerprints = record.get("fingerprints") or {}
    identity_fields = {
        "sha256": record.get("sha256"),
        "format": record.get("format"),
        "arch": record.get("arch") or record.get("machine"),
        "build_id": record.get("build_id") or fingerprints.get("build_id"),
        "uuid": record.get("uuid") or fingerprints.get("uuid"),
        "code_sha256": fingerprints.get("code_sha256"),
        "imports_sha256": fingerprints.get("imports_sha256"),
        "exports_sha256": hashlib.sha256(_canonical(record.get("exports") or []).encode()).hexdigest(),
        "package": (record.get("name") or record.get("file_name")),
        "version": record.get("version") or (record.get("java") or {}).get("version")
        or (record.get("python") or {}).get("version"),
    }
    stable_material = {key: value for key, value in identity_fields.items() if value not in (None, "")}
    stable_id = "binary:" + hashlib.sha256(_canonical(stable_material).encode()).hexdigest()
    return {"model_version": MODEL_VERSION, "stable_id": stable_id, **_redact(identity_fields)}


def enrich_record(record: dict[str, Any]) -> dict[str, Any]:
    """Attach the normalized contract without changing parser-specific fields."""
    state = _parser_state(record)
    record["parser_state"] = state
    record["runtime_behavior_proven"] = False
    record["runtime_behavior_caveat"] = (
        "static analysis only; observed imports, APIs, methods and algorithms do not prove execution")
    record["evidence_model_version"] = MODEL_VERSION
    record["evidence"] = normalize_evidence(record)
    record["identity"] = release_identity(record)
    return record


def scan_state(scan: Mapping[str, Any]) -> str:
    """Compute an honest overall result state from limits and parser states."""
    limits = scan.get("limits") or {}
    if limits.get("cancelled"):
        return "CANCELLED"
    if limits.get("budget_exhausted") or limits.get("truncated"):
        return "PARTIAL"
    states = [str(row.get("parser_state") or _parser_state(row))
              for row in _flatten(scan.get("binaries") or [])]
    if any(state in {"PARTIAL", "MALFORMED", "UNSUPPORTED", "REFUSED_BY_LIMIT", "UNKNOWN"}
           for state in states):
        return "PARTIAL"
    return "COMPLETE"


def _flatten(records: Iterable[Mapping[str, Any]], depth: int = 0) -> list[Mapping[str, Any]]:
    if depth > 8:
        return []
    output: list[Mapping[str, Any]] = []
    for record in records:
        output.append(record)
        children = record.get("embedded") or []
        if isinstance(children, list):
            output.extend(_flatten((child for child in children if isinstance(child, Mapping)), depth + 1))
    return output


def provenance_graph(scan: Mapping[str, Any]) -> dict[str, Any]:
    """Build a bounded parent/child graph for nested artifacts."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    by_path: dict[str, str] = {}
    for record in _flatten(scan.get("binaries") or []):
        if len(nodes) >= MAX_GRAPH_NODES:
            break
        identity = release_identity(record)
        path = _text(record.get("path") or record.get("name") or "unknown")
        node_id = identity["stable_id"]
        # A repeated hash can occur in two package members.  Location is part of
        # the graph identity while the release identity remains content stable.
        graph_id = node_id + "@" + hashlib.sha256(path.encode()).hexdigest()[:16]
        by_path[path] = graph_id
        node = {
            "id": graph_id,
            "identity": identity,
            "path": path,
            "format": record.get("format"),
            "sha256": record.get("sha256"),
            "parser_state": record.get("parser_state") or _parser_state(record),
            "extraction_reason": "top-level-input" if not record.get("derived_from") else "container-member",
            "member_offset": record.get("member_offset"),
            "member_size": record.get("size"),
        }
        nodes.append(node)
        parent_path = record.get("derived_from")
        if parent_path and parent_path in by_path and len(edges) < MAX_GRAPH_EDGES:
            edges.append({"from": by_path[parent_path], "to": graph_id,
                          "relationship": "contains", "reason": "bounded-static-extraction"})
    truncated = len(nodes) >= MAX_GRAPH_NODES or len(edges) >= MAX_GRAPH_EDGES
    return {"model_version": MODEL_VERSION, "nodes": nodes, "edges": edges,
            "truncated": truncated, "runtime_observed": False,
            "note": "containment is derived from bounded file/container parsing; no content was executed"}


def _asset_set(record: Mapping[str, Any]) -> dict[str, set[str]]:
    crypto = record.get("crypto") or {}
    libraries = {str(row.get("library") or row.get("name")) for row in crypto.get("libraries") or []
                 if isinstance(row, Mapping)}
    algorithms = {str(row) for row in crypto.get("algorithms") or []}
    certificates = {str(row.get("material_sha256")) for row in
                    (record.get("embedded_keys") or {}).get("keys") or []
                    if isinstance(row, Mapping) and row.get("kind") == "certificate" and row.get("material_sha256")}
    return {"libraries": libraries - {"None"}, "algorithms": algorithms,
            "certificates": certificates}


def compare_releases(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Compare normalized records without treating static findings as execution."""
    left, right = _asset_set(before), _asset_set(after)
    identity_before, identity_after = release_identity(before), release_identity(after)
    changes: dict[str, Any] = {}
    for name in ("libraries", "algorithms", "certificates"):
        changes[name] = {
            "added": sorted(right[name] - left[name]),
            "removed": sorted(left[name] - right[name]),
        }
    parser_before = before.get("parser_state") or _parser_state(before)
    parser_after = after.get("parser_state") or _parser_state(after)
    changes["parser_coverage"] = {"before": parser_before, "after": parser_after,
                                   "changed": parser_before != parser_after}
    changes["identity_changed"] = identity_before["stable_id"] != identity_after["stable_id"]
    changes["changed"] = bool(changes["identity_changed"] or
                               any(item["added"] or item["removed"] for item in changes.values()
                                   if isinstance(item, Mapping) and "added" in item))
    return {"model_version": MODEL_VERSION, "changed": changes["changed"],
            "before": identity_before, "after": identity_after, "changes": changes,
            "runtime_behavior_proven": False,
            "note": "release differences are static evidence differences, not proof of runtime behavior"}
