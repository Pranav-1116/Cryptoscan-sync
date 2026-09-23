"""The GraphQL schema this platform actually resolves — binary scanning first.

The surface is read-only and bound to what the platform already stores, so a
GraphQL answer and a REST answer are the same facts: artifacts come from the
artifact store, batches from the job rows that carry ``batch_id``, knowledge from
the installed packs, runtime findings from the repository the ingest writes.

Two rules kept everywhere:

* a field that cannot answer **says why** (an error with its path) instead of
  returning an empty list, because "no data" and "could not look" are different
  answers and only one of them is safe to act on;
* every list is bounded, and the bound is in the response's ``extensions`` and in
  the per-field ``truncated``/window notes — a truncated list never reads as a
  complete one.

``__schema`` is introspection-lite: the fields below, their arguments and their
types, as this module resolves them. It is deliberately not the full GraphQL
introspection protocol — a client that needs that is talking to a different
implementation, and this surface would rather say so than pretend.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from api.graphql_lang import MAX_LIST, Argument, ExecutionContext, Resolver, execute, parse
from api.job_view import job_card

#: the reader roles, same set the REST read endpoints use
READER_ROLES = ("admin", "superadmin", "security_analyst", "auditor", "readonly")

_ARTIFACT_KINDS = ("binary", "sbom", "generic")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _store():
    from devsecops.artifact_store import artifact_storage

    return artifact_storage()


def _manifests() -> list[dict[str, Any]]:
    try:
        return list(_store().list_manifests())
    except Exception:  # noqa: BLE001 — an unreadable store is an empty store, reported by the caller
        return []


def _manifest(artifact_id: str) -> dict[str, Any] | None:
    return next((row for row in _manifests() if str(row.get("artifact_id")) == str(artifact_id)), None)


def _artifact_components(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        payload = json.loads(_store().get(manifest["storage_key"]).decode("utf-8"))
    except Exception:  # noqa: BLE001 — a manifest whose blob is gone is reported empty, not fatal
        return []
    rows = payload.get("components") or []
    components: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        components.append({
            "__type__": "Component",
            "name": row.get("name"),
            "version": (row.get("version") or "").split("?")[0] or None,
            "ecosystem": row.get("type") or (row.get("properties") or [{}])[0].get("value"),
        })
    return components


def _artifact_cbom(manifest: dict[str, Any]) -> dict[str, Any] | None:
    key = manifest.get("cbom_storage_key")
    if not key:
        return None
    try:
        return json.loads(_store().get(key).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value or None


def _limit(arguments: dict[str, Any] | None = None, default: int = 50,
           ceiling: int = MAX_LIST) -> int:
    raw = (arguments or {}).get("limit", default)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(1, min(value, ceiling))


def _severity_filter(findings: Iterable[dict[str, Any]], severity: str | None) -> list[dict[str, Any]]:
    rows = [row for row in findings if isinstance(row, dict)]
    if not severity:
        return rows
    wanted = severity.strip().upper()
    if wanted in ("MODERATE", "MEDIUM"):
        wanted = "MEDIUM"
    return [row for row in rows if str(row.get("severity") or "").upper() == wanted]


def _manifest_card(manifest: dict[str, Any]) -> dict[str, Any]:
    summary = manifest.get("binary_summary") or {}
    return {
        "__type__": "BinaryArtifact",
        "artifactId": manifest.get("artifact_id"),
        "kind": manifest.get("kind"),
        "target": manifest.get("target"),
        "label": str(manifest.get("target") or "").rstrip("/").rsplit("/", 1)[-1] or None,
        "format": manifest.get("format"),
        "sha256": manifest.get("sha256"),
        "createdAt": manifest.get("created_at"),
        "createdBy": manifest.get("created_by"),
        "jobId": _text(manifest.get("job_id")),
        "rulesetDigest": _text(manifest.get("ruleset_digest")),
        "componentCount": manifest.get("component_count"),
        "binaryCount": manifest.get("binary_count"),
        "cryptoComponents": manifest.get("crypto_components"),
        "dependencyEdges": manifest.get("dependency_edges"),
        "vulnerabilityCount": manifest.get("vulnerability_count"),
        "compliant": manifest.get("compliant"),
        "minimumElements": manifest.get("minimum_elements"),
        "summary": summary,
        "findingsBySeverity": summary.get("findings_by_severity") or {},
        "algorithms": (summary.get("algorithms") or []),
        "posture": {
            "__type__": "BinaryPosture",
            "signaturePosture": summary.get("signature_posture") or {},
            "encryptedBinaries": summary.get("encrypted_binaries"),
            "keyMaterial": summary.get("key_material") or {},
            "constants": summary.get("constants") or {},
            "fingerprints": summary.get("fingerprints"),
            "packedBinaries": summary.get("packed_binaries"),
            "embeddedBinaries": summary.get("embedded_binaries"),
            "containersFollowed": summary.get("containers_followed"),
            "containersRefused": summary.get("containers_refused"),
            "extractionLimits": summary.get("extraction_limits") or {},
        },
        "_manifest": manifest,
    }


def _finding_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "__type__": "Finding",
        "code": row.get("code"),
        "severity": row.get("severity"),
        "title": row.get("title"),
        "detail": row.get("detail"),
        "path": row.get("path"),
        "rule": row.get("rule"),
        "tags": row.get("tags") or [],
        "severityFromRule": row.get("severity_from_rule"),
    }


# --------------------------------------------------------------------------- #
# resolvers
# --------------------------------------------------------------------------- #

def _binary_artifacts(arguments: dict[str, Any], context: ExecutionContext) -> list[dict[str, Any]]:
    kind = _text(arguments.get("kind")) or "binary"
    search = (_text(arguments.get("q")) or "").lower()
    limit = _limit(arguments)
    rows = [row for row in _manifests() if str(row.get("kind") or "").lower() == kind.lower()]
    if search:
        rows = [row for row in rows
                if search in str(row.get("target") or "").lower()
                or search in str(row.get("artifact_id") or "").lower()]
    rows.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)
    cards = [_manifest_card(row) for row in rows[:limit]]
    context.data["artifacts_seen"] = len(rows)
    context.data["artifacts_returned"] = len(cards)
    return cards


def _binary_artifact(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any] | None:
    artifact_id = _text(arguments.get("id"))
    if not artifact_id:
        raise ValueError("binaryArtifact needs an id")
    manifest = _manifest(artifact_id)
    if manifest is None:
        return None
    card = _manifest_card(manifest)
    card["components"] = _artifact_components(manifest)
    cbom = _artifact_cbom(manifest)
    card["cbom"] = {
        "__type__": "Cbom",
        "components": (cbom or {}).get("components") or [],
        "count": len(((cbom or {}).get("components") or [])),
        "present": cbom is not None,
    }
    return card


def _artifact_findings(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    manifest = arguments.get("_manifest") or _manifest(_text(arguments.get("artifactId")) or "")
    if manifest is None:
        raise ValueError("that artifact is not in this install's artifact store")
    summary = manifest.get("binary_summary") or {}
    excerpt = summary.get("findings_excerpt") or []
    total = int(summary.get("findings") or 0)
    severity = _text(arguments.get("severity"))
    limit = _limit(arguments, default=50)
    rows = _severity_filter(excerpt, severity)
    limit = min(limit, summary.get("findings_excerpt_limit") or MAX_LIST)
    return {
        "__type__": "FindingPage",
        "items": [_finding_row(row) for row in rows[:limit]],
        "returned": min(len(rows), limit),
        "total": total,
        "excerptLimit": summary.get("findings_excerpt_limit"),
        "truncated": total > len(excerpt) or len(rows) > limit,
        "note": (f"the manifest stores an excerpt of {summary.get('findings_excerpt_limit')} findings; "
                 f"this artifact recorded {total}"),
    }


def _artifact_crypto(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Crypto assets: the algorithm list from the manifest, the libraries from the CBOM.

    The manifest stores the algorithm names and a library *count* (it is
    manifest-sized on purpose); the library rows live in the CBOM next to it, so
    this reads them from there and says which of the two it has.
    """
    manifest = arguments.get("_manifest") or _manifest(_text(arguments.get("artifactId")) or "")
    if manifest is None:
        raise ValueError("that artifact is not in this install's artifact store")
    summary = manifest.get("binary_summary") or {}
    cbom = _artifact_cbom(manifest) or {}
    libraries: dict[str, dict[str, Any]] = {}
    for component in cbom.get("components") or []:
        if not isinstance(component, dict):
            continue
        properties = {row.get("name"): row.get("value")
                      for row in (component.get("properties") or []) if isinstance(row, dict)}
        library = properties.get("cryptoscan:library") or "unknown"
        row = libraries.setdefault(library, {"name": library, "version": None, "algorithms": []})
        if properties.get("cryptoscan:library-version"):
            row["version"] = properties["cryptoscan:library-version"]
        if component.get("name"):
            row["algorithms"].append(component["name"])
    return {
        "__type__": "Crypto",
        "algorithms": summary.get("algorithms") or [],
        "pqcMarkers": summary.get("pqc_markers") or [],
        "eccMarkers": summary.get("ecc_markers") or [],
        "libraries": [{"__type__": "CryptoLibrary", **row} for row in
                      sorted(libraries.values(), key=lambda item: item["name"])],
        "libraryCount": summary.get("crypto_libraries"),
        "cbomPresent": bool(cbom),
        "note": ("algorithms and markers come from the scan manifest; the library rows come "
                 "from the stored CBOM (an artifact without one has no library detail here)"),
    }


def _artifact_yara(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    manifest = arguments.get("_manifest") or _manifest(_text(arguments.get("artifactId")) or "")
    if manifest is None:
        raise ValueError("that artifact is not in this install's artifact store")
    block = (manifest.get("binary_summary") or {}).get("yara") or {}
    return {
        "__type__": "Yara",
        "matches": block.get("matches", 0),
        "filesMatched": block.get("files_matched", 0),
        "rules": block.get("rules", 0),
        "privateRules": block.get("private_rules", 0),
        "byRule": [{"__type__": "RuleCount", "rule": name, "count": count}
                   for name, count in (block.get("by_rule") or {}).items()],
        "bySeverity": [{"__type__": "SeverityCount", "severity": name, "count": count}
                       for name, count in (block.get("by_severity") or {}).items()],
        "digest": _text(block.get("digest")),
        "sources": block.get("sources") or [],
        "errors": block.get("errors") or [],
        "errorCount": block.get("error_count", 0),
        "truncatedScans": block.get("truncated_scans", 0),
        "ruleFilesSkipped": block.get("rule_files_skipped", 0),
        "note": block.get("note"),
    }


def _binary_job(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any] | None:
    job_id = _text(arguments.get("id"))
    if not job_id:
        raise ValueError("binaryJob needs an id")
    from api.job_view import job_snapshot  # one shape for REST, WebSocket and GraphQL

    return job_snapshot(_session(context), job_id)


def _binary_jobs(arguments: dict[str, Any], context: ExecutionContext) -> list[dict[str, Any]]:
    limit = _limit(arguments, default=20, ceiling=200)
    rows = _jobs(context, limit)
    kind = _text(arguments.get("jobType"))
    if kind:
        rows = [row for row in rows if str(getattr(row, "job_type", "") or "").upper() == kind.upper()]
    return [job_card(job) for job in rows]


def _jobs(context: ExecutionContext, limit: int) -> list[Any]:
    from db.repositories.job_repository import JobRepository

    session = _session(context)
    if session is None:
        raise ValueError("this query needs a database session")
    return list(JobRepository(session).list_recent(limit=min(limit, 200)))


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else _text(value)


def _binary_batch(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    batch_id = _text(arguments.get("batchId"))
    if not batch_id:
        raise ValueError("binaryBatch needs a batchId")
    from api.routers.devsecops import _BATCH_WINDOW as BATCH_WINDOW
    from db.repositories.job_repository import JobRepository

    session = _session(context)
    if session is None:
        raise ValueError("this query needs a database session")
    jobs = JobRepository(session).list_by_scan_option("batch_id", batch_id, limit=BATCH_WINDOW)
    files, by_status, binaries, findings, matches = [], {}, 0, 0, 0
    for job in jobs:
        card = job_card(job)
        progress = getattr(job, "progress", None) or {}
        binary = progress.get("binary") or {}
        status = card["status"] or ""
        by_status[status] = by_status.get(status, 0) + 1
        binaries += int(binary.get("binaries_scanned") or 0)
        findings += int(binary.get("findings") or 0)
        matches += int(binary.get("yara_matches") or 0)
        files.append(card)
    return {
        "__type__": "Batch",
        "batchId": batch_id,
        "jobs": len(files),
        "byStatus": [{"status": name, "count": count} for name, count in sorted(by_status.items())],
        "totals": {"__type__": "BatchTotals", "binariesScanned": binaries, "findings": findings,
                   "yaraMatches": matches},
        "files": files,
        "window": {"lookedAt": len(jobs), "limit": BATCH_WINDOW,
                   "truncated": len(jobs) >= BATCH_WINDOW},
    }


def _knowledge(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    from devsecops.knowledge import knowledge_state

    state = knowledge_state()
    packs = []
    for name, entry in sorted((state.get("installed") or {}).items()):
        packs.append({
            "__type__": "KnowledgePack",
            "name": name,
            "version": _text(entry.get("version")),
            "digest": entry.get("digest"),
            "description": _text(entry.get("description")),
            "signedBy": _text(entry.get("signed_by")),
            "installedAt": _text(entry.get("installed_at")),
            "rules": entry.get("rule_names") or [],
            "files": [row.get("name") for row in (entry.get("rules") or [])],
        })
    return {
        "__type__": "Knowledge",
        "builtinRules": (state.get("builtin") or {}).get("rules"),
        "builtinDigest": (state.get("builtin") or {}).get("digest"),
        "rulesetRules": (state.get("ruleset") or {}).get("rules"),
        "rulesetDigest": (state.get("ruleset") or {}).get("digest"),
        "rulesetErrors": (state.get("ruleset") or {}).get("error_count"),
        "rulesDir": state.get("rules_dir"),
        "packs": packs,
    }


def _runtime_findings(arguments: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    from db.repositories.runtime_finding_repository import RuntimeFindingRepository

    session = _session(context)
    if session is None:
        raise ValueError("this query needs a database session")
    limit = _limit(arguments, default=50)
    kind = _text(arguments.get("kind"))
    weak_only = bool(arguments.get("weakOnly") or False)
    rows = RuntimeFindingRepository(session).list_recent(limit=limit, kind=kind, weak_only=weak_only)
    summary = RuntimeFindingRepository(session).summary()
    return {
        "__type__": "RuntimeFindings",
        "items": [{
            "__type__": "RuntimeFinding",
            "hostname": getattr(row, "hostname", None),
            "process": getattr(row, "process_name", None),
            "algorithm": getattr(row, "algorithm", None),
            "status": getattr(row, "status", None),
            "keySize": getattr(row, "key_size", None),
            "tlsVersion": getattr(row, "tls_version", None),
            "weakTls": bool(getattr(row, "weak_tls", False)),
            "observations": getattr(row, "observation_count", None),
            "scannerId": getattr(row, "scanner_id", None),
            "source": (getattr(row, "extra", None) or {}).get("source"),
            "kind": getattr(row, "kind", None),
        } for row in rows],
        "returned": len(rows),
        "summary": summary,
    }


def _session(context: ExecutionContext) -> Any:
    return context.get("session")


# --------------------------------------------------------------------------- #
# the root
# --------------------------------------------------------------------------- #

SCHEMA_DOC = {
    "BinaryArtifact": {
        "search": "binaryArtifacts(kind, q, limit) / binaryArtifact(id)",
        "fields": ["artifactId", "kind", "target", "label", "format", "sha256", "createdAt",
                   "createdBy", "jobId", "rulesetDigest", "componentCount", "binaryCount",
                   "cryptoComponents", "dependencyEdges", "vulnerabilityCount", "compliant",
                   "minimumElements", "summary", "findingsBySeverity", "algorithms", "posture",
                   "components", "cbom", "findings", "crypto", "yara"],
        "args": {"findings": ["severity", "limit"], "cbom": [], "components": []},
    },
    "BinaryPosture": {"fields": ["signaturePosture", "encryptedBinaries", "keyMaterial",
                                 "constants", "fingerprints", "packedBinaries",
                                 "embeddedBinaries", "containersFollowed", "containersRefused",
                                 "extractionLimits"]},
    "Component": {"fields": ["name", "version", "ecosystem"]},
    "Finding": {"fields": ["code", "severity", "title", "detail", "path", "rule", "tags",
                           "severityFromRule"]},
    "FindingPage": {"fields": ["items", "returned", "total", "excerptLimit", "truncated", "note"]},
    "Cbom": {"fields": ["present", "count", "components"]},
    "Crypto": {"fields": ["algorithms", "pqcMarkers", "eccMarkers", "libraries", "libraryCount",
                          "cbomPresent", "note"]},
    "CryptoLibrary": {"fields": ["name", "version", "algorithms"]},
    "Yara": {"fields": ["matches", "filesMatched", "rules", "privateRules", "byRule", "bySeverity",
                        "digest", "sources", "errors", "errorCount", "truncatedScans",
                        "ruleFilesSkipped", "note"]},
    "Job": {"search": "binaryJob(id) / binaryJobs(limit, jobType)",
            "fields": ["jobId", "jobType", "status", "terminal", "target", "stage", "percent",
                       "stagesComplete", "totalStages", "stages", "createdAt", "startedAt",
                       "completedAt", "error", "binary", "artifactId", "reportUrl",
                       "downloadUrl", "batchId", "scanOptions"]},
    "Batch": {"search": "binaryBatch(batchId)",
              "fields": ["batchId", "jobs", "byStatus", "totals", "files", "window"]},
    "Knowledge": {"search": "knowledge", "fields": ["builtinRules", "builtinDigest", "rulesetRules",
                                                    "rulesetDigest", "rulesetErrors", "rulesDir",
                                                    "packs"]},
    "KnowledgePack": {"fields": ["name", "version", "digest", "description", "signedBy",
                                 "installedAt", "rules", "files"]},
    "RuntimeFinding": {"search": "runtimeFindings(limit, kind, weakOnly)",
                       "fields": ["hostname", "process", "algorithm", "status", "keySize",
                                  "tlsVersion", "weakTls", "observations", "scannerId", "source",
                                  "kind"]},
}


def _schema_field(_arguments: dict[str, Any], _context: ExecutionContext) -> dict[str, Any]:
    return {
        "__type__": "Schema",
        "types": [{"name": name, **value} for name, value in sorted(SCHEMA_DOC.items())],
        "note": ("introspection-lite: the types and fields this surface resolves. Mutations and "
                 "subscriptions are refused — every write is a REST endpoint with its own roles "
                 "and audit trail, so it cannot be reached from here"),
    }


ROOT_SCHEMA: dict[str, Resolver] = {
    "__schema": _schema_field,
    "binaryArtifacts": _binary_artifacts,
    "binaryArtifact": _binary_artifact,
    "binaryJobs": _binary_jobs,
    "binaryJob": _binary_job,
    "binaryBatch": _binary_batch,
    "knowledge": _knowledge,
    "runtimeFindings": _runtime_findings,
}


def _attach_children(artifact: dict[str, Any]) -> dict[str, Any]:
    """Bind an artifact card's child fields (`findings`, `crypto`, `yara`) to its manifest.

    The manifest is what those fields answer from, so the binding happens here, on
    the card that carries it, rather than by re-reading the artifact store per field.
    """
    manifest = artifact.get("_manifest") or {}

    def findings(arguments: dict[str, Any], context: ExecutionContext) -> Any:
        return _artifact_findings({**arguments, "_manifest": manifest}, context)

    def crypto(arguments: dict[str, Any], context: ExecutionContext) -> Any:
        return _artifact_crypto({**arguments, "_manifest": manifest}, context)

    def yara(arguments: dict[str, Any], context: ExecutionContext) -> Any:
        return _artifact_yara({**arguments, "_manifest": manifest}, context)

    artifact["findings"] = findings
    artifact["crypto"] = crypto
    artifact["yara"] = yara
    return artifact


def _with_children(resolver):
    """A root resolver whose artifact-shaped results carry their child fields."""
    def run(arguments: dict[str, Any], context: ExecutionContext) -> Any:
        value = resolver(arguments, context)
        if isinstance(value, list):
            return [_attach_children(item) if isinstance(item, dict) else item for item in value]
        return _attach_children(value) if isinstance(value, dict) else value

    return run


def query(query_text: str, *, variables: dict[str, Any] | None = None,
          session: Any = None, limit: int = MAX_LIST) -> dict[str, Any]:
    """Parse and execute a query, returning the GraphQL-shaped response body.

    A document that does not parse comes back in the same envelope as a resolver
    error: the request reached the surface, so the answer is a GraphQL answer, and
    the client does not have to learn two error dialects.
    """
    from api.graphql_lang import GraphQLSyntaxError

    envelope_limits = {"depth": 12, "fields": 500, "list": MAX_LIST}
    try:
        document = parse(query_text, variables=variables)
    except GraphQLSyntaxError as exc:
        return {"data": None, "errors": [{"message": str(exc), "path": [],
                                          "extensions": {"code": "SYNTAX_ERROR"}}],
                "extensions": {"limits": envelope_limits, "read_only": True}}
    context = ExecutionContext(data={"session": session}, limit=limit)
    root = dict(ROOT_SCHEMA)
    for name in ("binaryArtifacts", "binaryArtifact"):
        root[name] = _with_children(ROOT_SCHEMA[name])
    result = execute(document, root, context=context)
    result["extensions"].update({
        "artifacts_seen": context.data.get("artifacts_seen"),
        "artifacts_returned": context.data.get("artifacts_returned"),
        "schema": "cryptoscan-graphql-lite",
    })
    return result


__all__ = ["ROOT_SCHEMA", "SCHEMA_DOC", "READER_ROLES", "query", "Argument"]
