"""Process-level runtime tracing: application → process → provider → operation.

The review's item 7 calls this the biggest technical gap, and the chain it asks for
is explicit::

    payments-api
      PID 9182
      OpenSSL 3.0.13
      operation: EVP_EncryptInit_ex
      algorithm: AES-256-GCM
      parameters: key_size=256, mode=GCM
      observed_at: 2026-11-02 10:42:11
      evidence: RUNTIME-92821

That is a *runtime-confirmed* crypto asset, and it is a different fact from "the
SBOM lists openssl" or "openssl supports AES-256-GCM". This module keeps the chain:

* a trace missing any link (application, pid, operation, algorithm, evidence id,
  timestamp) is refused — a partial chain is a claim, not an observation;
* the **provider version** is kept as observed and marked ``UNKNOWN`` when the
  collector did not report one, because "OpenSSL" without a version cannot be
  compared with an SBOM;
* ``correlate`` compares the provider the process actually loaded with the version
  the SBOM declares, and a mismatch stays a mismatch (the review's 3.0.11 vs
  3.0.13 example);
* ``to_components`` produces the runtime-confirmed asset, with the whole chain in
  ``cryptoscan:`` properties and no invented quantum verdict;
* ``graph`` projects the chain as nodes and evidence-edged relationships for the
  digital twin.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from cbom import usage_graph

SCHEMA = "cryptoscan.cbom-process-tracing/1"

#: The chain, in order. Every link is data, not decoration: the review's point is
#: that "AES-256-GCM, somewhere, at some point" is not an observation.
CHAIN: tuple[str, ...] = ("application", "process", "provider", "operation", "algorithm")

#: Fields without which a row is a claim rather than a trace.
REQUIRED: tuple[str, ...] = ("application", "pid", "operation", "algorithm", "evidence_id",
                             "observed_at")

CORRELATION_STATES: tuple[str, ...] = (
    "MATCH", "VERSION_MISMATCH", "RUNTIME_VERSION_UNKNOWN", "RUNTIME_ONLY", "SBOM_ONLY",
)

PARAMETER_FIELDS: tuple[str, ...] = ("key_size", "mode", "curve", "padding")


def _observed_at(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


def _provider_label(name: str | None, version: str | None) -> str:
    provider = str(name or "").strip()
    if not provider:
        return "provider:UNKNOWN"
    label = provider if not version or version == "UNKNOWN" else f"{provider}@{version}"
    return f"provider:{label}"


def trace(operations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Operation rows -> full-chain runtime traces, or refusals.

    ``pid`` is not required to be numeric — some platforms report a container id or
    a service name — but it is required, because "which process" is the difference
    between a trace and a rumour.
    """
    traces: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in operations:
        if not isinstance(row, Mapping):
            refused.append({"operation": row, "reason": "an operation must be an object"})
            continue
        application = str(row.get("application") or row.get("system") or "").strip()
        pid = str(row.get("pid") or row.get("process_id") or "").strip()
        operation = str(row.get("operation") or "").strip()
        algorithm = str(row.get("algorithm") or "").strip()
        evidence_id = str(row.get("evidence_id") or "").strip()
        observed_raw = row.get("observed_at") or row.get("timestamp")
        observed_at = _observed_at(observed_raw)
        missing = [name for name, value in (
            ("application", application), ("pid", pid), ("operation", operation),
            ("algorithm", algorithm), ("evidence_id", evidence_id)) if not value]
        if observed_raw and not observed_at:
            missing.append("observed_at (unparseable)")
        elif not observed_raw:
            missing.append("observed_at")
        if missing:
            refused.append({
                "application": application or None, "pid": pid or None,
                "operation": operation or None, "algorithm": algorithm or None,
                "reason": "a runtime trace is missing " + ", ".join(missing),
            })
            continue
        provider = str(row.get("provider") or row.get("library") or "").strip() or None
        provider_version = str(row.get("provider_version") or row.get("library_version")
                               or "").strip() or None
        parameters = {key: row[key] for key in PARAMETER_FIELDS if row.get(key)}
        trace_row = {
            "application": application,
            "pid": pid,
            "provider": provider,
            "provider_version": provider_version,
            "provider_known": bool(provider),
            "provider_version_known": bool(provider and provider_version),
            "operation": operation,
            "algorithm": algorithm,
            "parameters": parameters,
            "purpose": str(row.get("purpose") or "").strip().upper() or None,
            "host": row.get("host"),
            "observed_at": observed_at,
            "evidence_id": evidence_id,
            "class": "RUNTIME_OBSERVED",
            "chain": {
                "application": f"application:{application}",
                "process": f"process:{application}/{pid}",
                "provider": _provider_label(provider, provider_version),
                "operation": f"operation:{operation}",
                "algorithm": f"algorithm:{algorithm}",
            },
        }
        traces.append(trace_row)

    providers = sorted({trace["chain"]["provider"] for trace in traces})
    processes = sorted({trace["chain"]["process"] for trace in traces})
    return {
        "schema": SCHEMA,
        "chain": list(CHAIN),
        "traces": traces,
        "refused": refused,
        "providers": providers,
        "processes": processes,
        "applications": sorted({trace["application"] for trace in traces}),
        "statement": (
            f"{len(traces)} runtime trace(s) across {len(processes)} process(es), "
            f"{len(providers)} provider(s)"
            + (f"; {len(refused)} row(s) refused for an incomplete chain" if refused else "")),
    }


def provider_observations(traces: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """What each crypto provider was *seen doing* — not what it could do."""
    grouped: dict[str, dict[str, Any]] = {}
    for item in traces:
        label = str(item.get("chain", {}).get("provider")
                    or _provider_label(item.get("provider"), item.get("provider_version")))
        row = grouped.setdefault(label, {
            "provider": label,
            "name": item.get("provider"),
            "version": item.get("provider_version"),
            "version_known": bool(item.get("provider_version_known")),
            "operations": Counter(),
            "algorithms": set(),
            "applications": set(),
            "processes": set(),
            "evidence_ids": set(),
            "last_observed_at": None,
        })
        row["operations"][str(item.get("operation"))] += 1
        row["algorithms"].add(str(item.get("algorithm")))
        row["applications"].add(str(item.get("application")))
        row["processes"].add(str(item.get("chain", {}).get("process")))
        row["evidence_ids"].add(str(item.get("evidence_id")))
        at = str(item.get("observed_at") or "")
        if at and (row["last_observed_at"] is None or at > row["last_observed_at"]):
            row["last_observed_at"] = at
    results = []
    for label in sorted(grouped):
        row = grouped[label]
        results.append({
            **{key: row[key] for key in ("provider", "name", "version", "version_known")},
            "operations": dict(sorted(row["operations"].items())),
            "algorithms": sorted(row["algorithms"]),
            "applications": sorted(row["applications"]),
            "processes": sorted(row["processes"]),
            "evidence_ids": sorted(row["evidence_ids"]),
            "last_observed_at": row["last_observed_at"],
            "statement": (
                f"{row['name'] or 'an unidentified provider'}"
                + (f" {row['version']}" if row["version_known"] else " (version not reported)")
                + f" was observed performing {', '.join(sorted(row['algorithms']))} in "
                f"{len(row['processes'])} process(es)"
                + ("" if row["version_known"] else
                   "; without a version it cannot be compared with an SBOM")),
        })
    return {
        "schema": SCHEMA,
        "providers": results,
        "unknown_version": [row["provider"] for row in results if not row["version_known"]],
        "statement": (f"{len(results)} crypto provider(s) observed at runtime"
                      + (f"; {sum(1 for row in results if not row['version_known'])} without a "
                         "version" if any(not row["version_known"] for row in results) else "")),
    }


def correlate(providers: Mapping[str, Any] | Iterable[Mapping[str, Any]],
              declared: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Runtime provider versions against the SBOM's declarations.

    The review's example — SBOM and container say 3.0.13, runtime says 3.0.11 — is a
    ``VERSION_MISMATCH``, not a resolved value. A provider the SBOM never mentions
    is ``RUNTIME_ONLY``; a library the SBOM lists that no process loaded is
    ``SBOM_ONLY`` (it may be on disk and unused, which is itself worth knowing).
    """
    rows = (list(providers.get("providers") or []) if isinstance(providers, Mapping)
            else list(providers))
    declarations: dict[str, list[dict[str, Any]]] = {}
    for item in declared:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or item.get("library") or "").strip().lower()
        if not name:
            continue
        declarations.setdefault(name, []).append({
            "version": str(item.get("version") or "").strip() or None,
            "evidence_id": str(item.get("evidence_id") or "").strip() or None,
            "source": item.get("source"),
        })

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        name = str(row.get("name") or "").strip().lower()
        label = str(row.get("provider") or name)
        version = str(row.get("version") or "").strip() or None
        known = bool(row.get("version_known", version))
        claimed = declarations.get(name, [])
        declared_versions = sorted({item["version"] for item in claimed if item["version"]})
        if not claimed:
            state = "RUNTIME_ONLY"
            detail = "the runtime loaded a provider the SBOM does not declare"
        elif not known:
            state = "RUNTIME_VERSION_UNKNOWN"
            detail = ("the runtime provider version was not reported, so agreement with the "
                      "SBOM cannot be established")
        elif declared_versions == [version]:
            state = "MATCH"
            detail = "the loaded provider matches the declared version"
        else:
            state = "VERSION_MISMATCH"
            detail = ("the process loaded a different provider version than the document "
                      "declares; neither value is discarded")
        seen.add(name)
        results.append({
            "provider": label,
            "name": row.get("name") or name or None,
            "runtime_version": version,
            "declared_versions": declared_versions,
            "state": state,
            "detail": detail,
            "evidence_ids": sorted({*(row.get("evidence_ids") or []),
                                    *(item["evidence_id"] for item in claimed
                                      if item["evidence_id"])}),
        })
    for name in sorted(set(declarations) - seen):
        versions = sorted({item["version"] for item in declarations[name] if item["version"]})
        results.append({
            "provider": f"provider:{name}",
            "name": name,
            "runtime_version": None,
            "declared_versions": versions,
            "state": "SBOM_ONLY",
            "detail": ("the document declares this library and no process was observed "
                       "loading it; presence on disk is not use"),
            "evidence_ids": sorted({item["evidence_id"] for item in declarations[name]
                                    if item["evidence_id"]}),
        })
    counts = Counter(row["state"] for row in results)
    return {
        "schema": SCHEMA,
        "correlations": results,
        "counts": {state: counts[state] for state in CORRELATION_STATES if counts[state]},
        "statement": (
            f"{len(results)} provider correlation(s): "
            + (", ".join(f"{state}={counts[state]}" for state in CORRELATION_STATES
                         if counts[state]) or "none")
            + ("; a version mismatch is reported, not resolved" if counts["VERSION_MISMATCH"]
               else "")),
    }


def to_components(traces: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Runtime traces -> CycloneDX cryptographic assets that are runtime-confirmed.

    One component per (application, process, provider, operation, algorithm,
    parameters): repeating an operation a thousand times is one asset with a count,
    not a thousand assets. Every platform claim lives in ``cryptoscan:`` properties,
    and nothing here writes a quantum verdict — that belongs to the PQC handoff.
    """
    grouped: dict[tuple, dict[str, Any]] = {}
    for item in traces:
        key = (item.get("application"), item.get("pid"), item.get("provider"),
               item.get("provider_version"), item.get("operation"), item.get("algorithm"),
               tuple(sorted((item.get("parameters") or {}).items())))
        row = grouped.setdefault(key, {
            "occurrences": 0,
            "evidence_ids": set(),
            "first": item.get("observed_at"),
            "last": item.get("observed_at"),
            "item": item,
        })
        row["occurrences"] += 1
        row["evidence_ids"].add(str(item.get("evidence_id")))
        at = str(item.get("observed_at") or "")
        if at and (row["first"] is None or at < str(row["first"])):
            row["first"] = at
        if at and (row["last"] is None or at > str(row["last"])):
            row["last"] = at

    components: list[dict[str, Any]] = []
    for key in sorted(grouped, key=lambda value: tuple(str(part) for part in value)):
        row = grouped[key]
        item = row["item"]
        parameters = item.get("parameters") or {}
        slug = "/".join(str(part) for part in (
            item.get("application"), item.get("pid"), item.get("operation"),
            item.get("algorithm"), item.get("provider") or "unknown-provider",
            item.get("provider_version") or "unknown-version"))
        properties = [
            {"name": "cryptoscan:runtime_confirmed", "value": "true"},
            {"name": "cryptoscan:application", "value": str(item.get("application"))},
            {"name": "cryptoscan:process", "value": str(item.get("pid"))},
            {"name": "cryptoscan:operation", "value": str(item.get("operation"))},
            {"name": "cryptoscan:observed_at", "value": str(row["last"])},
            {"name": "cryptoscan:occurrences", "value": str(row["occurrences"])},
        ]
        if item.get("provider"):
            properties.append({"name": "cryptoscan:provider", "value": str(item["provider"])})
        if item.get("provider_version"):
            properties.append({"name": "cryptoscan:provider_version",
                               "value": str(item["provider_version"])})
        else:
            properties.append({"name": "cryptoscan:provider_version_known", "value": "false"})
        properties += [{"name": "cryptoscan:evidence_id", "value": evidence_id}
                       for evidence_id in sorted(row["evidence_ids"])]
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"runtime/{slug}",
            "name": str(item.get("algorithm")),
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "parameterSetIdentifier": (str(parameters["key_size"])
                                               if parameters.get("key_size") else None),
                    "mode": parameters.get("mode"),
                    "padding": parameters.get("padding"),
                },
            },
            "properties": properties,
        })
    for component in components:
        algorithm_properties = {key: value for key, value
                                in component["cryptoProperties"]["algorithmProperties"].items()
                                if value is not None}
        if algorithm_properties:
            component["cryptoProperties"]["algorithmProperties"] = algorithm_properties
        else:
            # A collector that reported no parameters has no parameter set to claim;
            # an empty object would read as "parameters are known to be empty".
            component["cryptoProperties"].pop("algorithmProperties")
    return {
        "schema": SCHEMA,
        "components": components,
        "statement": (f"{len(components)} runtime-confirmed crypto asset(s) from "
                      f"{sum(len(row['evidence_ids']) for row in grouped.values())} evidence "
                      "reference(s); every one carries the process and provider chain"),
    }


def graph(traces: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The chain as twin relationships, each edge carrying its evidence.

    application → process → provider → operation → algorithm, plus application →
    algorithm directly, because a query like "which applications encrypt with
    AES-256-GCM" should not have to walk four edges.
    """
    edges: list[dict[str, Any]] = []
    nodes: dict[str, str] = {}

    def add(source: str, kind: str, target: str, item: Mapping[str, Any]) -> None:
        nodes.setdefault(source, source.split(":", 1)[0])
        nodes.setdefault(target, target.split(":", 1)[0])
        edges.append(usage_graph.evidence_edge(
            source, kind, target, evidence=[str(item.get("evidence_id"))],
            classes=["RUNTIME_OBSERVED"], observed_at=item.get("observed_at"),
            operation=item.get("operation")))

    for item in traces:
        chain = item.get("chain") or {}
        add(chain.get("application", ""), "RUNS_PROCESS", chain.get("process", ""), item)
        add(chain.get("process", ""), "LOADS_PROVIDER", chain.get("provider", ""), item)
        add(chain.get("provider", ""), "PERFORMS_OPERATION", chain.get("operation", ""), item)
        add(chain.get("operation", ""), "RESOLVES_TO", chain.get("algorithm", ""), item)
        add(chain.get("application", ""), "USES_CRYPTO", chain.get("algorithm", ""), item)

    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in edges:
        key = (edge["from"], edge["kind"], edge["to"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = edge
            continue
        existing["evidence_ids"] = sorted({*existing["evidence_ids"], *edge["evidence_ids"]})
        existing["evidence_classes"] = sorted({*existing["evidence_classes"],
                                               *edge["evidence_classes"]})
        if str(edge.get("observed_at") or "") > str(existing.get("observed_at") or ""):
            existing["observed_at"] = edge["observed_at"]
    final = [merged[key] for key in sorted(merged)]
    return {
        "schema": SCHEMA,
        "nodes": [{"id": node, "kind": kind.upper()} for node, kind in sorted(nodes.items())],
        "edges": final,
        "statement": (f"{len(final)} runtime relationship(s) across {len(nodes)} node(s); "
                      "every edge is RUNTIME_OBSERVED and carries its evidence id"),
    }


def summary(traces_body: Mapping[str, Any],
            providers_body: Mapping[str, Any] | None = None,
            correlation_body: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One answer for an operator: what ran, where, with which provider."""
    traces = list(traces_body.get("traces") or [])
    counts = Counter(str(item.get("algorithm")) for item in traces)
    return {
        "schema": SCHEMA,
        "traces": len(traces),
        "processes": len(traces_body.get("processes") or []),
        "applications": len(traces_body.get("applications") or []),
        "providers": len(traces_body.get("providers") or []),
        "algorithms": dict(sorted(counts.items())),
        "refused": len(traces_body.get("refused") or []),
        "correlation": (correlation_body or {}).get("counts"),
        "statement": (
            f"{len(traces)} runtime trace(s) across {len(traces_body.get('applications') or [])} "
            f"application(s) and {len(traces_body.get('providers') or [])} provider(s)"
            + (f"; {len(traces_body.get('refused') or [])} row(s) refused"
               if traces_body.get("refused") else "")),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
