"""Runtime crypto observations → graph assets and edges (the "runtime observed" link).

The runtime plane already turned every traced ``EVP_*`` call into an evidence record,
and the graph already expanded those into crypto *artefacts*. What it never did was
**connect** them: an application that was observed performing AES-256-GCM through
OpenSSL had an artefact saying so and no edge saying so, so the twin's chain stopped
at the application and a reader could not follow it to the library or the algorithm.

This module is that producer. It reads the observation rows the runtime plane
collected and emits:

    Application —uses_crypto_library→ Library
    Application —uses_algorithm→ Algorithm
    Library     —uses_algorithm→ Algorithm

every edge on the ``RUNTIME_OBSERVATION`` basis, carrying the evidence records of
the calls that established it and ``usage_state: OBSERVED``.

Four rules, because this is the link that makes a twin credible:

* **No provider, no library edge.** A trace of ``EVP_EncryptInit`` proves the
  process encrypted through libcrypto; it does not prove *which* build. When the
  observation does not name a provider, the library edge is not emitted and the
  gap is counted (``events_without_provider``) instead of being filled with
  "OpenSSL" because that is usually true.
* **No algorithm, no algorithm edge.** Same rule, counted as
  ``events_without_algorithm``.
* **Nothing sensitive.** Only the algorithm, mode, key size and operation names the
  tracer recorded are read. The tracer never records key bytes, IVs or plaintext,
  and nothing here reconstructs them.
* **A library→algorithm edge says "this library performed this operation in this
  process"**, not "this library supports this algorithm" — that is a capability
  claim and belongs to whichever collector read the library's version and cipher
  list.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

MODEL = "cryptoscan.runtime-crypto-edges/1"

#: Values a tracer uses when it saw a call but could not name the provider.
NO_PROVIDER = frozenset({"", "UNKNOWN", "NONE", "N/A", "?"})

#: How many evidence records one edge may cite. An application with 40 000 calls has
#: 40 000 pieces of evidence for one fact; the edge keeps the first N and says how
#: many it stands for, rather than shipping a list nobody can read.
MAX_EVIDENCE_PER_EDGE = 50


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or text.upper() in NO_PROVIDER:
        return None
    return text


def build(observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Turn observation rows into assets/relationships for a discovery payload.

    Each row needs ``app_ref`` (the payload ref of the application asset),
    ``evidence_ref`` (the payload ref of the evidence record for that call or call
    group) and may carry ``provider``, ``algorithm``, ``mode``, ``key_size`` and
    ``operation``. Rows may repeat an evidence ref; it is cited once.
    """
    assets: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    without_provider = 0
    without_algorithm = 0
    total = 0

    def edge(subject: str, predicate: str, obj: str, *, algorithm: str | None = None,
             provider: str | None = None) -> dict[str, Any]:
        key = (subject, predicate, obj)
        existing = edges.get(key)
        if existing is None:
            existing = {
                "subject": subject,
                "predicate": predicate,
                "object": obj,
                "basis": "RUNTIME_OBSERVATION",
                "evidence_refs": [],
                "attributes": {
                    "usage_state": "OBSERVED",
                    "algorithms": [],
                    "providers": [],
                    "operations": [],
                    "key_sizes": [],
                    "observation_count": 0,
                    "evidence_incomplete": False,
                },
            }
            edges[key] = existing
        attributes = existing["attributes"]
        attributes["observation_count"] += 1
        if algorithm and algorithm not in attributes["algorithms"]:
            attributes["algorithms"].append(algorithm)
        if provider and provider not in attributes["providers"]:
            attributes["providers"].append(provider)
        return existing

    for row in observations:
        total += 1
        app_ref = str(row.get("app_ref") or "")
        evidence_ref = str(row.get("evidence_ref") or "")
        if not app_ref or not evidence_ref:
            continue
        provider = _clean(row.get("provider"))
        algorithm = _clean(row.get("algorithm"))
        operation = _clean(row.get("operation"))
        if algorithm is None:
            without_algorithm += 1
        if provider is None:
            without_provider += 1

        if provider is not None:
            library_ref = f"crypto-library:{provider.lower()}"
            assets.setdefault(library_ref, {
                "ref": library_ref,
                "type": "LIBRARY",
                "name": provider,
                "identity": {"name": provider.lower()},
                "source": "runtime_agent",
                "attributes": {
                    "discovered_by": "runtime observation of a traced crypto call",
                    "version": "UNKNOWN",
                },
            })
            used = edge(app_ref, "uses_crypto_library", library_ref, provider=provider,
                        algorithm=algorithm)
            if operation and operation not in used["attributes"]["operations"]:
                used["attributes"]["operations"].append(operation)
            if evidence_ref not in used["evidence_refs"]:
                used["evidence_refs"].append(evidence_ref)

        if algorithm is not None:
            algorithm_ref = f"crypto-algorithm:{algorithm.lower()}"
            assets.setdefault(algorithm_ref, {
                "ref": algorithm_ref,
                "type": "CRYPTO_ASSET",
                "name": algorithm,
                "identity": {"name": algorithm.lower()},
                "source": "runtime_agent",
                "attributes": {"discovered_by": "runtime observation of a traced crypto call"},
            })
            uses = edge(app_ref, "uses_algorithm", algorithm_ref,
                        algorithm=algorithm, provider=provider)
            if operation and operation not in uses["attributes"]["operations"]:
                uses["attributes"]["operations"].append(operation)
            if row.get("key_size") not in (None, ""):
                size = str(row["key_size"])
                if size not in uses["attributes"]["key_sizes"]:
                    uses["attributes"]["key_sizes"].append(size)
            if evidence_ref not in uses["evidence_refs"]:
                uses["evidence_refs"].append(evidence_ref)

            if provider is not None:
                performed = edge(f"crypto-library:{provider.lower()}", "uses_algorithm",
                                 algorithm_ref, algorithm=algorithm, provider=provider)
                if operation and operation not in performed["attributes"]["operations"]:
                    performed["attributes"]["operations"].append(operation)
                if evidence_ref not in performed["evidence_refs"]:
                    performed["evidence_refs"].append(evidence_ref)

    relationships = []
    for entry in edges.values():
        attributes = entry["attributes"]
        cited = entry["evidence_refs"]
        if len(cited) > MAX_EVIDENCE_PER_EDGE:
            attributes["evidence_incomplete"] = True
            attributes["evidence_total"] = len(cited)
            cited = cited[:MAX_EVIDENCE_PER_EDGE]
        else:
            attributes["evidence_total"] = len(cited)
        relationships.append({**entry, "evidence_refs": cited})

    return {
        "model": MODEL,
        "assets": sorted(assets.values(), key=lambda asset: str(asset["ref"])),
        "relationships": sorted(
            relationships,
            key=lambda item: (item["subject"], item["predicate"], item["object"]),
        ),
        "summary": {
            "observations": total,
            "edges": len(relationships),
            "events_without_provider": without_provider,
            "events_without_algorithm": without_algorithm,
            "note": (
                "a call the tracer saw but could not attribute to a provider produces no "
                "library edge: 'libcrypto did it' is not 'OpenSSL 3.0.13 did it'"
            ),
        },
    }
