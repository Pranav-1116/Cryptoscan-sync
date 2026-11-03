"""IDS/IPS event correlation: *what cryptographic assets and critical systems are involved?*

An alert is a tuple of addresses. The estate question is a dependency path, and this module
walks it one hop at a time, with the record that states each hop:

    source IP → host → process → API → crypto library (OpenSSL) → HSM

Each hop is resolved from an inventory that already exists elsewhere in the platform (asset
inventory, process tracing, API inventory, runtime library findings, key inventory). Nothing
is matched by name similarity, and a hop nobody has collected is *named* as unresolved with
the reason — the same discipline the NBOM applies to ``10.10.10.20:443``.

The output is deliberately two things at once: a narrative path a reviewer can read, and a
list of evidence ids an auditor can check.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .base import CONFIGURED, OBSERVED, RUNTIME_OBSERVED, _norm
from cbom import techbom

NETWORK_OBSERVED = techbom.NETWORK_OBSERVED

QUESTION = ("What cryptographic assets and critical systems are involved in this network "
            "security event?")

#: the hops, in order, with the code that says why one did not resolve
HOPS: tuple[tuple[str, str, str], ...] = (
    ("host", "NO_HOST_FOR_ADDRESS",
     "no inventory declares this address, so the event lands on an unknown host"),
    ("process", "NO_PROCESS_FOR_HOST",
     "the host is known and no process observation ties it to an application"),
    ("api", "NO_API_FOR_PROCESS",
     "the process is known and no API or route is recorded against it"),
    ("library", "NO_LIBRARY_FOR_API",
     "the API is known and no runtime observation records the crypto library it loaded"),
    ("hsm", "NO_HSM_FOR_LIBRARY",
     "the crypto library is known and no key inventory ties it to an HSM or KMS"),
)


def _index(rows: Iterable[Mapping[str, Any]] | None, key: str) -> dict[str, list[dict]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for row in rows or ():
        if not isinstance(row, Mapping):
            continue
        value = _norm(row.get(key))
        if not value:
            continue
        index.setdefault(value, []).append(dict(row))
    return index


def correlate_event(event: Mapping[str, Any], *,
                    hosts: Iterable[Mapping[str, Any]] | None = None,
                    processes: Iterable[Mapping[str, Any]] | None = None,
                    apis: Iterable[Mapping[str, Any]] | None = None,
                    libraries: Iterable[Mapping[str, Any]] | None = None,
                    hsms: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Resolve one event to the crypto it touches.

    ``hosts``: ``{"ip", "host", "evidence_id", "basis"?}``;
    ``processes``: ``{"host", "process", "evidence_id", "basis"?}``;
    ``apis``: ``{"process", "api", "evidence_id"}``;
    ``libraries``: ``{"api", "library", "version", "evidence_id"}``;
    ``hsms``: ``{"library", "hsm" | "kms", "evidence_id", "key_label"?}``.

    A hop with two candidate records is reported as ``AMBIGUOUS`` rather than resolved to the
    first row: two hosts behind one address is a fact about NAT, not a tie to break by order.
    """
    host_by_ip = _index(hosts, "ip")
    process_by_host = _index(processes, "host")
    api_by_process = _index(apis, "process")
    library_by_api = _index(libraries, "api")
    hsm_by_library = _index(hsms, "library")

    src = _norm(event.get("src") or event.get("source"))
    dst = _norm(event.get("dst") or event.get("destination"))

    path: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    crypto: list[dict[str, Any]] = []
    systems: list[dict[str, Any]] = []

    def hop(name: str, subject: str, candidates: list[dict[str, Any]],
            value_key: str, fact: str) -> Any:
        code = next(code for hop_name, code, _ in HOPS if hop_name == name)
        reason = next(reason for hop_name, _, reason in HOPS if hop_name == name)
        if not subject:
            unresolved.append({"hop": name, "code": "NO_VALUE",
                               "subject": None,
                               "reason": f"the {name.replace('_', ' ')} is missing from the "
                                         "event, so the path stops here"})
            return None
        if not candidates:
            unresolved.append({"hop": name, "code": code, "subject": subject,
                               "reason": f"{subject}: {reason}"})
            return None
        if len({_norm(row.get(value_key)) for row in candidates}) > 1:
            unresolved.append({
                "hop": name, "code": "AMBIGUOUS", "subject": subject,
                "candidates": sorted({_norm(row.get(value_key)) for row in candidates}),
                "reason": f"{subject} has {len(candidates)} candidate {name}s; the path is "
                          "not decided by row order",
            })
            return None
        row = candidates[0]
        resolved = _norm(row.get(value_key))
        path.append({
            "hop": name,
            "from": subject,
            "to": resolved,
            "evidence_ids": [value for value in
                             [_norm(row.get("evidence_id")),
                              *[_norm(item) for item in row.get("evidence_ids") or []]]
                             if value],
            "basis": _norm(row.get("basis")) or "agent-inventory",
            "fact": fact,
        })
        return resolved

    host = hop("host", src, host_by_ip.get(src, []), "host", CONFIGURED)
    process = hop("process", host or "", process_by_host.get(host, []), "process",
                  RUNTIME_OBSERVED) if host else None
    api = hop("api", process or "", api_by_process.get(process, []), "api", CONFIGURED) \
        if process else None
    library = hop("library", api or "", library_by_api.get(api, []), "library",
                  CONFIGURED) if api else None
    # a library a process loaded is a runtime observation of the process, not of the config
    if path and path[-1]["hop"] == "library":
        path[-1]["fact"] = RUNTIME_OBSERVED
    hsm = hop("hsm", library or "", hsm_by_library.get(library, []), "hsm",
              CONFIGURED) if library else None

    if api:
        systems.append({"kind": "API", "name": api,
                        "evidence_ids": [_norm(row.get("evidence_id"))
                                         for row in api_by_process.get(process, [])
                                         if _norm(row.get("evidence_id"))]})
    if host:
        systems.append({"kind": "HOST", "name": host,
                        "evidence_ids": [_norm(row.get("evidence_id"))
                                         for row in host_by_ip.get(src, [])
                                         if _norm(row.get("evidence_id"))]})
    for row in library_by_api.get(api or "", []):
        strong = [value for value in
                  [_norm(row.get("evidence_id")),
                   *[_norm(item) for item in row.get("evidence_ids") or []]] if value]
        crypto.append({"kind": "CRYPTO_LIBRARY", "name": _norm(row.get("library")),
                       "version": _norm(row.get("version")) or None,
                       "evidence_ids": strong, "fact": RUNTIME_OBSERVED})
    for row in hsm_by_library.get(library or "", []):
        strong = [value for value in
                  [_norm(row.get("evidence_id")),
                   *[_norm(item) for item in row.get("evidence_ids") or []]] if value]
        crypto.append({"kind": "HSM", "name": _norm(row.get("hsm")),
                       "key_label": _norm(row.get("key_label")) or None,
                       "evidence_ids": strong, "fact": CONFIGURED})

    return {
        "question": QUESTION,
        "event": {
            "evidence_id": _norm(event.get("evidence_id")) or None,
            "kind": _norm(event.get("kind")) or None,
            "signature": _norm(event.get("signature")) or None,
            "src": src or None,
            "dst": dst or None,
            "protocol": _norm(event.get("protocol")) or None,
            "port": event.get("port"),
            "tls_version": event.get("tls_version"),
            "cipher_suite": event.get("cipher_suite"),
            "sni": event.get("sni"),
            "fact": OBSERVED,
        },
        "path": path,
        "hops": [name for name, _, _ in HOPS],
        "resolved_hops": [row["hop"] for row in path],
        "unresolved": unresolved,
        "crypto_assets": crypto,
        "critical_systems": systems,
        "reaches_crypto": bool(library or hsm),
        "answerable": bool(path),
        "facts": {
            OBSERVED: 1,
            NETWORK_OBSERVED: 1 if event.get("sni") or event.get("tls_version") else 0,
            CONFIGURED: len([row for row in path if row["fact"] == CONFIGURED]),
            RUNTIME_OBSERVED: len([row for row in path
                                   if row["fact"] == RUNTIME_OBSERVED]),
        },
        "note": "an unresolved hop is a coverage finding: the estate cannot answer for what "
                "it has never collected, and it says so instead of guessing",
    }
