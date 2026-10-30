"""Collector → estate: turn what was just observed into six BOMs.

The platform already had the collectors. What it did not have was a path from a
collector *run* into the evidence graph, so a fresh estate showed static findings and
nothing else: runtime evidence lived in its own table, TLS probes lived in the network
scanner's output, Windows exports lived nowhere. That is the maturity gap this module
closes, and it closes it at the only honest layer — the evidence graph every BOM is
projected from.

Three collectors, each producing an **estate package** (assets, evidence,
relationships, collector outcomes, coverage) that is merged into the stored observation
and re-projected:

``runtime``
    ``/proc`` process + mapped-crypto-library discovery, and optionally one command
    run under the LD_PRELOAD shim. A mapped library is evidence that the library is
    *present in a running process* — ``usage_state: SUPPORTED``, never OBSERVED. A
    traced call is ``OBSERVED``, because a call was counted.

``network``
    real TLS handshakes against the targets the operator names. A completed handshake
    is ``NETWORK_ACTIVE_OBSERVED`` with ``usage_state: NEGOTIATED``; a refused or
    unreachable target produces **no** evidence and is reported in the coverage rows
    with its reason, because "could not connect" is not "no crypto".

``windows``
    the exports a Windows host already wrote (SCHANNEL registry policy, cipher-suite
    list, certificate store). Configuration only — enabled is not used.

Every package records what it establishes. Nothing here promotes a declaration to an
observation, and re-running a collector is idempotent: evidence ids are content
addressed, so the same fact twice is the same fact once.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable, Sequence

from shared_models.estate_graph import asset_id as canonical_asset_id
from shared_models.estate_graph import content_evidence_id

logger = logging.getLogger(__name__)

SCHEMA = "cryptoscan.host-collect/1"

#: what each collector establishes, in the vocabulary the BOMs use
DEPTHS: dict[str, str] = {
    "runtime": "PROCESS_LIBRARY / INVOCATION",
    "network": "NEGOTIATED",
    "windows": "CONFIGURED",
}

COLLECTORS: tuple[dict[str, Any], ...] = (
    {
        "id": "runtime",
        "label": "Runtime — this host",
        "plane": "RUNTIME",
        "establishes": "a crypto library mapped by a running process (PROCESS_LIBRARY); a counted "
                       "crypto call when a command is traced (INVOCATION)",
        "cannot_claim": (
            "a mapped library is not a call. Nothing here says which algorithm ran: only a traced "
            "process yields invocation evidence, and only for processes started under the shim"
        ),
        "requires": "read access to /proc (same-user processes at minimum); a compiler for the "
                    "trace mode",
        "inputs": ["proc_base", "trace_argv", "trace_timeout"],
    },
    {
        "id": "network",
        "label": "Network — TLS handshakes",
        "plane": "NETWORK",
        "establishes": "the protocol version, cipher suite, ALPN and certificate a target actually "
                       "negotiated with this scanner",
        "cannot_claim": (
            "one handshake from one vantage point. It says what the endpoint offered this client "
            "once; it does not enumerate every suite or prove what applications use"
        ),
        "requires": "network reachability to each target; targets must be authorised by the operator",
        "inputs": ["targets", "timeout"],
    },
    {
        "id": "windows",
        "label": "Windows — exported artefacts",
        "plane": "WINDOWS",
        "establishes": "the Schannel protocol policy, the offered cipher suites and the machine "
                       "certificate store of a Windows host, read from its own exports",
        "cannot_claim": (
            "configuration, never invocation: an enabled protocol and an offered suite are not a "
            "connection, and a stored certificate was not necessarily presented"
        ),
        "requires": "artefact files exported on the host (reg export, Get-TlsCipherSuite, "
                    "Get-ChildItem Cert:\\)",
        "inputs": ["artifacts", "host"],
    },
)


# --------------------------------------------------------------------------- #
# package construction
# --------------------------------------------------------------------------- #
class _Package:
    """Assets, evidence and relationships for one collector run, deduplicated."""

    def __init__(self, collector: str) -> None:
        self.collector = collector
        self.assets: list[dict[str, Any]] = []
        self.evidence: list[dict[str, Any]] = []
        self.relationships: list[dict[str, Any]] = []
        self._asset_ids: dict[str, str] = {}
        self._evidence_ids: dict[str, str] = {}
        self._edges: set[tuple[str, str, str]] = set()

    def asset(
        self,
        kind: str,
        name: str,
        identity: dict[str, Any],
        *,
        attributes: dict[str, Any] | None = None,
        owner: str | None = None,
        location: str | None = None,
    ) -> str:
        ref = f"{kind.lower()}:{len(self._asset_ids)}:{abs(hash((kind, tuple(sorted(identity.items()))))) % 10**10}"
        node_id = canonical_asset_id(kind, identity, name=name)
        if node_id in self._asset_ids:
            return self._asset_ids[node_id]
        self.assets.append({
            "ref": ref,
            "type": kind,
            "name": name,
            "identity": dict(identity),
            "owner": owner,
            "location": location,
            "source": f"host-collect:{self.collector}",
            "attributes": dict(attributes or {}),
        })
        self._asset_ids[node_id] = ref
        self._node_ids = getattr(self, "_node_ids", {})
        self._node_ids[ref] = node_id
        return ref

    def node_id(self, ref: str) -> str:
        return getattr(self, "_node_ids", {}).get(ref, ref)

    def evidence_for(
        self,
        ref: str,
        evidence_type: str,
        facts: dict[str, Any],
        *,
        layer: str = "APPLICATION",
    ) -> str:
        target = self.node_id(ref)
        digest = content_evidence_id(
            evidence_type, target, facts, layer, f"host-collect:{self.collector}",
            f"host-collect:{self.collector}",
        )
        if digest in self._evidence_ids:
            return digest
        self.evidence.append({
            "source": f"host-collect:{self.collector}",
            "collector": f"host-collect:{self.collector}",
            "evidence_type": evidence_type,
            "target": ref,
            "layer": layer,
            "observed_at": None,
            "facts": facts,
        })
        self._evidence_ids[digest] = target
        return digest

    def relationship(
        self,
        subject: str,
        predicate: str,
        obj: str,
        *,
        basis: str,
        evidence_id: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        key = (subject, predicate, obj)
        if key in self._edges:
            return
        self._edges.add(key)
        self.relationships.append({
            "subject": subject,
            "predicate": predicate,
            "object": obj,
            "basis": basis,
            "evidence_ids": [evidence_id],
            "attributes": dict(attributes or {}),
        })


def _package_dict(package: _Package, *, collector: dict[str, Any], coverage: list[dict[str, Any]],
                  summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": package.collector,
        "assets": package.assets,
        "evidence": package.evidence,
        "relationships": package.relationships,
        "collector": collector,
        "coverage": coverage,
        "summary": summary,
    }


# --------------------------------------------------------------------------- #
# runtime
# --------------------------------------------------------------------------- #
def collect_runtime(
    *,
    proc_base: str = "/proc",
    trace_argv: Sequence[str] | None = None,
    trace_timeout: float = 120.0,
) -> dict[str, Any]:
    """Process + mapped-library discovery, plus one optional traced command."""
    from runtime.agent.process_discovery import scan_processes

    package = _Package("runtime")
    inventory = scan_processes(proc_base, crypto_only=(proc_base == "/proc"))
    host_name = str(inventory.get("host") or "unknown")
    host_ref = package.asset(
        "HOST", host_name, {"hostname": host_name},
        attributes={
            "source": "proc",
            "total_processes_scanned": inventory.get("total_processes_scanned"),
            "processes_with_tls_libraries": inventory.get("processes_with_tls_libraries"),
            "listening_processes": inventory.get("listening_processes"),
            "kernel_threads_skipped": inventory.get("kernel_threads_skipped"),
        },
        location=proc_base,
    )
    host_evidence = package.evidence_for(host_ref, "RUNTIME_OBSERVED", {
        "evidence_kind": "HOST_PROCESS_INVENTORY",
        "hostname": host_name,
        "processes_scanned": inventory.get("total_processes_scanned"),
        "processes_with_tls_libraries": inventory.get("processes_with_tls_libraries"),
        "usage_state": "SUPPORTED",
        "note": (
            "the process list is observed on a running host; which algorithm any of those "
            "processes ran is not observed by this pass"
        ),
    }, layer="PLATFORM")

    libraries: dict[tuple[str, str], dict[str, Any]] = {}
    endpoints: dict[tuple[str, int], str] = {}
    for process in inventory.get("processes") or []:
        for detail in process.get("library_details") or []:
            name = str(detail.get("library") or "").strip()
            if not name:
                continue
            version = str(detail.get("version") or "") or None
            entry = libraries.setdefault((name, version or ""), {
                "name": name,
                "version": version,
                "package": detail.get("package"),
                "package_version": detail.get("package_version"),
                "version_source": detail.get("version_source"),
                "status": detail.get("status"),
                "processes": [],
            })
            entry["processes"].append(process.get("process_name"))
        for port in process.get("listening_ports") or []:
            try:
                port_number = int(port)
            except (TypeError, ValueError):
                continue
            endpoints.setdefault((host_name, port_number), str(process.get("process_name") or ""))

    for (name, _version), entry in sorted(libraries.items()):
        ref = package.asset(
            "LIBRARY", name, {"name": name, "version": entry["version"]},
            attributes={
                "version": entry["version"],
                "version_source": entry["version_source"],
                "package": entry["package"],
                "package_version": entry["package_version"],
                "risk_status": entry["status"],
                "mapped_by_processes": sorted(set(entry["processes"]))[:20],
            },
        )
        evidence_id = package.evidence_for(ref, "RUNTIME_OBSERVED", {
            "library": name,
            "version": entry["version"],
            "evidence_kind": "PROCESS_LIBRARY",
            "mapped_by": sorted(set(entry["processes"]))[:20],
            "usage_state": "SUPPORTED",
            "note": (
                "mapped into a running process. That is presence at runtime, not a call: no "
                "algorithm is claimed and no usage state above SUPPORTED is set"
            ),
        })
        package.relationship(host_ref, "contains", ref, basis="RUNTIME_OBSERVATION",
                             evidence_id=evidence_id,
                             attributes={"kind": "mapped_library",
                                         "processes": len(set(entry["processes"]))})

    for (host, port), process_name in sorted(endpoints.items()):
        ref = package.asset(
            # an endpoint is identified by where it listens, not by what it turned out to
            # speak: the transport is an attribute so a handshake observed later lands on
            # the same asset instead of a second "tls" twin of the same socket
            "NETWORK_ENDPOINT", f"{host}:{port}", {"host": host, "port": port},
            attributes={
                "transport": "tcp",
                "process": process_name,
                "source": "proc-listening-socket",
            },
            location=f"{host}:{port}",
        )
        evidence_id = package.evidence_for(ref, "CONFIGURED", {
            "transport": "tcp",
            "listening": True,
            "process": process_name,
            "usage_state": "CONFIGURED",
            "note": "a listening socket observed in /proc; whether it speaks TLS is not established",
        }, layer="NETWORK_TRANSPORT")
        package.relationship(host_ref, "exposes", ref, basis="CONFIGURATION",
                             evidence_id=evidence_id,
                             attributes={"listening_process": process_name})

    trace_summary: dict[str, Any] | None = None
    trace_argv = [str(item) for item in (trace_argv or [])]
    if trace_argv:
        trace_summary = _trace(package, host_ref, trace_argv, float(trace_timeout))

    summary = {
        "collector": "runtime",
        "host": host_name,
        "processes_scanned": inventory.get("total_processes_scanned"),
        "processes_with_tls_libraries": inventory.get("processes_with_tls_libraries"),
        "libraries": len(libraries),
        "listening_endpoints": len(endpoints),
        "invocation": trace_summary,
        "establishes": DEPTHS["runtime"],
        "note": (
            "mapped libraries raise SBOM to observed presence; algorithms stay unclaimed until a "
            "process is traced"
        ),
    }
    coverage = [{
        "target": f"processes on {host_name}",
        "expected": inventory.get("total_processes_scanned"),
        "collected": inventory.get("process_count"),
        # The estate engine's vocabulary, not a word of our own: nothing scanned is a
        # failed collection, and it must reach the coverage row as one.
        "status": "COMPLETE" if inventory.get("total_processes_scanned") else "FAILED",
        "note": "same-user processes are readable without privilege; other users' maps are not",
        "impact": None if inventory.get("processes_with_tls_libraries") else
                  "no process on this host maps a crypto library this collector recognises",
    }]
    collector = {
        "plane": "RUNTIME",
        "status": "COMPLETE",
        "expected": inventory.get("total_processes_scanned") or 0,
        "collected": len(inventory.get("processes") or []),
        "reason": "process and mapped-library discovery via /proc",
        "impact": None,
    }
    return _package_dict(package, collector=collector, coverage=coverage, summary=summary)


def _trace(package: _Package, host_ref: str, argv: list[str], timeout: float) -> dict[str, Any]:
    """Run one command under the shim and record the calls it made."""
    from runtime.agent.preload_trace import trace_command

    try:
        result = trace_command(argv, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — a collector failure is reported, not raised
        return {"argv": argv, "state": "FAILED", "reason": f"{type(exc).__name__}: {exc}"[:240],
                "findings": 0}
    findings = result.get("findings") or []
    calls = 0
    for finding in findings:
        algorithm = str(finding.get("algorithm") or "UNKNOWN")
        facts = {
            "algorithm": algorithm,
            "mode": finding.get("mode"),
            "key_size": finding.get("key_size"),
            "function": finding.get("function"),
            "process": finding.get("process_name"),
            "observations": int(finding.get("observation_count") or 1),
            "evidence_kind": "INVOCATION",
            "usage_state": "OBSERVED",
            "note": "a crypto call counted under the LD_PRELOAD shim",
        }
        calls += int(finding.get("observation_count") or 1)
        package.evidence_for(host_ref, "RUNTIME_OBSERVED", facts)
    return {
        "argv": argv,
        "state": "TRACED" if result.get("findings") is not None else "FAILED",
        "returncode": result.get("returncode"),
        "timed_out": result.get("timed_out"),
        "findings": len(findings),
        "calls": calls,
        "note": (
            "invocation evidence for the traced command only; an untraced process on the same "
            "host contributes nothing"
        ),
    }


# --------------------------------------------------------------------------- #
# network
# --------------------------------------------------------------------------- #
def collect_network(
    targets: Iterable[str],
    *,
    timeout: float = 5.0,
    check_chain: bool = True,
) -> dict[str, Any]:
    """Real TLS handshakes against operator-named targets."""
    from cbom.nbom import probe_to_endpoint
    from network_scanner.probing.active_prober import probe_endpoint

    package = _Package("network")
    results: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    observed = 0

    for raw in targets:
        target = str(raw or "").strip()
        if not target:
            continue
        finding = probe_endpoint(target, timeout=timeout, check_chain_sent=check_chain)
        endpoint = probe_to_endpoint(finding) or {}
        status = str(finding.get("status") or "UNKNOWN")
        negotiated = bool(endpoint.get("observed"))
        host = str(endpoint.get("host") or target.rpartition(":")[0] or target)
        port = endpoint.get("port")
        port_number = int(port) if isinstance(port, int) or str(port).isdigit() else 0
        results.append({
            "target": target,
            "status": status,
            "observed": negotiated,
            "tls_version": endpoint.get("tls_version"),
            "cipher_suite": endpoint.get("cipher_suite"),
            "error": finding.get("error"),
        })
        if not negotiated:
            coverage.append({
                "target": target,
                "expected": 1,
                "collected": 0,
                "status": "NOT_OBSERVED",
                "note": f"handshake did not complete ({status})"
                        + (f": {finding.get('error')}" if finding.get("error") else ""),
                "impact": "no cryptographic fact was recorded for this target; it is not 'no crypto'",
            })
            continue
        observed += 1
        ref = package.asset(
            "NETWORK_ENDPOINT", f"{host}:{port_number}",
            {"host": host, "port": port_number},
            attributes={
                "transport": "tls",
                "protocol": str(endpoint.get("protocol") or "tls"),
                "tls_version": endpoint.get("tls_version"),
                "cipher_suite": endpoint.get("cipher_suite"),
                "alpn": endpoint.get("service"),
                "sni": finding.get("sni"),
                "scan_method": (finding.get("metadata") or {}).get("scan_method"),
            },
            location=f"{host}:{port_number}",
        )
        evidence_id = package.evidence_for(ref, "NETWORK_ACTIVE_OBSERVED", {
            "protocol": endpoint.get("tls_version"),
            "cipher_suite": endpoint.get("cipher_suite"),
            "alpn": endpoint.get("service"),
            "key_exchange": _suite_field(endpoint.get("cipher_suite"), "kex"),
            "encryption": _suite_field(endpoint.get("cipher_suite"), "bulk"),
            "usage_state": "NEGOTIATED",
            "note": (
                "one completed handshake with this scanner. It is what this endpoint offered "
                "this client once, not every suite it supports"
            ),
        }, layer="NETWORK_TRANSPORT")
        certificates = (finding.get("certificates") or [])[:1]
        if certificates:
            leaf = certificates[0]
            fingerprint = str(leaf.get("fingerprint_sha256") or "").strip()
            cert_ref = package.asset(
                "CERTIFICATE",
                str(leaf.get("subject") or fingerprint or f"{host}:{port_number}"),
                {
                    "fingerprint_sha256": fingerprint or None,
                    "serial_number": leaf.get("serial_number"),
                    "subject": leaf.get("subject"),
                },
                attributes={
                    "issuer": leaf.get("issuer"),
                    "not_after": str(leaf.get("not_after") or "") or None,
                    "public_key_algorithm": leaf.get("public_key_algorithm"),
                    "public_key_size": leaf.get("public_key_size"),
                    "is_self_signed": leaf.get("is_self_signed"),
                },
            )
            cert_evidence = package.evidence_for(cert_ref, "NETWORK_ACTIVE_OBSERVED", {
                "fingerprint_sha256": fingerprint or None,
                "issuer": leaf.get("issuer"),
                "not_after": str(leaf.get("not_after") or "") or None,
                "public_key_algorithm": leaf.get("public_key_algorithm"),
                "note": "the certificate this endpoint presented during the handshake",
            }, layer="NETWORK_TRANSPORT")
            package.relationship(ref, "protected_by", cert_ref, basis="NETWORK_OBSERVATION",
                                 evidence_id=cert_evidence)
        coverage.append({
            "target": target,
            "expected": 1,
            "collected": 1,
            "status": "COMPLETE",
            "note": f"negotiated {endpoint.get('tls_version')} {endpoint.get('cipher_suite') or ''}".strip(),
            "impact": None,
        })
        _ = evidence_id

    summary = {
        "collector": "network",
        "targets": len(results),
        "negotiated": observed,
        "failed": len([row for row in results if not row["observed"]]),
        "results": results,
        "establishes": DEPTHS["network"],
        "note": (
            "a completed handshake is NEGOTIATED evidence. A refused or unreachable target "
            "produces no evidence at all and is listed with its reason"
        ),
    }
    # all targets negotiated -> COMPLETE; some -> PARTIAL; none but targets were
    # named -> FAILED (the plane's inventory is unknown, not empty); no targets at
    # all -> NOT_ATTEMPTED. Each of those is a coverage fact, never an absence.
    if results and observed == len(results):
        status = "COMPLETE"
    elif observed:
        status = "PARTIAL"
    elif results:
        status = "FAILED"
    else:
        status = "NOT_ATTEMPTED"
    collector = {
        "plane": "NETWORK",
        "status": status,
        "expected": len(results),
        "collected": observed,
        "reason": "active TLS handshake per target",
        "impact": (
            None if status == "COMPLETE"
            else (
                f"no handshake completed on any of the {len(results)} named targets: this plane's "
                "inventory is unknown, not empty"
                if status == "FAILED"
                else "some targets did not negotiate; they are NOT_OBSERVED, not empty"
            )
        ),
    }
    return _package_dict(package, collector=collector, coverage=coverage, summary=summary)


def _suite_field(suite: Any, which: str) -> str | None:
    """Key-exchange / bulk-cipher name out of an OpenSSL suite name."""
    text = str(suite or "")
    if not text:
        return None
    parts = [part.strip() for part in text.split("-") if part.strip()]
    if which == "kex":
        return parts[0] if parts else None
    bulky = [part for part in parts[1:] if part.upper() in {"AES256", "AES128", "AES", "CHACHA20",
                                                            "3DES", "CAMELLIA256", "CAMELLIA128"}]
    return bulky[0] if bulky else (parts[1] if len(parts) > 1 else None)


# --------------------------------------------------------------------------- #
# windows
# --------------------------------------------------------------------------- #
def collect_windows(artifacts: Iterable[str | Path], *, host: str | None = None) -> dict[str, Any]:
    """Parse a Windows host's own exports into configuration evidence."""
    from api.windows_artifacts import parse_artifacts

    parsed = parse_artifacts([str(item) for item in artifacts])
    package = _Package("windows")
    host_name = str(host or "windows-host").strip() or "windows-host"
    ref = package.asset(
        "HOST", host_name, {"hostname": host_name},
        attributes={
            "platform": "windows",
            "artifacts_read": len(parsed["files"]) - len(parsed["refused"]),
            "artifacts_refused": len(parsed["refused"]),
            "source": "exported artefacts",
        },
    )
    package.evidence_for(ref, "CONFIGURED", {
        "platform": "windows",
        "evidence_kind": "ARTEFACT_EXPORT",
        "files": [row["path"] for row in parsed["files"] if not row["error"]][:20],
        "usage_state": "CONFIGURED",
        "note": (
            "read from exports the host produced; the control plane did not run on the host and "
            "observed no connection"
        ),
    }, layer="PLATFORM")

    for protocol in parsed["protocols"]:
        if protocol.get("enabled") is None and protocol.get("disabled_by_default") is None:
            continue
        name = str(protocol.get("protocol") or "").replace(" ", "").upper()
        package.evidence_for(ref, "CONFIGURED", {
            "protocol": name,
            "enabled": protocol.get("enabled"),
            "disabled_by_default": protocol.get("disabled_by_default"),
            "scope": protocol.get("scope"),
            "evidence_kind": "SCHANNEL_POLICY",
            "usage_state": "CONFIGURED",
            "note": "Schannel policy: this protocol is configured, which is not a connection",
        }, layer="NETWORK_TRANSPORT")

    capabilities: list[str] = []
    for suite in parsed["suites"]:
        for algorithm in suite.get("algorithms") or []:
            name = str(algorithm.get("algorithm") or "")
            if name and name not in capabilities:
                capabilities.append(name)
    if parsed["suites"]:
        package.evidence_for(ref, "CONFIGURED", {
            "capabilities": capabilities,
            "suites": [row["suite"] for row in parsed["suites"]][:200],
            "evidence_kind": "CIPHER_SUITE_POLICY",
            "usage_state": "CONFIGURED",
            "note": (
                "the suites this host offers, with the algorithms their names state. Offering a "
                "suite is capability, not a negotiated connection"
            ),
        }, layer="NETWORK_TRANSPORT")

    for certificate in parsed["certificates"]:
        subject = str(certificate.get("subject") or certificate.get("thumbprint") or "")
        cert_ref = package.asset(
            "CERTIFICATE", subject,
            {"subject": subject, "serial_number": certificate.get("thumbprint")},
            attributes={
                "thumbprint_sha1": certificate.get("thumbprint"),
                "issuer": certificate.get("issuer"),
                "not_before": certificate.get("not_before"),
                "not_after": certificate.get("not_after"),
                "has_private_key": certificate.get("has_private_key"),
                "public_key_algorithm": certificate.get("public_key_algorithm"),
                "dns_names": certificate.get("dns_names"),
            },
        )
        evidence_id = package.evidence_for(cert_ref, "CONFIGURED", {
            "thumbprint_sha1": certificate.get("thumbprint"),
            "issuer": certificate.get("issuer"),
            "not_after": certificate.get("not_after"),
            "note": "present in the exported machine store; not observed in a handshake",
        }, layer="NETWORK_TRANSPORT")
        package.relationship(ref, "contains", cert_ref, basis="CONFIGURATION",
                             evidence_id=evidence_id,
                             attributes={"store": "machine", "source": "export"})

    summary = {
        "collector": "windows",
        "host": host_name,
        "protocols": len(parsed["protocols"]),
        "suites": len(parsed["suites"]),
        "certificates": len(parsed["certificates"]),
        "refused": parsed["refused"],
        "capabilities": capabilities,
        "establishes": DEPTHS["windows"],
        "note": parsed["note"],
    }
    coverage = [{
        "target": f"windows artefacts for {host_name}",
        "expected": len(parsed["files"]),
        "collected": len(parsed["files"]) - len(parsed["refused"]),
        "status": "COMPLETE" if not parsed["refused"] else "PARTIAL",
        "note": "each refused file is listed with its reason",
        "impact": None,
    }]
    collector = {
        "plane": "WINDOWS",
        "status": "COMPLETE" if parsed["files"] and not parsed["refused"] else "PARTIAL",
        "expected": len(parsed["files"]),
        "collected": len(parsed["files"]) - len(parsed["refused"]),
        "reason": "offline parse of exported Windows artefacts (configuration only)",
        "impact": None if parsed["protocols"] or parsed["suites"] else
                  "no protocol or suite policy found in the exports",
    }
    return _package_dict(package, collector=collector, coverage=coverage, summary=summary)


# --------------------------------------------------------------------------- #
# merge into the stored observation
# --------------------------------------------------------------------------- #
def merge_payload(existing: dict[str, Any] | None, packages: Sequence[dict[str, Any]],
                  *, estate: str | None = None) -> dict[str, Any]:
    """The stored observation plus the new packages, deduplicated by identity.

    Same asset id, same evidence id, same edge → one entry. A collector re-run therefore
    converges instead of doubling the estate.
    """
    base = dict(existing or {})
    assets: list[dict[str, Any]] = list(base.get("assets") or [])
    evidence: list[dict[str, Any]] = list(base.get("evidence") or [])
    relationships: list[dict[str, Any]] = list(base.get("relationships") or [])
    collectors: list[dict[str, Any]] = list(base.get("collectors") or [])
    coverage: list[dict[str, Any]] = list(base.get("coverage") or [])

    seen_assets = {canonical_asset_id(str(row.get("type") or "UNKNOWN"), row.get("identity") or {},
                                      name=row.get("name"))
                   for row in assets if row.get("type")}
    seen_evidence = {_evidence_key(row) for row in evidence}
    seen_edges = {(row.get("subject"), row.get("predicate"), row.get("object")) for row in relationships}

    for package in packages:
        for row in package.get("assets") or []:
            node = canonical_asset_id(str(row.get("type") or "UNKNOWN"), row.get("identity") or {},
                                      name=row.get("name"))
            if node in seen_assets:
                continue
            seen_assets.add(node)
            assets.append(row)
        for row in package.get("evidence") or []:
            digest = _evidence_key(row)
            if digest in seen_evidence:
                continue
            seen_evidence.add(digest)
            evidence.append(row)
        for row in package.get("relationships") or []:
            key = (row.get("subject"), row.get("predicate"), row.get("object"))
            if key in seen_edges:
                continue
            seen_edges.add(key)
            relationships.append(row)
        if package.get("collector"):
            plane = package["collector"].get("plane")
            collectors = [row for row in collectors if row.get("plane") != plane]
            collectors.append(package["collector"])
        coverage.extend(package.get("coverage") or [])

    merged = {
        **base,
        "estate": estate or base.get("estate") or "default",
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "collectors": collectors,
        "coverage": coverage,
    }
    return merged


def _evidence_key(row: dict[str, Any]) -> str:
    """A stable key for one evidence record inside a payload.

    The engine's own id is content addressed over the *resolved* asset id, which a
    payload has not resolved yet, so this keys on the record's own content plus its
    target reference. Re-running a collector produces the same key and therefore the
    same single row.
    """
    explicit = str(row.get("evidence_id") or "") or None
    if explicit:
        return explicit
    return content_evidence_id(
        str(row.get("evidence_type") or "UNKNOWN"), str(row.get("target") or ""),
        row.get("facts") or {}, str(row.get("layer") or "UNKNOWN"),
        str(row.get("source") or ""), str(row.get("collector") or ""),
    )


def latest_payload(db: Any) -> tuple[dict[str, Any] | None, str | None]:
    """The newest stored observation payload and its estate name, if there is one."""
    from api.estate_twin_graph import RUN_KIND
    from db.repositories.scan_run_repository import ScanRunRepository
    from db.tenancy import current_tenant

    runs = ScanRunRepository(db).list_runs(limit=1, target_kind=RUN_KIND, owner=current_tenant())
    if not runs:
        return None, None
    payload = (runs[0].result or {}).get("estate_discovery") or None
    estate = str((payload or {}).get("estate") or "") or None
    return payload, estate


def capabilities(*, proc_base: str = "/proc") -> dict[str, Any]:
    """Which collectors can actually run here, with the reason when one cannot."""
    runtime_state, runtime_reason = "AVAILABLE", None
    if not Path(proc_base).is_dir():
        runtime_state, runtime_reason = "UNAVAILABLE", f"{proc_base} is not readable from this process"
    trace_state, trace_reason = "AVAILABLE", None
    try:
        from runtime.agent.preload_trace import ensure_shim

        if ensure_shim() is None:
            trace_state = "UNAVAILABLE"
            trace_reason = "no C compiler to build the LD_PRELOAD shim"
    except Exception as exc:  # noqa: BLE001 — a missing toolchain is a fact to report
        trace_state, trace_reason = "UNAVAILABLE", f"{type(exc).__name__}: {exc}"[:200]

    rows = []
    for collector in COLLECTORS:
        row = dict(collector)
        if collector["id"] == "runtime":
            row["state"] = runtime_state
            row["state_reason"] = runtime_reason
            row["trace"] = {"state": trace_state, "reason": trace_reason}
        else:
            row["state"] = "INPUT_REQUIRED"
            row["state_reason"] = (
                "name the targets to handshake" if collector["id"] == "network"
                else "point at the exported artefacts"
            )
        rows.append(row)
    return {
        "schema": SCHEMA,
        "collectors": rows,
        "estates": _estate_choices(),
        "note": (
            "a collector that cannot run here says so instead of returning an empty result that "
            "reads like an empty estate"
        ),
    }


def _estate_choices() -> list[str]:
    return ["runtime-local", "network-local", "windows-local"]


__all__ = [
    "COLLECTORS",
    "DEPTHS",
    "SCHEMA",
    "capabilities",
    "collect_network",
    "collect_runtime",
    "collect_windows",
    "latest_payload",
    "merge_payload",
]
