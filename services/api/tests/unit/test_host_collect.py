"""Collector → estate packages: what each collector really establishes.

The contracts pinned here are the honest ones:

* a mapped library is ``PROCESS_LIBRARY`` — ``usage_state: SUPPORTED``, never OBSERVED
  and never an algorithm claim;
* a completed handshake is ``NEGOTIATED``; a refused target produces **no** evidence;
* a Windows export is ``CONFIGURED`` — an enabled protocol is not a connection;
* re-running a collector converges instead of doubling the estate.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from api import host_collect
from shared_models.estate_graph import build_graph


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_fake_proc(base: Path) -> None:
    """One nginx mapping OpenSSL, listening on 443."""
    _write(base / "101" / "comm", "nginx\n")
    _write(base / "101" / "cmdline", "nginx: master process\x00")
    _write(
        base / "101" / "maps",
        "7f0000000000-7f0000010000 r--p 00000000 08:01 100 /usr/lib/libcrypto.so.3\n",
    )
    _write(base / "101" / "cgroup", "0::/system.slice/nginx.service\n")
    _write(
        base / "net" / "tcp",
        "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 000000 0 0 9001\n",
    )
    (base / "101" / "fd").mkdir(parents=True, exist_ok=True)
    os.symlink("socket:[9001]", base / "101" / "fd" / "3")


def test_runtime_reports_mapped_libraries_as_presence_not_use(tmp_path):
    build_fake_proc(tmp_path)
    package = host_collect.collect_runtime(proc_base=str(tmp_path))

    types = {row["type"] for row in package["assets"]}
    assert types == {"HOST", "LIBRARY", "NETWORK_ENDPOINT"}
    library = next(row for row in package["assets"] if row["type"] == "LIBRARY")
    assert library["name"] == "openssl"

    facts = [row["facts"] for row in package["evidence"]
             if row["evidence_type"] == "RUNTIME_OBSERVED" and row["facts"].get("library")]
    assert facts, "the mapped library must carry runtime evidence"
    assert facts[0]["evidence_kind"] == "PROCESS_LIBRARY"
    assert facts[0]["usage_state"] == "SUPPORTED"
    assert "not a call" in facts[0]["note"]

    # the relationship is `contains`, not `uses`: a mapped library is not a use
    predicates = {row["predicate"] for row in package["relationships"]}
    assert predicates == {"contains", "exposes"}

    graph = build_graph({
        "estate": "test", "scope": None,
        "assets": package["assets"], "evidence": package["evidence"],
        "relationships": package["relationships"], "collectors": [], "coverage": [],
    })
    # nothing here may create an OBSERVED crypto artefact
    assert graph.project("CBOM")["components"] == []
    assert package["summary"]["libraries"] == 1
    assert package["summary"]["listening_endpoints"] == 1


def test_runtime_trace_is_opt_in_and_reported_absent_when_not_asked(tmp_path):
    build_fake_proc(tmp_path)
    package = host_collect.collect_runtime(proc_base=str(tmp_path))
    assert package["summary"]["invocation"] is None


def test_network_records_a_real_handshake_as_negotiated():
    from network_scanner.probing.mock_bank_tls import MockBankTLS

    with MockBankTLS(max_tls_version="1.2", ciphers="ECDHE-RSA-AES128-GCM-SHA256") as server:
        package = host_collect.collect_network([server.endpoint], timeout=5.0)

    assert package["summary"]["negotiated"] == 1
    endpoint = next(row for row in package["assets"] if row["type"] == "NETWORK_ENDPOINT")
    facts = [row["facts"] for row in package["evidence"]
             if row["evidence_type"] == "NETWORK_ACTIVE_OBSERVED" and row["facts"].get("protocol")]
    assert facts and facts[0]["usage_state"] == "NEGOTIATED"
    assert facts[0]["protocol"] == "TLSv1.2"
    # the certificate the endpoint presented is its own asset, linked both ways
    assert any(row["type"] == "CERTIFICATE" for row in package["assets"])
    assert any(row["predicate"] == "protected_by" for row in package["relationships"])
    assert endpoint["attributes"]["cipher_suite"]


def test_an_unreachable_target_produces_no_evidence_and_says_why():
    package = host_collect.collect_network(["127.0.0.1:9"], timeout=1.0)
    assert package["summary"]["negotiated"] == 0
    assert package["evidence"] == []
    assert package["coverage"][0]["status"] == "NOT_OBSERVED"
    assert "not 'no crypto'" in package["coverage"][0]["impact"]


def test_windows_export_is_configuration_and_never_invocation(tmp_path):
    reg = tmp_path / "schannel.reg"
    reg.write_text(
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
        "\\SCHANNEL\\Protocols\\TLS 1.0\\Server]\n"
        '"Enabled"=dword:00000000\n',
        encoding="utf-8",
    )
    suites = tmp_path / "suites.json"
    suites.write_text('[{"Name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}]', encoding="utf-8")

    package = host_collect.collect_windows([reg, suites], host="win-bank-01")
    assert {row["evidence_type"] for row in package["evidence"]} == {"CONFIGURED"}
    kinds = {row["facts"].get("evidence_kind") for row in package["evidence"]}
    assert {"SCHANNEL_POLICY", "CIPHER_SUITE_POLICY", "ARTEFACT_EXPORT"} <= kinds

    graph = build_graph({
        "estate": "test", "scope": None,
        "assets": package["assets"], "evidence": package["evidence"],
        "relationships": package["relationships"], "collectors": [], "coverage": [],
    })
    artifacts = graph.project("CBOM")["components"]
    # a policy and a suite list are capability/configuration, never OBSERVED
    assert artifacts
    assert all(item["usage_state"] in {"SUPPORTED", "CONFIGURED"} for item in artifacts)


def test_merge_is_idempotent(tmp_path):
    build_fake_proc(tmp_path)
    package = host_collect.collect_runtime(proc_base=str(tmp_path))
    once = host_collect.merge_payload(None, [package], estate="local")
    twice = host_collect.merge_payload(once, [package], estate="local")
    assert len(once["assets"]) == len(twice["assets"])
    assert len(once["evidence"]) == len(twice["evidence"])
    assert len(once["relationships"]) == len(twice["relationships"])
    # and the collector outcome is replaced, not appended twice
    assert len(twice["collectors"]) == 1


def test_capabilities_state_which_collector_can_run_here(tmp_path):
    caps = host_collect.capabilities(proc_base=str(tmp_path))
    by_id = {row["id"]: row for row in caps["collectors"]}
    assert by_id["runtime"]["state"] == "AVAILABLE"
    assert by_id["network"]["state"] == "INPUT_REQUIRED"
    assert by_id["windows"]["state"] == "INPUT_REQUIRED"
    # trace mode is reported separately: a missing compiler must not read as "no runtime"
    assert by_id["runtime"]["trace"]["state"] in {"AVAILABLE", "UNAVAILABLE"}


def test_capabilities_report_a_missing_proc_tree_as_unavailable():
    caps = host_collect.capabilities(proc_base="/nonexistent-proc")
    runtime = next(row for row in caps["collectors"] if row["id"] == "runtime")
    assert runtime["state"] == "UNAVAILABLE"
    assert "/nonexistent-proc" in runtime["state_reason"]
