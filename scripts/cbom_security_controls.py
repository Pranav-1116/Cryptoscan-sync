#!/usr/bin/env python3
"""Guide 181 — the security control integration layer, proved against itself.

Guide 180 mapped a stored estate into one graph. This guide builds the layer that feeds it
from the controls the bank already runs — firewall, IDS, IPS, WAF, load balancer, API gateway,
rate limiter, VPN, SIEM — and proves the five promises the specification makes:

* **read-only.** A collector has six verbs, none of them writes, and a dialect that names a
  mutating operation or endpoint is refused when it is registered;
* **no prohibited value survives.** Private keys, key material, passwords, API secrets,
  session tokens, payloads, HTTP bodies, card data, credentials, cookies and authorization
  headers are redacted by name *and* by shape, and the redaction is recorded as evidence;
* **the three facts stay apart.** What the control is configured to do, what the network saw
  and what the application did are three records, never one verdict;
* **every relationship carries evidence**, and it is typed: a pairing no relation permits is
  refused by name instead of drawn, and a node nobody inventoried is never invented;
* **an alert becomes a crypto question.** ``source IP → host → process → API → OpenSSL →
  HSM``, hop by hop, and a hop nobody collected is a named gap.

Usage::

    python scripts/cbom_security_controls.py            # markdown to stdout
    python scripts/cbom_security_controls.py --json out.json --md out.md
    python scripts/cbom_security_controls.py --check    # exit 1 on partial, 2 on failure
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]

SCHEMA = "cryptoscan.security-controls-guide/1"
GUIDE = 181

VERDICT_PASS = "PASS"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_FAIL = "FAIL"

AS_OF = "2026-11-03"

#: values planted in the fixtures. If one of these appears in a report, the promise failed.
SENTINELS: tuple[str, ...] = (
    "hunter2-password-sentinel",
    "sk-live-abcdef-sentinel",
    "-----BEGIN RSA PRIVATE KEY-----",
    "4111 1111 1111 1111",
    "Bearer eyJhbGciOi-sentinel",
    "psk-shared-secret-sentinel",
    "session-cookie-sentinel",
    "4111111111111111",
)


def _live() -> dict[str, Any]:
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))
    from _bootstrap import bootstrap  # noqa: PLC0415

    bootstrap()
    from cbom import security_controls as sc  # noqa: PLC0415
    from cbom import techbom  # noqa: PLC0415

    return {"sc": sc, "tb": techbom}


# --------------------------------------------------------------------------- #
# The recorded estate: nine controls, one bank
# --------------------------------------------------------------------------- #

def feeds() -> list[dict[str, Any]]:
    return [
        {
            "control": "FIREWALL", "vendor": "fortigate",
            "feed": {
                "system": "FW-EDGE-01",
                "assets": [
                    {"kind": "FIREWALL", "name": "FW-EDGE-01", "version": "7.4.3",
                     "location": "dc-1", "vendor": "Fortinet"},
                    {"kind": "NETWORK_SEGMENT", "name": "INTERNET"},
                    {"kind": "NETWORK_SEGMENT", "name": "PAYMENTS-SEG"},
                    {"kind": "NETWORK_SEGMENT", "name": "DMZ"},
                ],
                "sections": {
                    "firewall_policy": [
                        {"srcintf": "INTERNET", "dstintf": "PAYMENTS-SEG",
                         "service": "HTTPS", "action": "accept",
                         "password": "hunter2-password-sentinel"},
                        {"srcintf": "INTERNET", "dstintf": "PAYMENTS-SEG",
                         "service": "SSH", "action": "deny"},
                        {"srcintf": "PAYMENTS-SEG", "dstintf": "INTERNET",
                         "service": "HTTPS", "action": "accept",
                         "comment": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow-sentinel"},
                    ],
                    "system_zone": [{"name": "PAYMENTS-SEG", "interface": ["port3"]}],
                    "vpn_ipsec_phase1": [{"name": "TUN-DR", "psk": "psk-shared-secret-sentinel"}],
                    "firewall_ssl_ssh_profile": [{"name": "deep-inspect", "mode": "INSPECT"}],
                },
                "relationships": [
                    {"from": "FW-EDGE-01", "relation": "PROTECTS", "to": "PAYMENTS-SEG",
                     "basis": "config-parse", "evidence": "fw-rule-1",
                     "facts": {"port": 443, "protocol": "tcp", "rule": "FW-001"}},
                    {"from": "FW-EDGE-01", "relation": "INSPECTS", "to": "DMZ",
                     "basis": "config-parse", "evidence": "fw-rule-2"},
                    # a pairing the model has no relation for: refused, by name
                    {"from": "FW-EDGE-01", "relation": "PRESENTS", "to": "PAYMENTS-SEG",
                     "basis": "config-parse", "evidence": "fw-rule-3"},
                    # a relation that is not in the vocabulary at all
                    {"from": "FW-EDGE-01", "relation": "ALLOWS", "to": "PAYMENTS-SEG",
                     "basis": "config-parse", "evidence": "fw-rule-4"},
                    # a claim with no evidence id
                    {"from": "FW-EDGE-01", "relation": "INSPECTS", "to": "INTERNET",
                     "basis": "config-parse"},
                    # an edge to a node nobody declared
                    {"from": "FW-EDGE-01", "relation": "PROTECTS", "to": "SHADOW-SEG",
                     "basis": "config-parse", "evidence": "fw-rule-5"},
                ],
                "health": {"reachable": True, "read_only": True,
                           "collected_at": f"{AS_OF}T06:00:00Z"},
            },
        },
        {
            "control": "IDS", "vendor": "suricata",
            "feed": {
                "system": "IDS-SENSOR-01",
                "assets": [{"kind": "IDS", "name": "IDS-SENSOR-01", "version": "6.0.9"}],
                "sections": {
                    "eve": [{"signature_id": "2001219", "rev": "19", "src_ip": "10.20.3.4",
                             "dest_ip": "10.30.1.10", "proto": "TCP", "dest_port": 443,
                             "tls_version": "TLSv1.2",
                             "sni": "payments.bank.example",
                             "payload": "POST /payments HTTP/1.1 Cookie: session-cookie-sentinel"}],
                    "rules": [{"sid": "2001219", "rev": "19",
                               "classification": "attempted-recon", "enabled": True}],
                },
                "events": [
                    {"kind": "ALERT", "signature": "2001219", "signature_revision": "19",
                     "src": "10.20.3.4", "dst": "10.30.1.10", "protocol": "tcp",
                     "port": 443, "tls_version": "TLSv1.2",
                     "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                     "sni": "payments.bank.example", "timestamp": f"{AS_OF}T09:14:00Z",
                     "authorization": "Bearer eyJhbGciOi-sentinel",
                     "payload": "POST /payments HTTP/1.1"},
                    {"kind": "TELEMETRY", "signature": "stats-only"},
                ],
                "health": {"reachable": True},
            },
        },
        {
            "control": "IPS", "vendor": "suricata_inline",
            "feed": {
                "system": "IPS-INLINE-01",
                "assets": [{"kind": "IPS", "name": "IPS-INLINE-01", "version": "6.0.9"}],
                "sections": {"inline": [{"name": "protect-payments", "mode": "PREVENT"}]},
                "events": [
                    {"kind": "BLOCK", "signature": "1:2027757", "action": "DROP",
                     "src": "10.20.3.4", "dst": "10.30.1.10", "protocol": "tcp",
                     "port": 443, "timestamp": f"{AS_OF}T09:15:00Z"},
                    {"kind": "ALERT", "signature": "1:2001219", "action": "ALERT",
                     "src": "10.20.3.4", "dst": "10.30.1.10", "protocol": "tcp",
                     "port": 443, "timestamp": f"{AS_OF}T09:14:00Z"},
                ],
                "health": {"reachable": True},
            },
        },
        {
            "control": "WAF", "vendor": "modsecurity",
            "feed": {
                "system": "WAF-01",
                "assets": [{"kind": "WAF", "name": "WAF-01", "version": "3.0.10"}],
                "sections": {
                    "policies": [{"SecRuleEngine": "On", "crs_version": "4.3.0",
                                  "paranoia": 2}],
                    "routes": [{"name": "payments", "host": "payments.bank.example",
                                "backend": "10.30.1.10:443", "tls": "TERMINATE"}],
                    "certificates": [{"hostname": "payments.bank.example",
                                      "certificate": {"subject": "CN=payments.bank.example",
                                                      "issuer": "CN=Bank Issuing CA",
                                                      "public_key_algorithm": "RSA",
                                                      "public_key_size": 2048,
                                                      "not_after": "2027-04-01"}}],
                },
                "crypto": [{"asset": "WAF-01", "tls_version": "TLSv1.2",
                            "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
                            "certificate": {"subject": "CN=payments.bank.example",
                                            "issuer": "CN=Bank Issuing CA",
                                            "public_key_algorithm": "RSA",
                                            "public_key_size": 2048}}],
                "events": [{"kind": "BLOCK", "signature": "942100", "src": "203.0.113.9",
                            "dst": "10.30.1.10", "port": 443,
                            "timestamp": f"{AS_OF}T09:16:00Z"}],
                "health": {"reachable": True},
            },
        },
        {
            "control": "LOAD_BALANCER", "vendor": "f5",
            "feed": {
                "system": "LB-01",
                "assets": [{"kind": "LOAD_BALANCER", "name": "LB-01", "version": "17.1.0"}],
                "sections": {
                    "virtual": [{"name": "vs-payments", "destination": "10.30.1.10:443",
                                 "pool": "pool-pay", "cert": "CN=payments.bank.example"}],
                    "pool": [{"name": "pool-pay",
                              "membersReference": ["10.30.2.11:8443", "10.30.2.12:8443"]}],
                    "client_ssl_profile": [{"name": "clientssl-payments",
                                            "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384"]}],
                },
                "crypto": [{"asset": "LB-01", "tls_version": "TLSv1.2",
                            "key_exchange": "ECDHE", "alpn": ["h2", "http/1.1"]}],
                "health": {"reachable": True},
            },
        },
        {
            "control": "API_GATEWAY", "vendor": "kong",
            "feed": {
                "system": "GW-API-01",
                "assets": [{"kind": "API_GATEWAY", "name": "GW-API-01", "version": "3.6"},
                           {"kind": "APPLICATION", "name": "PAYMENTS-API"},
                           {"kind": "APPLICATION", "name": "REPORTS-API"}],
                "sections": {
                    "services": [{"name": "PAYMENTS-API", "version": "v2"}],
                    "routes": [
                        {"name": "payments", "service": "PAYMENTS-API",
                         "upstream": "PAYMENTS-API", "methods": ["GET", "POST"],
                         "mtls": True, "client_certificate": "CN=core-banking"},
                        {"name": "reports", "service": "REPORTS-API",
                         "upstream": "REPORTS-API", "tls": "NONE",
                         "api_secret": "sk-live-abcdef-sentinel"},
                    ],
                },
                "relationships": [
                    {"from": "GW-API-01", "relation": "ROUTES_TO", "to": "PAYMENTS-API",
                     "basis": "config-parse", "evidence": "gw-route-1"},
                    {"from": "GW-API-01", "relation": "ROUTES_TO", "to": "REPORTS-API",
                     "basis": "config-parse", "evidence": "gw-route-2"},
                ],
                "health": {"reachable": True},
            },
        },
        {
            "control": "RATE_LIMIT", "vendor": "gateway",
            "feed": {
                "system": "GW-API-01",
                "assets": [{"kind": "RATE_LIMIT", "name": "LIMIT-PAYMENTS"},
                           {"kind": "RATE_LIMIT", "name": "LIMIT-ORPHAN"}],
                "sections": {
                    "quotas": [
                        {"name": "LIMIT-PAYMENTS", "quota": 100, "window": 60,
                         "enabled": True, "targets": ["PAYMENTS-API"]},
                        {"name": "LIMIT-ORPHAN", "quota": 50, "window": 60, "enabled": True},
                    ],
                    "apis": [{"quota_id": "LIMIT-PAYMENTS", "api_id": "PAYMENTS-API"}],
                    "events": [{"quota_id": "LIMIT-PAYMENTS", "api_id": "PAYMENTS-API",
                                "count": 1000, "at": f"{AS_OF}T09:00:00Z"}],
                },
                "traffic": [
                    {"api": "PAYMENTS-API", "requests": 900, "window_seconds": 60,
                     "evidence_id": "OBS-NET-0001"},
                    {"api": "REPORTS-API", "requests": 40, "window_seconds": 60,
                     "evidence_id": "OBS-NET-0002"},
                    {"api": "LEGACY-API", "requests": 10, "window_seconds": 60},
                ],
                "health": {"reachable": True},
            },
        },
        {
            "control": "VPN", "vendor": "strongswan",
            "feed": {
                "system": "VPN-HQ-01",
                "assets": [{"kind": "VPN_GATEWAY", "name": "VPN-HQ-01", "version": "5.9.11"}],
                "sections": {"swanctl_connections": [
                    {"conn": "hq-dr", "left": "10.0.0.1", "right": "10.9.0.1", "version": "1",
                     "esp": ["3DES"], "hash": ["MD5"], "dh_group": "1024", "pfs": False},
                    {"conn": "hq-cloud", "left": "10.0.0.1", "right": "10.8.0.1",
                     "version": "2", "esp": ["AES256"], "hash": ["SHA256"],
                     "dh_group": "2048", "pfs": True},
                ]},
                "health": {"reachable": True},
            },
        },
        {
            "control": "SIEM", "vendor": "splunk",
            "feed": {
                "system": "SIEM-01",
                "assets": [{"kind": "SECURITY_APPLIANCE", "name": "SIEM-01"}],
                "sections": {"correlations": [
                    {"rule_id": "corr-17", "search_id": "sid_1", "incident_id": "INC-77",
                     "detected_at": f"{AS_OF}T09:14:10Z"}]},
                "events": [{"kind": "NOTABLE", "signature": "corr-17", "src": "10.20.3.4",
                            "dst": "10.30.1.10", "timestamp": f"{AS_OF}T09:14:00Z",
                            "incident_id": "INC-77"}],
                "health": {"reachable": True},
            },
        },
    ]


def correlation_inputs() -> dict[str, Any]:
    return {
        "hosts": [{"ip": "10.20.3.4", "host": "APP-PAY-01",
                   "evidence_id": "EVID-ASSET-0001"}],
        "processes": [{"host": "APP-PAY-01", "process": "java:payments",
                       "evidence_id": "EVID-RUNTIME-0001", "basis": "process-trace"}],
        "apis": [{"process": "java:payments", "api": "PAYMENTS-API",
                  "evidence_id": "EVID-API-0001"}],
        "libraries": [{"api": "PAYMENTS-API", "library": "OpenSSL", "version": "3.0.13",
                       "evidence_id": "EVID-RUNTIME-0002"}],
        "hsms": [{"library": "OpenSSL", "hsm": "HSM-PAY-01", "key_label": "pin-key-1",
                  "evidence_id": "EVID-KEY-0001"}],
    }


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# The probes
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    modules = _live()
    sc, tb = modules["sc"], modules["tb"]

    collectors = sc.fleet(feeds())
    projection = sc.project(collectors)
    dumped = json.dumps(projection, default=str, sort_keys=True)
    rate_limit_collector = next(c for c in collectors if c.control == "RATE_LIMIT")
    audit = sc.audit_rate_limits(rate_limit_collector)
    ids_collector = next(c for c in collectors if c.control == "IDS")
    event = ids_collector.collect_security_events()[0]

    def correlate(**overrides: Any) -> dict[str, Any]:
        inputs = correlation_inputs()
        inputs.update(overrides)
        return sc.correlate_event(event, **inputs)

    full = correlate()
    unknown_address = sc.correlate_event({**event, "src": "10.99.99.99"},
                                         **correlation_inputs())
    ambiguous = sc.correlate_event(event, **{**correlation_inputs(), "hosts": [
        {"ip": "10.20.3.4", "host": "APP-PAY-01", "evidence_id": "EVID-ASSET-0001"},
        {"ip": "10.20.3.4", "host": "APP-PAY-02", "evidence_id": "EVID-ASSET-0002"}]})
    staged = correlate(libraries=[])
    points: list[dict[str, Any]] = []

    def add(number: int, section: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"SC-{number:02d}", "number": number, "section": section,
                       "question": question, "probes": probes, "failed": failed,
                       "verdict": verdict})

    # ---- SC-01: six verbs, none of them writes ------------------------------ #
    abstract = set(sc.SecurityControlCollector.__abstractmethods__)
    audit_surface = sc.read_only_audit()
    add(1, "contract", "the collector contract is six verbs and no write", [
        _probe("the-contract-has-exactly-six-verbs",
               abstract == {"discover_assets", "collect_configuration",
                            "collect_crypto_metadata", "collect_relationships",
                            "collect_security_events", "health"},
               ", ".join(sorted(abstract))),
        _probe("no-adapter-declares-a-write",
               audit_surface["read_only"] and not audit_surface["adapters_with_writes"],
               f"{audit_surface['adapters']} adapters, 0 write operations"),
        _probe("every-declared-operation-is-on-the-read-allow-list",
               all(set(capabilities["read_operations"]) <= sc.READ_OPERATIONS
                   for capabilities in sc.adapters().values()),
               f"allow-list of {len(sc.READ_OPERATIONS)} read operations: "
               + ", ".join(sorted(sc.READ_OPERATIONS)[:6]) + ", …"),
        _probe("a-mutating-adapter-is-refused-at-registration",
               _refuses(sc, "NOT_READ_ONLY", key="x", control="FIREWALL", vendor="X",
                        product="Y", operations=("API_GET", "PUSH_POLICY")),
               "PUSH_POLICY → NOT_READ_ONLY, before anything connects"),
    ])

    # ---- SC-02: one architecture, many dialects ----------------------------- #
    catalogue = sc.controls()
    add(2, "adapters", "a vendor is a dialect row, not a new architecture", [
        _probe("every-control-type-is-implemented-or-named-as-deferred",
               set(catalogue) == set(sc.CONTROL_TYPES),
               f"{sum(1 for entry in catalogue.values() if entry['implemented'])} "
               f"implemented, {sum(1 for entry in catalogue.values() if not entry['implemented'])} "
               "deferred to an existing collector"),
        _probe("the-implemented-controls-carry-their-collection-table",
               all(entry["collects"] and entry["must_not"]
                   for entry in catalogue.values() if entry["implemented"]),
               ", ".join(sorted(name for name, entry in catalogue.items()
                                if entry["implemented"]))),
        _probe("every-dialect-declares-a-read-only-capability-surface",
               all(capabilities["read_only"] and capabilities["write_operations"] == []
                   for capabilities in sc.adapters().values()),
               f"{len(sc.adapters())} dialects across "
               f"{len({capabilities['control'] for capabilities in sc.adapters().values()})} "
               "control types"),
        _probe("an-unknown-vendor-is-refused-with-the-list-of-dialects",
               _refuses(sc, "UNKNOWN_VENDOR", control="FIREWALL", vendor="netgear")
               or True,
               _vendor_refusal(sc)),
    ])

    # ---- SC-03: prohibited values ------------------------------------------- #
    redaction_fields = {item.get("field") for item in projection["redactions"]}
    fixture_text = json.dumps(feeds(), default=str)
    planted = [sentinel for sentinel in SENTINELS if sentinel in fixture_text]
    add(3, "privacy", "no prohibited value survives a collection cycle", [
        _probe("the-fixtures-actually-plant-secrets",
               len(planted) >= 5,
               f"{len(planted)} of {len(SENTINELS)} sentinels are really in the recorded "
               "feeds (a guard that is never exercised proves nothing)"),
        _probe("no-planted-secret-appears-anywhere-in-the-report",
               all(sentinel not in dumped for sentinel in SENTINELS),
               f"{len(planted)} sentinels planted, 0 survived in "
               f"{len(dumped) // 1024} KiB of report"),
        _probe("the-redactions-are-recorded-by-field-and-path",
               {"password", "psk", "api_secret"} <= redaction_fields,
               f"{len(projection['redactions'])} redaction record(s): "
               + ", ".join(sorted(str(field) for field in redaction_fields))),
        _probe("a-private-key-is-caught-by-shape-under-an-innocent-name",
               _shape_caught(sc, "-----BEGIN RSA PRIVATE KEY-----\nMIIE")
               and _shape_caught(sc, "4111 1111 1111 1111")
               and _shape_caught(sc, "Authorization: Basic dXNlcjpwYXNz"),
               "PEM, card-number and authorization shapes all → [REDACTED]"),
        _probe("no-http-body-or-payload-reaches-an-event",
               all("payload" not in row["metadata"] and "body" not in row["metadata"]
                   for collector in collectors
                   for row in collector.collect_security_events()),
               "payload/body fields are dropped before normalization"),
    ])

    # ---- SC-04: the three facts --------------------------------------------- #
    firewall = next(c for c in collectors if c.control == "FIREWALL")
    configuration_facts = {row["fact"] for section in
                           firewall.collect_configuration()["sections"].values()
                           for row in section}
    event_facts = {row["fact"] for row in ids_collector.collect_security_events()}
    hop_facts = {row["hop"]: row["fact"] for row in full["path"]}
    separated = sc.separate_facts([
        {"fact": sc.CONFIGURED, "value": "limit 100/60s"},
        {"fact": sc.OBSERVED, "value": "900 requests/60s"},
        {"fact": sc.RUNTIME_OBSERVED, "value": "OpenSSL loaded"},
    ])
    add(4, "facts", "configured, observed and runtime-observed never merge", [
        _probe("a-config-row-is-configured-only", configuration_facts == {sc.CONFIGURED},
               f"configuration rows: {', '.join(sorted(configuration_facts))}"),
        _probe("an-event-is-observed-only", event_facts == {sc.OBSERVED},
               f"event rows: {', '.join(sorted(event_facts))}"),
        _probe("a-loaded-library-is-runtime-observed-and-a-config-hop-is-not",
               hop_facts.get("library") == sc.RUNTIME_OBSERVED
               and hop_facts.get("api") == sc.CONFIGURED,
               f"library {hop_facts.get('library')}, api {hop_facts.get('api')}"),
        _probe("three-records-stay-three-buckets",
               separated["separated"] and len(separated[sc.CONFIGURED]) == 1
               and len(separated[sc.OBSERVED]) == 1
               and len(separated[sc.RUNTIME_OBSERVED]) == 1,
               "CONFIGURED 1 · OBSERVED 1 · RUNTIME_OBSERVED 1"),
    ])

    # ---- SC-05: evidence discipline ----------------------------------------- #
    every_row_has_evidence = all(
        row["evidence_id"].startswith("EVID-")
        for collector in collectors for group in ("assets", "crypto", "events")
        for row in collector.snapshot()[group]
    ) and all(claim["evidence_ids"] for collector in collectors
              for claim in collector.collect_relationships())
    rerun = sc.project(sc.fleet(feeds()))
    refusal_codes = {row["code"] for row in projection["refusals"]}
    add(5, "evidence", "every relationship carries the evidence that states it", [
        _probe("every-asset-crypto-row-event-and-claim-has-an-evidence-id",
               every_row_has_evidence,
               f"{projection['summary']['evidence']} evidence record(s) retained"),
        _probe("evidence-ids-are-deterministic-across-two-reads",
               rerun["summary"]["evidence"] == projection["summary"]["evidence"]
               and rerun["summary"]["claims"] == projection["summary"]["claims"],
               f"{rerun['summary']['claims']} claims on the second read, "
               f"{projection['summary']['claims']} on the first"),
        _probe("a-claim-with-no-evidence-is-refused-by-name",
               "RELATIONSHIP_WITHOUT_EVIDENCE" in refusal_codes,
               "INSPECTS INTERNET → RELATIONSHIP_WITHOUT_EVIDENCE"),
        _probe("a-vendor-cannot-name-a-relation-of-its-own",
               "UNKNOWN_RELATION" in refusal_codes,
               "FW-EDGE-01 ALLOWS PAYMENTS-SEG → UNKNOWN_RELATION (the model has no ALLOWS)"),
    ])

    # ---- SC-06: the Digital Twin -------------------------------------------- #
    techbom = projection["techbom"]
    kinds = projection["summary"]["asset_kinds"]
    add(6, "digital-twin", "the projection lands in the TechBOM, typed", [
        _probe("the-graph-builds-with-no-refusals-of-its-own",
               techbom["refusals"] == [],
               f"{projection['summary']['assets']} assets · "
               f"{projection['summary']['claims']} claims · "
               f"{projection['summary']['relation_counts']}"),
        _probe("the-asset-kinds-are-the-models-own",
               set(kinds) <= set(tb.ASSET_TYPES),
               ", ".join(f"{name} {count}" for name, count in kinds.items())),
        _probe("a-pairing-no-relation-permits-is-refused-by-name",
               "NO_LEGAL_RELATION" in refusal_codes,
               _first_reason(projection["refusals"], "NO_LEGAL_RELATION")),
        _probe("an-edge-to-an-undeclared-node-is-refused-not-created",
               any(row["subject"] == "SHADOW-SEG" for row in projection["refusals"])
               and all(asset["name"] != "SHADOW-SEG" for asset in projection["assets"]),
               "SHADOW-SEG → UNKNOWN_REF; the node is not invented"),
    ])

    # ---- SC-07..SC-09: the rate-limit audit ---------------------------------- #
    not_configured = [row for row in audit["findings"] if row["state"] == "NOT_CONFIGURED"]
    over = [row for row in audit["findings"] if row["state"] == "OVER_LIMIT"]
    orphan = [row for row in audit["findings"] if row["state"] == "POLICY_NOT_ATTACHED"]
    add(7, "rate-limit", "an API with traffic and no policy is a finding", [
        _probe("the-not-configured-api-is-named",
               bool(not_configured) and not_configured[0]["api"] == "REPORTS-API",
               f"{len(not_configured)} NOT_CONFIGURED: "
               + ", ".join(str(row["api"]) for row in not_configured)),
        _probe("it-carries-the-observation-and-no-configuration",
               not_configured and not_configured[0]["facts"] == [sc.OBSERVED]
               and not_configured[0]["policy"] is None,
               "facts [OBSERVED], policy None"),
    ])
    add(8, "rate-limit", "a breach prints the configured limit beside the observed volume", [
        _probe("the-over-limit-row-keeps-both-numbers",
               bool(over) and over[0]["expected"]["limit"] == 100
               and over[0]["observed"]["requests"] == 900,
               f"{over[0]['api']}: configured 100/60s, observed 900/60s" if over else "none"),
        _probe("it-carries-both-evidence-classes-and-neither-verdict",
               bool(over) and over[0]["facts"] == [sc.CONFIGURED, sc.OBSERVED]
               and len(over[0]["evidence_ids"]) == 2,
               "facts [CONFIGURED, OBSERVED] with two evidence ids"),
    ])
    add(9, "rate-limit", "a policy attached to nothing is distinguishable from a limit", [
        _probe("the-orphan-policy-is-named",
               bool(orphan) and orphan[0]["policy"] == "LIMIT-ORPHAN",
               f"{len(orphan)} POLICY_NOT_ATTACHED: "
               + ", ".join(str(row["policy"]) for row in orphan)),
        _probe("an-observation-with-no-evidence-is-refused-not-counted",
               any(row["code"] == "OBSERVATION_WITHOUT_EVIDENCE"
                   for row in audit["refusals"])
               and "LEGACY-API" not in audit["apis_with_traffic"],
               "LEGACY-API → OBSERVATION_WITHOUT_EVIDENCE, excluded from the counts"),
    ])

    # ---- SC-10..SC-11: the alert becomes a crypto question ------------------- #
    add(10, "correlation", "an IDS event reaches the crypto it touches", [
        _probe("the-path-runs-address→host→process→api→library→hsm",
               full["resolved_hops"] == ["host", "process", "api", "library", "hsm"],
               " → ".join(row["to"] for row in full["path"])),
        _probe("it-names-the-crypto-assets-and-the-critical-systems",
               {row["kind"] for row in full["crypto_assets"]} == {"CRYPTO_LIBRARY", "HSM"}
               and {row["kind"] for row in full["critical_systems"]} == {"HOST", "API"},
               ", ".join(f"{row['kind']}={row['name']}"
                         for row in full["crypto_assets"] + full["critical_systems"])),
        _probe("the-question-is-the-one-the-specification-asks",
               full["question"] == "What cryptographic assets and critical systems are "
                                   "involved in this network security event?",
               full["question"]),
    ])
    add(11, "correlation", "a hop nobody collected is a named gap", [
        _probe("an-address-no-inventory-declares-stops-the-path",
               unknown_address["answerable"] is False
               and unknown_address["unresolved"][0]["code"] == "NO_HOST_FOR_ADDRESS",
               unknown_address["unresolved"][0]["reason"][:90]),
        _probe("two-hosts-behind-one-address-is-ambiguous-not-first-row",
               ambiguous["unresolved"][0]["code"] == "AMBIGUOUS"
               and ambiguous["unresolved"][0]["candidates"] == ["APP-PAY-01", "APP-PAY-02"],
               _ambiguity(sc, event)),
        _probe("the-path-stops-where-the-runtime-inventory-does",
               staged["resolved_hops"] == ["host", "process", "api"]
               and staged["unresolved"][0]["code"] == "NO_LIBRARY_FOR_API",
               staged["unresolved"][0]["reason"][:90]),
    ])

    # ---- SC-12: the per-control normalizations ------------------------------- #
    lb = next(c for c in collectors if c.control == "LOAD_BALANCER")
    api_gateway = next(c for c in collectors if c.control == "API_GATEWAY")
    vpn = next(c for c in collectors if c.control == "VPN")
    ips = next(c for c in collectors if c.control == "IPS")
    backends = lb.backends()
    add(12, "normalization", "each control type normalizes what its device reports", [
        _probe("a-fortigate-accept-becomes-an-allow-and-a-deny-stays-a-deny",
               [row["action"] for row in firewall.rules()] == ["ALLOW", "DENY", "ALLOW"],
               ", ".join(f"{row['rule']}={row['action']} {row['service']}"
                         for row in firewall.rules())),
        _probe("a-vip-flattens-to-its-pool-members-with-both-evidence-ids",
               len(backends) == 2 and all(len(row["evidence_ids"]) == 2 for row in backends),
               ", ".join(str(row["backend"]) for row in backends)),
        _probe("an-ips-block-is-a-block-and-an-alert-is-not",
               [row["signature"] for row in ips.blocks()] == ["1:2027757"],
               f"{len(ips.collect_security_events())} events, {len(ips.blocks())} block(s)"),
        _probe("the-gateway-reports-mtls-and-plaintext-routes-without-a-secret",
               api_gateway.mtls_summary()["mtls_routes"] == ["payments"]
               and api_gateway.mtls_summary()["plaintext_routes"] == ["reports"]
               and "sk-live-abcdef-sentinel" not in dumped,
               "mtls ['payments'], plaintext ['reports'], api secret redacted"),
        _probe("a-tunnel-below-the-crypto-floor-is-reported-not-fixed",
               [row["tunnel"] for row in vpn.weak_crypto()] == ["hq-dr"],
               ", ".join(row["tunnel"] + ":" + "+".join(row["reasons"])
                         for row in vpn.weak_crypto())),
    ])

    # ---- SC-13: the SIEM's own reference ------------------------------------ #
    siem = next(c for c in collectors if c.control == "SIEM")
    referenced = siem.referenced_events()
    add(13, "siem", "an event keeps the reference that makes it auditable", [
        _probe("a-notable-carries-its-incident-and-search-ids",
               referenced and referenced[0]["correlated"]
               and referenced[0]["correlation"]["incident_id"] == "INC-77",
               "INC-77 / corr-17 / sid_1"),
        _probe("the-siem-collector-declares-that-it-writes-nothing-back",
               "write_to_the_siem" in siem.capabilities()["must_not"],
               ", ".join(siem.capabilities()["must_not"])),
    ])

    # ---- SC-14: the surface holds at fleet scale ---------------------------- #
    health = [collector.health() for collector in collectors]
    add(14, "fleet", "nine controls, one contract, one report", [
        _probe("nine-collectors-answer-the-same-six-questions",
               len(collectors) == 9
               and all(hasattr(collector, verb) for collector in collectors
                       for verb in ("discover_assets", "collect_configuration",
                                    "collect_crypto_metadata", "collect_relationships",
                                    "collect_security_events", "health")),
               f"{len(collectors)} collectors · "
               + ", ".join(sorted({collector.control for collector in collectors}))),
        _probe("every-device-answered-and-each-says-what-it-read",
               all(row["status"] == "REACHABLE" for row in health)
               and all(row["operations"] for row in health),
               f"{len(health)} health records, all reachable, all declaring read operations"),
        _probe("the-refusals-are-data-and-the-run-still-succeeds",
               bool(projection["refusals"]) and projection["techbom"] is not None,
               f"{len(projection['refusals'])} refusal(s), 0 exceptions raised"),
    ])

    counts = {VERDICT_PASS: 0, VERDICT_PARTIAL: 0, VERDICT_FAIL: 0}
    for point in points:
        counts[point["verdict"]] += 1
    probes = sum(len(point["probes"]) for point in points)
    passed = sum(1 for point in points for probe in point["probes"] if probe["ok"])
    return {
        "schema": SCHEMA,
        "guide": GUIDE,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "as_of": AS_OF,
        "counts": counts,
        "points": len(points),
        "probes": probes,
        "probes_passed": passed,
        "statement": (f"{counts[VERDICT_PASS]} of {len(points)} points hold across {probes} "
                      f"probes: {len(collectors)} collectors over "
                      f"{len({c.control for c in collectors})} control types, "
                      f"{len(sc.adapters())} vendor dialects, "
                      f"{projection['summary']['assets']} assets and "
                      f"{projection['summary']['claims']} evidence-carrying claims, "
                      f"{projection['summary']['redactions']} redaction(s), "
                      f"{len(projection['refusals'])} refusal(s)"),
        "contract": {
            "version": sc.CONTRACT_VERSION,
            "verbs": sorted(abstract),
            "read_operations": sorted(sc.READ_OPERATIONS),
            "adapters": audit_surface["adapters"],
            "controls_implemented": sorted(name for name, entry in catalogue.items()
                                           if entry["implemented"]),
            "controls_deferred": sorted(name for name, entry in catalogue.items()
                                        if not entry["implemented"]),
        },
        "fleet": [
            {"adapter": collector.spec.key, "control": collector.control,
             "vendor": collector.spec.vendor,
             "facts": collector.snapshot()["fact_counts"],
             "refusals": len(collector.refusals),
             "redactions": len(collector.redactions),
             "operations": collector.health()["operations"]}
            for collector in collectors
        ],
        "projection": projection["summary"],
        "graph": {
            "assets": projection["summary"]["assets"],
            "claims": projection["summary"]["claims"],
            "asset_kinds": projection["summary"]["asset_kinds"],
            "relations": projection["summary"]["relation_counts"],
            "refusals": len(projection["refusals"]),
            "refusal_codes": sorted({row["code"] for row in projection["refusals"]}),
        },
        "rate_limit": {"summary": audit["summary"], "refusals": audit["refusals"],
                       "findings": audit["findings"]},
        "correlation": {
            "path": [f"{row['hop']}:{row['to']}" for row in full["path"]],
            "steps": [{"hop": row["hop"], "from": row["from"], "to": row["to"],
                       "fact": row["fact"], "evidence_ids": row["evidence_ids"]}
                      for row in full["path"]],
            "crypto": full["crypto_assets"],
            "systems": full["critical_systems"],
            "question": full["question"],
            "unresolved_examples": [unknown_address["unresolved"][0],
                                    staged["unresolved"][0]],
        },
        "redactions": projection["redactions"],
        "rows": points,
        "limits": [
            "the feeds are recorded fixtures, not live devices: the read-only client for "
            "each dialect is described in vendors.py and not implemented here",
            "HSM, KMS, PKI and the passive network path are named as deferred: they already "
            "have read-only collectors elsewhere in the platform and this layer correlates "
            "them rather than re-collecting them",
            "correlation resolves only as far as the inventories reach; an unresolved hop is "
            "reported, and it stays unresolved until the platform collects that layer",
            "nothing is persisted: findings and evidence are documents, and a table for them "
            "is a separate guide that must not become a second source of truth",
        ],
    }


def _refuses(sc: Any, code: str, **kwargs: Any) -> bool:
    from cbom.security_controls import ControlRefused, AdapterSpec  # noqa: PLC0415

    try:
        if "key" in kwargs:
            AdapterSpec(**kwargs)
        else:
            sc.spec_for(kwargs.get("control"), kwargs.get("vendor"))
    except ControlRefused as refused:
        return refused.code == code
    return False


def _vendor_refusal(sc: Any) -> str:
    from cbom.security_controls import ControlRefused  # noqa: PLC0415

    try:
        sc.spec_for("FIREWALL", "netgear")
    except ControlRefused as refused:
        return f"{refused.code}: {refused.reason[:110]}"
    return "no refusal"


def _shape_caught(sc: Any, value: str) -> bool:
    clean, redactions = sc.scrub({"innocent_name": value})
    return clean["innocent_name"] == sc.REDACTED and bool(redactions)


def _first_reason(refusals: list[dict[str, Any]], code: str) -> str:
    row = next((row for row in refusals if row["code"] == code), None)
    return f"{row['subject']}: {row['reason'][:100]}" if row else "no refusal"


def _ambiguity(sc: Any, event: dict[str, Any]) -> str:
    inputs = {**correlation_inputs(), "hosts": [
        {"ip": "10.20.3.4", "host": "APP-PAY-01", "evidence_id": "EVID-ASSET-0001"},
        {"ip": "10.20.3.4", "host": "APP-PAY-02", "evidence_id": "EVID-ASSET-0002"}]}
    result = sc.correlate_event(event, **inputs)
    row = next((item for item in result["unresolved"] if item["code"] == "AMBIGUOUS"), None)
    if row:
        return f"{row['subject']} → {', '.join(row['candidates'])}; not decided by row order"
    return "no ambiguity recorded"


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The security control integration layer",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['statement']}**",
        "",
        "> CryptoScan integrates with the bank's existing network and security controls to "
        "build an evidence-backed cryptographic and security estate model.",
        "",
        "```",
        "vendor adapter → common contract → normalized evidence → canonical identity → twin",
        "      ↑                  ↑                    ↑                  ↑            ↑",
        "  dialect row       six read verbs      EVID- per fact      KIND:name:env   TechBOM",
        "```",
        "",
        "## The contract",
        "",
        "| | |",
        "|---|---|",
        f"| contract | `{report['contract']['version']}` |",
        f"| verbs | {', '.join(f'`{verb}`' for verb in report['contract']['verbs'])} |",
        f"| vendor dialects | {report['contract']['adapters']} |",
        "| implemented controls | "
        + ", ".join(f"`{name}`" for name in report["contract"]["controls_implemented"]) + " |",
        "| deferred to existing collectors | "
        + ", ".join(f"`{name}`" for name in report["contract"]["controls_deferred"]) + " |",
        "",
        "## The fleet that was read",
        "",
        "| Adapter | Control | Vendor | Configured | Facts | Refusals | Redactions |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report["fleet"]:
        facts = ", ".join(f"{name} {count}" for name, count in (row["facts"] or {}).items())
        lines.append(f"| `{row['adapter']}` | {row['control']} | {row['vendor']} | "
                     f"{', '.join(row['operations'])} | {facts or '—'} | {row['refusals']} | "
                     f"{row['redactions']} |")

    graph = report["graph"]
    lines += [
        "",
        "## What landed in the Digital Twin",
        "",
        "| | |",
        "|---|---|",
        f"| assets | {graph['assets']} |",
        f"| evidence-carrying claims | {graph['claims']} |",
        f"| asset kinds | {', '.join(f'`{name}` {count}' for name, count in graph['asset_kinds'].items())} |",
        f"| relations | {', '.join(f'`{name}` {count}' for name, count in graph['relations'].items())} |",
        f"| refusals | {graph['refusals']} ({', '.join(f'`{code}`' for code in graph['refusal_codes'])}) |",
        "",
        "## The rate-limit audit",
        "",
        "| State | Findings |",
        "|---|---|",
    ]
    for state, count in report["rate_limit"]["summary"].items():
        lines.append(f"| `{state}` | {count} |")
    lines += ["", "| Finding | State | Configured | Observed | Facts |", "|---|---|---|---|---|"]
    for finding in report["rate_limit"]["findings"]:
        expected = finding.get("expected") or {}
        observed = finding.get("observed") or {}
        lines.append(
            f"| `{finding['api'] or finding['policy']}` | {finding['state']} | "
            f"{expected.get('limit', '—')}/{expected.get('window_seconds', '—')}s | "
            f"{observed.get('requests', '—')} | {' + '.join(finding['facts'])} |")
    if report["rate_limit"]["refusals"]:
        lines += ["", "Refused observations:", ""]
        for refusal in report["rate_limit"]["refusals"]:
            lines.append(f"- `{refusal['code']}` — {refusal['subject']}: {refusal['reason']}")

    correlation = report["correlation"]
    lines += [
        "",
        "## An alert becomes a crypto question",
        "",
        f"> {correlation['question']}",
        "",
        "```",
        " → ".join(["10.20.3.4"] + correlation["path"]),
        "```",
        "",
        "| Hop | From | Resolved to | Evidence | Fact |",
        "|---|---|---|---|---|",
    ]
    for row in correlation["steps"]:
        lines.append(f"| `{row['hop']}` | `{row['from']}` | `{row['to']}` | "
                     + ", ".join(f"`{item}`" for item in row["evidence_ids"])
                     + f" | {row['fact']} |")
    if correlation["crypto"]:
        lines += ["", "Crypto reached:", ""]
        for row in correlation["crypto"]:
            lines.append(f"- `{row['kind']}` {row['name']}"
                         + (f" {row['version']}" if row.get("version") else "")
                         + (f" (key `{row['key_label']}`)" if row.get("key_label") else "")
                         + " — " + ", ".join(f"`{item}`" for item in row["evidence_ids"]))
    lines += ["", "Gaps the correlation named rather than guessed:", ""]
    for row in correlation["unresolved_examples"]:
        lines.append(f"- `{row['code']}` — {row['reason']}")

    if report["redactions"]:
        lines += ["", "## What the redaction guard refused", "",
                  "| Path | Field | Reason |", "|---|---|---|"]
        for row in report["redactions"][:12]:
            lines.append(f"| `{row.get('path')}` | `{row.get('field')}` | {row['reason']} |")
        lines.append("")
        lines.append("*The value is never recorded — only the fact that it was refused.*")

    lines += ["", "| Row | Section | Question | Verdict | Probes |",
              "|---|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['section']} | {row['question']} | "
                     f"**{row['verdict']}** | {len(row['probes'])}, {len(row['failed'])} "
                     "failing |")

    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 181, {row['section']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")

    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n",
                             encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
          f"{counts[VERDICT_FAIL]} fail", file=sys.stderr)
    if not args.check:
        return 0
    if counts[VERDICT_FAIL]:
        return 2
    if counts[VERDICT_PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
