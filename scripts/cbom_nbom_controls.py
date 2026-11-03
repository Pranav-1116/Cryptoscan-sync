#!/usr/bin/env python3
"""Guide 171 — the controls: IDS, IPS, firewall, rate limits, and what we may send.

The NBOM work answered what the estate *is*. This guide answers what stands in front of
it, and the question is not "is there a control" but "what can that control actually
stop". Six things, each a shape in :mod:`cbom.nbom_graph` and a probe here
(``cryptoscan.cbom-controls-guide/1``):

* **an IDS and an IPS are not the same control.** An IPS is in the path and can drop a
  packet; an IDS sees a copy. The model refuses an IDS that blocks (``IDS_CANNOT_BLOCK``)
  and a tap that claims to (``SENSOR_CANNOT_BLOCK_OFF_PATH``), and reports an IPS deployed
  as a tap (``IPS_NOT_INLINE``) rather than drawing it as prevention;
* **inspection is a property of a route**, not of a device — ``INSPECTED_INLINE``,
  ``TAP_ONLY``, ``NOT_INSPECTED``, ``FAIL_OPEN_INLINE``;
* **a firewall is evaluated, not asserted**: rules in order, first match wins, and the
  answer is ``CONFIGURED`` because a matching rule is not an observed packet;
* **a rate limit is a number and a behaviour**, and it is the behaviour that fails:
  ``LIMIT_FAIL_OPEN``, ``LIMIT_LOG_ONLY``, ``LIMIT_NOT_ENFORCED``, ``NO_LIMIT_RECORDED``;
* **request sending is gated before it is done**: an allowlist that must parse, a budget,
  a concurrency cap, a backoff and a method rule — in that order, because permission comes
  before budget;
* **every decision is evidence**, including the refusals, with a collector and a hash, so
  "we did not probe that segment" is a checkable fact rather than a silence.

The fixture is the bank path again: a WAF, an inline IPS, an API gateway and the payments
application, with a tap that watches the cardholder zone from outside the path and never
sees the route; a firewall whose rule set allows one service and denies by default; and a
limiter configured to reject at 100 rps that is deployed fail-open and observed at 250.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.cbom-controls-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID = "EVID-93001"
EVID_IPS = "EVID-93002"
EVID_IDS = "EVID-93003"
EVID_FW = "EVID-93004"
EVID_RL = "EVID-93005"
NOW = "2026-11-03T08:30:00Z"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES / "shared"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import nbom_graph, techbom  # noqa: PLC0415

    return {"n": nbom_graph, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _row(identifier: str, question: str, phase: str, probes: list[dict[str, Any]]) -> dict:
    return {"id": identifier, "question": question, "phase": phase, "probes": probes}


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The fixture: the bank path, with the controls that stand in front of it
# --------------------------------------------------------------------------- #

def _document(n: Any, t: Any) -> dict[str, Any]:
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID])
    application = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID])
    service = n.service_of(name="payments-api", port=8080, evidence_ids=[EVID])
    auth_application = t.asset("APPLICATION", "Auth API", evidence_ids=[EVID])
    segment = t.asset("NETWORK_SEGMENT", "CARDHOLDER", evidence_ids=[EVID])

    waf = n.endpoint(host="10.10.0.21", port=443, name="waf-01:443",
                     tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                     evidence_ids=[EVID])
    gateway = n.endpoint(host="10.10.0.40", port=8443, name="api-gw-01:8443",
                         tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                         evidence_ids=[EVID])
    payments = n.endpoint(host="10.10.1.5", port=8443, name="payments-api:8443",
                          tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                          evidence_ids=[EVID])
    auth = n.endpoint(host="10.10.1.9", port=9443, name="auth-api:9443",
                      tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                      evidence_ids=[EVID])

    # the IPS is in the path and blocks; the IDS watches the same zone from a tap and can
    # never drop anything, which is the distinction this guide exists for
    ips = n.intrusion_sensor(
        name="ips-01", kind="IPS", mode="INLINE", segments=["CARDHOLDER"],
        endpoints=["payments-api:8443"], forwards_to="api-gw-01:8443", fail_open=False,
        engine="Suricata 7.0", inspection=("HEADERS", "PAYLOAD"),
        evidence_ids=[EVID_IPS], basis="config-parse")
    ids = n.intrusion_sensor(
        name="ids-01", kind="IDS", mode="TAP", segments=["CARDHOLDER"],
        endpoints=["auth-api:9443"], engine="Zeek 6.0", inspection=("HEADERS",),
        evidence_ids=[EVID_IDS], basis="passive-capture")
    ips_dr = n.intrusion_sensor(
        name="ips-dr-01", kind="IPS", mode="TAP", segments=["CARDHOLDER"],
        endpoints=["payments-api:8443"], engine="Suricata 7.0",
        inspection=("HEADERS",), evidence_ids=[EVID_IPS], basis="passive-capture")

    device = n.network_device(kind="FIREWALL", name="fw-01", vendor="Palo Alto",
                              product="PA-5220", model="PA-5220", firmware_version="11.1.3",
                              evidence_ids=[EVID_FW])
    filtered = n.filters(
        firewall_row=device["assets"][0], default_action="DENY", logged=True,
        rules=[{"action": "ALLOW", "direction": "INBOUND", "source": "10.10.0.0/16",
                "destination": "10.10.1.5", "port": 8443, "protocol": "TCP"},
               {"action": "DENY", "direction": "INBOUND", "source": "ANY",
                "destination": "10.10.1.5", "port": 22, "protocol": "TCP"}],
        evidence_ids=[EVID_FW])
    firewall = n.part(filtered, *device["assets"][1:], claims=device["claims"])

    limiter = n.rate_limit(
        name="rl-payments-edge", enforcer_row=waf, limit=100, window_seconds=1,
        scope="CLIENT", burst=20, on_exceed="429", fail_open=True,
        observed={"rate": 250, "rejected": 0, "observed_at": NOW},
        targets=["waf-01:443"], evidence_ids=[EVID_RL])

    hops = n.part(claims=[
        t.claim("waf-01:443", "FORWARDS_TO", "ips-01", basis="load-balancer-config",
                evidence_ids=[EVID], protocol="TCP", port=8443),
        t.claim("ips-01", "FORWARDS_TO", "api-gw-01:8443", basis="config-parse",
                evidence_ids=[EVID_IPS], protocol="TCP", port=8443),
        t.claim("api-gw-01:8443", "FORWARDS_TO", "payments-api:8443",
                basis="api-gateway-config", evidence_ids=[EVID], protocol="TCP", port=8443),
        t.claim("payments-api:8443", "ROUTES_TO", "Payments API", basis="api-gateway-config",
                evidence_ids=[EVID], protocol="TCP", port=8443),
        t.claim("auth-api:9443", "ROUTES_TO", "Auth API", basis="api-gateway-config",
                evidence_ids=[EVID], protocol="TCP", port=9443),
    ])

    doc = n.estate(system, application, service, auth_application, segment, waf, gateway,
                   payments, auth, ips, ids, ips_dr, firewall, limiter, hops,
                   estate_id="bank-controls", environment="PRODUCTION")
    return {"estate": doc, "names": {"waf": "waf-01:443", "ips": "ips-01",
                                     "ids": "ids-01", "dr": "ips-dr-01",
                                     "auth": "auth-api:9443",
                                     "backend": "payments-api:8443"}}


def _build(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fixture = _document(modules["n"], modules["t"])
    return modules["n"].build(fixture["estate"]), fixture


def _policy(modules: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    n = modules["n"]
    settings = {"allowlist": ["10.10.0.0/16", "*.bank.example", "203.0.113.9:443"],
                "max_requests_per_target": 3, "max_concurrency": 2,
                "min_interval_ms": 250, "stop_after_errors": 3}
    settings.update(overrides)
    return n.probe_policy(**settings)


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #

def row_sensors(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, _ = _build(modules)
    sensors = {row["name"]: row for row in bom["sensors"]}
    probes = [
        _probe("an-ids-and-an-ips-are-two-kinds-not-one-appliance",
               {"IDS", "IPS"} <= set(t.ASSET_TYPES),
               "IDS and IPS are asset kinds beside SECURITY_APPLIANCE"),
        _probe("a-sensor-is-in-the-path-or-it-sees-a-copy",
               sensors["ips-01"]["mode"] == "INLINE"
               and sensors["ids-01"]["mode"] == "TAP"
               and sensors["ips-dr-01"]["mode"] == "TAP",
               f"ips-01 {sensors['ips-01']['mode']}, ids-01 {sensors['ids-01']['mode']}, "
               f"ips-dr-01 {sensors['ips-dr-01']['mode']}"),
        _probe("only-a-sensor-that-is-both-an-ips-and-inline-is-blocking",
               sensors["ips-01"]["blocking"] is True
               and sensors["ids-01"]["blocking"] is False
               and sensors["ips-dr-01"]["blocking"] is False,
               "ips-01 blocks; ids-01 and the DR IPS — deployed as a tap — observe"),
        _probe("the-sensors-have-their-own-ids-per-kind",
               sorted(row["id"] for row in bom["assets"] if row["kind"] == "IDS")
               == ["TECH-IDS-001"]
               and sorted(row["id"] for row in bom["assets"] if row["kind"] == "IPS")
               == ["TECH-IPS-001", "TECH-IPS-002"],
               "TECH-IDS-001, TECH-IPS-001 (inline), TECH-IPS-002 (the tap)"),
        _probe("an-ids-that-claims-to-block-is-refused",
               _refused(n.intrusion_sensor, name="ids-x", kind="IDS", mode="INLINE",
                        blocks=True, forwards_to="a:443", evidence_ids=[EVID])
               == "IDS_CANNOT_BLOCK",
               "IDS with blocks=True → IDS_CANNOT_BLOCK"),
        _probe("a-tap-cannot-drop-a-packet-it-never-carried",
               _refused(n.intrusion_sensor, name="ips-x", kind="IPS", mode="TAP",
                        blocks=True, segments=["S"], evidence_ids=[EVID])
               == "SENSOR_CANNOT_BLOCK_OFF_PATH",
               "IPS in TAP mode with blocks=True → SENSOR_CANNOT_BLOCK_OFF_PATH"),
        _probe("an-inline-sensor-with-nothing-behind-it-is-an-outage",
               _refused(n.intrusion_sensor, name="ips-x", kind="IPS", mode="INLINE",
                        segments=["S"], evidence_ids=[EVID])
               == "INLINE_WITHOUT_DOWNSTREAM",
               "inline IPS with no downstream → INLINE_WITHOUT_DOWNSTREAM"),
        _probe("only-an-ips-may-protect-in-the-type-table",
               "IPS" in t.RELATIONS["PROTECTS"]["from"]
               and "IDS" not in t.RELATIONS["PROTECTS"]["from"],
               "PROTECTS starts at IPS, WAF, FIREWALL, SERVICE_MESH — never at IDS"),
    ]
    return _row("sensors", "is an IDS a firewall with a different sticker", "ids, ips",
                probes)


def row_in_path(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, fixture = _build(modules)
    route = n.paths(bom, source="waf-01:443")["routes"][0]
    tap_route = n.paths(bom, source="auth-api:9443")["routes"][0]
    probes = [
        _probe("an-inline-ips-is-a-hop-on-the-route",
               "ips-01" in route["nodes"],
               route["path"]),
        _probe("a-tap-is-not-a-hop-on-any-route",
               "ids-01" not in route["nodes"]
               and "ids-01" not in tap_route["nodes"],
               "ids-01 appears in no path: a tap receives a copy"),
        _probe("inspecting-a-node-is-not-forwarding-to-it",
               "INSPECTS" not in n.PATH_RELATIONS
               and any(claim["relation"] == "INSPECTS"
                       for claim in bom["claims"]),
               "INSPECTS exists as a relation and is deliberately absent from "
               "PATH_RELATIONS"),
        _probe("an-ips-deployed-as-a-tap-is-reported-rather-than-drawn",
               "IPS_NOT_INLINE" in _sensor_codes(n, bom),
               "IPS in TAP mode → IPS_NOT_INLINE"),
    ]
    return _row("in-path", "does traffic actually pass through the control", "ips",
                probes)


def _sensor_codes(n: Any, bom: dict[str, Any]) -> set[str]:
    codes: set[str] = set()
    for name in bom["inspection"]:
        codes.update(row["code"] for row in
                     n.inspection_gap(bom, source=name)["sensor_findings"])
    return codes


def row_inspection(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    payments = n.inspection_gap(bom, source="waf-01:443")
    auth = n.inspection_gap(bom, source="auth-api:9443")
    probes = [
        _probe("a-route-that-crosses-a-blocking-control-is-inspected-inline",
               payments["inspected"] == len(payments["routes"]) >= 1
               and any("INSPECTED_INLINE" in row["codes"] for row in payments["routes"]),
               payments["statement"]),
        _probe("a-route-watched-only-from-a-tap-is-tap-only",
               auth["routes"][0]["codes"] == ["TAP_ONLY"]
               and auth["routes"][0]["tap_only"] == ["ids-01"],
               f"{auth['routes'][0]['path']} → TAP_ONLY via ids-01"),
        _probe("a-route-nothing-sees-says-not-inspected",
               auth["inspected"] == 0,
               f"{len(auth['bypass'])} route(s) cross no blocking control"),
        _probe("a-blocking-control-is-named-on-the-route-it-guards",
               payments["routes"][0]["blocking"] == ["ips-01"],
               f"blocking: {payments['routes'][0]['blocking']}"),
        _probe("an-inline-control-deployed-fail-open-gives-up-its-own-verdict",
               _fail_open_verdict(modules) == ["FAIL_OPEN_INLINE"],
               "inline IPS with fail_open → FAIL_OPEN_INLINE, inspected False"),
    ]
    return _row("inspection", "is inspection a property of the estate or of a route",
                "ips, ids", probes)


def _fail_open_verdict(modules: dict[str, Any]) -> list[str]:
    n = modules["n"]
    front = n.endpoint(host="10.0.0.1", port=443, name="front:443", evidence_ids=[EVID])
    backend = n.endpoint(host="10.0.2.5", port=8443, name="backend:8443",
                         evidence_ids=[EVID])
    sensor = n.intrusion_sensor(name="ips-open", kind="IPS", mode="INLINE",
                                endpoints=["backend:8443"], forwards_to="backend:8443",
                                fail_open=True, evidence_ids=[EVID])
    bom = n.build(n.estate(
        sensor, front, backend,
        modules["t"].asset("APPLICATION", "Payments API", evidence_ids=[EVID]),
        n.part(claims=[
            modules["t"].claim("front:443", "FORWARDS_TO", "ips-open",
                               basis="load-balancer-config", evidence_ids=[EVID],
                               protocol="TCP", port=8443),
            modules["t"].claim("backend:8443", "ROUTES_TO", "Payments API",
                               basis="api-gateway-config", evidence_ids=[EVID],
                               protocol="TCP", port=8443)]),
        estate_id="fail-open"))
    found = n.inspection_gap(bom, source="front:443")
    if found["inspected"]:
        return ["INSPECTED_INLINE"]
    return [code for row in found["routes"] for code in row["codes"]]


def row_firewall(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    allowed = n.filter_verdict(bom, source="10.10.0.9", target="10.10.1.5", port=8443)
    denied = n.filter_verdict(bom, source="10.10.0.9", target="10.10.1.5", port=22)
    unmatched = n.filter_verdict(bom, source="10.10.0.9", target="10.10.1.5", port=8080)
    firewall = next(row for row in bom["assets"] if row["kind"] == "FIREWALL")
    probes = [
        _probe("a-rule-that-matches-is-evaluated-in-order",
               allowed["decision"] == "ALLOW" and allowed["matched_rule"] == 1,
               allowed["statement"]),
        _probe("a-deny-rule-ahead-of-the-default-is-its-own-match",
               denied["decision"] == "DENY" and denied["matched_rule"] == 2,
               denied["statement"]),
        _probe("an-unmatched-flow-falls-to-the-default-action",
               unmatched["decision"] == "DENY" and unmatched["matched_rule"] is None,
               unmatched["statement"]),
        _probe("a-matching-rule-is-configured-and-never-network-observed",
               allowed["confidence"] == "CONFIGURED"
               and "capture" in allowed["not_proven"][0],
               "CONFIGURED, and the caveat — only a capture says what happened — travels "
               "with the answer"),
        _probe("a-rule-that-names-no-service-is-refused",
               _refused(n.filters, firewall_row=firewall,
                        rules=[{"action": "ALLOW", "destination": "10.10.1.5"}])
               == "RULE_WITHOUT_SERVICE",
               "a rule with no port → RULE_WITHOUT_SERVICE"),
        _probe("a-firewall-carries-its-vendor-chain-like-any-other-device",
               any(claim["relation"] == "HAS_MODEL" and claim["from"] == "fw-01"
                   for claim in bom["claims"]),
               "fw-01 HAS_MODEL Palo Alto PA-5220, SUPPLIED_BY Palo Alto"),
    ]
    return _row("firewall", "is a rule set evaluated or asserted", "firewall", probes)


def row_rate_limit(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    policy = next(row for row in bom["assets"] if row["kind"] == "RATE_LIMIT")
    attributes = policy["attributes"]
    relations = {claim["relation"] for claim in bom["claims"]
                 if claim["from"] == "rl-payments-edge"
                 or claim["to"] == "rl-payments-edge"}
    probes = [
        _probe("a-limit-is-a-number-a-window-and-a-scope",
               attributes["limit"] == 100 and attributes["window_seconds"] == 1
               and attributes["scope"] == "CLIENT",
               f"100 per {attributes['window_seconds']}s per {attributes['scope']}"),
        _probe("the-behaviour-at-the-edge-is-part-of-the-policy",
               attributes["on_exceed"] == "REJECT" and attributes["fail_open"] is True,
               "429 by configuration, pass-through when the limiter fails"),
        _probe("a-policy-is-joined-to-the-device-that-enforces-it",
               "ENFORCES" in relations and "LIMITS" in relations,
               "waf-01:443 ENFORCES rl-payments-edge, rl-payments-edge LIMITS waf-01:443"),
        _probe("a-limit-of-zero-or-a-window-of-zero-is-refused",
               _refused(n.rate_limit, name="rl", enforcer_row={"name": "waf"},
                        limit=0, evidence_ids=[EVID]) == "INVALID_RATE_LIMIT",
               "0 per 1s → INVALID_RATE_LIMIT"),
        _probe("a-scope-nobody-has-is-refused",
               _refused(n.rate_limit, name="rl", enforcer_row={"name": "waf"},
                        limit=10, scope="EVERYONE", evidence_ids=[EVID])
               == "UNKNOWN_RATE_SCOPE",
               "EVERYONE → UNKNOWN_RATE_SCOPE"),
        _probe("the-policy-is-a-node-with-its-own-id",
               policy["id"].startswith("TECH-RL-"), f"{policy['id']}"),
    ]
    return _row("rate-limit", "is a limit a policy or a paragraph", "ratelimit", probes)


def row_rate_limit_gap(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    findings = bom["rate_limits"]["findings"]
    codes = {row["code"] for row in findings}
    not_enforced = next(row for row in findings if row["code"] == "LIMIT_NOT_ENFORCED")
    probes = [
        _probe("a-limiter-deployed-fail-open-passes-what-it-was-meant-to-stop",
               "LIMIT_FAIL_OPEN" in codes,
               "fail_open=True → LIMIT_FAIL_OPEN"),
        _probe("traffic-above-the-limit-with-no-refusal-is-not-enforcement",
               not_enforced["observed_rate"] == 250 and not_enforced["limit"] == 100,
               "250 rps observed, limit 100, 0 refused → LIMIT_NOT_ENFORCED"),
        _probe("an-endpoint-behind-a-device-with-no-limit-read-is-a-finding",
               "NO_LIMIT_RECORDED" in codes,
               "NO_LIMIT_RECORDED on the endpoints behind a device"),
        _probe("a-limit-that-did-refuse-is-not-a-finding",
               _enforced_verdict(n) is False,
               "250 rps observed, 150 refused → no LIMIT_NOT_ENFORCED"),
        _probe("the-answer-carries-its-evidence-class",
               "CONFIGURED" in bom["rate_limits"]["not_proven"][0],
               bom["rate_limits"]["statement"]),
    ]
    return _row("rate-limit-gap", "does one healthy segment hide one sick one",
                "ratelimit", probes)


def _enforced_verdict(n: Any) -> bool:
    front = n.endpoint(host="10.0.0.1", port=443, name="front:443", evidence_ids=[EVID])
    limiter = n.rate_limit(name="rl", enforcer_row=front, limit=100,
                           observed={"rate": 250, "rejected": 150},
                           targets=["front:443"], evidence_ids=[EVID])
    bom = n.build(n.estate(limiter, front, estate_id="enforced"))
    return "LIMIT_NOT_ENFORCED" in {row["code"] for row in bom["rate_limits"]["findings"]}


def row_probe_gate(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    policy = _policy(modules)
    probes = [
        _probe("an-allowlist-is-a-list-of-ranges-names-and-addresses",
               [row["kind"] for row in policy["allowlist"]] == ["CIDR", "SUFFIX", "HOST"],
               "10.10.0.0/16 (CIDR), *.bank.example (SUFFIX), 203.0.113.9:443 (HOST)"),
        _probe("a-probe-with-no-allowlist-is-a-scan-of-the-internet",
               _refused(n.probe_policy, allowlist=[]) == "EMPTY_ALLOWLIST",
               "[] → EMPTY_ALLOWLIST"),
        _probe("an-allowlist-entry-that-does-not-parse-is-refused",
               _refused(n.probe_policy, allowlist=["10.0.0.0/999"]) == "ALLOWLIST_INVALID",
               "10.0.0.0/999 → ALLOWLIST_INVALID"),
        _probe("permission-is-decided-before-budget",
               n.probe_gate(policy, target="198.51.100.7:443",
                            sent=99)["code"] == "TARGET_NOT_ALLOWED",
               "an exhausted budget never turns an off-list target into an allowed one"),
        _probe("a-method-that-can-change-state-is-refused",
               n.probe_gate(policy, target="10.10.1.5:8443",
                            method="POST")["code"] == "METHOD_NOT_SAFE",
               "POST → METHOD_NOT_SAFE"),
        _probe("a-cidr-entry-admits-an-address-and-a-suffix-admits-a-name",
               n.probe_gate(policy, target="10.10.1.5:8443")["code"] == "SEND"
               and n.probe_gate(policy, target="auth.bank.example:9443")["code"] == "SEND",
               "10.10.1.5 in 10.10.0.0/16; auth.bank.example under *.bank.example"),
        _probe("the-budget-the-concurrency-and-the-backoff-each-stop-a-scan",
               [n.probe_gate(policy, target="10.10.1.5:8443", **kw)["code"] for kw in
                ({"sent": 3}, {"in_flight": 2}, {"recent_errors": 3})]
               == ["BUDGET_EXHAUSTED", "CONCURRENCY_EXHAUSTED", "BACKOFF_REQUIRED"],
               "budget → concurrency → backoff, each with its own code"),
        _probe("the-interval-between-requests-is-enforced-not-assumed",
               n.probe_gate(policy, target="10.10.1.5:8443", last_sent_at=10.0,
                            now=10.1)["code"] == "INTERVAL_NOT_ELAPSED",
               "100ms since the last request, floor 250ms → INTERVAL_NOT_ELAPSED"),
        _probe("a-dry-run-decides-and-sends-nothing",
               n.probe_gate(_policy(modules, dry_run=True),
                            target="10.10.1.5:8443")["code"] == "DRY_RUN",
               "dry_run=True → DRY_RUN"),
    ]
    return _row("probe-gate", "is a request sent or is it decided", "request sending",
                probes)


def row_probe_ledger(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    policy = _policy(modules)
    decisions = [
        n.probe_gate(policy, target="10.10.1.5:8443"),
        n.probe_gate(policy, target="198.51.100.7:443"),
        n.probe_gate(policy, target="10.10.1.5:22", method="POST"),
    ]
    ledger = n.probe_ledger(decisions, observed_at=NOW)
    sent, off_list, unsafe = ledger["records"]
    probes = [
        _probe("every-decision-becomes-a-record-including-the-refusals",
               len(ledger["records"]) == 3 and ledger["sent"] == 1
               and ledger["refused"] == 2,
               ledger["statement"]),
        _probe("a-sent-request-is-observed-and-a-refusal-is-configured",
               sent["evidence_type"] == "NETWORK_OBSERVED"
               and off_list["evidence_type"] == "CONFIGURED",
               "SEND → NETWORK_OBSERVED, refusal → CONFIGURED"),
        _probe("each-record-names-its-collector-and-carries-a-hash",
               all(row["collector"] == "probe-gate"
                   and str(row["hash"]).startswith("sha256:") for row in ledger["records"]),
               f"{len(ledger['records'])} record(s), collector probe-gate, sha256 each"),
        _probe("a-decision-with-no-collector-or-no-hash-is-refused",
               _refused(n.evidence_record, "EVID-X", collector="")
               == "EVIDENCE_WITHOUT_COLLECTOR"
               and _refused(n.evidence_record, "EVID-X", collector="c")
               == "EVIDENCE_WITHOUT_HASH",
               "EVIDENCE_WITHOUT_COLLECTOR / EVIDENCE_WITHOUT_HASH"),
        _probe("we-did-not-probe-that-segment-is-a-checkable-fact",
               off_list["normalized_fact"].startswith("TARGET_NOT_ALLOWED"),
               off_list["normalized_fact"]),
    ]
    return _row("probe-ledger", "is a request not sent a silence or a record",
                "request sending", probes)


def row_vocabulary(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, _ = _build(modules)
    probes = [
        _probe("the-three-control-relations-exist-in-the-one-graph",
               {"INSPECTS", "ENFORCES", "LIMITS"} <= set(t.RELATIONS),
               "INSPECTS, ENFORCES, LIMITS"),
        _probe("the-three-control-kinds-are-asset-types-with-prefixes",
               {"IDS", "IPS", "RATE_LIMIT"} <= set(t.ASSET_TYPES)
               and all(kind in t.PREFIX for kind in ("IDS", "IPS", "RATE_LIMIT")),
               "IDS, IPS, RATE_LIMIT"),
        _probe("a-control-is-a-level-in-the-chain-the-review-draws",
               "control" in bom["chains"]["waf-01:443"]["levels"]
               and bom["chains"]["waf-01:443"]["levels"]["control"],
               bom["chains"]["waf-01:443"]["statement"]),
        _probe("the-projection-reports-the-controls-it-holds",
               {row["kind"] for row in bom["sensors"]} == {"IDS", "IPS"}
               and bom["rate_limits"]["counts"].get("LIMIT_FAIL_OPEN") == 1,
               f"{len(bom['sensors'])} sensor(s), {len(bom['inspection'])} inspected route "
               "view(s)"),
        _probe("nothing-in-this-guide-needed-a-new-projection",
               bom["schema"] == n.SCHEMA and bom["source_of_truth"] == "CANONICAL_ESTATE",
               f"{bom['schema']} from {bom['source_of_truth']}"),
    ]
    return _row("vocabulary", "does the graph carry the controls it reports",
                "vocabulary", probes)


ROWS = (row_sensors, row_in_path, row_inspection, row_firewall, row_rate_limit,
        row_rate_limit_gap, row_probe_gate, row_probe_ledger, row_vocabulary)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = VERDICT_PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = VERDICT_PARTIAL
        else:
            verdict = VERDICT_FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    bom, _ = _build(modules)
    n = modules["n"]
    inspection = n.inspection_gap(bom, source="waf-01:443")
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "statement": bom["statement"],
        "sensors": bom["sensors"],
        "inspection": {"statement": inspection["statement"],
                       "codes": inspection["codes"],
                       "routes": [{"path": row["path"], "codes": row["codes"],
                                   "blocking": row["blocking"],
                                   "tap_only": row["tap_only"]}
                                  for row in inspection["routes"]],
                       "sensor_findings": inspection["sensor_findings"]},
        "firewall": {
            "allowed": n.filter_verdict(bom, source="10.10.0.9", target="10.10.1.5",
                                        port=8443),
            "default": n.filter_verdict(bom, source="10.10.0.9", target="10.10.1.5",
                                        port=8080),
        },
        "rate_limits": bom["rate_limits"],
        "by_code": bom["rate_limits"]["counts"],
        "refusals": bom["refusals"],
        "rows": rows,
        "limits": [
            "the fixture is the bank's own path: the shapes are real, the rows are not",
            "an inline control is where the traffic goes, not a rule that fired: a rule "
            "that matches is CONFIGURED and only a capture or a probe is NETWORK_OBSERVED",
            "a tap is evidenced against a node, so TAP_ONLY says the sensor watches a node "
            "on the route — not that it captured this request",
            "a rate-limit finding compares what was configured with one observation; a "
            "limiter that failed over after this capture is not in it",
            "the probe gate is a decision engine: it records what would be sent, and the "
            "socket lives outside this module so the check cannot be skipped by a caller "
            "that forgets it",
            "an allowlist that parses is not an authorisation: the signed scope for a scan "
            "is a contract with the bank, and this module only enforces the list it is "
            "given",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The controls in front of the estate",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "The NBOM answered what the estate is. This is what stands in front of it, and",
        "the question is not whether a control exists but what it can stop. An IPS in the",
        "path can drop a packet; an IDS on a tap can only say what it saw. A firewall rule",
        "that matches is a policy, not a packet. A rate limit is a number and a",
        "behaviour, and it is the behaviour that fails. A request the platform did not",
        "send is recorded with a collector and a hash, so silence is not mistaken for",
        "coverage.",
        "",
        "```",
        "ids      an IDS alerts, an IPS blocks — two kinds, two ids, one graph",
        "ips      inline is a hop on the route; a tap is a copy beside it",
        "inspect  INSPECTED_INLINE / TAP_ONLY / NOT_INSPECTED / FAIL_OPEN_INLINE",
        "firewall rules in order, first match wins, default action decides the rest",
        "limit    limit + window + scope + on_exceed + fail_open, as one policy node",
        "probe    allowlist → method → budget → concurrency → backoff → interval",
        "```",
        "",
        report["statement"],
        "",
        "## The sensors",
        "",
        "| sensor | kind | mode | inspects | blocks | fail-open |",
        "|---|---|---|---|---|---|",
    ]
    for row in report["sensors"]:
        lines.append(f"| {row['name']} | `{row['kind']}` | {row['mode']} | "
                     f"{', '.join(row['inspects']) or '—'} | "
                     f"{'yes' if row['blocking'] else 'no'} | "
                     f"{'yes' if row['fail_open'] else 'no'} |")
    inspection = report["inspection"]
    lines += ["", "## Inspection, per route", "", f"**{inspection['statement']}**", "",
              "| route | verdict | blocking | tap-only |", "|---|---|---|---|"]
    for row in inspection["routes"]:
        lines.append(f"| {row['path']} | {', '.join(row['codes'])} | "
                     f"{', '.join(row['blocking']) or '—'} | "
                     f"{', '.join(row['tap_only']) or '—'} |")
    if inspection["sensor_findings"]:
        lines += ["", "**Sensor findings**", ""]
        for row in inspection["sensor_findings"]:
            lines.append(f"- `{row['code']}` on {row['sensor']} — {row['reason']}")
    firewall = report["firewall"]
    lines += ["", "## The firewall", "",
              f"- **allowed** — {firewall['allowed'].get('statement', 'not evaluated')}",
              f"- **default** — {firewall['default'].get('statement', 'not evaluated')}",
              "", "## Rate limits", ""]
    limits = report["rate_limits"]
    lines.append(f"**{limits['statement']}**")
    lines.append("")
    for row in limits["findings"]:
        target = row.get("policy") or row.get("endpoint")
        lines.append(f"- `{row['code']}` — {target}: {row['reason']}")
    lines += ["", "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 171, {row['phase']})", ""]
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
