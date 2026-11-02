#!/usr/bin/env python3
"""Guide 156 — network asset identity: an address is an attribute, not a name.

Review item 20, in its own words:

    Not `IP:port` — IPs change. Stable identity from asset id, hostname, service
    identity, certificate fingerprint, SNI, interface, device id, collector source,
    environment, location. E.g. `NET-001928`, type `LOAD_BALANCER`, hostname
    `ext-lb-prod-01`, IPs `10.20.1.10`/`10.20.1.11`, cert `CERT-9281`, environment
    `PRODUCTION`, zone `DMZ`.

An inventory keyed on `10.20.1.10:443` rebuilds the estate on every failover: history
is lost, assets are invented, findings are orphaned. This guide gives the NBOM the
identity that survives the address, records address churn as *history on the asset*,
and refuses to name an application from a hostname.
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
SCHEMA = "cryptoscan.nbom-identity-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

LB = {
    "asset_id": "NET-001928", "type": "LOAD_BALANCER", "hostname": "ext-lb-prod-01",
    "ips": ["10.20.1.10", "10.20.1.11"], "environment": "PRODUCTION", "zone": "DMZ",
    "location": "DC1", "certificate": {"fingerprint_sha256": "CERT-9281"},
    "sni": "payments.bank.example", "collector_source": "authorized-scanner",
    "evidence_id": "NET-1", "observed_at": "2026-11-01T00:00:00Z",
}
WAF = {
    "hostname": "ext-waf-prod-01", "type": "WAF", "ips": ["10.20.1.20"],
    "environment": "PRODUCTION", "zone": "DMZ", "collector_source": "cmdb-export",
    "evidence_id": "CMDB-1", "observed_at": "2026-11-01T00:00:00Z",
}
#: The next day: one address moved, the certificate rotated, one asset disappeared.
LB_DAY2 = {**LB, "ips": ["10.20.1.11", "10.20.1.12"],
           "certificate": {"fingerprint_sha256": "CERT-9999"},
           "evidence_id": "NET-9", "observed_at": "2026-11-02T00:00:00Z"}


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import network_assets, network_identity  # noqa: PLC0415

    return {"ni": network_identity, "na": network_assets}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _resolved(modules: dict[str, Any]) -> dict[str, Any]:
    ni, na = modules["ni"], modules["na"]
    hops = [{"from": "Internet", "to": "External LB",
             "endpoint": "payments.bank.example:443", "observed_on": "External LB",
             "tls_version": "1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384",
             "evidence_id": "NET-1"}]
    return ni.resolve(na.assets(hops)["assets"],
                      ni.merge([{**LB, "hostname": "external lb"}])["assets"])


def _unresolved(modules: dict[str, Any]) -> dict[str, Any]:
    ni = modules["ni"]
    return ni.resolve([{"endpoint": "payments.bank.example:443",
                        "algorithm": "AES-256-GCM", "observed_on": "Mystery Box"}],
                      ni.merge([LB])["assets"])


def row_not_an_address(modules: dict[str, Any]) -> dict[str, Any]:
    ni = modules["ni"]
    refused: list[str] = []
    for row in ({"ip": "10.20.1.10", "port": 443},
                {"endpoint": "10.20.1.10:443", "cipher_suite": "TLS_AES_256_GCM_SHA384"}):
        try:
            ni.identity(row)
        except ValueError as exc:
            refused.append(str(exc))
    record = ni.identity(LB)
    derived_a = ni.identity({**WAF, "ips": ["10.20.1.20"]})
    derived_b = ni.identity({**WAF, "ips": ["10.99.99.99"]})
    probes = [
        _probe("an-ip-and-a-port-cannot-create-an-asset",
               len(refused) == 2 and all("IP:port is not an identity" in text
                                         for text in refused),
               refused[0] if refused else "accepted"),
        _probe("the-review-s-example-keeps-every-field-it-names",
               record["asset_id"] == "NET-001928" and record["type"] == "LOAD_BALANCER"
               and record["hostnames"] == ["ext-lb-prod-01"]
               and record["ips"] == ["10.20.1.10", "10.20.1.11"]
               and record["certificates"] == ["CERT-9281"]
               and record["environment"] == "PRODUCTION" and record["zone"] == "DMZ",
               f"{record['asset_id']} · {record['type']} · {record['zone']}"),
        _probe("a-derived-identity-is-deterministic-and-ignores-the-address",
               derived_a["asset_id"] == derived_b["asset_id"]
               and derived_a["asset_id"].startswith("NET-"),
               f"{derived_a['asset_id']} for both addresses"),
        _probe("an-explicit-asset-id-wins-over-a-derived-one",
               record["asset_id_source"] == "EXPLICIT"
               and ni.identity({**LB, "asset_id": "NET-777"})["asset_id"] == "NET-777",
               "the CMDB id is kept, not replaced by a hash"),
        _probe("no-key-material-is-ever-part-of-an-identity",
               record["private_material"] == "NOT_STORED"
               and "PRIVATE" not in json.dumps(record),
               record["private_material"]),
    ]
    return {"id": "not_an_address",
            "question": "is an address an identity, or a property of one?",
            "phase": "review 20", "probes": probes}


def row_one_asset_many_addresses(modules: dict[str, Any]) -> dict[str, Any]:
    ni = modules["ni"]
    before = ni.merge([LB, WAF])
    after = ni.merge([LB_DAY2, WAF])
    body = ni.churn(before, after)
    record = before["assets"][0]
    history = {item["ip"]: item for item in record["ip_history"]}
    probes = [
        _probe("an-address-change-does-not-become-a-new-asset",
               [asset["asset_id"] for asset in before["assets"]]
               == [asset["asset_id"] for asset in after["assets"]],
               ", ".join(asset["asset_id"] for asset in before["assets"])),
        _probe("churn-is-reported-as-attributes-on-the-same-identity",
               body["counts"] == {"CERTIFICATE_CHANGED": 2, "IP_ADDED": 1, "IP_REMOVED": 1}
               and body["identity_stable"] is True,
               body["statement"]),
        _probe("every-address-carries-when-it-was-first-and-last-seen",
               history["10.20.1.10"]["first_seen"] == "2026-11-01T00:00:00Z"
               and history["10.20.1.10"]["last_seen"] == "2026-11-01T00:00:00Z",
               "10.20.1.10 first and last seen 2026-11-01"),
        _probe("two-addresses-at-once-is-a-multi-homed-asset-not-two-assets",
               record["multiple_addresses"] is True and record["ip_count"] == 2,
               f"{record['ip_count']} addresses on one identity"),
        _probe("a-rotation-is-a-change-under-the-asset-not-a-replacement",
               "CERTIFICATE_CHANGED" in body["counts"]
               and body["identity_stable"] is True,
               "the certificate rotated, the asset did not"),
        _probe("the-statement-says-the-addresses-are-attributes",
               "not its identity" in record["statement"], record["statement"]),
    ]
    return {"id": "one_asset_many_addresses",
            "question": "what happens to history when an address moves?",
            "phase": "review 20", "probes": probes}


def row_what_an_identity_is_made_of(modules: dict[str, Any]) -> dict[str, Any]:
    ni = modules["ni"]
    prod = ni.identity(WAF)
    test = ni.identity({**WAF, "environment": "TEST"})
    elsewhere = ni.identity({**WAF, "zone": "CORE", "location": None})
    two_collectors = ni.merge([{**WAF, "collector_source": "authorized-scanner",
                               "evidence_id": "NET-2"},
                              {**WAF, "collector_source": "cmdb-export",
                               "evidence_id": "CMDB-1"}])
    conflict = ni.merge([{**LB, "type": "WAF", "evidence_id": "NET-3"}, LB])
    untyped = ni.merge([{**WAF, "type": None}])
    bad = ""
    try:
        ni.identity({**WAF, "type": "MAINFRAME_THING"})
    except ValueError as exc:
        bad = str(exc)
    probes = [
        _probe("environment-and-zone-are-part-of-the-identity",
               len({prod["asset_id"], test["asset_id"], elsewhere["asset_id"]}) == 3,
               "three contexts, three identities"),
        _probe("the-basis-is-recorded-so-a-reviewer-can-see-the-inference",
               prod["identity_basis"] == ["hostname"] and prod["identity_confidence"]
               == "STRONG",
               " · ".join(prod["identity_basis"])),
        _probe("two-collectors-seeing-one-device-produce-one-asset",
               len(two_collectors["assets"]) == 1
               and two_collectors["assets"][0]["observation_count"] == 2
               and two_collectors["assets"][0]["collector_sources"]
               == ["authorized-scanner", "cmdb-export"],
               two_collectors["statement"]),
        _probe("a-disagreeing-device-type-is-kept-as-a-conflict",
               conflict["assets"][0]["conflicts"][0]["field"] == "type"
               and sorted(conflict["assets"][0]["conflicts"][0]["values"])
               == ["LOAD_BALANCER", "WAF"],
               "both answers survive; neither is silently chosen"),
        _probe("an-unknown-device-class-is-recorded-and-listed",
               untyped["assets"][0]["type"] == "UNKNOWN"
               and untyped["untyped"] == [untyped["assets"][0]["asset_id"]],
               "UNKNOWN is a fact, not a guess"),
        _probe("a-class-outside-the-vocabulary-is-refused",
               "not an asset type this model records" in bad, bad or "accepted"),
        _probe("the-same-observations-in-another-order-give-the-same-inventory",
               ni.merge([LB, WAF])["statement"] == ni.merge([WAF, LB])["statement"],
               "order does not create identity"),
    ]
    return {"id": "what_an_identity_is_made_of",
            "question": "which fields identify a device, and which only describe it?",
            "phase": "review 20", "probes": probes}


def row_interface_is_not_an_application(modules: dict[str, Any]) -> dict[str, Any]:
    ni = modules["ni"]
    assets = ni.merge([LB, WAF])["assets"]
    unlinked = ni.link(assets)
    claim_only = ni.link(assets, {"NET-001928": {"applications": ["Payments API"]}})
    proven = ni.link(assets, {"NET-001928": {"applications": ["Payments API"],
                                             "evidence_id": "CMDB-7",
                                             "source": "CMDB"}})
    probes = [
        _probe("an-asset-with-no-mapping-names-no-application",
               unlinked["links"][0]["applications"] == []
               and unlinked["links"][0]["inference"] == "NOT_PROVEN",
               unlinked["links"][0]["statement"]),
        _probe("a-mapping-without-an-evidence-id-is-a-claim",
               claim_only["links"][0]["inference"] == "NOT_PROVEN"
               and "no evidence id" in claim_only["links"][0]["reason"],
               claim_only["links"][0]["reason"]),
        _probe("a-declared-mapping-with-evidence-is-the-only-proof",
               proven["links"][0]["inference"] == "PROVEN"
               and proven["links"][0]["evidence_id"] == "CMDB-7"
               and proven["links"][0]["source"] == "CMDB",
               proven["links"][0]["statement"]),
        _probe("a-hostname-that-looks-like-an-application-is-still-just-a-hostname",
               ni.link([ni.identity({**WAF, "hostname": "payments-api"})
                        ])["links"][0]["inference"] == "NOT_PROVEN",
               "the name is an entry point until a mapping says otherwise"),
        _probe("the-report-counts-proven-and-unproven-links",
               unlinked["proven"] == 0 and unlinked["unproven"] == 2
               and "2 left as interface facts" in unlinked["statement"],
               unlinked["statement"]),
        _probe("a-hop-asset-is-attached-to-the-device-that-terminated-it",
               _resolved(modules)["unresolved"] == 0
               and _resolved(modules)["resolved"] >= 1
               and _resolved(modules)["rows"][0]["asset_id"] == "NET-001928"
               and _resolved(modules)["rows"][0]["interface_role"] == "LOAD_BALANCER",
               _resolved(modules)["statement"]),
        _probe("an-interface-with-no-record-is-left-unresolved",
               _unresolved(modules)["rows"][0]["resolution"] == "UNRESOLVED"
               and "no inventory record carries" in _unresolved(modules)["rows"][0]["reason"],
               _unresolved(modules)["rows"][0]["reason"]),
    ]
    return {"id": "interface_is_not_an_application",
            "question": "may a load balancer's name be read as the application behind it?",
            "phase": "review 20 / item 8 boundary", "probes": probes}


def row_history_without_rekeying(modules: dict[str, Any]) -> dict[str, Any]:
    ni = modules["ni"]
    day1 = ni.merge([LB, WAF])
    day2 = ni.merge([LB_DAY2, WAF])
    day3 = ni.merge([LB_DAY2])
    first = ni.churn(day1, day2)
    second = ni.churn(day2, day3)
    summary = ni.summary(day1)
    try:
        ni.churn({"assets": []}, day1)
        refused = False
    except ValueError:
        refused = True
    probes = [
        _probe("a-three-run-history-answers-what-moved-without-re-keying",
               first["identity_stable"] is True
               and second["counts"] == {"ASSET_RETIRED": 1},
               second["statement"]),
        _probe("a-disappearance-is-a-question-for-the-owner",
               "indistinguishable" in second["changes"][0]["detail"]
               and second["identity_stable"] is False,
               second["changes"][0]["detail"]),
        _probe("changes-carry-the-evidence-from-both-inventories",
               all(change["evidence_before"] == ["NET-1"]
                   and change["evidence_after"] == ["NET-9"]
                   for change in first["changes"]),
               "NET-1 → NET-9 on every change"),
        _probe("the-summary-counts-addresses-under-identities",
               summary["assets"] == 2 and summary["addresses"] == 3
               and summary["multi_address"] == ["NET-001928"],
               summary["statement"]),
        _probe("the-summary-states-what-an-inventory-cannot-prove",
               any("new asset" in line for line in summary["not_proven"])
               and any("load balancer" in line.lower()
                       for line in summary["not_proven"]),
               f"{len(summary['not_proven'])} stated limit(s)"),
        _probe("a-churn-report-refuses-two-things-that-are-not-inventories",
               refused, "a foreign document is rejected, not diffed"),
    ]
    return {"id": "history_without_rekeying",
            "question": "does the history survive a failover, a rotation and a retirement?",
            "phase": "review 20 / 21 boundary", "probes": probes}


ROWS = (row_not_an_address, row_one_asset_many_addresses,
        row_what_an_identity_is_made_of, row_interface_is_not_an_application,
        row_history_without_rekeying)


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
    ni = modules["ni"]
    before = ni.merge([LB, WAF])
    after = ni.merge([LB_DAY2, WAF])
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "identifiers": list(ni.IDENTIFIERS),
        "asset_types": list(ni.ASSET_TYPES),
        "churn_kinds": list(ni.CHURN_KINDS),
        "inventory": ni.summary(before),
        "churn": ni.churn(before, after),
        "link": ni.link(before["assets"], {"NET-001928": {
            "applications": ["Payments API"], "evidence_id": "CMDB-7",
            "source": "CMDB"}}),
        "rows": rows,
        "limits": [
            "a derived identity is a convenience, not a CMDB record. It is stable for "
            "as long as the hostname, environment and location are, and it says "
            "DERIVED so nobody has to guess which kind of id they are reading",
            "an asset with no observation in a later run is reported as retired *or* "
            "unobserved. Distinguishing those needs the collector's attempted target "
            "list (guide 153), and this module will not guess",
            "two collectors reporting one hostname may be two devices behind one name. "
            "The evidence ids are kept separate and the observation count says how many "
            "times the identity was confirmed, not how many devices exist",
            "an address seen once is recorded with a timestamp; an address is not "
            "tracked to the second, so churn between two runs is reported as added and "
            "removed rather than as a move",
            "device type is whatever the source said, or UNKNOWN. A wrong type in the "
            "CMDB is silently wrong here too, which is why the type participates in a "
            "conflict but never in the identity",
            "linking an asset to an application needs a declared mapping with an "
            "evidence id. Nothing here infers an application from a name, a zone or a "
            "certificate, so an unlinked asset stays an interface fact",
            "a hop asset from guide 148 is attached to an identity by matching the "
            "interface name against a hostname, SNI or service identity. An interface "
            "with no matching record stays UNRESOLVED; the alternative is an asset "
            "invented from a label somebody typed on a diagram",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    inventory = report["inventory"]
    churn = report["churn"]
    lines = [
        "# Network asset identity: an address is an attribute, not a name",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Review item 20: *not* `IP:port`, because IPs change. A stable identity is "
        "assembled from the attributes that survive an address change, and the address "
        "becomes history on that identity.",
        "",
        "```",
        "asset_id → device_id → hostname + environment + location",
        "         → certificate fingerprint → service identity",
        "an address is never part of any step",
        "```",
        "",
        f"{inventory['statement']}",
        "",
        f"{churn['statement']}",
        "",
        "| identity source | what it means |",
        "|---|---|",
        "| `asset_id` | the CMDB's own id: strongest, kept verbatim |",
        "| `device_id` | a device serial or asset tag |",
        "| `hostname` + environment + zone | derived, deterministic, `NET-XXXXXXXXXX` |",
        "| certificate fingerprint | weak: a shared certificate is not a shared device |",
        "| `IP:port` alone | **refused** — an address is where an asset answered |",
        "",
        "| churn kind | reported as |",
        "|---|---|",
        "| `IP_ADDED` / `IP_REMOVED` | an attribute change carrying first/last seen |",
        "| `CERTIFICATE_CHANGED` | a rotation under the asset, not a replacement |",
        "| `HOSTNAME_CHANGED` | an alias added or lost |",
        "| `ASSET_RETIRED` | retired *or* unobserved: a question for the owner |",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* ({row['phase']})", ""]
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
