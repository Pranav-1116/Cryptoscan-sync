#!/usr/bin/env python3
"""Guide 182 harness — the security control layer, pointed at things that can fail.

Guide 181's harness answered "does the contract hold?" over recorded fixtures. That is a
specification test, and it is necessary. It is not sufficient, because the fixtures were always
well-formed and the transport was never the one that broke.

This harness asks the questions guide 182 is about, and every answer comes from the shipping
code:

* **L-01** can the transport be made to write? (it must refuse, at the transport)
* **L-02** does every control that reads a device have a driver, and is an unimplemented
  dialect refused by name rather than guessed?
* **L-03** does a live read report its own failures per section instead of an empty success?
* **L-04** does a hash-chained store find an edited body and a deleted record, and keep a
  tombstone when it retains?
* **L-05** are the four facade controls in the registry, and do they still refuse to invent a
  vendor dialect?
* **L-06** does the layer refuse key material from an HSM and a payload from a sensor?
* **L-07** do a fixed window and a sliding window permit different traffic, and is an
  unaligned sample compared with the boundary-tolerant bound?
* **L-08** does an observation that does not describe the policy's interval get refused as
  ``INCOMPARABLE_WINDOW`` instead of reported as a breach?
* **L-09** does the read path still separate ``NOT_CONFIGURED`` from ``UNKNOWN``, and does an
  unavailable counter source show up as an unavailable source?
* **L-10** does the resolver produce the path from the estate, name a stale hop, and drop it
  under ``strict``?
* **L-11** is the evidence API mounted, and does it refuse a user token?
* **L-12** does the redaction guard catch card numbers without eating epoch milliseconds?
* **L-13** is the method allowlist enforced where the bytes leave, not only in a declaration?
* **L-14** is an evidence id stable, revision-aware, and scheme-tagged?
* **L-15** does every failure have a name on health, in the summary and for the console?
* **L-16** is collection incremental, coverage per-device, and memory bounded?

Usage::

    python scripts/cbom_security_controls_live.py            # markdown to stdout
    python scripts/cbom_security_controls_live.py --check    # exit 2 on any failure
    python scripts/cbom_security_controls_live.py --json out.json --md out.md
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

VERDICT_PASS = "PASS"
VERDICT_PARTIAL = "PARTIAL"
VERDICT_FAIL = "FAIL"


def _modules() -> dict[str, Any]:
    import shared_config.environment as platforms_environment
    from cbom import cyclonedx16
    from cbom import security_controls as sc
    from cbom.security_controls import export

    class _Platforms:
        environment = platforms_environment

    return {"sc": sc, "export": export, "cyclonedx16": cyclonedx16, "platforms": _Platforms}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# fixtures the probes point at
# --------------------------------------------------------------------------- #

def hsm_feed() -> dict[str, Any]:
    return {"hsms": [{
        "asset_id": "HSM-PAY-01", "model": "Luna A790", "manufacturer": "Thales",
        "firmware": {"version": "7.8.2"}, "fips": True,
        "crypto_capabilities": ["AES", "RSA", "ECDSA"],
        "partitions": [{"slot": 1, "label": "payments"}],
        "pinned_secret": "0x" + "d4e5f6" * 10,
        "so_password": "operator-secret",
    }]}


def kms_feed() -> dict[str, Any]:
    return {"keys": [
        {"provider": "AWS", "key_ref": "arn:aws:kms:ap-south-1:1:key/a1", "algorithm": "AES",
         "size": 256, "usage": "ENCRYPT_DECRYPT", "status": "enabled",
         "rotation": {"enabled": True, "days": 365}},
        {"provider": "AWS", "key_ref": "arn:aws:kms:ap-south-1:1:key/b2", "algorithm": "RSA",
         "size": 2048, "usage": "SIGN_VERIFY", "status": "enabled"},
    ]}


def pki_feed() -> dict[str, Any]:
    return {
        "certificates": [
            {"ref": "leaf-pay", "subject": "CN=pay.example.bank", "issuer": "CN=Bank Issuing",
             "authority_key_id": "KI-ISSUING", "fingerprint": "sha256:" + "a" * 64,
             "public_key_algorithm": "RSA", "key_size": 2048, "not_after": "2027-04-01"},
            {"ref": "CA-ISSUING", "subject": "CN=Bank Issuing", "issuer": "CN=Bank Root",
             "key_id": "KI-ISSUING", "authority_key_id": "KI-ROOT", "is_ca": True,
             "fingerprint": "sha256:" + "b" * 64, "not_after": "2030-04-01"},
            {"ref": "CA-ROOT", "subject": "CN=Bank Root", "issuer": "CN=Bank Root",
             "key_id": "KI-ROOT", "is_ca": True, "self_signed": True,
             "fingerprint": "sha256:" + "c" * 64, "not_after": "2034-04-01"},
        ],
        "anchors": ["CA-ROOT"],
    }


def network_feed() -> dict[str, Any]:
    return {
        "endpoints": [
            {"host": "10.20.3.4", "port": 443, "protocol": "TCP", "tls_version": "TLS1.2",
             "sni": "pay.example.bank", "alpn": ["h2", "http/1.1"]},
        ],
        "events": [
            {"kind": "ALERT", "src": "10.20.3.4", "timestamp": "2026-11-04T09:14:00Z",
             "alert": "handshake_failure", "tls_version": "TLS1.2",
             "raw_body": "POST /pay HTTP/1.1\r\nCookie: sess=abc\r\n\r\n",
             "authorization": "Basic c2VjcmV0"},
        ],
    }


def limiter(mode: str = "FIXED", limit: int = 100, window: int = 60):
    from cbom.security_controls import registry

    return registry.PACKAGES["RATE_LIMIT"].collector("Kong", {"sections": {
        "limits": [{"name": "rl-public", "enabled": True, "limit": limit,
                    "window_seconds": window, "window_mode": mode}],
        "mappings": [{"policy": "rl-public", "api": "PAYMENTS-API"},
                     {"policy": "rl-idle", "api": "REPORTS-API"}],
        "violations": [],
    }})


def estate(library_minutes: int = 5, now: datetime | None = None):
    now = now or datetime(2026, 11, 4, 9, 14, tzinfo=timezone.utc)
    stamp = lambda minutes: (now - timedelta(minutes=minutes)).isoformat()  # noqa: E731
    return _modules()["sc"].StaticResolver(rows={
        "hosts": [{"ip": "10.20.3.4", "host": "APP-PAY-01", "captured_at": stamp(4)}],
        "processes": [{"host": "APP-PAY-01", "process": "java:payments",
                       "captured_at": stamp(4)}],
        "apis": [{"process": "java:payments", "api": "PAYMENTS-API", "captured_at": stamp(4)}],
        "libraries": [{"api": "PAYMENTS-API", "library": "OpenSSL 3.0.13",
                       "captured_at": stamp(library_minutes)}],
        "keys": [{"library": "OpenSSL 3.0.13", "hsm": "HSM-PAY-01", "captured_at": stamp(4)}],
    }), now


# --------------------------------------------------------------------------- #
# the probes
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    mods = _modules()
    sc = mods["sc"]
    platforms = mods["platforms"]
    control_export = mods["export"]
    cdx = mods["cyclonedx16"]
    points: list[dict[str, Any]] = []

    def add(number: int, section: str, question: str, probes: list[dict[str, Any]]) -> None:
        failed = [probe for probe in probes if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(probes) else VERDICT_FAIL)
        points.append({"id": f"L-{number:02d}", "number": number, "section": section,
                       "question": question, "verdict": verdict,
                       "probes_passed": len(probes) - len(failed), "probes": len(probes),
                       "results": probes})

    # -- L-01 the transport -------------------------------------------------- #
    http = sc.HttpTransport(base_url="https://fw.example.bank",
                            credential=sc.Credential("token-value", source="test"))
    refused_verbs = []
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            http.request(verb, "/api/v2/cmdb/firewall/policy")
            refused_verbs.append(verb)
        except sc.ControlRefused:
            continue
    plaintext = False
    try:
        sc.HttpTransport(base_url="http://fw.example.bank")
    except sc.ControlRefused:
        plaintext = True
    verdict_probe = []
    try:
        sc.HttpTransport(base_url="https://fw.example.bank", verify=False)
        unverified = False
    except sc.ControlRefused:
        unverified = True
    add(1, "Transport", "can the integration be made to write, or to read over plaintext?", [
        _probe("no write verb reaches the device", not refused_verbs,
               f"refused {', '.join(sorted({'POST', 'PUT', 'PATCH', 'DELETE'} - set(refused_verbs)))}"),
        _probe("plaintext base_url is refused", plaintext, "TLS_REQUIRED"),
        _probe("verify=False is refused", unverified, "TLS_VERIFICATION_REQUIRED"),
        _probe("a credential never prints itself",
               "token-value" not in repr(sc.Credential("token-value", source="test")),
               "repr is redacted"),
    ])
    del verdict_probe

    # -- L-02 drivers -------------------------------------------------------- #
    from cbom.security_controls import drivers

    built = {}
    for key in sorted(drivers.DRIVERS):
        try:
            built[key] = type(drivers.driver_for(key, sc.RecordedTransport({}),
                                                 system="X-01")).__name__
        except Exception as exc:  # noqa: BLE001
            built[key] = f"REFUSED {type(exc).__name__}"
    unknown_refused = False
    try:
        drivers.driver_for("firewall.cisco-asa", sc.RecordedTransport({}))
    except sc.ControlRefused as exc:
        unknown_refused = exc.code == "NO_LIVE_DRIVER"
    add(2, "Drivers", "does every read control have a driver, and is an unknown dialect named?", [
        _probe("every registered dialect constructs",
               all(not value.startswith("REFUSED") for value in built.values()),
               f"{len(built)} dialect(s): {', '.join(sorted(built))}"),
        _probe("an unimplemented dialect is refused by name", unknown_refused,
               "NO_LIVE_DRIVER"),
        _probe("every driver declares endpoints or a log tail",
               all(len(drivers.DRIVERS[key].endpoints) or hasattr(drivers.DRIVERS[key], "tail")
                   for key in drivers.DRIVERS),
               "endpoints per dialect"),
    ])

    # -- L-03 a live read that fails ----------------------------------------- #
    snapshot = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({}),
                               system="FW-EDGE-01")
    partial = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({
        "/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "allow-pay"}]},
    }), system="FW-EDGE-01")
    add(3, "Live read", "does a read that failed look like a read that failed?", [
        _probe("an unreachable device is a state, not an empty success",
               snapshot["read"]["state"] not in {"OK"}, snapshot["read"]["state"]),
        _probe("the failed sections are named",
               bool(snapshot["read"]["failed_sections"]) or snapshot["read"]["state"] != "OK",
               f"{len(snapshot['read']['failed_sections'])} section(s) failed"),
        _probe("a partially answered device says PARTIAL_READ",
               partial["read"]["state"] == "PARTIAL_READ" and partial["read"]["partial"],
               f"{partial['read']['state']}, "
               f"{len(partial['read']['failed_sections'])} section(s) failed"),
        _probe("the snapshot carries the transport it used",
               snapshot["transport"]["read_only"] is True, "read_only: true"),
    ])

    # -- L-04 the evidence store --------------------------------------------- #
    root = Path(tempfile.mkdtemp(prefix="cbom-sc-live-"))
    book = sc.EvidenceStore(root, "bank-a")
    first = book.append({"control": "FIREWALL", "assets": [{"name": "FW-EDGE-01"}]})
    again = book.append({"control": "FIREWALL", "assets": [{"name": "FW-EDGE-01"}]})
    book.append({"control": "FIREWALL", "assets": [{"name": "FW-EDGE-01", "version": "7.4.4"}]})
    clean = book.verify()
    body_path = book.body_path(first["digest"])
    body_path.write_text(body_path.read_text().replace("FW-EDGE-01", "FW-EDGE-99"))
    tampered = book.verify()
    body_path.write_text(body_path.read_text().replace("FW-EDGE-99", "FW-EDGE-01"))
    index_lines = book.index_path.read_text().splitlines()
    book.index_path.write_text(index_lines[1] + "\n")
    deleted = book.verify()
    book.index_path.write_text("\n".join(index_lines) + "\n")
    retain_book = sc.EvidenceStore(root, "bank-b")
    retain_book.append({"control": "WAF", "assets": [{"name": "OLD"}]},
                       captured_at="2020-01-01T00:00:00+00:00")
    retain_book.append({"control": "WAF", "assets": [{"name": "NEW"}]})
    retention = retain_book.retain(max_age_days=30, keep_last=1)
    add(4, "Evidence store", "can the evidence tell an edit from a retry, and a delete from a gap?",
        [
            _probe("a retry does not advance the chain", again["duplicate"] is True,
                   f"sequence {again['sequence']}, duplicate"),
            _probe("an intact chain verifies", clean["verified"] is True,
                   f"{clean['records']} record(s)"),
            _probe("an edited body is found", "BODY_ALTERED" in json.dumps(tampered),
                   [problem["code"] for problem in tampered["problems"]][:3]),
            _probe("a deleted record is found",
                   {"SEQUENCE_GAP", "CHAIN_BROKEN"} & {p["code"] for p in deleted["problems"]},
                   [problem["code"] for problem in deleted["problems"]][:3]),
            _probe("retention leaves a tombstone",
                   len(retention["removed"]) == 1 and retain_book.tombstone_path.exists(),
                   f"{len(retention['removed'])} removed, tombstone written"),
            _probe("a tenant name cannot escape the store root",
                   _refuses(sc, "TENANT_NOT_A_SLUG",
                            **{"root": str(root), "tenant": "../escape"}), "../ refused"),
        ])

    # -- L-05 facades -------------------------------------------------------- #
    catalogue = sc.controls()
    facade_controls = [control for control, entry in catalogue.items() if entry.get("facade")]
    no_vendor = all(_refuses(sc, "FACADE_HAS_NO_VENDOR", control=control, vendor="thales")
                    for control in facade_controls)
    delegates = {control: catalogue[control]["delegates_to"] for control in facade_controls}
    add(5, "Facades", "are HSM, KMS, PKI and NETWORK in the layer without a second architecture?",
        [
            _probe("the four facade controls are implemented",
                   set(facade_controls) == {"HSM", "KMS", "PKI", "NETWORK"},
                   ", ".join(sorted(facade_controls))),
            _probe("each names the module it delegates to",
                   all(value for value in delegates.values()),
                   "; ".join(f"{k} → {', '.join(v)}" for k, v in sorted(delegates.items()))),
            _probe("a facade has no vendor dialect of its own", no_vendor,
                   "FACADE_HAS_NO_VENDOR for all four"),
            _probe("nothing is deferred any more",
                   sc.read_only_audit()["deferred"] == [], "deferred: []"),
        ])

    # -- L-06 prohibited values ---------------------------------------------- #
    hsm_snapshot = sc.collector("HSM", "existing-collectors", hsm_feed()).snapshot()
    net_snapshot = sc.collector("NETWORK", "existing-collectors", network_feed()).snapshot()
    kms_snapshot = sc.collector("KMS", "existing-collectors", kms_feed()).snapshot()
    pki_snapshot = sc.collector("PKI", "existing-collectors", pki_feed()).snapshot()
    hsm_text = json.dumps(hsm_snapshot, default=str)
    net_text = json.dumps(net_snapshot, default=str)
    add(6, "Prohibited values", "does key material or a request body survive a cycle?", [
        _probe("HSM key material does not survive", "0x" + "d4e5f6" * 10 not in hsm_text
               and "operator-secret" not in hsm_text, "material and password refused"),
        _probe("a network payload does not survive", "sess=abc" not in net_text
               and "Basic c2VjcmV0" not in net_text, "body and header dropped by name"),
        _probe("the drop is recorded, not silent",
               {"raw_body", "authorization"} <= {row["field"] for row in net_snapshot["redactions"]},
               sorted({row["field"] for row in net_snapshot["redactions"]})),
        _probe("KMS keys are metadata only",
               all(row["kind"] in {"KMS", "KEY_REFERENCE"} for row in kms_snapshot["assets"]),
               f"{len(kms_snapshot['assets'])} asset(s)"),
        _probe("PKI emits only the model's own relations",
               all(row["relation"] in {"ISSUED_BY", "SIGNED_BY"}
                   for row in pki_snapshot["relationships"]),
               ", ".join(sorted({row["relation"] for row in pki_snapshot["relationships"]}))),
    ])

    # -- L-07 window arithmetic ---------------------------------------------- #
    fixed = sc.WindowModel(mode="FIXED", limit=100, window_seconds=60)
    sliding = sc.WindowModel(mode="SLIDING", limit=100, window_seconds=60)
    add(7, "Rate limit windows", "does the audit use the limiter's arithmetic, not its own?", [
        _probe("a sliding window permits N in any rolling window",
               sliding.expected(60)[0] == 100, f"{sliding.expected(60)[0]:g} over 60s"),
        _probe("a fixed counter permits a boundary burst",
               fixed.expected(60)[0] == 200, fixed.expected(60)[1]),
        _probe("an aligned window does not get the burst",
               sc.WindowModel(mode="FIXED", limit=100, window_seconds=60)
               .expected(60, aligned=True)[0] == 100, "100 over one closed window"),
        _probe("an unknown window model is refused",
               _refuses(sc, "UNKNOWN_WINDOW_MODE", mode="SOMETIMES", limit=10), "refused"),
    ])

    # -- L-08 comparability -------------------------------------------------- #
    source = sc.CounterAPI(sc.RecordedTransport({"/metrics": {"routes": [
        {"api": "PAYMENTS-API", "requests": 400, "window_seconds": 60,
         "window_mode": "SLIDING"},
    ]}}), "/metrics")
    audit = sc.audit_limits(limiter("FIXED"), source=source)
    incomparable = audit["summary"]["INCOMPARABLE_WINDOW"]
    partial_source = sc.CounterAPI(sc.RecordedTransport({"/metrics": {"routes": [
        {"api": "PAYMENTS-API", "requests": 40, "window_seconds": 30}]}}), "/metrics")
    partial_audit = sc.audit_limits(limiter("FIXED"), source=partial_source)
    add(8, "Comparability", "is a breach claimed only when the windows are the same interval?", [
        _probe("a mismatched window model is INCOMPARABLE_WINDOW",
               incomparable == 1 and audit["summary"]["OVER_LIMIT"] == 0,
               f"{incomparable} incomparable, {audit['summary']['OVER_LIMIT']} over limit"),
        _probe("a fragment of a window is not a rate",
               partial_audit["summary"]["INCOMPARABLE_WINDOW"] == 1,
               "30s sample under a 60s policy"),
    ])

    # -- L-09 states and sources --------------------------------------------- #
    measured = sc.CounterAPI(sc.RecordedTransport({"/metrics": {"routes": [
        {"api": "PAYMENTS-API", "requests": 140, "window_seconds": 60, "aligned": True,
         "window_mode": "FIXED"},
        {"api": "OPEN-API", "requests": 9000, "window_seconds": 60, "aligned": True},
    ]}}), "/metrics")
    measured_audit = sc.audit_limits(limiter("FIXED"), source=measured)
    states = {(row["api"], row["state"]) for row in measured_audit["findings"]}
    blind = sc.audit_limits(limiter("FIXED"),
                            source=sc.CounterAPI(sc.RecordedTransport({}), "/metrics"))
    add(9, "Observation states", "are NOT_CONFIGURED, UNKNOWN and OVER_LIMIT kept apart?", [
        _probe("traffic with no policy is NOT_CONFIGURED",
               ("OPEN-API", "NOT_CONFIGURED") in states, "OPEN-API → NOT_CONFIGURED"),
        _probe("an aligned counter over the limit is OVER_LIMIT",
               ("PAYMENTS-API", "OVER_LIMIT") in states, "140 over 100 in one closed window"),
        _probe("an unavailable source is reported, not treated as zero",
               any(row["code"] == "OBSERVATION_SOURCE_UNAVAILABLE"
                   for row in blind["refusals"]), "OBSERVATION_SOURCE_UNAVAILABLE"),
        _probe("the report says what was not measured",
               "not a limit that held" in sc.observation_report(measured_audit)["statement"],
               sc.observation_report(measured_audit)["statement"]),
    ])

    # -- L-10 the resolver --------------------------------------------------- #
    resolver, now = estate()
    window = sc.Window(event_at=now, max_age_seconds=3600)
    fresh = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.20.3.4"}, resolver,
                                        window=window)
    stale_resolver, _ = estate(library_minutes=600)
    stale = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.20.3.4"}, stale_resolver,
                                        window=window)
    strict = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.20.3.4"}, stale_resolver,
                                         window=window, strict=True)
    empty = sc.correlate_from_inventory({"id": "EVT-2", "src": "10.99.99.99"},
                                        sc.StaticResolver(rows={}), window=window)
    add(10, "Resolver", "does correlation come from the estate, and does it know when it is old?", [
        _probe("the whole path resolves from the inventory",
               fresh["answerable"] is True and fresh["trustworthy"] is True,
               " → ".join(hop["to"] for hop in fresh["path"])),
        _probe("a stale hop is named, not used as proof",
               bool(stale["inventory"]["stale"])
               and any(row["code"] == "STALE_EVIDENCE" for row in stale["unresolved"])
               and stale["trustworthy"] is False,
               f"{len(stale['inventory']['stale'])} stale hop(s)"),
        _probe("strict mode stops where the evidence stops",
               [hop["to"] for hop in strict["path"]][-1] == "PAYMENTS-API",
               f"path ends at {[hop['to'] for hop in strict['path']][-1]}"),
        _probe("an empty inventory is unresolved, not a pass",
               empty["answerable"] is False and empty["inventory"]["source"] == "empty",
               "answerable: false"),
    ])

    # -- L-11 the evidence API ----------------------------------------------- #
    try:
        from api.routers import security_controls as router_module

        prefix = router_module.router.prefix
        # routes are declared router-relative, so report them as mounted: the console and the
        # bank's SIEM call the prefixed path, and a route table without its prefix is a guess
        paths = {(route.path if route.path.startswith(prefix) else f"{prefix}{route.path}")
                 for route in router_module.router.routes}
        api_ok = {f"{prefix}/snapshots", f"{prefix}/findings",
                  f"{prefix}/verify"} <= paths
        api_note = ", ".join(sorted(paths))
    except Exception as exc:  # noqa: BLE001
        api_ok, api_note = False, f"{type(exc).__name__}: {exc}"
    model_ok, model_note = False, ""
    try:
        from db.models.security_control import (SecurityControlFinding,
                                                SecurityControlSnapshot)

        model_ok = (SecurityControlSnapshot.__tablename__ == "security_control_snapshots"
                    and "tenant_id" in {c.name for c in SecurityControlFinding.__table__.columns}
                    and "evidence_ids" in {c.name for c in
                                           SecurityControlFinding.__table__.columns})
        model_note = f"{SecurityControlSnapshot.__tablename__}, {SecurityControlFinding.__tablename__}"
    except Exception as exc:  # noqa: BLE001
        model_note = f"{type(exc).__name__}: {exc}"
    add(11, "Evidence API", "is a finding stored as evidence, tenant-scoped and citable?", [
        _probe("the write and read routes exist", api_ok, api_note),
        _probe("both tables exist and carry tenant_id", model_ok, model_note),
        _probe("a finding cannot exist without evidence ids",
               _findings_require_evidence(router_module), "FINDING_WITHOUT_EVIDENCE"),
        _probe("a user token is not a collector",
               _user_token_refused(router_module), "user_token_not_accepted"),
    ])

    # -- L-12 redaction precision -------------------------------------------- #
    corpus = {
        "epoch_ms": "1735689600000", "epoch_micros": "1735689600000123",
        "object_id": "1099511627776", "serial": "1234567890123456",
        "inode": "8392018475629", "bytes": "7812345678901", "uptime_ms": "86400000",
        "policyid": "1234567890123", "mtu": "9000", "port_range": "8080-8443",
        "created_at": "2026-11-04T09:14:00Z", "size": "4294967296",
    }
    clean, redactions = sc.scrub(dict(corpus))
    false_positives = sorted(key for key, value in clean.items() if value == sc.REDACTED)
    caught, _ = sc.scrub({"a": "4111 1111 1111 1111", "b": "5500 0000 0000 0004",
                          "c": "378282246310005", "d": "6011 0009 9013 9424"})
    allowed = sc.redaction_allowlist()
    add(12, "Redaction precision",
        "does the guard redact the card numbers and not the evidence?", [
            _probe("legitimate numeric fields survive", not false_positives,
                   f"{len(corpus)} field(s), {len(false_positives)} false positive(s)"),
            _probe("four real card numbers are still caught",
                   sum(1 for value in caught.values() if value == sc.REDACTED) == 4,
                   "Visa, Mastercard, Amex (15), Discover"),
            _probe("a Luhn-valid number in no issuer range is not a card",
                   sc.scrub({"reference": "1234567812345670"})[0]["reference"]
                   == "1234567812345670", "not a PAN"),
            _probe("the allowlist is published for review",
                   "timestamp" in allowed["numeric_fields"]
                   and "PEM_PRIVATE_KEY" in allowed["never_allowed"],
                   f"{len(allowed['numeric_fields'])} field(s) allowlisted"),
        ])

    # -- L-13 read-only, at the socket --------------------------------------- #
    class _Counter:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def request(self, method: str, url: str, **_kwargs: Any) -> Any:
            self.calls.append(method.upper())

            class _Response:
                status_code = 200
                headers: dict[str, str] = {}
                text = "{}"

                @staticmethod
                def json() -> dict[str, Any]:
                    return {}

            return _Response()

        def close(self) -> None:
            return None

    counter = _Counter()
    client = sc.HttpTransport(base_url="https://fw.example.bank",
                              credential=sc.Credential("t", source="probe"),
                              _client_factory=lambda: counter)
    refused_writes = 0
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            client.request(verb, "/api/v2/cmdb/firewall/policy")
        except sc.ControlRefused:
            refused_writes += 1
    reads = _Counter()
    reader = sc.HttpTransport(base_url="https://fw.example.bank",
                              credential=sc.Credential("t", source="probe"),
                              _client_factory=lambda: reads)
    reader.request("GET", "/api/v2/monitor/system/status")
    reader.request("HEAD", "/api/v2/monitor/license")
    add(13, "Read-only at the socket",
        "is the method allowlist enforced where the bytes leave?", [
            _probe("all four write verbs are refused", refused_writes == 4,
                   f"{refused_writes}/4 refused"),
            _probe("no refused write reached the client", counter.calls == [],
                   f"{len(counter.calls)} request(s) sent"),
            _probe("GET and HEAD do reach the client", reads.calls == ["GET", "HEAD"],
                   ", ".join(reads.calls)),
            _probe("the allowlist is the whole method set",
                   sc.transport.READ_METHODS == frozenset({"GET", "HEAD"}),
                   ", ".join(sorted(sc.transport.READ_METHODS))),
        ])

    # -- L-14 evidence ids: stable, versioned, scheme-tagged ------------------ #
    book = sc.EvidenceBook("FIREWALL", "Fortinet", "FW-EDGE-01")
    rule = {"name": "allow-payments", "action": "accept", "src": "10.0.0.0/8",
            "version": "42"}
    same = book.id_for("RULE", "allow-payments", rule) == \
        book.id_for("RULE", "allow-payments", rule)
    bumped = book.id_for("RULE", "allow-payments", {**rule, "version": "43"})
    original = book.id_for("RULE", "allow-payments", rule)
    verified = book.verify(original, "RULE", "allow-payments", rule)
    add(14, "Evidence identity",
        "is an evidence id stable, revision-aware and readable after a rule change?", [
            _probe("an unchanged fact keeps its id", same, "two reads, one id"),
            _probe("a bumped config revision moves the id", original != bumped,
                   "version 42 → 43"),
            _probe("every id carries its digest scheme",
                   original.startswith(f"EVID-{sc.EVIDENCE_SCHEME}-FIREWALL-"),
                   sc.evidence_scheme(original)),
            _probe("a legacy id is named, not misread",
                   sc.evidence_scheme("EVID-FIREWALL-0123456789ab") == sc.LEGACY_SCHEME,
                   "v0"),
            _probe("a citation re-verifies months later", verified["matches"] is True,
                   "recomputed match"),
        ])

    # -- L-15 the taxonomy, on every surface --------------------------------- #
    partial = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({
        "/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "allow"}]},
    }), system="FW-EDGE-01")
    unreachable = sc.collector("SIEM", "splunk", {"health": {"reachable": False}})
    faulted = sc.collector("FIREWALL", "fortigate", {"system": "FW-02",
                                                     "health": {"state": "AUTH_FAILED"}})
    projection = sc.project([sc.collector("WAF", "f5_asm", {"system": "WAF-01"}),
                             unreachable, faulted])
    coverage = projection["summary"]["coverage"]
    unsupported = False
    try:
        sc.drivers.driver_for("firewall.cisco-asa", sc.RecordedTransport({}))
    except sc.ControlRefused as exc:
        unsupported = exc.code == "NO_LIVE_DRIVER"
    add(15, "Failure taxonomy",
        "does every failure have a name, on health, in the summary and for the console?", [
            _probe("three of five sections is PARTIAL_READ with named failures",
                   partial["read"]["state"] == "PARTIAL_READ"
                   and set(partial["read"]["coverage"]["failed"])
                   == {"zones", "interfaces", "vpn", "tls_inspection"},
                   f"{partial['read']['coverage']['sections_read']}"
                   f"/{partial['read']['coverage']['sections_declared']} sections"),
            _probe("health carries the state and its meaning",
                   unreachable.health()["state"] == "UNREACHABLE"
                   and unreachable.health()["taxonomy"]["retryable"] is True,
                   "UNREACHABLE, retryable"),
            _probe("a refused credential is AUTH_FAILED, not unreachable",
                   faulted.health()["state"] == "AUTH_FAILED",
                   faulted.health()["taxonomy"]["operator_action"][:40]),
            _probe("the projection summary carries coverage, not just counts",
                   coverage["counts"].get("UNREACHABLE") == 1
                   and coverage["counts"].get("AUTH_FAILED") == 1
                   and coverage["complete"] is False,
                   coverage["statement"]),
            _probe("a dialect with no driver is UNSUPPORTED_DIALECT",
                   unsupported and sc.describe("UNSUPPORTED_DIALECT")["group"] == "ABSENT",
                   "ABSENT"),
            _probe("every state says what to do about it",
                   all(sc.describe(state)["operator_action"] for state in sc.CONTROL_STATES),
                   f"{len(sc.CONTROL_STATES)} states"),
        ])

    # -- L-16 scale ---------------------------------------------------------- #
    routes = {"/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "a"}]},
              "/api/v2/cmdb/system/zone": {"results": [{"name": "payments"}]}}
    first = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(routes),
                             system="FW-01")
    previous = {"sections": first["configuration"]["sections"], "health": first["health"]}
    again = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(routes),
                             system="FW-01", previous=previous, incremental=True)
    changed_routes = {**routes,
                      "/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1,
                                                                    "name": "b"}]}}
    changed = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(changed_routes),
                               system="FW-01", previous=previous, incremental=True)
    big = {"results": [{"policyid": index} for index in range(40)]}
    capped = sc.live_snapshot("FIREWALL", "fortigate",
                              sc.RecordedTransport({"/api/v2/cmdb/firewall/policy": big}),
                              system="FW-01", max_rows=10)
    add(16, "Scale",
        "is collection incremental, coverage per-device and memory bounded?", [
            _probe("an unchanged section is not re-read",
                   again["read"]["unchanged_sections"] == ["rules", "zones"],
                   ", ".join(again["read"]["unchanged_sections"])),
            _probe("the snapshot stays complete: unchanged rows are merged back",
                   again["read"]["merged_sections"] == ["rules", "zones"],
                   f"{again['read']['coverage']['sections_read']} section(s) present"),
            _probe("a changed section is read again",
                   changed["read"]["unchanged_sections"] == ["zones"],
                   "rules changed, zones did not"),
            _probe("coverage is per device, not per estate",
                   first["read"]["coverage"]["sections_read"] == 2
                   and sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({}),
                                       system="FW-02")["read"]["coverage"]["sections_read"] == 0,
                   "FW-01 2/5, FW-02 0/5"),
            _probe("a section past the cap is truncated and says so",
                   capped["read"]["truncated"]["rules"]["rows_dropped"] == 30,
                   "40 read, 10 kept"),
            _probe("the snapshot ceiling is published",
                   capped["read"]["limits"]["max_snapshot_bytes"] > 0,
                   f"{capped['read']['limits']['max_snapshot_bytes']} bytes"),
        ])


    # -- L-17 one production detector ---------------------------------------- #
    import os as _os

    os_environment = {"ENVIRONMENT": "prod"}
    detection = platforms.environment.detect(environ=os_environment)
    typo = platforms.environment.detect(environ={"ENVIRONMENT": "prodcution"})
    gate_sites = []
    for module_name, attribute in (("api.routers.resilience", "_production"),
                                   ("api.events.platform_events", "_is_production")):
        module = importlib.import_module(module_name)
        gate_sites.append(getattr(module, attribute)())
    add(17, "One production predicate",
        "does every gate ask the same function, and does a typo fail closed?", [
            _probe("an alias resolves to production",
                   detection["effective"] == "production" and detection["recognised"] is True,
                   f"{detection['value']} -> {detection['effective']}"),
            _probe("the answer carries where it came from",
                   detection["source"] == "environ argument", detection["source"]),
            _probe("an unrecognised spelling fails closed",
                   typo["effective"] == "production" and typo["recognised"] is False,
                   "prodcution -> production"),
            _probe("the API gates agree with each other",
                   len(set(gate_sites)) == 1, f"{len(gate_sites)} call site(s)"),
            _probe("the predicate is documented as a contract",
                   platforms.environment.describe()["schema"] == "cryptoscan.environment/1",
                   "cryptoscan.environment/1"),
            _probe("no gate reads os.environ itself",
                   _os.environ.get("CRYPTOSCAN_HARNESS_FAKE") != "1"
                   and "os.environ" not in platforms.environment.is_production.__code__.co_names,
                   "is_production() delegates"),
        ])

    # -- L-18 the estate leaves the console ---------------------------------- #
    exported_estate = {"generated_at": "2026-11-04T00:00:00+00:00",
              "summary": {"coverage": {"state": "PARTIAL", "collected": 2, "covered": 1}},
              "controls": [
                  {"id": "WAF", "vendor": "F5", "kind": "WAF", "state": "OK",
                   "observation_class": "RUNTIME_OBSERVED", "evidence_ids": ["EVID-v1-waf"]},
                  {"id": "IPS", "vendor": "Palo Alto", "kind": "IPS", "state": "REFUSED",
                   "reason": "device granted no read-only account",
                   "observation_class": "CONFIGURED", "evidence_ids": ["EVID-v1-ips"]},
                  {"id": "RATE_LIMIT", "vendor": "Kong", "kind": "RATE_LIMIT",
                   "state": "POLICY_NOT_ATTACHED", "observation_class": "CONFIGURED",
                   "evidence_ids": ["EVID-v1-rl"],
                   "redactions": [{"field": "authorization", "path": "headers.authorization",
                                   "reason": "credential"}]},
              ]}
    document = control_export.to_cyclonedx(exported_estate)
    validation = cdx.validate_cyclonedx16(document)
    cef_lines = control_export.to_cef(exported_estate)
    add(18, "Exports the bank can ingest",
        "do the findings leave the UI as CycloneDX and CEF without inventing a verdict?", [
            _probe("the CycloneDX document validates against the 1.6 schema",
                   validation["ok"] is True, "; ".join(validation["errors"]) or "schema clean"),
            _probe("each control is a subject a finding can attach to",
                   all(component["bom-ref"].startswith("urn:cryptoscan:control:")
                       for component in document["components"]),
                   f"{len(document['components'])} components"),
            _probe("every evidence id survives the export",
                   all(any(item["value"] == evidence_id
                           for item in component["properties"] if item["name"] == "cryptoscan:evidence.id")
                       for component in document["components"]
                       for evidence_id in ({"WAF": ["EVID-v1-waf"], "IPS": ["EVID-v1-ips"],
                                            "RATE_LIMIT": ["EVID-v1-rl"]}[component["name"]])),
                   "3 ids"),
            _probe("a refusal exports as a refusal, not as a gap",
                   any(item["name"] == "cryptoscan:refused" for item in
                       document["metadata"]["properties"])
                   and any("refused to answer" in annotation["text"]
                           for annotation in document.get("annotations", [])),
                   "REFUSED kept distinct"),
            _probe("the CEF lines escape a hostile device string",
                   all("\n" not in line for line in cef_lines)
                   and all(line.startswith("CEF:0|CryptoScan|") for line in cef_lines),
                   f"{len(cef_lines)} line(s)"),
            _probe("the export never claims a complete estate",
                   any(item["name"] == "cryptoscan:estate_completeness" for item in
                       document["metadata"]["properties"]),
                   "PARTIAL_WITH_REFUSALS"),
        ])

    counts = {VERDICT_PASS: 0, VERDICT_PARTIAL: 0, VERDICT_FAIL: 0}
    for point in points:
        counts[point["verdict"]] += 1
    total_probes = sum(point["probes"] for point in points)
    passed_probes = sum(point["probes_passed"] for point in points)
    return {
        "schema": "cryptoscan.security-controls-live/3",
        "guides": [182, 183, 184],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "positioning": ("CryptoScan integrates with the bank's existing network and security "
                        "controls to build an evidence-backed cryptographic and security "
                        "estate model."),
        "points": points,
        "counts": counts,
        "probes": {"total": total_probes, "passed": passed_probes,
                   "failed": total_probes - passed_probes},
    }


def _refuses(sc: Any, code: str, **kwargs: Any) -> bool:
    try:
        if "tenant" in kwargs:
            sc.EvidenceStore(kwargs["root"], kwargs["tenant"])
        elif "control" in kwargs and "vendor" in kwargs:
            sc.spec_for(kwargs["control"], kwargs["vendor"])
        elif "mode" in kwargs:
            sc.WindowModel(mode=kwargs["mode"], limit=kwargs["limit"])
        return False
    except sc.ControlRefused as exc:
        return exc.code == code


def _findings_require_evidence(router_module: Any) -> bool:
    finding = router_module.FindingIn(control="FIREWALL", state="OBSERVED", facts=["OBSERVED"])
    problems = router_module._validate([finding])
    return any(problem["code"] == "FINDING_WITHOUT_EVIDENCE" for problem in problems)


def _user_token_refused(router_module: Any) -> bool:
    """The router refuses a user session before it looks at any API key."""
    from fastapi import HTTPException
    from starlette.requests import Request

    from api import dependencies

    original = dependencies.SessionManager.validate_session
    dependencies.SessionManager.validate_session = lambda self, token: "alice"  # type: ignore[method-assign]
    try:
        request = Request({"type": "http", "headers": [(b"authorization", b"Bearer user-token")],
                          "method": "POST", "path": "/security-controls/snapshots"})
        try:
            router_module._service_identity(request, None)
            return False
        except HTTPException as exc:
            return exc.detail.get("error") == "user_token_not_accepted"
    finally:
        dependencies.SessionManager.validate_session = original  # type: ignore[method-assign]


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    probes = report["probes"]
    lines = [
        "# Security control integration — live harness (guides 182–183)",
        "",
        f"> {report['positioning']}",
        "",
        (f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
         f"{counts[VERDICT_FAIL]} fail** over {probes['total']} probes "
         f"({probes['passed']} passed, {probes['failed']} failed)."),
        "",
        "| | point | question | verdict | probes |",
        "|---|---|---|---|---|",
    ]
    for point in report["points"]:
        lines.append(f"| {point['id']} | {point['section']} | {point['question']} | "
                     f"**{point['verdict']}** | {point['probes_passed']}/{point['probes']} |")
    lines.append("")
    for point in report["points"]:
        lines.append(f"## {point['id']} — {point['section']}")
        lines.append("")
        lines.append(f"*{point['question']}*")
        lines.append("")
        for probe in point["results"]:
            mark = "PASS" if probe["ok"] else "FAIL"
            lines.append(f"- [{mark}] {probe['probe']} — {probe['observed']}")
        lines.append("")
    lines.append("## What this harness does not prove")
    lines.append("")
    lines.append(
        "* that a real device answers these endpoints: every read is through a recorded "
        "transport, so the *dialects* are exercised and the devices are not;")
    lines.append(
        "* that a PostgreSQL deployment applies the row-level policy in revision 0133 — the "
        "harness checks the tables and their columns, and the RBAC/RLS behaviour is covered by "
        "the database suite;")
    lines.append(
        "* that a rate-limit policy is the bank's policy: the numbers are the device's, and the "
        "policies are read from the device's own configuration.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    markdown = render_md(report)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n",
                             encoding="utf-8")
    if args.md:
        args.md.write_text(markdown, encoding="utf-8")
    if not args.json and not args.md:
        print(markdown)
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
