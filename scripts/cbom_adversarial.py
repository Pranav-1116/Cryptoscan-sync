#!/usr/bin/env python3
"""Guide 151 — adversarial CBOM: the review's five blockers, attacked on purpose.

Item 21 of the review ends with five red items:

1. **evidence spoofing** — imported CBOM/SBOM/vendor data must never become
   ``OBSERVED`` on its own say-so;
2. **false crypto attribution** — a library must not become every algorithm it
   supports;
3. **weak evidence promotion** — ``VENDOR_DECLARED`` must not become
   ``RUNTIME_OBSERVED`` without evidence;
4. **secret leakage** — collectors store references and properties, never
   material;
5. **signature/hash confusion** — a hash, an HMAC and a signature are different
   contracts.

Every probe here takes the attacker's side: hand the pipeline the most
convenient possible input and check that it is not believed. One blocker turned
out to be a real hole and is fixed in this increment — an event that named an
imported or vendor origin while *claiming* ``RUNTIME_OBSERVED`` was promoted as
runtime usage. The origin now wins, and the downgrade is recorded rather than
silent.
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
SCHEMA = "cryptoscan.cbom-adversarial-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

AES = "AES-256-GCM"
IMPORT_ORIGINS = ("imported", "import", "upload", "document", "cyclonedx", "spdx", "sbom")
VENDOR_ORIGINS = ("vendor", "vendor_declaration")
SECRET_FIELDS = ("private_key", "secret", "secret_key", "session_key", "plaintext",
                 "customer_payload", "password")


def _load() -> dict[str, Any]:
    for entry in (str(SERVICES / "cbom"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from cbom import estate_chain, pqc_handoff, promotion  # noqa: PLC0415
    from cbom import usage_collectors, usage_evidence  # noqa: PLC0415

    return {"ue": usage_evidence, "promo": promotion, "pq": pqc_handoff,
            "uc": usage_collectors, "ec": estate_chain}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _spoof(**overrides):
    return {**{"class": "RUNTIME_OBSERVED", "evidence_id": "VENDOR-1",
               "algorithm": AES}, **overrides}


# --------------------------------------------------------------------------- #


def row_evidence_spoofing(modules: dict[str, Any]) -> dict[str, Any]:
    ue, promo, ec = modules["ue"], modules["promo"], modules["ec"]
    imported = {origin: ue.normalize_event(_spoof(layer=origin))
                for origin in IMPORT_ORIGINS}
    vendor = {origin: ue.normalize_event(_spoof(source=origin))
              for origin in VENDOR_ORIGINS}
    laundered = ue.normalize_event(_spoof(layer="imported",
                                          evidence_id="PERFECT-LOOKING-ID"))
    genuine = ue.normalize_event({"layer": "runtime", "evidence_id": "R-1",
                                  "algorithm": AES})
    promoted = promo.promote([{"name": "openssl", "evidence_id": "SBOM-1",
                               "algorithms": [AES]}], [_spoof(layer="imported")])
    chain = ec.run({"name": "spoofed",
                    "components": [{"name": "openssl", "evidence_id": "SBOM-1",
                                    "algorithms": [AES]}],
                    "imported_events": [_spoof(layer="imported")]})
    probes = [
        _probe("an-imported-origin-is-never-an-observation",
               all(event["class"] == "IMPORTED" and event["observed"] is False
                   for event in imported.values()),
               f"{len(imported)} import spellings, all IMPORTED"),
        _probe("a-vendor-origin-is-downgraded-to-a-declaration",
               all(event["class"] == "VENDOR_DECLARED" and event["observed"] is False
                   for event in vendor.values()),
               ", ".join(f"{key} → {event['class']}" for key, event in vendor.items())),
        _probe("the-downgrade-is-recorded-not-silent",
               all(event["downgrades"] for event in imported.values())
               and "weaker class is kept" in imported["sbom"]["downgrades"][0],
               imported["sbom"]["downgrades"][0]),
        _probe("an-evidence-id-does-not-launder-an-imported-source",
               laundered["class"] == "IMPORTED"
               and laundered["evidence_id"] == "PERFECT-LOOKING-ID",
               "a plausible evidence id on an imported event is still an import"),
        _probe("a-real-runtime-event-is-not-downgraded",
               genuine["class"] == "RUNTIME_OBSERVED" and genuine["downgrades"] == [],
               "the guard protects the collector it exists to protect"),
        _probe("a-spoofed-event-cannot-promote-a-capability",
               promoted["assets"] == []
               and [row["algorithm"] for row in promoted["candidates"]] == [AES],
               promoted["statement"]),
        _probe("a-spoofed-estate-produces-an-empty-document",
               chain["document"]["components"] == [],
               "the chain never sees a claimed class, only the collector's"),
    ]
    return {"id": "evidence_spoofing",
            "question": "can an imported document call itself an observation?",
            "phase": "review 21 / 4", "probes": probes}


def row_false_attribution(modules: dict[str, Any]) -> dict[str, Any]:
    promo, ec = modules["promo"], modules["ec"]
    capability = promo.promote([{"name": "openssl", "evidence_id": "SBOM-1",
                                 "algorithms": ["AES-128-GCM", AES, "RSA-2048",
                                                "ECDSA-P256"]}], [])
    unattributed = promo.promote([{"name": "openssl",
                                   "algorithms": [AES]}], [])
    chain = ec.run({"name": "capabilities",
                    "components": [{"name": "openssl", "evidence_id": "SBOM-1",
                                    "algorithms": [AES, "RSA-2048"]}]})
    probes = [
        _probe("a-library-does-not-become-every-algorithm-it-supports",
               capability["assets"] == [] and len(capability["candidates"]) == 4,
               capability["statement"]),
        _probe("a-candidate-is-not-usage",
               all(row["profile"]["usage"] != "OBSERVED"
                   for row in capability["candidates"]),
               ", ".join(f"{row['algorithm']}={row['profile']['usage']}"
                         for row in capability["candidates"])),
        _probe("the-candidate-lists-what-would-promote-it",
               all(row["promotable_by"] for row in capability["candidates"]),
               "a reviewer can see the evidence that would make it an asset"),
        _probe("a-component-with-no-evidence-id-contributes-nothing",
               unattributed["assets"] == [] and unattributed["candidates"] == []
               and unattributed["refused"],
               unattributed["refused"][0]["reason"]),
        _probe("a-capability-only-estate-has-an-empty-document",
               chain["document"]["components"] == []
               and len(chain["promotion"]["candidates"]) == 2,
               "capabilities are reported, never written as fact"),
        _probe("the-document-says-how-many-it-left-out",
               {row["name"]: row["value"]
                for row in chain["document"]["metadata"]["properties"]}
               ["cryptoscan:candidates_excluded"] == "2",
               "the exclusion is in the document, not only in a log"),
    ]
    return {"id": "false_attribution",
            "question": "does a supporting library become an inventory of usage?",
            "phase": "review 21 / 6", "probes": probes}


def row_weak_promotion(modules: dict[str, Any]) -> dict[str, Any]:
    promo, pq = modules["promo"], modules["pq"]
    declared = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": [AES]}],
        [{"layer": "vendor", "evidence_id": "V-1", "algorithm": AES}])
    unattributed = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": [AES]}],
        [{"class": "RUNTIME_OBSERVED", "algorithm": AES}])
    quantum = pq.handoff([{"algorithm": "RSA-2048", "key_size": 2048,
                           "usage": "RUNTIME", "quantum_status": "POST_QUANTUM",
                           "quantum_safe": True, "evidence_ids": ["V-1"]}])["rows"][0]
    levels = promo.promotion_level(["VENDOR_DECLARED"])
    probes = [
        _probe("a-vendor-declaration-never-reaches-runtime",
               declared["assets"] == []
               and declared["candidates"][0]["profile"]["usage"] != "OBSERVED",
               declared["statement"]),
        _probe("an-observation-with-no-evidence-id-is-refused",
               unattributed["assets"] == [] and unattributed["candidates"],
               "a claim nobody can point at cannot promote anything"),
        _probe("a-vendor-quantum-claim-is-ignored-and-the-algorithm-is-classified",
               quantum["quantum_status"] == "QUANTUM_SENSITIVE"
               and quantum["status_basis"] == "REGISTRY_SHOR",
               f"vendor said POST_QUANTUM; the handoff says {quantum['quantum_status']} "
               f"({quantum['status_basis']})"),
        _probe("a-declared-class-promotes-to-a-declared-level-never-runtime",
               levels == "CAPABILITY", f"VENDOR_DECLARED → {levels}"),
        _probe("the-quantum-verdict-is-never-taken-from-the-document",
               quantum["quantum_status"] != "POST_QUANTUM",
               "a vendor cannot certify its own migration"),
    ]
    return {"id": "weak_promotion",
            "question": "can a declaration be promoted into an observation?",
            "phase": "review 21 / 5", "probes": probes}


def row_secret_leakage(modules: dict[str, Any]) -> dict[str, Any]:
    ue, ec = modules["ue"], modules["ec"]
    refused: dict[str, str] = {}
    for field in SECRET_FIELDS:
        try:
            ue.key_metadata({"key_ref": "HSM://partition-01/key/PAY-SIGN-001",
                             field: "do-not-store-me"})
        except ue.EvidenceRefused as exc:
            refused[field] = str(exc)
    record = ue.key_metadata({
        "key_ref": "HSM://partition-01/key/PAY-SIGN-001", "algorithm": "RSA",
        "key_size": 2048, "purpose": "SIGNATURE", "status": "ENABLED",
        "location": "partition-01", "owner": "payments", "evidence_id": "HSM-1"})
    unexpected = None
    try:
        ue.key_metadata({"key_ref": "k", "opaque_blob": "x"})
    except ue.EvidenceRefused as exc:
        unexpected = str(exc)
    chain = ec.run({"name": "leaky",
                    "keys": [{"key_ref": "k/1", "algorithm": "RSA", "key_size": 2048,
                              "provider": "AWS_KMS", "status": "ENABLED",
                              "evidence_id": "KMS-1", "private_key": "MIIEv..."}]})
    probes = [
        _probe("every-material-bearing-field-is-refused",
               len(refused) == len(SECRET_FIELDS),
               f"{len(refused)} of {len(SECRET_FIELDS)} refused, e.g. "
               f"{refused['private_key']}"),
        _probe("the-record-states-that-nothing-is-stored",
               record["private_material"] == "NOT STORED", record["private_material"]),
        _probe("the-metadata-that-is-allowed-is-the-metadata-a-bank-needs",
               record["key_ref"].startswith("HSM://") and record["algorithm"] == "RSA"
               and record["key_size"] == 2048 and record["purpose"] == "SIGNATURE",
               ", ".join(f"{key}={record[key]}" for key in
                         ("key_ref", "algorithm", "key_size", "purpose"))),
        _probe("an-unexpected-field-is-refused-rather-than-kept",
               unexpected is not None and "unexpected key metadata" in unexpected,
               unexpected or "accepted"),
        _probe("the-chain-refuses-a-key-record-carrying-material",
               bool(chain["keys"]["refused"]),
               chain["keys"]["refused"][0]["reason"]),
        _probe("no-material-reaches-the-document",
               "MIIEv" not in json.dumps(chain["document"]),
               "the exported document is checked for the value, not for the field name"),
    ]
    return {"id": "secret_leakage",
            "question": "can a collector be talked into storing key material?",
            "phase": "review 21 / 12", "probes": probes}


def row_signature_hash(modules: dict[str, Any]) -> dict[str, Any]:
    ue, uc, promo = modules["ue"], modules["uc"], modules["promo"]
    certificate = ue.certificate_evidence({
        "certificate_ref": "cert-9281", "public_key_algorithm": "ECDSA",
        "curve": "P-256", "signature_algorithm": "ECDSA-SHA256",
        "endpoint": "payments.bank.example:443", "observed_on": "External LB",
        "evidence_id": "NET-9281"})
    roles = {fact["algorithm"]: fact["role"] for fact in
             uc.algorithms_from_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384")}
    tls13 = {fact["algorithm"]: fact["role"] for fact in
             uc.algorithms_from_cipher_suite("TLS_AES_256_GCM_SHA384")}
    promoted = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": ["ECDSA-P256"]}],
        [certificate])
    probes = [
        _probe("a-certificate-is-its-own-category",
               certificate["usage"] == "CERTIFICATE_ONLY"
               and certificate["certificate"]["public_key_algorithm"] == "ECDSA",
               certificate["certificate"]["signature_algorithm"]),
        _probe("a-certificate-does-not-prove-an-application-operation",
               certificate["application_operation_proven"] is False
               and "does not prove" in certificate["statement"],
               certificate["statement"]),
        _probe("a-certificate-never-promotes-the-application-to-its-algorithm",
               promoted["assets"] == [], promoted["statement"]),
        _probe("a-suite-says-which-algorithm-plays-which-role",
               roles == {"AES-256-GCM": "BULK", "RSA": "SIGNATURE",
                         "ECDHE": "KEY_EXCHANGE", "SHA-384": "HASH"},
               json.dumps(roles, sort_keys=True)),
        _probe("a-hash-is-never-counted-as-a-signature",
               tls13.get("SHA-384") == "HASH" and "SIGNATURE" not in set(tls13.values()),
               "SHA-384 in a TLS 1.3 suite is a hash and nothing else"),
        _probe("an-unknown-suite-produces-no-fact-rather-than-a-guess",
               uc.algorithms_from_cipher_suite("TLS_NONSENSE_XYZ") == [],
               "a suite the table does not know yields nothing"),
    ]
    return {"id": "signature_hash",
            "question": "are hashes, signatures and key exchanges kept apart?",
            "phase": "review 21 / 3", "probes": probes}


ROWS = (row_evidence_spoofing, row_false_attribution, row_weak_promotion,
        row_secret_leakage, row_signature_hash)


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
    ue = modules["ue"]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "origins": {"import": list(IMPORT_ORIGINS), "vendor": list(VENDOR_ORIGINS)},
        "spoof_example": ue.normalize_event(_spoof(layer="imported")),
        "rows": rows,
        "limits": [
            "the guard is about the origin an event names, not about the class string. A "
            "caller that supplies its own evidence id and names a genuinely observing layer "
            "is believed, because the platform cannot audit a collector it did not write",
            "an imported *document* is still parsed for capabilities, and a capability is "
            "reported. What cannot happen is a capability becoming usage, which is a "
            "different claim from 'the document was ignored'",
            "the secret guard is a field-name and vocabulary check, not a secret scanner. A "
            "key material pasted into a free-text field named 'note' would pass, which is "
            "why the KMS collector also refuses unknown fields",
            "the certificate category says what the certificate contains. It cannot say "
            "whether the endpoint is still served by that certificate, which needs a probe",
            "these probes attack the modules directly. An attacker with write access to the "
            "platform's own collector output does not need any of this — provenance, not "
            "classification, is what stops that",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    spoof = report["spoof_example"]
    lines = [
        "# Adversarial CBOM: the five blockers, attacked",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Every probe here takes the attacker's side: hand the pipeline the most "
        "convenient possible input and check that it is not believed.",
        "",
        "```",
        "input:  {\"class\": \"RUNTIME_OBSERVED\", \"layer\": \"imported\", \"evidence_id\": \"V-1\"}",
        f"output: class={spoof['class']}, observed={spoof['observed']}",
        f"        {spoof['downgrades'][0]}",
        "```",
        "",
        "One of the five was a real hole when this guide attacked it: an event that "
        "named an imported or vendor origin while **claiming** `RUNTIME_OBSERVED` was "
        "promoted as runtime usage. `usage_evidence.normalize_event` now makes the origin "
        "win in both directions, and records the downgrade on the event instead of "
        "silently reclassifying it.",
        "",
        "| blocker | what is attacked | outcome |",
        "|---|---|---|",
        "| evidence spoofing | an imported document claiming an observation | `IMPORTED`, "
        "downgrade recorded, no promotion |",
        "| false attribution | a library that supports four algorithms | four candidates, "
        "zero assets |",
        "| weak promotion | a vendor claiming runtime use and quantum readiness | candidate "
        "only; the handoff classifies the algorithm itself |",
        "| secret leakage | key records carrying material | refused before storage, "
        "`private_material: NOT STORED` |",
        "| signature/hash confusion | a certificate's ECDSA-SHA256 | `CERTIFICATE_ONLY`, "
        "`application_operation_proven: false`, roles kept apart |",
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
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
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
