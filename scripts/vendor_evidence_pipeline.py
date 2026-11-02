#!/usr/bin/env python3
"""Guide 132 — the evidence pipeline: from a log to a defensible VBOM row.

Guide 131 closed the five gaps guide 130 named. Its own closing list then named
five more, and this artifact works through four of them plus the composition
that was never shown:

* **the logs a bank actually has** — a Zeek ``ssl.log``, a CSV export and an
  access log with ``$ssl_cipher`` appended are read into session records, with
  unreadable rows counted rather than dropped and a key-material column refusing
  the whole file;
* **which workload used it** — peers are joined to a register, and a shared
  appliance is ``AMBIGUOUS`` with every application named, an unregistered peer
  is ``UNATTRIBUTED``, and the leftover sessions stay in the workload table
  instead of being spread across the ones that were identified;
* **sub-vendor discovery** — a CycloneDX SBOM's ``supplier`` fields become
  sub-vendor edges with the component reference as their citation, while a
  component with no supplier is listed and never inferred;
* **the bank's own spellings** — an alias table that may add spellings but not
  redefine them, and a review stub emitted unfilled on purpose;
* **due-diligence sections that are filled in but cite nothing**, which the
  twenty-two-section completeness check calls complete.

The last row is the one that matters: a log line, through decode, attribution,
claim, VBOM row and coverage statement, with every hop asserted — so the
sentence "1 post-quantum tick is backed by an observed session" can be traced
back to a named session in a named file.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.vendor-evidence-guide/3"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"


def _load_modules() -> dict[str, Any]:
    for entry in (str(SERVICES / "vendor_intel"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config"), str(SERVICES / "database"),
                  str(SERVICES / "api")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from vendor_intel import algorithm_names as an  # noqa: PLC0415
    from vendor_intel import runtime_sources as rs  # noqa: PLC0415
    from vendor_intel import runtime_usage as ru  # noqa: PLC0415
    from vendor_intel import sbom_edges as se  # noqa: PLC0415
    from vendor_intel import usage_attribution as ua  # noqa: PLC0415
    from vendor_intel import vbom as vb  # noqa: PLC0415
    from vendor_intel import vendor_evidence as ve  # noqa: PLC0415
    return {"ve": ve, "an": an, "rs": rs, "ru": ru, "se": se, "ua": ua, "vb": vb}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _raises(expected: type[BaseException], call: Any) -> str:
    try:
        call()
    except expected as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001 - a different exception is a different failure
        return f"WRONG-EXCEPTION {type(exc).__name__}: {exc}"
    return ""


# --------------------------------------------------------------------------- #
# fixtures: the logs a bank has, and the register behind them
# --------------------------------------------------------------------------- #

ZEEK = "\n".join([
    "#separator \\x09",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve",
    *[f"17800000{index:02d}.5\tC{index}\t10.0.0.9\t5100{index}\t10.0.0.5\t443\tTLSv13\t"
      f"TLS_AES_256_GCM_SHA384\tx25519mlkem768" for index in range(12)],
    "1780000099.5\tC-broken\t10.0.0.9\t51099\t10.0.0.5\t443\tTLSv12\t-\t-",
    "",
])

CSV = "\n".join([
    "session_id,started_at,peer,cipher_suite,group,hostname",
    "A1,2026-10-01,10.0.0.5:443,AES256,x25519,hsm-001.corp",
    "A2,2026-10-01,10.0.0.5:443,RSA-3072,,hsm-001.corp",
    "A3,2026-10-01,10.0.0.5:443,,,",
    "",
])

NGINX = "\n".join([
    '10.0.0.9 - - [04/Oct/2026:10:11:12 +0000] "POST /v1/authorize HTTP/1.1" 200 512 "-" '
    '"curl/8" "TLSv1.3" "TLS_AES_256_GCM_SHA384" "x25519mlkem768"',
    '10.0.0.9 - - [04/Oct/2026:10:12:12 +0000] "GET /health HTTP/1.1" 200 12 "-" "curl/8"',
    "",
])

BOM = {
    "bomFormat": "CycloneDX",
    "serialNumber": "urn:uuid:9f2c",
    "metadata": {"component": {"name": "Crypto SDK 4.2",
                               "supplier": {"name": "Vendor-X"}}},
    "components": [
        {"name": "openssl-wrapper", "version": "1.0.3", "bom-ref": "c1",
         "supplier": {"name": "Vendor-Z"}, "purl": "pkg:generic/wrapper@1.0.3"},
        {"name": "libfoo", "version": "2.0"},
        {"name": "vendor-x-core", "version": "4.2", "publisher": "Vendor-X"},
    ],
}

AS_OF_DEFAULT = date(2026, 11, 2)


# --------------------------------------------------------------------------- #
# 1. the logs a bank already has
# --------------------------------------------------------------------------- #


def row_log_readers(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    rs, ru = modules["rs"], modules["ru"]
    probes = []

    zeek = rs.load_sessions(ZEEK)
    probes.append(_probe(
        "a-zeek-log-becomes-session-records",
        (zeek["format"], zeek["rows_used"], zeek["rows_skipped"]) == ("zeek_ssl_log", 12, 1),
        f"{zeek['rows_used']} of {zeek['rows_read']} row(s) used, {zeek['rows_skipped']} "
        f"skipped: {zeek['skipped'][0]['reason']}"))

    summary = ru.ingest_sessions(rs.records_for_ingest(zeek), asset_id="HSM-001")
    probes.append(_probe(
        "the-log-carries-post-quantum-key-establishment",
        summary["pqc_primitives"] == ["ML-KEM-768"] and summary["confidence"] == "HIGH",
        f"{summary['sessions']} session(s) -> {summary['pqc_primitives']} at "
        f"{summary['confidence']} confidence; the curve column is where it appears"))

    csv_loaded = rs.load_sessions(CSV)
    probes.append(_probe(
        "a-csv-is-mapped-and-its-unknown-columns-are-named",
        csv_loaded["rows_used"] == 2 and csv_loaded["unknown_columns"] == ["hostname"],
        f"{csv_loaded['rows_used']} row(s) used, {csv_loaded['rows_skipped']} skipped, "
        f"columns not used: {csv_loaded['unknown_columns']}"))

    nginx = rs.load_sessions(NGINX)
    probes.append(_probe(
        "an-access-log-yields-protocol-cipher-and-curve",
        nginx["records"][0]["group"] == "x25519mlkem768"
        and nginx["records"][0]["tls_version"] == "TLS1.3"
        and nginx["rows_skipped"] == 1,
        f"one line decoded ({nginx['records'][0]['cipher_suite']}), one skipped with "
        f"'{nginx['skipped'][0]['reason'][:52]}…'"))

    refused = _raises(rs.SourceError, lambda: rs.load_sessions(
        "session_id,started_at,cipher_suite,premaster_secret\n"))
    probes.append(_probe(
        "a-key-material-column-refuses-the-file",
        "premaster_secret" in refused,
        f"the CSV is refused rather than partially read: {refused[:90]}"))

    empty_row = _raises(rs.EmptySource, lambda: rs.load_sessions(
        '10.0.0.9 - - [04/Oct/2026:10:11:12 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8"'))
    probes.append(_probe(
        "a-file-that-yields-nothing-raises-instead-of-reporting-calm",
        "none carried a session" in empty_row,
        empty_row[:110]))

    unknown = _raises(rs.SourceError, lambda: rs.load_sessions("a paragraph about TLS 1.3\n"))
    probes.append(_probe(
        "an-unrecognised-file-is-named-not-guessed",
        "not in a shape" in unknown,
        f"detected {rs.detect_format('a paragraph about TLS 1.3')!r} and refused: {unknown[:80]}"))

    return {"id": "log_readers",
            "question": "can a session record come from a log the bank already keeps?",
            "phase": "6", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. which workload used it
# --------------------------------------------------------------------------- #


def row_workload_attribution(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    rs, ua, ve = modules["rs"], modules["ua"], modules["ve"]
    probes = []

    records = rs.records_for_ingest(rs.load_sessions(ZEEK))
    endpoints = [
        ua.Endpoint("10.0.0.5", asset_id="HSM-001", applications=("Payments API",),
                    evidence=ve.Evidence(ve.EvidenceType.OBSERVED, "cmdb:HSM-001",
                                         observed_at=as_of)),
        ua.Endpoint("10.0.0.7", asset_id="HSM-001",
                    applications=("Payments API", "Reporting")),
        ua.Endpoint("10.0.0.8", asset_id="WEB-01"),
    ]
    mixed = records + [{"peer": "10.0.0.7:443"}] * 3 + [{"peer": "10.9.9.9:443"}] * 2 \
        + [{"peer": "10.0.0.8:443"}]
    report = ua.attribute_sessions(mixed, endpoints, default_asset_id="HSM-001")

    attributed = next(row for row in report["rows"] if row["peer"] == "10.0.0.5:443")
    probes.append(_probe(
        "one-endpoint-one-application-is-attributed-with-its-citation",
        attributed["state"] == "ATTRIBUTED"
        and attributed["applications"] == ["Payments API"]
        and attributed["endpoint_evidence"],
        f"{attributed['sessions']} session(s) -> {attributed['applications']} on "
        f"{attributed['asset_ids']}, backed by {attributed['endpoint_evidence'][0]}"))

    shared = next(row for row in report["rows"] if row["peer"] == "10.0.0.7:443")
    probes.append(_probe(
        "a-shared-appliance-is-ambiguous-and-names-both",
        shared["state"] == "AMBIGUOUS" and shared["applications"] == ["Payments API", "Reporting"],
        f"{shared['state']}: {', '.join(shared['applications'])} — "
        f"{shared['reason']}"))

    unknown = next(row for row in report["rows"] if row["peer"] == "10.9.9.9:443")
    probes.append(_probe(
        "an-unregistered-peer-is-not-assigned-to-the-nearest-appliance",
        unknown["state"] == "UNATTRIBUTED" and unknown["applications"] == [],
        f"10.9.9.9:443 -> {unknown['state']} with no application; the collector's asset is "
        "kept and the workload is not guessed"))

    partial = next(row for row in report["rows"] if row["peer"] == "10.0.0.8:443")
    probes.append(_probe(
        "an-endpoint-with-no-application-is-partial",
        partial["state"] == "PARTIAL" and partial["asset_ids"] == ["WEB-01"],
        f"{partial['state']}: the asset is known and the workload is not — {partial['reason']}"))

    workload = ua.workload_summary(report)
    probes.append(_probe(
        "the-workload-table-keeps-the-remainder",
        workload["unattributed_sessions"] > 0 and workload["coverage"] < 100,
        f"{workload['applications']} covers {workload['coverage']}% of sessions; the other "
        f"{workload['unattributed_sessions']} are an unknown workload, not a rounding "
        "difference"))

    probes.append(_probe(
        "every-half-answer-reaches-a-ledger",
        {entry["state"] for entry in report["ledger"]} == {"PARTIAL", "AMBIGUOUS",
                                                           "UNATTRIBUTED"}
        and len(report["ledger"]) == 3,
        f"{len(report['ledger'])} ledger entr(ies): "
        + ", ".join(f"{entry['subject']}={entry['state']}" for entry in report["ledger"])))

    return {"id": "workload_attribution",
            "question": "does an observed session say which application used the primitive?",
            "phase": "11/12", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. sub-vendors discovered from an SBOM
# --------------------------------------------------------------------------- #


def row_sbom_sub_vendors(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    se, ve = modules["se"], modules["ve"]
    probes = []

    report = se.vendor_edges_from_cyclonedx(BOM, parent_vendor="Vendor-X",
                                            observed_at=as_of,
                                            evidence_factory=ve.Evidence)
    edge = report["edges"][0]
    probes.append(_probe(
        "a-supplier-field-becomes-an-edge-with-a-citation",
        edge["child_vendor"] == "Vendor-Z" and edge["reference"].startswith("sbom:")
        and edge["evidence"].kind is ve.EvidenceType.IMPORTED,
        f"{edge['child_vendor']} {edge['child_product']} from field "
        f"{edge['vendor_field']}, cited as {edge['reference']} "
        f"({edge['evidence'].evidence_id})"))

    probes.append(_probe(
        "a-component-with-no-supplier-is-listed-not-inferred",
        [row["component"] for row in report["unattributed"]] == ["libfoo"]
        and all(item["child_vendor"] != "libfoo" for item in report["edges"]),
        "libfoo names no supplier, so no vendor is invented for it: "
        f"{report['unattributed'][0]['reason'][:70]}…"))

    probes.append(_probe(
        "the-parents-own-component-is-not-a-sub-vendor",
        [row["component"] for row in report["self_edges"]] == ["vendor-x-core"],
        "vendor-x-core is published by Vendor-X, so it is a self edge and not a dependency"))

    edges = se.edges_for_footprint(report, edge_factory=ve.SubVendorEdge)
    asset = ve.HardwareDependency("HSM-001", ve.ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
                                  applications=("Payments API",),
                                  business_systems=("Payment System",),
                                  critical_systems=("Card Authorization",))
    inherited = ve.HardwareDependency("APP-07", ve.ProductIdentity("Vendor-Z", "HSA 9", "1.0"),
                                      applications=("Reporting",),
                                      business_systems=("Regulatory Reporting",))
    footprint = ve.vendor_footprint("Vendor-X", edges=edges, assets=[asset, inherited])
    probes.append(_probe(
        "the-edge-reaches-the-estate-through-the-embedded-vendor",
        footprint["direct"]["assets"] == ["HSM-001"]
        and footprint["indirect"]["assets"] == ["APP-07"]
        and footprint["sub_vendors"] == ["Vendor-Z"],
        f"direct {footprint['direct']['assets']}, inherited "
        f"{footprint['indirect']['assets']} via {footprint['sub_vendors']}; "
        f"{footprint['statement']}"))

    not_a_bom = _raises(se.SbomShapeError, lambda: se.vendor_edges_from_cyclonedx(
        {"bomFormat": "SPDX", "components": []}, parent_vendor="Vendor-X"))
    probes.append(_probe(
        "a-document-that-is-not-a-cyclonedx-bom-is-refused",
        "not a CycloneDX BOM" in not_a_bom,
        not_a_bom))

    empty = se.vendor_edges_from_cyclonedx({"bomFormat": "CycloneDX", "components": []},
                                           parent_vendor="Vendor-X")
    probes.append(_probe(
        "an-empty-bom-is-called-a-metadata-gap",
        "gap in the SBOM's supplier metadata" in empty["statement"],
        empty["statement"]))

    return {"id": "sbom_sub_vendors",
            "question": "does a sub-vendor edge come from the SBOM, or from folklore?",
            "phase": "12", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. the bank's own spellings
# --------------------------------------------------------------------------- #


def row_alias_overrides(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    an = modules["an"]
    probes = []

    table = an.AlgorithmTable(extra={"AESGCM256": "AES-256-GCM", "RSA-3K": "RSA-3072"})
    probes.append(_probe(
        "a-bank-spelling-resolves-through-the-supplied-table",
        table.identity("AESGCM256").canonical == "AES-256-GCM"
        and table.same("RSA-3K", "RSA-3072"),
        "AESGCM256 -> AES-256-GCM and RSA-3K -> RSA-3072; the builtin table is unchanged"))

    redefine = _raises(an.AliasConflict, lambda: an.AlgorithmTable(extra={"AES256": "AES-128"}))
    probes.append(_probe(
        "an-override-cannot-redefine-a-builtin",
        "already a builtin spelling" in redefine,
        redefine))

    invented = _raises(an.AliasConflict,
                       lambda: an.AlgorithmTable(extra={"X99": "NOPE-1"}))
    probes.append(_probe(
        "an-alias-cannot-point-at-a-name-nobody-knows",
        "does not know" in invented,
        invented))

    stub = an.AlgorithmTable().stub(["AES-256", "Weird-99-xyz"])
    probes.append(_probe(
        "the-review-stub-is-emitted-unfilled",
        stub["aliases"] == {"Weird-99-xyz": ""} and stub["unresolved"] == 1,
        f"one unknown name queued with an empty target: {stub['aliases']}"))

    unfilled = _raises(an.AliasConflict, lambda: an.load_alias_table(stub))
    probes.append(_probe(
        "an-unfilled-stub-cannot-be-loaded-as-no-aliases",
        "no target yet" in unfilled,
        unfilled[:100]))

    filled = an.load_alias_table({"aliases": {"MYCIPHER-1": "AES-128"}})
    probes.append(_probe(
        "a-filled-stub-loads-and-normalises",
        filled.normalise(["MYCIPHER-1", "MYCIPHER-1"]) == ["AES-128"]
        and filled.unknown(["MYCIPHER-1", "ZZZ"]) == ["ZZZ"],
        "MYCIPHER-1 -> AES-128, and ZZZ is still in the review queue"))

    return {"id": "alias_overrides",
            "question": "can a bank teach the reader its own spellings without weakening it?",
            "phase": "15", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. a section that cites nothing
# --------------------------------------------------------------------------- #


def row_due_diligence_evidence(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    ve = modules["ve"]
    probes = []

    sections = {name: f"{name} on file" for name in ve.DUE_DILIGENCE_SECTIONS}
    sections["review_status"] = "APPROVED"
    sections["last_review"] = date(2026, 9, 1)
    completeness = ve.evaluate_due_diligence(sections, as_of=as_of)
    audit = ve.audit_due_diligence_evidence(sections)
    probes.append(_probe(
        "a-record-can-be-complete-and-support-nothing",
        completeness["status"] == "COMPLETE" and audit["supported"] == 0
        and audit["counts"]["UNCITED"] == len(ve.DUE_DILIGENCE_SECTIONS),
        f"the completeness check says {completeness['status']} and the evidence audit says "
        f"{audit['supported']} of {audit['sections']} sections are supported"))

    # ``review_status`` and ``last_review`` are sections of the record too, so a
    # review that is on file without a minute behind it is uncited like any other.
    cited = {name: {"value": f"{name} on file", "evidence": [f"VD-{name[:6]}"]}
             for name in ve.DUE_DILIGENCE_SECTIONS}
    index = {f"VD-{name[:6]}" for name in ve.DUE_DILIGENCE_SECTIONS}
    supported = ve.audit_due_diligence_evidence(cited, evidence_index=index)
    probes.append(_probe(
        "citations-that-resolve-are-support",
        supported["supported"] == len(ve.DUE_DILIGENCE_SECTIONS)
        and supported["unsupported"] == 0,
        f"{supported['supported']} section(s) supported against an evidence index of "
        f"{len(index)} record(s)"))

    broken = dict(cited)
    broken["fips_claims"] = {"value": "FIPS 140-3", "evidence": ["VD-missing"]}
    audit_broken = ve.audit_due_diligence_evidence(broken, evidence_index=index)
    probes.append(_probe(
        "a-citation-that-does-not-resolve-is-not-support",
        audit_broken["counts"]["UNRESOLVED"] == 1,
        "fips_claims cites VD-missing, which is not in the evidence index, so the section is "
        "UNRESOLVED rather than supported"))

    ledger = ve.partial_ledger(audit["ledger"])
    probes.append(_probe(
        "every-uncited-section-is-a-listed-partial",
        ledger["partial_count"] == len(ve.DUE_DILIGENCE_SECTIONS) and ledger["dropped"] == 0,
        f"{ledger['partial_count']} partial(s) enumerated, none dropped, none renderable as a "
        "pass"))

    return {"id": "due_diligence_evidence",
            "question": "is a due-diligence section filled in, or supported?",
            "phase": "9", "probes": probes}


# --------------------------------------------------------------------------- #
# 6. end to end: a log line to a defensible VBOM row
# --------------------------------------------------------------------------- #


def row_end_to_end(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    rs, ru, ua, ve, vb = modules["rs"], modules["ru"], modules["ua"], modules["ve"], modules["vb"]
    probes = []

    loaded = rs.load_sessions(ZEEK)
    summary = ru.ingest_sessions(rs.records_for_ingest(loaded), asset_id="HSM-001",
                                 vendor="Vendor-X", product="HSM-X500",
                                 product_version="8.4.0")
    claims = ru.to_claims(summary, product=ve.ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"))
    attribution = ua.attribute_sessions(
        rs.records_for_ingest(loaded),
        [ua.Endpoint("10.0.0.5", asset_id="HSM-001", applications=("Payments API",))],
        default_asset_id="HSM-001")

    generator = vb.VbomGenerator()
    block = ve.add_claims(generator, {"id": "vendor-x", "name": "Vendor-X"}, claims,
                          systems=[{"system_id": "SYS-1", "system_name": "Payment System",
                                    "dependency_type": "PROVIDER"}])
    row = next(item for item in block["crypto"] if item["algorithm"] == "ML-KEM-768")
    probes.append(_probe(
        "a-log-line-becomes-a-vbom-row",
        row["verification_status"] == ve.VerificationStatus.RUNTIME_OBSERVED_ONLY.value
        and row["pqc_ready"] is True and len(row["evidence_ids"]) == 12,
        f"{row['algorithm']} in the vendor block from {len(row['evidence_ids'])} session "
        f"citation(s), status {row['verification_status']}"))

    ml_kem = next(claim for claim in claims if claim.algorithm == "ML-KEM-768")
    probes.append(_probe(
        "the-row-traces-back-to-a-named-session",
        all(item.reference.startswith("session:") for item in ml_kem.evidence)
        and ml_kem.evidence[0].reference in {f"session:C{index}" for index in range(12)},
        f"every citation names a session id from the log ({ml_kem.evidence[0].reference}, …) "
        "rather than a document that restates the conclusion"))

    coverage = ve.evidence_backed_pqc_coverage(generator.vendors())
    probes.append(_probe(
        "the-coverage-statement-says-which-tick-is-backed",
        coverage["pqc_declared_only"] == 0
        and coverage["pqc_evidence_backed"] == coverage["pqc_ready"] == 1,
        f"{coverage['pqc_ready']} post-quantum tick, {coverage['pqc_evidence_backed']} "
        f"evidence-backed ({coverage['backed_algorithms']}) and "
        f"{coverage['pqc_declared_only']} resting on a declaration"))

    probes.append(_probe(
        "the-workload-behind-the-tick-is-named-or-not-claimed",
        attribution["counts"]["ATTRIBUTED"] == 1
        and attribution["applications"] == ["Payments API"],
        f"{attribution['statement']} — so the row can say which workload, or say that it "
        "cannot"))

    document = generator.to_document()
    serialised = json.dumps(document)
    probes.append(_probe(
        "the-document-carries-the-verdict-not-just-the-algorithm",
        "RUNTIME_OBSERVED_ONLY" in serialised and "ML-KEM-768" in serialised
        and "VE-" in serialised,
        f"{len(serialised)} bytes of VBOM document carrying the algorithm, the verification "
        "status and an evidence id"))

    return {"id": "end_to_end",
            "question": "can one log line be followed all the way to a VBOM row somebody can "
                        "defend?",
            "phase": "6/11/13", "probes": probes}


ROWS = (row_log_readers, row_workload_attribution, row_sbom_sub_vendors, row_alias_overrides,
        row_due_diligence_evidence, row_end_to_end)


# --------------------------------------------------------------------------- #
# measure + render
# --------------------------------------------------------------------------- #


def _check_policy() -> dict[str, int]:
    """`--check` exit codes: a partial is not a pass."""
    return {"pass": 0, "partial": 1, "fail": 2}


def measure(as_of: date | None = None) -> dict[str, Any]:
    as_of = as_of or datetime.now(timezone.utc).date()
    modules = _load_modules()
    rows = []
    for builder in ROWS:
        row = builder(modules, as_of)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = PARTIAL
        else:
            verdict = FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "counts": counts,
        "rows": rows,
        "check_policy": _check_policy(),
        "limits": [
            "the logs are fixtures written by this file. The readers are graded against the "
            "column names, separators and absent-value conventions those formats use, not "
            "against a bank's own parser quirks",
            "attribution matches host and port exactly after normalisation. A NAT, a proxy or "
            "a load balancer between the session and the appliance will produce UNATTRIBUTED "
            "peers, which is the honest answer and not a defect to work around",
            "a shared appliance hosting several applications is reported AMBIGUOUS. Splitting "
            "that further needs an application-level audit trail this module does not have",
            "sub-vendor edges come from CycloneDX supplier metadata. A supplier field that is "
            "wrong makes the edge wrong; the citation is there so the claim can be checked "
            "against the vendor's own SBOM",
            "the alias table is validated but its content is a judgement: a bank that aliases "
            "MYCIPHER-1 to AES-128 has asserted that, and the audit trail is the reviewed file",
            "a due-diligence citation is checked for resolution only when the caller supplies "
            "an evidence index; without one, SUPPORTED means 'cites something', not 'cites "
            "something that exists'",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The evidence pipeline: from a log line to a VBOM row",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail**",
        "",
        "Guides 130 and 131 built an evidence model and then closed the gaps that model named "
        "against itself. What neither showed is the part a bank actually runs: **the logs it "
        "already keeps, joined to the register it already has, producing a row somebody can "
        "defend in a review.** That is this artifact.",
        "",
        "| | what it adds |",
        "|---|---|",
        "| `log_readers` | Zeek `ssl.log`, a CSV export and an access log with `$ssl_cipher` "
        "appended become session records; a key-material column refuses the file and a file "
        "that yields nothing raises instead of reporting calm |",
        "| `workload_attribution` | peers are joined to a register: one endpoint and one "
        "application is `ATTRIBUTED`, a shared appliance is `AMBIGUOUS` with both named, an "
        "unregistered peer is `UNATTRIBUTED`, and the remainder stays in the workload table |",
        "| `sbom_sub_vendors` | a CycloneDX `supplier` becomes a sub-vendor edge cited to the "
        "component; a component with no supplier is listed, never inferred |",
        "| `alias_overrides` | a bank may add spellings, may not redefine builtins, and gets "
        "an unfilled review stub for the names nobody recognises |",
        "| `due_diligence_evidence` | the twenty-two-section check can say COMPLETE while the "
        "evidence audit says nothing is supported — both answers are printed |",
        "| `end_to_end` | one log line, through decode, attribution, claim, VBOM row and "
        "coverage statement, with each hop asserted |",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (review item {row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines += [
        "",
        "## What is still missing",
        "",
        "1. **A live collector.** The readers take text. Something has to ship the log — a "
        "file drop, a syslog forwarder, a read-only mount — and that deployment is where the "
        "metadata-only rule is enforced a third time (after the reader and the decoder).",
        "2. **Application-level attribution on shared appliances.** Splitting an `AMBIGUOUS` "
        "peer needs a per-application audit trail (a PKCS#11 log with a process id, a mTLS "
        "client certificate per workload), which is a connector, not a matcher.",
        "3. **Transitive sub-vendor discovery.** Edges come from one SBOM's supplier fields. "
        "Following a vendor's own SBOM to its suppliers is the next hop, and it needs the "
        "vendor to publish one.",
        "4. **A signed alias table.** The file is reviewed and validated; it is not signed, so "
        "its provenance is a process rather than a proof.",
        "5. **Prose answers.** A questionnaire that answers in paragraphs, rather than "
        "`Label: value` lines or a table, is still read only where a label is recognisable.",
        "",
        "## How to run it",
        "",
        "```bash",
        "python scripts/vendor_evidence_pipeline.py --as-of 2026-11-02 \\",
        "    --json docs/bank-environment/132-vendor-evidence-pipeline.json \\",
        "    --md docs/bank-environment/132-vendor-evidence-pipeline.md",
        "python scripts/vendor_evidence_pipeline.py --check   # non-zero on FAIL or PARTIAL",
        "```",
        "",
    ]
    return "\n".join(textwrap.dedent(line) if line.startswith("    ") else line
                     for line in lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--as-of", type=date.fromisoformat, default=None,
                        help="the date to measure freshness and applicability against")
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero when any row is not PASS")
    args = parser.parse_args(argv)

    report = measure(args.as_of)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail",
          file=sys.stderr)
    if not args.check:
        return 0
    if counts[FAIL]:
        return _check_policy()["fail"]
    if counts[PARTIAL]:
        return _check_policy()["partial"]
    return _check_policy()["pass"]


if __name__ == "__main__":
    raise SystemExit(main())
