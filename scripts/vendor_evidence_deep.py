#!/usr/bin/env python3
"""Guide 131 — vendor evidence, second pass: the five gaps guide 130 named.

Guide 130 ended with a list of what it could not prove: vendor documents were
fixtures, identity had one axis, algorithm matching was string-exact, runtime
usage was a word rather than an evidence type, and vendor→vendor chains did not
exist. This script grades the work that closes those five, plus the two places
where the *evidence* had not yet reached the VBOM document itself.

Every row is executed against the modules in `services/vendor_intel`. Nothing
here is a claim about a real vendor: the questionnaire is written by this file,
the PDF is built by this file, and the session transcript is a fixture. What is
real is the code path — a PDF text layer is inflated and parsed, a cipher suite
is decomposed, an alias table resolves two spellings to one identity, and a
vendor that versions its crypto profile apart from its firmware is refused.

`--check` exits non-zero on a FAIL *or* a PARTIAL: a partial is not a pass, and
this artifact is about not rounding them.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import zlib
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
DOCS = ROOT / "docs" / "bank-environment"
SCHEMA = "cryptoscan.vendor-evidence-guide/2"

PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"


def _load_modules() -> dict[str, Any]:
    for entry in (str(SERVICES / "vendor_intel"), str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from vendor_intel import algorithm_names as an  # noqa: PLC0415
    from vendor_intel import declaration_extract as dx  # noqa: PLC0415
    from vendor_intel import pdf_text as pt  # noqa: PLC0415
    from vendor_intel import runtime_usage as ru  # noqa: PLC0415
    from vendor_intel import vbom as vb  # noqa: PLC0415
    from vendor_intel import vendor_evidence as ve  # noqa: PLC0415
    return {"ve": ve, "an": an, "dx": dx, "pt": pt, "ru": ru, "vb": vb}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _raises(expected: type[BaseException], call: Any) -> bool:
    try:
        call()
    except expected:
        return True
    except Exception:  # noqa: BLE001 - a different exception is a different failure
        return False
    return False


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

DECLARED_VERSION = "8.4.0"
PROFILE_VERSION = "3.1"
AS_OF_DEFAULT = date(2026, 11, 2)

QUESTIONNAIRE = """\
Vendor: Vendor-X
Product: HSM-X500
Version: 8.4.0
Crypto profile version: 3.1
Issued: 2026-06-01
Valid until: 2027-06-01
Supported algorithms: AES-256, RSA-3072, ML-DSA-65 and Dilithium3
PQC roadmap: ML-DSA in production since 2026-03
"""

SESSION_SUITE = "TLS_AES_256_GCM_SHA384"
SESSION_GROUP = "x25519mlkem768"


def _sessions(count: int = 12) -> list[dict[str, Any]]:
    return [{"session_id": f"S-{index}", "started_at": "2026-10-01",
             "peer": "10.0.0.5:443", "cipher_suite": SESSION_SUITE,
             "group": SESSION_GROUP} for index in range(count)]


def _pdf(lines: list[str], *, flate: bool = True) -> bytes:
    body = b"BT /F1 9 Tf 72 720 Td " + b" ".join(
        b"(" + line.encode().replace(b"(", b"\\(").replace(b")", b"\\)") + b") Tj 0 -14 Td "
        for line in lines) + b"ET"
    stream = zlib.compress(body) if flate else body
    return (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(stream)).encode()
            + (b" /Filter /FlateDecode" if flate else b"")
            + b" >>\nstream\n" + stream + b"\nendstream\nendobj\ntrailer<<>>\n%%EOF")


def _declaration(ve: Any, *, version: str = DECLARED_VERSION,
                 profile: str | None = PROFILE_VERSION) -> Any:
    return ve.VendorDeclaration(
        ve.ProductIdentity("Vendor-X", "HSM-X500", version, crypto_profile_version=profile),
        "doc:vendor-x/hsm-x500-crypto-profile-8.4",
        issued_at=date(2026, 6, 1), capabilities=("AES-256", "RSA-3072", "ML-DSA-65"),
        evidence_type="IMPORTED")


def _identity(ve: Any, *, profile: str | None = PROFILE_VERSION) -> Any:
    return ve.ProductIdentity("Vendor-X", "HSM-X500", DECLARED_VERSION,
                              crypto_profile_version=profile)


# --------------------------------------------------------------------------- #
# 1. algorithm identity
# --------------------------------------------------------------------------- #


def row_algorithm_identity(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    an = modules["an"]
    ve = modules["ve"]
    probes = []

    spellings = ["AES256", "aes_256", "AES 256", "AES-256"]
    canonicals = {an.algorithm_identity(name).canonical for name in spellings}
    probes.append(_probe(
        "one-algorithm-four-spellings", canonicals == {"AES-256"},
        f"{len(spellings)} spellings -> {sorted(canonicals)}; "
        f"'AES256' normalised={an.algorithm_identity('AES256').normalised}"))

    size = an.compare_algorithms("AES-128", "AES-256")
    probes.append(_probe(
        "a-size-is-not-a-spelling", size["relation"] == "DIFFERENT_PARAMETER",
        f"AES-128 against AES-256 -> {size['relation']}: {size['reason']}"))

    mode = an.compare_algorithms("AES-256", "AES-256-GCM")
    probes.append(_probe(
        "a-missing-mode-is-less-specific-not-wrong", mode["relation"] == "LESS_SPECIFIC",
        f"AES-256 against AES-256-GCM -> {mode['relation']}, so it reconciles PARTIAL, "
        "not CONFLICT"))

    families = an.compare_algorithms("3DES", "AES-256")["relation"]
    params = an.compare_algorithms("AES-256-GCM", "AES-256-CBC")["relation"]
    probes.append(_probe(
        "two-families-and-two-modes-are-never-merged",
        families == "DIFFERENT_ALGORITHM" and params == "DIFFERENT_MODE",
        f"3DES/AES-256 -> {families}, AES-256-GCM/AES-256-CBC -> {params}"))

    legacy = an.algorithm_identity("Dilithium3")
    probes.append(_probe(
        "the-pre-standard-pqc-name-resolves", legacy.canonical == "ML-DSA-65" and legacy.pqc,
        f"Dilithium3 -> {legacy.canonical} (pqc={legacy.pqc}); "
        f"KYBER768 -> {an.algorithm_identity('KYBER768').canonical}"))

    unknown = an.algorithm_identity("FOO256")
    summary = an.identity_summary(["AES256", "ML-DSA-65", "FOO-256"])
    probes.append(_probe(
        "an-unknown-name-is-flagged-not-invented",
        unknown.recognised is False and summary["unrecognised"] == ["FOO-256"],
        f"FOO-256 parses by shape with recognised=False; summary names "
        f"{summary['unrecognised']} as outside the alias table"))

    report = ve.reconcile_algorithms(
        "aes", {"vendor": "AES256", "runtime": "AES-256"},
        sources={"vendor": ve.EvidenceType.DECLARED, "runtime": ve.EvidenceType.RUNTIME_OBSERVED})
    probes.append(_probe(
        "the-reconciler-uses-the-table-and-records-it",
        report["state"] == "AGREE" and report["normalisation_applied"]
        and "normalised, not rewritten" in report["statement"],
        f"vendor=AES256 runtime=AES-256 -> {report['state']} on {report['canonical']}, "
        f"normalisation recorded={report['normalisation_applied']}"))

    return {"id": "algorithm_identity",
            "question": "does the VBOM tell two spellings of one algorithm from two algorithms?",
            "phase": "15", "probes": probes}


# --------------------------------------------------------------------------- #
# 2. the second identity axis
# --------------------------------------------------------------------------- #


def row_profile_axis(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    ve = modules["ve"]
    probes = []

    mismatch = ve.assess_applicability(
        _declaration(ve, profile="3.0"), _identity(ve, profile="3.1"), as_of=as_of)
    probes.append(_probe(
        "firmware-agrees-and-the-profile-does-not",
        mismatch.state is ve.Applicability.VERSION_MISMATCH and mismatch.axis == "crypto_profile",
        f"firmware 8.4.0/8.4.0 but profile 3.0/3.1 -> {mismatch.state.value} on axis "
        f"{mismatch.axis}: {mismatch.reasons[0]}"))

    unverified = ve.assess_applicability(
        _declaration(ve, profile=PROFILE_VERSION), _identity(ve, profile=None), as_of=as_of)
    probes.append(_probe(
        "an-unobserved-profile-leaves-the-answer-partial",
        unverified.state is ve.Applicability.PARTIAL_MATCH,
        f"profile 3.1 declared, none observed -> {unverified.state.value} "
        f"({unverified.axes}); the declaration cannot be quoted as a full match"))

    matched = ve.assess_applicability(
        _declaration(ve, profile=PROFILE_VERSION), _identity(ve, profile="3.1.0"), as_of=as_of)
    probes.append(_probe(
        "matched-needs-both-axes", matched.state is ve.Applicability.MATCHED
        and matched.axes == {"product_version": "EXACT", "crypto_profile": "MATCH"},
        f"both axes agree -> {matched.state.value} {matched.axes}"))

    firmware = ve.assess_applicability(
        _declaration(ve, version="8.2.1", profile="3.0"), _identity(ve, profile="3.1"),
        as_of=as_of)
    probes.append(_probe(
        "a-firmware-mismatch-is-not-blamed-on-the-profile",
        firmware.state is ve.Applicability.VERSION_MISMATCH
        and firmware.axis == "product_version",
        f"declared 8.2.1 profile 3.0 against deployed 8.4.0 profile 3.1 -> "
        f"{firmware.state.value} on axis {firmware.axis}"))

    original = ve._profile_axis
    try:
        ve._profile_axis = lambda declared, observed: {"state": "MATCH", "reason": ""}  # noqa: ARG005
        forced = ve.claims_from_declaration(
            _declaration(ve, profile="3.0"), _identity(ve, profile="3.1"),
            asset_id="HSM-001", as_of=as_of)
    finally:
        ve._profile_axis = original
    lit = [claim.algorithm for claim in forced if claim.vendor_declared]
    probes.append(_probe(
        "the-axis-is-what-withholds-the-capability",
        bool(lit) and len(lit) == 3,
        f"with the profile axis replaced by a constant MATCH the same document lights "
        f"{len(lit)} capability(ies) ({', '.join(lit)}) on an appliance whose profile "
        "differs — so the refusal is the gate, not this paragraph"))

    return {"id": "profile_axis",
            "question": "when a vendor versions its crypto profile apart from its firmware, "
                        "does the gate still hold?",
            "phase": "7/8", "probes": probes}


# --------------------------------------------------------------------------- #
# 3. document extraction
# --------------------------------------------------------------------------- #


def row_document_extraction(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    dx = modules["dx"]
    pt = modules["pt"]
    ve = modules["ve"]
    probes = []

    result = dx.extract_declaration(QUESTIONNAIRE, document="doc:vendor-x/questionnaire-2026")
    fields = result["fields"]
    probes.append(_probe(
        "a-questionnaire-is-read-with-a-citation-per-field",
        result["declaration"].identity.version == DECLARED_VERSION
        and fields["version"]["line"] == 3 and len(fields["version"]["line_hash"]) == 16,
        f"{len(fields)} field(s) with line numbers and line hashes; version from line "
        f"{fields['version']['line']}, profile {result['declaration'].identity.crypto_profile_version}"))

    pdf = _pdf([line for line in QUESTIONNAIRE.strip().splitlines()])
    from_pdf = dx.extract_declaration(pt.extract_text(pdf), document="doc:vendor-x/questionnaire.pdf")
    probes.append(_probe(
        "a-pdf-text-layer-is-read",
        from_pdf["declaration"].identity.version == DECLARED_VERSION
        and from_pdf["algorithms"]["canonical"] == ["AES-256", "RSA-3072", "ML-DSA-65"],
        f"{len(pdf)} bytes of PDF -> version {from_pdf['declaration'].identity.version}, "
        f"{len(from_pdf['algorithms']['canonical'])} canonical algorithm(s)"))

    encrypted = _raises(pt.PdfTextError, lambda: pt.extract_text(
        b"%PDF-1.7\n/Encrypt 4 0 R\nstream\nx\nendstream"))
    scanned = _raises(pt.PdfTextError, lambda: pt.extract_text(_pdf([])))
    not_pdf = _raises(pt.PdfTextError, lambda: pt.extract_text(b"Vendor: Vendor-X\n"))
    probes.append(_probe(
        "an-encrypted-or-scanned-document-is-refused-with-its-reason",
        encrypted and scanned and not_pdf,
        "three refusals rather than an empty string: encrypted (no text layer), scanned "
        "(no text layer, OCR or a text copy needed), not-a-PDF"))

    unversioned = dx.extract_declaration(
        "Vendor: Vendor-X\nProduct: HSM-X500\nSupported algorithms: AES-256\n",
        document="doc:vendor-x/unversioned")
    verdict = ve.assess_applicability(unversioned["declaration"], _identity(ve), as_of=as_of)
    probes.append(_probe(
        "a-missing-version-stays-unknown",
        unversioned["complete"] is False and unversioned["missing"] == ["version"]
        and verdict.state is ve.Applicability.UNKNOWN,
        f"missing={unversioned['missing']} -> applicability {verdict.state.value}, so the "
        "document is filed and cannot be quoted"))

    probes.append(_probe(
        "extraction-is-not-approval",
        result["requires_review"] is True and result["declaration"].evidence_type == "IMPORTED",
        f"evidence_type={result['declaration'].evidence_type}, requires_review={result['requires_review']} — "
        "a machine read it, a person has not confirmed it"))

    anonymous = _raises(dx.ExtractionError, lambda: dx.extract_declaration(
        "Product: HSM-X500\nVersion: 8.4.0\n", document="doc:anonymous"))
    probes.append(_probe(
        "a-document-with-no-vendor-cannot-become-a-declaration", anonymous,
        "no vendor -> refused rather than attached to whatever supplier is nearest"))

    return {"id": "document_extraction",
            "question": "is a vendor questionnaire read, or still a fixture?",
            "phase": "9", "probes": probes}


# --------------------------------------------------------------------------- #
# 4. runtime usage evidence
# --------------------------------------------------------------------------- #


def row_runtime_usage(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    ru = modules["ru"]
    ve = modules["ve"]
    probes = []

    summary = ru.ingest_sessions(_sessions(), asset_id="HSM-001", vendor="Vendor-X",
                                 product="HSM-X500", product_version=DECLARED_VERSION)
    claims = ru.to_claims(summary, product=_identity(ve))
    aes = next(claim for claim in claims if claim.algorithm == "AES-256-GCM")
    probes.append(_probe(
        "a-session-becomes-a-claim-with-one-citation-per-session",
        len(aes.evidence) == 12 and aes.verification_status is ve.VerificationStatus.RUNTIME_OBSERVED_ONLY,
        f"12 sessions -> {aes.algorithm} with {len(aes.evidence)} citation(s), status "
        f"{aes.verification_status.value}, confidence {aes.confidence}"))

    pqc = summary["pqc_primitives"]
    probes.append(_probe(
        "a-hybrid-group-means-post-quantum-was-actually-used",
        pqc == ["ML-KEM-768"] and summary["pqc_used"],
        f"group x25519mlkem768 -> {pqc}: key establishment, observed, not declared"))

    mystery = ru.decode_cipher_suite("TLS_MYSTERY_SHA256")
    probes.append(_probe(
        "an-unknown-suite-is-named-not-guessed",
        mystery["known"] is False and mystery["primitives"] == [],
        f"TLS_MYSTERY_SHA256 -> known=False, primitives=[], reason: {mystery['reason']}"))

    refused = _raises(ru.PayloadRefused, lambda: ru.ingest_sessions(
        [_sessions(1)[0] | {"payload": "deadbeef"}], asset_id="HSM-001"))
    key_refused = _raises(ru.PayloadRefused, lambda: ru.ingest_sessions(
        [_sessions(1)[0] | {"premaster_secret": "00"}], asset_id="HSM-001"))
    probes.append(_probe(
        "payload-and-key-material-are-refused-by-name", refused and key_refused,
        "a record carrying 'payload' or 'premaster_secret' is refused at ingestion — this "
        "reader holds metadata only"))

    one = ru.ingest_sessions(_sessions(1), asset_id="HSM-001")
    many = ru.ingest_sessions(_sessions(40), asset_id="HSM-001")
    probes.append(_probe(
        "one-session-and-forty-sessions-are-different-statements",
        one["primitives"][0]["confidence"] == "LOW"
        and many["primitives"][0]["confidence"] == "HIGH",
        f"1 session -> {one['primitives'][0]['confidence']}, 40 -> "
        f"{many['primitives'][0]['confidence']} for the same algorithm"))

    empty = ru.ingest_sessions([], asset_id="HSM-001")
    probes.append(_probe(
        "an-empty-transcript-is-not-an-all-clear", empty["sessions"] == 0
        and "not evidence of absence" in empty["statement"],
        empty["statement"]))

    undeclared = ve.reconcile_capabilities(claims, as_of=as_of)
    grouped = next(report for report in undeclared if report["algorithm"] == "AES-256-GCM")
    probes.append(_probe(
        "runtime-evidence-reaches-the-claim-flags",
        grouped["verification_status"] == ve.VerificationStatus.RUNTIME_OBSERVED_ONLY.value,
        f"the grouped capability reports {grouped['verification_status']}: observed at "
        "runtime, declared by nobody — a finding about the estate"))

    return {"id": "runtime_usage",
            "question": "does USAGE_OBSERVED exist as evidence, or only as a word?",
            "phase": "6", "probes": probes}


# --------------------------------------------------------------------------- #
# 5. vendor -> vendor chains
# --------------------------------------------------------------------------- #


def row_sub_vendor_chains(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    ve = modules["ve"]
    probes = []

    edge = ve.SubVendorEdge(
        "Vendor-X", "Crypto SDK 4.2", "Vendor-Z", "OpenSSL Wrapper 1.0",
        evidence=ve.Evidence(ve.EvidenceType.IMPORTED, "sbom:vendor-x/sdk-4.2", date(2026, 5, 1)))
    chain = ve.sub_vendor_chain("Vendor-X", [edge])
    probes.append(_probe(
        "a-sub-vendor-edge-carries-its-path-and-evidence",
        chain["depth"] == 1 and chain["vendors"][0]["path"] == ["Vendor-X", "Vendor-Z"]
        and chain["vendors"][0]["evidence_id"].startswith("VE-"),
        f"Vendor-X -> Vendor-Z at depth {chain['depth']}, cited by "
        f"{chain['vendors'][0]['evidence_id']}"))

    back = ve.SubVendorEdge("Vendor-Z", "Wrapper 1.0", "Vendor-X", "SDK 4.2")
    cycle = ve.sub_vendor_chain("Vendor-X", [edge, back])
    probes.append(_probe(
        "a-cycle-is-refused-rather-than-followed",
        len(cycle["cycles"]) == 1 and cycle["vendor_names"] == ["Vendor-Z"],
        f"two vendors that embed each other -> {len(cycle['cycles'])} cycle reported, "
        f"expansion stops at {cycle['vendor_names']}"))

    direct = ve.HardwareDependency(
        "HSM-001", ve.ProductIdentity("Vendor-X", "HSM-X500", DECLARED_VERSION),
        applications=("Payments API",), services=("Card Auth Service",),
        business_systems=("Payment System",), critical_systems=("Card Authorization",))
    inherited = ve.HardwareDependency(
        "HSM-009", ve.ProductIdentity("Vendor-Z", "HSA 9", "1.0"),
        applications=("Reporting",), business_systems=("Regulatory Reporting",))
    footprint = ve.vendor_footprint("Vendor-X", edges=[edge], assets=[direct, inherited])
    probes.append(_probe(
        "direct-and-indirect-exposure-are-counted-separately",
        footprint["direct"]["assets"] == ["HSM-001"]
        and footprint["indirect"]["assets"] == ["HSM-009"],
        f"1 appliance bought directly, 1 reached through Vendor-Z; "
        f"{footprint['statement']}"))

    self_edge = _raises(ValueError, lambda: ve.SubVendorEdge(
        "Vendor-X", "SDK 4.2", "vendor-x", "SDK 3.0"))
    probes.append(_probe(
        "a-vendor-cannot-embed-itself", self_edge,
        "a self-edge is refused at construction rather than producing a depth-2 chain "
        "back to the same supplier"))

    return {"id": "sub_vendor_chains",
            "question": "can the estate answer 'which systems depend on Vendor-X, including "
                        "through the vendors it embeds?'",
            "phase": "11/12", "probes": probes}


# --------------------------------------------------------------------------- #
# 6. the evidence reaches the VBOM document
# --------------------------------------------------------------------------- #


def _claims(modules: dict[str, Any], as_of: date) -> list[Any]:
    ve = modules["ve"]
    ru = modules["ru"]
    declared = ve.claims_from_declaration(_declaration(ve), _identity(ve),
                                          asset_id="HSM-001", as_of=as_of)
    summary = ru.ingest_sessions(_sessions(), asset_id="HSM-001", vendor="Vendor-X",
                                 product="HSM-X500", product_version=DECLARED_VERSION)
    observed = ru.to_claims(summary, product=_identity(ve))
    return list(declared) + list(observed)


def row_vbom_integration(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    ve = modules["ve"]
    vb = modules["vb"]
    probes = []

    claims = _claims(modules, as_of)
    generator = vb.VbomGenerator()
    block = ve.add_claims(generator, {"id": "vendor-x", "name": "Vendor-X"}, claims)
    row = block["crypto"][0]
    probes.append(_probe(
        "claims-feed-the-existing-generator-with-their-evidence",
        row["verification_status"] in {status.value for status in ve.VerificationStatus}
        and row["applicability"] == "MATCHED" and row["evidence_ids"],
        f"{len(block['crypto'])} row(s) in the vendor block; the first carries applicability "
        f"{row['applicability']}, status {row['verification_status']} and "
        f"{len(row['evidence_ids'])} evidence id(s)"))

    coverage = ve.evidence_backed_pqc_coverage(generator.vendors())
    probes.append(_probe(
        "pqc-coverage-and-evidence-backed-coverage-are-different-numbers",
        coverage["pqc_ready"] == coverage["pqc_evidence_backed"] + coverage["pqc_declared_only"]
        and coverage["pqc_declared_only"] > 0,
        f"{coverage['pqc_ready']} post-quantum tick(s), {coverage['pqc_evidence_backed']} "
        f"backed by observation ({coverage['backed_algorithms']}), "
        f"{coverage['pqc_declared_only']} resting on a declaration "
        f"({coverage['declared_only_algorithms']})"))

    summary = generator.summary()
    naive = summary["pqc_ready_entries"]
    probes.append(_probe(
        "the-document-cannot-print-one-green-number",
        naive == coverage["pqc_ready"] and naive != coverage["pqc_evidence_backed"],
        f"the generator's own summary reports {naive} of {summary['crypto_entries']} row(s) "
        f"post-quantum ready ({summary['pqc_ready_pct']}%); the evidence-backed count is "
        f"{coverage['pqc_evidence_backed']} — both numbers stay in the output on purpose"))

    return {"id": "vbom_integration",
            "question": "does the evidence reach the VBOM document, and does the PQC tick "
                        "keep its qualification?",
            "phase": "13", "probes": probes}


# --------------------------------------------------------------------------- #
# 7. the partial ledger
# --------------------------------------------------------------------------- #


def row_partial_ledger(modules: dict[str, Any], as_of: date) -> dict[str, Any]:
    ve = modules["ve"]
    probes = []

    partial = ve.assess_applicability(
        _declaration(ve, profile=PROFILE_VERSION), _identity(ve, profile=None), as_of=as_of)
    matched = ve.assess_applicability(_declaration(ve), _identity(ve), as_of=as_of)
    ledger = ve.partial_ledger([partial, matched,
                                {"state": "PARTIAL", "subject": "openssl"}])
    probes.append(_probe(
        "partials-are-enumerated-not-summarised",
        ledger["partial_count"] == 2 and ledger["total"] == 3 and ledger["entries"][0]["reasons"],
        f"{ledger['partial_count']} of {ledger['total']} answers are partial and each appears "
        f"with its reason; counts {ledger['counts']}"))

    probes.append(_probe(
        "no-partial-can-be-rendered-as-a-pass",
        all(entry["renderable_as_pass"] is False for entry in ledger["entries"])
        and ledger["dropped"] == 0,
        "every entry carries renderable_as_pass=False and dropped=0 — a partial is neither "
        "rounded up to green nor deleted"))

    clean = ve.partial_ledger([{"state": "MATCHED"}, {"state": "AGREE"}])
    probes.append(_probe(
        "a-clean-run-says-that-nothing-is-partial",
        clean["partial_count"] == 0 and "none of 2" in clean["statement"],
        clean["statement"]))

    probes.append(_probe(
        "the-check-fails-on-a-partial-as-well-as-on-a-failure",
        _check_policy() == {"pass": 0, "partial": 1, "fail": 2},
        "this artifact's --check exits 2 on FAIL and 1 on PARTIAL, so a partial row cannot "
        "be mistaken for a green artefact"))

    return {"id": "partial_ledger",
            "question": "is 'some, but not all' a state, or a rounding error?",
            "phase": "8/15", "probes": probes}


def _check_policy() -> dict[str, int]:
    """The exit codes `--check` uses, stated where the probe can read them."""
    return {"pass": 0, "partial": 1, "fail": 2}


ROWS = (row_algorithm_identity, row_profile_axis, row_document_extraction, row_runtime_usage,
        row_sub_vendor_chains, row_vbom_integration, row_partial_ledger)


# --------------------------------------------------------------------------- #
# measure + render
# --------------------------------------------------------------------------- #


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
            "no vendor was contacted. The questionnaire is written by this file and the PDF "
            "is built by this file, so what is graded is the reader, not a vendor's paperwork",
            "the PDF reader handles text layers only: encrypted files and scanned pages are "
            "refused with a reason, and object-stream or font-encoding edge cases are not "
            "implemented",
            "the alias table is finite and hand-written. A name outside it is carried "
            "verbatim and flagged; nothing is guessed, and a bank's own spelling has to be "
            "added deliberately",
            "the session transcript is a fixture shaped like a TLS session log. A live "
            "connector (a tap on the payment path, a PKCS#11 audit log) is still required to "
            "produce it, and that connector is where the metadata-only rule has to be enforced "
            "a second time",
            "sub-vendor edges are supplied by the bank from SBOMs and contracts; nothing here "
            "discovers that a vendor embeds another vendor's library",
            "runtime claims prove a primitive was exercised. They do not prove which "
            "application did it: application attribution still comes from the dependency "
            "records in guide 130",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Vendor evidence, second pass: closing the five gaps",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · as of "
        f"{report['as_of']} · **{counts[PASS]} pass · {counts[PARTIAL]} partial · "
        f"{counts[FAIL]} fail**",
        "",
        "Guide 130 ended with five things it could not prove, and said so. This artifact is "
        "the work that closes them, and it is deliberately harder to satisfy than the first: "
        "a PDF is actually inflated and parsed, a cipher suite is actually decomposed, and "
        "the second identity axis is exercised with a negative control that would light every "
        "capability if the gate were a sentence instead of code.",
        "",
        "| What guide 130 could not prove | What this artifact does instead |",
        "|---|---|",
        "| vendor documents were fixtures | a questionnaire — text, Markdown table or PDF text "
        "layer — is read with a line number and a line hash per field |",
        "| identity had one axis | `crypto_profile_version` is a second axis, and an "
        "unobserved profile leaves the answer `PARTIAL_MATCH` instead of `MATCHED` |",
        "| reconciliation was string-exact | an alias table resolves `AES256`, `aes_256` and "
        "`Dilithium3` while keeping `AES-128` and `AES-256-GCM` as different statements |",
        "| `USAGE_OBSERVED` was a word | a session transcript becomes claims with one "
        "citation per session, and a hybrid group is post-quantum use in the wild |",
        "| there were no vendor→vendor edges | a sub-vendor chain with depth, path, evidence "
        "and cycle refusal, and direct exposure counted apart from inherited exposure |",
        "",
        "Two further rows exist because the evidence had not yet reached the document: the "
        "existing `VbomGenerator` now accepts evidence-bearing rows, and every partial answer "
        "is enumerated in a ledger that cannot render it as a pass.",
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
        "1. **Vendor paperwork is still synthetic.** The reader is real; the document is not. "
        "A bank's first action with this module is to run it over the questionnaire it "
        "actually received, and to reject anything the extraction cannot cite.",
        "2. **No live runtime connector.** The transcript format is defined and the decoder "
        "is graded; producing the transcript from a payment path needs a tap or an audit-log "
        "reader, and that is the next piece of work rather than a parser tweak.",
        "3. **Brand new algorithm families.** The alias table knows the names in use today. A "
        "name it does not know is flagged, never resolved, so a new family is a code change "
        "rather than a silent mis-match.",
        "4. **Sub-vendor discovery.** Edges are asserted from SBOMs and contracts; transitive "
        "discovery from a vendor's own SBOM is not implemented.",
        "5. **Application attribution of runtime use.** A session proves a primitive was used; "
        "which application used it still comes from the dependency records.",
        "",
        "## How to run it",
        "",
        "```bash",
        "python scripts/vendor_evidence_deep.py --as-of 2026-11-02 \\",
        "    --json docs/bank-environment/131-vendor-evidence-deep.json \\",
        "    --md docs/bank-environment/131-vendor-evidence-deep.md",
        "python scripts/vendor_evidence_deep.py --check    # non-zero on FAIL or PARTIAL",
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
