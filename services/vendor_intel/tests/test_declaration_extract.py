"""Reading a vendor document: every field cited, nothing invented, PDF or text."""

from __future__ import annotations

import zlib
from datetime import date

import pytest

from vendor_intel.declaration_extract import (
    ExtractionError,
    extract_declaration,
    parse_fields,
    split_algorithms,
)
from vendor_intel.pdf_text import PdfTextError, extract_text
from vendor_intel.vendor_evidence import (
    Applicability,
    ProductIdentity,
    assess_applicability,
)

QUESTIONNAIRE = """\
Vendor: Vendor-X
Product: HSM-X500
Version: 8.2.1
Crypto profile version: 3.1
Issued: 2026-06-01
Valid until: 2027-06-01
Supported algorithms: AES-256, RSA-3072, ML-DSA-65 and Dilithium3
PQC roadmap: ML-DSA in production since 2026-03
"""

TABLE = """\
| Questionnaire item | Response |
|---|---|
| Vendor name | Vendor-X |
| Product | HSM-X500 |
| Firmware version | 8.2.1 |
| Cryptographic algorithms | AES256; ML-DSA-65 |
"""


def _pdf(lines: list[bytes], *, flate: bool = True) -> bytes:
    body = b"BT /F1 9 Tf 72 720 Td " + b" ".join(
        b"(" + line.replace(b"(", b"\\(").replace(b")", b"\\)") + b") Tj 0 -14 Td "
        for line in lines) + b"ET"
    stream = zlib.compress(body) if flate else body
    return (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(stream)).encode()
            + (b" /Filter /FlateDecode" if flate else b"") + b" >>\nstream\n"
            + stream + b"\nendstream\nendobj\ntrailer<<>>\n%%EOF")


def test_every_field_carries_the_line_it_came_from():
    result = extract_declaration(QUESTIONNAIRE, document="doc:vendor-x/questionnaire-2026")
    declaration = result["declaration"]
    assert declaration.identity.vendor == "Vendor-X"
    assert declaration.identity.product == "HSM-X500"
    assert declaration.identity.version == "8.2.1"
    assert declaration.identity.crypto_profile_version == "3.1"
    assert declaration.issued_at == date(2026, 6, 1)
    fields = result["fields"]
    assert fields["version"]["line"] == 3
    assert len(fields["version"]["line_hash"]) == 16
    assert result["document_hash"] == result["document_hash"].lower()


def test_a_markdown_table_is_read_like_a_questionnaire():
    result = extract_declaration(TABLE, document="doc:table")
    assert result["declaration"].identity.version == "8.2.1"
    assert result["algorithms"]["canonical"] == ["AES-256", "ML-DSA-65"]


def test_extraction_is_not_approval():
    result = extract_declaration(QUESTIONNAIRE, document="doc:vendor-x/questionnaire-2026")
    assert result["requires_review"] is True
    assert result["declaration"].requires_review is True
    assert result["declaration"].evidence_type == "IMPORTED"


def test_a_missing_version_is_a_partial_not_a_guess():
    text = "Vendor: Vendor-X\nProduct: HSM-X500\nSupported algorithms: AES-256\n"
    result = extract_declaration(text, document="doc:unversioned")
    assert result["complete"] is False
    assert result["missing"] == ["version"]
    declaration = result["declaration"]
    assert declaration.identity.version is None
    verdict = assess_applicability(
        declaration, ProductIdentity("Vendor-X", "HSM-X500", "8.4.0"),
        as_of=date(2026, 11, 2))
    assert verdict.state is Applicability.UNKNOWN
    assert verdict.applicable is False


def test_a_document_without_a_vendor_cannot_become_a_declaration():
    text = "Product: HSM-X500\nVersion: 8.4.0\n"
    with pytest.raises(ExtractionError) as raised:
        extract_declaration(text, document="doc:anonymous")
    assert "vendor" in str(raised.value)
    soft = extract_declaration(text, document="doc:anonymous", strict=False)
    assert soft["declaration"] is None
    assert "vendor" in soft["missing"]


def test_algorithms_are_canonicalised_and_the_unknown_ones_are_named():
    result = extract_declaration(QUESTIONNAIRE, document="doc:vendor-x/questionnaire-2026")
    canonical = result["algorithms"]["canonical"]
    assert canonical == ["AES-256", "RSA-3072", "ML-DSA-65"]
    # ``Dilithium3`` is the pre-standard name for ``ML-DSA-65``; both spellings are
    # kept so the document can be quoted, and only one identity is counted.
    assert result["algorithms"]["spellings"]["ML-DSA-65"] == ["ML-DSA-65", "Dilithium3"]
    text = "Vendor: V\nProduct: P\nVersion: 1.0\nSupported algorithms: AES-256, FOO-256\n"
    result = extract_declaration(text, document="doc:unknown-name")
    assert result["algorithms"]["unknown"] == ["FOO-256"]
    assert "outside the alias table" in result["statement"]


def test_a_pdf_text_layer_is_read():
    data = _pdf([b"Vendor: Vendor-X", b"Product: HSM-X500", b"Version: 8.2.1",
                 b"Supported algorithms: AES-256, ML-DSA-65"])
    text = extract_text(data)
    result = extract_declaration(text, document="doc:vendor-x/questionnaire.pdf")
    assert result["declaration"].identity.version == "8.2.1"
    assert result["algorithms"]["canonical"] == ["AES-256", "ML-DSA-65"]


def test_an_uncompressed_pdf_is_read_too():
    data = _pdf([b"Vendor: Vendor-X", b"Product: HSM-X500", b"Version: 8.4.0"], flate=False)
    assert "8.4.0" in extract_text(data)


def test_an_encrypted_pdf_is_refused_with_a_reason():
    with pytest.raises(PdfTextError) as raised:
        extract_text(b"%PDF-1.7\n/Encrypt 4 0 R\nstream\nx\nendstream")
    assert "encrypted" in str(raised.value)


def test_a_scanned_page_is_a_document_to_send_back():
    with pytest.raises(PdfTextError) as raised:
        extract_text(_pdf([]))
    assert "scanned" in str(raised.value)


def test_a_file_that_is_not_a_pdf_is_named_as_such():
    with pytest.raises(PdfTextError) as raised:
        extract_text(b"Vendor: Vendor-X\n")
    assert "not a PDF" in str(raised.value)
    with pytest.raises(PdfTextError):
        extract_text(b"")


def test_an_empty_document_is_not_an_empty_declaration():
    with pytest.raises(ExtractionError):
        extract_declaration("   \n\n", document="doc:blank")
    with pytest.raises(ExtractionError):
        extract_declaration("Vendor: V\nProduct: P\nVersion: 1.0\n", document="")


def test_algorithm_lists_survive_the_separators_vendors_use():
    assert split_algorithms("AES-256, RSA-3072; ML-DSA-65 and Dilithium3") == [
        "AES-256", "RSA-3072", "ML-DSA-65", "Dilithium3"]
    assert split_algorithms("None") == []


def test_prose_is_not_read_as_a_field():
    text = ("The appliance supports AES-256 in all modes.\n"
            "Vendor: Vendor-X\nProduct: HSM-X500\nVersion: 8.2.1\n")
    fields = parse_fields(text)
    assert "vendor" in fields
    assert fields["vendor"].line_number == 2
    assert "algorithms" not in fields
