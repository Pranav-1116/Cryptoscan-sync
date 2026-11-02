"""Read a vendor questionnaire into a declaration, with a citation per field.

The gap this closes is the first one in guide 130's own list: *the declarations
were fixtures*. This module takes the text of a vendor's security questionnaire
— ``Label: value`` lines, a Markdown table, or the text layer of a PDF — and
produces a :class:`~vendor_intel.vendor_evidence.VendorDeclaration` whose every
field carries the line it came from and the hash of that line.

Three behaviours matter more than the parsing:

**Nothing is invented.** A field the document does not contain is absent from
the result and named in ``missing``. There is no default version, no assumed
vendor, and no "the vendor obviously means 8.4".

**Partial is a state, not a failure.** A questionnaire that names the vendor and
the product but not the firmware version produces a declaration with
``version=None``, which the existing applicability gate already refuses to match
— so the gap shows up as ``UNKNOWN`` applicability instead of a guess.

**Extraction is not approval.** Every result says ``requires_review: True``. The
evidence type is ``IMPORTED``, never ``DECLARED`` and never ``OBSERVED``: a
machine read the document, and a person has not yet confirmed it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable, Mapping

from vendor_intel.algorithm_names import algorithm_identity

SCHEMA = "cryptoscan.declaration-extract/1"

#: Label aliases, lower-cased and stripped of punctuation by :func:`_label`.
FIELDS: dict[str, tuple[str, ...]] = {
    "vendor": ("vendor", "vendor name", "manufacturer", "supplier", "company"),
    "product": ("product", "product name", "solution", "appliance", "platform"),
    "version": ("version", "firmware version", "firmware", "product version",
                "software version", "sw version"),
    "revision": ("revision", "build", "build number"),
    "crypto_profile_version": ("crypto profile version", "crypto profile",
                               "profile version", "cryptographic profile version"),
    "algorithms": ("algorithms", "supported algorithms", "crypto capabilities",
                   "cryptographic algorithms", "supported ciphers",
                   "cryptographic capabilities", "crypto"),
    "issued_at": ("issued", "issued at", "date", "questionnaire date", "document date",
                  "completed on", "completed"),
    "valid_until": ("valid until", "valid through", "expires", "review by",
                    "next review"),
    "pqc": ("pqc", "post-quantum", "post quantum", "pqc roadmap",
            "post-quantum roadmap", "pqc status"),
}

#: Fields without which no declaration can be attached to anything.
IDENTITY_FIELDS: tuple[str, ...] = ("vendor", "product", "version")

_TABLE_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
_SEPARATOR = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]*$")
_SPLIT = re.compile(r"[,;]|\band\b|/", re.IGNORECASE)


class ExtractionError(ValueError):
    """The document does not contain enough to be a declaration."""


@dataclass(frozen=True)
class ExtractedField:
    """One value, the line it came from, and that line's hash."""

    field: str
    value: str
    line_number: int
    line_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "value": self.value,
                "line": self.line_number, "line_hash": self.line_hash}


def _label(text: str) -> str:
    return re.sub(r"[^a-z ]", "", text.strip().lower()).strip()


_LABEL_INDEX: dict[str, str] = {
    alias: field for field, aliases in FIELDS.items() for alias in aliases
}


def _split_line(line: str) -> tuple[str, str] | None:
    """``(label, value)`` from a table row or a ``Label: value`` line."""
    table = _TABLE_ROW.match(line)
    if table:
        cells = [cell.strip() for cell in table.group(1).split("|")]
        if len(cells) >= 2 and cells[0] and cells[1]:
            return cells[0], cells[1]
        return None
    if ":" in line:
        label, _, value = line.partition(":")
        if label.strip() and value.strip():
            return label, value
    return None


def parse_fields(text: str) -> dict[str, ExtractedField]:
    """Every recognised field, first occurrence wins, each with its citation."""
    found: dict[str, ExtractedField] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if _SEPARATOR.match(line):
            continue
        parts = _split_line(line)
        if parts is None:
            continue
        label, value = parts
        field = _LABEL_INDEX.get(_label(label))
        if field is None or field in found:
            continue
        found[field] = ExtractedField(
            field=field, value=value.strip(), line_number=number,
            line_hash=hashlib.sha256(line.strip().encode()).hexdigest()[:16])
    return found


def split_algorithms(value: str) -> list[str]:
    """The algorithm names in one field value, in document order, de-duplicated."""
    names: list[str] = []
    for token in _SPLIT.split(value):
        token = token.strip(" .()[]")
        if not token or token.lower() in {"none", "n/a", "na", "yes", "no"}:
            continue
        if not re.search(r"[a-z]", token, re.IGNORECASE):
            continue
        if token not in names:
            names.append(token)
    return names


def extract_declaration(text: str, *, document: str, vendor: str | None = None,
                        product: str | None = None, issued_at: Any = None,
                        strict: bool = True, evidence_type: str = "IMPORTED") -> dict[str, Any]:
    """Read a questionnaire into a declaration plus its provenance.

    ``strict`` raises :class:`ExtractionError` when the vendor or product is
    missing, because no declaration can exist without them. A missing *version*
    is not an error: it is returned as a partial declaration that the
    applicability gate will refuse to match.
    """
    from vendor_intel.vendor_evidence import ProductIdentity, VendorDeclaration

    if not str(text or "").strip():
        raise ExtractionError("the document contains no text to extract")
    if not str(document or "").strip():
        raise ExtractionError("extraction needs a document reference to cite")

    fields = parse_fields(text)
    values = {name: field.value for name, field in fields.items()}
    resolved_vendor = vendor or values.get("vendor")
    resolved_product = product or values.get("product")

    missing = [name for name in IDENTITY_FIELDS if not _stated(name, values, vendor, product)]
    algorithms_raw = split_algorithms(values.get("algorithms", ""))
    algorithms: list[str] = []
    spellings: dict[str, list[str]] = {}
    unknown_algorithms: list[str] = []
    for name in algorithms_raw:
        try:
            identity = algorithm_identity(name)
        except ValueError:
            continue
        if identity.canonical not in algorithms:
            algorithms.append(identity.canonical)
        spellings.setdefault(identity.canonical, []).append(name)
        if not identity.recognised:
            unknown_algorithms.append(name)

    if not resolved_vendor or not resolved_product:
        if strict:
            raise ExtractionError(
                "the document names no "
                + ("vendor" if not resolved_vendor else "product")
                + "; a declaration needs both, and guessing either would attach a claim to "
                "the wrong supplier")
        declaration = None
    else:
        identity_obj = ProductIdentity(
            vendor=resolved_vendor, product=resolved_product,
            version=values.get("version"), revision=values.get("revision"),
            crypto_profile_version=values.get("crypto_profile_version"))
        declaration = VendorDeclaration(
            identity=identity_obj,
            document=document,
            issued_at=_date_or_none(values.get("issued_at") or issued_at),
            valid_until=_date_or_none(values.get("valid_until")),
            capabilities=tuple(algorithms),
            evidence_type=evidence_type,
            requires_review=True,
        )

    document_hash = hashlib.sha256(text.encode()).hexdigest()
    return {
        "schema": SCHEMA,
        "document": document,
        "document_hash": document_hash,
        "fields": {name: field.to_dict() for name, field in sorted(fields.items())},
        "algorithms": {"declared": algorithms_raw, "canonical": algorithms,
                       "spellings": spellings, "unknown": unknown_algorithms},
        "missing": missing,
        "complete": not missing,
        "requires_review": True,
        "declaration": declaration,
        "statement": _statement(document, declaration, missing, algorithms_raw, unknown_algorithms),
    }


def _stated(name: str, values: Mapping[str, str], vendor: str | None, product: str | None) -> bool:
    if name == "vendor" and vendor:
        return True
    if name == "product" and product:
        return True
    return bool(values.get(name))


def _date_or_none(value: Any) -> date | None:
    if not value:
        return None
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    for parser in (date.fromisoformat, lambda item: date.fromisoformat(item[:10])):
        try:
            return parser(text)
        except ValueError:
            continue
    return None


def _statement(document: str, declaration: Any, missing: Iterable[str],
               raw: Iterable[str], unknown: Iterable[str]) -> str:
    if declaration is None:
        return (f"{document}: no declaration could be built because "
                f"{', '.join(missing)} is absent — the document is filed, not interpreted")
    text = (f"{document}: {len(list(raw))} algorithm(s) read for "
            f"{declaration.identity.vendor} {declaration.identity.product} "
            f"{declaration.identity.version or '(no version stated)'}; "
            "imported by machine and awaiting review")
    missing = list(missing)
    if missing:
        text += f"; missing {', '.join(missing)}"
    unknown = list(unknown)
    if unknown:
        text += (f"; {len(unknown)} name(s) are outside the alias table "
                 f"({', '.join(unknown)}) and are carried verbatim")
    return text
