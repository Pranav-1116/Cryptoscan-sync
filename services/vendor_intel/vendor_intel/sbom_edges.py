"""Sub-vendor edges out of a CycloneDX SBOM, with the citation attached.

A crypto SDK that embeds a second vendor's library is a dependency the bank
never contracted for, and the only record of it is usually the SBOM the SDK
shipped. This module turns that SBOM into :class:`SubVendorEdge` rows for
:mod:`vendor_intel.vendor_evidence`, and it is deliberately narrow about what
it will believe:

* the child vendor comes from **``supplier.name``, then ``publisher``, then
  ``group``** — never from the component's own name. "openssl-wrapper" is a
  product name, not a supplier, and inferring a vendor from a name is how a BOM
  grows dependencies nobody can trace;
* a component with no supplier field is listed under ``unattributed`` with its
  reason, not quietly attached to the parent vendor or left out;
* a component whose supplier is the parent vendor is a *self-edge* and is
  reported as such rather than becoming a cycle the chain builder has to refuse;
* every edge cites the SBOM and the component reference, so the edge can be
  argued with.

The output feeds :func:`vendor_intel.vendor_evidence.vendor_footprint`, which
counts what was bought directly apart from what arrives through an embed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.sbom-edges/1"

#: In order of trust. ``supplier`` is a CycloneDX field with a defined meaning;
#: ``publisher`` and ``group`` are heuristics and are labelled as such in the
#: evidence reference so a reviewer can weigh them.
SUPPLIER_FIELDS: tuple[str, ...] = ("supplier", "publisher", "group")


class SbomShapeError(ValueError):
    """The document is not a CycloneDX BOM this reader can use."""


@dataclass(frozen=True)
class ComponentVendor:
    """One component, and who the SBOM says supplies it."""

    component: str
    version: str | None
    purl: str | None
    bom_ref: str | None
    vendor: str | None
    vendor_field: str | None
    is_pqc_relevant: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"component": self.component, "version": self.version, "purl": self.purl,
                "bom_ref": self.bom_ref, "vendor": self.vendor,
                "vendor_field": self.vendor_field,
                "pqc_relevant": self.is_pqc_relevant}


def _text(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("name")
    text = str(value or "").strip()
    return text or None


def component_vendor(component: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """``(vendor, which field said so)`` — or ``(None, None)`` rather than a guess."""
    for field in SUPPLIER_FIELDS:
        vendor = _text(component.get(field))
        if vendor:
            return vendor, field
    return None, None


def read_components(bom: Mapping[str, Any]) -> list[ComponentVendor]:
    """Every component in the BOM, with the supplier field that named its vendor."""
    if not isinstance(bom, Mapping):
        raise SbomShapeError("a CycloneDX BOM is a JSON object")
    if str(bom.get("bomFormat") or "").lower() not in {"cyclonedx", ""}:
        raise SbomShapeError(f"not a CycloneDX BOM: bomFormat={bom.get('bomFormat')!r}")
    components = bom.get("components") or []
    if not isinstance(components, Sequence) or isinstance(components, (str, bytes)):
        raise SbomShapeError("'components' must be a list")
    rows: list[ComponentVendor] = []
    for component in components:
        if not isinstance(component, Mapping):
            continue
        name = _text(component.get("name"))
        if not name:
            continue
        vendor, field = component_vendor(component)
        rows.append(ComponentVendor(
            component=name,
            version=_text(component.get("version")),
            purl=_text(component.get("purl")),
            bom_ref=_text(component.get("bom-ref")) or _text(component.get("bomRef")),
            vendor=vendor,
            vendor_field=field,
            is_pqc_relevant=bool((component.get("cryptoProperties") or {})
                                 .get("assetType")),
        ))
    return rows


def vendor_edges_from_cyclonedx(bom: Mapping[str, Any], *, parent_vendor: str,
                                parent_product: str | None = None,
                                observed_at: date | None = None,
                                evidence_factory: Any = None) -> dict[str, Any]:
    """Sub-vendor edges for one BOM, with everything that could not be one.

    ``evidence_factory`` is ``vendor_evidence.Evidence``, passed in so this
    module never has to import the model it feeds.
    """
    if not str(parent_vendor or "").strip():
        raise SbomShapeError("a BOM belongs to a product, and the product has a vendor")
    serial = _text(bom.get("serialNumber"))
    subject = bom.get("metadata", {}).get("component", {}) if isinstance(
        bom.get("metadata"), Mapping) else {}
    product = parent_product or _text(subject.get("name")) or "unknown-product"
    document = f"sbom:{serial or _text(subject.get('bom-ref')) or 'unserialised'}"

    components = read_components(bom)
    edges: list[Any] = []
    self_edges: list[dict[str, Any]] = []
    unattributed: list[dict[str, Any]] = []
    duplicates: list[str] = []
    seen: set[tuple[str, str]] = set()

    for component in components:
        if component.vendor is None:
            unattributed.append({
                "component": component.component, "version": component.version,
                "reason": ("the component carries no supplier, publisher or group; a component "
                           "name is not a vendor and this reader does not infer one")})
            continue
        if _norm(component.vendor) == _norm(parent_vendor):
            self_edges.append({"component": component.component,
                               "reason": "supplied by the BOM's own vendor: not a sub-vendor"})
            continue
        key = (_norm(component.vendor), _norm(component.component))
        if key in seen:
            duplicates.append(component.component)
            continue
        seen.add(key)
        reference = f"{document}#{component.bom_ref or component.purl or component.component}"
        evidence = None
        if evidence_factory is not None:
            evidence = evidence_factory(
                "IMPORTED", reference, observed_at=observed_at, source_document=document)
        edges.append({
            "child_vendor": component.vendor,
            "child_product": (f"{component.component} {component.version}".strip()
                              if component.version else component.component),
            "vendor_field": component.vendor_field,
            "reference": reference,
            "evidence": evidence,
        })
    return {
        "schema": SCHEMA,
        "document": document,
        "parent_vendor": parent_vendor,
        "parent_product": product,
        "components": len(components),
        "edges": edges,
        "self_edges": self_edges,
        "unattributed": unattributed,
        "duplicates": duplicates,
        "statement": _statement(parent_vendor, components, edges, self_edges, unattributed),
    }


def _norm(value: Any) -> str:
    return "".join(str(value or "").split()).upper()


def _statement(parent_vendor: str, components: Iterable[Any], edges: Sequence[Mapping[str, Any]],
               self_edges: Sequence[Mapping[str, Any]],
               unattributed: Sequence[Mapping[str, Any]]) -> str:
    components = list(components)
    vendors = sorted({edge["child_vendor"] for edge in edges})
    if not edges:
        return (f"{len(components)} component(s) read for {parent_vendor} and no sub-vendor edge "
                "follows: that is a gap in the SBOM's supplier metadata, not evidence that "
                "nothing is embedded")
    return (f"{len(edges)} sub-vendor edge(s) for {parent_vendor} from {len(components)} "
            f"component(s): {', '.join(vendors)}"
            + (f"; {len(unattributed)} component(s) name no supplier" if unattributed else "")
            + (f"; {len(self_edges)} are the parent's own components"
               if self_edges else ""))


def edges_for_footprint(report: Mapping[str, Any], *, edge_factory: Any) -> list[Any]:
    """``SubVendorEdge`` rows for :func:`vendor_evidence.vendor_footprint`."""
    rows = []
    for edge in report.get("edges") or ():
        rows.append(edge_factory(
            parent_vendor=report["parent_vendor"],
            parent_product=report["parent_product"],
            child_vendor=edge["child_vendor"],
            child_product=edge["child_product"],
            relationship="EMBEDDED_COMPONENT",
            evidence=edge["evidence"],
        ))
    return rows
