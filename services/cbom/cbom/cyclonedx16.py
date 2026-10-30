"""Native CycloneDX 1.6 JSON metadata profile and offline full-schema validation.

Not an attestation: schema validity does not prove discovery, dependency runtime
usage, correct crypto, FIPS validation or replacement interoperability. Legacy
CryptoScan fields are projected to named properties, never smuggled into the
standard cryptoProperties shape. Raw finding payloads and secret values are not
part of this allowlisted metadata profile. XML remains the legacy serializer.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7
from shared_models.algorithm_registry import parse_algorithm

try:  # a URI format rule, not the profile itself
    from rfc3986_validator import validate_rfc3986
except ModuleNotFoundError:  # pragma: no cover - exercised by test_cyclonedx_validator_absent
    validate_rfc3986 = None  # type: ignore[assignment]


class ValidationUnavailable(RuntimeError):
    """The document was not judged: a check the profile needs could not be loaded.

    Raised rather than returning ``ok=False``, because "invalid" and "not
    evaluated" are different answers. A caller that records the second as the
    first would reject a sound document, and a caller that records it as valid
    would accept an unchecked one.
    """


UNAVAILABLE_PACKAGES = {"rfc3986_validator": "rfc3986-validator"}


def unavailable_reason() -> str | None:
    """Why validation cannot run here, or ``None`` when every check is present."""
    if validate_rfc3986 is None:
        return (
            "rfc3986-validator is not installed, so a URI-typed CycloneDX field cannot be "
            "checked: the document's validity is NOT_EVALUATED, not invalid"
        )
    return None

SCHEMA_DIR = Path(__file__).parent / "validators/schema/cyclonedx-1.6"
# Pinned upstream tag1.6, commit55343ba19dee1785acf1ce9191540d5fd7b590db.
# Constants prevent a missing/corrupted/edited schema from becoming a green check.
SCHEMA_HASHES = {
    "bom-1.6.schema.json": "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93",
    "spdx.schema.json": "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}
CONTEXT_FIELDS = (
    "application", "owner", "data_classification", "retention_years", "criticality",
    "exposure", "purpose", "library", "system", "system_id", "confidence", "asset_key",
    "source_basis", "reported_confidence",
)
SAFE_PROPERTIES = {f"cryptoscan:{key}" for key in CONTEXT_FIELDS} | {
    "cryptoscan:reported_algorithm", "cryptoscan:reported_key_size", "cryptoscan:reported_mode",
    "cryptoscan:reported_padding", "cryptoscan:deployment_readiness", "cryptoscan:business_context",
    "cryptoscan:import_source_basis", "cryptoscan:import_document_sha256",
    "cryptoscan:import_parameter_set_identifier", "cryptoscan:import_key_size_basis",
}

from shared_models.host_collection import HostEvidenceRef
SAFE_PROPERTIES |= {f"cryptoscan:host:{field}" for field in HostEvidenceRef.model_fields}


def _validator() -> Draft7Validator:
    resources = []
    schema = None
    for name, expected in SCHEMA_HASHES.items():
        raw = (SCHEMA_DIR / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("schema integrity failure")
        data = json.loads(raw)
        if name == "bom-1.6.schema.json":
            schema = data
        resource = Resource.from_contents(data, default_specification=DRAFT7)
        for uri in (f"http://cyclonedx.org/schema/{name}", f"https://cyclonedx.org/schema/{name}"):
            resources.append((uri, resource))
    # No retrieve callback: references outside this registry fail, never fetch.
    checker = FormatChecker()
    # FormatChecker otherwise silently accepts unknown formats when optional
    # packages are absent. JSF algorithm is oneOf(JWA enum, URI), so accepting
    # "HS256" as a URI incorrectly rejects every standard signed document.
    @checker.checks("uri")
    def absolute_uri(value):
        return not isinstance(value, str) or bool(validate_rfc3986(value, rule="URI"))

    @checker.checks("date-time")
    def date_time(value):
        if not isinstance(value, str):
            return True
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value, re.I):
            return False
        try:
            return datetime.fromisoformat(value.upper().replace("Z", "+00:00")).tzinfo is not None
        except ValueError:
            return False
    return Draft7Validator(schema, registry=Registry().with_resources(resources), format_checker=checker)


def validate_cyclonedx16(bom: Any) -> dict[str, Any]:
    basis = "CYCLONEDX_1_6_OFFICIAL_SCHEMA_AND_REFERENCES"
    missing = unavailable_reason()
    if missing:
        raise ValidationUnavailable(missing)
    errors = []
    try:
        validator = _validator()
        for error in validator.iter_errors(bom):
            # Do not copy invalid instance values/raw content into error output.
            path = "/".join(str(p) for p in error.absolute_path) or "$"
            errors.append(f"{path}: violates {error.validator}")
        if not errors:
            if bom.get("specVersion") != "1.6":
                errors.append("specVersion: expected1.6")
            refs: set[str] = set()
            def collect(component):
                ref = component.get("bom-ref")
                if ref:
                    if ref in refs:
                        errors.append("duplicate bom-ref")
                    refs.add(ref)
                for child in component.get("components", []):
                    collect(child)
            collect(bom.get("metadata", {}).get("component", {}))
            for component in bom.get("components", []):
                collect(component)
            for dependency in bom.get("dependencies", []):
                if dependency["ref"] not in refs or any(c not in refs for c in dependency.get("dependsOn", [])):
                    errors.append("dependencies: dangling component reference")
            for composition in bom.get("compositions", []):
                for field in ("assemblies", "dependencies"):
                    if any(c not in refs for c in composition.get(field, [])):
                        errors.append("compositions: dangling component reference")
    except (OSError, ValueError, TypeError, RecursionError):
        errors.append("official schema unavailable, invalid or integrity check failed")
    return {"ok": not errors, "errors": errors, "warnings": [], "validation_basis": basis,
            "bank_approved": False, "discovery_completeness_proven": False}


def _property(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": str(value)}


def to_cyclonedx16(bom: dict, *, omit_inventory_dependencies: bool = False) -> dict:
    """Project the existing generator's metadata into the official1.6 shape.

    This deliberately does not copy arbitrary evidence, external custom fields,
    claims, key values, certificate bodies or arbitrary user property names.
    Relations retained from legacy sources remain source assertions, not proven
    runtime or replacement-compatibility edges. The caller can omit the legacy
    generator's invented inventory root fanout.
    """
    meta = bom.get("metadata") or {}
    root = meta.get("component") or {}
    properties = [copy.deepcopy(p) for p in meta.get("properties", [])
                  if p.get("name") in {"cryptoscan:scope", "cryptoscan:systems", "cryptoscan:assets",
                    "cryptoscan:truncated", "cryptoscan:asset_limit", "cryptoscan:assets_total", "cryptoscan:source_basis",
                    "cryptoscan:retained_mixed_evidence_assets", "cryptoscan:inventory_completeness"}]
    properties += [_property("cryptoscan:discovery_completeness", "NOT_PROVEN"),
                   _property("cryptoscan:dependency_basis", "SOURCE_RELATIONSHIPS_NOT_RUNTIME_OR_REPLACEMENT_PROOF"),
                   _property("cryptoscan:profile", "ALLOWLISTED_CRYPTO_METADATA_NO_SECRET_VALUES")]
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": bom.get("version", 1),
        "metadata": {"component": {k: copy.deepcopy(v) for k, v in root.items()
                                    if k in {"type", "name", "version", "bom-ref"}}, "properties": properties},
        "components": [],
    }
    scan_refs = [ref for ref in bom.get("externalReferences", [])
                 if ref.get("type") == "provenance" and re.fullmatch(r"urn:cryptoscan:scan:[A-Za-z0-9_.:-]+", ref.get("url", ""))]
    if scan_refs:
        document["metadata"]["properties"] += [_property("cryptoscan:source_scan", ref["url"]) for ref in scan_refs]
    for field in ("timestamp", "tools"):
        if field in meta:
            document["metadata"][field] = copy.deepcopy(meta[field])
    if bom.get("serialNumber"):
        document["serialNumber"] = bom["serialNumber"]
    by_ref: dict[str, dict] = {}
    for old in bom.get("components", []):
        component = {k: copy.deepcopy(v) for k, v in old.items() if k in {"type", "name", "version", "bom-ref"}}
        props = [copy.deepcopy(p) for p in old.get("properties", []) if p.get("name") in SAFE_PROPERTIES]
        crypto = old.get("cryptoProperties")
        if crypto:
            reported = crypto.get("algorithmProperties") or {}
            algorithm = str(reported.get("algorithm") or old.get("name") or "UNKNOWN")
            info = parse_algorithm(algorithm)
            family = {"aead": "ae", "kem-pqc": "kem", "signature-pqc": "signature", "kem-hybrid-pqc": "combiner"}.get(info.family, info.family)
            primitives = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}
            algorithms = {"primitive": family if info.recognized and family in primitives else "unknown"}
            if reported.get("parameterSetIdentifier") is not None:
                algorithms["parameterSetIdentifier"] = str(reported["parameterSetIdentifier"])
                props.append(_property("cryptoscan:reported_key_size", reported["parameterSetIdentifier"]))
            # FIPS parameter-set names are not public-key byte counts. The
            # legacy key_size field has no trustworthy unit provenance.
            parameter_set = re.fullmatch(r"ML-(?:KEM|DSA)-(\d+)", info.canonical)
            slh_set = re.fullmatch(r"SLH-DSA-(SHA2|SHAKE)-(128|192|256)([sf])", info.canonical)
            if info.family in {"kem-pqc", "signature-pqc", "kem-hybrid-pqc"}:
                algorithms.pop("parameterSetIdentifier", None)
                if parameter_set:
                    algorithms["parameterSetIdentifier"] = parameter_set.group(1)
                elif slh_set:
                    algorithms["parameterSetIdentifier"] = "-".join(slh_set.groups()[:2]) + slh_set.group(3)
                if reported.get("parameterSetIdentifier") is not None:
                    props.append(_property("cryptoscan:reported_key_size_basis", "REPORTED_UNIT_NOT_ESTABLISHED"))
            for field, allowed in (("mode", {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}),
                                   ("padding", {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"})):
                if reported.get(field):
                    raw = str(reported[field])
                    algorithms[field] = raw.lower() if raw.lower() in allowed else "other"
                    props.append(_property(f"cryptoscan:reported_{field}", raw))
            props += [_property("cryptoscan:reported_algorithm", algorithm),
                      _property("cryptoscan:deployment_readiness", "NOT_ESTABLISHED")]
            component["cryptoProperties"] = {"assetType": crypto.get("assetType", "algorithm")}
            if component["cryptoProperties"]["assetType"] == "algorithm":
                component["cryptoProperties"]["algorithmProperties"] = algorithms
            # The old OID table contains family/variant ambiguities. Do not
            # manufacture an exact algorithm OID or certification in this profile.
        context = {p["name"].removeprefix("cryptoscan:"): p["value"] for p in props
                   if p["name"].removeprefix("cryptoscan:") in CONTEXT_FIELDS}
        if context:
            declaration = _property("cryptoscan:business_context", json.dumps(context, sort_keys=True))
            if declaration not in props:
                props.append(declaration)
        if props:
            component["properties"] = props
        evidence = old.get("evidence") or {}
        occurrences = []
        for occurrence in evidence.get("occurrences") or ([{"location": evidence.get("file"), "line": evidence.get("line")}] if evidence.get("file") else []):
            if not occurrence.get("location"):
                continue
            item = {"location": str(occurrence["location"])}
            if type(occurrence.get("line")) is int and occurrence["line"] > 0:
                item["line"] = occurrence["line"]
            occurrences.append(item)
        if occurrences:
            component["evidence"] = {"occurrences": occurrences}
        ref = component.get("bom-ref")
        if ref and ref in by_ref:
            existing = by_ref[ref]
            identity = lambda c: {k: v for k, v in c.items() if k not in {"properties", "evidence"}}
            if identity(existing) != identity(component):
                raise ValueError("Conflicting component identity for shared bom-ref")
            for prop in component.get("properties", []):
                if prop not in existing.setdefault("properties", []):
                    existing["properties"].append(prop)
            for occurrence in component.get("evidence", {}).get("occurrences", []):
                occurrences = existing.setdefault("evidence", {}).setdefault("occurrences", [])
                if occurrence not in occurrences:
                    occurrences.append(occurrence)
        else:
            document["components"].append(component)
            if ref:
                by_ref[ref] = component
    refs = [c["bom-ref"] for c in document["components"] if c.get("bom-ref")]
    document["compositions"] = [{"aggregate": "incomplete", "assemblies": refs}]
    if bom.get("dependencies") and not omit_inventory_dependencies:
        document["dependencies"] = copy.deepcopy(bom["dependencies"])
    check = validate_cyclonedx16(document)
    if not check["ok"]:
        raise ValueError("CycloneDX1.6 export failed validation: " + "; ".join(check["errors"][:10]))
    return document
