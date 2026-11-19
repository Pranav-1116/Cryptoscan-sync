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

try:  # the upstream URI format rule, when the pinned package is installed
    from rfc3986_validator import validate_rfc3986 as _upstream_uri_rule
except ModuleNotFoundError:  # pragma: no cover - covered by the fallback test
    _upstream_uri_rule = None

# RFC 3986 absolute-URI shape: scheme ":" then no whitespace. The upstream rule
# is stricter about the URI grammar; this catches the errors a BOM actually
# carries (a bare name, a path with a space, a missing scheme).
_LOCAL_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$")


def _local_uri_rule(value: Any, rule: str = "URI") -> bool:  # noqa: ARG001 - upstream signature
    if not isinstance(value, str):
        return True
    return bool(_LOCAL_URI.match(value))


def uri_rule():
    """(callable, name) for the URI format check this process can run."""
    if _upstream_uri_rule is not None:
        return _upstream_uri_rule, "RFC3986_VALIDATOR_PACKAGE"
    return _local_uri_rule, "LOCAL_RFC3986_SHAPE_CHECK"


def uri_check_warning() -> str | None:
    """A stated substitution, or None when the pinned package is present.

    A missing format checker must not block an import (the operator would read an
    empty CBOM as "no cryptography"), and it must not pass silently either: the
    document is judged, with the URI rule named in the result.
    """
    if _upstream_uri_rule is not None:
        return None
    return (
        "rfc3986-validator is not installed: URI-typed fields were checked with the local "
        "RFC 3986 shape check, not the upstream package. Install the pinned dependencies "
        "for the exact upstream check"
    )

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
SAFE_PROPERTIES |= {
    "cryptoscan:reported_key_size_basis", "cryptoscan:classification", "cryptoscan:algorithm_family",
    "cryptoscan:primitive_basis", "cryptoscan:registry_status", "cryptoscan:registry_notes",
    "cryptoscan:standard", "cryptoscan:parameter_set_basis", "cryptoscan:parameter_facts",
    "cryptoscan:curve", "cryptoscan:curve_basis", "cryptoscan:security_level_basis",
    "cryptoscan:crypto_functions_basis", "cryptoscan:normalization_notes", "cryptoscan:deployment_stage",
    "cryptoscan:hardcoded_key", "cryptoscan:lifecycle_state", "cryptoscan:verification_status",
    "cryptoscan:occurrence_count", "cryptoscan:evidence_link_status", "cryptoscan:evidence_count",
    "cryptoscan:evidence_withheld", "cryptoscan:component_role", "cryptoscan:relationships",
    "cryptoscan:quantum_status", "cryptoscan:quantum_status_basis", "cryptoscan:algorithm_class",
    "cryptoscan:requires_review", "cryptoscan:technical_owner", "cryptoscan:security_owner",
}
#: Generated namespaces (values are produced by CryptoScan code, never copied
#: from arbitrary user properties): evidence chain, identity, ownership mapping,
#: risk, system/certificate/library provenance.
SAFE_PREFIXES = ("cryptoscan:evidence:", "cryptoscan:identity:", "cryptoscan:mapping_", "cryptoscan:risk:",
                 "cryptoscan:system:", "cryptoscan:certificate:", "cryptoscan:library:", "cryptoscan:tls:",
                 "cryptoscan:pqc:", "cryptoscan:relationship", "cryptoscan:runtime_", "cryptoscan:hsm:")


def _safe(name: Any) -> bool:
    return isinstance(name, str) and (name in SAFE_PROPERTIES or name.startswith(SAFE_PREFIXES))


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
    rule, _name = uri_rule()

    @checker.checks("uri")
    def absolute_uri(value):
        return bool(rule(value, rule="URI")) if _name == "RFC3986_VALIDATOR_PACKAGE" else rule(value)

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
                if dependency["ref"] not in refs or any(c not in refs for c in dependency.get("dependsOn", [])) \
                        or any(c not in refs for c in dependency.get("provides", [])):
                    errors.append("dependencies: dangling component reference")
            for composition in bom.get("compositions", []):
                for field in ("assemblies", "dependencies"):
                    if any(c not in refs for c in composition.get(field, [])):
                        errors.append("compositions: dangling component reference")
    except (OSError, ValueError, TypeError, RecursionError):
        errors.append("official schema unavailable, invalid or integrity check failed")
    _rule, rule_name = uri_rule()
    warning = uri_check_warning()
    return {"ok": not errors, "errors": errors, "warnings": [warning] if warning else [],
            "validation_basis": basis, "format_checks": {"uri": rule_name},
            "bank_approved": False, "discovery_completeness_proven": False}


def _property(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": str(value)}


#: Document-level metadata properties a source document may carry into 1.6.
_METADATA_PASSTHROUGH = {
    "cryptoscan:scope", "cryptoscan:systems", "cryptoscan:assets", "cryptoscan:truncated",
    "cryptoscan:asset_limit", "cryptoscan:assets_total", "cryptoscan:source_basis",
    "cryptoscan:retained_mixed_evidence_assets", "cryptoscan:inventory_completeness",
}
_METADATA_PREFIXES = ("cryptoscan:portfolio:", "cryptoscan:coverage", "cryptoscan:export:",
                      "cryptoscan:collection:", "cryptoscan:organization")
_OCCURRENCE_FIELDS = ("bom-ref", "location", "line", "offset", "symbol", "additionalContext")
_CONFIDENCE = {"HIGH": 0.9, "CONFIRMED": 0.9, "MEDIUM": 0.6, "LIKELY": 0.6, "LOW": 0.3, "TENTATIVE": 0.3}


def _json_prop(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return None
    try:
        return json.loads(value)
    except ValueError:
        return None


def _props_dict(props: list[dict[str, str]]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in props if isinstance(p, dict) and "name" in p}


def _algorithm_block(n: Any) -> dict[str, Any]:
    algorithm: dict[str, Any] = {"primitive": n.primitive if n.primitive in {
        "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
        "key-agree", "kem", "ae", "combiner", "other", "unknown"} else "unknown"}
    if n.parameter_set:
        algorithm["parameterSetIdentifier"] = n.parameter_set
    if n.curve:
        algorithm["curve"] = n.curve
    if n.mode:
        algorithm["mode"] = n.mode
    if n.padding:
        algorithm["padding"] = n.padding
    if n.crypto_functions:
        algorithm["cryptoFunctions"] = list(n.crypto_functions)
    if n.classical_level is not None:
        algorithm["classicalSecurityLevel"] = int(n.classical_level)
    if n.quantum_level is not None:
        algorithm["nistQuantumSecurityLevel"] = int(n.quantum_level)
    return algorithm


def to_cyclonedx16(bom: dict, *, omit_inventory_dependencies: bool = False) -> dict:
    """Project a CryptoScan BOM into the official 1.6 shape.

    Every cryptographic record goes through the CBOM normalization registry
    (:mod:`cbom.crypto_normalization`) — family, primitive, variant name, mode,
    parameter set, security levels, OID and classification are decided there,
    never per discovery engine. Placeholder rows are excluded (and counted);
    unrecognized names are kept but flagged as candidates. Protocols become
    ``assetType: protocol``. Certificates and keys keep their native blocks.

    This deliberately does not copy arbitrary evidence payloads, external
    custom fields, claims, key values, certificate bodies or arbitrary user
    property names. Relations remain source assertions with their stated
    basis, not runtime or replacement proof.
    """
    from cbom import crypto_risk
    from cbom.crypto_normalization import NORMALIZER_VERSION, deployment_stage, detection_technique, normalize

    meta = bom.get("metadata") or {}
    root = meta.get("component") or {}
    properties = [copy.deepcopy(p) for p in meta.get("properties", [])
                  if isinstance(p, dict) and (p.get("name") in _METADATA_PASSTHROUGH
                                              or str(p.get("name", "")).startswith(_METADATA_PREFIXES))]
    properties += [_property("cryptoscan:discovery_completeness", "NOT_PROVEN"),
                   _property("cryptoscan:dependency_basis", "SOURCE_RELATIONSHIPS_NOT_RUNTIME_OR_REPLACEMENT_PROOF"),
                   _property("cryptoscan:profile", "ALLOWLISTED_CRYPTO_METADATA_NO_SECRET_VALUES"),
                   _property("cryptoscan:normalizer_version", NORMALIZER_VERSION),
                   _property("cryptoscan:risk_model_version", crypto_risk.RISK_MODEL_VERSION)]
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": bom.get("version", 1),
        "metadata": {"component": {k: copy.deepcopy(v) for k, v in root.items()
                                    if k in {"type", "name", "version", "bom-ref", "description"}}, "properties": properties},
        "components": [],
    }
    scan_refs = [ref for ref in bom.get("externalReferences", [])
                 if ref.get("type") == "provenance" and re.fullmatch(r"urn:cryptoscan:scan:[A-Za-z0-9_.:-]+", ref.get("url", ""))]
    if scan_refs:
        document["metadata"]["properties"] += [_property("cryptoscan:source_scan", ref["url"]) for ref in scan_refs]
    for field in ("timestamp", "tools", "lifecycles", "manufacturer", "supplier"):
        if field in meta:
            document["metadata"][field] = copy.deepcopy(meta[field])
    if bom.get("serialNumber"):
        document["serialNumber"] = bom["serialNumber"]
    by_ref: dict[str, dict] = {}
    excluded: list[dict[str, str]] = []
    excluded_refs: set[str] = set()
    for old in bom.get("components", []):
        component = {k: copy.deepcopy(v) for k, v in old.items()
                     if k in {"type", "name", "version", "bom-ref", "description", "group", "purl"}}
        props = [copy.deepcopy(p) for p in old.get("properties", []) if isinstance(p, dict) and _safe(p.get("name"))]
        known = _props_dict(props)
        crypto = old.get("cryptoProperties")
        evidence = old.get("evidence") or {}
        locations = [o for o in (evidence.get("occurrences") or []) if isinstance(o, dict) and o.get("location")]
        location = (locations[0]["location"] if locations else evidence.get("file")) or None
        stage = known.get("cryptoscan:deployment_stage") or (deployment_stage(location, host_evidence=any(
            p["name"].startswith("cryptoscan:host:") for p in props)) if location else None)
        n = None
        if crypto:
            asset_type = crypto.get("assetType", "algorithm")
            if asset_type in {"certificate", "related-crypto-material"}:
                block_name = "certificateProperties" if asset_type == "certificate" else "relatedCryptoMaterialProperties"
                component["cryptoProperties"] = {"assetType": asset_type}
                if isinstance(crypto.get(block_name), dict):
                    component["cryptoProperties"][block_name] = copy.deepcopy(crypto[block_name])
                if crypto.get("oid"):
                    component["cryptoProperties"]["oid"] = str(crypto["oid"])
            else:
                reported = crypto.get("algorithmProperties") or {}
                algorithm = str(reported.get("algorithm") or known.get("cryptoscan:reported_algorithm") or old.get("name") or "UNKNOWN")
                n = normalize(algorithm, key_size=reported.get("parameterSetIdentifier"), mode=reported.get("mode"),
                              padding=reported.get("padding"), purpose=known.get("cryptoscan:purpose"),
                              curve=reported.get("curve") or known.get("cryptoscan:curve"), location=location,
                              confidence=known.get("cryptoscan:confidence"))
                if not n.exported:
                    ref = str(old.get("bom-ref") or "")
                    excluded_refs.add(ref)
                    excluded.append({"ref": ref, "recorded_algorithm": algorithm, "reason": n.exclusion_reason or ""})
                    continue
                component["name"] = n.name
                if known.get("cryptoscan:quantum_status_basis") == "UNRECOGNIZED_ALGORITHM" and \
                        n.classification != "UNRECOGNIZED_CANDIDATE" and n.asset_type == "algorithm":
                    # the legacy status table missed a spelling the registry
                    # normalizes (e.g. DHE): restate it from the normalized family
                    from cbom import pqc_handoff
                    stale = {"cryptoscan:quantum_status", "cryptoscan:quantum_status_basis",
                             "cryptoscan:algorithm_class", "cryptoscan:requires_review"}
                    restated = pqc_handoff.component_properties("DH" if n.family == "DHE" else n.name, n.key_size_bits)
                    if not any(q["value"] == "UNRECOGNIZED_ALGORITHM" for q in restated):
                        props = [q for q in props if q["name"] not in stale] + restated
                if n.asset_type == "protocol":
                    # a protocol's quantum posture is that of its negotiated
                    # algorithms; it is not an unrecognized algorithm
                    props = [q for q in props if q["name"] not in {"cryptoscan:quantum_status_basis", "cryptoscan:algorithm_class"}]
                    props += [_property("cryptoscan:quantum_status_basis", "PROTOCOL_DEPENDS_ON_NEGOTIATED_ALGORITHMS"),
                              _property("cryptoscan:algorithm_class", "PROTOCOL")]
                if reported.get("parameterSetIdentifier") is not None:
                    props.append(_property("cryptoscan:reported_key_size", reported["parameterSetIdentifier"]))
                    if n.family in {"ML-KEM", "ML-DSA", "SLH-DSA"} or n.primitive == "combiner":
                        basis = n.parameter_set_basis or ""
                        props.append(_property("cryptoscan:reported_key_size_basis",
                                               "PARAMETER_SET_IDENTIFIER_NOT_KEY_LENGTH" if basis.startswith("REPORTED_NUMBER_IS")
                                               else "REPORTED_UNIT_NOT_ESTABLISHED"))
                for field, value in (("mode", n.mode_reported), ("padding", n.padding_reported)):
                    if value:
                        props.append(_property(f"cryptoscan:reported_{field}", value))
                props += [_property("cryptoscan:reported_algorithm", algorithm),
                          _property("cryptoscan:deployment_readiness", "NOT_ESTABLISHED"),
                          _property("cryptoscan:classification", n.classification),
                          _property("cryptoscan:algorithm_family", n.family),
                          _property("cryptoscan:primitive_basis", n.primitive_basis),
                          _property("cryptoscan:registry_status", n.registry_status),
                          _property("cryptoscan:identity:algorithm", n.identity_key())]
                for name, value in (("cryptoscan:standard", n.standard), ("cryptoscan:parameter_set_basis", n.parameter_set_basis),
                                    ("cryptoscan:curve_basis", None if n.curve and n.curve_basis == "RECORDED_IN_EVIDENCE" else n.curve_basis),
                                    ("cryptoscan:security_level_basis", n.security_level_basis),
                                    ("cryptoscan:crypto_functions_basis", n.crypto_functions_basis),
                                    ("cryptoscan:registry_notes", n.registry_notes or None)):
                    if value:
                        props.append(_property(name, value))
                if n.parameter_facts:
                    props.append(_property("cryptoscan:parameter_facts", json.dumps(n.parameter_facts, sort_keys=True)))
                if n.notes:
                    props.append(_property("cryptoscan:normalization_notes", "; ".join(n.notes)))
                if n.asset_type == "protocol":
                    protocol: dict[str, Any] = {"type": n.protocol_type or "unknown"}
                    if n.protocol_version:
                        protocol["version"] = n.protocol_version
                    supplied = crypto.get("protocolProperties") if isinstance(crypto.get("protocolProperties"), dict) else {}
                    if supplied.get("cipherSuites"):
                        protocol["cipherSuites"] = copy.deepcopy(supplied["cipherSuites"])
                    elif n.parameter_facts.get("cipher_suite") or known.get("cryptoscan:evidence:cipher_suite"):
                        protocol["cipherSuites"] = [{"name": n.parameter_facts.get("cipher_suite")
                                                     or known["cryptoscan:evidence:cipher_suite"]}]
                    component["cryptoProperties"] = {"assetType": "protocol", "protocolProperties": protocol}
                else:
                    component["cryptoProperties"] = {"assetType": "algorithm", "algorithmProperties": _algorithm_block(n)}
                    if n.oid:
                        component["cryptoProperties"]["oid"] = n.oid
                tls_facts = _json_prop(known.get("cryptoscan:tls:observation"))
                tls_view = None
                if n.asset_type == "protocol" and n.family in {"TLS", "DTLS"} and isinstance(tls_facts, dict):
                    from cbom import tls_analysis
                    tls_view = tls_analysis.assess(
                        version=tls_facts.get("version") or (f"TLS {n.protocol_version}" if n.protocol_version else None),
                        cipher_suite=tls_facts.get("cipher_suite"), key_exchange=tls_facts.get("key_exchange"),
                        group=tls_facts.get("key_exchange_group"),
                        cert_public_key_algorithm=tls_facts.get("certificate_public_key_algorithm"),
                        cert_public_key_bits=tls_facts.get("certificate_public_key_bits"),
                        cert_curve=tls_facts.get("certificate_curve"),
                        cert_signature_algorithm=tls_facts.get("certificate_signature_algorithm"),
                        not_before=tls_facts.get("certificate_not_before"), not_after=tls_facts.get("certificate_not_after"),
                        self_signed=tls_facts.get("certificate_self_signed"),
                        chain_status=tls_facts.get("chain_status"), trust_status=tls_facts.get("trust_status"))
                    props.append(_property("cryptoscan:tls:assessment", json.dumps(tls_view, sort_keys=True)))
                if location or known.get("cryptoscan:component_role") != "ALGORITHM_REFERENCE":
                    risk = crypto_risk.assess(
                        n, purpose=known.get("cryptoscan:purpose"), criticality=known.get("cryptoscan:criticality"),
                        exposure=known.get("cryptoscan:exposure"), data_classification=known.get("cryptoscan:data_classification"),
                        retention_years=known.get("cryptoscan:retention_years"), confidence=known.get("cryptoscan:confidence"),
                        deployment_stage=stage, hardcoded_key=known.get("cryptoscan:hardcoded_key") == "true",
                        tls=tls_view, location=location)
                    dims = risk["dimensions"]
                    props += [_property("cryptoscan:risk:algorithm_risk", risk["algorithm_risk"]),
                              _property("cryptoscan:risk:priority", risk["priority"]),
                              _property("cryptoscan:risk:quantum_exposure", risk["quantum_exposure"]),
                              _property("cryptoscan:risk:finding_status", risk["finding_status"]),
                              _property("cryptoscan:risk:factors", json.dumps(risk["factors"], sort_keys=True)),
                              _property("cryptoscan:risk:summary", risk["summary"])]
                    props += [_property(f"cryptoscan:risk:{axis}", dims[axis]["level"]) for axis in dims]
                    props.append(_property("cryptoscan:risk:dimensions", json.dumps(dims, sort_keys=True)))
                    if dims["quantum"]["shor_exposed"]:
                        props.append(_property("cryptoscan:risk:shor_exposure", json.dumps(
                            {k: dims["quantum"][k] for k in ("mechanism", "curve", "curve_note") if k in dims["quantum"]},
                            sort_keys=True)))
                    if risk["reasons"]:
                        props.append(_property("cryptoscan:risk:reasons", json.dumps(risk["reasons"])))
                from cbom import pqc_deployment
                if pqc_deployment.is_pqc(n):
                    stages = [stage] if stage else []
                    negotiated = bool(isinstance(tls_facts, dict) and tls_facts.get("pqc_group_negotiated"))
                    # no production-approval record exists in the store, so
                    # APPROVED_FOR_PRODUCTION is never claimed from properties
                    ladder = pqc_deployment.stage_ladder(stages, negotiated=negotiated, approval_ref=None)
                    props += [_property("cryptoscan:pqc:highest_stage", ladder["highest_stage"]),
                              _property("cryptoscan:pqc:ready", "true" if ladder["pqc_ready"] else "false"),
                              _property("cryptoscan:pqc:ready_reason", ladder["reason"]),
                              _property("cryptoscan:pqc:stage_ladder", json.dumps(ladder["ladder"]))]
                if stage and "cryptoscan:deployment_stage" not in known:
                    props.append(_property("cryptoscan:deployment_stage", stage))
            # The old OID table contains family/variant ambiguities; only the
            # registry's fully-determined variants get an OID. No certification
            # level is ever manufactured.
        context = {p["name"].removeprefix("cryptoscan:"): p["value"] for p in props
                   if p["name"].removeprefix("cryptoscan:") in CONTEXT_FIELDS}
        if context:
            declaration = _property("cryptoscan:business_context", json.dumps(context, sort_keys=True))
            if declaration not in props:
                props.append(declaration)
        deduped: list[dict[str, str]] = []
        for prop in props:
            if prop not in deduped:
                deduped.append(prop)
        if deduped:
            component["properties"] = deduped
        occurrences = []
        for occurrence in evidence.get("occurrences") or ([{"location": evidence.get("file"), "line": evidence.get("line")}] if evidence.get("file") else []):
            if not isinstance(occurrence, dict) or not occurrence.get("location"):
                continue
            item: dict[str, Any] = {"location": str(occurrence["location"])}
            if type(occurrence.get("line")) is int and occurrence["line"] > 0:
                item["line"] = occurrence["line"]
            if type(occurrence.get("offset")) is int and occurrence["offset"] >= 0:
                item["offset"] = occurrence["offset"]
            for key in ("bom-ref", "symbol", "additionalContext"):
                if occurrence.get(key):
                    item[key] = str(occurrence[key])
            occurrences.append(item)
        if occurrences:
            component["evidence"] = {"occurrences": occurrences}
            if n is not None:
                level = _CONFIDENCE.get(str(known.get("cryptoscan:confidence") or "").upper(), 0.9)
                component["evidence"]["identity"] = [{
                    "field": "name", "confidence": level, "concludedValue": n.name,
                    "methods": [{"technique": detection_technique(stage or "DETECTED_IN_SOURCE"), "confidence": level,
                                 "value": f"{occurrences[0]['location']}" + (f":{occurrences[0]['line']}" if occurrences[0].get("line") else "")}],
                }]
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
    _link_suite_algorithms(document["components"])
    refs = [c["bom-ref"] for c in document["components"] if c.get("bom-ref")]
    document["compositions"] = [{"aggregate": "incomplete", "assemblies": refs}]
    if bom.get("dependencies") and not omit_inventory_dependencies:
        dependencies = []
        for dependency in bom["dependencies"]:
            if not isinstance(dependency, dict) or dependency.get("ref") in excluded_refs:
                continue
            item = {"ref": dependency["ref"]}
            for key in ("dependsOn", "provides"):
                if key in dependency:
                    item[key] = [r for r in dependency[key] if r not in excluded_refs]
            dependencies.append(item)
        document["dependencies"] = dependencies
    if excluded:
        document["metadata"]["properties"].append(_property("cryptoscan:excluded_candidates", json.dumps(
            {"count": len(excluded), "items": excluded[:50],
             "basis": "placeholder or bookkeeping rows are not cryptographic assets"}, sort_keys=True)))
    document["metadata"]["properties"].append(_property("cryptoscan:inventory_summary", json.dumps(
        _inventory_summary(document), sort_keys=True)))
    check = validate_cyclonedx16(document)
    if not check["ok"]:
        raise ValueError("CycloneDX1.6 export failed validation: " + "; ".join(check["errors"][:10]))
    return document


def _link_suite_algorithms(components: list[dict[str, Any]]) -> None:
    """Reference a cipher suite's component algorithms only where this document
    holds an algorithm component observed at the same location (the same
    endpoint or file). The suite name alone never manufactures a reference."""
    from cbom.crypto_normalization import normalize, suite_algorithms

    def locations(component: dict[str, Any]) -> set[str]:
        return {o["location"] for o in (component.get("evidence") or {}).get("occurrences", []) if o.get("location")}

    algorithms = [(c, locations(c), _props_dict(c.get("properties") or []).get("cryptoscan:algorithm_family"))
                  for c in components if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm" and c.get("bom-ref")]
    for component in components:
        protocol = (component.get("cryptoProperties") or {}).get("protocolProperties")
        if not isinstance(protocol, dict) or not protocol.get("cipherSuites"):
            continue
        where = locations(component)
        for suite in protocol["cipherSuites"]:
            if not isinstance(suite, dict) or suite.get("algorithms") or not suite.get("name"):
                continue
            families = {normalize(name).family for _role, name in suite_algorithms(suite["name"])}
            refs = sorted({c["bom-ref"] for c, locs, family in algorithms if family in families and locs & where})
            if refs:
                suite["algorithms"] = refs


def _inventory_summary(document: dict[str, Any]) -> dict[str, Any]:
    """Counts computed from the components actually in this document — the
    single source of truth a reader can recount."""
    kinds: dict[str, int] = {}
    classes: dict[str, int] = {}
    for component in document.get("components", []):
        crypto = component.get("cryptoProperties") or {}
        kind = crypto.get("assetType") or component.get("type") or "unknown"
        props = _props_dict(component.get("properties") or [])
        if props.get("cryptoscan:component_role") == "ALGORITHM_REFERENCE":
            kind = "algorithm-reference"
        kinds[kind] = kinds.get(kind, 0) + 1
        if props.get("cryptoscan:classification"):
            classes[props["cryptoscan:classification"]] = classes.get(props["cryptoscan:classification"], 0) + 1
    deps = document.get("dependencies") or []
    axes: dict[str, dict[str, int]] = {}
    pqc: dict[str, int] = {}
    pqc_ready = 0
    for component in document.get("components", []):
        props = _props_dict(component.get("properties") or [])
        for axis in ("classical", "quantum", "configuration", "migration_urgency", "deployment_verification"):
            level = props.get(f"cryptoscan:risk:{axis}")
            if level:
                axes.setdefault(axis, {})[level] = axes.setdefault(axis, {}).get(level, 0) + 1
        if props.get("cryptoscan:pqc:highest_stage"):
            stage = props["cryptoscan:pqc:highest_stage"]
            pqc[stage] = pqc.get(stage, 0) + 1
            pqc_ready += props.get("cryptoscan:pqc:ready") == "true"
    return {
        "risk_dimensions": {axis: dict(sorted(levels.items())) for axis, levels in sorted(axes.items())},
        "pqc_deployment": {"by_highest_stage": dict(sorted(pqc.items())), "pqc_ready": pqc_ready,
                           "basis": "ready only when negotiated and approved for production"},
        "components_total": len(document.get("components", [])),
        "components_by_kind": dict(sorted(kinds.items())),
        "crypto_classification": dict(sorted(classes.items())),
        "dependency_records": len(deps),
        "dependency_edges": sum(len(d.get("dependsOn") or []) for d in deps),
        "provides_edges": sum(len(d.get("provides") or []) for d in deps),
    }
