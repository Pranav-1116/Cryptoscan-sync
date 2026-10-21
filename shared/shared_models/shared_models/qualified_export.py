"""A deliberately narrow, bounded offline export adapter, not a live vendor SDK.

No XML, archives, URLs, code execution, proprietary parsing, or name joins.
"""
import json
from typing import Annotated, Literal
from pydantic import Field, model_validator
from .assurance import Contract, Text, Purpose


class Package(Contract):
    kind: Literal["packages"]
    package_identity: Text

    @model_validator(mode="after")
    def exact(self):
        from shared_models.software_identity import package_identity
        if package_identity(self.package_identity) != self.package_identity:
            raise ValueError("Package identity must include an exact supported version")
        return self


class Endpoint(Contract):
    kind: Literal["endpoints"]
    endpoint: Text
    protocol: Literal["tls", "ssh"]
    service_ref: Text | None = None
    # service_ref remains a supplier declaration, not a resolved application ID.


class Crypto(Contract):
    kind: Literal["crypto"]
    algorithm: Text
    purpose: Purpose
    security_use: bool | None = None
    location: Text
    package_identity: Text | None = None


class Deployment(Contract):
    kind: Literal["deployments"]
    application_ref: Text
    artifact_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    deployment_ref: Text
    service_ref: Text


class Hardware(Contract):
    kind: Literal["hardware"]
    product: Text
    product_version: Text
    firmware_version: Text | None = None
    hardware_backed: bool | None = None
    operating_mode: Text | None = None


class Supplier(Contract):
    kind: Literal["suppliers"]
    supplier: Text
    product: Text
    version: Text
    declaration_ref: Text


Fact = Annotated[Package | Endpoint | Crypto | Deployment | Hardware | Supplier, Field(discriminator="kind")]


class Page(Contract):
    number: int = Field(ge=1, le=10000)
    facts: list[Fact] = Field(max_length=500)


class Export(Contract):
    schema_version: Literal["vendor-export/v1"]
    vendor: Text
    product: Text
    version: Text
    profile: Text
    customer_id: Text
    build_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    expected_pages: int = Field(ge=1, le=10000)
    expected_items: int = Field(ge=0, le=1000000)
    pages: list[Page] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def pagination_contract(self):
        numbers = [p.number for p in self.pages]
        if len(numbers) != len(set(numbers)) or max(numbers) > self.expected_pages:
            raise ValueError("Duplicate/out-of-range pages")
        count = sum(len(p.facts) for p in self.pages)
        if count > 2000 or count > self.expected_items:
            raise ValueError("Fact count exceeds bound or declared total")
        if len(numbers) == self.expected_pages and count != self.expected_items:
            raise ValueError("A complete page set must agree with the declared item total")
        return self


def bounded_json(data, *, max_bytes=1048576):
    if not data or len(data) > max_bytes:
        raise ValueError("Offline export byte bound")
    # Reject pathological JSON before recursive parsing. Brackets inside escaped
    # JSON strings are not structural. Parsing only handles bounded JSON data.
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 24:
                raise ValueError("Offline export nesting bound")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError("Invalid JSON structure")
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("Duplicate JSON key")
            result[k] = v
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON number")))


def collect_export(data, manifest):
    export = Export.model_validate(bounded_json(data))
    for name in ("vendor", "product", "version", "profile", "customer_id", "build_digest"):
        if getattr(export, name) != manifest[name]:
            raise ValueError("Export identity disagrees with the signed envelope")
    facts = [f.model_dump(mode="json") for page in sorted(export.pages, key=lambda p: p.number) for f in page.facts]
    return {"facts": facts, "collection_complete": len(export.pages) == export.expected_pages,
            "expected_pages": export.expected_pages, "received_pages": len(export.pages),
            "expected_items": export.expected_items, "received_items": len(facts),
            "assertion_source": "SIGNED_SUPPLIER_DECLARATION_NOT_INDEPENDENT_VERIFICATION",
            "recording_completed": True, "observation_succeeded": bool(facts), "posture_acceptable": None}


def engine_fingerprint():
    """Bind offline qualification to this parser/schema implementation, not name.

    This is deliberately narrower than a signed deployment image/SBOM attestation.
    Dependency/image provenance and a reproducible release remain external gates.
    """
    import hashlib
    import marshal
    import sys
    import pydantic
    from shared_models.software_identity import package_identity
    code = b"".join(marshal.dumps(function.__code__) for function in (
        bounded_json, collect_export, Export.pagination_contract, Package.exact, package_identity))
    schema = json.dumps(Export.model_json_schema(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(code + schema + pydantic.__version__.encode() + sys.version.encode()).hexdigest()
