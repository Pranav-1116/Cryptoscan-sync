"""Vendor REST readers (phase H4): the manifests, and the refusal to guess.

Some appliances expose neither PKCS#11 nor KMIP on the segment the estate can
reach — the only honest surface is the vendor's own HTTPS API. Reading one is
easy to get wrong in a way that never fails loudly: a plausible-looking path
that the appliance answers with 404, or a field name that exists but means
something else, produces an observation that is empty or wrong and looks
finished. So this module is built around one rule:

    **An endpoint exists here only because a published vendor document says so.**

Every :class:`DocumentedEndpoint` carries the URL of the page it was read from
and a one-line statement of what that page says it returns. :data:`VENDORS`
holds the manifests that were written that way — currently the Thales Luna
Network HSM REST API — and :data:`UNDOCUMENTED` names the vendors whose REST
surfaces are real but whose documentation this repository has *not* read. Asking
for one of those raises :class:`VendorNotDocumented` with the reason, rather
than inventing `/api/v1/...` and hoping.

Three further limits are structural, not stylistic:

* **Read-only.** Every shipped endpoint is a ``GET``; the module has no method
  for a verb that changes an appliance, and a test asserts the table cannot grow
  one. Login itself is not performed here: the transport arrives already
  authenticated, so a password never enters this code or its output.
* **Metadata only.** The projection reads the fields named below and drops the
  rest of the reply, so an API that returns a wrapped key yields nothing. The
  HSM resource's ``authenticationMethod`` is dropped on purpose: its *value* is
  a credential word (``ped``, or the password variant), and this reader does not
  put credential vocabulary into an evidence artifact. Authentication posture
  belongs to the PKCS#11 and KMIP readers, which read it without a secret.
  :func:`~universal_vendor.hardware.safety.refuse_secret_material` is still
  applied to the result, because a projection that misses a field must fail
  loudly rather than store it.
* **Parameters are path segments.** ``hsmid`` and ``partitionid`` are
  URL-encoded and cannot carry ``/`` or ``..`` out of their segment.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from universal_vendor.hardware.safety import refuse_secret_material

SCHEMA = "cryptoscan.hsm-rest/1"

#: Tokens that must not appear in what this reader returns.
_FORBIDDEN_IN_OUTPUT = ("private_key", "private key", "password", "passwd", "secret",
                        "key_material", "key material", "authorization", "bearer ")

#: The pages each endpoint was read from. They are quoted exactly as fetched —
#: the Thales documentation serves the same REST reference under several
#: version paths, so a citation here may be a 7.0 PDF or a 10.2 HTML rendering
#: of the same resource. Baking in the URL that was actually opened is the point:
#: a reader that says "documented somewhere" is a reader nobody can audit.
_LUNA_HSMS = ("https://thalesdocs.com/gphsm/luna/7.0/docs/network/Content/PDF_Network/"
              "REST%20API%20Reference%20Guide.pdf")
_LUNA_HSM = ("https://thalesdocs.com/gphsm/luna/7.3/docs/network/Content/REST_API/"
             "REST_API_Reference_Guide/html/hsms_hsmid_page_name.html")
_LUNA_PARTITION = ("https://thalesdocs.com/gphsm/luna/10.2/docs/network/Content/REST_API/"
                   "7_0_0/html/hsms_hsmid_partitions_partition_id_page_name.html")
_LUNA_ROLES = ("https://thalesdocs.com/gphsm/luna/7/docs/network/Content/REST_API/latest/"
               "hsms_hsmid_partitions_partition_id_roles_page_name.html")
_LUNA_CAPABILITIES = ("https://www.thalesdocs.com/gphsm/luna/7/docs/network/Content/"
                      "REST_API/latest/hsms_hsmid_capabilities_page_name.html")


class VendorNotDocumented(RuntimeError):
    """No manifest exists for this vendor, and one will not be invented."""


class EndpointNotAllowed(RuntimeError):
    """An endpoint key outside the vendor's manifest was requested."""


class RestReadError(RuntimeError):
    """The appliance answered, but not with what the document describes."""


@dataclass(frozen=True)
class DocumentedEndpoint:
    """One endpoint, with the document that says it exists and what it returns."""

    key: str
    method: str
    path: str
    source: str
    returns: str

    def __post_init__(self) -> None:
        """An endpoint without a citation is not an endpoint, it is a guess."""
        if not self.source.startswith("https://"):
            raise ValueError(
                f"{self.key}: an endpoint must cite the https page it was read from")
        if not self.returns.strip():
            raise ValueError(f"{self.key}: an endpoint must say what the document "
                             "says it returns")
        if not self.path.startswith("/"):
            raise ValueError(f"{self.key}: a documented path starts with '/'")
        if self.method.upper() != self.method:
            raise ValueError(f"{self.key}: methods are upper-case")

    @property
    def parameters(self) -> tuple[str, ...]:
        """The path placeholders, in order."""
        found: list[str] = []
        for part in self.path.split("{")[1:]:
            found.append(part.split("}", 1)[0])
        return tuple(found)


@dataclass(frozen=True)
class VendorManifest:
    """Everything known about one vendor's REST surface, and where it was read."""

    key: str
    vendor: str
    product: str
    documentation: str
    doc_version: str
    endpoints: tuple[DocumentedEndpoint, ...]
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.documentation.startswith("https://"):
            raise ValueError(f"{self.key}: a manifest names the document it was read from")
        if not self.endpoints:
            raise ValueError(f"{self.key}: a manifest with no endpoints describes nothing")
        keys = [endpoint.key for endpoint in self.endpoints]
        if len(set(keys)) != len(keys):
            raise ValueError(f"{self.key}: duplicate endpoint keys in {keys}")

    def endpoint(self, key: str) -> DocumentedEndpoint:
        for endpoint in self.endpoints:
            if endpoint.key == key:
                return endpoint
        raise EndpointNotAllowed(
            f"{key!r} is not a documented {self.vendor} endpoint; the manifest holds "
            f"{sorted(endpoint.key for endpoint in self.endpoints)} and this reader "
            "does not construct paths that a vendor document does not name")

    def get_paths(self) -> tuple[DocumentedEndpoint, ...]:
        return tuple(endpoint for endpoint in self.endpoints if endpoint.method == "GET")


#: Thales Luna Network HSM REST API. The ``model``/``firmwareVersion``/
#: ``fipsModeEnabled``/``partitionsCreated`` fields and the per-partition
#: ``objectCount`` are in the guide's own example results, quoted in the
#: ``returns`` line of each endpoint below.
THALES_LUNA = VendorManifest(
    key="thales_luna",
    vendor="Thales",
    product="Luna Network HSM (REST API)",
    documentation=_LUNA_HSM,
    doc_version="7.x (7.0 PDF, 7.3 HTML, 10.2 rendering of the 7.0 resource)",
    endpoints=(
        DocumentedEndpoint(
            "hsms", "GET", "/api/lunasa/hsms", _LUNA_HSMS,
            "the serial numbers of every HSM in the appliance"),
        DocumentedEndpoint(
            "hsm", "GET", "/api/lunasa/hsms/{hsmid}", _LUNA_HSM,
            "model, partNumber, firmwareVersion, label, state, fipsModeEnabled, "
            "partitionsCreated/partitionsAllowed and storageSpace"),
        DocumentedEndpoint(
            "partition", "GET", "/api/lunasa/hsms/{hsmid}/partitions/{partitionid}",
            _LUNA_PARTITION,
            "label, name, state, objectCount, storageSpace"),
        DocumentedEndpoint(
            "partition_roles", "GET",
            "/api/lunasa/hsms/{hsmid}/partitions/{partitionid}/roles", _LUNA_ROLES,
            "role identifiers and display names, and no credential of any kind"),
        DocumentedEndpoint(
            "capabilities", "GET", "/api/lunasa/hsms/{hsmid}/capabilities",
            _LUNA_CAPABILITIES,
            "identifiers of the capabilities the HSM advertises"),
    ),
    notes="the guide documents the HSM and partition resources; it does not publish "
          "a partition *list* shape that this reader was willing to pin, so partition "
          "ids are supplied by the caller from its own inventory",
)

#: The vendors a bank actually has, whose REST surface this repository has not
#: read. Naming them is the honest alternative to guessing their paths.
UNDOCUMENTED: dict[str, str] = {
    "utimaco": "Utimaco's REST surface is product-specific (SecurityServer/Blockchain "
               "Protection); no public endpoint reference was read while writing this "
               "module, so no manifest exists",
    "entrust_nshield": "nShield is administered through frontend/hardserver, and its "
                       "REST surface (if licensed) is not the same across versions; no "
                       "endpoint reference was read",
    "fortanix_dsm": "the DSM API is documented behind a customer portal rather than a "
                    "public reference this repository could cite",
}

VENDORS: dict[str, VendorManifest] = {THALES_LUNA.key: THALES_LUNA}


def manifest_for(vendor: str) -> VendorManifest:
    """The manifest for ``vendor``, or :class:`VendorNotDocumented`."""
    key = vendor.strip().lower().replace(" ", "_")
    if key in VENDORS:
        return VENDORS[key]
    if key in UNDOCUMENTED:
        raise VendorNotDocumented(
            f"no documented manifest for {vendor!r}: {UNDOCUMENTED[key]}. Add one by "
            "citing the vendor page for each endpoint — inventing a path produces a "
            "reader that returns an empty observation and calls it success")
    raise VendorNotDocumented(
        f"{vendor!r} is not a known HSM vendor; known manifests: {sorted(VENDORS)}, "
        f"named but undocumented: {sorted(UNDOCUMENTED)}")


@dataclass
class HsmRestFacts:
    """What one appliance's own API said about itself."""

    vendor: str
    product: str
    serial_reference: str | None = None
    model: str | None = None
    firmware: str | None = None
    fips_mode: bool | None = None
    state: str | None = None
    label: str | None = None
    part_number: str | None = None
    partitions_allowed: int | None = None
    partitions_created: int | None = None
    storage: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    partitions: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, str]] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)
    documentation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "vendor": self.vendor,
            "product": self.product,
            "serial_reference": self.serial_reference,
            "model": self.model,
            "firmware": self.firmware,
            "fips_mode": self.fips_mode,
            "state": self.state,
            "label": self.label,
            "part_number": self.part_number,
            "partitions_allowed": self.partitions_allowed,
            "partitions_created": self.partitions_created,
            "storage": dict(self.storage),
            "capabilities": list(self.capabilities),
            "partitions": list(self.partitions),
            "evidence": list(self.evidence),
            "unavailable": list(self.unavailable),
            "documentation": self.documentation,
        }

    def to_raw(self) -> dict[str, Any]:
        """The shape ``HsmHardwareScanner`` reads — the same one PKCS#11 and KMIP fill.

        Unlike KMIP ``Query``, the REST HSM resource *does* name the firmware
        version, so the field is filled here rather than left empty. Algorithms
        are still absent: this API describes the appliance and its partitions,
        not a mechanism list, and a mechanism list is what PKCS#11 is for.
        """
        return {
            "manufacturer": self.vendor,
            "model": self.model or "",
            "firmware": self.firmware,
            "serial_reference": self.serial_reference,
            "fips_mode": self.fips_mode,
            "partition_metadata": list(self.partitions),
            "key_type_metadata": [],
            "supported_algorithms": [],
            "certificate_dependencies": [],
            "capabilities": list(self.capabilities),
            "rest_capability_source": self.documentation,
        }


Transport = Callable[[str], Mapping[str, Any]]


def https_json_transport(*, opener: Any = None, timeout: float = 15.0,
                         headers: Mapping[str, str] | None = None,
                         allow_plain_http: bool = False) -> Transport:
    """A `GET`-only JSON transport over TLS.

    ``headers`` carries whatever the appliance requires — a session cookie, a
    bearer token — and stays inside this closure. It is never copied into a
    fact, and the module never logs it: the credential belongs to the operator,
    and an evidence artifact is not a place to keep one.

    ``opener`` is injectable for the same reason the RESTCONF reader's is: the
    tests drive the real parsing and the real error handling without a network.
    """
    session = urllib.request.build_opener() if opener is None else opener

    def fetch(url: str) -> Mapping[str, Any]:
        scheme = urllib.parse.urlsplit(url).scheme
        if scheme != "https" and not allow_plain_http:
            raise RestReadError(f"refusing {scheme or 'a schemeless'} URL: an HSM API is https")
        request = urllib.request.Request(url, method="GET")  # noqa: S310 - scheme checked above
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with session.open(request, timeout=timeout) as response:  # type: ignore[attr-defined]
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise RestReadError(f"{url}: HTTP {exc.code} {exc.reason}") from None
        except urllib.error.URLError as exc:
            raise RestReadError(f"{url}: {exc.reason}") from None
        try:
            payload = json.loads(body)
        except ValueError:
            raise RestReadError(f"{url}: the reply was not JSON") from None
        if not isinstance(payload, dict):
            raise RestReadError(f"{url}: expected a JSON object, got {type(payload).__name__}")
        return payload

    return fetch


def quote_segment(value: Any) -> str:
    """A path parameter that cannot leave its segment."""
    text = urllib.parse.quote(str(value), safe="")
    if not text or text in {"..", "."}:
        raise RestReadError(f"{value!r} is not usable as a path segment")
    return text


def build_url(base_url: str, endpoint: DocumentedEndpoint, **params: Any) -> str:
    """``base_url`` + one documented path, with every parameter encoded."""
    expected = endpoint.parameters
    missing = [name for name in expected if name not in params]
    if missing:
        raise RestReadError(f"{endpoint.key} needs {missing}")
    extra = [name for name in params if name not in expected]
    if extra:
        raise RestReadError(
            f"{endpoint.key} takes {list(expected)}; {extra} is not a parameter of a "
            "documented path")
    path = endpoint.path
    for name in expected:
        path = path.replace("{" + name + "}", quote_segment(params[name]))
    return base_url.rstrip("/") + path


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


class RestHsmReader:
    """Read one documented appliance through its own API.

    The partition list is deliberately *not* read: the vendor guide documents the
    single-partition resource and does not pin a list shape, so the caller passes
    the ids it already owns. A guessed list parse would either return nothing or
    return the wrong thing, and both look like a working reader.
    """

    def __init__(self, manifest: VendorManifest, transport: Transport,
                 *, base_url: str) -> None:
        self.manifest = manifest
        self.transport = transport
        self.base_url = base_url

    def get(self, key: str, **params: Any) -> Mapping[str, Any]:
        endpoint = self.manifest.endpoint(key)
        if endpoint.method != "GET":
            raise EndpointNotAllowed(f"{key} is {endpoint.method}; this reader is read-only")
        return self.transport(build_url(self.base_url, endpoint, **params))

    def _evidence(self, key: str, url: str) -> dict[str, str]:
        endpoint = self.manifest.endpoint(key)
        return {"endpoint": key, "url": url, "documentation": endpoint.source,
                "documented_returns": endpoint.returns}

    def collect(self, hsmid: str | int, *, partition_ids: tuple[str | int, ...] = ()) \
            -> HsmRestFacts:
        facts = HsmRestFacts(vendor=self.manifest.vendor, product=self.manifest.product,
                             documentation=self.manifest.documentation)

        url = build_url(self.base_url, self.manifest.endpoint("hsm"), hsmid=hsmid)
        payload = self.get("hsm", hsmid=hsmid)
        facts.evidence.append(self._evidence("hsm", url))
        facts.serial_reference = _clean(payload.get("serialNumber")) or _clean(hsmid)
        facts.model = _clean(payload.get("model"))
        facts.firmware = _clean(payload.get("firmwareVersion"))
        facts.label = _clean(payload.get("label"))
        facts.state = _clean(payload.get("state"))
        facts.part_number = _clean(payload.get("partNumber"))
        fips = payload.get("fipsModeEnabled")
        facts.fips_mode = bool(fips) if isinstance(fips, bool) or fips in (0, 1) else None
        facts.partitions_allowed = _int_or_none(payload.get("partitionsAllowed"))
        facts.partitions_created = _int_or_none(payload.get("partitionsCreated"))
        storage = payload.get("storageSpace")
        if isinstance(storage, dict):
            facts.storage = {name: value for name, value in storage.items()
                             if name in {"total", "used", "free"}}
        if not facts.firmware:
            facts.unavailable.append(
                "hsm: the reply carried no firmwareVersion; the appliance's firmware is "
                "unknown rather than empty")
        if not facts.model:
            facts.unavailable.append("hsm: the reply carried no model")

        try:
            capability_payload = self.get("capabilities", hsmid=hsmid)
        except RestReadError as exc:
            facts.unavailable.append(f"capabilities: {exc}")
        else:
            facts.evidence.append(
                self._evidence("capabilities",
                               build_url(self.base_url,
                                         self.manifest.endpoint("capabilities"),
                                         hsmid=hsmid)))
            facts.capabilities = _capability_ids(capability_payload)

        for partition_id in partition_ids:
            facts.partitions.append(self._partition(hsmid, partition_id, facts))
        refuse_secret_material(facts.to_dict(), _FORBIDDEN_IN_OUTPUT,
                               surface="hsm rest reader")
        return facts

    def _partition(self, hsmid: str | int, partition_id: str | int,
                   facts: HsmRestFacts) -> dict[str, Any]:
        url = build_url(self.base_url, self.manifest.endpoint("partition"),
                        hsmid=hsmid, partitionid=partition_id)
        record: dict[str, Any] = {"id": str(partition_id)}
        try:
            payload = self.get("partition", hsmid=hsmid, partitionid=partition_id)
        except RestReadError as exc:
            record["unavailable"] = str(exc)
            facts.unavailable.append(f"partition {partition_id}: {exc}")
            return record
        facts.evidence.append(self._evidence("partition", url))
        record.update({
            "label": _clean(payload.get("label")),
            "name": _clean(payload.get("name")),
            "state": _clean(payload.get("state")),
            "object_count": _int_or_none(payload.get("objectCount")),
        })
        storage = payload.get("storageSpace")
        if isinstance(storage, dict):
            record["storage"] = {name: value for name, value in storage.items()
                                 if name in {"total", "used", "free"}}
        try:
            roles = self.get("partition_roles", hsmid=hsmid, partitionid=partition_id)
        except RestReadError as exc:
            record["roles"] = []
            record["roles_unavailable"] = str(exc)
        else:
            facts.evidence.append(
                self._evidence("partition_roles",
                               build_url(self.base_url,
                                         self.manifest.endpoint("partition_roles"),
                                         hsmid=hsmid, partitionid=partition_id)))
            record["roles"] = [
                {"id": _clean(role.get("id")), "name": _clean(role.get("name"))}
                for role in _role_records(roles) if isinstance(role, dict)]
        return record


def _capability_ids(payload: Mapping[str, Any]) -> list[str]:
    """Capability identifiers, from whichever shape the reply uses.

    The guide says the reply lists unique identifiers and does not pin the
    envelope, so both a bare list and a wrapped list are accepted, and anything
    else yields nothing rather than a fabricated capability list.
    """
    for key in ("capabilities", "items", "capability"):
        value = payload.get(key)
        if isinstance(value, list):
            return [_clean(item.get("id") if isinstance(item, dict) else item) or ""
                    for item in value]
    if payload and all(isinstance(item, (str, int)) for item in payload.values()):
        return [str(item) for item in payload.values()]
    return []


def _role_records(payload: Mapping[str, Any]) -> list[Any]:
    roles = payload.get("roles")
    if isinstance(roles, list):
        return roles
    return []
