"""Hardware as a projection of the estate graph — the HBOM review, answered.

The platform already had hardware surfaces: the TechBOM ``hbom`` layer, the live engine's
``GET /hardware/hbom`` built from ephemeral state, and :mod:`cbom.hbom` rendering every
``hardware_assets`` row as one document. What none of them could do is the thing this
module exists for:

    is a server one row, or is it a tree of parts — and does "the HSM supports RSA"
    mean the same thing as "the application uses RSA"?

The answer is a **hardware view of the same graph the rest of the estate lives in**, not a
fourth database beside it. Every function here returns estate assets and estate claims;
:func:`build` assembles them with :func:`cbom.techbom.build`, so a hardware asset has one
identity in the HBOM, the TechBOM, the CBOM relationship that names it and the vendor view
that supplied it.

Four rules are enforced rather than documented:

* **a device is a tree, not a row.** CPU, memory, motherboard, BIOS, firmware, TPM, NIC,
  storage, RAID controller, GPU, PCI devices, crypto accelerator and HSM are kinds of
  their own, joined by ``HAS_COMPONENT`` / ``RUNS_BIOS`` / ``RUNS_FIRMWARE`` — and the
  seventeen fields a hardware asset should carry are **declared**: whatever the collector
  did not supply is listed in ``unknown_fields`` rather than silently absent;
* **capability is not use.** ``HSM SUPPORTS RSA-2048`` is a claim about the device,
  ``HSM PERFORMS RSA-SIGN`` is a claim that something ran there (and a datasheet cannot
  carry it — see ``RELATION_MIN_CONFIDENCE``), ``APPLICATION USES_CRYPTO RSA-2048`` is a
  claim about the application, and ``RSA-2048 PROTECTED_BY HSM`` is a claim about the key.
  They are four relations because they are four facts;
* **identity is evidence, not a hostname.** ``ASSET-HW-…`` is derived from manufacturer,
  model and serial (or an asset tag, or a firmware UUID); a hostname, an IP and a MAC are
  refused as anchors and reported as ignored, so a re-addressed machine is the same
  machine and the change is ``NETWORK_INTERFACE_CHANGED`` in the drift feed;
* **key material never arrives.** Attribute names and values are scanned for private
  keys, plaintext and wrapped key material, and the claim is refused by name. What a
  hardware collector may hand over is a key *reference*.

And the projection rule, which is the review's last point and the reason the module is
shaped this way: :func:`from_document` refuses an HBOM or a TechBOM as input, because a
projection that can become its own source is a second source of truth.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from cbom import techbom as tb
from shared_models.canonical import canonical_json

HBOM_SCHEMA = "cryptoscan.hbom/1"
ESTATE_SCHEMA = tb.ESTATE_SCHEMA

#: hardware-bearing kinds. A hardware asset is one of these, and nothing else.
HARDWARE_KINDS: tuple[str, ...] = (
    "PHYSICAL_SERVER", "HOST", "VM", "HSM", "TPM", "CPU", "MEMORY", "MOTHERBOARD",
    "BIOS", "NIC", "STORAGE", "RAID_CONTROLLER", "GPU", "PCI_DEVICE",
    "CRYPTO_ACCELERATOR", "SMART_CARD", "SECURITY_APPLIANCE", "HSM_CLUSTER",
    "HSM_PARTITION", "DISK", "FIRMWARE", "FIREWALL", "LOAD_BALANCER", "API_GATEWAY",
    "WAF", "NETWORK_SEGMENT", "HYPERVISOR", "OS", "KUBERNETES_NODE", "CLOUD_ACCOUNT",
    "CLOUD_REGION", "CLOUD_INSTANCE",
)

#: the kinds the hardware view renders: the devices themselves plus the vendor, advisory
#: and evidence rows a hardware document is expected to show. An application, a crypto
#: asset or a network endpoint stays in the graph and is reached by a walk — it is not a
#: hardware row, and dressing it as one is how an HBOM starts duplicating the CBOM.
HBOM_KINDS: tuple[str, ...] = HARDWARE_KINDS + ("CRYPTO_CAPABILITY", "CERTIFICATE",
                                               "VENDOR", "VENDOR_PRODUCT",
                                               "VULNERABILITY", "EVIDENCE")

#: the field set the review asks of every hardware asset, in its own order.
ASSET_FIELDS: tuple[str, ...] = (
    "asset_id", "asset_type", "manufacturer", "model", "serial_number", "part_number",
    "firmware_version", "bios_version", "hardware_revision", "location", "datacenter",
    "rack", "slot", "owner", "environment", "status", "first_seen", "last_seen",
    "evidence_id",
)

#: what may anchor an identity. A serial, a tag or a firmware UUID is a fact about the
#: device; everything in :data:`NETWORK_IDENTIFIERS` is a fact about its current place on
#: a network, and place changes without the device changing.
IDENTITY_ANCHORS: tuple[str, ...] = (
    "manufacturer", "model", "serial_number", "asset_tag", "uuid",
)
NETWORK_IDENTIFIERS: tuple[str, ...] = (
    "hostname", "ip", "ip_address", "ip_addresses", "mac", "mac_address",
    "mac_addresses", "dns_name",
)

#: names that are key material rather than a description of it
KEY_MATERIAL_KEYS: frozenset[str] = frozenset({
    "private_key", "privatekey", "private_key_pem", "key_material", "keymaterial",
    "key_bytes", "key_data", "key_value", "wrapped_key", "master_key", "kek", "dek",
    "secret", "secret_key", "plaintext", "password", "passphrase", "pin", "pin_block",
})
KEY_MATERIAL_MARKERS: tuple[str, ...] = (
    "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY",
)

#: a firmware release stands somewhere; these are the states it may be in
FIRMWARE_STATUS: tuple[str, ...] = ("SUPPORTED", "EOL", "EOS", "ANNOUNCED", "UNKNOWN")

#: a product is retired before it disappears: a model going EOL is the start of a migration,
#: not the end of the record (review hbom 5).
PRODUCT_STATUS: tuple[str, ...] = ("SUPPORTED", "ANNOUNCED", "EOL", "EOS", "RETIRED",
                                   "UNKNOWN")

Refused = tb.ClaimRefused


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _norm(value: Any) -> str:
    return tb._norm(value)


def _digest(text: str, length: int = 10) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _key_material(attributes: Mapping[str, Any]) -> str | None:
    """The first key-material attribute or value, named — or ``None`` if there is none."""
    for name, value in attributes.items():
        lowered = str(name).strip().lower()
        if lowered in KEY_MATERIAL_KEYS:
            return f"{name} is key material; an HBOM records a reference, never the key"
        text = str(value or "")
        for marker in KEY_MATERIAL_MARKERS:
            if marker in text:
                return (f"{name} carries a PEM private key; an HBOM records the "
                        "reference and the public half, never the private half")
    return None


def _certifications(rows: Sequence[Any] | None) -> list[dict[str, Any]]:
    """Attestations a device holds — FIPS, Common Criteria, a national scheme.

    A certification is not a boolean on a row: it names a standard, usually a level, an
    expiry and the attestation that proves it. A row with no standard is refused rather
    than stored as "certified", and a certification with no evidence id is kept but marked
    unbacked, because a claim nobody can check is exactly what an auditor asks about.
    """
    out: list[dict[str, Any]] = []
    for row in rows or []:
        if isinstance(row, str):
            body = {"standard": row}
        elif isinstance(row, Mapping):
            body = dict(row)
        else:
            raise Refused("CERTIFICATION_NOT_A_RECORD",
                          f"{row!r} is not a certification record")
        standard = _norm(body.get("standard") or body.get("name"))
        if not standard:
            raise Refused("CERTIFICATION_WITHOUT_STANDARD",
                          "a certification has to name the standard it is against")
        out.append({
            "standard": standard,
            "level": _norm(body.get("level")) or None,
            "expires": _norm(body.get("expires") or body.get("valid_until")) or None,
            "evidence_id": _norm(body.get("evidence_id")) or None,
            "backed": bool(_norm(body.get("evidence_id"))),
        })
    return out


def cpu_topology(*, sockets: Any, cores_per_socket: Any,
                 threads_per_core: Any = 1, numa_nodes: Any = None,
                 frequency_mhz: Any = None, vendor: Any = None, model: Any = None,
                 cores: Any = None, threads: Any = None) -> dict[str, Any]:
    """A CPU as a topology, with the arithmetic checked instead of assumed.

    ``2 sockets x 16 cores x 2 threads`` is 32 cores and 64 threads; a caller that also
    passes a total which disagrees is refused, because a component whose own numbers do not
    reconcile is worse than one with fewer numbers (review hbom 1, "CPU topology").
    """
    def _count(value: Any, name: str) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise Refused("TOPOLOGY_NOT_A_NUMBER",
                          f"{name} is {value!r}, and a topology is counted") from None
        if number < 1:
            raise Refused("TOPOLOGY_NOT_POSITIVE", f"{name} must be at least 1")
        return number

    socket_count = _count(sockets, "sockets")
    per_socket = _count(cores_per_socket, "cores_per_socket")
    per_core = _count(threads_per_core, "threads_per_core")
    physical = socket_count * per_socket
    logical = physical * per_core
    if cores is not None and _count(cores, "cores") != physical:
        raise Refused(
            "TOPOLOGY_DOES_NOT_RECONCILE",
            f"{socket_count} socket(s) x {per_socket} core(s) is {physical} physical "
            f"core(s), and the caller says {cores}; one of the two is wrong")
    if threads is not None and _count(threads, "threads") != logical:
        raise Refused(
            "TOPOLOGY_DOES_NOT_RECONCILE",
            f"{physical} core(s) x {per_core} thread(s) is {logical}, and the caller says "
            f"{threads}")
    body: dict[str, Any] = {
        "sockets": socket_count, "cores_per_socket": per_socket,
        "threads_per_core": per_core, "cores": physical, "threads": logical,
        "topology": f"{socket_count} socket(s) x {per_socket} core(s) x "
                    f"{per_core} thread(s) = {logical} logical processor(s)",
    }
    for name, value in (("numa_nodes", numa_nodes), ("frequency_mhz", frequency_mhz),
                        ("vendor", vendor), ("model", model)):
        if value not in (None, ""):
            body[name] = _norm(value)
    return body


def evidence(evidence_id: Any, *, collector: Any, collector_version: Any = None,
             target_id: Any = None, observed_at: Any = None, source: Any = None,
             evidence_type: Any = None, raw_reference: Any = None,
             normalized_fact: Any = None, hash: Any = None,
             confidence: Any = "HIGH") -> dict[str, Any]:
    """One evidence record: how the platform knows this hardware exists.

    The review asks for eleven parts and this refuses to make three of them optional —
    the collector, the moment it looked, and the hash of what it said. An observation
    without a hash cannot be re-checked; an observation without a time cannot be
    ordered against the next one.
    """
    identifier = _norm(evidence_id)
    if not identifier:
        raise Refused("EVIDENCE_WITHOUT_ID", "an evidence record needs an id")
    collector_text = _norm(collector)
    if not collector_text:
        raise Refused("EVIDENCE_WITHOUT_COLLECTOR",
                      f"{identifier}: evidence nobody can name is a rumour")
    observed = _norm(observed_at)
    if not observed:
        raise Refused("EVIDENCE_WITHOUT_TIME",
                      f"{identifier}: an observation with no timestamp cannot be ordered "
                      "against the next one")
    digest = _norm(hash)
    if not digest:
        raise Refused("EVIDENCE_WITHOUT_HASH",
                      f"{identifier}: an observation that cannot be re-checked is not "
                      "evidence, it is a memory")
    return {
        "evidence_id": identifier,
        "collector": collector_text,
        "collector_version": _norm(collector_version) or None,
        "target_id": _norm(target_id) or None,
        "observed_at": observed,
        "source": _norm(source) or None,
        "evidence_type": (_norm(evidence_type) or "INVENTORY").upper(),
        "raw_reference": _norm(raw_reference) or None,
        "normalized_fact": _norm(normalized_fact) or None,
        "hash": digest,
        "confidence": (_norm(confidence) or "HIGH").upper(),
    }


def identity(*, manufacturer: Any = None, model: Any = None,
             serial_number: Any = None, asset_tag: Any = None, uuid: Any = None,
             hostname: Any = None, ip_addresses: Iterable[Any] | None = None,
             mac_addresses: Iterable[Any] | None = None) -> dict[str, Any]:
    """A canonical hardware id, and the evidence it rests on.

    ``ASSET-HW-928182`` is derived from the device's own facts so that an estate renumbering
    a hostname, a DHCP lease or a network move does not mint a new server. When the only
    things known about a device are its hostname, its IP and its MAC, the id is returned
    **provisional** — and the block says so, because a provisional id is exactly where a
    duplicate will appear.
    """
    anchors = {name: _norm(value) for name, value in (
        ("manufacturer", manufacturer), ("model", model),
        ("serial_number", serial_number), ("asset_tag", asset_tag), ("uuid", uuid),
    ) if _norm(value)}
    ignored = {
        "hostname": _norm(hostname) or None,
        "ip_addresses": [_norm(v) for v in (ip_addresses or []) if _norm(v)],
        "mac_addresses": [_norm(v) for v in (mac_addresses or []) if _norm(v)],
    }
    strong = any(anchors.get(name) for name in ("serial_number", "asset_tag", "uuid"))
    if not anchors:
        raise Refused(
            "IDENTITY_WITHOUT_ANCHOR",
            "a device known only as a hostname, an IP and a MAC is not identified: the "
            "next lease would create a second asset, so name at least a manufacturer and "
            "a model, or a serial, a tag or a UUID")
    material = "|".join(f"{name}={anchors[name].lower()}" for name in IDENTITY_ANCHORS
                        if anchors.get(name))
    number = int(hashlib.sha256(material.encode("utf-8")).hexdigest(), 16) % 1_000_000
    method = ("serial" if anchors.get("serial_number") else
              "asset-tag" if anchors.get("asset_tag") else
              "uuid" if anchors.get("uuid") else "manufacturer+model")
    return {
        "asset_id": f"ASSET-HW-{number:06d}",
        "method": method,
        "anchors": anchors,
        "ignored_identifiers": {name: value for name, value in ignored.items() if value},
        "provisional": not strong,
        "durable": strong,
        "statement": (
            f"{method} identity from "
            f"{', '.join(sorted(anchors))}"
            + ("; provisional, because a manufacturer and a model are shared by every "
               "unit of that model, so two of them collide" if not strong else "")
            + (f"; {len(ignored['ip_addresses']) + len(ignored['mac_addresses'])} network "
               "identifier(s) kept as observations and not used as identity"
               if ignored["ip_addresses"] or ignored["mac_addresses"] else "")),
        "not_proven": [
            "that the serial number is unique in the estate: vendors duplicate them "
            "across refurbished units, and this id only says the facts match",
            "that a provisional id is stable: when a serial appears the asset is "
            "re-identified, and the drift feed will show a replacement",
        ],
    }


def hardware(asset_type: Any, *, name: Any = None, asset_id: Any = None,
             manufacturer: Any = None,
             model: Any = None, serial_number: Any = None, part_number: Any = None,
             asset_tag: Any = None, uuid: Any = None, firmware_version: Any = None,
             bios_version: Any = None, hardware_revision: Any = None,
             location: Any = None, datacenter: Any = None, rack: Any = None,
             slot: Any = None, owner: Any = None, sku: Any = None,
             certifications: Sequence[Any] | None = None,
             environment: Any = "PRODUCTION",
             status: Any = "ACTIVE", first_seen: Any = None, last_seen: Any = None,
             evidence_ids: Sequence[Any] | None = None,
             identity_evidence: Mapping[str, Any] | None = None,
             **attributes: Any) -> dict[str, Any]:
    """One hardware asset: the review's field set, declared, with what is missing named.

    ``identity_evidence`` is what :func:`identity` returned; when it is omitted the id is
    derived here from the same anchors, so there is one identity rule and not two. The
    fields a collector did not supply are listed in ``attributes['unknown_fields']`` — a
    gap in the collector is a fact about the estate, and a document that hides it is
    fiction with better formatting.
    """
    kind = _norm(asset_type).upper()
    if kind not in HARDWARE_KINDS:
        raise Refused("NOT_A_HARDWARE_KIND",
                      f"{kind or '(none)'} is not a hardware asset type")
    if identity_evidence and identity_evidence.get("asset_id"):
        asset_id = str(identity_evidence["asset_id"])
        identity_block = dict(identity_evidence)
    elif _norm(asset_id):
        # a caller may hand over the identity it derived elsewhere — or, for a component,
        # the position inside its device, which is all a part collector has
        given = _norm(asset_id)
        try:
            identity_block = dict(identity(
                manufacturer=manufacturer, model=model, serial_number=serial_number,
                asset_tag=asset_tag, uuid=uuid))
        except Refused:
            identity_block = {
                "asset_id": given, "method": "position", "provisional": False,
                "durable": True, "ignored_identifiers": {},
                "statement": (f"{given} is identified by its position in the device; a "
                              "part carries no serial to key on"),
                "not_proven": ["that the part was not swapped: position identifies the "
                               "slot, not the component in it"],
            }
        asset_id = given
        identity_block["asset_id"] = given
    else:
        identity_block = identity(
            manufacturer=manufacturer, model=model, serial_number=serial_number,
            asset_tag=asset_tag, uuid=uuid, hostname=attributes.get("hostname"),
            ip_addresses=attributes.get("ip_addresses") or (
                [attributes["ip"]] if attributes.get("ip") else []),
            mac_addresses=attributes.get("mac_addresses") or (
                [attributes["mac"]] if attributes.get("mac") else []))
        asset_id = identity_block["asset_id"]
    evidence_list = [_norm(value) for value in (evidence_ids or []) if _norm(value)]
    if not evidence_list:
        raise Refused("HARDWARE_WITHOUT_EVIDENCE",
                      f"{asset_id}: how the platform knows this device exists is part of "
                      "the asset, not an optional annotation")
    if kind in {"PHYSICAL_SERVER", "HSM", "FIREWALL", "SECURITY_APPLIANCE"} and not (
            _norm(manufacturer) and _norm(model)):
        raise Refused(
            "DEVICE_WITHOUT_MAKE_OR_MODEL",
            f"{kind} {asset_id}: a device with no manufacturer and model cannot be "
            "supplied, recalled or matched to a firmware release")

    declared = {
        "asset_id": asset_id,
        "asset_type": kind,
        "manufacturer": _norm(manufacturer) or None,
        "model": _norm(model) or None,
        "serial_number": _norm(serial_number) or None,
        "part_number": _norm(part_number) or None,
        "firmware_version": _norm(firmware_version) or None,
        "bios_version": _norm(bios_version) or None,
        "hardware_revision": _norm(hardware_revision) or None,
        "location": _norm(location) or None,
        "datacenter": _norm(datacenter) or None,
        "rack": _norm(rack) or None,
        "slot": _norm(slot) or None,
        "owner": _norm(owner) or None,
        "sku": _norm(sku) or None,
        "certifications": _certifications(certifications),
        "environment": _norm(environment).upper() or "PRODUCTION",
        "status": _norm(status).upper() or "ACTIVE",
        "first_seen": _norm(first_seen) or None,
        "last_seen": _norm(last_seen) or None,
        "evidence_id": evidence_list[0],
    }
    missing = [field for field in ASSET_FIELDS if declared.get(field) in (None, "")]
    for name_, value in {**declared, **attributes}.items():
        if isinstance(value, str):
            for marker in KEY_MATERIAL_MARKERS:
                if marker in value:
                    raise Refused(
                        "KEY_MATERIAL_REFUSED",
                        f"{asset_id}.{name_} carries a private key; an HBOM records a "
                        "reference and a public half, never key material")
    rejected = _key_material(attributes)
    if rejected:
        raise Refused("KEY_MATERIAL_REFUSED", f"{asset_id}: {rejected}")
    extra = {key: value for key, value in attributes.items()
             if key not in declared and value not in (None, "")}
    # `version` is the builder's own field; a component's spec may carry one, and it
    # belongs to the asset rather than being passed twice
    version_value = extra.pop("version", None) or declared["firmware_version"]
    body = {
        **{key: value for key, value in declared.items()
           if key not in {"environment", "status", "evidence_id", "owner", "location",
                          "first_seen", "last_seen"}},
        **extra,
        "unknown_fields": missing,
        "identity": {name: identity_block[name] for name in
                     ("asset_id", "method", "provisional", "durable",
                      "ignored_identifiers")},
        "field_completeness": {
            "declared": len(ASSET_FIELDS) - len(missing),
            "expected": len(ASSET_FIELDS),
            "missing": missing,
        },
    }
    return tb.asset(kind, name or asset_id, environment=declared["environment"],
                    version=version_value,
                    owner=declared["owner"], location=declared["location"],
                    status=declared["status"], first_seen=declared["first_seen"],
                    last_seen=declared["last_seen"], evidence_ids=evidence_list,
                    **body)


def firmware(release: Any, *, version: Any, vendor: Any = None, product: Any = None,
             release_date: Any = None, status: Any = "SUPPORTED", eol_date: Any = None,
             eos_date: Any = None, vulnerabilities: Iterable[Any] | None = None,
             evidence_ids: Sequence[Any] | None = None,
             environment: Any = "PRODUCTION", **attributes: Any) -> dict[str, Any]:
    """A firmware release as a first-class asset, not a string on a device.

    A version string on a row can be compared and cannot be *reasoned about*: it has no
    release date, no support status and no vulnerabilities, so "the HSM is out of date"
    stays an opinion. Here the release stands on its own, devices point at it with
    ``RUNS_FIRMWARE``, and the vendor's lifecycle is an attribute of the release.
    """
    status_text = _norm(status).upper() or "UNKNOWN"
    if status_text not in FIRMWARE_STATUS:
        raise Refused("UNKNOWN_FIRMWARE_STATUS",
                      f"{status_text} is not one of {', '.join(FIRMWARE_STATUS)}")
    body = tb.asset("FIRMWARE", release, environment=environment,
                    version=_norm(version) or "unspecified",
                    evidence_ids=list(evidence_ids or []),
                    vendor=_norm(vendor) or None, product=_norm(product) or None,
                    release_date=_norm(release_date) or None,
                    support_status=status_text, eol_date=_norm(eol_date) or None,
                    eos_date=_norm(eos_date) or None,
                    vulnerabilities=sorted(_norm(v) for v in (vulnerabilities or [])
                                           if _norm(v)),
                    **attributes)
    return body


def vulnerability(identifier: Any, *, severity: Any = "UNKNOWN", published: Any = None,
                  summary: Any = None, affected_versions: Iterable[Any] | None = None,
                  evidence_ids: Sequence[Any] | None = None,
                  environment: Any = "PRODUCTION") -> dict[str, Any]:
    """A known defect against a release, so an EOL or a CVE reaches the devices that ran it."""
    return tb.asset("VULNERABILITY", identifier, environment=environment,
                    severity=_norm(severity).upper() or "UNKNOWN",
                    published=_norm(published) or None, summary=_norm(summary) or None,
                    affected_versions=sorted(_norm(v) for v in (affected_versions or [])
                                             if _norm(v)),
                    evidence_ids=list(evidence_ids or []))


def capability(name: Any, *, algorithm: Any, key_types: Iterable[Any] | None = None,
               key_sizes: Iterable[Any] | None = None,
               operations: Iterable[Any] | None = None,
               evidence_type: Any = "CAPABILITY",
               evidence_ids: Sequence[Any] | None = None,
               environment: Any = "PRODUCTION") -> dict[str, Any]:
    """What a device can do with an algorithm — a capability, not a use.

    ``CRYPTO_CAPABILITY`` sits between a device and an algorithm on purpose: ``SUPPORTS``
    ends here, ``IMPLEMENTS`` reaches the algorithm, and neither relation says an
    application used anything. That is the review's point 4 as a graph shape.
    """
    return tb.asset("CRYPTO_CAPABILITY", name, environment=environment,
                    evidence_type=_norm(evidence_type).upper() or "CAPABILITY",
                    algorithm=_norm(algorithm),
                    key_types=sorted(_norm(v) for v in (key_types or []) if _norm(v)),
                    key_sizes=sorted(_norm(v) for v in (key_sizes or []) if _norm(v)),
                    operations=sorted(_norm(v).upper() for v in (operations or [])
                                      if _norm(v)),
                    evidence_ids=list(evidence_ids or []))


def network_device(asset_type: Any, *, name: Any = None, manufacturer: Any = None,
                   model: Any = None, serial_number: Any = None, sku: Any = None,
                   firmware_version: Any = None, ip: Any = None, mac: Any = None,
                   interface: Any = None, vlan: Any = None, zone: Any = None,
                   subnet: Any = None, routing: Any = None, ha_role: Any = None,
                   tls: Mapping[str, Any] | None = None, certificate: Any = None,
                   hsm: Any = None, location: Any = None, datacenter: Any = None,
                   rack: Any = None, slot: Any = None, owner: Any = None,
                   evidence_ids: Sequence[Any], basis: str = "api-poll",
                   environment: Any = "PRODUCTION", **fields: Any) -> dict[str, Any]:
    """A network appliance with the fourteen facts the review asks of one.

    IP, MAC, interface, VLAN, zone, subnet, routing, HA role, firmware, vendor, model, TLS
    capability, certificate and HSM reference — and the two references are **claims**, not
    strings: ``PRESENTS`` reaches the certificate and ``USES_HSM`` reaches the key custody
    behind the TLS offload. HBOM and NBOM then read the same edges instead of two lists.
    """
    kind = _norm(asset_type).upper()
    if kind not in {"FIREWALL", "LOAD_BALANCER", "API_GATEWAY", "WAF",
                    "SECURITY_APPLIANCE"}:
        raise Refused("NOT_A_NETWORK_DEVICE",
                      f"{kind or '(none)'} is not a network appliance this builder knows")
    tls_facts = dict(tls or {})
    device = hardware(
        kind, name=name, manufacturer=manufacturer, model=model,
        serial_number=serial_number, sku=sku, firmware_version=firmware_version,
        location=location, datacenter=datacenter, rack=rack, slot=slot, owner=owner,
        evidence_ids=evidence_ids, environment=environment,
        ip=_norm(ip) or None, mac=_norm(mac) or None,
        interface=_norm(interface) or None, vlan=_norm(vlan) or None,
        zone=_norm(zone) or None, subnet=_norm(subnet) or None,
        routing=_norm(routing) or None, ha_role=_norm(ha_role) or None,
        tls={key: value for key, value in tls_facts.items() if value not in (None, "")}
        or None,
        tls_capability=(_norm(tls_facts.get("min_version")) or None),
        certificate_reference=_norm(certificate) or None,
        hsm_reference=_norm(hsm) or None,
        **fields)
    assets: list[dict[str, Any]] = [device]
    claims: list[dict[str, Any]] = []
    if certificate:
        claims.append(claim(device["name"], "PRESENTS", _norm(certificate), basis=basis,
                            evidence_ids=evidence_ids))
    if hsm:
        claims.append(claim(device["name"], "USES_HSM", _norm(hsm), basis=basis,
                            evidence_ids=evidence_ids))
    return _part(assets, claims)


def product(name: Any, *, vendor: Any, model: Any = None, status: Any = "SUPPORTED",
            eol_date: Any = None, eos_date: Any = None, replacement: Any = None,
            certifications: Sequence[Any] | None = None,
            evidence_ids: Sequence[Any] | None = None,
            environment: Any = "PRODUCTION") -> dict[str, Any]:
    """A vendor product with a lifecycle, so a model going EOL is a fact and not a rumour."""
    status_text = _norm(status).upper() or "UNKNOWN"
    if status_text not in PRODUCT_STATUS:
        raise Refused("UNKNOWN_PRODUCT_STATUS",
                      f"{status_text} is not one of {', '.join(PRODUCT_STATUS)}")
    evidence_list = [_norm(value) for value in (evidence_ids or []) if _norm(value)]
    if not evidence_list:
        raise Refused("PRODUCT_WITHOUT_EVIDENCE",
                      f"{_norm(name)}: a lifecycle claim needs the document it came from")
    return tb.asset("VENDOR_PRODUCT", name, environment=environment,
                    vendor=_norm(vendor), model=_norm(model) or None,
                    support_status=status_text, eol_date=_norm(eol_date) or None,
                    eos_date=_norm(eos_date) or None,
                    replacement=_norm(replacement) or None,
                    certifications=_certifications(certifications),
                    evidence_ids=evidence_list)


# --------------------------------------------------------------------------- #
# Claims
# --------------------------------------------------------------------------- #

def claim(source: Any, relation: Any, target: Any, *, basis: Any,
          evidence_ids: Sequence[Any], confidence: Any = None, rule: Any = None,
          note: Any = None) -> dict[str, Any]:
    """A hardware claim in estate form. The class rules are :mod:`cbom.techbom`'s."""
    row = tb.claim(source, relation, target, basis=basis, evidence_ids=evidence_ids,
                   confidence=confidence, rule=rule, note=note)
    return {key: row[key] for key in
            ("from", "relation", "to", "basis", "confidence", "evidence_ids", "rule",
             "note")}


def _part(assets: Iterable[dict[str, Any]],
          claims: Iterable[dict[str, Any]]) -> dict[str, Any]:
    return {"assets": list(assets), "claims": list(claims)}


def merge(*parts: Any) -> dict[str, Any]:
    """Several ``{"assets": …, "claims": …}`` blocks into one, order preserved."""
    assets: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    seen: dict[tuple[str, str, str], str] = {}
    for part in parts:
        if part is None:
            continue
        if not isinstance(part, Mapping):
            raise ValueError("merge() takes {'assets': …, 'claims': …} blocks")
        if "kind" in part and "name" in part:
            # a bare asset is one asset; merging a list of them should not need a wrapper
            part = {"assets": [part], "claims": []}
        for row in part.get("assets") or []:
            identity_key = (str(row.get("kind")), str(row.get("name")),
                            str(row.get("environment")))
            fingerprint = _digest(canonical_json(row.get("attributes") or {}), 16)
            if identity_key in seen:
                # the same asset described twice and identically is one asset — a shared
                # vendor node is not a duplicate. Two *different* descriptions of one
                # identity are kept, and build() refuses them by name.
                if seen[identity_key] == fingerprint:
                    continue
            else:
                seen[identity_key] = fingerprint
            assets.append(row)
        claims.extend(part.get("claims") or [])
    return _part(assets, claims)


def estate(*parts: Any, estate_id: Any = None, environment: Any = "PRODUCTION",
           expected: Mapping[str, Any] | None = None,
           gaps: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """A hardware estate document the TechBOM builder accepts — the one identity."""
    merged = merge(*parts)
    return {
        "schema": ESTATE_SCHEMA,
        "estate_id": _norm(estate_id) or "hardware-estate",
        "environment": _norm(environment).upper() or "PRODUCTION",
        "assets": merged["assets"],
        "claims": merged["claims"],
        "expected": dict(expected or {}),
        "gaps": [dict(row) for row in (gaps or [])],
    }


# --------------------------------------------------------------------------- #
# Devices: the server is a tree
# --------------------------------------------------------------------------- #

def component(kind: Any, *, asset_id: Any, parent: Any = None, basis: Any = "agent-inventory",
              evidence_ids: Sequence[Any], environment: Any = "PRODUCTION",
              **fields: Any) -> dict[str, Any]:
    """A part of a device, and the ``HAS_COMPONENT`` claim that puts it there.

    ``parent`` is the parent's reference (its ``name``, which :func:`hardware` sets to the
    canonical asset id). The relation is claimed here so a caller cannot add a component
    without saying how it was found.
    """
    row = hardware(kind, name=_norm(asset_id), asset_id=_norm(asset_id),
                   evidence_ids=evidence_ids, environment=environment, **fields)
    claims = []
    if parent:
        claims.append(claim(parent, "HAS_COMPONENT", row["name"], basis=basis,
                            evidence_ids=evidence_ids))
    return _part([row], claims)


def server(asset_id: Any = None, *, manufacturer: Any, model: Any,
           serial_number: Any = None, asset_tag: Any = None, uuid: Any = None,
           cpu: Mapping[str, Any] | None = None, memory: Mapping[str, Any] | None = None,
           motherboard: Mapping[str, Any] | None = None, bios: Mapping[str, Any] | None = None,
           nics: Sequence[Mapping[str, Any]] = (), storage: Sequence[Mapping[str, Any]] = (),
           raid: Mapping[str, Any] | None = None, gpus: Sequence[Mapping[str, Any]] = (),
           pci: Sequence[Mapping[str, Any]] = (),
           accelerator: Mapping[str, Any] | None = None,
           tpm: Mapping[str, Any] | None = None, hsm: Mapping[str, Any] | None = None,
           evidence_ids: Sequence[Any], basis: Any = "agent-inventory",
           environment: Any = "PRODUCTION", **fields: Any) -> dict[str, Any]:
    """A physical server and the parts it is made of, in one block.

    Every part is a ``HAS_COMPONENT`` claim from the server, so the tree the review draws
    is walkable and each edge carries the basis it arrived with. A part the collector did
    not find is simply absent — the absence is visible in the coverage block, not smoothed
    over with an empty component.
    """
    host = hardware("PHYSICAL_SERVER", name=asset_id, manufacturer=manufacturer, model=model,
                    serial_number=serial_number, asset_tag=asset_tag, uuid=uuid,
                    evidence_ids=evidence_ids, environment=environment, **fields)
    parts: list[dict[str, Any]] = [host]
    claims: list[dict[str, Any]] = []
    parent = host["name"]

    def add(kind: str, label: str, spec: Mapping[str, Any],
            relation: str = "HAS_COMPONENT") -> None:
        spec = dict(spec)
        spec.setdefault("asset_tag", label)
        row = hardware(kind, name=label, asset_id=label, evidence_ids=evidence_ids,
                       environment=environment, **spec)
        parts.append(row)
        claims.append(claim(parent, relation, row["name"], basis=basis,
                            evidence_ids=evidence_ids))

    if cpu:
        add("CPU", f"{parent}-CPU", cpu)
    if memory:
        add("MEMORY", f"{parent}-MEM", memory)
    if motherboard:
        add("MOTHERBOARD", f"{parent}-MB", motherboard)
    if bios:
        add("BIOS", f"{parent}-BIOS", bios, "RUNS_BIOS")
    if tpm:
        add("TPM", f"{parent}-TPM", tpm)
    for index, nic in enumerate(nics, start=1):
        add("NIC", nic.get("name") or f"{parent}-NIC{index}", nic)
    for index, disk in enumerate(storage, start=1):
        add("STORAGE", disk.get("name") or f"{parent}-STG{index}", disk)
    if raid:
        add("RAID_CONTROLLER", f"{parent}-RAID", raid)
    for index, gpu in enumerate(gpus, start=1):
        add("GPU", gpu.get("name") or f"{parent}-GPU{index}", gpu)
    for index, device in enumerate(pci, start=1):
        add("PCI_DEVICE", device.get("name") or f"{parent}-PCI{index}", device)
    if accelerator:
        add("CRYPTO_ACCELERATOR", f"{parent}-ACCEL", accelerator)
    if hsm:
        add("HSM", hsm.pop("name", f"{parent}-HSM"), hsm)
    return _part(parts, claims)


def hsm(asset_id: Any = None, *, vendor: Any, product: Any, model: Any,
        firmware_release: Any = None, firmware_version: Any = None,
        ha_mode: Any = None, cluster: Any = None, members: Sequence[Mapping[str, Any]] = (),
        partitions: Sequence[Mapping[str, Any]] = (),
        capabilities: Sequence[Mapping[str, Any]] = (),
        key_types: Iterable[Any] | None = None, key_sizes: Iterable[Any] | None = None,
        operations: Iterable[Any] | None = None,
        certificates: Iterable[Any] | None = None,
        applications: Iterable[Any] | None = None, systems: Iterable[Any] | None = None,
        serial_number: Any = None, location: Any = None, datacenter: Any = None,
        product_asset: Mapping[str, Any] | None = None,
        evidence_ids: Sequence[Any], capability_basis: str = "vendor-datasheet",
        environment: Any = "PRODUCTION", **fields: Any) -> dict[str, Any]:
    """An HSM with the twelve things an HSM has, not a vendor and a model string.

    ``capabilities`` is the vendor's or the firmware's list of what the device can do: it
    is claimed with ``SUPPORTS`` against a ``CRYPTO_CAPABILITY`` — never against the
    application, and never as a use. Partitions and HA members are their own nodes, and
    the applications that are wired to the device are ``USES_HSM`` claims with their own
    basis, so "the HSM lists ML-KEM" and "Payments API signs with it" stay separable.
    """
    identifier = _norm(asset_id) or f"HSM-{_digest(f'{vendor}|{model}', 6).upper()}"
    device = hardware("HSM", name=identifier, asset_id=identifier, manufacturer=vendor,
                      model=model,
                      serial_number=serial_number, firmware_version=firmware_version,
                      location=location, datacenter=datacenter,
                      evidence_ids=evidence_ids, environment=environment,
                      vendor=_norm(vendor), product=_norm(product), ha_mode=_norm(ha_mode),
                      key_types=sorted(_norm(v) for v in (key_types or []) if _norm(v)),
                      key_sizes=sorted(_norm(v) for v in (key_sizes or []) if _norm(v)),
                      operations=sorted(_norm(v).upper() for v in (operations or [])
                                        if _norm(v)),
                      partitions=[_norm(row.get("name") or row.get("id"))
                                  for row in partitions],
                      certificates=sorted(_norm(v) for v in (certificates or []) if _norm(v)),
                      **fields)
    assets: list[dict[str, Any]] = [device]
    claims: list[dict[str, Any]] = []

    # vendor → product → model → firmware → asset (review point 5)
    product_name = (str(product_asset.get("name")) if product_asset
                    else f"{_norm(vendor)} {_norm(product)}")
    if product_asset:
        product_row = dict(product_asset)
    else:
        product_row = tb.asset("VENDOR_PRODUCT", product_name, environment=environment,
                               vendor=_norm(vendor), product=_norm(product),
                               model=_norm(model), evidence_ids=list(evidence_ids))
    vendor_asset = tb.asset("VENDOR", _norm(vendor), environment=environment,
                            evidence_ids=list(evidence_ids))
    assets += [product_row, vendor_asset]
    claims.append(claim(identifier, "HAS_MODEL", product_name, basis="vendor-datasheet",
                        evidence_ids=evidence_ids))
    claims.append(claim(product_name, "SUPPLIED_BY", _norm(vendor),
                        basis="vendor-datasheet", evidence_ids=evidence_ids))

    if firmware_release:
        assets.append(firmware_release)
        claims.append(claim(identifier, "RUNS_FIRMWARE", firmware_release["name"],
                            basis="api-poll", evidence_ids=evidence_ids))
        claims.append(claim(firmware_release["name"], "SUPPLIED_BY", _norm(vendor),
                            basis="vendor-datasheet", evidence_ids=evidence_ids))

    if cluster:
        cluster_name = f"{_norm(cluster)}"
        assets.append(tb.asset("HSM_CLUSTER", cluster_name, environment=environment,
                               ha_mode=_norm(ha_mode) or None,
                               members=[_norm(row.get("name")) for row in members
                                        if _norm(row.get("name"))],
                               evidence_ids=list(evidence_ids)))
        claims.append(claim(identifier, "MEMBER_OF", cluster_name, basis="api-poll",
                            evidence_ids=evidence_ids))
        for member in members:
            if not member.get("name"):
                continue
            member_asset = hardware("HSM", name=_norm(member["name"]),
                                    asset_id=_norm(member["name"]),
                                    manufacturer=vendor, model=model,
                                    serial_number=member.get("serial_number"),
                                    asset_tag=member.get("asset_tag") or _norm(member["name"]),
                                    evidence_ids=evidence_ids, environment=environment,
                                    ha_role=_norm(member.get("role")) or None)
            assets.append(member_asset)
            claims.append(claim(identifier, "PEERS_WITH", member_asset["name"],
                                basis="api-poll", evidence_ids=evidence_ids))
            claims.append(claim(member_asset["name"], "MEMBER_OF", cluster_name,
                                basis="api-poll", evidence_ids=evidence_ids))

    for certificate in certificates or ():
        certificate_name = _norm(certificate)
        if not certificate_name:
            continue
        assets.append(tb.asset("CERTIFICATE", certificate_name,
                               environment=environment, evidence_ids=list(evidence_ids),
                               source="hsm-metadata"))
        claims.append(claim(identifier, "HOLDS_CERTIFICATE", certificate_name,
                            basis="api-poll", evidence_ids=evidence_ids))

    for partition in partitions:
        label = _norm(partition.get("name")) or f"{identifier}-PART{len(assets)}"
        row = hardware("HSM_PARTITION", name=label, asset_id=label, asset_tag=label,
                       evidence_ids=partition.get("evidence_ids") or evidence_ids,
                       environment=environment,
                       partition_id=_norm(partition.get("id")) or None,
                       key_types=sorted(_norm(v) for v in (partition.get("key_types") or [])),
                       applications=sorted(_norm(v) for v in
                                           (partition.get("applications") or [])),
                       **{key: value for key, value in partition.items()
                          if key not in {"name", "id", "key_types", "applications",
                                         "evidence_ids"}})
        assets.append(row)
        claims.append(claim(identifier, "HAS_PARTITION", row["name"], basis="api-poll",
                            evidence_ids=evidence_ids))

    for spec in capabilities:
        capability_name = f"{identifier} {_norm(spec.get('algorithm'))} " \
                          f"{'/'.join(_norm(v).upper() for v in (spec.get('operations') or []))}"
        row = capability(
            capability_name.strip(), algorithm=spec.get("algorithm"),
            key_types=spec.get("key_types"), key_sizes=spec.get("key_sizes"),
            operations=spec.get("operations"),
            evidence_type="CAPABILITY",
            evidence_ids=spec.get("evidence_ids") or evidence_ids,
            environment=environment)
        assets.append(row)
        algorithm_name = f"{_norm(spec.get('algorithm'))}"
        algorithm_asset = tb.asset("ALGORITHM", algorithm_name, environment=environment,
                                   evidence_ids=list(evidence_ids))
        assets.append(algorithm_asset)
        claims.append(claim(identifier, "SUPPORTS", row["name"], basis=capability_basis,
                            evidence_ids=evidence_ids))
        claims.append(claim(row["name"], "IMPLEMENTS", algorithm_name,
                            basis=capability_basis, evidence_ids=evidence_ids))

    for application in applications or ():
        claims.append(claim(_norm(application), "USES_HSM", identifier,
                            basis="config-parse", evidence_ids=evidence_ids))
    for system in systems or ():
        claims.append(claim(_norm(system), "OWNS", identifier, basis="cmdb-import",
                            evidence_ids=evidence_ids))
    return _part(assets, claims)


# --------------------------------------------------------------------------- #
# Build — the projection, assembled by the one graph
# --------------------------------------------------------------------------- #

def _with_evidence_nodes(document: Mapping[str, Any]) -> dict[str, Any]:
    """Every cited evidence record becomes a node, and each device an ``EVIDENCED_BY`` edge.

    A register in a side table is a document nobody can walk. As nodes, the evidence behind
    a device is reachable from the device — which is what "how do you know this hardware
    exists" has to mean in a graph, and what lets a consumer refuse a fact whose evidence
    it cannot see.
    """
    assets = list(document.get("assets") or [])
    claims = list(document.get("claims") or [])
    created: dict[str, dict[str, Any]] = {}
    for row in assets:
        records = (row.get("attributes") or {}).get("evidence") or []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            identifier = _norm(record.get("evidence_id"))
            if not identifier or identifier in created:
                continue
            created[identifier] = tb.asset(
                "EVIDENCE", identifier,
                environment=row.get("environment") or document.get("environment")
                or "PRODUCTION",
                evidence_ids=[identifier],
                collector=_norm(record.get("collector")) or None,
                collector_version=_norm(record.get("collector_version")) or None,
                observed_at=_norm(record.get("observed_at")) or None,
                source=_norm(record.get("source")) or None,
                evidence_type=_norm(record.get("evidence_type")) or None,
                raw_reference=_norm(record.get("raw_reference")) or None,
                normalized_fact=_norm(record.get("normalized_fact")) or None,
                hash=_norm(record.get("hash")) or None,
                confidence=_norm(record.get("confidence")) or None,
                evidence_record=True)
    if not created:
        return dict(document)
    cited: set[str] = set()
    extra_claims: list[dict[str, Any]] = []
    for row in list(assets):
        identifiers = list(row.get("evidence_ids") or [])
        for record in (row.get("attributes") or {}).get("evidence") or []:
            if isinstance(record, Mapping) and _norm(record.get("evidence_id")):
                identifiers.append(_norm(record.get("evidence_id")))
        for identifier in dict.fromkeys(identifiers):
            if identifier not in created:
                continue
            if str(row.get("kind")) not in tb.RELATIONS["EVIDENCED_BY"]["from"]:
                continue  # a vendor or a product row is not a collected device
            key = (str(row.get("kind")), str(row.get("name")), str(row.get("environment")))
            if key in cited:
                continue
            cited.add(key)
            basis = ("passive-capture" if "PASSIVE" in
                     _norm((created[identifier].get("attributes") or {})
                           .get("evidence_type")).upper()
                     else "capability-list" if "CAPABILITY" in
                     _norm((created[identifier].get("attributes") or {})
                           .get("evidence_type")).upper()
                     else "agent-inventory")
            extra_claims.append(claim(row.get("name"), "EVIDENCED_BY", identifier,
                                      basis=basis, evidence_ids=[identifier]))
    return {**document, "assets": [*assets, *created.values()],
            "claims": [*claims, *extra_claims]}


def build(document: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical hardware estate → HBOM, as a view of the TechBOM.

    The HBOM is not a second document with a second set of edges: it is
    :func:`cbom.techbom.build` over the same estate, restricted to the hardware kinds and
    the relationships that touch them, plus the blocks the review asks for — the component
    tree, the field and coverage accounting, and the evidence register.
    """
    if not isinstance(document, Mapping) or document.get("schema") != ESTATE_SCHEMA:
        raise ValueError(f"build() takes a {ESTATE_SCHEMA} document; an HBOM is a "
                         "projection of the canonical estate, not a source")
    bom = tb.build(_with_evidence_nodes(document))
    assets = bom["assets"]
    hardware_assets = [row for row in assets if row["kind"] in HBOM_KINDS]
    hardware_keys = {row["key"] for row in hardware_assets
                     if row["kind"] in HARDWARE_KINDS}
    hardware_claims = [row for row in bom["claims"]
                       if row["from_key"] in hardware_keys or row["to_key"] in hardware_keys]

    # the composed tree, from HAS_COMPONENT / RUNS_BIOS / HAS_PARTITION only
    children: dict[str, list[str]] = {}
    for row in bom["claims"]:
        if row["relation"] in {"HAS_COMPONENT", "RUNS_BIOS", "HAS_PARTITION"}:
            children.setdefault(row["from_key"], []).append(row["to_key"])
    child_keys = {key for values in children.values() for key in values}

    def tree(key: str, depth: int = 0) -> dict[str, Any]:
        row = bom["by_key"][key]
        return {
            "asset_id": row["name"], "kind": row["kind"], "depth": depth,
            "children": [tree(child, depth + 1) for child in sorted(children.get(key, []))],
        }

    roots = sorted(key for key in children if key not in child_keys)
    component_tree = [tree(key) for key in roots]

    # field accounting: a gap in the collector is a fact about the estate
    field_rows: dict[str, dict[str, int]] = {}
    for row in hardware_assets:
        if row["kind"] not in HARDWARE_KINDS:
            continue
        for field in ASSET_FIELDS:
            bucket = field_rows.setdefault(field, {"declared": 0, "missing": 0})
            value = (row["attributes"].get(field) or row.get(field)
                     or (row["name"] if field == "asset_id" else None)
                     or (row["kind"] if field == "asset_type" else None)
                     or ((row.get("evidence_ids") or [None])[0]
                         if field == "evidence_id" else None))
            if value in (None, "", []):
                bucket["missing"] += 1
            else:
                bucket["declared"] += 1
    missing_total = sum(bucket["missing"] for bucket in field_rows.values())

    # evidence register, and the refusal that keeps it honest
    register: dict[str, dict[str, Any]] = {}
    for row in hardware_assets:
        records = row["attributes"].get("evidence") or []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            identifier = _norm(record.get("evidence_id"))
            if not identifier:
                continue
            register[identifier] = dict(record)
    refusals = list(bom["refusals"])

    # firmware lifecycle: which devices sit behind a release that has ended
    firmware_rows = [row for row in assets if row["kind"] == "FIRMWARE"]
    lifecycle = []
    for row in firmware_rows:
        status = str(row["attributes"].get("support_status") or "UNKNOWN").upper()
        dependents = [edge["from_key"] for edge in bom["claims"]
                      if edge["relation"] == "RUNS_FIRMWARE" and edge["to_key"] == row["key"]]
        lifecycle.append({
            "firmware": row["name"], "version": row["version"], "status": status,
            "release_date": row["attributes"].get("release_date"),
            "vulnerabilities": row["attributes"].get("vulnerabilities") or [],
            "devices": sorted(bom["by_key"][key]["name"] for key in dependents),
            "actionable": status in {"EOL", "EOS"},
        })

    return {
        "schema": HBOM_SCHEMA,
        "projection": True,
        "source_of_truth": "CANONICAL_ESTATE",
        "derived_from": document.get("estate_id"),
        "environment": bom["environment"],
        "assets": hardware_assets,
        "by_key": bom["by_key"],
        "hardware_by_key": {row["key"]: row for row in hardware_assets
                            if row["kind"] in HARDWARE_KINDS},
        "claims": bom["claims"],
        "hardware_claims": hardware_claims,
        "component_tree": component_tree,
        "components": len(hardware_assets),
        "counts": {kind: sum(1 for row in hardware_assets if row["kind"] == kind)
                   for kind in sorted({row["kind"] for row in hardware_assets})},
        "fields": dict(sorted(field_rows.items())),
        "field_gaps": missing_total,
        "evidence_register": dict(sorted(register.items())),
        "firmware_lifecycle": sorted(lifecycle, key=lambda row: row["firmware"]),
        "refusals": refusals,
        "coverage": bom["completeness"],
        "techbom": {
            "assets": len(assets), "claims": len(bom["claims"]),
            "by_kind": bom["counts"], "by_confidence": _confidence_counts(bom["claims"]),
        },
        "statement": (
            f"{len(hardware_assets)} hardware asset(s) across "
            f"{len({row['kind'] for row in hardware_assets})} kind(s) and "
            f"{len(hardware_claims)} relationship(s) touching them out of "
            f"{len(bom['claims'])} in the estate; {len(component_tree)} device root(s); "
            f"{missing_total} declared field(s) the collectors did not supply; "
            f"{len(lifecycle)} firmware release(s) tracked"),
        "not_proven": [
            "that the tree is complete: a component nobody inventoried is absent, and the "
            "field gaps count what the collectors admitted they did not see",
            "that a capability is a use: SUPPORTS is the device's own list, and an "
            "application's USES_CRYPTO is a claim about the application",
            "that a device is where the network says it is: an address is an observation "
            "and never an identity",
            "that a firmware status is current: EOL is what the vendor said at the time "
            "the release was recorded",
        ],
    }


#: relations along which a failure travels *down*: if the host dies, what it carries dies
#: with it. :func:`cbom.techbom.blast_radius` walks the other direction, because "who
#: depends on this application" is an inbound question; "what goes down with this
#: hypervisor" is an outbound one, and a hardware question is usually the second.
CONTAINMENT_RELATIONS: frozenset[str] = frozenset({
    "HAS_COMPONENT", "RUNS_BIOS", "HAS_PARTITION", "RUNS_HYPERVISOR", "HOSTS_OS",
    "RUNS_APPLICATION", "SCHEDULED_ON", "IN_REGION", "IN_ACCOUNT", "MEMBER_OF",
    # what a device carries goes with it: its firmware and the operations it can perform
    "RUNS_FIRMWARE", "SUPPORTS", "PERFORMS", "IMPLEMENTS",
    # a traffic path fails downstream too: lose the firewall and the endpoint behind it
    # is exposed, so the same walk answers "what does this much of the path carry"
    "FORWARDS_TO", "ROUTES_TO", "FRONTED_BY", "EXPOSES", "PROTECTED_BY", "ATTACHED_TO",
})


def _walk(document: Mapping[str, Any], seed: str, *, include_declared: bool = True,
          max_hops: int = 8) -> dict[str, Any]:
    """Dependents and dependants of one asset, with the strength of the path kept.

    A node is *proven* only when every edge on the way to it is OBSERVED or CONFIGURED;
    one declared hop taints everything past it, exactly as in the TechBOM walker.
    """
    by_key = document.get("by_key") or {}
    claims = document.get("claims") or []
    inbound: dict[str, list[Mapping[str, Any]]] = {}
    outbound: dict[str, list[Mapping[str, Any]]] = {}
    for row in claims:
        inbound.setdefault(row["to_key"], []).append(row)
        outbound.setdefault(row["from_key"], []).append(row)
    strength: dict[str, bool] = {seed: True}
    hops: dict[str, int] = {seed: 0}
    frontier = [seed]
    depth = 0
    used: list[Mapping[str, Any]] = []
    while frontier and depth < max_hops:
        depth += 1
        nxt: list[str] = []
        for current in frontier:
            edges = list(inbound.get(current, []))
            edges += [edge for edge in outbound.get(current, [])
                      if edge["relation"] in CONTAINMENT_RELATIONS]
            for edge in edges:
                other = edge["from_key"] if edge["to_key"] == current else edge["to_key"]
                if not include_declared and edge["confidence"] not in tb.PROVEN:
                    continue
                proven = strength[current] and edge["confidence"] in tb.PROVEN
                if other in strength:
                    strength[other] = strength[other] or proven
                    continue
                strength[other] = proven
                hops[other] = depth
                used.append(edge)
                nxt.append(other)
        frontier = nxt
    reached = {key: value for key, value in strength.items()
               if key != seed and key in by_key}
    return {"strength": reached, "hops": hops, "edges": used}


def radius(document: Mapping[str, Any], *, query: Any, include_declared: bool = True,
           max_hops: int = 8) -> dict[str, Any]:
    """What breaks with this device — in the review's own units.

    Two directions, because a hardware question needs both: **dependents** (the
    applications and systems that rely on the device, walked backwards over every
    relation) and **dependants** (the parts and workloads that go down with it, walked
    forwards over containment). A node is *proven* only when every edge to it is
    OBSERVED or CONFIGURED, so a CMDB-imported containment does not become a fact.
    """
    if not isinstance(document, Mapping) or document.get("schema") != HBOM_SCHEMA:
        raise ValueError(f"radius() takes a {HBOM_SCHEMA} document")
    text = _norm(query)
    if not text:
        raise ValueError("a blast radius needs something to start from")
    by_key = document.get("by_key") or {}
    seeds = [key for key, row in by_key.items()
             if row["name"].lower() == text.lower() or row["id"].lower() == text.lower()]
    if not seeds:
        seeds = [key for key, row in by_key.items()
                 if row["name"].lower().startswith(text.lower())]
    if not seeds:
        return {"schema": HBOM_SCHEMA, "query": text, "seeds": [], "impacts": {},
                "proven": [], "possible": [], "statement":
                f"nothing in this HBOM matches {text}"}
    walk = _walk(document, seeds[0], include_declared=include_declared,
                 max_hops=max_hops)
    groups: dict[str, list[str]] = {}
    proven: list[str] = []
    possible: list[str] = []
    for key, is_proven in sorted(walk["strength"].items()):
        row = by_key[key]
        groups.setdefault(row["kind"], []).append(row["name"])
        (proven if is_proven else possible).append(row["name"])
    network = (groups.get("NETWORK_ENDPOINT", []) + groups.get("LOAD_BALANCER", [])
               + groups.get("WAF", []) + groups.get("API_GATEWAY", [])
               + groups.get("FIREWALL", []))
    crypto = groups.get("CRYPTO_ASSET", []) + groups.get("CRYPTO_CAPABILITY", [])
    return {
        "schema": HBOM_SCHEMA,
        "query": text,
        "seed": by_key[seeds[0]]["name"],
        "impacts": {kind: sorted(names) for kind, names in sorted(groups.items())},
        "applications": sorted(groups.get("APPLICATION", [])),
        "systems": sorted(groups.get("BUSINESS_SYSTEM", [])),
        "crypto_assets": sorted(crypto),
        "network_paths": sorted(network),
        "proven": sorted(proven),
        "possible": sorted(possible),
        "edges_walked": len(walk["edges"]),
        "statement": (
            f"{by_key[seeds[0]]['name']}: {len(groups.get('APPLICATION', []))} "
            f"application(s), {len(groups.get('BUSINESS_SYSTEM', []))} business system(s), "
            f"{len(crypto)} cryptographic asset(s), {len(network)} network path(s) "
            "affected"
            + (f"; {len(possible)} reached only through a declared edge" if possible
               else "")),
        "not_proven": [
            "that reachability is impact: a device in the path is exposure, and whether "
            "the business stops needs the owner's assessment",
            "that the path is complete: a relationship nobody recorded is missing here, "
            "not absent from the estate",
        ],
    }


def product_lifecycle(document: Mapping[str, Any], *,
                      max_hops: int = 6) -> dict[str, Any]:
    """Products that have ended, and everything behind them.

    The review's point 5 is that a vendor chain is only useful if it can answer "this model
    is retired — what runs on it?". That is one walk from the product: its devices, the
    applications wired to them, the business systems above those, and the cryptography in
    between, with the count in the units an owner reads.
    """
    if not isinstance(document, Mapping) or document.get("schema") != HBOM_SCHEMA:
        raise ValueError(f"product_lifecycle() takes a {HBOM_SCHEMA} document")
    by_key = document.get("by_key") or {}
    claims = document.get("claims") or []
    products: dict[str, list[str]] = {}
    for row in claims:
        if row["relation"] == "HAS_MODEL":
            products.setdefault(row["to_key"], []).append(row["from_key"])
    rows: list[dict[str, Any]] = []
    for key, device_keys in sorted(products.items()):
        product = by_key.get(key)
        if not product:
            continue
        status = str((product.get("attributes") or {}).get("support_status")
                     or "UNKNOWN").upper()
        affected: dict[str, set[str]] = {}
        for device_key in device_keys:
            for reached, proven in _walk(document, device_key,
                                         max_hops=max_hops)["strength"].items():
                row = by_key.get(reached)
                if row is None:
                    continue
                affected.setdefault(row["kind"], set()).add(row["name"])
        rows.append({
            "product": product["name"],
            "model": (product.get("attributes") or {}).get("model"),
            "status": status,
            "eol_date": (product.get("attributes") or {}).get("eol_date"),
            "replacement": (product.get("attributes") or {}).get("replacement"),
            "devices": sorted(by_key[device_key]["name"] for device_key in device_keys
                              if device_key in by_key),
            "applications": sorted(affected.get("APPLICATION", set())),
            "systems": sorted(affected.get("BUSINESS_SYSTEM", set())),
            "crypto_assets": sorted(affected.get("CRYPTO_ASSET", set())
                                    | affected.get("CRYPTO_CAPABILITY", set())),
            "actionable": status in {"EOL", "EOS", "RETIRED"},
        })
    ended = [row for row in rows if row["actionable"]]
    return {
        "schema": HBOM_SCHEMA,
        "products": rows,
        "statement": (
            f"{len(rows)} vendor product(s) in the chain, {len(ended)} past end of life"
            + (": " + "; ".join(
                f"{row['product']} {row['status']} → {len(row['devices'])} device(s), "
                f"{len(row['applications'])} application(s), {len(row['systems'])} "
                f"system(s)" for row in ended) if ended else "")),
        "not_proven": [
            "that the vendor's lifecycle page is current: the status is what was recorded "
            "when the product row was written",
            "that a replacement exists in this estate: the field names one, and nothing "
            "here checks it was bought",
        ],
    }


def impact_summary(document: Mapping[str, Any], *, query: Any,
                   max_hops: int = 8) -> dict[str, Any]:
    """The review's sentence, in the review's units: *1 HSM, 3 applications, 2 systems …*.

    The counts come from :func:`radius`, so they inherit its two directions and its rule
    that one declared hop taints everything past it. Nothing is added up twice: a device
    reached twice is one device.
    """
    radius_block = radius(document, query=query, max_hops=max_hops)
    seed = radius_block.get("seed")
    seed_kind = None
    if seed:
        row = next((row for row in (document.get("by_key") or {}).values()
                    if row["name"] == seed), None)
        seed_kind = row["kind"] if row else None
    hsms = sorted(set(radius_block["impacts"].get("HSM", []))
                  | ({seed} if seed_kind == "HSM" else set()))
    counts = {
        "hsm": len(hsms),
        "applications": len(radius_block["applications"]),
        "business_systems": len(radius_block["systems"]),
        "crypto_assets": len(radius_block["crypto_assets"]),
        "network_paths": len(radius_block["network_paths"]),
        "devices": len([name for kind, names in radius_block["impacts"].items()
                        if kind in HARDWARE_KINDS for name in names]),
    }
    plural = [("HSM", counts["hsm"]), ("application", counts["applications"]),
              ("business system", counts["business_systems"]),
              ("cryptographic asset", counts["crypto_assets"]),
              ("network path", counts["network_paths"])]
    return {
        "schema": HBOM_SCHEMA,
        "query": radius_block.get("query"),
        "seed": seed,
        **counts,
        "statement": (
            (f"{seed}: " if seed else "")
            + ", ".join(f"{count} {label}{'' if count == 1 else 's'} affected"
                        for label, count in plural)
            + (f"; {len(radius_block['possible'])} node(s) only through a declared edge"
               if radius_block["possible"] else "")),
        "not_proven": list(radius_block.get("not_proven") or []),
    }


def _confidence_counts(claims: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in claims:
        counts[row["confidence"]] = counts.get(row["confidence"], 0) + 1
    return dict(sorted(counts.items()))


# --------------------------------------------------------------------------- #
# Coverage — the denominator, and the buckets that have to add up
# --------------------------------------------------------------------------- #

def coverage(expected: Any, collected: Any, *, unavailable: Any = 0,
             permission_denied: Any = 0, unknown: Any = 0,
             gaps: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Expected against collected, with every missing device accounted for.

    ``expected`` is the number the estate *should* hold — from the CMDB, the rack diagram,
    the purchase order. The four buckets have to add up to it, because a coverage
    percentage built from numbers that do not reconcile is a worse answer than "unknown".
    """
    numbers = {}
    for name, value in (("expected", expected), ("collected", collected),
                        ("unavailable", unavailable),
                        ("permission_denied", permission_denied), ("unknown", unknown)):
        try:
            numbers[name] = int(value)
        except (TypeError, ValueError):
            raise Refused("COVERAGE_NOT_A_NUMBER",
                          f"{name} is {value!r}, and coverage needs counts") from None
        if numbers[name] < 0:
            raise Refused("COVERAGE_NEGATIVE", f"{name} cannot be negative")
    seen = numbers["collected"] + numbers["unavailable"] + numbers["permission_denied"] \
        + numbers["unknown"]
    if seen != numbers["expected"]:
        raise Refused(
            "COVERAGE_DOES_NOT_RECONCILE",
            f"collected {numbers['collected']} + unavailable {numbers['unavailable']} + "
            f"permission denied {numbers['permission_denied']} + unknown "
            f"{numbers['unknown']} = {seen}, but {numbers['expected']} devices were "
            "expected; the difference is a device nobody has accounted for")
    expected_total = numbers["expected"]
    ratio = 1.0 if expected_total <= 0 else round(numbers["collected"] / expected_total, 4)
    verdict = ("COMPLETE" if numbers["collected"] >= expected_total else
               "PARTIAL" if numbers["collected"] else "MISSING")
    return {
        "schema": HBOM_SCHEMA,
        **numbers,
        "coverage": ratio,
        "verdict": verdict,
        "gaps": [{"kind": _norm(row.get("kind")).upper() or "HARDWARE",
                  "reason": _norm(row.get("reason")) or "no reason given"}
                 for row in (gaps or [])],
        "statement": (
            f"expected {numbers['expected']}, collected {numbers['collected']}, "
            f"unavailable {numbers['unavailable']}, permission denied "
            f"{numbers['permission_denied']}, unknown {numbers['unknown']} — coverage "
            f"{verdict} ({ratio:.0%})"),
        "not_proven": [
            "that the denominator is right: expected comes from a CMDB or a rack diagram, "
            "and an estate nobody documented has no denominator at all",
            "that an inaccessible device is absent: permission denied means nobody looked",
        ],
    }


# --------------------------------------------------------------------------- #
# Drift — hardware changes, and what they do to cryptography
# --------------------------------------------------------------------------- #

#: attribute → the review's change type. The key is the *smallest* thing that moved.
FIELD_CHANGE: dict[str, str] = {
    "cpu": "CPU_CHANGED", "cpu_model": "CPU_CHANGED", "cpu_count": "CPU_CHANGED",
    "cpu_topology": "CPU_CHANGED", "cores": "CPU_CHANGED", "threads": "CPU_CHANGED",
    "memory_total_mb": "RAM_CHANGED", "memory": "RAM_CHANGED", "memory_modules": "RAM_CHANGED",
    "nic": "NIC_CHANGED", "nic_count": "NIC_CHANGED", "nics": "NIC_CHANGED",
    "mac_address": "NIC_CHANGED", "interfaces": "NIC_CHANGED",
    "firmware_version": "FIRMWARE_CHANGED",
    "bios_version": "BIOS_CHANGED", "bios": "BIOS_CHANGED",
    "tpm": "TPM_CHANGED", "tpm_version": "TPM_CHANGED", "tpm_present": "TPM_CHANGED",
    "ha_mode": "HSM_CONFIGURATION_CHANGED", "partitions": "HSM_CONFIGURATION_CHANGED",
    "key_types": "HSM_CONFIGURATION_CHANGED", "key_sizes": "HSM_CONFIGURATION_CHANGED",
    "operations": "HSM_CONFIGURATION_CHANGED", "certificates": "HSM_CONFIGURATION_CHANGED",
    "serial_number": "DEVICE_REPLACED", "part_number": "DEVICE_REPLACED",
    "ip": "NETWORK_INTERFACE_CHANGED", "ip_address": "NETWORK_INTERFACE_CHANGED",
    "ip_addresses": "NETWORK_INTERFACE_CHANGED", "vlan": "NETWORK_INTERFACE_CHANGED",
    "subnet": "NETWORK_INTERFACE_CHANGED", "zone": "NETWORK_INTERFACE_CHANGED",
}

#: the review's twelve, so a feed can be checked against the list rather than a vibe
DRIFT_TYPES: tuple[str, ...] = (
    "CPU_CHANGED", "RAM_CHANGED", "NIC_CHANGED", "FIRMWARE_CHANGED", "BIOS_CHANGED",
    "TPM_CHANGED", "HSM_FIRMWARE_CHANGED", "HSM_CONFIGURATION_CHANGED", "DEVICE_ADDED",
    "DEVICE_REMOVED", "DEVICE_REPLACED", "NETWORK_INTERFACE_CHANGED",
)


def drift(previous: Mapping[str, Any], current: Mapping[str, Any], *,
          max_hops: int = 6) -> dict[str, Any]:
    """Two HBOMs → hardware change events, each with the cryptography behind the device.

    The device is matched by its **canonical id**, not by name: a server that kept its
    serial and changed its address is the same asset, and the address change is
    ``NETWORK_INTERFACE_CHANGED`` — which is the whole point of the identity rule. The
    drift feed then asks the graph what cryptography sits behind the device, so an HSM
    firmware change arrives with the applications and algorithms that depend on it.
    """
    for label, document in (("previous", previous), ("current", current)):
        if not isinstance(document, Mapping) or document.get("schema") != HBOM_SCHEMA:
            raise ValueError(f"{label} is not a {HBOM_SCHEMA} document")
    before = previous.get("hardware_by_key") or {}
    after = current.get("hardware_by_key") or {}
    events: list[dict[str, Any]] = []

    def placement(row: Mapping[str, Any]) -> tuple[Any, ...] | None:
        attributes = row.get("attributes") or {}
        rack, slot = attributes.get("rack"), attributes.get("slot")
        if not (rack or slot):
            return None
        return (row["kind"], attributes.get("datacenter"), rack, slot)

    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    replacements: list[tuple[str, str]] = []
    removed_by_placement: dict[tuple[Any, ...], str] = {}
    for key in removed:
        slot_key = placement(before[key])
        if slot_key:
            removed_by_placement.setdefault(slot_key, key)
    for key in list(added):
        slot_key = placement(after[key])
        old_key = removed_by_placement.pop(slot_key, None) if slot_key else None
        if old_key is None:
            continue
        # a different canonical id in the same bay is a swapped device, not two events
        replacements.append((old_key, key))
        added.remove(key)
        removed.remove(old_key)
        old, new = before[old_key], after[key]
        events.append({
            "change": "DEVICE_REPLACED", "category": "HARDWARE_DRIFT",
            "asset_id": new["name"], "kind": new["kind"], "asset": key,
            "previous_asset_id": old["name"],
            "detail": (f"{new['kind']} {old['name']} → {new['name']} in the same bay "
                       f"({(new.get('attributes') or {}).get('rack')}/"
                       f"{(new.get('attributes') or {}).get('slot')})")})
    for key in added:
        row = after[key]
        events.append({"change": "DEVICE_ADDED", "category": "HARDWARE_DRIFT",
                       "asset_id": row["name"], "kind": row["kind"], "asset": key,
                       "detail": f"{row['kind']} {row['name']} appeared"})
    for key in removed:
        row = before[key]
        events.append({"change": "DEVICE_REMOVED", "category": "HARDWARE_DRIFT",
                       "asset_id": row["name"], "kind": row["kind"], "asset": key,
                       "detail": f"{row['kind']} {row['name']} is no longer reported"})
    for key in sorted(set(before) & set(after)):
        old, new = before[key], after[key]
        if (old.get("version") or "") != (new.get("version") or ""):
            change = ("HSM_FIRMWARE_CHANGED" if new["kind"] == "HSM"
                      else "BIOS_CHANGED" if new["kind"] == "BIOS"
                      else "FIRMWARE_CHANGED")
            events.append({"change": change, "category": "HARDWARE_DRIFT",
                           "asset_id": new["name"], "kind": new["kind"], "asset": key,
                           "detail": f"{new['name']}: {old.get('version') or '(none)'} → "
                                     f"{new.get('version') or '(none)'}"})
        old_attrs = old.get("attributes") or {}
        new_attrs = new.get("attributes") or {}
        for name in sorted(set(old_attrs) | set(new_attrs)):
            if (old_attrs.get(name),) == (new_attrs.get(name),):
                continue
            change = FIELD_CHANGE.get(name)
            if not change:
                continue
            if new["kind"] == "HSM" and change in {"FIRMWARE_CHANGED", "BIOS_CHANGED"}:
                change = "HSM_FIRMWARE_CHANGED"
            events.append({"change": change, "category": "HARDWARE_DRIFT",
                           "asset_id": new["name"], "kind": new["kind"], "asset": key,
                           "attribute": name,
                           "detail": f"{new['name']}.{name}: {old_attrs.get(name)!r} → "
                                     f"{new_attrs.get(name)!r}"})
    for event in events:
        event["crypto_impact"] = _crypto_behind(current, event["asset"],
                                                max_hops=max_hops)
    by_change: dict[str, int] = {}
    for event in events:
        by_change[event["change"]] = by_change.get(event["change"], 0) + 1
    affected = sorted({name for event in events for name in
                       event["crypto_impact"]["applications"]})
    return {
        "schema": HBOM_SCHEMA,
        "events": events,
        "by_change": dict(sorted(by_change.items())),
        "hardware_drift": bool(events),
        "unmodelled_changes": sorted({event["change"] for event in events}
                                     - set(DRIFT_TYPES)),
        "crypto_impact": {
            "crypto_assets": sorted({name for event in events for name in
                                     event["crypto_impact"]["crypto_assets"]}),
            "applications": affected,
            "systems": sorted({name for event in events for name in
                               event["crypto_impact"]["systems"]}),
            "network_paths": sorted({name for event in events for name in
                                     event["crypto_impact"]["network_paths"]}),
        },
        "statement": (
            f"{len(events)} hardware change(s)"
            + (": " + ", ".join(f"{name} {count}" for name, count in
                                sorted(by_change.items())) if by_change else "")
            + (f"; {len(affected)} application(s) sit behind the changed devices"
               if affected else "")),
        "not_proven": [
            "why the device changed: a firmware change is a fact about two snapshots, and "
            "an upgrade, a rollback and a collector bug look identical here",
            "that an unchanged device is untouched: drift is what was collected twice, "
            "and a device nobody re-read shows nothing",
        ],
    }


def _crypto_behind(bom: Mapping[str, Any], key: str, *,
                   max_hops: int = 6) -> dict[str, Any]:
    """Everything that depends on this device, in the units the review asks for."""
    if key not in (bom.get("by_key") or {}):
        return {"assets": 0, "crypto_assets": [], "applications": [], "systems": [],
                "network_paths": [], "by_kind": {}, "edges_considered": 0}
    walk = _walk(bom, key, max_hops=max_hops)
    by_key = bom["by_key"]
    groups: dict[str, list[str]] = {}
    for reached in walk["strength"]:
        row = by_key[reached]
        groups.setdefault(row["kind"], []).append(row["name"])
    return {
        "assets": sum(len(values) for values in groups.values()),
        "crypto_assets": sorted(groups.get("CRYPTO_ASSET", []))
        + sorted(groups.get("CRYPTO_CAPABILITY", [])),
        "applications": sorted(groups.get("APPLICATION", [])),
        "systems": sorted(groups.get("BUSINESS_SYSTEM", [])),
        "network_paths": sorted(groups.get("NETWORK_ENDPOINT", [])
                                + groups.get("LOAD_BALANCER", [])
                                + groups.get("WAF", [])
                                + groups.get("API_GATEWAY", [])
                                + groups.get("FIREWALL", [])),
        "by_kind": {kind: sorted(values) for kind, values in sorted(groups.items())},
        "edges_considered": len(bom.get("claims") or []),
    }


# --------------------------------------------------------------------------- #
# Cross-BOM correlation (review point 15)
# --------------------------------------------------------------------------- #

#: which BOM a kind belongs to, so one walk can be read as five views of one estate
BOM_OF_KIND: dict[str, str] = {
    "PHYSICAL_SERVER": "HBOM", "HOST": "HBOM", "VM": "HBOM", "HSM": "HBOM",
    "TPM": "HBOM", "CPU": "HBOM", "MEMORY": "HBOM", "MOTHERBOARD": "HBOM",
    "BIOS": "HBOM", "NIC": "HBOM", "STORAGE": "HBOM", "RAID_CONTROLLER": "HBOM",
    "GPU": "HBOM", "PCI_DEVICE": "HBOM", "CRYPTO_ACCELERATOR": "HBOM",
    "SMART_CARD": "HBOM", "SECURITY_APPLIANCE": "HBOM", "HSM_CLUSTER": "HBOM",
    "HSM_PARTITION": "HBOM", "DISK": "HBOM", "FIRMWARE": "HBOM", "FIREWALL": "HBOM",
    "NETWORK_SEGMENT": "HBOM", "HYPERVISOR": "HBOM", "OS": "HBOM",
    "KUBERNETES_NODE": "HBOM", "CLOUD_ACCOUNT": "HBOM", "CLOUD_REGION": "HBOM",
    "CLOUD_INSTANCE": "HBOM",
    "CRYPTO_ASSET": "CBOM", "CRYPTO_LIBRARY": "CBOM", "CRYPTO_CAPABILITY": "CBOM",
    "ALGORITHM": "CBOM", "CERTIFICATE": "CBOM", "CERTIFICATE_AUTHORITY": "CBOM",
    "PUBLIC_KEY": "CBOM", "KEY_REFERENCE": "CBOM", "KMS": "CBOM",
    "PACKAGE": "SBOM", "APPLICATION": "SBOM", "SERVICE": "SBOM", "CONTAINER": "SBOM",
    "IMAGE": "SBOM", "SOURCE": "SBOM", "BUILD": "SBOM", "ARTIFACT": "SBOM",
    "SBOM": "SBOM", "DEPLOYMENT": "SBOM", "POD": "SBOM", "PROCESS": "SBOM",
    "BUSINESS_SYSTEM": "TBOM",
    "NETWORK_ENDPOINT": "NBOM", "LOAD_BALANCER": "NBOM", "API_GATEWAY": "NBOM",
    "WAF": "NBOM", "SERVICE_MESH": "NBOM",
    "VENDOR": "VBOM", "VENDOR_PRODUCT": "VBOM",
    "EVIDENCE": "EVIDENCE", "VULNERABILITY": "VULNERABILITY",
}


def correlate(bom: Mapping[str, Any], reference: Any, *,
              max_hops: int = 6) -> dict[str, Any]:
    """One hardware asset → its algorithm, library, application, endpoint and vendor.

    The review's point 15 is not "put five documents in one file": it is that the same
    physical fact has to be reachable from every view. This walks *one* graph in both
    directions from one asset and reports each asset under the BOM whose view it belongs
    to, so the caller sees one chain rather than five documents to reconcile.
    """
    if not isinstance(bom, Mapping) or bom.get("schema") != HBOM_SCHEMA:
        raise ValueError(f"correlate() takes a {HBOM_SCHEMA} document")
    text = _norm(reference)
    hardware_by_key = bom.get("hardware_by_key") or {}
    seeds = [key for key, row in hardware_by_key.items()
             if row["name"].lower() == text.lower()]
    if not seeds:
        seeds = [key for key, row in hardware_by_key.items()
                 if text.lower() in row["name"].lower()]
    if not seeds:
        return {"schema": HBOM_SCHEMA, "query": text, "seed": None, "by_bom": {},
                "statement": f"no hardware asset in this HBOM matches {text}"}
    seed = seeds[0]
    adjacency: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
    for row in bom.get("claims") or []:
        adjacency.setdefault(row["from_key"], []).append((row["to_key"], row))
        adjacency.setdefault(row["to_key"], []).append((row["from_key"], row))
    seen: dict[str, int] = {seed: 0}
    frontier = [seed]
    hops = 0
    while frontier and hops < max_hops:
        hops += 1
        nxt: list[str] = []
        for current in frontier:
            for neighbour, _edge in adjacency.get(current, []):
                if neighbour in seen:
                    continue
                seen[neighbour] = hops
                nxt.append(neighbour)
        frontier = nxt
    by_bom: dict[str, list[dict[str, Any]]] = {}
    for key, distance in sorted(seen.items(), key=lambda item: (item[1], item[0])):
        row = bom["by_key"][key]
        by_bom.setdefault(BOM_OF_KIND.get(row["kind"], "OTHER"), []).append(
            {"asset_id": row["name"], "kind": row["kind"], "hops": distance})
    chain_order = ["HBOM", "CBOM", "SBOM", "TBOM", "NBOM", "VBOM", "EVIDENCE",
                   "VULNERABILITY", "OTHER"]
    ordered = {name: by_bom[name] for name in chain_order if name in by_bom}
    return {
        "schema": HBOM_SCHEMA,
        "query": text,
        "seed": bom["by_key"][seed]["name"],
        "by_bom": ordered,
        "views": len(ordered),
        "statement": (
            f"{bom['by_key'][seed]['name']}: "
            + ", ".join(f"{name} {len(rows)}" for name, rows in ordered.items())
            + " — one graph, read as separate views"),
        "not_proven": [
            "that two assets in different views are the same fact: they are the same "
            "asset when an edge joins them, and co-occurrence is not a join",
            "that the walk is exhaustive: a relationship nobody recorded is missing here, "
            "not absent from the estate",
        ],
    }


# --------------------------------------------------------------------------- #
# From stored hardware rows — the same adapter shape as the TechBOM's
# --------------------------------------------------------------------------- #

#: the device types a collector writes into ``hardware_assets.device_type``, mapped onto
#: the kinds. Anything else is reported as skipped rather than guessed into a server.
DEVICE_TYPE_KINDS: dict[str, str] = {
    "server": "PHYSICAL_SERVER", "physical_server": "PHYSICAL_SERVER",
    "host": "HOST", "bare_metal": "PHYSICAL_SERVER", "mainframe": "PHYSICAL_SERVER",
    "hsm": "HSM", "kms": "KMS", "tpm": "TPM", "cpu": "CPU", "memory": "MEMORY",
    "motherboard": "MOTHERBOARD", "bios": "BIOS", "nic": "NIC",
    "network_interface": "NIC", "storage": "STORAGE", "disk": "DISK",
    "raid": "RAID_CONTROLLER", "raid_controller": "RAID_CONTROLLER", "gpu": "GPU",
    "pci": "PCI_DEVICE", "crypto_accelerator": "CRYPTO_ACCELERATOR",
    "smart_card": "SMART_CARD", "smartcard": "SMART_CARD",
    "security_appliance": "SECURITY_APPLIANCE", "firewall": "FIREWALL",
    "router": "FIREWALL", "switch": "NETWORK_SEGMENT",
    "hypervisor": "HYPERVISOR", "vm": "VM", "virtual_machine": "VM",
    "os": "OS", "kubernetes_node": "KUBERNETES_NODE",
    "cloud_instance": "CLOUD_INSTANCE", "cloud_region": "CLOUD_REGION",
}


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return _norm(value) or None


def _content_hash(*parts: Any) -> str:
    return "sha256:" + hashlib.sha256(
        "|".join(_norm(part) for part in parts).encode("utf-8")).hexdigest()


def stored_hardware(rows: Iterable[Mapping[str, Any]], *,
                    environment: Any = "PRODUCTION") -> dict[str, Any]:
    """``hardware_assets`` rows → hardware estate parts, with what cannot be placed named.

    A stored row is not an observation: the class ceiling is ``CONFIGURED`` at best (an
    agent inventory read), the evidence is the row's own agent and timestamps, and the
    content hash is the fingerprint the engine already computed. A row with no identity
    anchor, or a ``device_type`` this model cannot place, is skipped **with the reason**
    rather than defaulted into a server.
    """
    assets: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in rows or []:
        asset_id = _norm(row.get("asset_id"))
        device_type = _norm(row.get("device_type")).lower() or "other"
        kind = DEVICE_TYPE_KINDS.get(device_type)
        subject = asset_id or f"(row {row.get('id')})"
        if not kind:
            skipped.append({"kind": "HARDWARE", "subject": subject,
                            "reason": (f"its device_type {device_type!r} is not one this "
                                       "model can place, so it is not defaulted into a "
                                       "server")})
            continue
        observed = _iso(row.get("last_seen")) or _iso(row.get("first_seen"))
        if not observed:
            skipped.append({"kind": kind, "subject": subject,
                            "reason": ("the row carries no observation time, so the "
                                       "evidence it cites cannot be ordered")})
            continue
        fingerprint = _norm(row.get("current_fingerprint")) or _content_hash(
            asset_id, row.get("manufacturer"), row.get("model"),
            _iso(row.get("last_seen")))
        record = evidence(
            f"HW-{_digest(asset_id or str(row.get('id')), 8).upper()}",
            collector="hardware-agent", collector_version=row.get("agent_version"),
            target_id=asset_id or None, observed_at=observed,
            source="hardware_assets", evidence_type="INVENTORY",
            raw_reference=_norm(row.get("current_fingerprint")) or None,
            normalized_fact=f"{_norm(row.get('manufacturer'))} "
                            f"{_norm(row.get('model'))}".strip() or None,
            hash=fingerprint,
            confidence="HIGH" if row.get("current_fingerprint") else "MEDIUM")
        raw_firmware = row.get("firmware")
        payload = dict(raw_firmware) if isinstance(raw_firmware, Mapping) else (
            {"version": _norm(raw_firmware)} if _norm(raw_firmware) else {})
        try:
            device = hardware(
                kind, name=asset_id or None,
                asset_id=asset_id or None,
                manufacturer=row.get("manufacturer"), model=row.get("model"),
                serial_number=row.get("serial_reference"),
                hardware_revision=row.get("hardware_revision"),
                firmware_version=payload.get("version"),
                first_seen=_iso(row.get("first_seen")),
                last_seen=_iso(row.get("last_seen")),
                status=(_norm(row.get("last_change")) or "ACTIVE").upper()
                if row.get("last_change") in {"ACTIVE", "RETIRED"} else "ACTIVE",
                environment=environment, evidence_ids=[record["evidence_id"]],
                evidence=[record],
                **{key: row.get(key) for key in ("risk_level", "agent_id")
                   if row.get(key)},
            )
        except Refused as exc:
            skipped.append({"kind": kind, "subject": subject, "reason": exc.reason,
                            "code": exc.code})
            continue
        assets.append(device)

        # the vendor chain a stored row can support: manufacturer → product → device. The
        # lifecycle status is whatever the row recorded, and UNKNOWN when it recorded none.
        vendor_name = _norm(row.get("manufacturer"))
        model_name = _norm(row.get("model"))
        if vendor_name and model_name:
            product_name = f"{vendor_name} {model_name}"
            lifecycle_status = (_norm(row.get("lifecycle")) or "UNKNOWN").upper()
            if lifecycle_status not in PRODUCT_STATUS:
                lifecycle_status = "UNKNOWN"
            product_row = tb.asset("VENDOR_PRODUCT", product_name,
                                   environment=environment, vendor=vendor_name,
                                   model=model_name, support_status=lifecycle_status,
                                   eol_date=_norm(row.get("eol_date")) or None,
                                   evidence_ids=[record["evidence_id"]])
            vendor_row = tb.asset("VENDOR", vendor_name, environment=environment,
                                  evidence_ids=[record["evidence_id"]])
            assets += [product_row, vendor_row]
            claims.append(claim(device["name"], "HAS_MODEL", product_name,
                                basis="vendor-datasheet",
                                evidence_ids=[record["evidence_id"]]))
            claims.append(claim(product_name, "SUPPLIED_BY", vendor_name,
                                basis="vendor-datasheet",
                                evidence_ids=[record["evidence_id"]]))

        if payload:
            release = firmware(
                f"{_norm(row.get('manufacturer'))} {_norm(row.get('model'))} firmware "
                f"{_norm(payload.get('version')) or 'unspecified'}".strip(),
                version=payload.get("version"),
                vendor=row.get("manufacturer"), product=row.get("model"),
                release_date=payload.get("release_date"),
                status=(_norm(payload.get("status") or payload.get("support_status"))
                        or "UNKNOWN").upper(),
                eol_date=payload.get("eol_date"), eos_date=payload.get("eos_date"),
                vulnerabilities=payload.get("vulnerabilities") or (),
                evidence_ids=[record["evidence_id"]], environment=environment)
            assets.append(release)
            claims.append(claim(device["name"], "RUNS_FIRMWARE", release["name"],
                                basis="agent-inventory",
                                evidence_ids=[record["evidence_id"]]))

        capabilities = row.get("crypto_capabilities") or {}
        if isinstance(capabilities, Mapping):
            capability_rows = [{"algorithm": algorithm, **(spec if isinstance(
                spec, Mapping) else {})} for algorithm, spec in capabilities.items()]
        elif isinstance(capabilities, Sequence) and not isinstance(capabilities, str):
            capability_rows = [row_ for row_ in capabilities if isinstance(row_, Mapping)]
        else:
            capability_rows = []
        for spec in capability_rows:
            algorithm = _norm(spec.get("algorithm"))
            if not algorithm:
                continue
            row_capability = capability(
                f"{_norm(device['name'])} {algorithm}", algorithm=algorithm,
                key_types=spec.get("key_types"), key_sizes=spec.get("key_sizes"),
                operations=spec.get("operations"), evidence_ids=[record["evidence_id"]],
                environment=environment)
            assets.append(row_capability)
            claims.append(claim(device["name"], "SUPPORTS", row_capability["name"],
                                basis="agent-inventory",
                                evidence_ids=[record["evidence_id"]]))

    return {"assets": assets, "claims": claims, "skipped": skipped,
            "statement": (
                f"{len(assets)} hardware asset(s) and {len(claims)} claim(s) read from the "
                f"stored rows; {len(skipped)} row(s) skipped with a reason; a stored row "
                "supports CONFIGURED at best, because an inventory read is not a probe")}


# --------------------------------------------------------------------------- #
# Projection guard
# --------------------------------------------------------------------------- #

def from_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Always refused: an HBOM is a projection, and a projection is never a source."""
    if isinstance(document, Mapping) and document.get("schema") == HBOM_SCHEMA:
        raise ValueError(
            "an HBOM is the hardware view of the canonical estate, not a source: feeding "
            "one back in would make a second source of truth and the two would drift")
    if isinstance(document, Mapping) and document.get("schema") == tb.SCHEMA:
        raise ValueError(
            "a TechBOM is a projection of the canonical estate, not a source; build the "
            "hardware view from the estate instead")
    raise ValueError(f"build() takes a {ESTATE_SCHEMA} document")


def summary(document: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: what hardware exists, how well it is described, what has ended."""
    assets = document.get("assets") or []
    return {
        "schema": HBOM_SCHEMA,
        "assets": len(assets),
        "by_kind": document.get("counts") or {},
        "identities_provisional": sum(
            1 for row in assets
            if (row.get("attributes") or {}).get("identity", {}).get("provisional")),
        "field_gaps": document.get("field_gaps"),
        "component_roots": len(document.get("component_tree") or []),
        "firmware_actionable": [row["firmware"] for row in
                                document.get("firmware_lifecycle") or []
                                if row["actionable"]],
        "refusals": len(document.get("refusals") or []),
        "coverage": (document.get("coverage") or {}).get("overall"),
        "statement": document.get("statement", ""),
        "not_proven": list(document.get("not_proven") or []),
    }


def bom_link(document: Mapping[str, Any], *, base: Any = "hbom") -> dict[str, Any]:
    """The pointer another BOM carries to this one, instead of a copy of its rows.

    A BOM-Link is a reference: ``bom-link:<base>:<digest>``. Copying hardware rows into the
    CBOM would create the second source of truth the review's last point is about, so what
    travels is the identity of the document plus the digest that pins it.
    """
    digest = _digest(canonical_json(document), 16)
    return {
        "schema": HBOM_SCHEMA,
        "link": f"bom-link:{_norm(base) or 'hbom'}:{digest}",
        "asset_count": len(document.get("assets") or []),
        "derived_from": document.get("derived_from"),
        "statement": ("a link names the document and pins it by digest; the rows stay in "
                      "the estate, where every view reads the same ones"),
    }


__all__ = [
    "HBOM_SCHEMA", "ESTATE_SCHEMA", "HARDWARE_KINDS", "ASSET_FIELDS", "IDENTITY_ANCHORS",
    "NETWORK_IDENTIFIERS", "KEY_MATERIAL_KEYS", "FIRMWARE_STATUS", "FIELD_CHANGE",
    "DRIFT_TYPES", "BOM_OF_KIND", "evidence", "identity", "hardware", "firmware",
    "vulnerability", "capability", "claim", "merge", "estate", "component", "server",
    "HBOM_KINDS", "CONTAINMENT_RELATIONS", "hsm", "build", "coverage", "drift",
    "correlate", "radius", "stored_hardware", "DEVICE_TYPE_KINDS", "cpu_topology",
    "network_device", "product", "product_lifecycle", "impact_summary",
    "cpu_topology",
    "from_document", "summary",
    "bom_link",
]
