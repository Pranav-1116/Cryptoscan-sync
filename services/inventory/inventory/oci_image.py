"""Offline four-file OCI metadata reader. No pull, layer reads/extraction or exec."""

import hashlib
from shared_models.oci_image import (
    OciImageFact,
    OciLayer,
    MANIFEST_TYPE,
    CONFIG_TYPE,
    LAYER_TYPES,
    image_resource,
    select_oci_manifest,
    metadata_bytes,
)
from shared_models.qualified_export import bounded_json


def descriptor(value, media_type=None):
    import re

    if (
        not isinstance(value, dict)
        or any(k in value for k in ("urls", "data", "artifactType"))
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("digest", "")))
        or type(value.get("size")) is not int
        or not 0 <= value["size"] <= 9007199254740991
    ):
        raise ValueError("Unsupported OCI descriptor; no remote/embedded fallback")
    if media_type and value.get("mediaType") != media_type:
        raise ValueError("Unsupported OCI media type")
    return value


def collect_image(item, limit, charge):
    from inventory.host import _read, Refused

    root, arch, variant, manifest_sha = image_resource(item.path)
    consumed = 0

    def counted(size):
        nonlocal consumed
        charge(size)
        consumed += size

    def read(relative):
        if consumed >= limit:
            raise Refused("BUDGET_EXCEEDED", "LIMIT")
        raw = _read(root + "/" + relative, limit - consumed, counted)
        return raw, bounded_json(raw, max_bytes=limit)

    def verified_blob(desc):
        raw, data = read("blobs/sha256/" + desc["digest"][7:])
        if len(raw) != desc["size"] or hashlib.sha256(raw).hexdigest() != desc["digest"][7:]:
            raise ValueError("OCI blob digest/size mismatch")
        return raw, data

    samples = []
    for _ in range(2):
        layout_raw, layout = read("oci-layout")
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("Unsupported OCI layout")
        index_raw, index = read("index.json")
        selected = descriptor(select_oci_manifest(index, "sha256:" + manifest_sha), MANIFEST_TYPE)
        platform = selected.get("platform")
        if not isinstance(platform, dict) or platform != {
            "os": "linux",
            "architecture": arch,
            **({"variant": variant} if variant else {}),
        }:
            raise ValueError("Approved OCI platform differs from descriptor")
        manifest_raw, manifest = verified_blob(selected)
        if (
            not isinstance(manifest, dict)
            or type(manifest.get("schemaVersion")) is not int
            or manifest["schemaVersion"] != 2
            or manifest.get("mediaType") != MANIFEST_TYPE
            or any(k in manifest for k in ("subject", "artifactType"))
        ):
            raise ValueError("Direct OCI image manifest required")
        config_desc = descriptor(manifest.get("config"), CONFIG_TYPE)
        config_raw, config = verified_blob(config_desc)
        if (
            not isinstance(config, dict)
            or config.get("os") != "linux"
            or config.get("architecture") != arch
            or config.get("variant") not in (None, variant)
        ):
            raise ValueError("OCI config platform mismatch")
        rootfs = config.get("rootfs")
        layers = manifest.get("layers")
        if (
            not isinstance(rootfs, dict)
            or rootfs.get("type") != "layers"
            or not isinstance(rootfs.get("diff_ids"), list)
            or not isinstance(layers, list)
            or len(layers) > 128
            or len(layers) != len(rootfs["diff_ids"])
        ):
            raise ValueError("Bounded consistent OCI rootfs descriptors required")
        layer_facts = []
        for entry, diff_id in zip(layers, rootfs["diff_ids"]):
            entry = descriptor(entry)
            if entry.get("mediaType") not in LAYER_TYPES:
                raise ValueError("Unsupported OCI layer media type")
            layer_facts.append(
                OciLayer(
                    digest=entry["digest"], size=entry["size"], media_type=entry["mediaType"], diff_id=diff_id
                ).model_dump(mode="json")
            )
        image_config = config.get("config", {})
        if not isinstance(image_config, dict):
            raise ValueError("Invalid OCI image configuration")
        ports = image_config.get("ExposedPorts", {})
        if not isinstance(ports, dict) or len(ports) > 64 or any(v != {} for v in ports.values()):
            raise ValueError("Invalid bounded OCI port declarations")
        annotations = manifest.get("annotations", {})
        if not isinstance(annotations, dict):
            raise ValueError("Invalid OCI annotations")
        samples.append(
            dict(
                layout_sha256=hashlib.sha256(layout_raw).hexdigest(),
                index_sha256=hashlib.sha256(index_raw).hexdigest(),
                manifest_sha256=manifest_sha,
                manifest_size=len(manifest_raw),
                config_sha256=config_desc["digest"][7:],
                config_size=len(config_raw),
                image_os="linux",
                image_architecture=arch,
                image_variant=variant,
                layers=layer_facts,
                declared_ports=sorted(ports),
                declared_base_digest=annotations.get("org.opencontainers.image.base.digest"),
            )
        )
    if samples[0] != samples[1]:
        raise Refused("INVALID", "INPUT_CHANGED")
    data = samples[1]
    raw = metadata_bytes(data)
    if len(raw) > limit - consumed:
        raise Refused("BUDGET_EXCEEDED", "LIMIT")
    counted(len(raw))
    fact = OciImageFact(
        kind="OCI_IMAGE_METADATA",
        identity_key=f"oci-manifest:sha256:{manifest_sha}:linux:{arch}:{variant or 'unspecified'}",
        interface_sha256=hashlib.sha256(raw).hexdigest(),
        **data,
    )
    return raw, [fact]
