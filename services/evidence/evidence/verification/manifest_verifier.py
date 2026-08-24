def verify_manifest(manifest) -> bool:
    if hasattr(manifest, "verify_manifest_hash"):
        return manifest.verify_manifest_hash()
    return bool(manifest.get("manifest_hash"))
