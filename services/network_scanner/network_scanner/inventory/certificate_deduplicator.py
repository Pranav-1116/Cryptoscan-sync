"""SHA-256 fingerprint certificate deduplication."""

from network_scanner.inventory.certificate_inventory import merge_certificates

dedupe_certificates = merge_certificates

__all__ = ["dedupe_certificates", "merge_certificates"]
