"""Map ELB SSL policy → TLS config."""

from cloud_scanner.aws.mappers import min_tls_from_protocols, weak_tls_protocols

__all__ = ["min_tls_from_protocols", "weak_tls_protocols"]
