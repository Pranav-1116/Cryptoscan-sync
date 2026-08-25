"""Container registry pull + webhook adapters."""

from container_scanner.registry.acr_handler import parse_acr_event
from container_scanner.registry.dockerhub_handler import parse_dockerhub_event
from container_scanner.registry.ecr_handler import parse_ecr_event
from container_scanner.registry.gcr_handler import parse_gcr_event
from container_scanner.registry.harbor_handler import parse_harbor_event
from container_scanner.registry.registry_webhook_handler import parse_registry_event

__all__ = [
    "parse_acr_event",
    "parse_dockerhub_event",
    "parse_ecr_event",
    "parse_gcr_event",
    "parse_harbor_event",
    "parse_registry_event",
]
