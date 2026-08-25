"""Detection method and registry type labels."""

from __future__ import annotations

from enum import Enum


class DetectionMethod(str, Enum):
    PACKAGE_MANAGER = "PACKAGE_MANAGER"
    BINARY_FINGERPRINT = "BINARY_FINGERPRINT"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"
    PYTHON_PACKAGE = "PYTHON_PACKAGE"
    JAR = "JAR"


class RegistryType(str, Enum):
    ECR = "ecr"
    ACR = "acr"
    GCR = "gcr"
    DOCKERHUB = "dockerhub"
    HARBOR = "harbor"
    GENERIC = "generic"
