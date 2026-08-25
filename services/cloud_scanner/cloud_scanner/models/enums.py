"""Cloud provider / service / scan-method enumerations."""

from __future__ import annotations

from enum import Enum


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    IAC = "IAC"
    UNKNOWN = "UNKNOWN"


class CloudService(str, Enum):
    KMS = "KMS"
    S3 = "S3"
    ACM = "ACM"
    ELB = "ELB"
    RDS = "RDS"
    SECRETS = "SECRETS"
    STORAGE = "STORAGE"
    KEY_VAULT = "KEY_VAULT"
    UNKNOWN = "UNKNOWN"


class ScanMethod(str, Enum):
    IAC = "IAC"
    LIVE = "LIVE"
    TAG = "TAG"
