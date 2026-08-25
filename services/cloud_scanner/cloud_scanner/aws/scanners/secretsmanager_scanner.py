"""Secrets Manager scanning."""

from cloud_scanner.aws.scanners import scan_secretsmanager

__all__ = ["scan_secretsmanager"]
