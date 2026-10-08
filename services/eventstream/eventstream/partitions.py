"""Tenant partitioning for the event-stream stores (2026-10).

The bus logs and the live-CBOM version store used to be process-global:
every tenant's observations, attack detections and CBOM chains lived in one
directory set, so any tenant could read another tenant's stream. The
partition rule is deliberately boring:

- an unscoped request (single-tenant install, platform operator) uses the
  base directory itself — byte-for-byte the paths used before tenancy, so
  on-prem deployments and their history are unchanged;
- a tenant-scoped request uses ``<base>/tenants/<tenant-id>/``;

and each scope sees **only** its own partition — no cross-visibility in
either direction (unlike DB rows, where a tenant also sees NULL-owned
platform rows: stream partitions carry raw observations and detections,
and one customer's data must never surface in another's console).

Tenant ids come from the membership-validated request scope (UUIDs), but
the filesystem name is sanitized anyway — a tenant id is never trusted as
a path.
"""

from __future__ import annotations

import os
from pathlib import Path

TENANT_SUBDIR = "tenants"


def _safe_name(tenant: str) -> str:
    return "".join(ch for ch in str(tenant) if ch.isalnum() or ch in "-_") or "platform"


def tenant_partition_dir(base: str | os.PathLike[str],
                         tenant: str | None) -> Path:
    """The store directory for ``tenant`` under ``base``.

    ``None`` (no scope) maps to ``base`` itself — the platform partition.
    """
    root = Path(base)
    if not tenant:
        return root
    return root / TENANT_SUBDIR / _safe_name(tenant)


def iter_tenant_partition_dirs(base: str | os.PathLike[str]) -> list[Path]:
    """Every tenant partition that exists under ``base`` (platform base
    excluded). For operator surfaces that aggregate partitions: read-only
    inventory of what is on disk, never a tenant list from the DB."""
    root = Path(base) / TENANT_SUBDIR
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir())
