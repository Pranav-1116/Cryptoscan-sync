"""Compatibility package: `database.db` is an alias for `db`."""

from importlib import import_module
import sys

import db

_ALIASES = [
    "db",
    "db.models",
    "db.models.base",
    "db.models.scan",
    "db.models.evidence_record",
    "db.models.scan_job",
    "db.models.baseline",
    "db.models.drift_event",
    "db.models.repo_configuration",
    "db.models.verification_log",
    "db.connection",
    "db.connection.session",
    "db.connection.engine",
    "db.repositories",
    "db.repositories.base_repository",
    "db.repositories.job_repository",
    "db.repositories.evidence_repository",
    "db.repositories.scan_repository",
    "db.repositories.drift_repository",
    "db.repositories.baseline_repository",
    "db.loader",
    "db.loader.evidence_loader",
]

for name in _ALIASES:
    try:
        module = import_module(name)
        sys.modules[f"database.{name}"] = module
    except Exception:
        continue

sys.modules["database.db"] = db
