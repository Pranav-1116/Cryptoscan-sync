"""Storage optimization for continuous CryptoScan operation (spec §2.1/§7).

The repeated-collection problem: continuous scanning rediscovers the same
cryptographic evidence every run. Storing each discovery whole multiplies
storage; this package stores the bytes once and the provenance always:

* :mod:`db.storage.cas` — content-addressed storage (SHA-256), zstd
  compression, chunking, reference counting, tenant-bound deduplication.
* :mod:`db.storage.provenance` — deduplicate evidence bytes; NEVER
  deduplicate owners, collection times, source locations or authorization
  contexts.
* :mod:`db.storage.delta` — incremental snapshots: deltas between runs,
  unchanged content referenced, historical states preserved.
* :mod:`db.storage.lifecycle` — retention policies, hot/warm/cold tiers,
  archive-verified expiry, safe garbage collection (dry-run by default).
* :mod:`db.storage.quotas` — per-tenant and per-job storage budgets.
* :mod:`db.storage.monitoring` — usage truth and near-full alerts.
* :mod:`db.storage.restore` — restore testing with records of itself.

PostgreSQL holds the metadata and relationships; the evidence objects go
to the configured object store (database bodies by default, a
bank-approved object-storage directory via ``FileObjectStore``).
"""

from db.storage.cas import (  # noqa: F401
    CHUNK_SIZE, ContentAddressedStore, ContentCorruptionError, ContentGoneError,
    ContentRef, DbObjectStore, FileObjectStore, ObjectStore, S3ObjectStore, sha256_hex,
)
from db.storage.compression import compress, decompress  # noqa: F401
from db.storage.provenance import record_evidence_content  # noqa: F401
from db.storage.delta import (  # noqa: F401
    SnapshotDiff, diff_items, materialize_snapshot, snapshot_state, store_snapshot_delta,
)
from db.storage.quotas import QuotaExceeded, QuotaUsage, check_quota, usage  # noqa: F401
from db.storage.lifecycle import (  # noqa: F401
    DEFAULT_POLICIES, LifecycleAction, SweepReport, ensure_default_policies,
    gc_unreferenced, policy_for, retention_sweep, transition_tiers,
)
from db.storage.monitoring import StorageAlert, UsageReport, space_alerts, usage_report  # noqa: F401
from db.storage.restore import run_restore_test, verify_restorable  # noqa: F401
