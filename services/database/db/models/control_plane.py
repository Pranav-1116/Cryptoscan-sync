"""ZELNX Control Plane — the P0 enterprise control layer.

Groups the cross-cutting capabilities a large-bank / critical-infrastructure
deployment needs on top of the universal scan engine:

* Multi-tenant isolation + hierarchical scope authorization
  (Region -> Business Unit -> Environment -> Asset) — ABAC on top of RBAC.
* Credential / secrets-vault references (never stores key material), with
  rotation, expiration, health and access auditing.
* Agent fleet management (enrollment, heartbeats, upgrade/rollback, config).
* Safe-scanning policies (mode, rate/connection budgets, exclusions,
  maintenance windows, automatic stop conditions).
* Asset identity resolution (canonical asset identity across sources with
  CONFIRMED/PROBABLE/POSSIBLE/UNKNOWN/CONFLICT confidence).
* Durable event queue (outbox) for decoupled worker processing.
* Detection benchmarking datasets/results (precision/recall/F1/FPR/FNR).

Security doctrine: deterministic, fail-closed, metadata-only. No secret
material is ever persisted here — credentials are *references* into an
external vault (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager,
HashiCorp Vault, or an on-prem KMS), and short-lived tokens are fetched
out-of-band by the scanner at run time.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped

# --------------------------------------------------------------------------- #
# Authorization / tenancy
# --------------------------------------------------------------------------- #

#: hierarchy levels for scope grants (most -> least specific).
SCOPE_LEVELS = ("region", "business_unit", "environment", "asset")

#: asset-identity / detection confidence states (never force YES/NO).
CONFIDENCE_STATES = ("CONFIRMED", "PROBABLE", "POSSIBLE", "UNKNOWN", "CONFLICT")


class Tenant(BaseModel):
    """An isolated customer / tenant. Data residency is declared per tenant."""

    __tablename__ = "cp_tenants"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    #: data-residency region the tenant's data must stay within (e.g. "uae", "eu", "us")
    data_residency_region: Mapped[str] = mapped_column(String(40), nullable=False, default="us")
    #: processing regions allowed for this tenant's workloads
    processing_regions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    metadata_: Mapped[dict | None] = mapped_column("extra_info", JSON, nullable=True)


class ScopeGrant(BaseModel, TenantScoped):
    """An authorization grant: a subject (user/role) may act within a scope.

    Scope is hierarchical: region -> business_unit -> environment -> asset.
    A grant at a higher level implies access below it. Enforcement is
    fail-closed: an action is allowed only if a matching grant exists.
    """

    __tablename__ = "cp_scope_grants"

    subject: Mapped[str] = mapped_column(String(200), nullable=False, index=True)  # username or role:*
    subject_type: Mapped[str] = mapped_column(String(20), nullable=False, default="user")  # user/role
    actions: Mapped[list] = mapped_column(JSON, nullable=False)  # ["read"] or ["*"]
    region: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    business_unit: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    effect: Mapped[str] = mapped_column(String(10), nullable=False, default="allow")  # allow/deny
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# --------------------------------------------------------------------------- #
# Credentials / secrets vault (references only — never the secret)
# --------------------------------------------------------------------------- #

CREDENTIAL_KINDS = ("cloud", "network_device", "hsm", "database", "kubernetes",
                    "git", "siem", "api", "other")
VAULT_PROVIDERS = ("aws_secrets_manager", "azure_key_vault", "gcp_secret_manager",
                   "hashicorp_vault", "kms_onprem", "manual_out_of_band")
CREDENTIAL_STATUSES = ("active", "rotating", "expired", "revoked", "error", "pending")


class CredentialRef(BaseModel, TenantScoped):
    """A reference to a secret held in an external vault. No key material here."""

    __tablename__ = "cp_credentials"

    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False, default="other")
    vault_provider: Mapped[str] = mapped_column(String(40), nullable=False, default="manual_out_of_band")
    #: non-secret locator, e.g. secret ARN/name/URI within the vault
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    #: least-privilege scope the credential is restricted to (metadata)
    least_privilege_scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    rotation_policy_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    health_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    access_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


# --------------------------------------------------------------------------- #
# Agent fleet
# --------------------------------------------------------------------------- #

AGENT_STATUSES = ("enrolled", "connecting", "connected", "offline", "upgrading",
                  "error", "retired")
AGENT_PLATFORMS = ("linux", "windows", "container", "appliance", "ot_gateway")


class Agent(BaseModel, TenantScoped):
    """A deployed ZELNX agent (on-prem / air-gapped / hybrid environments)."""

    __tablename__ = "cp_agents"

    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(120), nullable=True)
    platform: Mapped[str] = mapped_column(String(20), nullable=False, default="linux")
    #: enrollment token fingerprint (the token itself is one-time and never stored)
    enrollment_token_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="enrolled", index=True)
    version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    target_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    link: Mapped[str] = mapped_column(String(20), nullable=False, default="disconnected")  # disconnected/connecting/encrypted
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    resource_limits: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # cpu/mem/bandwidth caps
    offline_events_buffered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cert_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)


# --------------------------------------------------------------------------- #
# Safe scanning
# --------------------------------------------------------------------------- #

SCAN_SAFETY_MODES = ("safe", "passive", "low_impact", "standard", "deep", "emergency_stop")


class SafeScanPolicy(BaseModel, TenantScoped):
    """Impact-protection policy applied to scanning within a scope."""

    __tablename__ = "cp_safe_scan_policies"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scope_region: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    scope_environment: Mapped[str | None] = mapped_column(String(120), nullable=True)
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="standard")
    rate_limit_qps: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_connections: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    concurrent_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    scan_budget_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=240)
    excluded_assets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    excluded_ports: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    excluded_protocols: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    #: weekly maintenance windows [{"day":"sun","start":"01:00","duration_minutes":120}]
    maintenance_windows: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    maintenance_timezone: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: automatic stop conditions (e.g. error_rate threshold, latency spike)
    auto_stop_conditions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    emergency_stop: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# --------------------------------------------------------------------------- #
# Asset identity resolution
# --------------------------------------------------------------------------- #

class AssetIdentity(BaseModel, TenantScoped):
    """Canonical identity for a discovered asset, fused from multiple sources."""

    __tablename__ = "cp_asset_identities"
    # Canonical identifiers are tenant-local. A global unique index would turn
    # another tenant's existing asset into an existence oracle on insert.
    __table_args__ = (
        UniqueConstraint("tenant_id", "canonical_id", name="uq_cp_asset_identity_tenant_canonical"),
    )

    canonical_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    region: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    business_unit: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    environment: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    maintainer: Mapped[str | None] = mapped_column(String(200), nullable=True)
    application: Mapped[str | None] = mapped_column(String(200), nullable=True)
    service: Mapped[str | None] = mapped_column(String(200), nullable=True)
    data_classification: Mapped[str | None] = mapped_column(String(40), nullable=True)
    criticality: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN", index=True)
    evidence_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    source_refs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)  # source -> external id


# --------------------------------------------------------------------------- #
# Durable event queue (outbox) — decouples scanner/control plane from workers
# --------------------------------------------------------------------------- #

EVENT_STATUSES = ("queued", "leased", "completed", "dead")
EVENT_PRIORITIES = ("critical", "high", "normal", "low")


class QueuedEvent(BaseModel, TenantScoped):
    """A durable event in the outbox/inbox queue (backed by Redis in prod;
    this table provides a persistent audit/outbox and fallback transport)."""

    __tablename__ = "cp_queued_events"

    event_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(60), nullable=False, default="control_plane")
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="normal", index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    leased_by: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


# --------------------------------------------------------------------------- #
# Detection benchmarking — measure precision/recall/F1 against ground truth
# --------------------------------------------------------------------------- #

BENCHMARK_RUN_STATUSES = ("created", "scored", "archived")


class BenchmarkDataset(BaseModel):
    """A labelled ground-truth dataset (references to labelled cases, not the
    raw secrets). Cases are stored as metadata rows in cp_benchmark_cases."""

    __tablename__ = "cp_benchmark_datasets"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sector: Mapped[str | None] = mapped_column(String(50), nullable=True)
    case_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class BenchmarkCase(BaseModel):
    """A single labelled ground-truth item: what the scanner SHOULD detect."""

    __tablename__ = "cp_benchmark_cases"

    dataset_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    case_ref: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    #: the ground-truth label (e.g. algorithm / finding type) or "benign"
    ground_truth: Mapped[str] = mapped_column(String(120), nullable=False)
    expected_detection: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    metadata_: Mapped[dict | None] = mapped_column("extra_info", JSON, nullable=True)


class BenchmarkRun(BaseModel):
    """A scored benchmark run: scanner predictions vs ground truth."""

    __tablename__ = "cp_benchmark_runs"

    dataset_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scanner_id: Mapped[str] = mapped_column(String(120), nullable=False, default="universal")
    scanner_version: Mapped[str | None] = mapped_column(String(60), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="created")
    true_positive: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    false_positive: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    true_negative: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    false_negative: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    f1: Mapped[float | None] = mapped_column(Float, nullable=True)
    false_positive_rate: Mapped[float | None] = mapped_column(Float, nullable=True)
    accuracy: Mapped[float | None] = mapped_column(Float, nullable=True)
    scored_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)


# --------------------------------------------------------------------------- #
# Outbound webhook delivery (SIEM / ITSM / SOAR) — real HTTP fan-out audit
# --------------------------------------------------------------------------- #

DELIVERY_STATUSES = ("delivered", "failed", "skipped")


class SecurityPosture(BaseModel, TenantScoped):
    """A durable snapshot of ZELNX's own security posture.

    The security center aggregates live signals (agent fleet health, plugin
    trust, anomaly flags, failed logins, certificate expiry, audit-chain
    integrity, credential health) into a deterministic 0-100 score plus a
    component breakdown. Each GET/score is computed atomically by the control
    plane; this table retains the history so a 24/7 SOC (and the audit
    governance model) can show posture over time, not just the current frame.

    Deterministic and metadata-only: no secret material is ever persisted.
    """

    __tablename__ = "cp_security_posture"

    score: Mapped[int] = mapped_column(Integer, nullable=False)
    agents_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    agents_healthy: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    plugins_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    plugins_verified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threats_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threats_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cert_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cert_valid_pct: Mapped[int | None] = mapped_column(Integer, nullable=True)
    audit_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    credentials_active: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    credentials_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: per-signal sub-scores (0..1) + human-readable notes for the console.
    components: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="live")


class DeliveryLog(BaseModel, TenantScoped):
    """One outbound webhook delivery attempt to a registered integration.

    Records the deterministic outcome of actually POSTing a SIEM/ITSM event to
    an external system: HTTP status, attempts, signature prefix (never the
    secret), duration, and any error. This is the audit trail that turns
    'event enqueued' into 'event delivered to the SOC/ticketing system'.
    """

    __tablename__ = "cp_delivery_logs"

    integration_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False, default="webhook")
    kind: Mapped[str] = mapped_column(String(20), nullable=False, default="siem", index=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    event_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="skipped", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    signature_prefix: Mapped[str | None] = mapped_column(String(24), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
