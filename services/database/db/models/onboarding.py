"""Enterprise onboarding aggregate: Organization, Environment, Authorized
Scope, and Connections (the setup flow before discovery).

This is the top-level customer-journey model. It does not replace the existing
per-domain tables (cloud_accounts, network_scan_targets, repo_configurations);
it organizes them so the platform knows *who the customer is, which
environments they have, and exactly what ZELNX is authorized to inspect*.

Security: connector configuration stores NON-SECRET references only (IAM role
ARN, service principal, host/port, method). No credentials, tokens or keys are
ever persisted — discovery always uses read-only/least-privilege access the
customer grants out-of-band. A strict whitelist enforces this.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel

#: connector/config keys that may never be persisted (secret material).
SECRET_KEY_HINTS = ("secret", "password", "token", "private_key", "access_key",
                    "client_secret", "credential", "api_key", "key_material")

ENVIRONMENT_TYPES = (
    "production", "dr", "development", "testing", "staging",
    "ot", "cloud", "hybrid",
)

SCOPE_KINDS = ("network", "cloud", "application", "hardware")

CONNECTOR_KINDS = (
    "network", "aws", "azure", "gcp", "kubernetes", "git",
    "vmware", "hardware", "hsm", "siem", "other",
)

CONNECTOR_METHODS = (
    "agent", "snmp", "ssh", "api", "netconf", "restconf",
    "vendor_api", "syslog", "flow_telemetry", "iam_role", "service_principal",
    "service_account", "other",
)

SCAN_MODES = ("discovery", "standard", "deep", "passive", "continuous",
              "targeted", "compliance", "pqc")

ONBOARDING_STAGES = (
    "organization", "sector", "environment", "scope",
    "connections", "policy", "discovery",
)


class Organization(BaseModel):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    sector: Mapped[str] = mapped_column(String(50), nullable=False, default="generic")
    industry: Mapped[str | None] = mapped_column(String(100), nullable=True)
    regions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    business_units: Mapped[list | None] = mapped_column(JSON, nullable=True)
    #: onboarding wizard progress: organization/sector/environment/scope/connections/policy/discovery
    onboarding_stage: Mapped[str] = mapped_column(String(40), nullable=False, default="organization")
    onboarding_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class Environment(BaseModel):
    __tablename__ = "environments"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    env_type: Mapped[str] = mapped_column(String(40), nullable=False, default="production")
    region: Mapped[str | None] = mapped_column(String(120), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: scan mode for this environment (passive recommended for OT)
    scan_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="standard")
    active_probing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ScopeEntry(BaseModel):
    """One authorized target. The scanner only ever operates within these."""

    __tablename__ = "scope_entries"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    env_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # network/cloud/application/hardware
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Connector(BaseModel):
    """A registered infrastructure connection (Connections Center)."""

    __tablename__ = "connectors"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    env_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    method: Mapped[str] = mapped_column(String(30), nullable=False, default="api")
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="passive")  # passive/active
    #: non-secret reference metadata only (role ARN, principal, host, ...)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending/configured/connected/error
    last_tested_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    test_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    agent_healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class DiscoveryRun(BaseModel):
    """A record of an initial/continuous discovery orchestration."""

    __tablename__ = "discovery_runs"

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    run_type: Mapped[str] = mapped_column(String(20), nullable=False, default="initial")  # initial/targeted/continuous
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")  # planned/running/complete
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    assets_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    triggered_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
