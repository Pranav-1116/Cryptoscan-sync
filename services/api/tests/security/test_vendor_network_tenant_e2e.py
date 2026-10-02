"""End-to-end tenant_id isolation for vendor and network API surfaces."""
from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import TenantResolutionRefused, get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.network_inventory import NetworkInventoryRevision
from db.models.vendor import Vendor
from db.models.vendor_crypto import VendorCryptoInventory
from db.models.vendor_profile import VendorProfileRevision
from db.tenancy import install_tenant_guard

TENANT_A = "tenant-a-11111111-1111-1111-1111-111111111111"
TENANT_B = "tenant-b-22222222-2222-2222-2222-222222222222"


def _make_app():
    # Keep this focused harness independent of the caller's process settings.
    os.environ["ENVIRONMENT"] = "test"
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    install_tenant_guard()
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    # Test environment intentionally omits auth/tenant middleware in the
    # broad API harness. Add the real tenant middleware here so these requests
    # exercise the request boundary, ContextVar scope, and ORM guard together.
    from api.middleware.tenant_scope import TenantScopeMiddleware

    app.add_middleware(TenantScopeMiddleware)

    def current_user(request: Request):
        return request.headers.get("X-Test-User", "user-a")

    app.dependency_overrides[get_current_user] = current_user

    def db_session():
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise

    app.dependency_overrides[get_db_session] = db_session
    return app, session, engine


def _tenant_resolution(request):
    """Test the real middleware/ORM scope with an explicit membership map.

    The production resolver performs the membership lookup; this test replaces
    only that lookup so the in-memory API session remains the same session used
    by the routes. The middleware, tenant_scope context, ORM loader criteria,
    and tenant stamping all remain real.
    """
    user = request.headers.get("X-Test-User", "user-a")
    expected = {"user-a": TENANT_A, "user-b": TENANT_B}.get(user)
    requested = request.headers.get("X-Tenant-ID")
    if expected is None:
        raise TenantResolutionRefused(403, "no tenant membership")
    if requested and requested != expected:
        raise TenantResolutionRefused(404, "Unknown tenant")
    return expected


def _headers(user: str, tenant: str | None = None) -> dict[str, str]:
    result = {"X-Test-User": user}
    if tenant:
        result["X-Tenant-ID"] = tenant
    return result


def _complete_profile(vendor_id: str) -> dict:
    """A non-secret fixture covering every profile section and nested type."""
    return {
        "schema": "cryptoscan.vendor-profile/1",
        "identity": {
            "legal_name": "Evidence-backed Vendor",
            "vendor_id": vendor_id,
            "duns_number": "123456789",
            "vendor_type": "OEM",
            "criticality": "high",
            "vendor_tier": 1,
            "parent_company": "Parent Holdings",
            "ownership_structure": "Private",
            "headquarters_location": "Coimbatore, IN",
            "jurisdictions": ["IN"],
            "operating_locations": ["IN", "AE"],
        },
        "contacts": {
            "business": "business@example.invalid",
            "technical_support": "support@example.invalid",
            "security_incident_response": "security@example.invalid",
            "account_manager": "account@example.invalid",
            "escalation_contacts": ["escalation@example.invalid"],
            "emergency_24x7": "on-call process documented",
        },
        "components": [{
            "component_id": "component-1",
            "name": "Managed Platform",
            "version": "1.2.3",
            "component_type": "SAAS",
            "license_model": "subscription",
            "support_level": "24x7",
            "eol_date": "2030-12-31",
            "replacement_product": "unknown",
            "used_by": ["payments"],
            "criticality": "high",
            "alternatives": ["alternative-provider"],
            "vendor_lock_in_risk": "medium",
        }],
        "contracts": [{
            "contract_id": "contract-1",
            "contract_type": "MSA",
            "start_date": "2026-01-01",
            "end_date": "2027-01-01",
            "auto_renewal": True,
            "renewal_terms": "annual review",
            "termination_notice_days": 90,
            "termination_terms": "written notice",
            "termination_assistance": "transition support",
            "contract_value": 1000,
            "contract_currency": "USD",
            "payment_terms": "net 30",
        }],
        "service_level_agreements": [{
            "contract_id": "contract-1",
            "uptime_guarantee": "99.9%",
            "response_time": "1 hour",
            "resolution_time": "4 hours",
            "business_hours": "24x7",
            "maintenance_windows": "scheduled",
            "measurement_window": "monthly",
            "performance_metrics": {"availability": "observed"},
            "penalties": "service credits",
            "remedies": "remediation plan",
            "service_credits": "defined in contract",
        }],
        "legal_liability": {
            "limitation_of_liability": "contractual cap",
            "indemnification": "mutual",
            "insurance_requirements": "commercial coverage",
            "intellectual_property": "licensed",
            "confidentiality": "NDA",
            "governing_law": "India",
            "dispute_resolution": "arbitration",
        },
        "security_compliance": {
            "assessments": [{
                "assessment_id": "assessment-1",
                "last_assessment_date": "2026-02-01",
                "last_questionnaire_date": "2026-02-02",
                "assessment_type": "QUESTIONNAIRE",
                "assessor": "customer-security-team",
                "assurance_level": "INTERNAL",
                "risk_rating": "medium",
                "risk_score": 42,
                "questionnaire_results": {"status": "self-reported"},
                "remediation_status": "open items tracked",
                "open_findings": [{
                    "finding_id": "finding-1",
                    "title": "Evidence refresh pending",
                    "severity": "medium",
                    "status": "OPEN",
                    "remediation": "collect evidence",
                    "due_date": "2026-12-31",
                    "evidence_reference": "evidence://finding-1",
                }],
            }],
            "certifications": [{
                "certification_type": "ISO 27001",
                "issued_date": "2026-01-01",
                "expires_date": "2027-01-01",
                "report_date": "2026-01-02",
                "certificate_number": "unknown",
                "scope": "platform",
                "evidence_reference": "evidence://certification-1",
                "status": "UNVERIFIED",
            }],
            "compliance": {
                "gdpr": None,
                "ccpa_cpra": None,
                "hipaa": None,
                "sox": None,
                "pci_dss": True,
                "fedramp_level": "unknown",
                "csa_star": "unknown",
                "nist_csf_alignment": "partial",
                "regulatory_attestations": [{
                    "framework": "PCI DSS",
                    "status": "UNVERIFIED",
                    "scope": "payment service",
                    "assessed_on": "2026-02-01",
                    "expires_on": "2027-02-01",
                    "evidence_reference": "evidence://attestation-1",
                }],
                "industry_requirements": ["payment security"],
                "processor_or_controller_role": "PROCESSOR",
                "cross_border_transfer_mechanism": "unknown",
                "dpa_signed": None,
                "dpa_version": "unknown",
                "dpa_date": None,
                "subprocessors": [{
                    "name": "Subprocessor One",
                    "service": "hosting",
                    "processing_purpose": "platform operation",
                    "locations": ["IN"],
                    "data_categories": ["CONFIDENTIAL"],
                    "status": "PENDING",
                    "notification_date": "2026-03-01",
                    "evidence_reference": "evidence://subprocessor-1",
                }],
            },
        },
        "data_privacy": {
            "data_types_processed": ["PII", "FINANCIAL"],
            "data_classification": "CONFIDENTIAL",
            "data_owner": "customer privacy office",
            "data_flow": "customer to managed platform",
            "data_flow_diagram_reference": "evidence://data-flow",
            "processing_locations": ["IN"],
            "data_residency": ["IN"],
            "data_sovereignty": ["IN"],
            "data_retention": "contract-defined",
            "data_deletion_process": "ticketed deletion",
            "deletion_sla": "30 days",
            "privacy_mechanisms": ["access review"],
            "privacy_policy_url": "https://example.invalid/privacy",
            "data_privacy_framework": "privacy program",
            "standard_contractual_clauses": "unknown",
            "binding_corporate_rules": "unknown",
            "privacy_certifications": ["unknown"],
            "dpo_contact": "dpo@example.invalid",
            "subprocessors": [],
        },
        "financial_stability": {
            "public_or_private": "PRIVATE",
            "financial_statements_reference": "evidence://financials",
            "annual_revenue_range": "unknown",
            "profitability_status": "unknown",
            "credit_rating": "unknown",
            "d_and_b_rating": "unknown",
            "funding_status": "unknown",
            "recent_funding": [{
                "event_date": "2025-01-01",
                "event_type": "unknown",
                "amount": None,
                "currency": "USD",
                "investors": ["unknown"],
                "evidence_reference": "evidence://funding-1",
            }],
            "business_continuity_plan": "documented plan reference",
            "financial_risk": "unknown",
            "years_in_business": 5,
            "customer_base_summary": "unknown",
            "market_share_summary": "unknown",
            "strategic_importance": "high",
            "succession_plan": "unknown",
        },
        "incident_history": {
            "incidents": [{
                "incident_id": "incident-1",
                "incident_type": "OUTAGE",
                "occurred_on": "2026-01-10",
                "disclosed_on": "2026-01-11",
                "scope": "service region",
                "customer_impact": "temporary outage",
                "root_cause": "unknown",
                "root_cause_evidence_reference": "evidence://incident-1",
                "remediation": "corrective action tracked",
                "notification_required": False,
                "notification_timeliness": "within policy",
                "regulatory_notifications": "not applicable",
                "severity": "medium",
                "status": "CLOSED",
            }],
            "incident_response_plan": "documented plan",
            "notification_obligations": "contract-defined",
            "incident_response_time": "1 hour",
            "communication_plan": "customer notification process",
            "communication_channels": ["status page"],
        },
        "dependencies": {
            "critical_dependency": True,
            "single_point_of_failure": False,
            "concentration_risk": "medium",
            "systemic_risk": "unknown",
            "irreplaceability": "medium",
            "vendor_lock_in_summary": "migration effort documented",
            "sub_vendors": [{
                "name": "Sub-vendor One",
                "service": "hosting",
                "tier": 2,
                "locations": ["IN"],
                "criticality": "medium",
                "risk_rating": "unknown",
                "evidence_reference": "evidence://sub-vendor-1",
            }],
            "nth_party_visibility": "tier two known",
            "fourth_party_visibility": "unknown",
            "supply_chain_visibility_depth": 2,
            "subvendor_change_notification": "contract notice",
            "ecosystem_vendors": ["Sub-vendor One"],
            "ecosystem_dependencies": ["hosting"],
            "integration_points": [{
                "name": "Payment API",
                "direction": "BIDIRECTIONAL",
                "protocol": "HTTPS",
                "data_exchanged": ["transaction metadata"],
                "dependent_systems": ["payments"],
                "criticality": "high",
                "cascading_failure_effect": "payment processing impact",
            }],
            "cascading_failure_analysis": "documented analysis",
        },
        "access_permissions": {
            "access_types": ["API", "VPN"],
            "system_access": True,
            "api_access": True,
            "vpn_access": False,
            "physical_access": False,
            "administrative_access": False,
            "access_scope": ["payment metadata"],
            "access_controls": ["RBAC", "MFA"],
            "mfa_required": True,
            "ip_restrictions": "allow-listed network",
            "time_restrictions": "business approved",
            "privileged_access": False,
            "access_review_frequency": "quarterly",
            "background_checks": "unknown",
            "nda_status": "active",
            "training_requirements": "annual",
            "personnel_change_notification": "contract notice",
        },
        "exit_strategy": {
            "transition_period": "90 days",
            "data_retrieval_process": "export request",
            "data_deletion_confirmation": "written confirmation",
            "data_export_format": ["JSON"],
            "knowledge_transfer": "runbooks and workshops",
            "license_portability": "contract-defined",
            "escrow_arrangements": "unknown",
            "replacement_plan": "qualified alternative review",
            "migration_plan": "phased migration",
            "migration_dependencies": ["replacement provider"],
            "rollback_plan": "dual run",
            "last_tested_on": "2026-02-15",
        },
        "evidence": [{
            "evidence_id": "profile-evidence-1",
            "evidence_type": "ASSESSMENT",
            "evidence_reference": "evidence://profile-assessment-1",
            "status": "UNVERIFIED",
            "captured_at": "2026-02-01T00:00:00Z",
            "acquired_at": "2026-02-02T00:00:00Z",
            "expires_at": "2027-02-01T00:00:00Z",
            "issuer": "customer-security-team",
            "source_system": "vendor-review",
            "collection_method": "QUESTIONNAIRE",
            "collector": "reviewer",
            "reviewed_by": "reviewer",
            "content_type": "application/json",
            "redaction_status": "VERIFIED_NO_SECRETS",
            "limitations": ["self-reported"],
            "sha256": "a" * 64,
        }],
    }


@pytest.mark.asyncio
async def test_vendor_and_network_rows_are_isolated_end_to_end(monkeypatch):
    app, session, engine = _make_app()
    import api.dependencies as dependencies

    monkeypatch.setattr(dependencies, "resolve_tenant_for_request", _tenant_resolution)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor_a = (await client.post(
            "/api/v1/vendors",
            headers=_headers("user-a", TENANT_A),
            json={"name": "Tenant A Vendor"},
        )).json()
        vendor_b = (await client.post(
            "/api/v1/vendors",
            headers=_headers("user-b", TENANT_B),
            json={"name": "Tenant B Vendor"},
        )).json()

        profile_a = (await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )).json()["profile"]
        profile_b = (await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-b", TENANT_B),
        )).json()["profile"]
        saved_a = await client.put(
            f"/api/v1/vendors/{vendor_a['id']}/profile",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile_a, "status": "DRAFT"},
        )
        saved_b = await client.put(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-b", TENANT_B),
            json={"profile": profile_b, "status": "DRAFT"},
        )

        network_a = await client.put(
            "/api/v1/network/inventory",
            headers=_headers("user-a", TENANT_A),
            json={"inventory_id": "default", "inventory": {"devices": [{
                "device_id": "a-router", "device_type": "router", "management_ip": "10.10.0.1",
            }]}},
        )
        network_b = await client.put(
            "/api/v1/network/inventory",
            headers=_headers("user-b", TENANT_B),
            json={"inventory_id": "default", "inventory": {"devices": [{
                "device_id": "b-router", "device_type": "router", "management_ip": "10.20.0.1",
            }]}},
        )
        network_b_private = await client.put(
            "/api/v1/network/inventory",
            headers=_headers("user-b", TENANT_B),
            json={"inventory_id": "tenant-b-only", "inventory": {"devices": [{
                "device_id": "b-private-router", "device_type": "router", "management_ip": "10.20.1.1",
            }]}},
        )

        vendors_a = await client.get("/api/v1/vendors", headers=_headers("user-a", TENANT_A))
        vendors_b = await client.get("/api/v1/vendors", headers=_headers("user-b", TENANT_B))
        inventory_a = await client.get("/api/v1/network/inventory", headers=_headers("user-a", TENANT_A))
        inventory_b = await client.get("/api/v1/network/inventory", headers=_headers("user-b", TENANT_B))
        inventory_b_private_for_a = await client.get(
            "/api/v1/network/inventory",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        inventory_b_private_for_b = await client.get(
            "/api/v1/network/inventory",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-b", TENANT_B),
        )
        history_a = await client.get(
            "/api/v1/network/inventory/history", headers=_headers("user-a", TENANT_A)
        )
        history_b = await client.get(
            "/api/v1/network/inventory/history", headers=_headers("user-b", TENANT_B)
        )

        vendor_a_detail = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}", headers=_headers("user-a", TENANT_A)
        )
        vendor_a_schema = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile/schema",
            headers=_headers("user-a", TENANT_A),
        )
        profile_history_a = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile/history",
            headers=_headers("user-a", TENANT_A),
        )
        questionnaire_a = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
        )
        risk_a = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/risk", headers=_headers("user-a", TENANT_A)
        )
        risks_a = await client.get("/api/v1/vendor-risks", headers=_headers("user-a", TENANT_A))
        questionnaire_write_a = await client.post(
            f"/api/v1/vendors/{vendor_a['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
            json={"transit": "TLS 1.3", "rest": "AES-256", "kms": "HSM", "pqc": "Planned"},
        )

        cross_vendor = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )
        cross_vendor_detail = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}", headers=_headers("user-a", TENANT_A)
        )
        cross_vendor_schema = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile/schema",
            headers=_headers("user-a", TENANT_A),
        )
        cross_profile_history = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile/history",
            headers=_headers("user-a", TENANT_A),
        )
        cross_questionnaire = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
        )
        cross_risk = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/risk", headers=_headers("user-a", TENANT_A)
        )
        cross_profile_validate = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/profile/validate",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile_b, "status": "DRAFT"},
        )
        cross_profile_write = await client.put(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile_b, "status": "DRAFT"},
        )
        cross_profile_evidence = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/profile/evidence",
            headers=_headers("user-a", TENANT_A),
            json={
                "evidence_id": "tenant-b-evidence",
                "evidence_type": "OTHER",
                "evidence_reference": "evidence://tenant-b",
            },
        )
        cross_questionnaire_write = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/questionnaire",
            headers=_headers("user-a", TENANT_A),
            json={},
        )
        cross_cbom = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/cbom",
            headers=_headers("user-a", TENANT_A),
            json={"sbom": {}},
        )
        cross_docs = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/docs",
            headers=_headers("user-a", TENANT_A),
            json={"text": "no credentials or secrets"},
        )
        cross_patch = await client.patch(
            f"/api/v1/vendors/{vendor_b['id']}",
            headers=_headers("user-a", TENANT_A),
            json={"criticality": "HIGH"},
        )
        cross_expire = await client.delete(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )
        cross_api_scan = await client.post(
            f"/api/v1/vendors/{vendor_b['id']}/api-scan",
            headers=_headers("user-a", TENANT_A),
            json={"endpoint": "example.invalid"},
        )
        cross_inventory = await client.get(
            "/api/v1/network/inventory",
            headers=_headers("user-a", TENANT_B),
        )
        cross_inventory_history = await client.get(
            "/api/v1/network/inventory/history",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_risk = await client.get(
            "/api/v1/network/inventory/risk",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_topology = await client.get(
            "/api/v1/network/inventory/topology",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_drift = await client.get(
            "/api/v1/network/inventory/configuration/drift",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        cross_inventory_coverage = await client.get(
            "/api/v1/network/inventory/coverage",
            params={"inventory_id": "tenant-b-only"},
            headers=_headers("user-a", TENANT_A),
        )
        default_tenant = await client.get(
            "/api/v1/vendors",
            headers=_headers("user-a"),
        )

    assert saved_a.status_code == 200
    assert saved_b.status_code == 200
    assert network_a.status_code == 200
    assert network_b.status_code == 200
    assert network_b_private.status_code == 200
    assert vendor_a_detail.status_code == 200
    assert vendor_a_schema.status_code == 200
    assert profile_history_a.status_code == 200
    assert questionnaire_a.status_code == 200
    assert risk_a.status_code == 200
    assert risks_a.status_code == 200
    assert questionnaire_write_a.status_code == 200, questionnaire_write_a.text
    assert {row["name"] for row in vendors_a.json()["vendors"]} == {"Tenant A Vendor"}
    assert {row["name"] for row in vendors_b.json()["vendors"]} == {"Tenant B Vendor"}
    assert inventory_a.json()["inventory"]["devices"][0]["device_id"] == "a-router"
    assert inventory_b.json()["inventory"]["devices"][0]["device_id"] == "b-router"
    assert inventory_b_private_for_a.status_code == 200
    assert inventory_b_private_for_a.json()["persisted"] is False
    assert inventory_b_private_for_a.json()["revision"] is None
    assert "b-private-router" not in str(inventory_b_private_for_a.json())
    assert inventory_b_private_for_b.status_code == 200
    assert inventory_b_private_for_b.json()["persisted"] is True
    assert inventory_b_private_for_b.json()["inventory"]["devices"][0]["device_id"] == "b-private-router"
    assert history_a.status_code == 200
    assert history_b.status_code == 200
    assert len(history_a.json()["revisions"]) == 1
    assert len(history_b.json()["revisions"]) == 1
    assert cross_vendor.status_code == 404
    assert cross_vendor_detail.status_code == 404
    assert cross_vendor_schema.status_code == 404
    assert cross_profile_history.status_code == 404
    assert cross_questionnaire.status_code == 404
    assert cross_risk.status_code == 404
    assert cross_profile_validate.status_code == 404
    assert cross_profile_write.status_code == 404
    assert cross_profile_evidence.status_code == 404
    assert cross_questionnaire_write.status_code == 404
    assert cross_cbom.status_code == 404
    assert cross_docs.status_code == 404
    assert cross_patch.status_code == 404
    assert cross_expire.status_code == 404
    assert cross_api_scan.status_code == 404
    assert cross_inventory.status_code == 404
    assert cross_inventory_history.status_code == 200
    assert cross_inventory_history.json()["revisions"] == []
    assert cross_inventory_risk.status_code == 200
    assert cross_inventory_risk.json()["revision"] is None
    assert cross_inventory_topology.status_code == 200
    assert cross_inventory_topology.json()["revision"] is None
    assert cross_inventory_drift.status_code == 200
    assert cross_inventory_drift.json()["revision"] is None
    assert cross_inventory_coverage.status_code == 200
    assert cross_inventory_coverage.json()["revision"] is None
    assert default_tenant.status_code == 200
    assert {row["name"] for row in default_tenant.json()["vendors"]} == {"Tenant A Vendor"}

    vendor_rows = session.execute(select(Vendor).order_by(Vendor.name)).scalars().all()
    profile_rows = session.execute(select(VendorProfileRevision)).scalars().all()
    inventory_rows = session.execute(select(NetworkInventoryRevision)).scalars().all()
    crypto_rows = session.execute(select(VendorCryptoInventory)).scalars().all()
    assert {(row.name, row.tenant_id) for row in vendor_rows} == {
        ("Tenant A Vendor", TENANT_A),
        ("Tenant B Vendor", TENANT_B),
    }
    assert {(row.vendor_id, row.tenant_id) for row in profile_rows} == {
        (vendor_a["id"], TENANT_A),
        (vendor_b["id"], TENANT_B),
    }
    assert {(row.inventory_id, row.tenant_id) for row in inventory_rows} == {
        ("default", TENANT_A),
        ("default", TENANT_B),
        ("tenant-b-only", TENANT_B),
    }
    assert crypto_rows
    assert {row.tenant_id for row in crypto_rows} == {TENANT_A}
    assert {row.vendor_id for row in crypto_rows} == {vendor_a["id"]}
    session.close()
    engine.dispose()


@pytest.mark.asyncio
async def test_production_tenant_resolution_is_exercised_over_http(monkeypatch):
    """Use real membership resolution, not the narrow resolver shim above."""
    app, session, engine = _make_app()
    app.dependency_overrides.pop(get_current_user, None)

    from db.connection import session as connection
    from db.repositories.tenant_repository import TenantRepository
    from api.security.session_manager import SessionManager

    # TenantScopeMiddleware's resolver uses SessionLocal, while route
    # handlers use the in-memory dependency override. Point the production
    # resolver at a fresh session bound to this same in-memory engine.
    real_session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(connection, "SessionLocal", real_session_factory)

    tenants = TenantRepository(session)
    tenants.ensure_user("member-a")
    tenants.ensure_user("member-b")
    tenants.ensure_user("orphan-user")
    tenants.ensure_user("multi-user")
    tenant_a = tenants.create(name="Real Alpha", slug="real-alpha", created_by="member-a")
    tenant_b = tenants.create(name="Real Beta", slug="real-beta", created_by="member-b")
    tenants.add_member(tenant_a.id, "member-a", "member")
    tenants.add_member(tenant_b.id, "member-b", "member")
    tenants.add_member(tenant_a.id, "multi-user", "member")
    tenants.add_member(tenant_b.id, "multi-user", "member")
    session.commit()

    def auth(username: str) -> dict[str, str]:
        token = SessionManager().create_session(username, roles=["readonly"])
        return {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created_a = await client.post(
            "/api/v1/vendors",
            headers=auth("member-a"),
            json={"name": "Real Alpha Vendor"},
        )
        created_b = await client.post(
            "/api/v1/vendors",
            headers=auth("member-b"),
            json={"name": "Real Beta Vendor"},
        )
        listed_a = await client.get("/api/v1/vendors", headers=auth("member-a"))
        cross_b = await client.get(
            f"/api/v1/vendors/{created_b.json()['id']}/profile",
            headers=auth("member-a"),
        )
        orphan = await client.get("/api/v1/vendors", headers=auth("orphan-user"))
        forged = await client.get(
            "/api/v1/vendors",
            headers={**auth("member-a"), "X-Tenant-ID": tenant_b.id},
        )
        ambiguous = await client.get("/api/v1/vendors", headers=auth("multi-user"))

    assert created_a.status_code == 200, created_a.text
    assert created_b.status_code == 200, created_b.text
    assert {row["name"] for row in listed_a.json()["vendors"]} == {"Real Alpha Vendor"}
    assert cross_b.status_code == 404
    assert orphan.status_code == 403
    assert forged.status_code == 404
    assert ambiguous.status_code == 400
    session.close()
    engine.dispose()


@pytest.mark.asyncio
async def test_tenant_middleware_fails_closed_for_unknown_and_ambiguous_requests(monkeypatch):
    app, session, engine = _make_app()
    import api.dependencies as dependencies

    monkeypatch.setattr(dependencies, "resolve_tenant_for_request", _tenant_resolution)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unknown_user = await client.get(
            "/api/v1/vendors", headers=_headers("not-a-member", TENANT_A)
        )
        forged_tenant = await client.get(
            "/api/v1/vendors", headers=_headers("user-a", TENANT_B)
        )

    assert unknown_user.status_code == 403
    assert forged_tenant.status_code == 404
    session.close()
    engine.dispose()


@pytest.mark.asyncio
async def test_full_vendor_profile_sections_round_trip_and_remain_tenant_scoped(monkeypatch):
    """Exercise every profile section through the real HTTP lifecycle."""
    app, session, engine = _make_app()
    import api.dependencies as dependencies

    monkeypatch.setattr(dependencies, "resolve_tenant_for_request", _tenant_resolution)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor_a = (await client.post(
            "/api/v1/vendors",
            headers=_headers("user-a", TENANT_A),
            json={"name": "Complete Profile A"},
        )).json()
        vendor_b = (await client.post(
            "/api/v1/vendors",
            headers=_headers("user-b", TENANT_B),
            json={"name": "Complete Profile B"},
        )).json()
        profile = _complete_profile(vendor_a["id"])
        saved = await client.put(
            f"/api/v1/vendors/{vendor_a['id']}/profile",
            headers=_headers("user-a", TENANT_A),
            json={"profile": profile, "status": "DRAFT", "source": "e2e-fixture"},
        )
        fetched = await client.get(
            f"/api/v1/vendors/{vendor_a['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )
        listed = await client.get("/api/v1/vendors", headers=_headers("user-a", TENANT_A))
        cross = await client.get(
            f"/api/v1/vendors/{vendor_b['id']}/profile",
            headers=_headers("user-a", TENANT_A),
        )

    assert saved.status_code == 200, saved.text
    assert fetched.status_code == 200, fetched.text
    persisted = fetched.json()["profile"]
    assert persisted["identity"]["legal_name"] == "Evidence-backed Vendor"
    assert persisted["contacts"]["emergency_24x7"] == "on-call process documented"
    assert persisted["components"][0]["component_type"] == "SAAS"
    assert persisted["contracts"][0]["contract_id"] == "contract-1"
    assert persisted["service_level_agreements"][0]["uptime_guarantee"] == "99.9%"
    assert persisted["legal_liability"]["governing_law"] == "India"
    assert persisted["security_compliance"]["assessments"][0]["open_findings"][0]["finding_id"] == "finding-1"
    assert persisted["security_compliance"]["certifications"][0]["certification_type"] == "ISO 27001"
    assert persisted["security_compliance"]["compliance"]["subprocessors"][0]["name"] == "Subprocessor One"
    assert persisted["data_privacy"]["data_types_processed"] == ["PII", "FINANCIAL"]
    assert persisted["financial_stability"]["recent_funding"][0]["event_type"] == "unknown"
    assert persisted["incident_history"]["incidents"][0]["incident_id"] == "incident-1"
    assert persisted["dependencies"]["sub_vendors"][0]["name"] == "Sub-vendor One"
    assert persisted["dependencies"]["integration_points"][0]["name"] == "Payment API"
    assert persisted["access_permissions"]["mfa_required"] is True
    assert persisted["exit_strategy"]["migration_plan"] == "phased migration"
    assert persisted["evidence"][0]["redaction_status"] == "VERIFIED_NO_SECRETS"
    assert listed.status_code == 200
    listed_profile = listed.json()["vendors"][0]["vendor_profile"]
    assert listed_profile["revision"] == 1
    assert cross.status_code == 404

    profile_rows = session.execute(select(VendorProfileRevision)).scalars().all()
    assert {(row.vendor_id, row.tenant_id) for row in profile_rows} == {
        (vendor_a["id"], TENANT_A),
    }
    session.close()
    engine.dispose()
