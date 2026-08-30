"""ZELNX Live engine tests — connectors, five layers, universal event
schema, change classification (§1–§6).

Covers:
  §1  five monitoring layers (L1 events / L2 audit / L3 API state /
      L4 reconciliation / L5 deep discovery)
  §3  AWS live connector
  §4  Azure live connector
  §5  GCP live connector
  §6  universal CloudEvent schema (fields + provider_metadata preserved)
  §2  change classification (NEW / UPDATED / DELETED / CRYPTO /
      IDENTITY / NETWORK)
"""

from __future__ import annotations

import pytest

from cloud_scanner.enterprise.live.change_classifier import (
    CHANGE_TO_SCANNERS,
    classify_change,
    scanner_set_for,
)
from cloud_scanner.enterprise.live.connectors import (
    ProviderConnector,
    UniversalEventNormalizer,
    aws_connector,
    azure_connector,
    gcp_connector,
)
from cloud_scanner.enterprise.live.engine import LiveCloudEngine
from cloud_scanner.enterprise.live.event_schema import (
    CHANGE_TYPES,
    EVENT_TYPES,
    CloudEvent,
    is_valid_change_type,
    is_valid_event_type,
)
from zelix_live_fixtures import (
    AWS_CERT,
    AWS_KEY,
    AZURE_CERT,
    GCP_KEY,
    all_live_connectors,
    aws_audit,
    aws_events,
    aws_reconcile,
    azure_events,
    gcp_events,
    make_live_engine,
)


# ---------------------------------------------------------------------- §6 schema

class TestUniversalCloudEventSchema:
    def test_schema_fields_present(self):
        event = CloudEvent(
            event_id="e1", provider="aws", event_type="KEY_ROTATED",
            change_type="CRYPTO_CHANGE", resource_id="k1", organization_id="org-1",
            account_id="111", region="us-east-1", source="events",
        )
        dumped = event.to_dict()
        for field_name in (
            "event_id", "provider", "event_type", "change_type", "resource_id",
            "resource_type", "organization_id", "account_id", "subscription_id",
            "project_id", "region", "timestamp", "actor_reference", "source",
            "evidence_reference", "confidence", "provider_metadata",
        ):
            assert field_name in dumped

    def test_provider_metadata_preserved_never_lost(self):
        raw = {"event_id": "e1", "provider": "aws", "event_name": "kms:PutKeyPolicy",
               "resource_id": AWS_KEY, "awsRegion": "us-east-1",
               "kms_detail": {"policy_version": "v3"}, "extra": {"deep": True}}
        event = UniversalEventNormalizer().normalize(raw, provider="aws", source="events")
        assert event.provider_metadata["kms_detail"] == {"policy_version": "v3"}
        assert event.provider_metadata["extra"] == {"deep": True}

    def test_invalid_provider_rejected(self):
        raw = {"event_id": "x", "provider": "oracle", "event_name": "stuff"}
        assert UniversalEventNormalizer().normalize(raw, provider="oracle", source="events") is None

    def test_event_type_validation(self):
        assert is_valid_event_type("KEY_ROTATED")
        assert not is_valid_event_type("NOT_A_REAL_EVENT")
        assert is_valid_change_type("CRYPTO_CHANGE")
        assert not is_valid_change_type("MAYBE_CHANGE")

    def test_event_types_cover_spec_areas(self):
        joined = " ".join(EVENT_TYPES)
        for expected in ("KEY_POLICY_CHANGED", "CERTIFICATE_REVOKED",
                         "NEW_PUBLIC_ENDPOINT", "K8S_MTLS_CHANGED",
                         "SERVERLESS_DEPENDENCY_CHANGE", "RESOURCE_DISCOVERED",
                         "NETWORK_CHANGED", "DEPENDENCY_CHANGED"):
            assert expected in joined


# --------------------------------------------------------------- §2 classification

class TestChangeClassification:
    @pytest.mark.parametrize("event_type,expected", [
        ("KEY_CREATED", "NEW_RESOURCE"),
        ("KEY_POLICY_CHANGED", "IDENTITY_CHANGE"),
        ("KEY_ALGORITHM_CHANGED", "CRYPTO_CHANGE"),
        ("CERTIFICATE_RENEWED", "CRYPTO_CHANGE"),
        ("CERTIFICATE_CREATED", "NEW_RESOURCE"),
        ("NEW_PUBLIC_ENDPOINT", "NETWORK_CHANGE"),
        ("TLS_TERMINATION_CHANGE", "NETWORK_CHANGE"),
        ("ROUTE_CHANGE", "NETWORK_CHANGE"),
        ("K8S_NEW_WORKLOAD", "NEW_RESOURCE"),
        ("K8S_CERTIFICATE_CHANGED", "CRYPTO_CHANGE"),
        ("SERVERLESS_NEW_VERSION", "UPDATED_RESOURCE"),
        ("RESOURCE_REMOVED", "DELETED_RESOURCE"),
        ("DEPENDENCY_CHANGED", "UPDATED_RESOURCE"),
    ])
    def test_event_to_change_type(self, event_type, expected):
        event = CloudEvent(event_id="e", provider="aws", event_type=event_type,
                           change_type="")
        assert classify_change(event).change_type == expected

    def test_crypto_change_selects_crypto_scanners(self):
        event = CloudEvent(event_id="e", provider="aws",
                           event_type="CERTIFICATE_ALGORITHM_CHANGED", change_type="")
        classified = classify_change(event)
        assert "tls_discovery" in classified.scanners
        assert "pqc_readiness" in classified.scanners
        assert "dependency_graph" in classified.scanners

    def test_identity_change_selects_iam_scanners(self):
        event = CloudEvent(event_id="e", provider="gcp",
                           event_type="KEY_PERMISSION_CHANGED", change_type="")
        classified = classify_change(event)
        assert "iam_access" in classified.scanners

    def test_unknown_event_falls_back_to_updated(self):
        event = CloudEvent(event_id="e", provider="aws", event_type="MYSTERY_EVENT",
                           change_type="")
        assert classify_change(event).change_type == "UPDATED_RESOURCE"

    def test_override_wins(self):
        event = CloudEvent(event_id="e", provider="aws", event_type="KEY_ROTATED",
                           change_type="")
        assert classify_change(event, override="NETWORK_CHANGE").change_type == "NETWORK_CHANGE"

    def test_scanner_set_for(self):
        assert scanner_set_for("NEW_PUBLIC_ENDPOINT") == CHANGE_TO_SCANNERS["NETWORK_CHANGE"]


# ---------------------------------------------------------- §3/§4/§5 connectors

class TestProviderConnectors:
    def test_aws_connector_all_sources(self):
        connector = aws_connector(event_source=aws_events, audit_source=aws_audit,
                                  api_state_source=lambda: [{"event_id": "s1",
                                                             "event_name": "KMS.DescribeKey",
                                                             "resource_id": "k1",
                                                             "provider": "aws"}],
                                  reconcile_source=aws_reconcile,
                                  organization_id="org-1")
        events = connector.poll_events()
        assert len(events) == 6
        assert all(e.provider == "aws" for e in events)
        assert all(e.organization_id == "org-1" for e in events)

    def test_azure_connector_event_types_mapped(self):
        connector = azure_connector(event_source=azure_events)
        events = connector.poll_events()
        by_type = {e.resource_type: e.event_type for e in events}
        assert "Microsoft.KeyVault/vaults/certificates" in by_type
        assert "Microsoft.KeyVault/vaults/keys" in by_type
        assert "Microsoft.Network/vpnGateways" in by_type

    def test_gcp_connector_event_types_mapped(self):
        connector = gcp_connector(event_source=gcp_events)
        events = connector.poll_events()
        by_operation = {e.provider_metadata.get("operation"): e.event_type for e in events}
        assert "cloudkms.CryptoKey.Rotate" in by_operation
        assert "certificatemanager.Certificate.Create" in by_operation

    def test_missing_sources_return_empty(self):
        connector = aws_connector()
        polled = connector.poll_all()
        assert polled == {"events": [], "audit": [], "api_state": [], "reconciliation": []}

    def test_source_error_recorded_not_raised(self):
        def boom():
            raise RuntimeError("source down")

        connector = aws_connector(event_source=boom)
        assert connector.poll_events() == []
        assert connector.errors and "source down" in connector.errors[0]["detail"]

    def test_normalizer_keeps_provider_detail(self):
        connector = gcp_connector(event_source=gcp_events)
        event = connector.poll_events()[0]
        assert event.provider_metadata["protection_level"] == "HSM"


# --------------------------------------------------- §1 five layers via engine

class TestFiveMonitoringLayers:
    def test_engine_layers_all_polled(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert report.layers["L1_realtime_events"] >= 10
        assert report.layers["L2_audit_logs"] >= 3
        assert report.layers["L3_api_state"] >= 1
        assert report.layers["L4_reconciliation"] >= 1

    def test_layer5_deep_discovery_stronger_than_full_scan(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        plans = report.deep_discovery_plans
        assert plans
        deep = [p for p in plans if p["deep"]]
        assert deep
        # L5 is change-triggered — never a plan for every asset
        assert len(deep) <= len(report.events)

    def test_each_source_flows_through_universal_schema(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        sources = {e["source"] for e in report.events}
        assert {"events", "audit", "api_state", "reconciliation"} <= sources
        for event in report.events:
            assert "provider_metadata" in event


# ----------------------------------------------------- unified flow (§2) basics

class TestUnifiedFlow:
    def test_engine_events_classified_and_assets_tracked(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert len(report.events) == len(report.classifications)
        # assets dedupe by resource_id (a resource may be observed by
        # multiple source families in one cycle)
        distinct = len({e["resource_id"] for e in report.events})
        assert report.asset_state["summary"]["assets"] == distinct
        assert report.evidence_verified is True

    def test_connector_types(self):
        assert isinstance(aws_connector(), ProviderConnector)
        assert isinstance(azure_connector(), ProviderConnector)
        assert isinstance(gcp_connector(), ProviderConnector)

    def test_read_only_contract(self):
        engine = make_live_engine()
        report = engine.cycle(cycle_number=1)
        assert report.read_only is True
