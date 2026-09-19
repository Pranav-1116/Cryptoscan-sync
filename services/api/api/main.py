"""CryptoScan API + dashboard host."""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.config.settings import APISettings, get_settings, validate_runtime_settings
from fastapi.middleware.gzip import GZipMiddleware
from api.middleware.auth_middleware import AuthMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.logging_middleware import LoggingMiddleware
from api.middleware.request_id_middleware import RequestIDMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.routers import (
    agility,
    analytics,
    billing,
    compliance,
    ops,
    priority,
    saas,
    stream,
    assets,
    inventory,
    inventory_cloud,
    scope,
    risk,
    connectors,
    live,
    auth,
    banking,
    baselines,
    business,
    business_context,
    cbom,
    certificates,
    cloud,
    cloud_scans,
    container,
    container_scans,
    crypto,
    drift,
    estate,
    events,
    techbom,
    exceptions,
    notifications,
    export,
    findings,
    graph,
    hardware,
    health,
    intelligence,
    jobs,
    live_scan,
    network,
    network_scans,
    ot,
    ot_safety,
    policy,
    quantum,
    reachability,
    remediation,
    report_schedules,
    monitor,
    payment_crypto,
    telecom,
    audit_export,
    repo_configs,
    runtime,
    scans,
    stats,
    systems,
    sla,
    automation,
    automation_ops,
    trigger,
    vulnerability,
    vulns,
    webhooks,
    api_keys,
    algorithms,
    platform,
    sectors,
    sso,
    scim,
    workload,
    crypto_assurance,
    devsecops,
    onboarding,
    control_plane,
    enterprise,
    marketplace as marketplace_router,
    datalake as datalake_router,
    anomaly as anomaly_router,
    governance as governance_router,
    security as security_router,
    resilience,
    production,
    compliance_packs,
    siem,
    zero_trust,
    threat_model,
    incident_response,
    chaos,
    active_active,
    backup,
    casb,
    hbom,
    entropy_core,
    sovereign_storage,
    hsm_fabric,
    qsim,
    collaboration,
    compliance_cert,
    living_cbom,
    api_scanner,
    network_device_scanner,
    ca_hierarchy,
    key_lifecycle,
    streaming_backbone,
    attack_detection,
    telecom_enhanced,
    hsm_inventory_enhanced,
    migration_simulator,
    ot_enhanced,
    compliance_deterministic,
    evidence_chain_enhanced,
    exception_enhanced,
    supply_chain_integrity,
    sbom_slsa,
    ct_log_monitor,
    cert_lifecycle_automation,
    policy_as_code,
    telemetry_pipeline,
    pqc_infra_monitor,
    qrng_entropy_monitor,
    vpn_monitor,
    dnssec_dane_monitor,
    secure_boot_tpm,
    firmware_analysis,
    incident_response_playbooks,
    forensic_vault,
    kms_policy_enforcement,
    backup_encryption_verification,
    dr_crypto_validation,
    audit_merkle,
    compliance_evidence_automation,
    plugin_marketplace,
    secrets_detection,
    dependency_risk,
    remediation_orchestrator,
    threat_intel,
    zero_trust_crypto,
    compliance_mapping,
    data_classification,
    blockchain_crypto,
    iot_ot_crypto,
    ai_ml_crypto_guard,
    runtime_crypto_ebpf,
    slsa_attestation_verifier,
    pq_migration_cost,
    drift_anomaly,
    risk_quantification,
    tenant_isolation_validator,
    secure_code_review,
    hsm_deep_inventory,
    network_crypto_analyzer,
    evidence_lake,
    deterministic_policy_enforcement,
    crypto_agility_maturity,
    quantum_threat_timeline,
    hndl_risk_calculator,
    pqc_migration_playbook,
    crypto_inventory_health,
    compliance_evidence_graph,
    remediation_verification,
    crypto_drift_timeline,
    executive_risk_heatmap,
    third_party_crypto_risk,
    cloud_crypto_posture,
    kubernetes_crypto_security,
    cicd_crypto_gate,
    secrets_management_integration,
    certificate_transparency_v2,
    pqc_readiness_dashboard,
    crypto_policy_drift,
    automated_evidence_collection,
    threat_model_automation,
    crypto_material_vault,
    key_birth_death_ledger,
    certificate_lifecycle_orchestrator,
    cryptographic_debt_ledger,
    cryptographic_simulation_engine,
    change_impact_predictor,
    blast_radius_calculator,
    cryptographic_boundary_mapper,
    live_crypto_posture_score,
    anomaly_detection_engine,
    crypto_health_monitor,
    real_time_attack_detector,
    pqc_migration_orchestrator,
    hybrid_mode_manager,
    quantum_readiness_index,
    pqc_performance_benchmarker,
    telecom_signaling_analyzer,
    three_gpp_compliance_mapper,
    ot_protocol_crypto_analyzer,
    industrial_control_crypto_monitor,
    supply_chain_provenance_engine,
    sbom_correlation_engine,
    vendor_crypto_risk_scorer,
    firmware_provenance_tracker,
    evidence_automation_engine,
    audit_log_merkle_compressor,
    attestation_pipeline,
    backup_dr_orchestrator,
    capacity_planner,
    cryptographic_trust_graph,
    crypto_agility_index,
    deterministic_threat_modeler,
    multi_dimensional_compliance_cube,
    quantum_entropy_fabric,
    pqc_code_signing_orchestrator,
    zero_trust_crypto_enforcer,
    confidential_computing_attestor,
    fhe_performance_optimizer,
    zk_proof_verifier,
    threshold_crypto_orchestrator,
    crypto_policy_simulator,
    key_rotation_orchestrator,
    certificate_pinning_enforcer,
    tls_hardening_orchestrator,
    dnssec_chain_validator,
    secure_boot_chain_verifier,
    firmware_crypto_extractor,
    runtime_secret_leak_detector_v2,
    sbom_vulnerability_correlator,
    ct_log_aggregator,
    k8s_crypto_admission_controller,
    cicd_crypto_gate_enforcer,
    secrets_management_unifier,
    cloud_kms_posture_enforcer,
    network_device_crypto_auditor,
    api_crypto_posture_analyzer,
    blockchain_crypto_auditor,
    iot_firmware_crypto_scanner,
    ml_model_crypto_guard,
    siem_crypto_correlator,
    forensic_crypto_vault,
    compliance_evidence_lake,
    crypto_drift_predictor,
    hsm_fleet_orchestrator,
    kms_key_hierarchy_mapper,
    crypto_compliance_benchmark,
    pqc_migration_cost_estimator,
    quantum_threat_forecaster,
    crypto_asset_risk_scorer,
    crypto_inventory_reconciler,
    crypto_policy_enforcer_v2,
    audit_log_analytics_engine,
    evidence_chain_verifier,
    exception_management_engine,
    remediation_orchestrator_v2,
    threat_model_automation_engine,
    data_classification_engine,
    confidential_data_flow_tracker_v2,
    crypto_asset_lineage_tracker_v2,
    continuous_assurance_monitor_v2,
    telemetry_pipeline_orchestrator,
    streaming_backbone_monitor,
    tenant_isolation_validator_v2,
    secure_code_review_engine,
    hsm_deep_inventory_scanner_v2,
    network_crypto_posture_enforcer,
    evidence_lake_query_engine,
    api_security_posture_enforcer,
    cloud_kms_inventory_enhanced,
    secrets_rotation_automation_engine,
    cert_pinning_validator_enhanced,
    pqc_tls_analyzer_enhanced,
    supply_chain_attestation_verifier,
    realtime_system,
    cryptographic_digital_twin,
    twin_mirror_ingestion,
    twin_state_store,
    twin_entity_model,
    twin_relationship_model,
    twin_behavioral_model,
    twin_temporal_model,
    twin_simulation_engine,
    twin_scenario_types,
    twin_analysis_output,
    twin_isolation_guardrails,
    twin_time_travel,
    twin_api,
    cryptographic_digital_twin_real,
    correlation_engine,
    behavioral_baselines,
    risk_scoring_engine,
    cross_standard_compliance,
    live_cbom_v2,
    attack_path_analysis,
    data_sovereignty,
    certification_pipeline,
    key_custody_splitting,
    timeseries_analytics,
    quantum_key_distribution_monitor,
    post_quantum_hsm_integration,
    crypto_bill_of_materials_enhanced,
    secure_multiparty_computation_validator,
    homomorphic_encryption_analyzer,
    differential_privacy_validator,
    confidential_data_flow_tracker,
    crypto_asset_lineage_tracker,
    automated_pqc_migration_executor,
    continuous_assurance_monitor,
    confidential_computing_validator,
    post_quantum_code_signing,
    crypto_inventory_reconciliation,
    automated_compliance_reporting,
    threat_modeling_engine,
    key_ceremony_orchestrator,
    secure_boot_attestation,
    tls_configuration_hardening,
    crypto_policy_enforcement,
    audit_log_analytics,
    api_security_posture,
    cloud_kms_inventory,
    secrets_rotation_automation,
    certificate_pinning_validator,
    pqc_tls_analyzer,
    supply_chain_attestation,
    runtime_secret_leak_detector,
    crypto_agility_score_v2,
    compliance_drift_detector,
    executive_dashboard,
)
from api.routers import metrics as metrics_router
from api.security.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)


def _under_test() -> bool:
    """True when running under pytest.

    Several test fixtures set ``ENVIRONMENT=development`` (closer to real
    runtime than ``test``), which would otherwise start the async event tailer /
    telemetry heartbeat in the app lifespan. Those background asyncio tasks and
    their threads keep the process alive after the suite finishes, causing
    hangs. Detecting pytest directly lets us suppress them regardless of the
    ENVIRONMENT value a fixture sets.
    """
    return "pytest" in sys.modules


def _shared_rate_limit_backend():
    """Redis client for cluster-wide rate limits; None (in-process) when unset/down."""
    url = os.environ.get("REDIS_URL", "")
    if not url:
        return None
    try:
        import redis

        return redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
    except Exception:
        return None


def create_app(settings: APISettings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from db.connection.session import init_db
        from shared_config.env_loader import load_env
        from shared_logging.logger_factory import configure_logging

        load_env()
        configure_logging(settings.LOG_LEVEL, json_output=settings.is_production)
        validate_runtime_settings(settings)
        if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
            init_db()
            try:
                from graph_engine.connection.neo4j_driver import get_driver
                from graph_engine.core.store import Neo4jGraphStore

                driver = get_driver()
                if driver is not None:
                    Neo4jGraphStore(driver).apply_schema()
            except Exception:
                logger.debug("neo4j_schema_skipped", exc_info=True)
            try:
                from db.connection.session import SessionLocal
                from api.security.auth import AuthService

                with SessionLocal() as session:
                    AuthService(session=session).bootstrap_admin()
            except Exception:
                logger.warning("admin_bootstrap_skipped", exc_info=True)
        logger.info("cryptoscan_api_started", extra={"env": settings.ENVIRONMENT})
        tailer_task = None
        telemetry_task = None
        redis_sync = None
        if (
            settings.EVENT_TAILER_SECONDS > 0
            and settings.ENVIRONMENT.lower() not in {"test", "testing"}
            and not _under_test()
        ):
            from api.routers.events import start_event_tailer, start_telemetry_heartbeat

            tailer_task = start_event_tailer(settings.EVENT_TAILER_SECONDS)
            if tailer_task is not None:
                logger.info("event_tailer_started", extra={"interval": settings.EVENT_TAILER_SECONDS})
            try:
                from api.events.automation_bridge import start_automation_bridge

                if start_automation_bridge():
                    logger.info("automation_bridge_started")
            except Exception:  # noqa: BLE001
                logger.debug("automation_bridge_start_skipped", exc_info=True)
            telemetry_task = start_telemetry_heartbeat()
            if telemetry_task is not None:
                logger.info("telemetry_heartbeat_started")
            # Cross-instance realtime: when REDIS_URL is set, federate events so
            # SSE clients on ANY replica receive events published on another
            # replica. Without Redis the bus stays on the local node (and the
            # durable DB tailer still federates cross-process events).
            redis_sync = None
            try:
                if settings.REDIS_URL:
                    import redis as _redis
                    from api.events.bus import get_event_bus
                    from api.events.redis_sync import start_redis_federation

                    rclient = _redis.Redis.from_url(
                        settings.REDIS_URL, socket_timeout=2, socket_connect_timeout=2
                    )
                    redis_sync = start_redis_federation(rclient, get_event_bus())
                    if redis_sync is not None:
                        logger.info("redis_event_federation_started")
                    # Share the live scan status across replicas so any node can
                    # answer /orchestrator/status even if it did not run the scan.
                    from api.live_scan.current_run import get_current_run_store
                    from api.live_scan.orchestrator import get_scan_orchestrator

                    get_scan_orchestrator().set_status_store(
                        get_current_run_store(settings.REDIS_URL)
                    )
            except Exception:  # noqa: BLE001 — Redis must never break startup
                logger.debug("redis_event_federation_skipped", exc_info=True)
        # Restore the latest live-scanner snapshot so consoles see the most
        # recent real scan immediately after a restart (best-effort; runs
        # independent of the event tailer).
        try:
            from api.live_scan.runner import get_live_scan_runner

            if get_live_scan_runner().load_persisted_snapshot():
                logger.info("live_scan_snapshot_restored")
        except Exception:  # noqa: BLE001
            logger.debug("live_scan_snapshot_restore_skipped", exc_info=True)
        yield
        if tailer_task is not None:
            tailer_task.cancel()
        if telemetry_task is not None:
            telemetry_task.cancel()
        if redis_sync is not None:
            try:
                redis_sync.stop()
            except Exception:  # noqa: BLE001
                pass
        logger.info("cryptoscan_api_stopped")

    app = FastAPI(
        title="CryptoScan Intelligence Platform",
        description="Deterministic cryptographic discovery, inventory, and compliance.",
        version=settings.API_VERSION,
        docs_url="/api/docs" if settings.docs_enabled else None,
        redoc_url="/api/redoc" if settings.docs_enabled else None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # Production WAF — outermost defense, blocks malicious patterns before any processing
    try:
        from api.middleware.waf_middleware import WafMiddleware
        app.add_middleware(WafMiddleware, enforced=settings.WAF_ENFORCED, mode=settings.WAF_MODE)
    except Exception:
        logger.debug("waf_middleware_skipped", exc_info=True)

    # Production mTLS — inter-service authentication
    try:
        from api.middleware.mtls_middleware import MtlsMiddleware
        app.add_middleware(MtlsMiddleware, enforced=settings.MTLS_ENFORCED)
    except Exception:
        logger.debug("mtls_middleware_skipped", exc_info=True)

    origins = settings.cors_origin_list
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=origins != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Request-Duration-ms", "X-Trace-Id", "X-Total-Count", "X-Cache", "X-Cache-Hit"],
    )
    if settings.trusted_host_list and settings.trusted_host_list != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_host_list)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1024)  # W59-60: compress bulky JSON payloads
    app.add_middleware(RequestIDMiddleware)
    if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
        app.add_middleware(AuthMiddleware, settings=settings)
        app.add_middleware(RateLimitMiddleware, redis_client=_shared_rate_limit_backend())
    # Platform self-observability: W3C trace-context + Prometheus metrics on
    # every request (works in all environments; cheap single pass).
    from observability.metrics import MetricsRegistry
    from observability.metrics import TraceStore as _TraceStore
    import os as _os

    app.state.metrics = MetricsRegistry()
    app.state.evidence_pack = None
    _sink = _os.environ.get("CRYPTOSCAN_SNAPSHOT_DIR", "data")
    app.state.traces = _TraceStore(
        sink_path=None if settings.ENVIRONMENT.lower() in {"test", "testing"}
        else Path(_sink) / "traces" / "spans.jsonl",
        otlp_endpoint=_os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))
    from api.middleware.observability_middleware import ObservabilityMiddleware

    app.add_middleware(ObservabilityMiddleware,
                       registry=app.state.metrics, traces=app.state.traces)
    # ABAC scope enforcement runs just inside the auth gate on EVERY route.
    # It is a no-op unless ABAC_ENFORCED is set (and grants are provisioned),
    # so test/dev installs keep working while large-bank deployments get
    # fail-closed Region→BU→Environment→Asset isolation.
    from api.middleware.abac_middleware import AbacMiddleware

    app.add_middleware(AbacMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Innermost: runs right after the route so every successful mutating call
    # across all services lands on the real-time bus (api.<segment>.<verb>).
    from api.middleware.control_events import ControlEventMiddleware

    app.add_middleware(ControlEventMiddleware)

    @app.exception_handler(AuthenticationError)
    async def auth_exception_handler(request: Request, exc: AuthenticationError):
        return JSONResponse(status_code=401, content={"detail": exc.message})

    @app.exception_handler(ValidationError)
    async def validation_exception_handler(request: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content={"detail": exc.message, "errors": exc.errors})

    @app.get("/health")
    def health_check():
        return {"status": "healthy", "version": settings.API_VERSION, "environment": settings.ENVIRONMENT}

    @app.get("/ready")
    def ready_check():
        from db.connection.engine import check_db_health

        db = check_db_health()
        ready = db.get("status") == "healthy"
        return {
            "ready": ready,
            "status": "ok" if ready else "degraded",
            "database": db,
            "environment": settings.ENVIRONMENT,
            "version": settings.API_VERSION,
        }

    # Root-level LB/K8s probe aliases of /api/v1/healthz + /api/v1/readyz.
    # smoke_test.sh and the hardening guide probe these at the edge; /readyz
    # carries the drain semantics (503 while the database is down) that the
    # legacy /ready above intentionally does not have.
    @app.get("/healthz")
    def healthz_root_alias():
        from api.routers.health import healthz as _healthz

        return _healthz()

    @app.get("/readyz")
    def readyz_root_alias():
        from api.routers.health import readyz as _readyz

        return _readyz()

    prefix = "/api/v1"
    app.include_router(auth.router, prefix=prefix)
    app.include_router(banking.router, prefix=prefix)
    # Runtime findings MUST be registered before scans.router: scans exposes a
    # catch-all GET /scans/{scan_id} which would otherwise shadow the static
    # path /scans/runtime-findings (FastAPI matches routes in include order).
    app.include_router(runtime.router, prefix=prefix)
    app.include_router(scans.router, prefix=prefix)
    app.include_router(findings.router, prefix=prefix)
    app.include_router(drift.router, prefix=prefix)
    app.include_router(jobs.router, prefix=prefix)
    app.include_router(stats.router, prefix=prefix)
    app.include_router(baselines.router, prefix=prefix)
    app.include_router(trigger.router, prefix=prefix)
    app.include_router(webhooks.router, prefix=prefix)
    app.include_router(repo_configs.router, prefix=prefix)
    app.include_router(hardware.router, prefix=prefix)
    app.include_router(crypto.router, prefix=prefix)
    app.include_router(health.router, prefix=prefix)
    app.include_router(export.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(inventory.router, prefix=prefix)
    app.include_router(inventory_cloud.router, prefix=prefix)
    app.include_router(scope.router, prefix=prefix)
    app.include_router(risk.router, prefix=prefix)
    app.include_router(connectors.router, prefix=prefix)
    app.include_router(live.router, prefix=prefix)
    app.include_router(algorithms.router, prefix=prefix)
    app.include_router(systems.router, prefix=prefix)
    app.include_router(cbom.router, prefix=prefix)
    app.include_router(container.router, prefix=prefix)
    app.include_router(container_scans.router, prefix=prefix)
    app.include_router(vulns.router, prefix=prefix)
    app.include_router(vulnerability.router, prefix=prefix)
    app.include_router(policy.router, prefix=prefix)
    app.include_router(quantum.router, prefix=prefix)
    app.include_router(intelligence.router, prefix=prefix)
    app.include_router(network.router, prefix=prefix)
    app.include_router(network_scans.router, prefix=prefix)
    app.include_router(certificates.router, prefix=prefix)
    app.include_router(cloud.router, prefix=prefix)
    app.include_router(cloud_scans.router, prefix=prefix)
    app.include_router(estate.router, prefix=prefix)
    app.include_router(techbom.router, prefix=prefix)
    app.include_router(graph.router, prefix=prefix)
    app.include_router(reachability.router, prefix=prefix)
    app.include_router(remediation.router, prefix=prefix)
    app.include_router(report_schedules.router, prefix=prefix)
    app.include_router(monitor.router, prefix=prefix)
    app.include_router(payment_crypto.router, prefix=prefix)
    app.include_router(telecom.router, prefix=prefix)
    app.include_router(audit_export.router, prefix=prefix)
    app.include_router(events.router, prefix=prefix)
    app.include_router(notifications.router, prefix=prefix)
    app.include_router(live_scan.router, prefix=prefix)
    app.include_router(api_keys.router, prefix=prefix)
    app.include_router(saas.router, prefix=prefix)
    app.include_router(stream.router, prefix=prefix)
    app.include_router(priority.router, prefix=prefix)
    app.include_router(billing.router, prefix=prefix)
    app.include_router(ops.router, prefix=prefix)
    app.include_router(compliance.router, prefix=prefix)
    app.include_router(business.router, prefix=prefix)
    app.include_router(business_context.router, prefix=prefix)
    app.include_router(agility.router, prefix=prefix)
    app.include_router(exceptions.router, prefix=prefix)
    app.include_router(ot.router, prefix=prefix)
    app.include_router(ot_safety.router, prefix=prefix)
    app.include_router(sla.router, prefix=prefix)
    app.include_router(automation.router, prefix=prefix)
    app.include_router(automation_ops.router, prefix=prefix)
    app.include_router(analytics.router, prefix=prefix)
    app.include_router(platform.router, prefix=prefix)
    app.include_router(sectors.router, prefix=prefix)
    app.include_router(sso.router, prefix=prefix)
    app.include_router(scim.router, prefix=prefix)
    app.include_router(workload.router, prefix=prefix)
    app.include_router(devsecops.router, prefix=prefix)
    app.include_router(resilience.router, prefix=prefix)
    app.include_router(crypto_assurance.router, prefix=prefix)
    app.include_router(onboarding.router, prefix=prefix)
    app.include_router(control_plane.router, prefix=prefix)
    app.include_router(security_router.router, prefix=prefix)
    app.include_router(enterprise.router, prefix=prefix)
    app.include_router(marketplace_router.router, prefix=prefix)
    app.include_router(datalake_router.router, prefix=prefix)
    app.include_router(anomaly_router.router, prefix=prefix)
    app.include_router(governance_router.router, prefix=prefix)
    app.include_router(production.router, prefix=prefix)
    app.include_router(compliance_packs.router, prefix=prefix)
    app.include_router(siem.router, prefix=prefix)
    app.include_router(zero_trust.router, prefix=prefix)
    app.include_router(threat_model.router, prefix=prefix)
    app.include_router(incident_response.router, prefix=prefix)
    app.include_router(chaos.router, prefix=prefix)
    app.include_router(active_active.router, prefix=prefix)
    app.include_router(backup.router, prefix=prefix)
    # QSE parity — CASB, HBOM, Entropy Core, Sovereign Storage, HSM Fabric, QSim, Collaboration, Compliance Cert
    app.include_router(casb.router, prefix=prefix)
    app.include_router(hbom.router, prefix=prefix)
    app.include_router(entropy_core.router, prefix=prefix)
    app.include_router(sovereign_storage.router, prefix=prefix)
    app.include_router(hsm_fabric.router, prefix=prefix)
    app.include_router(qsim.router, prefix=prefix)
    app.include_router(collaboration.router, prefix=prefix)
    app.include_router(compliance_cert.router, prefix=prefix)
    # Improvement plan to beat QSE — Living CBOM, API Scanner, Network Device, CA Hierarchy, Key Lifecycle, Streaming Backbone, Attack Detection, Telecom Enhanced, HSM Enhanced, Migration Simulator
    app.include_router(living_cbom.router, prefix=prefix)
    app.include_router(api_scanner.router, prefix=prefix)
    app.include_router(network_device_scanner.router, prefix=prefix)
    app.include_router(ca_hierarchy.router, prefix=prefix)
    app.include_router(key_lifecycle.router, prefix=prefix)
    app.include_router(streaming_backbone.router, prefix=prefix)
    app.include_router(attack_detection.router, prefix=prefix)
    app.include_router(telecom_enhanced.router, prefix=prefix)
    app.include_router(hsm_inventory_enhanced.router, prefix=prefix)
    app.include_router(migration_simulator.router, prefix=prefix)
    app.include_router(ot_enhanced.router, prefix=prefix)
    app.include_router(compliance_deterministic.router, prefix=prefix)
    app.include_router(evidence_chain_enhanced.router, prefix=prefix)
    app.include_router(exception_enhanced.router, prefix=prefix)
    # Additional 20 improvements architecture & dataflow
    app.include_router(supply_chain_integrity.router, prefix=prefix)
    app.include_router(sbom_slsa.router, prefix=prefix)
    app.include_router(ct_log_monitor.router, prefix=prefix)
    app.include_router(cert_lifecycle_automation.router, prefix=prefix)
    app.include_router(policy_as_code.router, prefix=prefix)
    app.include_router(telemetry_pipeline.router, prefix=prefix)
    app.include_router(pqc_infra_monitor.router, prefix=prefix)
    app.include_router(qrng_entropy_monitor.router, prefix=prefix)
    app.include_router(vpn_monitor.router, prefix=prefix)
    app.include_router(dnssec_dane_monitor.router, prefix=prefix)
    app.include_router(secure_boot_tpm.router, prefix=prefix)
    app.include_router(firmware_analysis.router, prefix=prefix)
    app.include_router(incident_response_playbooks.router, prefix=prefix)
    app.include_router(forensic_vault.router, prefix=prefix)
    app.include_router(kms_policy_enforcement.router, prefix=prefix)
    app.include_router(backup_encryption_verification.router, prefix=prefix)
    app.include_router(dr_crypto_validation.router, prefix=prefix)
    app.include_router(audit_merkle.router, prefix=prefix)
    app.include_router(compliance_evidence_automation.router, prefix=prefix)
    app.include_router(plugin_marketplace.router, prefix=prefix)
    # Next 20 — secrets, dependency risk, remediation, threat intel, zero trust, compliance mapping, data classification, blockchain, IoT/OT, AI/ML, eBPF, SLSA attestation, PQ cost, drift anomaly, risk quantification, tenant isolation, code review, HSM deep, network analyzer, evidence lake
    app.include_router(secrets_detection.router, prefix=prefix)
    app.include_router(dependency_risk.router, prefix=prefix)
    app.include_router(remediation_orchestrator.router, prefix=prefix)
    app.include_router(threat_intel.router, prefix=prefix)
    app.include_router(zero_trust_crypto.router, prefix=prefix)
    app.include_router(compliance_mapping.router, prefix=prefix)
    app.include_router(data_classification.router, prefix=prefix)
    app.include_router(blockchain_crypto.router, prefix=prefix)
    app.include_router(iot_ot_crypto.router, prefix=prefix)
    app.include_router(ai_ml_crypto_guard.router, prefix=prefix)
    app.include_router(runtime_crypto_ebpf.router, prefix=prefix)
    app.include_router(slsa_attestation_verifier.router, prefix=prefix)
    app.include_router(pq_migration_cost.router, prefix=prefix)
    app.include_router(drift_anomaly.router, prefix=prefix)
    app.include_router(risk_quantification.router, prefix=prefix)
    app.include_router(tenant_isolation_validator.router, prefix=prefix)
    app.include_router(secure_code_review.router, prefix=prefix)
    app.include_router(hsm_deep_inventory.router, prefix=prefix)
    app.include_router(network_crypto_analyzer.router, prefix=prefix)
    app.include_router(evidence_lake.router, prefix=prefix)
    app.include_router(deterministic_policy_enforcement.router, prefix=prefix)
    app.include_router(crypto_agility_maturity.router, prefix=prefix)
    app.include_router(quantum_threat_timeline.router, prefix=prefix)
    app.include_router(hndl_risk_calculator.router, prefix=prefix)
    app.include_router(pqc_migration_playbook.router, prefix=prefix)
    app.include_router(crypto_inventory_health.router, prefix=prefix)
    app.include_router(compliance_evidence_graph.router, prefix=prefix)
    app.include_router(remediation_verification.router, prefix=prefix)
    app.include_router(crypto_drift_timeline.router, prefix=prefix)
    app.include_router(executive_risk_heatmap.router, prefix=prefix)
    app.include_router(third_party_crypto_risk.router, prefix=prefix)
    app.include_router(cloud_crypto_posture.router, prefix=prefix)
    app.include_router(kubernetes_crypto_security.router, prefix=prefix)
    app.include_router(cicd_crypto_gate.router, prefix=prefix)
    app.include_router(secrets_management_integration.router, prefix=prefix)
    app.include_router(certificate_transparency_v2.router, prefix=prefix)
    app.include_router(pqc_readiness_dashboard.router, prefix=prefix)
    app.include_router(crypto_policy_drift.router, prefix=prefix)
    app.include_router(automated_evidence_collection.router, prefix=prefix)
    app.include_router(threat_model_automation.router, prefix=prefix)
    app.include_router(crypto_material_vault.router, prefix=prefix)
    app.include_router(key_birth_death_ledger.router, prefix=prefix)
    app.include_router(certificate_lifecycle_orchestrator.router, prefix=prefix)
    app.include_router(cryptographic_debt_ledger.router, prefix=prefix)
    app.include_router(cryptographic_simulation_engine.router, prefix=prefix)
    app.include_router(change_impact_predictor.router, prefix=prefix)
    app.include_router(blast_radius_calculator.router, prefix=prefix)
    app.include_router(cryptographic_boundary_mapper.router, prefix=prefix)
    app.include_router(live_crypto_posture_score.router, prefix=prefix)
    app.include_router(anomaly_detection_engine.router, prefix=prefix)
    app.include_router(crypto_health_monitor.router, prefix=prefix)
    app.include_router(real_time_attack_detector.router, prefix=prefix)
    app.include_router(pqc_migration_orchestrator.router, prefix=prefix)
    app.include_router(hybrid_mode_manager.router, prefix=prefix)
    app.include_router(quantum_readiness_index.router, prefix=prefix)
    app.include_router(pqc_performance_benchmarker.router, prefix=prefix)
    app.include_router(telecom_signaling_analyzer.router, prefix=prefix)
    app.include_router(three_gpp_compliance_mapper.router, prefix=prefix)
    app.include_router(ot_protocol_crypto_analyzer.router, prefix=prefix)
    app.include_router(industrial_control_crypto_monitor.router, prefix=prefix)
    app.include_router(supply_chain_provenance_engine.router, prefix=prefix)
    app.include_router(sbom_correlation_engine.router, prefix=prefix)
    app.include_router(vendor_crypto_risk_scorer.router, prefix=prefix)
    app.include_router(firmware_provenance_tracker.router, prefix=prefix)
    app.include_router(evidence_automation_engine.router, prefix=prefix)
    app.include_router(audit_log_merkle_compressor.router, prefix=prefix)
    app.include_router(attestation_pipeline.router, prefix=prefix)
    app.include_router(backup_dr_orchestrator.router, prefix=prefix)
    app.include_router(capacity_planner.router, prefix=prefix)
    app.include_router(cryptographic_trust_graph.router, prefix=prefix)
    app.include_router(crypto_agility_index.router, prefix=prefix)
    app.include_router(deterministic_threat_modeler.router, prefix=prefix)
    app.include_router(multi_dimensional_compliance_cube.router, prefix=prefix)
    app.include_router(quantum_entropy_fabric.router, prefix=prefix)
    app.include_router(pqc_code_signing_orchestrator.router, prefix=prefix)
    app.include_router(zero_trust_crypto_enforcer.router, prefix=prefix)
    app.include_router(confidential_computing_attestor.router, prefix=prefix)
    app.include_router(fhe_performance_optimizer.router, prefix=prefix)
    app.include_router(zk_proof_verifier.router, prefix=prefix)
    app.include_router(threshold_crypto_orchestrator.router, prefix=prefix)
    app.include_router(crypto_policy_simulator.router, prefix=prefix)
    app.include_router(key_rotation_orchestrator.router, prefix=prefix)
    app.include_router(certificate_pinning_enforcer.router, prefix=prefix)
    app.include_router(tls_hardening_orchestrator.router, prefix=prefix)
    app.include_router(dnssec_chain_validator.router, prefix=prefix)
    app.include_router(secure_boot_chain_verifier.router, prefix=prefix)
    app.include_router(firmware_crypto_extractor.router, prefix=prefix)
    app.include_router(runtime_secret_leak_detector_v2.router, prefix=prefix)
    app.include_router(sbom_vulnerability_correlator.router, prefix=prefix)
    app.include_router(ct_log_aggregator.router, prefix=prefix)
    app.include_router(k8s_crypto_admission_controller.router, prefix=prefix)
    app.include_router(cicd_crypto_gate_enforcer.router, prefix=prefix)
    app.include_router(secrets_management_unifier.router, prefix=prefix)
    app.include_router(cloud_kms_posture_enforcer.router, prefix=prefix)
    app.include_router(network_device_crypto_auditor.router, prefix=prefix)
    app.include_router(api_crypto_posture_analyzer.router, prefix=prefix)
    app.include_router(blockchain_crypto_auditor.router, prefix=prefix)
    app.include_router(iot_firmware_crypto_scanner.router, prefix=prefix)
    app.include_router(ml_model_crypto_guard.router, prefix=prefix)
    app.include_router(siem_crypto_correlator.router, prefix=prefix)
    app.include_router(forensic_crypto_vault.router, prefix=prefix)
    app.include_router(compliance_evidence_lake.router, prefix=prefix)
    app.include_router(crypto_drift_predictor.router, prefix=prefix)
    app.include_router(hsm_fleet_orchestrator.router, prefix=prefix)
    app.include_router(kms_key_hierarchy_mapper.router, prefix=prefix)
    app.include_router(crypto_compliance_benchmark.router, prefix=prefix)
    app.include_router(pqc_migration_cost_estimator.router, prefix=prefix)
    app.include_router(quantum_threat_forecaster.router, prefix=prefix)
    app.include_router(crypto_asset_risk_scorer.router, prefix=prefix)
    app.include_router(crypto_inventory_reconciler.router, prefix=prefix)
    app.include_router(crypto_policy_enforcer_v2.router, prefix=prefix)
    app.include_router(audit_log_analytics_engine.router, prefix=prefix)
    app.include_router(evidence_chain_verifier.router, prefix=prefix)
    app.include_router(exception_management_engine.router, prefix=prefix)
    app.include_router(remediation_orchestrator_v2.router, prefix=prefix)
    app.include_router(threat_model_automation_engine.router, prefix=prefix)
    app.include_router(data_classification_engine.router, prefix=prefix)
    app.include_router(confidential_data_flow_tracker_v2.router, prefix=prefix)
    app.include_router(crypto_asset_lineage_tracker_v2.router, prefix=prefix)
    app.include_router(continuous_assurance_monitor_v2.router, prefix=prefix)
    app.include_router(telemetry_pipeline_orchestrator.router, prefix=prefix)
    app.include_router(streaming_backbone_monitor.router, prefix=prefix)
    app.include_router(tenant_isolation_validator_v2.router, prefix=prefix)
    app.include_router(secure_code_review_engine.router, prefix=prefix)
    app.include_router(hsm_deep_inventory_scanner_v2.router, prefix=prefix)
    app.include_router(network_crypto_posture_enforcer.router, prefix=prefix)
    app.include_router(evidence_lake_query_engine.router, prefix=prefix)
    app.include_router(api_security_posture_enforcer.router, prefix=prefix)
    app.include_router(cloud_kms_inventory_enhanced.router, prefix=prefix)
    app.include_router(secrets_rotation_automation_engine.router, prefix=prefix)
    app.include_router(cert_pinning_validator_enhanced.router, prefix=prefix)
    app.include_router(pqc_tls_analyzer_enhanced.router, prefix=prefix)
    app.include_router(supply_chain_attestation_verifier.router, prefix=prefix)
    app.include_router(realtime_system.router, prefix=prefix)
    app.include_router(cryptographic_digital_twin.router, prefix=prefix)
    app.include_router(twin_mirror_ingestion.router, prefix=prefix)
    app.include_router(twin_state_store.router, prefix=prefix)
    app.include_router(twin_entity_model.router, prefix=prefix)
    app.include_router(twin_relationship_model.router, prefix=prefix)
    app.include_router(twin_behavioral_model.router, prefix=prefix)
    app.include_router(twin_temporal_model.router, prefix=prefix)
    app.include_router(twin_simulation_engine.router, prefix=prefix)
    app.include_router(twin_scenario_types.router, prefix=prefix)
    app.include_router(twin_analysis_output.router, prefix=prefix)
    app.include_router(twin_isolation_guardrails.router, prefix=prefix)
    app.include_router(twin_time_travel.router, prefix=prefix)
    app.include_router(twin_api.router, prefix=prefix)
    app.include_router(cryptographic_digital_twin_real.router, prefix=prefix)
    app.include_router(correlation_engine.router, prefix=prefix)
    app.include_router(behavioral_baselines.router, prefix=prefix)
    app.include_router(risk_scoring_engine.router, prefix=prefix)
    app.include_router(cross_standard_compliance.router, prefix=prefix)
    app.include_router(live_cbom_v2.router, prefix=prefix)
    app.include_router(attack_path_analysis.router, prefix=prefix)
    app.include_router(data_sovereignty.router, prefix=prefix)
    app.include_router(certification_pipeline.router, prefix=prefix)
    app.include_router(key_custody_splitting.router, prefix=prefix)
    app.include_router(timeseries_analytics.router, prefix=prefix)
    app.include_router(quantum_key_distribution_monitor.router, prefix=prefix)
    app.include_router(post_quantum_hsm_integration.router, prefix=prefix)
    app.include_router(crypto_bill_of_materials_enhanced.router, prefix=prefix)
    app.include_router(secure_multiparty_computation_validator.router, prefix=prefix)
    app.include_router(homomorphic_encryption_analyzer.router, prefix=prefix)
    app.include_router(differential_privacy_validator.router, prefix=prefix)
    app.include_router(confidential_data_flow_tracker.router, prefix=prefix)
    app.include_router(crypto_asset_lineage_tracker.router, prefix=prefix)
    app.include_router(automated_pqc_migration_executor.router, prefix=prefix)
    app.include_router(continuous_assurance_monitor.router, prefix=prefix)
    app.include_router(confidential_computing_validator.router, prefix=prefix)
    app.include_router(post_quantum_code_signing.router, prefix=prefix)
    app.include_router(crypto_inventory_reconciliation.router, prefix=prefix)
    app.include_router(automated_compliance_reporting.router, prefix=prefix)
    app.include_router(threat_modeling_engine.router, prefix=prefix)
    app.include_router(key_ceremony_orchestrator.router, prefix=prefix)
    app.include_router(secure_boot_attestation.router, prefix=prefix)
    app.include_router(tls_configuration_hardening.router, prefix=prefix)
    app.include_router(crypto_policy_enforcement.router, prefix=prefix)
    app.include_router(audit_log_analytics.router, prefix=prefix)
    app.include_router(api_security_posture.router, prefix=prefix)
    app.include_router(cloud_kms_inventory.router, prefix=prefix)
    app.include_router(secrets_rotation_automation.router, prefix=prefix)
    app.include_router(certificate_pinning_validator.router, prefix=prefix)
    app.include_router(pqc_tls_analyzer.router, prefix=prefix)
    app.include_router(supply_chain_attestation.router, prefix=prefix)
    app.include_router(runtime_secret_leak_detector.router, prefix=prefix)
    app.include_router(crypto_agility_score_v2.router, prefix=prefix)
    app.include_router(compliance_drift_detector.router, prefix=prefix)
    app.include_router(executive_dashboard.router, prefix=prefix)
    app.include_router(metrics_router.router)  # /metrics (no /api prefix)

    dashboard_dist = Path(__file__).resolve().parents[2] / "dashboard" / "dist"
    dashboard_html = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
    if dashboard_dist.is_dir() and (dashboard_dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dashboard_dist / "assets"), name="assets")

        @app.get("/")
        def spa_root():
            return FileResponse(dashboard_dist / "index.html")
    elif dashboard_html.is_file():

        @app.get("/")
        def home():
            return HTMLResponse(dashboard_html.read_text(encoding="utf-8"))

    return app


settings = get_settings()
app = create_app(settings)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST or "0.0.0.0",
        port=int(settings.API_PORT or 8010),
        reload=False,
    )


if __name__ == "__main__":
    run()
