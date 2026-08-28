"""Scan processing pipeline stages executed by the worker.

Modules:
- cloud_job: Execute a CLOUD inventory job without cloning a git repository
- pipeline_runner: 8-stage scan pipeline (sync)
- progress: Named pipeline stages used for job progress reporting
- stage_agility: Score the resolved system with the 6-factor agility + readiness engines
- stage_quantum: Scan-level quantum report + PQC migration plan into scan statistics
- stage_alert: Pipeline stage: notify on high/critical drift
- stage_business_enrich: Persist business_context onto crypto_assets.extra after the graph is known
- stage_cbom_generate: Optional pipeline stage: write a CycloneDX CBOM for the scan
- stage_cert_inventory: Update certificate inventory after a network TLS scan
- stage_clone: Pipeline stage: clone the target repository
- stage_cloud_scan: Scan Terraform / CloudFormation / Kubernetes manifests for crypto config
- stage_container_scan: Optional container / image-root inventory stage
- stage_deduplication: Pipeline stage: merge findings into crypto assets
- stage_drift: Pipeline stage: compare the current scan to the approved baseline
- stage_evidence: Pipeline stage: evidence integrity chain
- stage_graph_sync: Sync the relational inventory into Neo4j after a scan
- stage_language_detect: Detect languages present in the cloned workspace
- stage_load: Pipeline stage: persist scan + evidence
- stage_multi_scanner: Run static, container, network, and cloud scanners for one workspace
- stage_network_scan: Discover TLS endpoints and local certificates in the scanned tree
- stage_normalize: Pipeline stage: normalize algorithm names
- stage_ot_scan: Passively parse OT/ICS captures that happen to live in the scanned tree
- stage_policy: Pipeline stage: evaluate policy rules
- stage_scan: Pipeline stage: static multi-language scan
"""
