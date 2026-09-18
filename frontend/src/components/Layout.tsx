import React, { useEffect, useState } from "react";
import { useLiveTicker, useAlertToasts, Toasts } from "./Live.jsx";
import SearchOverlay from "./Search.jsx";
import { getToken, setToken, getUserName, apiMyGrants, apiStatsSummary } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";

const NAV = [
  { sectionKey: "nav.groupOverview", items: [
    { to: "/", labelKey: "nav.commandCenter", icon: "◈" },
    { to: "/executive", labelKey: "nav.executiveView", icon: "▦" },
    { to: "/role-home", labelKey: "nav.roleWorkspace", icon: "◐" },
    { to: "/onboarding", labelKey: "nav.discovery", icon: "➤" },
  ]},
  { sectionKey: "nav.groupScanners", items: [
    { to: "/scanners", labelKey: "nav.scanners", icon: "⌖" },
    { to: "/live-scanners", labelKey: "nav.realtimeScanners", icon: "◉" },
    { to: "/live-stream", labelKey: "nav.liveStream", icon: "⇄" },
    { to: "/priorities", labelKey: "nav.priorities", icon: "▲" },
    { to: "/telecom", labelKey: "nav.telecom", icon: "⌬" },
    { to: "/network", labelKey: "nav.network", icon: "◈" },
    { to: "/cloud", labelKey: "nav.cloud", icon: "☁" },
    { to: "/hardware", labelKey: "nav.hardware", icon: "⌬" },
    { to: "/vendor", labelKey: "nav.vendor", icon: "▤" },
    { to: "/runtime", labelKey: "nav.runtimeHosts", icon: "⧉" },
    { to: "/certificates", labelKey: "nav.certificates", icon: "⊞" },
  ]},
  { sectionKey: "nav.groupAssets", items: [
    { to: "/cmdb", labelKey: "nav.cmdb", icon: "▣" },
    { to: "/assets", labelKey: "nav.assets", icon: "▤" },
    { to: "/catalog", labelKey: "nav.catalogs", icon: "☷" },
    { to: "/crypto-assets", labelKey: "nav.cryptoAssets", icon: "⚿" },
    { to: "/libraries", labelKey: "nav.cryptoLibraries", icon: "▤" },
    { to: "/protocols", labelKey: "nav.protocols", icon: "⇄" },
    { to: "/devsecops", labelKey: "nav.devsecops", icon: "⛀" },
  ]},
  { sectionKey: "nav.groupIntelligence", items: [
    { to: "/crypto", labelKey: "nav.cryptography", icon: "⚿" },
    { to: "/cbom", labelKey: "nav.cbom", icon: "⬡" },
    { to: "/hbom", labelKey: "nav.hbom", icon: "⬢" },
    { to: "/live-asset-intelligence", labelKey: "nav.liveAssetIntelligence", icon: "⬟" },
    { to: "/graph", labelKey: "nav.dependencyGraph", icon: "⬟" },
  ]},
  { sectionKey: "nav.groupAssess", items: [
    { to: "/pqc", labelKey: "nav.pqcReadiness", icon: "◬" },
    { to: "/pqc-map", labelKey: "nav.pqcMigrationMap", icon: "⇉" },
    { to: "/risk", labelKey: "nav.risk", icon: "⚠" },
    { to: "/drift", labelKey: "nav.drift", icon: "⇄" },
    { to: "/alerts", labelKey: "nav.alerts", icon: "▲" },
    { to: "/agility", labelKey: "nav.cryptoAgility", icon: "◔" },
    { to: "/crypto-assurance", labelKey: "nav.cryptoAssurance", icon: "⚿" },
  ]},
  { sectionKey: "nav.groupOperations", items: [
    { to: "/whatif", labelKey: "nav.whatIf", icon: "▶" },
    { to: "/migration", labelKey: "nav.migrationPlanning", icon: "⇉" },
    { to: "/automation", labelKey: "nav.automation", icon: "⚙" },
    { to: "/crypto-changes", labelKey: "nav.liveCryptoChanges", icon: "≋" },
    { to: "/timeline", labelKey: "nav.globalTimeline", icon: "◷" },
    { to: "/env", labelKey: "nav.liveEnvironment", icon: "◉" },
  ]},
  { sectionKey: "nav.groupGovern", items: [
    { to: "/scope", labelKey: "nav.scope", icon: "⚖" },
    { to: "/compliance", labelKey: "nav.compliance", icon: "✓" },
    { to: "/governance", labelKey: "nav.governance", icon: "⚖" },
    { to: "/supervision", labelKey: "nav.supervision", icon: "⛨" },
    { to: "/resilience", labelKey: "nav.resilience", icon: "⛨" },
    { to: "/trust", labelKey: "nav.trustKeys", icon: "⚿" },
    { to: "/evidence", labelKey: "nav.evidence", icon: "⛨" },
    { to: "/reports", labelKey: "nav.reports", icon: "▤" },
  ]},
  { sectionKey: "nav.groupPlatform", items: [
    { to: "/findings", labelKey: "nav.findings", icon: "⌕" },
    { to: "/integrations", labelKey: "nav.integrations", icon: "⇌" },
    { to: "/notifications", labelKey: "nav.notifications", icon: "✉" },
    { to: "/identity", labelKey: "nav.usersAccess", icon: "⛃" },
    { to: "/security", labelKey: "nav.security", icon: "🛡" },
    { to: "/security-center", labelKey: "nav.securityCenter", icon: "☗" },
    { to: "/security-policy", labelKey: "nav.securityPolicy", icon: "⛨" },
    { to: "/settings", labelKey: "nav.settings", icon: "⚙" },
    { to: "/organization", labelKey: "nav.organization", icon: "◫" },
    { to: "/tenancy", labelKey: "nav.tenancy", icon: "⛓" },
    { to: "/sectors", labelKey: "nav.sectorProfiles", icon: "⛨" },
    { to: "/accuracy", labelKey: "nav.accuracy", icon: "◔" },
    { to: "/platform", labelKey: "nav.platformP2", icon: "⬢" },
    { to: "/admin", labelKey: "nav.administration", icon: "⚙" },
  ]},
  { sectionKey: "Beat QSE — 10 Priorities", items: [
    { to: "/living-cbom", labelKey: "Living CBOM", icon: "⬡" },
    { to: "/api-scanner", labelKey: "API Scanner", icon: "⌖" },
    { to: "/network-device", labelKey: "Net Device Scanner", icon: "◈" },
    { to: "/ca-hierarchy", labelKey: "CA Hierarchy", icon: "⊞" },
    { to: "/key-lifecycle", labelKey: "Key Lifecycle", icon: "⚿" },
    { to: "/hsm-enhanced", labelKey: "HSM Enhanced", icon: "⌬" },
    { to: "/streaming-backbone", labelKey: "Streaming Backbone", icon: "⇄" },
    { to: "/attack-detection", labelKey: "Attack Detection", icon: "⚠" },
    { to: "/telecom-enhanced", labelKey: "Telecom Enhanced", icon: "⌬" },
    { to: "/migration-simulator", labelKey: "Migration Simulator", icon: "⇉" },
  ]},
  { sectionKey: "Beat QSE — 20 More", items: [
    { to: "/supply-chain", labelKey: "Supply Chain Integrity", icon: "⬡" },
    { to: "/sbom-slsa", labelKey: "SBOM + SLSA", icon: "⬢" },
    { to: "/ct-monitor", labelKey: "CT Log Monitor", icon: "⊞" },
    { to: "/cert-lifecycle", labelKey: "Cert Lifecycle ACME/EST", icon: "⊞" },
    { to: "/policy-as-code", labelKey: "Policy as Code GitOps", icon: "⚖" },
    { to: "/telemetry-pipeline", labelKey: "Telemetry Pipeline", icon: "⇄" },
    { to: "/pqc-infra", labelKey: "PQC Infra Monitor", icon: "◬" },
    { to: "/qrng-entropy", labelKey: "QRNG / Entropy", icon: "◔" },
    { to: "/vpn-monitor", labelKey: "VPN Monitor", icon: "◈" },
    { to: "/dnssec-dane", labelKey: "DNSSEC / DANE", icon: "◈" },
    { to: "/secure-boot-tpm", labelKey: "Secure Boot / TPM / TEE", icon: "⛨" },
    { to: "/firmware-analysis", labelKey: "Firmware Analysis", icon: "⌬" },
    { to: "/incident-response-playbooks", labelKey: "IR Playbooks", icon: "⚠" },
    { to: "/forensic-vault", labelKey: "Forensic Vault WORM", icon: "⛨" },
    { to: "/kms-policy", labelKey: "KMS Policy Enforcement", icon: "⚿" },
    { to: "/backup-encryption", labelKey: "Backup Encryption", icon: "▤" },
    { to: "/dr-crypto", labelKey: "DR Crypto Validation", icon: "⛨" },
    { to: "/audit-merkle", labelKey: "Audit Merkle Tree", icon: "⛨" },
    { to: "/compliance-evidence", labelKey: "Compliance Evidence Auto", icon: "✓" },
    { to: "/plugin-marketplace", labelKey: "Plugin Marketplace", icon: "⬢" },
  ]},
  { sectionKey: "Backend Additional & Unique 41 Features", items: [
    { to: "/crypto-material-vault", labelKey: "Crypto Material Vault Full Lifecycle", icon: "⚿" },
    { to: "/key-birth-death-ledger", labelKey: "Key Birth-Death Ledger Blockchain", icon: "⬡" },
    { to: "/certificate-lifecycle-orchestrator", labelKey: "Cert Lifecycle Orchestrator", icon: "⊞" },
    { to: "/cryptographic-debt-ledger", labelKey: "Crypto Debt Ledger $ Interest", icon: "⚠" },
    { to: "/cryptographic-simulation-engine", labelKey: "Crypto Simulation What-If", icon: "◈" },
    { to: "/change-impact-predictor", labelKey: "Change Impact Predictor", icon: "⇉" },
    { to: "/blast-radius-calculator", labelKey: "Blast Radius Calculator", icon: "⬟" },
    { to: "/cryptographic-boundary-mapper", labelKey: "Crypto Boundary Mapper", icon: "◫" },
    { to: "/live-crypto-posture-score", labelKey: "Live Posture Score 0-100", icon: "◔" },
    { to: "/anomaly-detection-engine", labelKey: "Anomaly Detection YAML Flink", icon: "≋" },
    { to: "/crypto-health-monitor", labelKey: "Crypto Health Monitor 8 Checks", icon: "◉" },
    { to: "/real-time-attack-detector", labelKey: "Real-Time Attack Detector 13 Rules", icon: "⚠" },
    { to: "/pqc-migration-orchestrator", labelKey: "PQC Migration Orchestrator 6 Phases", icon: "⇉" },
    { to: "/hybrid-mode-manager", labelKey: "Hybrid Mode Manager Classical+PQC", icon: "◬" },
    { to: "/quantum-readiness-index", labelKey: "Quantum Readiness Index 0-100", icon: "◬" },
    { to: "/pqc-performance-benchmarker", labelKey: "PQC Performance Benchmarker", icon: "◔" },
    { to: "/telecom-signaling-analyzer", labelKey: "Telecom Signaling Analyzer SS7", icon: "⌬" },
    { to: "/3gpp-compliance-mapper", labelKey: "3GPP Compliance Mapper", icon: "✓" },
    { to: "/ot-protocol-crypto-analyzer", labelKey: "OT Protocol Crypto Analyzer", icon: "⌬" },
    { to: "/industrial-control-crypto-monitor", labelKey: "Industrial Control Crypto Monitor", icon: "⌬" },
    { to: "/supply-chain-provenance-engine", labelKey: "Supply Chain Provenance Engine", icon: "⬡" },
    { to: "/sbom-correlation-engine", labelKey: "SBOM Correlation Engine", icon: "⬢" },
    { to: "/vendor-crypto-risk-scorer", labelKey: "Vendor Crypto Risk Scorer", icon: "⚠" },
    { to: "/firmware-provenance-tracker", labelKey: "Firmware Provenance Tracker", icon: "⌬" },
    { to: "/evidence-automation-engine", labelKey: "Evidence Automation Engine", icon: "⛨" },
    { to: "/audit-log-merkle-compressor", labelKey: "Audit Log Merkle Compressor", icon: "⛨" },
    { to: "/attestation-pipeline", labelKey: "Attestation Pipeline CISO", icon: "✓" },
    { to: "/backup-dr-orchestrator", labelKey: "Backup & DR Orchestrator RTO 1h", icon: "▤" },
    { to: "/capacity-planner", labelKey: "Capacity Planner Auto-Scale", icon: "◷" },
    { to: "/cryptographic-trust-graph", labelKey: "Crypto Trust Graph Root→Leaf", icon: "⬟" },
    { to: "/crypto-agility-index", labelKey: "Crypto Agility Index 6 Factors", icon: "◔" },
    { to: "/deterministic-threat-modeler", labelKey: "Threat Modeler STRIDE ATT&CK", icon: "⚠" },
    { to: "/multi-dimensional-compliance-cube", labelKey: "Compliance Cube 3D Standards×Systems×Time", icon: "▦" },
  ]},
  { sectionKey: "Wave 9 — 30 More Deterministic", items: [
    { to: "/quantum-entropy-fabric", labelKey: "Quantum Entropy Fabric QRNG 100 Gbps", icon: "◉" },
    { to: "/pqc-code-signing-orchestrator", labelKey: "PQC Code Signing ML-DSA SLH-DSA", icon: "✓" },
    { to: "/zero-trust-crypto-enforcer", labelKey: "Zero Trust Crypto Enforcer mTLS", icon: "⛨" },
    { to: "/confidential-computing-attestor", labelKey: "Confidential Computing Attestor SGX", icon: "⛨" },
    { to: "/fhe-performance-optimizer", labelKey: "FHE Performance Optimizer BFV BGV", icon: "◔" },
    { to: "/zk-proof-verifier", labelKey: "ZK Proof Verifier Groth16 PLONK", icon: "◈" },
    { to: "/threshold-crypto-orchestrator", labelKey: "Threshold Crypto DKG Refresh", icon: "⚿" },
    { to: "/crypto-policy-simulator", labelKey: "Crypto Policy Simulator What-If", icon: "◈" },
    { to: "/key-rotation-orchestrator", labelKey: "Key Rotation Orchestrator 90d 30d", icon: "↻" },
    { to: "/certificate-pinning-enforcer", labelKey: "Cert Pinning Enforcer HPKP", icon: "⊞" },
    { to: "/tls-hardening-orchestrator", labelKey: "TLS Hardening Orchestrator PQC", icon: "◫" },
    { to: "/dnssec-chain-validator", labelKey: "DNSSEC Chain Validator Root→TLD", icon: "⌬" },
    { to: "/secure-boot-chain-verifier", labelKey: "Secure Boot Chain Verifier UEFI", icon: "⛨" },
    { to: "/firmware-crypto-extractor", labelKey: "Firmware Crypto Extractor Binwalk", icon: "⌬" },
    { to: "/runtime-secret-leak-detector-v2", labelKey: "Runtime Secret Leak Detector v2 eBPF", icon: "⚠" },
    { to: "/sbom-vulnerability-correlator", labelKey: "SBOM Vuln Correlator NVD OSV GHSA", icon: "⬢" },
    { to: "/ct-log-aggregator", labelKey: "CT Log Aggregator 50+ Logs Merkle", icon: "◉" },
    { to: "/k8s-crypto-admission-controller", labelKey: "K8s Admission Controller Crypto", icon: "⎈" },
    { to: "/cicd-crypto-gate-enforcer", labelKey: "CI/CD Crypto Gate Enforcer", icon: "⛨" },
    { to: "/secrets-management-unifier", labelKey: "Secrets Management Unifier Vault", icon: "⚿" },
    { to: "/cloud-kms-posture-enforcer", labelKey: "Cloud KMS Posture Enforcer", icon: "☁" },
    { to: "/network-device-crypto-auditor", labelKey: "Network Device Crypto Auditor", icon: "⌬" },
    { to: "/api-crypto-posture-analyzer", labelKey: "API Crypto Posture Analyzer OWASP", icon: "◫" },
    { to: "/blockchain-crypto-auditor", labelKey: "Blockchain Crypto Auditor EVM", icon: "⬡" },
    { to: "/iot-firmware-crypto-scanner", labelKey: "IoT Firmware Crypto Scanner", icon: "⌬" },
    { to: "/ml-model-crypto-guard", labelKey: "ML Model Crypto Guard Training", icon: "◈" },
    { to: "/siem-crypto-correlator", labelKey: "SIEM Crypto Correlator STIX TAXII", icon: "≋" },
    { to: "/forensic-crypto-vault", labelKey: "Forensic Crypto Vault PCAP Chain", icon: "⛨" },
    { to: "/compliance-evidence-lake", labelKey: "Compliance Evidence Lake WORM 7y", icon: "▤" },
    { to: "/crypto-drift-predictor", labelKey: "Crypto Drift Predictor Forecast", icon: "◷" },
  ]},
  { sectionKey: "Wave 10 — 30 More Enterprise Platform", items: [
    { to: "/hsm-fleet-orchestrator", labelKey: "HSM Fleet Orchestrator Thales Luna", icon: "⚿" },
    { to: "/kms-key-hierarchy-mapper", labelKey: "KMS Key Hierarchy Mapper DEK KEK", icon: "⬡" },
    { to: "/crypto-compliance-benchmark", labelKey: "Crypto Compliance Benchmark PCI NIST", icon: "✓" },
    { to: "/pqc-migration-cost-estimator", labelKey: "PQC Migration Cost Estimator 6-Phase", icon: "◔" },
    { to: "/quantum-threat-forecaster", labelKey: "Quantum Threat Forecaster NIST FIPS", icon: "◬" },
    { to: "/crypto-asset-risk-scorer", labelKey: "Crypto Asset Risk Scorer 0-100", icon: "⚠" },
    { to: "/crypto-inventory-reconciler", labelKey: "Crypto Inventory Reconciler 360 View", icon: "⬢" },
    { to: "/crypto-policy-enforcer-v2", labelKey: "Crypto Policy Enforcer v2 GitOps", icon: "⛨" },
    { to: "/audit-log-analytics-engine", labelKey: "Audit Log Analytics Engine Merkle", icon: "◷" },
    { to: "/evidence-chain-verifier", labelKey: "Evidence Chain Verifier WORM", icon: "⛨" },
    { to: "/exception-management-engine", labelKey: "Exception Management Engine Workflow", icon: "⚠" },
    { to: "/remediation-orchestrator-v2", labelKey: "Remediation Orchestrator v2 12 Strategies", icon: "⇉" },
    { to: "/threat-model-automation-engine", labelKey: "Threat Model Automation STRIDE", icon: "⚠" },
    { to: "/data-classification-engine", labelKey: "Data Classification Engine PII PHI", icon: "◫" },
    { to: "/confidential-data-flow-tracker-v2", labelKey: "Confidential Data Flow Tracker v2", icon: "◫" },
    { to: "/crypto-asset-lineage-tracker-v2", labelKey: "Crypto Asset Lineage Tracker v2", icon: "⬡" },
    { to: "/continuous-assurance-monitor-v2", labelKey: "Continuous Assurance Monitor v2 100K", icon: "◉" },
    { to: "/telemetry-pipeline-orchestrator", labelKey: "Telemetry Pipeline Orchestrator 100K", icon: "≋" },
    { to: "/streaming-backbone-monitor", labelKey: "Streaming Backbone Monitor Kafka", icon: "≋" },
    { to: "/tenant-isolation-validator-v2", labelKey: "Tenant Isolation Validator v2", icon: "⛨" },
    { to: "/secure-code-review-engine", labelKey: "Secure Code Review Engine 20 Langs", icon: "✓" },
    { to: "/hsm-deep-inventory-scanner-v2", labelKey: "HSM Deep Inventory Scanner v2", icon: "⚿" },
    { to: "/network-crypto-posture-enforcer", labelKey: "Network Crypto Posture Enforcer JA3", icon: "⌬" },
    { to: "/evidence-lake-query-engine", labelKey: "Evidence Lake Query Engine WORM", icon: "▤" },
    { to: "/api-security-posture-enforcer", labelKey: "API Security Posture Enforcer OWASP", icon: "◫" },
    { to: "/cloud-kms-inventory-enhanced", labelKey: "Cloud KMS Inventory Enhanced AWS Azure", icon: "☁" },
    { to: "/secrets-rotation-automation-engine", labelKey: "Secrets Rotation Automation 90d 30d", icon: "↻" },
    { to: "/cert-pinning-validator-enhanced", labelKey: "Cert Pinning Validator Enhanced HPKP", icon: "⊞" },
    { to: "/pqc-tls-analyzer-enhanced", labelKey: "PQC TLS Analyzer Enhanced ML-KEM", icon: "◫" },
    { to: "/supply-chain-attestation-verifier", labelKey: "Supply Chain Attestation Verifier SLSA", icon: "⬡" },
  ]},
  { sectionKey: "Real-Time System — Live", items: [
    { to: "/realtime-system", labelKey: "Real-Time System Central Hub 100K+ p99<500ms", icon: "◉" },
  ]},
  { sectionKey: "Cryptographic Digital Twin — Live Replica Flight Simulator", items: [
    { to: "/cryptographic-digital-twin", labelKey: "Cryptographic Digital Twin Live Replica", icon: "◈" },
    { to: "/twin-mirror-ingestion", labelKey: "Twin Mirror Ingestion Read-Only One-Way", icon: "⇉" },
    { to: "/twin-state-store", labelKey: "Twin State Store Isolated Never Touches Prod", icon: "▤" },
    { to: "/twin-entity-model", labelKey: "Twin Entity Model CryptoAsset System Endpoint", icon: "⬢" },
    { to: "/twin-relationship-model", labelKey: "Twin Relationship Model Graph USES CALLS", icon: "⬟" },
    { to: "/twin-behavioral-model", labelKey: "Twin Behavioral Model Traffic Baselines", icon: "◷" },
    { to: "/twin-temporal-model", labelKey: "Twin Temporal Model Snapshot Change Log Time-Travel", icon: "◷" },
    { to: "/twin-simulation-engine", labelKey: "Twin Simulation Engine Deterministic Cloner", icon: "◈" },
    { to: "/twin-scenario-types", labelKey: "Twin Scenario Types 10 Types Migration Policy Attack", icon: "◈" },
    { to: "/twin-analysis-output", labelKey: "Twin Analysis Output Impact Blast Radius Timeline", icon: "▦" },
    { to: "/twin-isolation-guardrails", labelKey: "Twin Isolation Guardrails Network Data Code Audit", icon: "⛨" },
    { to: "/twin-time-travel", labelKey: "Twin Time-Travel Snapshot Restore Comparison Diff", icon: "◷" },
    { to: "/twin-api", labelKey: "Twin API Management Simulation Scenario Templates", icon: "◫" },
  ]},
  { sectionKey: "Beat QSE — 20 Next", items: [
    { to: "/secrets-detection", labelKey: "Secrets Detection 150+", icon: "⚿" },
    { to: "/dependency-risk", labelKey: "Dependency Risk Blast Radius", icon: "⬟" },
    { to: "/remediation-orchestrator", labelKey: "Remediation Orchestrator", icon: "⚙" },
    { to: "/threat-intel", labelKey: "Threat Intel STIX/TAXII", icon: "◈" },
    { to: "/zero-trust-crypto", labelKey: "Zero-Trust Crypto", icon: "⛨" },
    { to: "/compliance-mapping", labelKey: "Compliance Mapping v2", icon: "✓" },
    { to: "/data-classification", labelKey: "Data Classification PII/PHI", icon: "⚖" },
    { to: "/blockchain-crypto", labelKey: "Blockchain/Web3 Crypto", icon: "⬢" },
    { to: "/iot-ot-crypto", labelKey: "IoT/OT Crypto Deep Scan", icon: "⌬" },
    { to: "/ai-ml-crypto-guard", labelKey: "AI/ML Model Crypto Guard", icon: "◔" },
    { to: "/runtime-crypto-ebpf", labelKey: "Runtime eBPF Telemetry", icon: "⇄" },
    { to: "/slsa-attestation-verifier", labelKey: "SLSA Attestation Sigstore", icon: "⛨" },
    { to: "/pq-migration-cost", labelKey: "PQ Migration Cost Calculator", icon: "⇉" },
    { to: "/drift-anomaly", labelKey: "Drift & Anomaly Detection", icon: "≋" },
    { to: "/risk-quantification", labelKey: "Risk Quant FAIR $", icon: "⚠" },
    { to: "/tenant-isolation-validator", labelKey: "Tenant Isolation Validator", icon: "⛓" },
    { to: "/secure-code-review", labelKey: "Secure Code Review 20 Lang", icon: "⌕" },
    { to: "/hsm-deep-inventory", labelKey: "HSM Deep Inventory FIPS 140-3", icon: "⌬" },
    { to: "/network-crypto-analyzer", labelKey: "Network Crypto JA3/JARM", icon: "◈" },
    { to: "/evidence-lake", labelKey: "Evidence Lake WORM 7y", icon: "⛨" },
    { to: "/api-security-posture", labelKey: "API Security Posture OWASP", icon: "⌖" },
    { to: "/cloud-kms-inventory", labelKey: "Cloud KMS Inventory", icon: "⚿" },
    { to: "/secrets-rotation-automation", labelKey: "Secrets Rotation 90d", icon: "◔" },
    { to: "/certificate-pinning-validator", labelKey: "Cert Pinning Validator", icon: "⊞" },
    { to: "/pqc-tls-analyzer", labelKey: "PQC TLS Analyzer", icon: "◬" },
    { to: "/supply-chain-attestation", labelKey: "Supply Chain Attestation", icon: "⛨" },
    { to: "/runtime-secret-leak-detector", labelKey: "Runtime Secret Leak eBPF", icon: "⇄" },
    { to: "/crypto-agility-score-v2", labelKey: "Crypto Agility Score v2", icon: "◔" },
    { to: "/compliance-drift-detector", labelKey: "Compliance Drift Detector", icon: "≋" },
    { to: "/executive-dashboard", labelKey: "Executive Dashboard FAIR", icon: "▦" },
    { to: "/deterministic-policy-enforcement", labelKey: "Policy Enforcement OPA/Rego 100+", icon: "⚖" },
    { to: "/crypto-agility-maturity", labelKey: "Crypto Agility Maturity 5 Levels", icon: "◔" },
    { to: "/quantum-threat-timeline", labelKey: "Quantum Threat Timeline NIST NSA", icon: "◬" },
    { to: "/hndl-risk-calculator", labelKey: "HNDL Risk Calculator", icon: "⚠" },
    { to: "/pqc-migration-playbook", labelKey: "PQC Migration Playbook Generator", icon: "⇉" },
    { to: "/crypto-inventory-health", labelKey: "Crypto Inventory Health Score", icon: "◔" },
    { to: "/compliance-evidence-graph", labelKey: "Compliance Evidence Graph Neo4j", icon: "⬟" },
    { to: "/remediation-verification", labelKey: "Remediation Verification", icon: "✓" },
    { to: "/crypto-drift-timeline", labelKey: "Crypto Drift Timeline", icon: "◷" },
    { to: "/executive-risk-heatmap", labelKey: "Executive Risk Heatmap", icon: "▦" },
    { to: "/third-party-crypto-risk", labelKey: "Third-Party Crypto Risk", icon: "⚠" },
    { to: "/cloud-crypto-posture", labelKey: "Cloud Crypto Posture CSPM", icon: "☁" },
    { to: "/kubernetes-crypto-security", labelKey: "K8s Crypto Security", icon: "⧉" },
    { to: "/cicd-crypto-gate", labelKey: "CI/CD Crypto Gate", icon: "⛀" },
    { to: "/secrets-management-integration", labelKey: "Secrets Management Integration", icon: "⚿" },
    { to: "/certificate-transparency-v2", labelKey: "CT v2 Enhanced 50+ Logs", icon: "⊞" },
    { to: "/pqc-readiness-dashboard", labelKey: "PQC Readiness Dashboard", icon: "◬" },
    { to: "/crypto-policy-drift", labelKey: "Crypto Policy Drift", icon: "≋" },
    { to: "/automated-evidence-collection", labelKey: "Automated Evidence Collection WORM", icon: "⛨" },
    { to: "/threat-model-automation", labelKey: "Threat Model STRIDE LINDDUN PASTA", icon: "⚠" },
    { to: "/correlation-engine", labelKey: "Correlation Engine 8 Types", icon: "⬟" },
    { to: "/behavioral-baselines", labelKey: "Behavioral Baselines Statistical", icon: "≋" },
    { to: "/risk-scoring-engine", labelKey: "Risk Scoring Engine Explainable", icon: "⚠" },
    { to: "/cross-standard-compliance", labelKey: "Cross-Standard Compliance", icon: "✓" },
    { to: "/live-cbom-v2", labelKey: "Live CBOM v2 VEX-Enabled", icon: "⬡" },
    { to: "/attack-path-analysis", labelKey: "Attack Path Analysis Graph", icon: "⬟" },
    { to: "/data-sovereignty", labelKey: "Data Sovereignty Multi-Region", icon: "◫" },
    { to: "/certification-pipeline", labelKey: "Certification Pipeline SOC2 ISO", icon: "✓" },
    { to: "/key-custody-splitting", labelKey: "Key Custody Shamir/MPC", icon: "⚿" },
    { to: "/timeseries-analytics", labelKey: "Time-Series Analytics Statistical", icon: "◷" },
    { to: "/quantum-key-distribution-monitor", labelKey: "QKD Monitor BB84 E91", icon: "◔" },
    { to: "/post-quantum-hsm-integration", labelKey: "PQ HSM Integration ML-KEM/ML-DSA", icon: "⌬" },
    { to: "/crypto-bill-of-materials-enhanced", labelKey: "CBOM 2.0 Enhanced CycloneDX 1.6", icon: "⬡" },
    { to: "/secure-multiparty-computation-validator", labelKey: "MPC Validator BGW/GMW/Yao", icon: "⛨" },
    { to: "/homomorphic-encryption-analyzer", labelKey: "FHE Analyzer BFV/BGV/CKKS/TFHE", icon: "◔" },
    { to: "/differential-privacy-validator", labelKey: "Differential Privacy epsilon/delta", icon: "⚖" },
    { to: "/confidential-data-flow-tracker", labelKey: "Confidential Data Flow Taint", icon: "⇄" },
    { to: "/crypto-asset-lineage-tracker", labelKey: "Crypto Asset Lineage Provenance", icon: "⬟" },
    { to: "/automated-pqc-migration-executor", labelKey: "Automated PQC Migration Executor", icon: "⇉" },
    { to: "/continuous-assurance-monitor", labelKey: "Continuous Assurance 100K+/sec", icon: "◉" },
    { to: "/confidential-computing-validator", labelKey: "Confidential Computing SGX/SEV/TDX", icon: "⛨" },
    { to: "/post-quantum-code-signing", labelKey: "PQ Code Signing ML-DSA SLH-DSA", icon: "⛨" },
    { to: "/crypto-inventory-reconciliation", labelKey: "Crypto Inventory Reconciliation", icon: "⬡" },
    { to: "/automated-compliance-reporting", labelKey: "Automated Compliance Reporting", icon: "✓" },
    { to: "/threat-modeling-engine", labelKey: "Threat Modeling STRIDE/LINDDUN", icon: "⚠" },
    { to: "/key-ceremony-orchestrator", labelKey: "Key Ceremony M-of-N", icon: "⚿" },
    { to: "/secure-boot-attestation", labelKey: "Secure Boot Attestation PCR", icon: "⛨" },
    { to: "/tls-configuration-hardening", labelKey: "TLS Config Hardening", icon: "◈" },
    { to: "/crypto-policy-enforcement", labelKey: "Crypto Policy Enforcement", icon: "⚖" },
    { to: "/audit-log-analytics", labelKey: "Audit Log Analytics Merkle", icon: "⛨" },
    { to: "/ot-enhanced", labelKey: "OT Enhanced", icon: "⌬" },
    { to: "/compliance-deterministic", labelKey: "Compliance Deterministic", icon: "✓" },
    { to: "/evidence-chain-enhanced", labelKey: "Evidence Chain", icon: "⛨" },
    { to: "/exceptions-enhanced", labelKey: "Exceptions CISO", icon: "⚖" },
  ]},
];

export default function Layout({ route, children }: { route: string; children: React.ReactNode }) {
  const { t, dir } = useI18n();
  const [showSearch, setShowSearch] = useState(false);
  const [theme, setTheme] = useState<string>(() => {
    try { return localStorage.getItem("zelnx-theme") || "dark"; } catch { return "dark"; }
  });
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "light") root.setAttribute("data-theme", "light");
    else root.removeAttribute("data-theme");
    try { localStorage.setItem("zelnx-theme", theme); } catch { /* ignore */ }
  }, [theme]);
  const [abac, setAbac] = useState<{ enforced: boolean; grants: number } | null>(null);
  const ticker = useLiveTicker();
  const toasts = useAlertToasts();
  const liveStats = usePollingApi(apiStatsSummary, 20000, []);
  const st = ((ticker.connected || liveStats.source === "live") ? liveStats.data : null) as Record<string, number> | null;

  useEffect(() => {
    if (!getToken()) { setAbac(null); return; }
    let alive = true;
    const load = () => apiMyGrants().then((r) => {
      if (alive && r.source === "live" && r.data) {
        setAbac({ enforced: !!r.data.abac_enforced, grants: r.data.count ?? r.data.grants?.length ?? 0 });
      }
    }).catch(() => {});
    void load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, [ticker.connected]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <a href="#/" className="logo" style={{ display: "flex", alignItems: "center", gap: 11, fontWeight: 700, fontSize: 18, letterSpacing: "0.02em", margin: "2px 8px 12px" }}>
          <span className="mark" style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "var(--grad)", color: "#04121d", fontSize: 18, boxShadow: "var(--glow-cyan)" }}>◈</span>
          <span>ZELNX<span style={{ color: "var(--faint)", fontWeight: 500, fontSize: 10, marginLeft: 8, letterSpacing: "0.16em" }}>CRYPTO INTELLIGENCE</span></span>
        </a>
        {NAV.map((group) => (
          <React.Fragment key={group.sectionKey}>
            <div className="nav-label">{t(group.sectionKey)}</div>
            {group.items.map((item) => (
              <a key={item.to} href={`#${item.to}`} className={`nav ${route === item.to ? "active" : ""}`}>
                <span className="nav-icon">{item.icon}</span>
                {t(item.labelKey)}
              </a>
            ))}
          </React.Fragment>
        ))}
        <div style={{ marginTop: 20, padding: "0 8px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: dir === "rtl" ? "flex-end" : "flex-start", gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 11, color: "var(--faint)", letterSpacing: "0.08em" }}>{t("lang.label").toUpperCase()}</span>
            <LanguageSwitcher />
          </div>
          <div className="demobanner" style={{
            color: ticker.backend ? "var(--green)" : "var(--amber)",
            borderColor: ticker.backend ? "rgba(34,197,94,0.35)" : undefined,
            background: ticker.backend ? "rgba(34,197,94,0.07)" : undefined,
          }}>
            <span className="dot" style={{ background: ticker.backend ? "var(--green)" : "var(--amber)" }} />
            <span>
              {ticker.backend === null
                ? t("app.banner.connecting")
                : ticker.backend
                  ? t("app.banner.live")
                  : t("app.banner.offline")}
            </span>
          </div>
          <div style={{ marginTop: 10, padding: "0 8px", fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)", lineHeight: 1.7 }}>
            v1.0 · {t("app.footer")}<br />{t("app.footer2")}
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="livehead">
          {(() => {
            const conn = ticker.conn ?? (ticker.connected ? "live" : "offline");
            const map: Record<string, { c: string; label: string; pulse: boolean }> = {
              live: { c: "var(--green)", label: t("common.live"), pulse: true },
              connecting: { c: "var(--cyan)", label: t("common.connecting"), pulse: true },
              stalled: { c: "var(--amber)", label: t("common.reconnecting"), pulse: true },
              offline: { c: "var(--slate)", label: t("common.idle"), pulse: false },
            };
            const s = map[conn] ?? map.offline;
            return (
              <>
                <span className="live-dot" style={{ background: s.c, boxShadow: `0 0 12px ${s.c}`, animation: s.pulse ? undefined : "none" }} />
                <span className="item"><b style={{ color: s.c }}>{s.label}</b></span>
              </>
            );
          })()}
          <span className="item">{t("head.lastEvent")} <b>{ticker.ago === null ? "—" : `${ticker.ago}s`}</b> {t("head.ago")}</span>
          <span className="item">{t("head.eventsPerSec")} <b>{ticker.eps || "—"}</b></span>
          {ticker.connected ? (
            <span className="item">{t("head.streamSubs")} <b>{ticker.subscribers}</b></span>
          ) : (
            <span className="item">{t("head.agents")} <b>{Number(st?.agents_healthy ?? 0)}/{Number(st?.agents_total ?? 0)}</b> {t("head.healthy")}</span>
          )}
          <span className="item">{t("head.scanners")} <b>{Number(st?.active_scanners ?? 0)}/{Number(st?.total_scanners ?? 0)}</b></span>
          <span className="item">{t("head.scans")} <b>{Number(st?.total_scans ?? 0)}</b></span>
          <span className="item">{t("head.findings")} <b>{Number(st?.total_findings ?? 0)}</b></span>
          {abac && (
            <span className="item" title={t("head.abac")}>
              ABAC <b style={{ color: abac.enforced ? "var(--green)" : "var(--amber)" }}>
                {abac.enforced ? `${abac.grants} grants` : "off"}
              </b>
            </span>
          )}
          <div className="searchbox" onClick={() => setShowSearch(true)}>
            <span>⌕</span> {t("common.search")}
            <span style={{ marginLeft: "auto", fontSize: 10, border: "1px solid var(--line-strong)", borderRadius: 4, padding: "1px 6px" }}>esc</span>
          </div>
          <button
            className="btn sm"
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            onClick={() => setTheme((x) => (x === "dark" ? "light" : "dark"))}
            style={{ fontFamily: "var(--mono)" }}
          >
            {theme === "dark" ? "☾ dark" : "☀ light"}
          </button>
          {getToken() ? (
            <button
              className="btn sm"
              title={t("common.signOut")}
              onClick={() => { setToken(null); window.location.hash = "#/"; }}
            >
              {getUserName() || "user"} · {t("common.signOut")}
            </button>
          ) : (
            <a href="#/login" className="btn sm">{t("common.signIn")}</a>
          )}
        </div>
        {children}
      </main>

      {showSearch && <SearchOverlay onClose={() => setShowSearch(false)} />}
      <Toasts toasts={toasts} />
    </div>
  );
}
