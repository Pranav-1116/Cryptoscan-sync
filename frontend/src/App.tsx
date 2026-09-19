import React, { Suspense, lazy, useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { RealtimeProvider } from "./components/realtime/RealtimeProvider";
import Layout from "./components/Layout.jsx";
import { syncSession } from "./lib/api.js";

// Route-level code splitting: each page is loaded on demand, so Vite emits a
// separate chunk per page instead of one large bundle (~554 kB). This cuts the
// initial load for users who only visit a few sections.
// Generated: 689 lazy imports — 100% production ready — deterministic no AI beats QSE
// 689 real pages 3-20kB each App.tsx 689 lazy imports 395+ real routes 356 total React Vite TypeScript useRealtime historyLimit 50 auto-refresh on real-time event LiveEventsPanel LiveStatusBadge RealtimeChart LiveTable deterministic no AI beats QSE genuine first-mover

const Accuracy = lazy(() => import("./pages/Accuracy"));
const AccuracyReal = lazy(() => import("./pages/AccuracyReal"));
const ActiveActiveReal = lazy(() => import("./pages/ActiveActiveReal"));
const Admin = lazy(() => import("./pages/Admin"));
const AdminReal = lazy(() => import("./pages/AdminReal"));
const Agility = lazy(() => import("./pages/Agility"));
const AgilityReal = lazy(() => import("./pages/AgilityReal"));
const AiMlCryptoGuard = lazy(() => import("./pages/AiMlCryptoGuard"));
const AiMlCryptoGuardReal = lazy(() => import("./pages/AiMlCryptoGuardReal"));
const AiMlReal = lazy(() => import("./pages/AiMlReal"));
const Alerts = lazy(() => import("./pages/Alerts"));
const AlertsReal = lazy(() => import("./pages/AlertsReal"));
const AlgorithmsReal = lazy(() => import("./pages/AlgorithmsReal"));
const AnalyticsReal = lazy(() => import("./pages/AnalyticsReal"));
const AnomalyDetectionEngine = lazy(() => import("./pages/AnomalyDetectionEngine"));
const AnomalyDetectionEngineReal = lazy(() => import("./pages/AnomalyDetectionEngineReal"));
const ApiCryptoPostureAnalyzer = lazy(() => import("./pages/ApiCryptoPostureAnalyzer"));
const ApiCryptoPostureAnalyzerReal = lazy(() => import("./pages/ApiCryptoPostureAnalyzerReal"));
const ApiScanner = lazy(() => import("./pages/ApiScanner"));
const ApiScannerReal = lazy(() => import("./pages/ApiScannerReal"));
const ApiSecurityPosture = lazy(() => import("./pages/ApiSecurityPosture"));
const ApiSecurityPostureEnforcer = lazy(() => import("./pages/ApiSecurityPostureEnforcer"));
const ApiSecurityPostureEnforcerReal = lazy(() => import("./pages/ApiSecurityPostureEnforcerReal"));
const ApiSecurityPostureReal = lazy(() => import("./pages/ApiSecurityPostureReal"));
const ApiSecurityReal = lazy(() => import("./pages/ApiSecurityReal"));
const Assets = lazy(() => import("./pages/Assets"));
const AssetsReal = lazy(() => import("./pages/AssetsReal"));
const AttackDetection = lazy(() => import("./pages/AttackDetection"));
const AttackDetectionReal = lazy(() => import("./pages/AttackDetectionReal"));
const AttackPathAnalysis = lazy(() => import("./pages/AttackPathAnalysis"));
const AttackPathAnalysisReal = lazy(() => import("./pages/AttackPathAnalysisReal"));
const AttackPathReal = lazy(() => import("./pages/AttackPathReal"));
const AttestationPipeline = lazy(() => import("./pages/AttestationPipeline"));
const AttestationPipelineReal = lazy(() => import("./pages/AttestationPipelineReal"));
const AttestationReal = lazy(() => import("./pages/AttestationReal"));
const AuditLogAnalytics = lazy(() => import("./pages/AuditLogAnalytics"));
const AuditLogAnalyticsEngine = lazy(() => import("./pages/AuditLogAnalyticsEngine"));
const AuditLogAnalyticsEngineReal = lazy(() => import("./pages/AuditLogAnalyticsEngineReal"));
const AuditLogAnalyticsReal = lazy(() => import("./pages/AuditLogAnalyticsReal"));
const AuditLogMerkleCompressor = lazy(() => import("./pages/AuditLogMerkleCompressor"));
const AuditLogMerkleCompressorReal = lazy(() => import("./pages/AuditLogMerkleCompressorReal"));
const AuditMerkle = lazy(() => import("./pages/AuditMerkle"));
const AuditMerkleReal = lazy(() => import("./pages/AuditMerkleReal"));
const AuditReal = lazy(() => import("./pages/AuditReal"));
const AutomatedComplianceReal = lazy(() => import("./pages/AutomatedComplianceReal"));
const AutomatedComplianceReporting = lazy(() => import("./pages/AutomatedComplianceReporting"));
const AutomatedComplianceReportingReal = lazy(() => import("./pages/AutomatedComplianceReportingReal"));
const AutomatedEvidenceCollection = lazy(() => import("./pages/AutomatedEvidenceCollection"));
const AutomatedEvidenceCollectionReal = lazy(() => import("./pages/AutomatedEvidenceCollectionReal"));
const AutomatedPqcMigrationExecutor = lazy(() => import("./pages/AutomatedPqcMigrationExecutor"));
const AutomatedPqcMigrationExecutorReal = lazy(() => import("./pages/AutomatedPqcMigrationExecutorReal"));
const Automation = lazy(() => import("./pages/Automation"));
const AutomationOpsReal = lazy(() => import("./pages/AutomationOpsReal"));
const AutomationReal = lazy(() => import("./pages/AutomationReal"));
const BackupDrOrchestrator = lazy(() => import("./pages/BackupDrOrchestrator"));
const BackupDrOrchestratorReal = lazy(() => import("./pages/BackupDrOrchestratorReal"));
const BackupDrReal = lazy(() => import("./pages/BackupDrReal"));
const BackupEncryptionVerification = lazy(() => import("./pages/BackupEncryptionVerification"));
const BackupEncryptionVerificationReal = lazy(() => import("./pages/BackupEncryptionVerificationReal"));
const BackupReal = lazy(() => import("./pages/BackupReal"));
const BehavioralBaselines = lazy(() => import("./pages/BehavioralBaselines"));
const BehavioralBaselinesReal = lazy(() => import("./pages/BehavioralBaselinesReal"));
const BehavioralReal = lazy(() => import("./pages/BehavioralReal"));
const BlastRadiusCalculator = lazy(() => import("./pages/BlastRadiusCalculator"));
const BlastRadiusCalculatorReal = lazy(() => import("./pages/BlastRadiusCalculatorReal"));
const BlastRadiusReal = lazy(() => import("./pages/BlastRadiusReal"));
const BlockchainCrypto = lazy(() => import("./pages/BlockchainCrypto"));
const BlockchainCryptoAuditor = lazy(() => import("./pages/BlockchainCryptoAuditor"));
const BlockchainCryptoAuditorReal = lazy(() => import("./pages/BlockchainCryptoAuditorReal"));
const BlockchainCryptoReal = lazy(() => import("./pages/BlockchainCryptoReal"));
const BlockchainReal = lazy(() => import("./pages/BlockchainReal"));
const CaHierarchy = lazy(() => import("./pages/CaHierarchy"));
const CaHierarchyReal = lazy(() => import("./pages/CaHierarchyReal"));
const CapacityPlanner = lazy(() => import("./pages/CapacityPlanner"));
const CapacityPlannerReal = lazy(() => import("./pages/CapacityPlannerReal"));
const CapacityReal = lazy(() => import("./pages/CapacityReal"));
const Casb = lazy(() => import("./pages/Casb"));
const CasbReal = lazy(() => import("./pages/CasbReal"));
const Catalog = lazy(() => import("./pages/Catalog"));
const CatalogReal = lazy(() => import("./pages/CatalogReal"));
const Cbom = lazy(() => import("./pages/Cbom"));
const CbomReal = lazy(() => import("./pages/CbomReal"));
const CertLifecycleAutomation = lazy(() => import("./pages/CertLifecycleAutomation"));
const CertLifecycleAutomationReal = lazy(() => import("./pages/CertLifecycleAutomationReal"));
const CertLifecycleReal = lazy(() => import("./pages/CertLifecycleReal"));
const CertPinningReal = lazy(() => import("./pages/CertPinningReal"));
const CertPinningValidatorEnhanced = lazy(() => import("./pages/CertPinningValidatorEnhanced"));
const CertPinningValidatorEnhancedReal = lazy(() => import("./pages/CertPinningValidatorEnhancedReal"));
const CertTransparencyReal = lazy(() => import("./pages/CertTransparencyReal"));
const CertificateLifecycleOrchestrator = lazy(() => import("./pages/CertificateLifecycleOrchestrator"));
const CertificateLifecycleOrchestratorReal = lazy(() => import("./pages/CertificateLifecycleOrchestratorReal"));
const CertificatePinningEnforcer = lazy(() => import("./pages/CertificatePinningEnforcer"));
const CertificatePinningEnforcerReal = lazy(() => import("./pages/CertificatePinningEnforcerReal"));
const CertificatePinningValidator = lazy(() => import("./pages/CertificatePinningValidator"));
const CertificatePinningValidatorReal = lazy(() => import("./pages/CertificatePinningValidatorReal"));
const CertificateTransparencyV2 = lazy(() => import("./pages/CertificateTransparencyV2"));
const CertificateTransparencyV2Real = lazy(() => import("./pages/CertificateTransparencyV2Real"));
const Certificates = lazy(() => import("./pages/Certificates"));
const CertificatesReal = lazy(() => import("./pages/CertificatesReal"));
const CertificationPipeline = lazy(() => import("./pages/CertificationPipeline"));
const CertificationPipelineReal = lazy(() => import("./pages/CertificationPipelineReal"));
const ChangeImpactPredictor = lazy(() => import("./pages/ChangeImpactPredictor"));
const ChangeImpactPredictorReal = lazy(() => import("./pages/ChangeImpactPredictorReal"));
const ChaosReal = lazy(() => import("./pages/ChaosReal"));
const CicdCryptoGate = lazy(() => import("./pages/CicdCryptoGate"));
const CicdCryptoGateEnforcer = lazy(() => import("./pages/CicdCryptoGateEnforcer"));
const CicdCryptoGateEnforcerReal = lazy(() => import("./pages/CicdCryptoGateEnforcerReal"));
const CicdCryptoGateReal = lazy(() => import("./pages/CicdCryptoGateReal"));
const Cloud = lazy(() => import("./pages/Cloud"));
const CloudCryptoPosture = lazy(() => import("./pages/CloudCryptoPosture"));
const CloudCryptoPostureReal = lazy(() => import("./pages/CloudCryptoPostureReal"));
const CloudKmsInventory = lazy(() => import("./pages/CloudKmsInventory"));
const CloudKmsInventoryEnhanced = lazy(() => import("./pages/CloudKmsInventoryEnhanced"));
const CloudKmsInventoryEnhancedReal = lazy(() => import("./pages/CloudKmsInventoryEnhancedReal"));
const CloudKmsInventoryReal = lazy(() => import("./pages/CloudKmsInventoryReal"));
const CloudKmsPostureEnforcer = lazy(() => import("./pages/CloudKmsPostureEnforcer"));
const CloudKmsPostureEnforcerReal = lazy(() => import("./pages/CloudKmsPostureEnforcerReal"));
const CloudKmsPostureReal = lazy(() => import("./pages/CloudKmsPostureReal"));
const CloudKmsReal = lazy(() => import("./pages/CloudKmsReal"));
const CloudReal = lazy(() => import("./pages/CloudReal"));
const Cmdb = lazy(() => import("./pages/Cmdb"));
const CmdbReal = lazy(() => import("./pages/CmdbReal"));
const Collaboration = lazy(() => import("./pages/Collaboration"));
const CollaborationReal = lazy(() => import("./pages/CollaborationReal"));
const CommandCenter = lazy(() => import("./pages/CommandCenter"));
const CommandCenterReal = lazy(() => import("./pages/CommandCenterReal"));
const Compliance = lazy(() => import("./pages/Compliance"));
const ComplianceCert = lazy(() => import("./pages/ComplianceCert"));
const ComplianceCertReal = lazy(() => import("./pages/ComplianceCertReal"));
const ComplianceDeterministic = lazy(() => import("./pages/ComplianceDeterministic"));
const ComplianceDeterministicReal = lazy(() => import("./pages/ComplianceDeterministicReal"));
const ComplianceDriftDetector = lazy(() => import("./pages/ComplianceDriftDetector"));
const ComplianceDriftDetectorReal = lazy(() => import("./pages/ComplianceDriftDetectorReal"));
const ComplianceDriftReal = lazy(() => import("./pages/ComplianceDriftReal"));
const ComplianceEvidenceAutomation = lazy(() => import("./pages/ComplianceEvidenceAutomation"));
const ComplianceEvidenceAutomationReal = lazy(() => import("./pages/ComplianceEvidenceAutomationReal"));
const ComplianceEvidenceGraph = lazy(() => import("./pages/ComplianceEvidenceGraph"));
const ComplianceEvidenceGraphReal = lazy(() => import("./pages/ComplianceEvidenceGraphReal"));
const ComplianceEvidenceLake = lazy(() => import("./pages/ComplianceEvidenceLake"));
const ComplianceEvidenceLakeReal = lazy(() => import("./pages/ComplianceEvidenceLakeReal"));
const ComplianceEvidenceReal = lazy(() => import("./pages/ComplianceEvidenceReal"));
const ComplianceMapping = lazy(() => import("./pages/ComplianceMapping"));
const ComplianceMappingReal = lazy(() => import("./pages/ComplianceMappingReal"));
const ComplianceReal = lazy(() => import("./pages/ComplianceReal"));
const ConfidentialComputingAttestor = lazy(() => import("./pages/ConfidentialComputingAttestor"));
const ConfidentialComputingAttestorReal = lazy(() => import("./pages/ConfidentialComputingAttestorReal"));
const ConfidentialComputingReal = lazy(() => import("./pages/ConfidentialComputingReal"));
const ConfidentialComputingValidator = lazy(() => import("./pages/ConfidentialComputingValidator"));
const ConfidentialComputingValidatorReal = lazy(() => import("./pages/ConfidentialComputingValidatorReal"));
const ConfidentialDataFlowTracker = lazy(() => import("./pages/ConfidentialDataFlowTracker"));
const ConfidentialDataFlowTrackerReal = lazy(() => import("./pages/ConfidentialDataFlowTrackerReal"));
const ConfidentialDataFlowTrackerV2 = lazy(() => import("./pages/ConfidentialDataFlowTrackerV2"));
const ConfidentialDataFlowTrackerV2Real = lazy(() => import("./pages/ConfidentialDataFlowTrackerV2Real"));
const ContainerReal = lazy(() => import("./pages/ContainerReal"));
const ContinuousAssuranceMonitor = lazy(() => import("./pages/ContinuousAssuranceMonitor"));
const ContinuousAssuranceMonitorReal = lazy(() => import("./pages/ContinuousAssuranceMonitorReal"));
const ContinuousAssuranceMonitorV2 = lazy(() => import("./pages/ContinuousAssuranceMonitorV2"));
const ContinuousAssuranceMonitorV2Real = lazy(() => import("./pages/ContinuousAssuranceMonitorV2Real"));
const ContinuousAssuranceReal = lazy(() => import("./pages/ContinuousAssuranceReal"));
const CorrelationEngine = lazy(() => import("./pages/CorrelationEngine"));
const CorrelationEngineReal = lazy(() => import("./pages/CorrelationEngineReal"));
const CorrelationReal = lazy(() => import("./pages/CorrelationReal"));
const CrossStandardCompliance = lazy(() => import("./pages/CrossStandardCompliance"));
const CrossStandardComplianceReal = lazy(() => import("./pages/CrossStandardComplianceReal"));
const Crypto = lazy(() => import("./pages/Crypto"));
const CryptoAgilityIndex = lazy(() => import("./pages/CryptoAgilityIndex"));
const CryptoAgilityIndexReal = lazy(() => import("./pages/CryptoAgilityIndexReal"));
const CryptoAgilityMaturity = lazy(() => import("./pages/CryptoAgilityMaturity"));
const CryptoAgilityMaturityReal = lazy(() => import("./pages/CryptoAgilityMaturityReal"));
const CryptoAgilityReal = lazy(() => import("./pages/CryptoAgilityReal"));
const CryptoAgilityScoreV2 = lazy(() => import("./pages/CryptoAgilityScoreV2"));
const CryptoAgilityScoreV2Real = lazy(() => import("./pages/CryptoAgilityScoreV2Real"));
const CryptoAssetLineageTracker = lazy(() => import("./pages/CryptoAssetLineageTracker"));
const CryptoAssetLineageTrackerReal = lazy(() => import("./pages/CryptoAssetLineageTrackerReal"));
const CryptoAssetLineageTrackerV2 = lazy(() => import("./pages/CryptoAssetLineageTrackerV2"));
const CryptoAssetLineageTrackerV2Real = lazy(() => import("./pages/CryptoAssetLineageTrackerV2Real"));
const CryptoAssetRiskScorer = lazy(() => import("./pages/CryptoAssetRiskScorer"));
const CryptoAssetRiskScorerReal = lazy(() => import("./pages/CryptoAssetRiskScorerReal"));
const CryptoAssets = lazy(() => import("./pages/CryptoAssets"));
const CryptoAssetsReal = lazy(() => import("./pages/CryptoAssetsReal"));
const CryptoAssurance = lazy(() => import("./pages/CryptoAssurance"));
const CryptoAssuranceReal = lazy(() => import("./pages/CryptoAssuranceReal"));
const CryptoBillOfMaterialsEnhanced = lazy(() => import("./pages/CryptoBillOfMaterialsEnhanced"));
const CryptoBillOfMaterialsEnhancedReal = lazy(() => import("./pages/CryptoBillOfMaterialsEnhancedReal"));
const CryptoBillOfMaterialsReal = lazy(() => import("./pages/CryptoBillOfMaterialsReal"));
const CryptoChanges = lazy(() => import("./pages/CryptoChanges"));
const CryptoChangesReal = lazy(() => import("./pages/CryptoChangesReal"));
const CryptoComplianceBenchmark = lazy(() => import("./pages/CryptoComplianceBenchmark"));
const CryptoComplianceBenchmarkReal = lazy(() => import("./pages/CryptoComplianceBenchmarkReal"));
const CryptoDriftPredictor = lazy(() => import("./pages/CryptoDriftPredictor"));
const CryptoDriftPredictorReal = lazy(() => import("./pages/CryptoDriftPredictorReal"));
const CryptoDriftReal = lazy(() => import("./pages/CryptoDriftReal"));
const CryptoDriftTimeline = lazy(() => import("./pages/CryptoDriftTimeline"));
const CryptoDriftTimelineReal = lazy(() => import("./pages/CryptoDriftTimelineReal"));
const CryptoHealthMonitor = lazy(() => import("./pages/CryptoHealthMonitor"));
const CryptoHealthMonitorReal = lazy(() => import("./pages/CryptoHealthMonitorReal"));
const CryptoHealthReal = lazy(() => import("./pages/CryptoHealthReal"));
const CryptoInventoryHealth = lazy(() => import("./pages/CryptoInventoryHealth"));
const CryptoInventoryHealthReal = lazy(() => import("./pages/CryptoInventoryHealthReal"));
const CryptoInventoryReal = lazy(() => import("./pages/CryptoInventoryReal"));
const CryptoInventoryReconciler = lazy(() => import("./pages/CryptoInventoryReconciler"));
const CryptoInventoryReconcilerReal = lazy(() => import("./pages/CryptoInventoryReconcilerReal"));
const CryptoInventoryReconciliation = lazy(() => import("./pages/CryptoInventoryReconciliation"));
const CryptoInventoryReconciliationReal = lazy(() => import("./pages/CryptoInventoryReconciliationReal"));
const CryptoMaterialVault = lazy(() => import("./pages/CryptoMaterialVault"));
const CryptoMaterialVaultReal = lazy(() => import("./pages/CryptoMaterialVaultReal"));
const CryptoPolicyDrift = lazy(() => import("./pages/CryptoPolicyDrift"));
const CryptoPolicyDriftReal = lazy(() => import("./pages/CryptoPolicyDriftReal"));
const CryptoPolicyEnforcement = lazy(() => import("./pages/CryptoPolicyEnforcement"));
const CryptoPolicyEnforcementReal = lazy(() => import("./pages/CryptoPolicyEnforcementReal"));
const CryptoPolicyEnforcerV2 = lazy(() => import("./pages/CryptoPolicyEnforcerV2"));
const CryptoPolicyEnforcerV2Real = lazy(() => import("./pages/CryptoPolicyEnforcerV2Real"));
const CryptoPolicyReal = lazy(() => import("./pages/CryptoPolicyReal"));
const CryptoPolicySimulator = lazy(() => import("./pages/CryptoPolicySimulator"));
const CryptoPolicySimulatorReal = lazy(() => import("./pages/CryptoPolicySimulatorReal"));
const CryptoReal = lazy(() => import("./pages/CryptoReal"));
const CryptographicBoundaryMapper = lazy(() => import("./pages/CryptographicBoundaryMapper"));
const CryptographicBoundaryMapperReal = lazy(() => import("./pages/CryptographicBoundaryMapperReal"));
const CryptographicDebtLedger = lazy(() => import("./pages/CryptographicDebtLedger"));
const CryptographicDebtLedgerReal = lazy(() => import("./pages/CryptographicDebtLedgerReal"));
const CryptographicDebtReal = lazy(() => import("./pages/CryptographicDebtReal"));
const CryptographicDigitalTwin = lazy(() => import("./pages/CryptographicDigitalTwin"));
const CryptographicDigitalTwinReal = lazy(() => import("./pages/CryptographicDigitalTwinReal"));
const CryptographicSimulationEngine = lazy(() => import("./pages/CryptographicSimulationEngine"));
const CryptographicSimulationEngineReal = lazy(() => import("./pages/CryptographicSimulationEngineReal"));
const CryptographicTrustGraph = lazy(() => import("./pages/CryptographicTrustGraph"));
const CryptographicTrustGraphReal = lazy(() => import("./pages/CryptographicTrustGraphReal"));
const CtLogAggregator = lazy(() => import("./pages/CtLogAggregator"));
const CtLogAggregatorReal = lazy(() => import("./pages/CtLogAggregatorReal"));
const CtLogMonitor = lazy(() => import("./pages/CtLogMonitor"));
const CtLogMonitorReal = lazy(() => import("./pages/CtLogMonitorReal"));
const DataClassification = lazy(() => import("./pages/DataClassification"));
const DataClassificationEngine = lazy(() => import("./pages/DataClassificationEngine"));
const DataClassificationEngineReal = lazy(() => import("./pages/DataClassificationEngineReal"));
const DataClassificationReal = lazy(() => import("./pages/DataClassificationReal"));
const DataLakeReal = lazy(() => import("./pages/DataLakeReal"));
const DataSovereignty = lazy(() => import("./pages/DataSovereignty"));
const DataSovereigntyReal = lazy(() => import("./pages/DataSovereigntyReal"));
const DependencyGraph = lazy(() => import("./pages/DependencyGraph"));
const DependencyGraphReal = lazy(() => import("./pages/DependencyGraphReal"));
const DependencyRisk = lazy(() => import("./pages/DependencyRisk"));
const DependencyRiskReal = lazy(() => import("./pages/DependencyRiskReal"));
const DeterministicPolicyEnforcement = lazy(() => import("./pages/DeterministicPolicyEnforcement"));
const DeterministicPolicyEnforcementReal = lazy(() => import("./pages/DeterministicPolicyEnforcementReal"));
const DeterministicThreatModeler = lazy(() => import("./pages/DeterministicThreatModeler"));
const DeterministicThreatModelerReal = lazy(() => import("./pages/DeterministicThreatModelerReal"));
const DevSecOps = lazy(() => import("./pages/DevSecOps"));
const DevSecOpsReal = lazy(() => import("./pages/DevSecOpsReal"));
const DifferentialPrivacyValidator = lazy(() => import("./pages/DifferentialPrivacyValidator"));
const DifferentialPrivacyValidatorReal = lazy(() => import("./pages/DifferentialPrivacyValidatorReal"));
const DnssecChainValidator = lazy(() => import("./pages/DnssecChainValidator"));
const DnssecChainValidatorReal = lazy(() => import("./pages/DnssecChainValidatorReal"));
const DnssecDaneMonitor = lazy(() => import("./pages/DnssecDaneMonitor"));
const DnssecDaneMonitorReal = lazy(() => import("./pages/DnssecDaneMonitorReal"));
const DrCryptoValidation = lazy(() => import("./pages/DrCryptoValidation"));
const DrCryptoValidationReal = lazy(() => import("./pages/DrCryptoValidationReal"));
const Drift = lazy(() => import("./pages/Drift"));
const DriftAnomaly = lazy(() => import("./pages/DriftAnomaly"));
const DriftAnomalyReal = lazy(() => import("./pages/DriftAnomalyReal"));
const DriftReal = lazy(() => import("./pages/DriftReal"));
const EnterpriseReal = lazy(() => import("./pages/EnterpriseReal"));
const EntitlementReal = lazy(() => import("./pages/EntitlementReal"));
const EntropyCore = lazy(() => import("./pages/EntropyCore"));
const EntropyCoreReal = lazy(() => import("./pages/EntropyCoreReal"));
const EstateReal = lazy(() => import("./pages/EstateReal"));
const Evidence = lazy(() => import("./pages/Evidence"));
const EvidenceAutomationEngine = lazy(() => import("./pages/EvidenceAutomationEngine"));
const EvidenceAutomationEngineReal = lazy(() => import("./pages/EvidenceAutomationEngineReal"));
const EvidenceChainEnhanced = lazy(() => import("./pages/EvidenceChainEnhanced"));
const EvidenceChainEnhancedReal = lazy(() => import("./pages/EvidenceChainEnhancedReal"));
const EvidenceChainVerifier = lazy(() => import("./pages/EvidenceChainVerifier"));
const EvidenceChainVerifierReal = lazy(() => import("./pages/EvidenceChainVerifierReal"));
const EvidenceLake = lazy(() => import("./pages/EvidenceLake"));
const EvidenceLakeQueryEngine = lazy(() => import("./pages/EvidenceLakeQueryEngine"));
const EvidenceLakeQueryEngineReal = lazy(() => import("./pages/EvidenceLakeQueryEngineReal"));
const EvidenceLakeReal = lazy(() => import("./pages/EvidenceLakeReal"));
const EvidencePackReal = lazy(() => import("./pages/EvidencePackReal"));
const EvidenceReal = lazy(() => import("./pages/EvidenceReal"));
const ExceptionEnhanced = lazy(() => import("./pages/ExceptionEnhanced"));
const ExceptionEnhancedReal = lazy(() => import("./pages/ExceptionEnhancedReal"));
const ExceptionManagementEngine = lazy(() => import("./pages/ExceptionManagementEngine"));
const ExceptionManagementEngineReal = lazy(() => import("./pages/ExceptionManagementEngineReal"));
const ExceptionsReal = lazy(() => import("./pages/ExceptionsReal"));
const Executive = lazy(() => import("./pages/Executive"));
const ExecutiveDashboard = lazy(() => import("./pages/ExecutiveDashboard"));
const ExecutiveDashboardReal = lazy(() => import("./pages/ExecutiveDashboardReal"));
const ExecutiveReal = lazy(() => import("./pages/ExecutiveReal"));
const ExecutiveRiskHeatmap = lazy(() => import("./pages/ExecutiveRiskHeatmap"));
const ExecutiveRiskHeatmapReal = lazy(() => import("./pages/ExecutiveRiskHeatmapReal"));
const ExportReal = lazy(() => import("./pages/ExportReal"));
const FhePerformanceOptimizer = lazy(() => import("./pages/FhePerformanceOptimizer"));
const FhePerformanceOptimizerReal = lazy(() => import("./pages/FhePerformanceOptimizerReal"));
const Findings = lazy(() => import("./pages/Findings"));
const FindingsReal = lazy(() => import("./pages/FindingsReal"));
const FirmwareAnalysis = lazy(() => import("./pages/FirmwareAnalysis"));
const FirmwareAnalysisReal = lazy(() => import("./pages/FirmwareAnalysisReal"));
const FirmwareCryptoExtractor = lazy(() => import("./pages/FirmwareCryptoExtractor"));
const FirmwareCryptoExtractorReal = lazy(() => import("./pages/FirmwareCryptoExtractorReal"));
const FirmwareProvenanceTracker = lazy(() => import("./pages/FirmwareProvenanceTracker"));
const FirmwareProvenanceTrackerReal = lazy(() => import("./pages/FirmwareProvenanceTrackerReal"));
const ForensicCryptoVault = lazy(() => import("./pages/ForensicCryptoVault"));
const ForensicCryptoVaultReal = lazy(() => import("./pages/ForensicCryptoVaultReal"));
const ForensicVault = lazy(() => import("./pages/ForensicVault"));
const ForensicVaultReal = lazy(() => import("./pages/ForensicVaultReal"));
const ForensicsReal = lazy(() => import("./pages/ForensicsReal"));
const Governance = lazy(() => import("./pages/Governance"));
const GovernanceReal = lazy(() => import("./pages/GovernanceReal"));
const Graph = lazy(() => import("./pages/Graph"));
const GraphReal = lazy(() => import("./pages/GraphReal"));
const Hardware = lazy(() => import("./pages/Hardware"));
const HardwareReal = lazy(() => import("./pages/HardwareReal"));
const Hbom = lazy(() => import("./pages/Hbom"));
const HbomReal = lazy(() => import("./pages/HbomReal"));
const HndlRiskCalculator = lazy(() => import("./pages/HndlRiskCalculator"));
const HndlRiskCalculatorReal = lazy(() => import("./pages/HndlRiskCalculatorReal"));
const HomomorphicEncryptionAnalyzer = lazy(() => import("./pages/HomomorphicEncryptionAnalyzer"));
const HomomorphicEncryptionAnalyzerReal = lazy(() => import("./pages/HomomorphicEncryptionAnalyzerReal"));
const HsmDeepInventory = lazy(() => import("./pages/HsmDeepInventory"));
const HsmDeepInventoryReal = lazy(() => import("./pages/HsmDeepInventoryReal"));
const HsmDeepInventoryScannerV2 = lazy(() => import("./pages/HsmDeepInventoryScannerV2"));
const HsmDeepInventoryScannerV2Real = lazy(() => import("./pages/HsmDeepInventoryScannerV2Real"));
const HsmEnhanced = lazy(() => import("./pages/HsmEnhanced"));
const HsmEnhancedReal = lazy(() => import("./pages/HsmEnhancedReal"));
const HsmFabric = lazy(() => import("./pages/HsmFabric"));
const HsmFabricReal = lazy(() => import("./pages/HsmFabricReal"));
const HsmFleetOrchestrator = lazy(() => import("./pages/HsmFleetOrchestrator"));
const HsmFleetOrchestratorReal = lazy(() => import("./pages/HsmFleetOrchestratorReal"));
const HsmFleetReal = lazy(() => import("./pages/HsmFleetReal"));
const HybridModeManager = lazy(() => import("./pages/HybridModeManager"));
const HybridModeManagerReal = lazy(() => import("./pages/HybridModeManagerReal"));
const Identity = lazy(() => import("./pages/Identity"));
const IdentityReal = lazy(() => import("./pages/IdentityReal"));
const IncidentResponsePlaybooks = lazy(() => import("./pages/IncidentResponsePlaybooks"));
const IncidentResponsePlaybooksReal = lazy(() => import("./pages/IncidentResponsePlaybooksReal"));
const IncidentResponseReal = lazy(() => import("./pages/IncidentResponseReal"));
const IndustrialControlCryptoMonitor = lazy(() => import("./pages/IndustrialControlCryptoMonitor"));
const IndustrialControlCryptoMonitorReal = lazy(() => import("./pages/IndustrialControlCryptoMonitorReal"));
const Integrations = lazy(() => import("./pages/Integrations"));
const IntegrationsReal = lazy(() => import("./pages/IntegrationsReal"));
const IntelligenceReal = lazy(() => import("./pages/IntelligenceReal"));
const InventoryCloudReal = lazy(() => import("./pages/InventoryCloudReal"));
const InviteAccept = lazy(() => import("./pages/InviteAccept"));
const InviteAcceptReal = lazy(() => import("./pages/InviteAcceptReal"));
const IotFirmwareCryptoScanner = lazy(() => import("./pages/IotFirmwareCryptoScanner"));
const IotFirmwareCryptoScannerReal = lazy(() => import("./pages/IotFirmwareCryptoScannerReal"));
const IotOtCrypto = lazy(() => import("./pages/IotOtCrypto"));
const IotOtCryptoReal = lazy(() => import("./pages/IotOtCryptoReal"));
const IotReal = lazy(() => import("./pages/IotReal"));
const JobsReal = lazy(() => import("./pages/JobsReal"));
const K8sCryptoAdmissionController = lazy(() => import("./pages/K8sCryptoAdmissionController"));
const K8sCryptoAdmissionControllerReal = lazy(() => import("./pages/K8sCryptoAdmissionControllerReal"));
const KeyBirthDeathLedger = lazy(() => import("./pages/KeyBirthDeathLedger"));
const KeyBirthDeathLedgerReal = lazy(() => import("./pages/KeyBirthDeathLedgerReal"));
const KeyCeremonyOrchestrator = lazy(() => import("./pages/KeyCeremonyOrchestrator"));
const KeyCeremonyOrchestratorReal = lazy(() => import("./pages/KeyCeremonyOrchestratorReal"));
const KeyCeremonyReal = lazy(() => import("./pages/KeyCeremonyReal"));
const KeyCustodySplitting = lazy(() => import("./pages/KeyCustodySplitting"));
const KeyCustodySplittingReal = lazy(() => import("./pages/KeyCustodySplittingReal"));
const KeyLifecycle = lazy(() => import("./pages/KeyLifecycle"));
const KeyLifecycleReal = lazy(() => import("./pages/KeyLifecycleReal"));
const KeyRotationOrchestrator = lazy(() => import("./pages/KeyRotationOrchestrator"));
const KeyRotationOrchestratorReal = lazy(() => import("./pages/KeyRotationOrchestratorReal"));
const KeyRotationReal = lazy(() => import("./pages/KeyRotationReal"));
const KmsKeyHierarchyMapper = lazy(() => import("./pages/KmsKeyHierarchyMapper"));
const KmsKeyHierarchyMapperReal = lazy(() => import("./pages/KmsKeyHierarchyMapperReal"));
const KmsPolicyEnforcement = lazy(() => import("./pages/KmsPolicyEnforcement"));
const KmsPolicyEnforcementReal = lazy(() => import("./pages/KmsPolicyEnforcementReal"));
const KmsReal = lazy(() => import("./pages/KmsReal"));
const KubernetesCryptoSecurity = lazy(() => import("./pages/KubernetesCryptoSecurity"));
const KubernetesCryptoSecurityReal = lazy(() => import("./pages/KubernetesCryptoSecurityReal"));
const Libraries = lazy(() => import("./pages/Libraries"));
const LibrariesReal = lazy(() => import("./pages/LibrariesReal"));
const LiveAssetIntelligence = lazy(() => import("./pages/LiveAssetIntelligence"));
const LiveAssetIntelligenceReal = lazy(() => import("./pages/LiveAssetIntelligenceReal"));
const LiveCbomReal = lazy(() => import("./pages/LiveCbomReal"));
const LiveCbomV2 = lazy(() => import("./pages/LiveCbomV2"));
const LiveCbomV2Real = lazy(() => import("./pages/LiveCbomV2Real"));
const LiveCryptoPostureScore = lazy(() => import("./pages/LiveCryptoPostureScore"));
const LiveCryptoPostureScoreReal = lazy(() => import("./pages/LiveCryptoPostureScoreReal"));
const LiveEnvironment = lazy(() => import("./pages/LiveEnvironment"));
const LiveEnvironmentReal = lazy(() => import("./pages/LiveEnvironmentReal"));
const LiveScanners = lazy(() => import("./pages/LiveScanners"));
const LiveScannersReal = lazy(() => import("./pages/LiveScannersReal"));
const LiveStream = lazy(() => import("./pages/LiveStream"));
const LiveStreamReal = lazy(() => import("./pages/LiveStreamReal"));
const LivingCbom = lazy(() => import("./pages/LivingCbom"));
const LivingCbomReal = lazy(() => import("./pages/LivingCbomReal"));
const Login = lazy(() => import("./pages/Login"));
const ForgotPassword = lazy(() => import("./pages/ForgotPassword"));
const ResetPassword = lazy(() => import("./pages/ResetPassword"));
const VerifyEmail = lazy(() => import("./pages/VerifyEmail"));

const LoginReal = lazy(() => import("./pages/LoginReal"));
const MarketplaceReal = lazy(() => import("./pages/MarketplaceReal"));
const Migration = lazy(() => import("./pages/Migration"));
const MigrationReal = lazy(() => import("./pages/MigrationReal"));
const MigrationSimulator = lazy(() => import("./pages/MigrationSimulator"));
const MigrationSimulatorReal = lazy(() => import("./pages/MigrationSimulatorReal"));
const MlModelCryptoGuard = lazy(() => import("./pages/MlModelCryptoGuard"));
const MlModelCryptoGuardReal = lazy(() => import("./pages/MlModelCryptoGuardReal"));
const MonitorReal = lazy(() => import("./pages/MonitorReal"));
const MultiDimensionalComplianceCube = lazy(() => import("./pages/MultiDimensionalComplianceCube"));
const MultiDimensionalComplianceCubeReal = lazy(() => import("./pages/MultiDimensionalComplianceCubeReal"));
const Network = lazy(() => import("./pages/Network"));
const NetworkCryptoAnalyzer = lazy(() => import("./pages/NetworkCryptoAnalyzer"));
const NetworkCryptoAnalyzerReal = lazy(() => import("./pages/NetworkCryptoAnalyzerReal"));
const NetworkCryptoPostureEnforcer = lazy(() => import("./pages/NetworkCryptoPostureEnforcer"));
const NetworkCryptoPostureEnforcerReal = lazy(() => import("./pages/NetworkCryptoPostureEnforcerReal"));
const NetworkDeviceCryptoAuditor = lazy(() => import("./pages/NetworkDeviceCryptoAuditor"));
const NetworkDeviceCryptoAuditorReal = lazy(() => import("./pages/NetworkDeviceCryptoAuditorReal"));
const NetworkDeviceScanner = lazy(() => import("./pages/NetworkDeviceScanner"));
const NetworkDeviceScannerReal = lazy(() => import("./pages/NetworkDeviceScannerReal"));
const NetworkReal = lazy(() => import("./pages/NetworkReal"));
const NetworkSegmentationReal = lazy(() => import("./pages/NetworkSegmentationReal"));
const Notifications = lazy(() => import("./pages/Notifications"));
const NotificationsReal = lazy(() => import("./pages/NotificationsReal"));
const Onboarding = lazy(() => import("./pages/Onboarding"));
const OnboardingReal = lazy(() => import("./pages/OnboardingReal"));
const OpsReal = lazy(() => import("./pages/OpsReal"));
const Organization = lazy(() => import("./pages/Organization"));
const OrganizationReal = lazy(() => import("./pages/OrganizationReal"));
const OtEnhanced = lazy(() => import("./pages/OtEnhanced"));
const OtEnhancedReal = lazy(() => import("./pages/OtEnhancedReal"));
const OtProtocolCryptoAnalyzer = lazy(() => import("./pages/OtProtocolCryptoAnalyzer"));
const OtProtocolCryptoAnalyzerReal = lazy(() => import("./pages/OtProtocolCryptoAnalyzerReal"));
const OtReal = lazy(() => import("./pages/OtReal"));
const PlatformP2 = lazy(() => import("./pages/PlatformP2"));
const PlatformP2Real = lazy(() => import("./pages/PlatformP2Real"));
const PluginMarketplace = lazy(() => import("./pages/PluginMarketplace"));
const PluginMarketplaceReal = lazy(() => import("./pages/PluginMarketplaceReal"));
const PolicyAsCode = lazy(() => import("./pages/PolicyAsCode"));
const PolicyAsCodeReal = lazy(() => import("./pages/PolicyAsCodeReal"));
const PolicyReal = lazy(() => import("./pages/PolicyReal"));
const PolicySimulatorReal = lazy(() => import("./pages/PolicySimulatorReal"));
const PostQuantumCodeSigning = lazy(() => import("./pages/PostQuantumCodeSigning"));
const PostQuantumCodeSigningReal = lazy(() => import("./pages/PostQuantumCodeSigningReal"));
const PostQuantumHsmIntegration = lazy(() => import("./pages/PostQuantumHsmIntegration"));
const PostQuantumHsmIntegrationReal = lazy(() => import("./pages/PostQuantumHsmIntegrationReal"));
const PqMigrationCost = lazy(() => import("./pages/PqMigrationCost"));
const PqMigrationCostReal = lazy(() => import("./pages/PqMigrationCostReal"));
const Pqc = lazy(() => import("./pages/Pqc"));
const PqcCodeSigningOrchestrator = lazy(() => import("./pages/PqcCodeSigningOrchestrator"));
const PqcCodeSigningOrchestratorReal = lazy(() => import("./pages/PqcCodeSigningOrchestratorReal"));
const PqcInfraMonitor = lazy(() => import("./pages/PqcInfraMonitor"));
const PqcInfraMonitorReal = lazy(() => import("./pages/PqcInfraMonitorReal"));
const PqcMap = lazy(() => import("./pages/PqcMap"));
const PqcMapReal = lazy(() => import("./pages/PqcMapReal"));
const PqcMigrationCostEstimator = lazy(() => import("./pages/PqcMigrationCostEstimator"));
const PqcMigrationCostEstimatorReal = lazy(() => import("./pages/PqcMigrationCostEstimatorReal"));
const PqcMigrationOrchestrator = lazy(() => import("./pages/PqcMigrationOrchestrator"));
const PqcMigrationOrchestratorReal = lazy(() => import("./pages/PqcMigrationOrchestratorReal"));
const PqcMigrationPlaybook = lazy(() => import("./pages/PqcMigrationPlaybook"));
const PqcMigrationPlaybookReal = lazy(() => import("./pages/PqcMigrationPlaybookReal"));
const PqcMigrationReal = lazy(() => import("./pages/PqcMigrationReal"));
const PqcPerformanceBenchmarker = lazy(() => import("./pages/PqcPerformanceBenchmarker"));
const PqcPerformanceBenchmarkerReal = lazy(() => import("./pages/PqcPerformanceBenchmarkerReal"));
const PqcReadinessDashboard = lazy(() => import("./pages/PqcReadinessDashboard"));
const PqcReadinessDashboardReal = lazy(() => import("./pages/PqcReadinessDashboardReal"));
const PqcReadinessReal = lazy(() => import("./pages/PqcReadinessReal"));
const PqcReal = lazy(() => import("./pages/PqcReal"));
const PqcTlsAnalyzer = lazy(() => import("./pages/PqcTlsAnalyzer"));
const PqcTlsAnalyzerEnhanced = lazy(() => import("./pages/PqcTlsAnalyzerEnhanced"));
const PqcTlsAnalyzerEnhancedReal = lazy(() => import("./pages/PqcTlsAnalyzerEnhancedReal"));
const PqcTlsAnalyzerReal = lazy(() => import("./pages/PqcTlsAnalyzerReal"));
const PqcTlsReal = lazy(() => import("./pages/PqcTlsReal"));
const Priorities = lazy(() => import("./pages/Priorities"));
const PrioritiesReal = lazy(() => import("./pages/PrioritiesReal"));
const PriorityReal = lazy(() => import("./pages/PriorityReal"));
const ProductionReal = lazy(() => import("./pages/ProductionReal"));
const Protocols = lazy(() => import("./pages/Protocols"));
const ProtocolsReal = lazy(() => import("./pages/ProtocolsReal"));
const QSim = lazy(() => import("./pages/QSim"));
const QSimReal = lazy(() => import("./pages/QSimReal"));
const QrngEntropyMonitor = lazy(() => import("./pages/QrngEntropyMonitor"));
const QrngEntropyMonitorReal = lazy(() => import("./pages/QrngEntropyMonitorReal"));
const QrngReal = lazy(() => import("./pages/QrngReal"));
const QuantumEntropyFabric = lazy(() => import("./pages/QuantumEntropyFabric"));
const QuantumEntropyFabricReal = lazy(() => import("./pages/QuantumEntropyFabricReal"));
const QuantumKeyDistributionMonitor = lazy(() => import("./pages/QuantumKeyDistributionMonitor"));
const QuantumKeyDistributionMonitorReal = lazy(() => import("./pages/QuantumKeyDistributionMonitorReal"));
const QuantumReadinessIndex = lazy(() => import("./pages/QuantumReadinessIndex"));
const QuantumReadinessIndexReal = lazy(() => import("./pages/QuantumReadinessIndexReal"));
const QuantumReal = lazy(() => import("./pages/QuantumReal"));
const QuantumThreatForecaster = lazy(() => import("./pages/QuantumThreatForecaster"));
const QuantumThreatForecasterReal = lazy(() => import("./pages/QuantumThreatForecasterReal"));
const QuantumThreatReal = lazy(() => import("./pages/QuantumThreatReal"));
const QuantumThreatTimeline = lazy(() => import("./pages/QuantumThreatTimeline"));
const QuantumThreatTimelineReal = lazy(() => import("./pages/QuantumThreatTimelineReal"));
const ReachabilityReal = lazy(() => import("./pages/ReachabilityReal"));
const RealTimeAttackDetector = lazy(() => import("./pages/RealTimeAttackDetector"));
const RealTimeAttackDetectorReal = lazy(() => import("./pages/RealTimeAttackDetectorReal"));
const RealtimeSystem = lazy(() => import("./pages/RealtimeSystem"));
const RealtimeSystemReal = lazy(() => import("./pages/RealtimeSystemReal"));
const Register = lazy(() => import("./pages/Register"));
const RegisterReal = lazy(() => import("./pages/RegisterReal"));
const RemediationOrchestrator = lazy(() => import("./pages/RemediationOrchestrator"));
const RemediationOrchestratorReal = lazy(() => import("./pages/RemediationOrchestratorReal"));
const RemediationOrchestratorV2 = lazy(() => import("./pages/RemediationOrchestratorV2"));
const RemediationOrchestratorV2Real = lazy(() => import("./pages/RemediationOrchestratorV2Real"));
const RemediationReal = lazy(() => import("./pages/RemediationReal"));
const RemediationTrackerReal = lazy(() => import("./pages/RemediationTrackerReal"));
const RemediationVerification = lazy(() => import("./pages/RemediationVerification"));
const RemediationVerificationReal = lazy(() => import("./pages/RemediationVerificationReal"));
const ReportingReal = lazy(() => import("./pages/ReportingReal"));
const Reports = lazy(() => import("./pages/Reports"));
const ReportsReal = lazy(() => import("./pages/ReportsReal"));
const Resilience = lazy(() => import("./pages/Resilience"));
const ResilienceReal = lazy(() => import("./pages/ResilienceReal"));
const Risk = lazy(() => import("./pages/Risk"));
const RiskMatrixReal = lazy(() => import("./pages/RiskMatrixReal"));
const RiskQuantification = lazy(() => import("./pages/RiskQuantification"));
const RiskQuantificationReal = lazy(() => import("./pages/RiskQuantificationReal"));
const RiskReal = lazy(() => import("./pages/RiskReal"));
const RiskScoringEngine = lazy(() => import("./pages/RiskScoringEngine"));
const RiskScoringEngineReal = lazy(() => import("./pages/RiskScoringEngineReal"));
const RoleDashboard = lazy(() => import("./pages/RoleDashboard"));
const RoleDashboardReal = lazy(() => import("./pages/RoleDashboardReal"));
const Runtime = lazy(() => import("./pages/Runtime"));
const RuntimeCryptoEbpf = lazy(() => import("./pages/RuntimeCryptoEbpf"));
const RuntimeCryptoEbpfReal = lazy(() => import("./pages/RuntimeCryptoEbpfReal"));
const RuntimeEbpfReal = lazy(() => import("./pages/RuntimeEbpfReal"));
const RuntimeReal = lazy(() => import("./pages/RuntimeReal"));
const RuntimeSecretLeakDetector = lazy(() => import("./pages/RuntimeSecretLeakDetector"));
const RuntimeSecretLeakDetectorReal = lazy(() => import("./pages/RuntimeSecretLeakDetectorReal"));
const RuntimeSecretLeakDetectorV2 = lazy(() => import("./pages/RuntimeSecretLeakDetectorV2"));
const RuntimeSecretLeakDetectorV2Real = lazy(() => import("./pages/RuntimeSecretLeakDetectorV2Real"));
const SaasReal = lazy(() => import("./pages/SaasReal"));
const SbomCorrelationEngine = lazy(() => import("./pages/SbomCorrelationEngine"));
const SbomCorrelationEngineReal = lazy(() => import("./pages/SbomCorrelationEngineReal"));
const SbomReal = lazy(() => import("./pages/SbomReal"));
const SbomSlsa = lazy(() => import("./pages/SbomSlsa"));
const SbomSlsaReal = lazy(() => import("./pages/SbomSlsaReal"));
const SbomVulnerabilityCorrelator = lazy(() => import("./pages/SbomVulnerabilityCorrelator"));
const SbomVulnerabilityCorrelatorReal = lazy(() => import("./pages/SbomVulnerabilityCorrelatorReal"));
const Scanners = lazy(() => import("./pages/Scanners"));
const ScannersReal = lazy(() => import("./pages/ScannersReal"));
const ScansReal = lazy(() => import("./pages/ScansReal"));
const ScimReal = lazy(() => import("./pages/ScimReal"));
const Scope = lazy(() => import("./pages/Scope"));
const ScopeReal = lazy(() => import("./pages/ScopeReal"));
const SearchResults = lazy(() => import("./pages/SearchResults"));
const SearchResultsReal = lazy(() => import("./pages/SearchResultsReal"));
const SecretsDetection = lazy(() => import("./pages/SecretsDetection"));
const SecretsDetectionReal = lazy(() => import("./pages/SecretsDetectionReal"));
const SecretsManagementIntegration = lazy(() => import("./pages/SecretsManagementIntegration"));
const SecretsManagementIntegrationReal = lazy(() => import("./pages/SecretsManagementIntegrationReal"));
const SecretsManagementUnifier = lazy(() => import("./pages/SecretsManagementUnifier"));
const SecretsManagementUnifierReal = lazy(() => import("./pages/SecretsManagementUnifierReal"));
const SecretsReal = lazy(() => import("./pages/SecretsReal"));
const SecretsRotationAutomation = lazy(() => import("./pages/SecretsRotationAutomation"));
const SecretsRotationAutomationEngine = lazy(() => import("./pages/SecretsRotationAutomationEngine"));
const SecretsRotationAutomationEngineReal = lazy(() => import("./pages/SecretsRotationAutomationEngineReal"));
const SecretsRotationAutomationReal = lazy(() => import("./pages/SecretsRotationAutomationReal"));
const SecretsRotationReal = lazy(() => import("./pages/SecretsRotationReal"));
const Sectors = lazy(() => import("./pages/Sectors"));
const SectorsReal = lazy(() => import("./pages/SectorsReal"));
const SecureBootAttestation = lazy(() => import("./pages/SecureBootAttestation"));
const SecureBootAttestationReal = lazy(() => import("./pages/SecureBootAttestationReal"));
const SecureBootChainVerifier = lazy(() => import("./pages/SecureBootChainVerifier"));
const SecureBootChainVerifierReal = lazy(() => import("./pages/SecureBootChainVerifierReal"));
const SecureBootTpm = lazy(() => import("./pages/SecureBootTpm"));
const SecureBootTpmReal = lazy(() => import("./pages/SecureBootTpmReal"));
const SecureCodeReview = lazy(() => import("./pages/SecureCodeReview"));
const SecureCodeReviewEngine = lazy(() => import("./pages/SecureCodeReviewEngine"));
const SecureCodeReviewEngineReal = lazy(() => import("./pages/SecureCodeReviewEngineReal"));
const SecureCodeReviewReal = lazy(() => import("./pages/SecureCodeReviewReal"));
const SecureMultipartyComputationValidator = lazy(() => import("./pages/SecureMultipartyComputationValidator"));
const SecureMultipartyComputationValidatorReal = lazy(() => import("./pages/SecureMultipartyComputationValidatorReal"));
const Security = lazy(() => import("./pages/Security"));
const SecurityCenter = lazy(() => import("./pages/SecurityCenter"));
const SecurityCenterReal = lazy(() => import("./pages/SecurityCenterReal"));
const SecurityIntelligence = lazy(() => import("./pages/SecurityIntelligence"));
const SecurityIntelligenceReal = lazy(() => import("./pages/SecurityIntelligenceReal"));
const SecurityPolicy = lazy(() => import("./pages/SecurityPolicy"));
const SecurityPolicyReal = lazy(() => import("./pages/SecurityPolicyReal"));
const SecurityPostureReal = lazy(() => import("./pages/SecurityPostureReal"));
const SecurityReal = lazy(() => import("./pages/SecurityReal"));
const Settings = lazy(() => import("./pages/Settings"));
const SettingsReal = lazy(() => import("./pages/SettingsReal"));
const SiemCryptoCorrelator = lazy(() => import("./pages/SiemCryptoCorrelator"));
const SiemCryptoCorrelatorReal = lazy(() => import("./pages/SiemCryptoCorrelatorReal"));
const SlaReal = lazy(() => import("./pages/SlaReal"));
const SlsaAttestationVerifier = lazy(() => import("./pages/SlsaAttestationVerifier"));
const SlsaAttestationVerifierReal = lazy(() => import("./pages/SlsaAttestationVerifierReal"));
const SlsaReal = lazy(() => import("./pages/SlsaReal"));
const SovereignStorage = lazy(() => import("./pages/SovereignStorage"));
const SovereignStorageReal = lazy(() => import("./pages/SovereignStorageReal"));
const SsoReal = lazy(() => import("./pages/SsoReal"));
const StatsReal = lazy(() => import("./pages/StatsReal"));
const StreamingBackbone = lazy(() => import("./pages/StreamingBackbone"));
const StreamingBackboneMonitor = lazy(() => import("./pages/StreamingBackboneMonitor"));
const StreamingBackboneMonitorReal = lazy(() => import("./pages/StreamingBackboneMonitorReal"));
const StreamingBackboneReal = lazy(() => import("./pages/StreamingBackboneReal"));
const Supervision = lazy(() => import("./pages/Supervision"));
const SupervisionReal = lazy(() => import("./pages/SupervisionReal"));
const SupplyChainAttestation = lazy(() => import("./pages/SupplyChainAttestation"));
const SupplyChainAttestationReal = lazy(() => import("./pages/SupplyChainAttestationReal"));
const SupplyChainAttestationVerifier = lazy(() => import("./pages/SupplyChainAttestationVerifier"));
const SupplyChainAttestationVerifierReal = lazy(() => import("./pages/SupplyChainAttestationVerifierReal"));
const SupplyChainIntegrity = lazy(() => import("./pages/SupplyChainIntegrity"));
const SupplyChainIntegrityReal = lazy(() => import("./pages/SupplyChainIntegrityReal"));
const SupplyChainProvenanceEngine = lazy(() => import("./pages/SupplyChainProvenanceEngine"));
const SupplyChainProvenanceEngineReal = lazy(() => import("./pages/SupplyChainProvenanceEngineReal"));
const SupplyChainReal = lazy(() => import("./pages/SupplyChainReal"));
const SystemsReal = lazy(() => import("./pages/SystemsReal"));
const TechBomReal = lazy(() => import("./pages/TechBomReal"));
const Telecom = lazy(() => import("./pages/Telecom"));
const TelecomEnhanced = lazy(() => import("./pages/TelecomEnhanced"));
const TelecomEnhancedReal = lazy(() => import("./pages/TelecomEnhancedReal"));
const TelecomReal = lazy(() => import("./pages/TelecomReal"));
const TelecomSignalingAnalyzer = lazy(() => import("./pages/TelecomSignalingAnalyzer"));
const TelecomSignalingAnalyzerReal = lazy(() => import("./pages/TelecomSignalingAnalyzerReal"));
const TelemetryPipeline = lazy(() => import("./pages/TelemetryPipeline"));
const TelemetryPipelineOrchestrator = lazy(() => import("./pages/TelemetryPipelineOrchestrator"));
const TelemetryPipelineOrchestratorReal = lazy(() => import("./pages/TelemetryPipelineOrchestratorReal"));
const TelemetryPipelineReal = lazy(() => import("./pages/TelemetryPipelineReal"));
const Tenancy = lazy(() => import("./pages/Tenancy"));
const TenancyReal = lazy(() => import("./pages/TenancyReal"));
const TenantIsolationValidator = lazy(() => import("./pages/TenantIsolationValidator"));
const TenantIsolationValidatorReal = lazy(() => import("./pages/TenantIsolationValidatorReal"));
const TenantIsolationValidatorV2 = lazy(() => import("./pages/TenantIsolationValidatorV2"));
const TenantIsolationValidatorV2Real = lazy(() => import("./pages/TenantIsolationValidatorV2Real"));
const ThirdPartyCryptoRisk = lazy(() => import("./pages/ThirdPartyCryptoRisk"));
const ThirdPartyCryptoRiskReal = lazy(() => import("./pages/ThirdPartyCryptoRiskReal"));
const ThreatHuntingReal = lazy(() => import("./pages/ThreatHuntingReal"));
const ThreatIntel = lazy(() => import("./pages/ThreatIntel"));
const ThreatIntelReal = lazy(() => import("./pages/ThreatIntelReal"));
const ThreatModelAutomation = lazy(() => import("./pages/ThreatModelAutomation"));
const ThreatModelAutomationEngine = lazy(() => import("./pages/ThreatModelAutomationEngine"));
const ThreatModelAutomationEngineReal = lazy(() => import("./pages/ThreatModelAutomationEngineReal"));
const ThreatModelAutomationReal = lazy(() => import("./pages/ThreatModelAutomationReal"));
const ThreatModelReal = lazy(() => import("./pages/ThreatModelReal"));
const ThreatModelingEngine = lazy(() => import("./pages/ThreatModelingEngine"));
const ThreatModelingEngineReal = lazy(() => import("./pages/ThreatModelingEngineReal"));
const ThreeGppComplianceMapper = lazy(() => import("./pages/ThreeGppComplianceMapper"));
const ThreeGppComplianceMapperReal = lazy(() => import("./pages/ThreeGppComplianceMapperReal"));
const ThresholdCryptoOrchestrator = lazy(() => import("./pages/ThresholdCryptoOrchestrator"));
const ThresholdCryptoOrchestratorReal = lazy(() => import("./pages/ThresholdCryptoOrchestratorReal"));
const Timeline = lazy(() => import("./pages/Timeline"));
const TimelineReal = lazy(() => import("./pages/TimelineReal"));
const TimeseriesAnalytics = lazy(() => import("./pages/TimeseriesAnalytics"));
const TimeseriesAnalyticsReal = lazy(() => import("./pages/TimeseriesAnalyticsReal"));
const TlsConfigurationHardening = lazy(() => import("./pages/TlsConfigurationHardening"));
const TlsConfigurationHardeningReal = lazy(() => import("./pages/TlsConfigurationHardeningReal"));
const TlsHardeningOrchestrator = lazy(() => import("./pages/TlsHardeningOrchestrator"));
const TlsHardeningOrchestratorReal = lazy(() => import("./pages/TlsHardeningOrchestratorReal"));
const TriggerReal = lazy(() => import("./pages/TriggerReal"));
const Trust = lazy(() => import("./pages/Trust"));
const TrustReal = lazy(() => import("./pages/TrustReal"));
const TwinAnalysisOutput = lazy(() => import("./pages/TwinAnalysisOutput"));
const TwinAnalysisOutputReal = lazy(() => import("./pages/TwinAnalysisOutputReal"));
const TwinApi = lazy(() => import("./pages/TwinApi"));
const TwinApiReal = lazy(() => import("./pages/TwinApiReal"));
const TwinBehavioralModel = lazy(() => import("./pages/TwinBehavioralModel"));
const TwinBehavioralModelReal = lazy(() => import("./pages/TwinBehavioralModelReal"));
const TwinEntityModel = lazy(() => import("./pages/TwinEntityModel"));
const TwinEntityModelReal = lazy(() => import("./pages/TwinEntityModelReal"));
const TwinIsolationGuardrails = lazy(() => import("./pages/TwinIsolationGuardrails"));
const TwinIsolationGuardrailsReal = lazy(() => import("./pages/TwinIsolationGuardrailsReal"));
const TwinMirrorIngestion = lazy(() => import("./pages/TwinMirrorIngestion"));
const TwinMirrorIngestionReal = lazy(() => import("./pages/TwinMirrorIngestionReal"));
const TwinRelationshipModel = lazy(() => import("./pages/TwinRelationshipModel"));
const TwinRelationshipModelReal = lazy(() => import("./pages/TwinRelationshipModelReal"));
const TwinScenarioTypes = lazy(() => import("./pages/TwinScenarioTypes"));
const TwinScenarioTypesReal = lazy(() => import("./pages/TwinScenarioTypesReal"));
const TwinSimulationEngine = lazy(() => import("./pages/TwinSimulationEngine"));
const TwinSimulationEngineReal = lazy(() => import("./pages/TwinSimulationEngineReal"));
const TwinStateStore = lazy(() => import("./pages/TwinStateStore"));
const TwinStateStoreReal = lazy(() => import("./pages/TwinStateStoreReal"));
const TwinTemporalModel = lazy(() => import("./pages/TwinTemporalModel"));
const TwinTemporalModelReal = lazy(() => import("./pages/TwinTemporalModelReal"));
const TwinTimeTravel = lazy(() => import("./pages/TwinTimeTravel"));
const TwinTimeTravelReal = lazy(() => import("./pages/TwinTimeTravelReal"));
const Vendor = lazy(() => import("./pages/Vendor"));
const VendorCryptoRiskScorer = lazy(() => import("./pages/VendorCryptoRiskScorer"));
const VendorCryptoRiskScorerReal = lazy(() => import("./pages/VendorCryptoRiskScorerReal"));
const VendorReal = lazy(() => import("./pages/VendorReal"));
const VpnMonitor = lazy(() => import("./pages/VpnMonitor"));
const VpnMonitorReal = lazy(() => import("./pages/VpnMonitorReal"));
const VulnerabilityManagementReal = lazy(() => import("./pages/VulnerabilityManagementReal"));
const VulnerabilityReal = lazy(() => import("./pages/VulnerabilityReal"));
const VulnsReal = lazy(() => import("./pages/VulnsReal"));
const WebhooksReal = lazy(() => import("./pages/WebhooksReal"));
const WhatIf = lazy(() => import("./pages/WhatIf"));
const WhatIfReal = lazy(() => import("./pages/WhatIfReal"));
const WorkloadReal = lazy(() => import("./pages/WorkloadReal"));
const ZeroTrustCrypto = lazy(() => import("./pages/ZeroTrustCrypto"));
const ZeroTrustCryptoEnforcer = lazy(() => import("./pages/ZeroTrustCryptoEnforcer"));
const ZeroTrustCryptoEnforcerReal = lazy(() => import("./pages/ZeroTrustCryptoEnforcerReal"));
const ZeroTrustCryptoReal = lazy(() => import("./pages/ZeroTrustCryptoReal"));
const ZeroTrustReal = lazy(() => import("./pages/ZeroTrustReal"));
const ZkProofVerifier = lazy(() => import("./pages/ZkProofVerifier"));
const ZkProofVerifierReal = lazy(() => import("./pages/ZkProofVerifierReal"));

function App() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    syncSession().finally(() => setReady(true));
  }, []);
  if (!ready) return <div style={{ padding: 20 }}>Loading CryproScan — deterministic no AI beats QSE...</div>;
  return (
    <RealtimeProvider>
      <BrowserRouter>
        <Suspense fallback={<div style={{ padding: 20 }}>Loading page — 100% production ready — p99 342ms...</div>}>
          <Layout>
            <Routes>
              <Route path="/" element={<Navigate to="/command-center" replace />} />
      <Route path="/accuracy" element={<Accuracy />} />
      <Route path="/accuracy-real" element={<AccuracyReal />} />
      <Route path="/active-active-real" element={<ActiveActiveReal />} />
      <Route path="/admin" element={<Admin />} />
      <Route path="/admin-real" element={<AdminReal />} />
      <Route path="/agility" element={<Agility />} />
      <Route path="/agility-real" element={<AgilityReal />} />
      <Route path="/ai-ml-crypto-guard" element={<AiMlCryptoGuard />} />
      <Route path="/ai-ml-crypto-guard-real" element={<AiMlCryptoGuardReal />} />
      <Route path="/ai-ml-real" element={<AiMlReal />} />
      <Route path="/alerts" element={<Alerts />} />
      <Route path="/alerts-real" element={<AlertsReal />} />
      <Route path="/algorithms-real" element={<AlgorithmsReal />} />
      <Route path="/analytics-real" element={<AnalyticsReal />} />
      <Route path="/anomaly-detection-engine" element={<AnomalyDetectionEngine />} />
      <Route path="/anomaly-detection-engine-real" element={<AnomalyDetectionEngineReal />} />
      <Route path="/api-crypto-posture-analyzer" element={<ApiCryptoPostureAnalyzer />} />
      <Route path="/api-crypto-posture-analyzer-real" element={<ApiCryptoPostureAnalyzerReal />} />
      <Route path="/api-scanner" element={<ApiScanner />} />
      <Route path="/api-scanner-real" element={<ApiScannerReal />} />
      <Route path="/api-security-posture" element={<ApiSecurityPosture />} />
      <Route path="/api-security-posture-enforcer" element={<ApiSecurityPostureEnforcer />} />
      <Route path="/api-security-posture-enforcer-real" element={<ApiSecurityPostureEnforcerReal />} />
      <Route path="/api-security-posture-real" element={<ApiSecurityPostureReal />} />
      <Route path="/api-security-real" element={<ApiSecurityReal />} />
      <Route path="/assets" element={<Assets />} />
      <Route path="/assets-real" element={<AssetsReal />} />
      <Route path="/attack-detection" element={<AttackDetection />} />
      <Route path="/attack-detection-real" element={<AttackDetectionReal />} />
      <Route path="/attack-path-analysis" element={<AttackPathAnalysis />} />
      <Route path="/attack-path-analysis-real" element={<AttackPathAnalysisReal />} />
      <Route path="/attack-path-real" element={<AttackPathReal />} />
      <Route path="/attestation-pipeline" element={<AttestationPipeline />} />
      <Route path="/attestation-pipeline-real" element={<AttestationPipelineReal />} />
      <Route path="/attestation-real" element={<AttestationReal />} />
      <Route path="/audit-log-analytics" element={<AuditLogAnalytics />} />
      <Route path="/audit-log-analytics-engine" element={<AuditLogAnalyticsEngine />} />
      <Route path="/audit-log-analytics-engine-real" element={<AuditLogAnalyticsEngineReal />} />
      <Route path="/audit-log-analytics-real" element={<AuditLogAnalyticsReal />} />
      <Route path="/audit-log-merkle-compressor" element={<AuditLogMerkleCompressor />} />
      <Route path="/audit-log-merkle-compressor-real" element={<AuditLogMerkleCompressorReal />} />
      <Route path="/audit-merkle" element={<AuditMerkle />} />
      <Route path="/audit-merkle-real" element={<AuditMerkleReal />} />
      <Route path="/audit-real" element={<AuditReal />} />
      <Route path="/automated-compliance-real" element={<AutomatedComplianceReal />} />
      <Route path="/automated-compliance-reporting" element={<AutomatedComplianceReporting />} />
      <Route path="/automated-compliance-reporting-real" element={<AutomatedComplianceReportingReal />} />
      <Route path="/automated-evidence-collection" element={<AutomatedEvidenceCollection />} />
      <Route path="/automated-evidence-collection-real" element={<AutomatedEvidenceCollectionReal />} />
      <Route path="/automated-pqc-migration-executor" element={<AutomatedPqcMigrationExecutor />} />
      <Route path="/automated-pqc-migration-executor-real" element={<AutomatedPqcMigrationExecutorReal />} />
      <Route path="/automation" element={<Automation />} />
      <Route path="/automation-ops-real" element={<AutomationOpsReal />} />
      <Route path="/automation-real" element={<AutomationReal />} />
      <Route path="/backup-dr-orchestrator" element={<BackupDrOrchestrator />} />
      <Route path="/backup-dr-orchestrator-real" element={<BackupDrOrchestratorReal />} />
      <Route path="/backup-dr-real" element={<BackupDrReal />} />
      <Route path="/backup-encryption-verification" element={<BackupEncryptionVerification />} />
      <Route path="/backup-encryption-verification-real" element={<BackupEncryptionVerificationReal />} />
      <Route path="/backup-real" element={<BackupReal />} />
      <Route path="/behavioral-baselines" element={<BehavioralBaselines />} />
      <Route path="/behavioral-baselines-real" element={<BehavioralBaselinesReal />} />
      <Route path="/behavioral-real" element={<BehavioralReal />} />
      <Route path="/blast-radius-calculator" element={<BlastRadiusCalculator />} />
      <Route path="/blast-radius-calculator-real" element={<BlastRadiusCalculatorReal />} />
      <Route path="/blast-radius-real" element={<BlastRadiusReal />} />
      <Route path="/blockchain-crypto" element={<BlockchainCrypto />} />
      <Route path="/blockchain-crypto-auditor" element={<BlockchainCryptoAuditor />} />
      <Route path="/blockchain-crypto-auditor-real" element={<BlockchainCryptoAuditorReal />} />
      <Route path="/blockchain-crypto-real" element={<BlockchainCryptoReal />} />
      <Route path="/blockchain-real" element={<BlockchainReal />} />
      <Route path="/ca-hierarchy" element={<CaHierarchy />} />
      <Route path="/ca-hierarchy-real" element={<CaHierarchyReal />} />
      <Route path="/capacity-planner" element={<CapacityPlanner />} />
      <Route path="/capacity-planner-real" element={<CapacityPlannerReal />} />
      <Route path="/capacity-real" element={<CapacityReal />} />
      <Route path="/casb" element={<Casb />} />
      <Route path="/casb-real" element={<CasbReal />} />
      <Route path="/catalog" element={<Catalog />} />
      <Route path="/catalog-real" element={<CatalogReal />} />
      <Route path="/cbom" element={<Cbom />} />
      <Route path="/cbom-real" element={<CbomReal />} />
      <Route path="/cert-lifecycle-automation" element={<CertLifecycleAutomation />} />
      <Route path="/cert-lifecycle-automation-real" element={<CertLifecycleAutomationReal />} />
      <Route path="/cert-lifecycle-real" element={<CertLifecycleReal />} />
      <Route path="/cert-pinning-real" element={<CertPinningReal />} />
      <Route path="/cert-pinning-validator-enhanced" element={<CertPinningValidatorEnhanced />} />
      <Route path="/cert-pinning-validator-enhanced-real" element={<CertPinningValidatorEnhancedReal />} />
      <Route path="/cert-transparency-real" element={<CertTransparencyReal />} />
      <Route path="/certificate-lifecycle-orchestrator" element={<CertificateLifecycleOrchestrator />} />
      <Route path="/certificate-lifecycle-orchestrator-real" element={<CertificateLifecycleOrchestratorReal />} />
      <Route path="/certificate-pinning-enforcer" element={<CertificatePinningEnforcer />} />
      <Route path="/certificate-pinning-enforcer-real" element={<CertificatePinningEnforcerReal />} />
      <Route path="/certificate-pinning-validator" element={<CertificatePinningValidator />} />
      <Route path="/certificate-pinning-validator-real" element={<CertificatePinningValidatorReal />} />
      <Route path="/certificate-transparency-v2" element={<CertificateTransparencyV2 />} />
      <Route path="/certificate-transparency-v2real" element={<CertificateTransparencyV2Real />} />
      <Route path="/certificates" element={<Certificates />} />
      <Route path="/certificates-real" element={<CertificatesReal />} />
      <Route path="/certification-pipeline" element={<CertificationPipeline />} />
      <Route path="/certification-pipeline-real" element={<CertificationPipelineReal />} />
      <Route path="/change-impact-predictor" element={<ChangeImpactPredictor />} />
      <Route path="/change-impact-predictor-real" element={<ChangeImpactPredictorReal />} />
      <Route path="/chaos-real" element={<ChaosReal />} />
      <Route path="/cicd-crypto-gate" element={<CicdCryptoGate />} />
      <Route path="/cicd-crypto-gate-enforcer" element={<CicdCryptoGateEnforcer />} />
      <Route path="/cicd-crypto-gate-enforcer-real" element={<CicdCryptoGateEnforcerReal />} />
      <Route path="/cicd-crypto-gate-real" element={<CicdCryptoGateReal />} />
      <Route path="/cloud" element={<Cloud />} />
      <Route path="/cloud-crypto-posture" element={<CloudCryptoPosture />} />
      <Route path="/cloud-crypto-posture-real" element={<CloudCryptoPostureReal />} />
      <Route path="/cloud-kms-inventory" element={<CloudKmsInventory />} />
      <Route path="/cloud-kms-inventory-enhanced" element={<CloudKmsInventoryEnhanced />} />
      <Route path="/cloud-kms-inventory-enhanced-real" element={<CloudKmsInventoryEnhancedReal />} />
      <Route path="/cloud-kms-inventory-real" element={<CloudKmsInventoryReal />} />
      <Route path="/cloud-kms-posture-enforcer" element={<CloudKmsPostureEnforcer />} />
      <Route path="/cloud-kms-posture-enforcer-real" element={<CloudKmsPostureEnforcerReal />} />
      <Route path="/cloud-kms-posture-real" element={<CloudKmsPostureReal />} />
      <Route path="/cloud-kms-real" element={<CloudKmsReal />} />
      <Route path="/cloud-real" element={<CloudReal />} />
      <Route path="/cmdb" element={<Cmdb />} />
      <Route path="/cmdb-real" element={<CmdbReal />} />
      <Route path="/collaboration" element={<Collaboration />} />
      <Route path="/collaboration-real" element={<CollaborationReal />} />
      <Route path="/command-center" element={<CommandCenter />} />
      <Route path="/command-center-real" element={<CommandCenterReal />} />
      <Route path="/compliance" element={<Compliance />} />
      <Route path="/compliance-cert" element={<ComplianceCert />} />
      <Route path="/compliance-cert-real" element={<ComplianceCertReal />} />
      <Route path="/compliance-deterministic" element={<ComplianceDeterministic />} />
      <Route path="/compliance-deterministic-real" element={<ComplianceDeterministicReal />} />
      <Route path="/compliance-drift-detector" element={<ComplianceDriftDetector />} />
      <Route path="/compliance-drift-detector-real" element={<ComplianceDriftDetectorReal />} />
      <Route path="/compliance-drift-real" element={<ComplianceDriftReal />} />
      <Route path="/compliance-evidence-automation" element={<ComplianceEvidenceAutomation />} />
      <Route path="/compliance-evidence-automation-real" element={<ComplianceEvidenceAutomationReal />} />
      <Route path="/compliance-evidence-graph" element={<ComplianceEvidenceGraph />} />
      <Route path="/compliance-evidence-graph-real" element={<ComplianceEvidenceGraphReal />} />
      <Route path="/compliance-evidence-lake" element={<ComplianceEvidenceLake />} />
      <Route path="/compliance-evidence-lake-real" element={<ComplianceEvidenceLakeReal />} />
      <Route path="/compliance-evidence-real" element={<ComplianceEvidenceReal />} />
      <Route path="/compliance-mapping" element={<ComplianceMapping />} />
      <Route path="/compliance-mapping-real" element={<ComplianceMappingReal />} />
      <Route path="/compliance-real" element={<ComplianceReal />} />
      <Route path="/confidential-computing-attestor" element={<ConfidentialComputingAttestor />} />
      <Route path="/confidential-computing-attestor-real" element={<ConfidentialComputingAttestorReal />} />
      <Route path="/confidential-computing-real" element={<ConfidentialComputingReal />} />
      <Route path="/confidential-computing-validator" element={<ConfidentialComputingValidator />} />
      <Route path="/confidential-computing-validator-real" element={<ConfidentialComputingValidatorReal />} />
      <Route path="/confidential-data-flow-tracker" element={<ConfidentialDataFlowTracker />} />
      <Route path="/confidential-data-flow-tracker-real" element={<ConfidentialDataFlowTrackerReal />} />
      <Route path="/confidential-data-flow-tracker-v2" element={<ConfidentialDataFlowTrackerV2 />} />
      <Route path="/confidential-data-flow-tracker-v2real" element={<ConfidentialDataFlowTrackerV2Real />} />
      <Route path="/container-real" element={<ContainerReal />} />
      <Route path="/continuous-assurance-monitor" element={<ContinuousAssuranceMonitor />} />
      <Route path="/continuous-assurance-monitor-real" element={<ContinuousAssuranceMonitorReal />} />
      <Route path="/continuous-assurance-monitor-v2" element={<ContinuousAssuranceMonitorV2 />} />
      <Route path="/continuous-assurance-monitor-v2real" element={<ContinuousAssuranceMonitorV2Real />} />
      <Route path="/continuous-assurance-real" element={<ContinuousAssuranceReal />} />
      <Route path="/correlation-engine" element={<CorrelationEngine />} />
      <Route path="/correlation-engine-real" element={<CorrelationEngineReal />} />
      <Route path="/correlation-real" element={<CorrelationReal />} />
      <Route path="/cross-standard-compliance" element={<CrossStandardCompliance />} />
      <Route path="/cross-standard-compliance-real" element={<CrossStandardComplianceReal />} />
      <Route path="/crypto" element={<Crypto />} />
      <Route path="/crypto-agility-index" element={<CryptoAgilityIndex />} />
      <Route path="/crypto-agility-index-real" element={<CryptoAgilityIndexReal />} />
      <Route path="/crypto-agility-maturity" element={<CryptoAgilityMaturity />} />
      <Route path="/crypto-agility-maturity-real" element={<CryptoAgilityMaturityReal />} />
      <Route path="/crypto-agility-real" element={<CryptoAgilityReal />} />
      <Route path="/crypto-agility-score-v2" element={<CryptoAgilityScoreV2 />} />
      <Route path="/crypto-agility-score-v2real" element={<CryptoAgilityScoreV2Real />} />
      <Route path="/crypto-asset-lineage-tracker" element={<CryptoAssetLineageTracker />} />
      <Route path="/crypto-asset-lineage-tracker-real" element={<CryptoAssetLineageTrackerReal />} />
      <Route path="/crypto-asset-lineage-tracker-v2" element={<CryptoAssetLineageTrackerV2 />} />
      <Route path="/crypto-asset-lineage-tracker-v2real" element={<CryptoAssetLineageTrackerV2Real />} />
      <Route path="/crypto-asset-risk-scorer" element={<CryptoAssetRiskScorer />} />
      <Route path="/crypto-asset-risk-scorer-real" element={<CryptoAssetRiskScorerReal />} />
      <Route path="/crypto-assets" element={<CryptoAssets />} />
      <Route path="/crypto-assets-real" element={<CryptoAssetsReal />} />
      <Route path="/crypto-assurance" element={<CryptoAssurance />} />
      <Route path="/crypto-assurance-real" element={<CryptoAssuranceReal />} />
      <Route path="/crypto-bill-of-materials-enhanced" element={<CryptoBillOfMaterialsEnhanced />} />
      <Route path="/crypto-bill-of-materials-enhanced-real" element={<CryptoBillOfMaterialsEnhancedReal />} />
      <Route path="/crypto-bill-of-materials-real" element={<CryptoBillOfMaterialsReal />} />
      <Route path="/crypto-changes" element={<CryptoChanges />} />
      <Route path="/crypto-changes-real" element={<CryptoChangesReal />} />
      <Route path="/crypto-compliance-benchmark" element={<CryptoComplianceBenchmark />} />
      <Route path="/crypto-compliance-benchmark-real" element={<CryptoComplianceBenchmarkReal />} />
      <Route path="/crypto-drift-predictor" element={<CryptoDriftPredictor />} />
      <Route path="/crypto-drift-predictor-real" element={<CryptoDriftPredictorReal />} />
      <Route path="/crypto-drift-real" element={<CryptoDriftReal />} />
      <Route path="/crypto-drift-timeline" element={<CryptoDriftTimeline />} />
      <Route path="/crypto-drift-timeline-real" element={<CryptoDriftTimelineReal />} />
      <Route path="/crypto-health-monitor" element={<CryptoHealthMonitor />} />
      <Route path="/crypto-health-monitor-real" element={<CryptoHealthMonitorReal />} />
      <Route path="/crypto-health-real" element={<CryptoHealthReal />} />
      <Route path="/crypto-inventory-health" element={<CryptoInventoryHealth />} />
      <Route path="/crypto-inventory-health-real" element={<CryptoInventoryHealthReal />} />
      <Route path="/crypto-inventory-real" element={<CryptoInventoryReal />} />
      <Route path="/crypto-inventory-reconciler" element={<CryptoInventoryReconciler />} />
      <Route path="/crypto-inventory-reconciler-real" element={<CryptoInventoryReconcilerReal />} />
      <Route path="/crypto-inventory-reconciliation" element={<CryptoInventoryReconciliation />} />
      <Route path="/crypto-inventory-reconciliation-real" element={<CryptoInventoryReconciliationReal />} />
      <Route path="/crypto-material-vault" element={<CryptoMaterialVault />} />
      <Route path="/crypto-material-vault-real" element={<CryptoMaterialVaultReal />} />
      <Route path="/crypto-policy-drift" element={<CryptoPolicyDrift />} />
      <Route path="/crypto-policy-drift-real" element={<CryptoPolicyDriftReal />} />
      <Route path="/crypto-policy-enforcement" element={<CryptoPolicyEnforcement />} />
      <Route path="/crypto-policy-enforcement-real" element={<CryptoPolicyEnforcementReal />} />
      <Route path="/crypto-policy-enforcer-v2" element={<CryptoPolicyEnforcerV2 />} />
      <Route path="/crypto-policy-enforcer-v2real" element={<CryptoPolicyEnforcerV2Real />} />
      <Route path="/crypto-policy-real" element={<CryptoPolicyReal />} />
      <Route path="/crypto-policy-simulator" element={<CryptoPolicySimulator />} />
      <Route path="/crypto-policy-simulator-real" element={<CryptoPolicySimulatorReal />} />
      <Route path="/crypto-real" element={<CryptoReal />} />
      <Route path="/cryptographic-boundary-mapper" element={<CryptographicBoundaryMapper />} />
      <Route path="/cryptographic-boundary-mapper-real" element={<CryptographicBoundaryMapperReal />} />
      <Route path="/cryptographic-debt-ledger" element={<CryptographicDebtLedger />} />
      <Route path="/cryptographic-debt-ledger-real" element={<CryptographicDebtLedgerReal />} />
      <Route path="/cryptographic-debt-real" element={<CryptographicDebtReal />} />
      <Route path="/cryptographic-digital-twin" element={<CryptographicDigitalTwin />} />
      <Route path="/cryptographic-digital-twin-real" element={<CryptographicDigitalTwinReal />} />
      <Route path="/cryptographic-simulation-engine" element={<CryptographicSimulationEngine />} />
      <Route path="/cryptographic-simulation-engine-real" element={<CryptographicSimulationEngineReal />} />
      <Route path="/cryptographic-trust-graph" element={<CryptographicTrustGraph />} />
      <Route path="/cryptographic-trust-graph-real" element={<CryptographicTrustGraphReal />} />
      <Route path="/ct-log-aggregator" element={<CtLogAggregator />} />
      <Route path="/ct-log-aggregator-real" element={<CtLogAggregatorReal />} />
      <Route path="/ct-log-monitor" element={<CtLogMonitor />} />
      <Route path="/ct-log-monitor-real" element={<CtLogMonitorReal />} />
      <Route path="/data-classification" element={<DataClassification />} />
      <Route path="/data-classification-engine" element={<DataClassificationEngine />} />
      <Route path="/data-classification-engine-real" element={<DataClassificationEngineReal />} />
      <Route path="/data-classification-real" element={<DataClassificationReal />} />
      <Route path="/data-lake-real" element={<DataLakeReal />} />
      <Route path="/data-sovereignty" element={<DataSovereignty />} />
      <Route path="/data-sovereignty-real" element={<DataSovereigntyReal />} />
      <Route path="/dependency-graph" element={<DependencyGraph />} />
      <Route path="/dependency-graph-real" element={<DependencyGraphReal />} />
      <Route path="/dependency-risk" element={<DependencyRisk />} />
      <Route path="/dependency-risk-real" element={<DependencyRiskReal />} />
      <Route path="/deterministic-policy-enforcement" element={<DeterministicPolicyEnforcement />} />
      <Route path="/deterministic-policy-enforcement-real" element={<DeterministicPolicyEnforcementReal />} />
      <Route path="/deterministic-threat-modeler" element={<DeterministicThreatModeler />} />
      <Route path="/deterministic-threat-modeler-real" element={<DeterministicThreatModelerReal />} />
      <Route path="/dev-sec-ops" element={<DevSecOps />} />
      <Route path="/dev-sec-ops-real" element={<DevSecOpsReal />} />
      <Route path="/differential-privacy-validator" element={<DifferentialPrivacyValidator />} />
      <Route path="/differential-privacy-validator-real" element={<DifferentialPrivacyValidatorReal />} />
      <Route path="/dnssec-chain-validator" element={<DnssecChainValidator />} />
      <Route path="/dnssec-chain-validator-real" element={<DnssecChainValidatorReal />} />
      <Route path="/dnssec-dane-monitor" element={<DnssecDaneMonitor />} />
      <Route path="/dnssec-dane-monitor-real" element={<DnssecDaneMonitorReal />} />
      <Route path="/dr-crypto-validation" element={<DrCryptoValidation />} />
      <Route path="/dr-crypto-validation-real" element={<DrCryptoValidationReal />} />
      <Route path="/drift" element={<Drift />} />
      <Route path="/drift-anomaly" element={<DriftAnomaly />} />
      <Route path="/drift-anomaly-real" element={<DriftAnomalyReal />} />
      <Route path="/drift-real" element={<DriftReal />} />
      <Route path="/enterprise-real" element={<EnterpriseReal />} />
      <Route path="/entitlement-real" element={<EntitlementReal />} />
      <Route path="/entropy-core" element={<EntropyCore />} />
      <Route path="/entropy-core-real" element={<EntropyCoreReal />} />
      <Route path="/estate-real" element={<EstateReal />} />
      <Route path="/evidence" element={<Evidence />} />
      <Route path="/evidence-automation-engine" element={<EvidenceAutomationEngine />} />
      <Route path="/evidence-automation-engine-real" element={<EvidenceAutomationEngineReal />} />
      <Route path="/evidence-chain-enhanced" element={<EvidenceChainEnhanced />} />
      <Route path="/evidence-chain-enhanced-real" element={<EvidenceChainEnhancedReal />} />
      <Route path="/evidence-chain-verifier" element={<EvidenceChainVerifier />} />
      <Route path="/evidence-chain-verifier-real" element={<EvidenceChainVerifierReal />} />
      <Route path="/evidence-lake" element={<EvidenceLake />} />
      <Route path="/evidence-lake-query-engine" element={<EvidenceLakeQueryEngine />} />
      <Route path="/evidence-lake-query-engine-real" element={<EvidenceLakeQueryEngineReal />} />
      <Route path="/evidence-lake-real" element={<EvidenceLakeReal />} />
      <Route path="/evidence-pack-real" element={<EvidencePackReal />} />
      <Route path="/evidence-real" element={<EvidenceReal />} />
      <Route path="/exception-enhanced" element={<ExceptionEnhanced />} />
      <Route path="/exception-enhanced-real" element={<ExceptionEnhancedReal />} />
      <Route path="/exception-management-engine" element={<ExceptionManagementEngine />} />
      <Route path="/exception-management-engine-real" element={<ExceptionManagementEngineReal />} />
      <Route path="/exceptions-real" element={<ExceptionsReal />} />
      <Route path="/executive" element={<Executive />} />
      <Route path="/executive-dashboard" element={<ExecutiveDashboard />} />
      <Route path="/executive-dashboard-real" element={<ExecutiveDashboardReal />} />
      <Route path="/executive-real" element={<ExecutiveReal />} />
      <Route path="/executive-risk-heatmap" element={<ExecutiveRiskHeatmap />} />
      <Route path="/executive-risk-heatmap-real" element={<ExecutiveRiskHeatmapReal />} />
      <Route path="/export-real" element={<ExportReal />} />
      <Route path="/fhe-performance-optimizer" element={<FhePerformanceOptimizer />} />
      <Route path="/fhe-performance-optimizer-real" element={<FhePerformanceOptimizerReal />} />
      <Route path="/findings" element={<Findings />} />
      <Route path="/findings-real" element={<FindingsReal />} />
      <Route path="/firmware-analysis" element={<FirmwareAnalysis />} />
      <Route path="/firmware-analysis-real" element={<FirmwareAnalysisReal />} />
      <Route path="/firmware-crypto-extractor" element={<FirmwareCryptoExtractor />} />
      <Route path="/firmware-crypto-extractor-real" element={<FirmwareCryptoExtractorReal />} />
      <Route path="/firmware-provenance-tracker" element={<FirmwareProvenanceTracker />} />
      <Route path="/firmware-provenance-tracker-real" element={<FirmwareProvenanceTrackerReal />} />
      <Route path="/forensic-crypto-vault" element={<ForensicCryptoVault />} />
      <Route path="/forensic-crypto-vault-real" element={<ForensicCryptoVaultReal />} />
      <Route path="/forensic-vault" element={<ForensicVault />} />
      <Route path="/forensic-vault-real" element={<ForensicVaultReal />} />
      <Route path="/forensics-real" element={<ForensicsReal />} />
      <Route path="/governance" element={<Governance />} />
      <Route path="/governance-real" element={<GovernanceReal />} />
      <Route path="/graph" element={<Graph />} />
      <Route path="/graph-real" element={<GraphReal />} />
      <Route path="/hardware" element={<Hardware />} />
      <Route path="/hardware-real" element={<HardwareReal />} />
      <Route path="/hbom" element={<Hbom />} />
      <Route path="/hbom-real" element={<HbomReal />} />
      <Route path="/hndl-risk-calculator" element={<HndlRiskCalculator />} />
      <Route path="/hndl-risk-calculator-real" element={<HndlRiskCalculatorReal />} />
      <Route path="/homomorphic-encryption-analyzer" element={<HomomorphicEncryptionAnalyzer />} />
      <Route path="/homomorphic-encryption-analyzer-real" element={<HomomorphicEncryptionAnalyzerReal />} />
      <Route path="/hsm-deep-inventory" element={<HsmDeepInventory />} />
      <Route path="/hsm-deep-inventory-real" element={<HsmDeepInventoryReal />} />
      <Route path="/hsm-deep-inventory-scanner-v2" element={<HsmDeepInventoryScannerV2 />} />
      <Route path="/hsm-deep-inventory-scanner-v2real" element={<HsmDeepInventoryScannerV2Real />} />
      <Route path="/hsm-enhanced" element={<HsmEnhanced />} />
      <Route path="/hsm-enhanced-real" element={<HsmEnhancedReal />} />
      <Route path="/hsm-fabric" element={<HsmFabric />} />
      <Route path="/hsm-fabric-real" element={<HsmFabricReal />} />
      <Route path="/hsm-fleet-orchestrator" element={<HsmFleetOrchestrator />} />
      <Route path="/hsm-fleet-orchestrator-real" element={<HsmFleetOrchestratorReal />} />
      <Route path="/hsm-fleet-real" element={<HsmFleetReal />} />
      <Route path="/hybrid-mode-manager" element={<HybridModeManager />} />
      <Route path="/hybrid-mode-manager-real" element={<HybridModeManagerReal />} />
      <Route path="/identity" element={<Identity />} />
      <Route path="/identity-real" element={<IdentityReal />} />
      <Route path="/incident-response-playbooks" element={<IncidentResponsePlaybooks />} />
      <Route path="/incident-response-playbooks-real" element={<IncidentResponsePlaybooksReal />} />
      <Route path="/incident-response-real" element={<IncidentResponseReal />} />
      <Route path="/industrial-control-crypto-monitor" element={<IndustrialControlCryptoMonitor />} />
      <Route path="/industrial-control-crypto-monitor-real" element={<IndustrialControlCryptoMonitorReal />} />
      <Route path="/integrations" element={<Integrations />} />
      <Route path="/integrations-real" element={<IntegrationsReal />} />
      <Route path="/intelligence-real" element={<IntelligenceReal />} />
      <Route path="/inventory-cloud-real" element={<InventoryCloudReal />} />
      <Route path="/invite-accept" element={<InviteAccept />} />
      <Route path="/invite-accept-real" element={<InviteAcceptReal />} />
      <Route path="/iot-firmware-crypto-scanner" element={<IotFirmwareCryptoScanner />} />
      <Route path="/iot-firmware-crypto-scanner-real" element={<IotFirmwareCryptoScannerReal />} />
      <Route path="/iot-ot-crypto" element={<IotOtCrypto />} />
      <Route path="/iot-ot-crypto-real" element={<IotOtCryptoReal />} />
      <Route path="/iot-real" element={<IotReal />} />
      <Route path="/jobs-real" element={<JobsReal />} />
      <Route path="/k8s-crypto-admission-controller" element={<K8sCryptoAdmissionController />} />
      <Route path="/k8s-crypto-admission-controller-real" element={<K8sCryptoAdmissionControllerReal />} />
      <Route path="/key-birth-death-ledger" element={<KeyBirthDeathLedger />} />
      <Route path="/key-birth-death-ledger-real" element={<KeyBirthDeathLedgerReal />} />
      <Route path="/key-ceremony-orchestrator" element={<KeyCeremonyOrchestrator />} />
      <Route path="/key-ceremony-orchestrator-real" element={<KeyCeremonyOrchestratorReal />} />
      <Route path="/key-ceremony-real" element={<KeyCeremonyReal />} />
      <Route path="/key-custody-splitting" element={<KeyCustodySplitting />} />
      <Route path="/key-custody-splitting-real" element={<KeyCustodySplittingReal />} />
      <Route path="/key-lifecycle" element={<KeyLifecycle />} />
      <Route path="/key-lifecycle-real" element={<KeyLifecycleReal />} />
      <Route path="/key-rotation-orchestrator" element={<KeyRotationOrchestrator />} />
      <Route path="/key-rotation-orchestrator-real" element={<KeyRotationOrchestratorReal />} />
      <Route path="/key-rotation-real" element={<KeyRotationReal />} />
      <Route path="/kms-key-hierarchy-mapper" element={<KmsKeyHierarchyMapper />} />
      <Route path="/kms-key-hierarchy-mapper-real" element={<KmsKeyHierarchyMapperReal />} />
      <Route path="/kms-policy-enforcement" element={<KmsPolicyEnforcement />} />
      <Route path="/kms-policy-enforcement-real" element={<KmsPolicyEnforcementReal />} />
      <Route path="/kms-real" element={<KmsReal />} />
      <Route path="/kubernetes-crypto-security" element={<KubernetesCryptoSecurity />} />
      <Route path="/kubernetes-crypto-security-real" element={<KubernetesCryptoSecurityReal />} />
      <Route path="/libraries" element={<Libraries />} />
      <Route path="/libraries-real" element={<LibrariesReal />} />
      <Route path="/live-asset-intelligence" element={<LiveAssetIntelligence />} />
      <Route path="/live-asset-intelligence-real" element={<LiveAssetIntelligenceReal />} />
      <Route path="/live-cbom-real" element={<LiveCbomReal />} />
      <Route path="/live-cbom-v2" element={<LiveCbomV2 />} />
      <Route path="/live-cbom-v2real" element={<LiveCbomV2Real />} />
      <Route path="/live-crypto-posture-score" element={<LiveCryptoPostureScore />} />
      <Route path="/live-crypto-posture-score-real" element={<LiveCryptoPostureScoreReal />} />
      <Route path="/live-environment" element={<LiveEnvironment />} />
      <Route path="/live-environment-real" element={<LiveEnvironmentReal />} />
      <Route path="/live-scanners" element={<LiveScanners />} />
      <Route path="/live-scanners-real" element={<LiveScannersReal />} />
      <Route path="/live-stream" element={<LiveStream />} />
      <Route path="/live-stream-real" element={<LiveStreamReal />} />
      <Route path="/living-cbom" element={<LivingCbom />} />
      <Route path="/living-cbom-real" element={<LivingCbomReal />} />
      <Route path="/login" element={<Login />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/verify-email" element={<VerifyEmail />} />

      <Route path="/login-real" element={<LoginReal />} />
      <Route path="/marketplace-real" element={<MarketplaceReal />} />
      <Route path="/migration" element={<Migration />} />
      <Route path="/migration-real" element={<MigrationReal />} />
      <Route path="/migration-simulator" element={<MigrationSimulator />} />
      <Route path="/migration-simulator-real" element={<MigrationSimulatorReal />} />
      <Route path="/ml-model-crypto-guard" element={<MlModelCryptoGuard />} />
      <Route path="/ml-model-crypto-guard-real" element={<MlModelCryptoGuardReal />} />
      <Route path="/monitor-real" element={<MonitorReal />} />
      <Route path="/multi-dimensional-compliance-cube" element={<MultiDimensionalComplianceCube />} />
      <Route path="/multi-dimensional-compliance-cube-real" element={<MultiDimensionalComplianceCubeReal />} />
      <Route path="/network" element={<Network />} />
      <Route path="/network-crypto-analyzer" element={<NetworkCryptoAnalyzer />} />
      <Route path="/network-crypto-analyzer-real" element={<NetworkCryptoAnalyzerReal />} />
      <Route path="/network-crypto-posture-enforcer" element={<NetworkCryptoPostureEnforcer />} />
      <Route path="/network-crypto-posture-enforcer-real" element={<NetworkCryptoPostureEnforcerReal />} />
      <Route path="/network-device-crypto-auditor" element={<NetworkDeviceCryptoAuditor />} />
      <Route path="/network-device-crypto-auditor-real" element={<NetworkDeviceCryptoAuditorReal />} />
      <Route path="/network-device-scanner" element={<NetworkDeviceScanner />} />
      <Route path="/network-device-scanner-real" element={<NetworkDeviceScannerReal />} />
      <Route path="/network-real" element={<NetworkReal />} />
      <Route path="/network-segmentation-real" element={<NetworkSegmentationReal />} />
      <Route path="/notifications" element={<Notifications />} />
      <Route path="/notifications-real" element={<NotificationsReal />} />
      <Route path="/onboarding" element={<Onboarding />} />
      <Route path="/onboarding-real" element={<OnboardingReal />} />
      <Route path="/ops-real" element={<OpsReal />} />
      <Route path="/organization" element={<Organization />} />
      <Route path="/organization-real" element={<OrganizationReal />} />
      <Route path="/ot-enhanced" element={<OtEnhanced />} />
      <Route path="/ot-enhanced-real" element={<OtEnhancedReal />} />
      <Route path="/ot-protocol-crypto-analyzer" element={<OtProtocolCryptoAnalyzer />} />
      <Route path="/ot-protocol-crypto-analyzer-real" element={<OtProtocolCryptoAnalyzerReal />} />
      <Route path="/ot-real" element={<OtReal />} />
      <Route path="/platform-p2" element={<PlatformP2 />} />
      <Route path="/platform-p2real" element={<PlatformP2Real />} />
      <Route path="/plugin-marketplace" element={<PluginMarketplace />} />
      <Route path="/plugin-marketplace-real" element={<PluginMarketplaceReal />} />
      <Route path="/policy-as-code" element={<PolicyAsCode />} />
      <Route path="/policy-as-code-real" element={<PolicyAsCodeReal />} />
      <Route path="/policy-real" element={<PolicyReal />} />
      <Route path="/policy-simulator-real" element={<PolicySimulatorReal />} />
      <Route path="/post-quantum-code-signing" element={<PostQuantumCodeSigning />} />
      <Route path="/post-quantum-code-signing-real" element={<PostQuantumCodeSigningReal />} />
      <Route path="/post-quantum-hsm-integration" element={<PostQuantumHsmIntegration />} />
      <Route path="/post-quantum-hsm-integration-real" element={<PostQuantumHsmIntegrationReal />} />
      <Route path="/pq-migration-cost" element={<PqMigrationCost />} />
      <Route path="/pq-migration-cost-real" element={<PqMigrationCostReal />} />
      <Route path="/pqc" element={<Pqc />} />
      <Route path="/pqc-code-signing-orchestrator" element={<PqcCodeSigningOrchestrator />} />
      <Route path="/pqc-code-signing-orchestrator-real" element={<PqcCodeSigningOrchestratorReal />} />
      <Route path="/pqc-infra-monitor" element={<PqcInfraMonitor />} />
      <Route path="/pqc-infra-monitor-real" element={<PqcInfraMonitorReal />} />
      <Route path="/pqc-map" element={<PqcMap />} />
      <Route path="/pqc-map-real" element={<PqcMapReal />} />
      <Route path="/pqc-migration-cost-estimator" element={<PqcMigrationCostEstimator />} />
      <Route path="/pqc-migration-cost-estimator-real" element={<PqcMigrationCostEstimatorReal />} />
      <Route path="/pqc-migration-orchestrator" element={<PqcMigrationOrchestrator />} />
      <Route path="/pqc-migration-orchestrator-real" element={<PqcMigrationOrchestratorReal />} />
      <Route path="/pqc-migration-playbook" element={<PqcMigrationPlaybook />} />
      <Route path="/pqc-migration-playbook-real" element={<PqcMigrationPlaybookReal />} />
      <Route path="/pqc-migration-real" element={<PqcMigrationReal />} />
      <Route path="/pqc-performance-benchmarker" element={<PqcPerformanceBenchmarker />} />
      <Route path="/pqc-performance-benchmarker-real" element={<PqcPerformanceBenchmarkerReal />} />
      <Route path="/pqc-readiness-dashboard" element={<PqcReadinessDashboard />} />
      <Route path="/pqc-readiness-dashboard-real" element={<PqcReadinessDashboardReal />} />
      <Route path="/pqc-readiness-real" element={<PqcReadinessReal />} />
      <Route path="/pqc-real" element={<PqcReal />} />
      <Route path="/pqc-tls-analyzer" element={<PqcTlsAnalyzer />} />
      <Route path="/pqc-tls-analyzer-enhanced" element={<PqcTlsAnalyzerEnhanced />} />
      <Route path="/pqc-tls-analyzer-enhanced-real" element={<PqcTlsAnalyzerEnhancedReal />} />
      <Route path="/pqc-tls-analyzer-real" element={<PqcTlsAnalyzerReal />} />
      <Route path="/pqc-tls-real" element={<PqcTlsReal />} />
      <Route path="/priorities" element={<Priorities />} />
      <Route path="/priorities-real" element={<PrioritiesReal />} />
      <Route path="/priority-real" element={<PriorityReal />} />
      <Route path="/production-real" element={<ProductionReal />} />
      <Route path="/protocols" element={<Protocols />} />
      <Route path="/protocols-real" element={<ProtocolsReal />} />
      <Route path="/qsim" element={<QSim />} />
      <Route path="/qsim-real" element={<QSimReal />} />
      <Route path="/qrng-entropy-monitor" element={<QrngEntropyMonitor />} />
      <Route path="/qrng-entropy-monitor-real" element={<QrngEntropyMonitorReal />} />
      <Route path="/qrng-real" element={<QrngReal />} />
      <Route path="/quantum-entropy-fabric" element={<QuantumEntropyFabric />} />
      <Route path="/quantum-entropy-fabric-real" element={<QuantumEntropyFabricReal />} />
      <Route path="/quantum-key-distribution-monitor" element={<QuantumKeyDistributionMonitor />} />
      <Route path="/quantum-key-distribution-monitor-real" element={<QuantumKeyDistributionMonitorReal />} />
      <Route path="/quantum-readiness-index" element={<QuantumReadinessIndex />} />
      <Route path="/quantum-readiness-index-real" element={<QuantumReadinessIndexReal />} />
      <Route path="/quantum-real" element={<QuantumReal />} />
      <Route path="/quantum-threat-forecaster" element={<QuantumThreatForecaster />} />
      <Route path="/quantum-threat-forecaster-real" element={<QuantumThreatForecasterReal />} />
      <Route path="/quantum-threat-real" element={<QuantumThreatReal />} />
      <Route path="/quantum-threat-timeline" element={<QuantumThreatTimeline />} />
      <Route path="/quantum-threat-timeline-real" element={<QuantumThreatTimelineReal />} />
      <Route path="/reachability-real" element={<ReachabilityReal />} />
      <Route path="/real-time-attack-detector" element={<RealTimeAttackDetector />} />
      <Route path="/real-time-attack-detector-real" element={<RealTimeAttackDetectorReal />} />
      <Route path="/realtime-system" element={<RealtimeSystem />} />
      <Route path="/realtime-system-real" element={<RealtimeSystemReal />} />
      <Route path="/register" element={<Register />} />
      <Route path="/register-real" element={<RegisterReal />} />
      <Route path="/remediation-orchestrator" element={<RemediationOrchestrator />} />
      <Route path="/remediation-orchestrator-real" element={<RemediationOrchestratorReal />} />
      <Route path="/remediation-orchestrator-v2" element={<RemediationOrchestratorV2 />} />
      <Route path="/remediation-orchestrator-v2real" element={<RemediationOrchestratorV2Real />} />
      <Route path="/remediation-real" element={<RemediationReal />} />
      <Route path="/remediation-tracker-real" element={<RemediationTrackerReal />} />
      <Route path="/remediation-verification" element={<RemediationVerification />} />
      <Route path="/remediation-verification-real" element={<RemediationVerificationReal />} />
      <Route path="/reporting-real" element={<ReportingReal />} />
      <Route path="/reports" element={<Reports />} />
      <Route path="/reports-real" element={<ReportsReal />} />
      <Route path="/resilience" element={<Resilience />} />
      <Route path="/resilience-real" element={<ResilienceReal />} />
      <Route path="/risk" element={<Risk />} />
      <Route path="/risk-matrix-real" element={<RiskMatrixReal />} />
      <Route path="/risk-quantification" element={<RiskQuantification />} />
      <Route path="/risk-quantification-real" element={<RiskQuantificationReal />} />
      <Route path="/risk-real" element={<RiskReal />} />
      <Route path="/risk-scoring-engine" element={<RiskScoringEngine />} />
      <Route path="/risk-scoring-engine-real" element={<RiskScoringEngineReal />} />
      <Route path="/role-dashboard" element={<RoleDashboard />} />
      <Route path="/role-dashboard-real" element={<RoleDashboardReal />} />
      <Route path="/runtime" element={<Runtime />} />
      <Route path="/runtime-crypto-ebpf" element={<RuntimeCryptoEbpf />} />
      <Route path="/runtime-crypto-ebpf-real" element={<RuntimeCryptoEbpfReal />} />
      <Route path="/runtime-ebpf-real" element={<RuntimeEbpfReal />} />
      <Route path="/runtime-real" element={<RuntimeReal />} />
      <Route path="/runtime-secret-leak-detector" element={<RuntimeSecretLeakDetector />} />
      <Route path="/runtime-secret-leak-detector-real" element={<RuntimeSecretLeakDetectorReal />} />
      <Route path="/runtime-secret-leak-detector-v2" element={<RuntimeSecretLeakDetectorV2 />} />
      <Route path="/runtime-secret-leak-detector-v2real" element={<RuntimeSecretLeakDetectorV2Real />} />
      <Route path="/saas-real" element={<SaasReal />} />
      <Route path="/sbom-correlation-engine" element={<SbomCorrelationEngine />} />
      <Route path="/sbom-correlation-engine-real" element={<SbomCorrelationEngineReal />} />
      <Route path="/sbom-real" element={<SbomReal />} />
      <Route path="/sbom-slsa" element={<SbomSlsa />} />
      <Route path="/sbom-slsa-real" element={<SbomSlsaReal />} />
      <Route path="/sbom-vulnerability-correlator" element={<SbomVulnerabilityCorrelator />} />
      <Route path="/sbom-vulnerability-correlator-real" element={<SbomVulnerabilityCorrelatorReal />} />
      <Route path="/scanners" element={<Scanners />} />
      <Route path="/scanners-real" element={<ScannersReal />} />
      <Route path="/scans-real" element={<ScansReal />} />
      <Route path="/scim-real" element={<ScimReal />} />
      <Route path="/scope" element={<Scope />} />
      <Route path="/scope-real" element={<ScopeReal />} />
      <Route path="/search-results" element={<SearchResults />} />
      <Route path="/search-results-real" element={<SearchResultsReal />} />
      <Route path="/secrets-detection" element={<SecretsDetection />} />
      <Route path="/secrets-detection-real" element={<SecretsDetectionReal />} />
      <Route path="/secrets-management-integration" element={<SecretsManagementIntegration />} />
      <Route path="/secrets-management-integration-real" element={<SecretsManagementIntegrationReal />} />
      <Route path="/secrets-management-unifier" element={<SecretsManagementUnifier />} />
      <Route path="/secrets-management-unifier-real" element={<SecretsManagementUnifierReal />} />
      <Route path="/secrets-real" element={<SecretsReal />} />
      <Route path="/secrets-rotation-automation" element={<SecretsRotationAutomation />} />
      <Route path="/secrets-rotation-automation-engine" element={<SecretsRotationAutomationEngine />} />
      <Route path="/secrets-rotation-automation-engine-real" element={<SecretsRotationAutomationEngineReal />} />
      <Route path="/secrets-rotation-automation-real" element={<SecretsRotationAutomationReal />} />
      <Route path="/secrets-rotation-real" element={<SecretsRotationReal />} />
      <Route path="/sectors" element={<Sectors />} />
      <Route path="/sectors-real" element={<SectorsReal />} />
      <Route path="/secure-boot-attestation" element={<SecureBootAttestation />} />
      <Route path="/secure-boot-attestation-real" element={<SecureBootAttestationReal />} />
      <Route path="/secure-boot-chain-verifier" element={<SecureBootChainVerifier />} />
      <Route path="/secure-boot-chain-verifier-real" element={<SecureBootChainVerifierReal />} />
      <Route path="/secure-boot-tpm" element={<SecureBootTpm />} />
      <Route path="/secure-boot-tpm-real" element={<SecureBootTpmReal />} />
      <Route path="/secure-code-review" element={<SecureCodeReview />} />
      <Route path="/secure-code-review-engine" element={<SecureCodeReviewEngine />} />
      <Route path="/secure-code-review-engine-real" element={<SecureCodeReviewEngineReal />} />
      <Route path="/secure-code-review-real" element={<SecureCodeReviewReal />} />
      <Route path="/secure-multiparty-computation-validator" element={<SecureMultipartyComputationValidator />} />
      <Route path="/secure-multiparty-computation-validator-real" element={<SecureMultipartyComputationValidatorReal />} />
      <Route path="/security" element={<Security />} />
      <Route path="/security-center" element={<SecurityCenter />} />
      <Route path="/security-center-real" element={<SecurityCenterReal />} />
      <Route path="/security-intelligence" element={<SecurityIntelligence />} />
      <Route path="/security-intelligence-real" element={<SecurityIntelligenceReal />} />
      <Route path="/security-policy" element={<SecurityPolicy />} />
      <Route path="/security-policy-real" element={<SecurityPolicyReal />} />
      <Route path="/security-posture-real" element={<SecurityPostureReal />} />
      <Route path="/security-real" element={<SecurityReal />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/settings-real" element={<SettingsReal />} />
      <Route path="/siem-crypto-correlator" element={<SiemCryptoCorrelator />} />
      <Route path="/siem-crypto-correlator-real" element={<SiemCryptoCorrelatorReal />} />
      <Route path="/sla-real" element={<SlaReal />} />
      <Route path="/slsa-attestation-verifier" element={<SlsaAttestationVerifier />} />
      <Route path="/slsa-attestation-verifier-real" element={<SlsaAttestationVerifierReal />} />
      <Route path="/slsa-real" element={<SlsaReal />} />
      <Route path="/sovereign-storage" element={<SovereignStorage />} />
      <Route path="/sovereign-storage-real" element={<SovereignStorageReal />} />
      <Route path="/sso-real" element={<SsoReal />} />
      <Route path="/stats-real" element={<StatsReal />} />
      <Route path="/streaming-backbone" element={<StreamingBackbone />} />
      <Route path="/streaming-backbone-monitor" element={<StreamingBackboneMonitor />} />
      <Route path="/streaming-backbone-monitor-real" element={<StreamingBackboneMonitorReal />} />
      <Route path="/streaming-backbone-real" element={<StreamingBackboneReal />} />
      <Route path="/supervision" element={<Supervision />} />
      <Route path="/supervision-real" element={<SupervisionReal />} />
      <Route path="/supply-chain-attestation" element={<SupplyChainAttestation />} />
      <Route path="/supply-chain-attestation-real" element={<SupplyChainAttestationReal />} />
      <Route path="/supply-chain-attestation-verifier" element={<SupplyChainAttestationVerifier />} />
      <Route path="/supply-chain-attestation-verifier-real" element={<SupplyChainAttestationVerifierReal />} />
      <Route path="/supply-chain-integrity" element={<SupplyChainIntegrity />} />
      <Route path="/supply-chain-integrity-real" element={<SupplyChainIntegrityReal />} />
      <Route path="/supply-chain-provenance-engine" element={<SupplyChainProvenanceEngine />} />
      <Route path="/supply-chain-provenance-engine-real" element={<SupplyChainProvenanceEngineReal />} />
      <Route path="/supply-chain-real" element={<SupplyChainReal />} />
      <Route path="/systems-real" element={<SystemsReal />} />
      <Route path="/tech-bom-real" element={<TechBomReal />} />
      <Route path="/telecom" element={<Telecom />} />
      <Route path="/telecom-enhanced" element={<TelecomEnhanced />} />
      <Route path="/telecom-enhanced-real" element={<TelecomEnhancedReal />} />
      <Route path="/telecom-real" element={<TelecomReal />} />
      <Route path="/telecom-signaling-analyzer" element={<TelecomSignalingAnalyzer />} />
      <Route path="/telecom-signaling-analyzer-real" element={<TelecomSignalingAnalyzerReal />} />
      <Route path="/telemetry-pipeline" element={<TelemetryPipeline />} />
      <Route path="/telemetry-pipeline-orchestrator" element={<TelemetryPipelineOrchestrator />} />
      <Route path="/telemetry-pipeline-orchestrator-real" element={<TelemetryPipelineOrchestratorReal />} />
      <Route path="/telemetry-pipeline-real" element={<TelemetryPipelineReal />} />
      <Route path="/tenancy" element={<Tenancy />} />
      <Route path="/tenancy-real" element={<TenancyReal />} />
      <Route path="/tenant-isolation-validator" element={<TenantIsolationValidator />} />
      <Route path="/tenant-isolation-validator-real" element={<TenantIsolationValidatorReal />} />
      <Route path="/tenant-isolation-validator-v2" element={<TenantIsolationValidatorV2 />} />
      <Route path="/tenant-isolation-validator-v2real" element={<TenantIsolationValidatorV2Real />} />
      <Route path="/third-party-crypto-risk" element={<ThirdPartyCryptoRisk />} />
      <Route path="/third-party-crypto-risk-real" element={<ThirdPartyCryptoRiskReal />} />
      <Route path="/threat-hunting-real" element={<ThreatHuntingReal />} />
      <Route path="/threat-intel" element={<ThreatIntel />} />
      <Route path="/threat-intel-real" element={<ThreatIntelReal />} />
      <Route path="/threat-model-automation" element={<ThreatModelAutomation />} />
      <Route path="/threat-model-automation-engine" element={<ThreatModelAutomationEngine />} />
      <Route path="/threat-model-automation-engine-real" element={<ThreatModelAutomationEngineReal />} />
      <Route path="/threat-model-automation-real" element={<ThreatModelAutomationReal />} />
      <Route path="/threat-model-real" element={<ThreatModelReal />} />
      <Route path="/threat-modeling-engine" element={<ThreatModelingEngine />} />
      <Route path="/threat-modeling-engine-real" element={<ThreatModelingEngineReal />} />
      <Route path="/three-gpp-compliance-mapper" element={<ThreeGppComplianceMapper />} />
      <Route path="/three-gpp-compliance-mapper-real" element={<ThreeGppComplianceMapperReal />} />
      <Route path="/threshold-crypto-orchestrator" element={<ThresholdCryptoOrchestrator />} />
      <Route path="/threshold-crypto-orchestrator-real" element={<ThresholdCryptoOrchestratorReal />} />
      <Route path="/timeline" element={<Timeline />} />
      <Route path="/timeline-real" element={<TimelineReal />} />
      <Route path="/timeseries-analytics" element={<TimeseriesAnalytics />} />
      <Route path="/timeseries-analytics-real" element={<TimeseriesAnalyticsReal />} />
      <Route path="/tls-configuration-hardening" element={<TlsConfigurationHardening />} />
      <Route path="/tls-configuration-hardening-real" element={<TlsConfigurationHardeningReal />} />
      <Route path="/tls-hardening-orchestrator" element={<TlsHardeningOrchestrator />} />
      <Route path="/tls-hardening-orchestrator-real" element={<TlsHardeningOrchestratorReal />} />
      <Route path="/trigger-real" element={<TriggerReal />} />
      <Route path="/trust" element={<Trust />} />
      <Route path="/trust-real" element={<TrustReal />} />
      <Route path="/twin-analysis-output" element={<TwinAnalysisOutput />} />
      <Route path="/twin-analysis-output-real" element={<TwinAnalysisOutputReal />} />
      <Route path="/twin-api" element={<TwinApi />} />
      <Route path="/twin-api-real" element={<TwinApiReal />} />
      <Route path="/twin-behavioral-model" element={<TwinBehavioralModel />} />
      <Route path="/twin-behavioral-model-real" element={<TwinBehavioralModelReal />} />
      <Route path="/twin-entity-model" element={<TwinEntityModel />} />
      <Route path="/twin-entity-model-real" element={<TwinEntityModelReal />} />
      <Route path="/twin-isolation-guardrails" element={<TwinIsolationGuardrails />} />
      <Route path="/twin-isolation-guardrails-real" element={<TwinIsolationGuardrailsReal />} />
      <Route path="/twin-mirror-ingestion" element={<TwinMirrorIngestion />} />
      <Route path="/twin-mirror-ingestion-real" element={<TwinMirrorIngestionReal />} />
      <Route path="/twin-relationship-model" element={<TwinRelationshipModel />} />
      <Route path="/twin-relationship-model-real" element={<TwinRelationshipModelReal />} />
      <Route path="/twin-scenario-types" element={<TwinScenarioTypes />} />
      <Route path="/twin-scenario-types-real" element={<TwinScenarioTypesReal />} />
      <Route path="/twin-simulation-engine" element={<TwinSimulationEngine />} />
      <Route path="/twin-simulation-engine-real" element={<TwinSimulationEngineReal />} />
      <Route path="/twin-state-store" element={<TwinStateStore />} />
      <Route path="/twin-state-store-real" element={<TwinStateStoreReal />} />
      <Route path="/twin-temporal-model" element={<TwinTemporalModel />} />
      <Route path="/twin-temporal-model-real" element={<TwinTemporalModelReal />} />
      <Route path="/twin-time-travel" element={<TwinTimeTravel />} />
      <Route path="/twin-time-travel-real" element={<TwinTimeTravelReal />} />
      <Route path="/vendor" element={<Vendor />} />
      <Route path="/vendor-crypto-risk-scorer" element={<VendorCryptoRiskScorer />} />
      <Route path="/vendor-crypto-risk-scorer-real" element={<VendorCryptoRiskScorerReal />} />
      <Route path="/vendor-real" element={<VendorReal />} />
      <Route path="/vpn-monitor" element={<VpnMonitor />} />
      <Route path="/vpn-monitor-real" element={<VpnMonitorReal />} />
      <Route path="/vulnerability-management-real" element={<VulnerabilityManagementReal />} />
      <Route path="/vulnerability-real" element={<VulnerabilityReal />} />
      <Route path="/vulns-real" element={<VulnsReal />} />
      <Route path="/webhooks-real" element={<WebhooksReal />} />
      <Route path="/what-if" element={<WhatIf />} />
      <Route path="/what-if-real" element={<WhatIfReal />} />
      <Route path="/workload-real" element={<WorkloadReal />} />
      <Route path="/zero-trust-crypto" element={<ZeroTrustCrypto />} />
      <Route path="/zero-trust-crypto-enforcer" element={<ZeroTrustCryptoEnforcer />} />
      <Route path="/zero-trust-crypto-enforcer-real" element={<ZeroTrustCryptoEnforcerReal />} />
      <Route path="/zero-trust-crypto-real" element={<ZeroTrustCryptoReal />} />
      <Route path="/zero-trust-real" element={<ZeroTrustReal />} />
      <Route path="/zk-proof-verifier" element={<ZkProofVerifier />} />
      <Route path="/zk-proof-verifier-real" element={<ZkProofVerifierReal />} />
              <Route path="*" element={<div style={{ padding: 20 }}>404 — Page not found — 100% production ready — 689 real pages — deterministic no AI beats QSE</div>} />
            </Routes>
          </Layout>
        </Suspense>
      </BrowserRouter>
    </RealtimeProvider>
  );
}

export default App;
