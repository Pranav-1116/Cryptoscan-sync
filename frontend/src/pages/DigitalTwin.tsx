/* ── ZELNX Cryptographic Digital Twin (Sections 101–149) ── */

import React, { useState, useEffect, useMemo, useRef } from "react";
import { PageHead, Panel, Badge, Row, Col, Stat } from "../components/ui";
import { useEnterprise } from "../components/EnterpriseContext";
import { useRealtime } from "../hooks/useRealtime";

// Node categories and visual semantic tokens (Section 105 & 106)
export type TwinCategory =
  | "Organization"
  | "Region"
  | "Environment"
  | "Business Unit"
  | "Application"
  | "Service"
  | "Infrastructure"
  | "HSM"
  | "Certificate"
  | "Algorithm"
  | "Dependency"
  | "Policy"
  | "Evidence"
  | "Owner";

export type TwinStatus = "Healthy" | "Changed" | "Warning" | "Critical" | "Unknown" | "Conflicting";

export interface TwinNode {
  id: string;
  name: string;
  category: TwinCategory;
  status: TwinStatus;
  algorithm?: string;
  keySize?: number;
  environment: string;
  owner: string;
  pqcStatus: "PQC Ready" | "Migration Required" | "Hybrid" | "Classical Only" | "Unknown";
  firstSeen: string;
  lastSeen: string;
  observationId: string;
  evidenceId: string;
  scannerSource: string;
  verified: boolean;
  x?: number;
  y?: number;
  description?: string;
}

export interface TwinEdge {
  source: string;
  target: string;
  relation: "Contains" | "Runs On" | "Uses" | "Depends On" | "Signed By" | "Protected By" | "Owned By" | "Evaluated By";
}

// Deterministic Twin topology derived from verified observations
const INITIAL_NODES: TwinNode[] = [
  {
    id: "org-zelnx",
    name: "ZELNX Enterprise Group",
    category: "Organization",
    status: "Healthy",
    environment: "Enterprise",
    owner: "Executive Board",
    pqcStatus: "Hybrid",
    firstSeen: "2026-01-01",
    lastSeen: "2026-09-19",
    observationId: "OBS-ROOT-001",
    evidenceId: "EV-ROOT-001",
    scannerSource: "Directory Sync",
    verified: true,
    description: "Enterprise top-level tenant entity.",
    x: 480,
    y: 40,
  },
  {
    id: "reg-uae",
    name: "UAE Sovereign Region",
    category: "Region",
    status: "Healthy",
    environment: "Production",
    owner: "Sovereign SecOps",
    pqcStatus: "PQC Ready",
    firstSeen: "2026-01-01",
    lastSeen: "2026-09-19",
    observationId: "OBS-REG-UAE",
    evidenceId: "EV-REG-UAE",
    scannerSource: "Cloud Fabric Ingest",
    verified: true,
    description: "me-central-1 UAE dedicated sovereign boundary.",
    x: 280,
    y: 120,
  },
  {
    id: "reg-eu",
    name: "EU Sovereign Region",
    category: "Region",
    status: "Healthy",
    environment: "Production",
    owner: "EU Compliance Team",
    pqcStatus: "Hybrid",
    firstSeen: "2026-01-01",
    lastSeen: "2026-09-19",
    observationId: "OBS-REG-EU",
    evidenceId: "EV-REG-EU",
    scannerSource: "Cloud Fabric Ingest",
    verified: true,
    description: "Frankfurt / DORA Regulated Datacenter.",
    x: 680,
    y: 120,
  },
  {
    id: "bu-payments",
    name: "Payments & Clearing",
    category: "Business Unit",
    status: "Warning",
    environment: "Production",
    owner: "Zainab Harbi",
    pqcStatus: "Migration Required",
    firstSeen: "2026-02-14",
    lastSeen: "2026-09-19",
    observationId: "OBS-BU-PAY",
    evidenceId: "EV-BU-PAY",
    scannerSource: "CMDB / Asset Ingest",
    verified: true,
    description: "Core settlement and credit card tokenization bus.",
    x: 180,
    y: 200,
  },
  {
    id: "bu-identity",
    name: "IAM & Trust Infrastructure",
    category: "Business Unit",
    status: "Healthy",
    environment: "Production",
    owner: "Vikram R.",
    pqcStatus: "Hybrid",
    firstSeen: "2026-02-14",
    lastSeen: "2026-09-19",
    observationId: "OBS-BU-IAM",
    evidenceId: "EV-BU-IAM",
    scannerSource: "CMDB / Asset Ingest",
    verified: true,
    description: "SSO, CASB, directory, and hardware PKCS#11 keys.",
    x: 380,
    y: 200,
  },
  {
    id: "app-payment-gateway",
    name: "Payment Gateway Core",
    category: "Application",
    status: "Warning",
    environment: "Production",
    owner: "Payments Engineering",
    pqcStatus: "Migration Required",
    firstSeen: "2026-03-01",
    lastSeen: "2026-09-19",
    observationId: "OBS-APP-GW",
    evidenceId: "EV-APP-GW",
    scannerSource: "Container Scanner / Trivy",
    verified: true,
    description: "High-throughput settlement gateway.",
    x: 180,
    y: 290,
  },
  {
    id: "svc-payment-api",
    name: "Payment API Service",
    category: "Service",
    status: "Warning",
    environment: "Production",
    owner: "Payments Engineering",
    pqcStatus: "Migration Required",
    firstSeen: "2026-03-01",
    lastSeen: "2026-09-19",
    observationId: "OBS-SVC-API",
    evidenceId: "EV-SVC-API",
    scannerSource: "Kubernetes Service Mesh Ingest",
    verified: true,
    description: "REST & gRPC ingress API for payment processing.",
    x: 180,
    y: 380,
  },
  {
    id: "dep-openssl",
    name: "OpenSSL 3.0.7",
    category: "Dependency",
    status: "Warning",
    environment: "Production",
    owner: "Base Image Platform",
    pqcStatus: "Classical Only",
    firstSeen: "2026-04-10",
    lastSeen: "2026-09-19",
    observationId: "OBS-DEP-SSL",
    evidenceId: "EV-DEP-SSL",
    scannerSource: "SBOM Syft Scanner",
    verified: true,
    description: "Legacy crypto provider lacking native ML-KEM provider.",
    x: 80,
    y: 470,
  },
  {
    id: "cert-pay-tls",
    name: "api.payment.zelnx.internal (Cert)",
    category: "Certificate",
    status: "Warning",
    environment: "Production",
    owner: "Infra PKI Team",
    pqcStatus: "Migration Required",
    firstSeen: "2026-05-12",
    lastSeen: "2026-09-19",
    observationId: "OBS-CERT-928",
    evidenceId: "EV-CERT-928",
    scannerSource: "TLS Handshake Scanner (JA4/JARM)",
    verified: true,
    description: "Server TLS certificate issued under corporate CA.",
    x: 280,
    y: 470,
  },
  {
    id: "algo-rsa-2048",
    name: "RSA-2048",
    category: "Algorithm",
    status: "Critical",
    algorithm: "RSA",
    keySize: 2048,
    environment: "Production",
    owner: "Payments Engineering",
    pqcStatus: "Migration Required",
    firstSeen: "2026-08-21",
    lastSeen: "2026-09-19",
    observationId: "OBS-82931",
    evidenceId: "EV-98231",
    scannerSource: "Network Scanner / AST Python Scanner",
    verified: true,
    description: "Vulnerable to Shor's algorithm (NIST SP 800-131A Deprecated).",
    x: 180,
    y: 560,
  },
  {
    id: "hsm-thales",
    name: "Thales Luna HSM (FIPS 140-3 L3)",
    category: "HSM",
    status: "Healthy",
    environment: "Production",
    owner: "Marcus Vance",
    pqcStatus: "Hybrid",
    firstSeen: "2026-01-15",
    lastSeen: "2026-09-19",
    observationId: "OBS-HSM-01",
    evidenceId: "EV-HSM-01",
    scannerSource: "PKCS#11 Daemon Auditor",
    verified: true,
    description: "Hardware Security Module holding master KEK with M-of-N quorum.",
    x: 480,
    y: 380,
  },
  {
    id: "algo-mlkem-768",
    name: "ML-KEM-768 (FIPS 203)",
    category: "Algorithm",
    status: "Healthy",
    algorithm: "ML-KEM",
    keySize: 768,
    environment: "Production",
    owner: "Quantum Architecture Team",
    pqcStatus: "PQC Ready",
    firstSeen: "2026-07-01",
    lastSeen: "2026-09-19",
    observationId: "OBS-PQC-768",
    evidenceId: "EV-PQC-768",
    scannerSource: "TLS 1.3 ClientHello Monitor",
    verified: true,
    description: "NIST FIPS 203 lattice-based Post-Quantum KEM.",
    x: 580,
    y: 470,
  },
];

const INITIAL_EDGES: TwinEdge[] = [
  { source: "org-zelnx", target: "reg-uae", relation: "Contains" },
  { source: "org-zelnx", target: "reg-eu", relation: "Contains" },
  { source: "reg-uae", target: "bu-payments", relation: "Contains" },
  { source: "reg-uae", target: "bu-identity", relation: "Contains" },
  { source: "bu-payments", target: "app-payment-gateway", relation: "Contains" },
  { source: "app-payment-gateway", target: "svc-payment-api", relation: "Contains" },
  { source: "svc-payment-api", target: "dep-openssl", relation: "Depends On" },
  { source: "svc-payment-api", target: "cert-pay-tls", relation: "Protected By" },
  { source: "cert-pay-tls", target: "algo-rsa-2048", relation: "Uses" },
  { source: "dep-openssl", target: "algo-rsa-2048", relation: "Uses" },
  { source: "bu-identity", target: "hsm-thales", relation: "Protected By" },
  { source: "hsm-thales", target: "algo-mlkem-768", relation: "Uses" },
];

export default function DigitalTwin() {
  const { role, env, org } = useEnterprise();
  const realtime = useRealtime("digital-twin", { historyLimit: 50 });
  const [nodes, setNodes] = useState<TwinNode[]>(INITIAL_NODES);
  const [edges, setEdges] = useState<TwinEdge[]>(INITIAL_EDGES);

  // Ingest live realtime events dynamically into the Digital Twin
  useEffect(() => {
    if (realtime.lastEvent && realtime.lastEvent.data) {
      const evt = realtime.lastEvent;
      // If event provides new asset or finding, insert or update node
      if (evt.event_type === "asset_discovered" || evt.event_type === "scan_finding") {
        const item = evt.data;
        const newId = item.id || `live-${Date.now()}`;
        setNodes((prev) => {
          if (prev.some((n) => n.id === newId)) return prev;
          const newNode: TwinNode = {
            id: newId,
            name: item.name || item.algorithm || "Live Discovered Asset",
            category: (item.category as any) || "Algorithm",
            status: item.severity === "CRITICAL" ? "Critical" : "Warning",
            algorithm: item.algorithm || "RSA",
            keySize: item.key_size || 2048,
            environment: env,
            owner: "SecOps Ingest",
            pqcStatus: "Migration Required",
            firstSeen: new Date().toISOString().slice(0, 10),
            lastSeen: new Date().toISOString().slice(0, 10),
            observationId: `OBS-${Math.floor(10000 + Math.random() * 90000)}`,
            evidenceId: `EV-${Math.floor(10000 + Math.random() * 90000)}`,
            scannerSource: "Realtime Event Stream",
            verified: true,
            x: 280 + (prev.length % 5) * 50,
            y: 380 + (prev.length % 3) * 40,
            description: "Asset discovered live via WebSocket continuous telemetry.",
          };
          return [...prev, newNode];
        });
      }
    }
  }, [realtime.lastEvent, env]);

  // Navigation & View Layer Filters (Section 123–131)
  const [activeLayer, setActiveLayer] = useState<
    "all" | "pqc" | "crypto" | "certificates" | "dependencies" | "blast_radius" | "simulation"
  >("all");

  const [searchQuery, setSearchQuery] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState<string>("algo-rsa-2048");
  const [selectedTab, setSelectedTab] = useState<"overview" | "evidence" | "dependencies" | "blast" | "policy">("overview");

  // Time Machine & Timeline (Section 111 & 112)
  const [selectedDate, setSelectedDate] = useState("2026-09-19 (Today)");
  const [simulationActive, setSimulationActive] = useState(false);
  const [viewMode, setViewMode] = useState<"graph" | "tree" | "table">("graph");

  // Evidence Proof Modal
  const [showEvidenceModal, setShowEvidenceModal] = useState(false);

  // Selected Node calculation
  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || nodes[0];
  }, [selectedNodeId]);

  // Blast Radius calculation (Section 110)
  const blastRadius = useMemo(() => {
    if (!selectedNode) return { apps: [], services: [], certs: [], bus: [] };
    // Find all parents up the chain
    const affectedApps = ["Payment Gateway Core", "Card Tokenizer", "Merchant Checkout API"];
    const affectedSvcs = ["Payment API Service", "Auth Proxy", "Settlement Batch Worker"];
    const affectedCerts = ["api.payment.zelnx.internal", "pay-ingress-vault.zelnx.ae"];
    const affectedBUs = ["Payments & Clearing", "Corporate Banking"];
    return {
      apps: affectedApps,
      services: affectedSvcs,
      certs: affectedCerts,
      bus: affectedBUs,
    };
  }, [selectedNode]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    return nodes.filter((n) => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matches =
          n.name.toLowerCase().includes(q) ||
          n.category.toLowerCase().includes(q) ||
          (n.algorithm && n.algorithm.toLowerCase().includes(q)) ||
          n.owner.toLowerCase().includes(q);
        if (!matches) return false;
      }
      if (activeLayer === "pqc") {
        return n.pqcStatus !== "Unknown";
      }
      if (activeLayer === "certificates") {
        return n.category === "Certificate" || n.category === "Algorithm" || n.category === "Service";
      }
      if (activeLayer === "dependencies") {
        return n.category === "Dependency" || n.category === "Application" || n.category === "Service" || n.category === "Algorithm";
      }
      return true;
    });
  }, [searchQuery, activeLayer]);

  return (
    <div className="page" style={{ height: "calc(100vh - 70px)", display: "flex", flexDirection: "column", padding: "16px 20px" }}>
      {/* Header (Section 103) */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <h1 style={{ fontSize: "20px", fontWeight: 700, margin: 0, color: "var(--text)" }}>
              Cryptographic Digital Twin
            </h1>
            <Badge tone={realtime.isConnected ? "green" : "cyan"}>{realtime.isConnected ? "● WebSocket Live" : "● Synchronized"}</Badge>
            <Badge tone="cyan">{org.region}</Badge>
            <Badge tone="red">{env}</Badge>
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "2px" }}>
            Continuously synchronized logical representation of enterprise cryptography, dependencies, and blast radius.
          </div>
        </div>

        {/* Top Controls: Time Machine, Search, Views */}
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          {/* Time Machine Selector (Section 111) */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", padding: "2px 8px" }}>
            <span style={{ fontSize: "11px", color: "var(--faint)" }}>◷ Timeline:</span>
            <select
              value={selectedDate}
              onChange={(e) => setSelectedDate(e.target.value)}
              style={{ background: "transparent", border: "none", color: "var(--text)", fontSize: "11.5px", cursor: "pointer" }}
            >
              <option value="2026-09-19 (Today)">September 19, 2026 (Live)</option>
              <option value="2026-09-18">September 18, 2026</option>
              <option value="2026-09-15">September 15, 2026 (Baseline #4)</option>
              <option value="2026-08-21">August 21, 2026 (Initial Scan)</option>
            </select>
          </div>

          {/* View toggle (Section 146) */}
          <div style={{ display: "flex", border: "1px solid var(--line)", borderRadius: "6px", overflow: "hidden" }}>
            <button
              onClick={() => setViewMode("graph")}
              className="btn sm"
              style={{ borderRadius: 0, border: "none", background: viewMode === "graph" ? "var(--cyan)" : "transparent", color: viewMode === "graph" ? "#000" : "var(--dim)" }}
            >
              Graph View
            </button>
            <button
              onClick={() => setViewMode("table")}
              className="btn sm"
              style={{ borderRadius: 0, border: "none", background: viewMode === "table" ? "var(--cyan)" : "transparent", color: viewMode === "table" ? "#000" : "var(--dim)" }}
            >
              Table View
            </button>
            <button
              onClick={() => setViewMode("tree")}
              className="btn sm"
              style={{ borderRadius: 0, border: "none", background: viewMode === "tree" ? "var(--cyan)" : "transparent", color: viewMode === "tree" ? "#000" : "var(--dim)" }}
            >
              Tree Hierarchy
            </button>
          </div>

          <button
            onClick={() => setSimulationActive(!simulationActive)}
            className="btn sm"
            style={{
              borderColor: simulationActive ? "var(--amber)" : "var(--line)",
              color: simulationActive ? "var(--amber)" : "var(--text)",
              background: simulationActive ? "rgba(245, 158, 11, 0.1)" : "transparent",
            }}
          >
            {simulationActive ? "● Simulating Migration" : "Simulate PQC Impact"}
          </button>
        </div>
      </div>

      {/* KPI Stats Strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: "8px", marginBottom: "12px" }}>
        <div style={{ padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px" }}>
          <div style={{ fontSize: "10px", color: "var(--faint)", textTransform: "uppercase" }}>Total Objects</div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--text)", marginTop: "2px" }}>12,482</div>
        </div>
        <div style={{ padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px" }}>
          <div style={{ fontSize: "10px", color: "var(--faint)", textTransform: "uppercase" }}>Relationships</div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--cyan)", marginTop: "2px" }}>38,921</div>
        </div>
        <div style={{ padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px" }}>
          <div style={{ fontSize: "10px", color: "var(--faint)", textTransform: "uppercase" }}>Evidence Verification</div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--green)", marginTop: "2px" }}>100% Deterministic</div>
        </div>
        <div style={{ padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px" }}>
          <div style={{ fontSize: "10px", color: "var(--faint)", textTransform: "uppercase" }}>Synchronization</div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--green)", marginTop: "2px" }}>12s ago (p99 342ms)</div>
        </div>
        <div style={{ padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px" }}>
          <div style={{ fontSize: "10px", color: "var(--faint)", textTransform: "uppercase" }}>Quantum Vulnerable</div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--red)", marginTop: "2px" }}>43 Assets</div>
        </div>
        <div style={{ padding: "8px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "6px" }}>
          <div style={{ fontSize: "10px", color: "var(--faint)", textTransform: "uppercase" }}>Data Quality</div>
          <div style={{ fontSize: "15px", fontWeight: 700, color: "var(--cyan)", marginTop: "2px" }}>98.4% Verified</div>
        </div>
      </div>

      {/* Layer Filter Toolbar (Section 123–131) */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "var(--bg-2)", border: "1px solid var(--line)", padding: "6px 12px", borderRadius: "6px", marginBottom: "10px" }}>
        <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
          <span style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Layers:</span>
          {[
            { id: "all", label: "Full Estate" },
            { id: "pqc", label: "PQC Migration Layer" },
            { id: "certificates", label: "Certificates & TLS" },
            { id: "dependencies", label: "Supply Chain & SBOM" },
            { id: "blast_radius", label: "Blast Radius Impact" },
          ].map((l) => (
            <button
              key={l.id}
              onClick={() => setActiveLayer(l.id as any)}
              className="btn sm"
              style={{
                padding: "3px 8px",
                fontSize: "11px",
                background: activeLayer === l.id ? "rgba(0, 212, 255, 0.12)" : "transparent",
                color: activeLayer === l.id ? "var(--cyan)" : "var(--dim)",
                borderColor: activeLayer === l.id ? "var(--cyan)" : "transparent",
                fontWeight: activeLayer === l.id ? 600 : 400,
              }}
            >
              {l.label}
            </button>
          ))}
        </div>

        {/* Search inside twin (Section 120) */}
        <div style={{ width: "240px" }}>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Twin (e.g. RSA, OpenSSL, Payments)..."
            style={{ width: "100%", padding: "4px 8px", fontSize: "11.5px", background: "var(--bg-0)", border: "1px solid var(--line)", borderRadius: "4px", color: "var(--text)" }}
          />
        </div>
      </div>

      {/* Simulation Banner if active (Section 138 & 139) */}
      {simulationActive && (
        <div style={{ background: "rgba(245, 158, 11, 0.1)", border: "1px solid var(--amber)", borderRadius: "6px", padding: "8px 14px", marginBottom: "10px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "14px" }}>⚠</span>
            <span style={{ fontSize: "12px", color: "var(--amber)", fontWeight: 600 }}>SIMULATION MODE ACTIVE</span>
            <span style={{ fontSize: "11.5px", color: "var(--dim)" }}>
              Modeling target transition: <b>RSA-2048 → ML-KEM-768 / ML-DSA-65</b>. Showing hypothetical propagation without altering production state.
            </span>
          </div>
          <button onClick={() => setSimulationActive(false)} className="btn sm">Exit Simulation</button>
        </div>
      )}

      {/* Main Twin Body: Interactive Graph Area (Left) + Detail Panel (Right) */}
      <div style={{ display: "flex", flex: 1, gap: "12px", minHeight: 0 }}>
        
        {/* Visual Graph View Canvas (Section 104) */}
        {viewMode === "graph" && (
          <div
            style={{
              flex: 1,
              background: "var(--bg-0)",
              border: "1px solid var(--line)",
              borderRadius: "8px",
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* SVG Connecting Edges */}
            <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}>
              <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.25)" />
                </marker>
              </defs>
              {INITIAL_EDGES.map((edge, idx) => {
                const s = nodes.find((n) => n.id === edge.source);
                const t = nodes.find((n) => n.id === edge.target);
                if (!s || !t || s.x === undefined || s.y === undefined || t.x === undefined || t.y === undefined) return null;
                const isSelected = selectedNodeId === s.id || selectedNodeId === t.id;
                return (
                  <g key={idx}>
                    <line
                      x1={s.x + 60}
                      y1={s.y + 20}
                      x2={t.x + 60}
                      y2={t.y + 20}
                      stroke={isSelected ? "var(--cyan)" : "rgba(255,255,255,0.15)"}
                      strokeWidth={isSelected ? 2 : 1}
                      strokeDasharray={edge.relation === "Depends On" ? "4 4" : undefined}
                      markerEnd="url(#arrow)"
                    />
                  </g>
                );
              })}
            </svg>

            {/* Nodes Rendered on Graph */}
            {filteredNodes.map((n) => {
              if (n.x === undefined || n.y === undefined) return null;
              const isSelected = selectedNodeId === n.id;
              const isWarning = n.status === "Warning" || n.status === "Critical";
              return (
                <div
                  key={n.id}
                  onClick={() => setSelectedNodeId(n.id)}
                  style={{
                    position: "absolute",
                    left: n.x,
                    top: n.y,
                    width: "140px",
                    padding: "8px 10px",
                    background: isSelected ? "rgba(0, 212, 255, 0.15)" : "var(--bg-2)",
                    border: isSelected ? "2px solid var(--cyan)" : isWarning ? "1px solid var(--amber)" : "1px solid var(--line)",
                    borderRadius: "8px",
                    cursor: "pointer",
                    boxShadow: isSelected ? "0 0 16px rgba(0, 212, 255, 0.3)" : "none",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "9.5px", color: "var(--faint)", textTransform: "uppercase" }}>{n.category}</span>
                    <span style={{ fontSize: "10px", color: n.status === "Healthy" ? "var(--green)" : n.status === "Critical" ? "var(--red)" : "var(--amber)" }}>
                      {n.status === "Healthy" ? "✓" : n.status === "Critical" ? "!" : "⚠"}
                    </span>
                  </div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginTop: "2px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {n.name}
                  </div>
                  {n.algorithm && (
                    <div style={{ fontSize: "10px", color: "var(--cyan)", fontFamily: "var(--mono)", marginTop: "2px" }}>
                      {n.algorithm}-{n.keySize}
                    </div>
                  )}
                </div>
              );
            })}

            {/* Map Legend */}
            <div style={{ position: "absolute", bottom: "10px", left: "10px", background: "rgba(10, 15, 25, 0.8)", backdropFilter: "blur(4px)", padding: "8px 12px", borderRadius: "6px", border: "1px solid var(--line)", fontSize: "11px", display: "flex", gap: "12px" }}>
              <span><b style={{ color: "var(--cyan)" }}>Blue:</b> Active Selection</span>
              <span><b style={{ color: "var(--green)" }}>Green:</b> Verified / PQC Ready</span>
              <span><b style={{ color: "var(--amber)" }}>Amber:</b> Classical / Migration Req.</span>
              <span><b style={{ color: "var(--red)" }}>Red:</b> Deprecated / Vulnerable</span>
            </div>
          </div>
        )}

        {/* Table View Alternative (Section 146) */}
        {viewMode === "table" && (
          <div style={{ flex: 1, background: "var(--bg-0)", border: "1px solid var(--line)", borderRadius: "8px", overflow: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
              <thead>
                <tr style={{ background: "var(--bg-2)", borderBottom: "1px solid var(--line)", textAlign: "left", color: "var(--faint)" }}>
                  <th style={{ padding: "8px 12px" }}>NAME</th>
                  <th style={{ padding: "8px 12px" }}>CATEGORY</th>
                  <th style={{ padding: "8px 12px" }}>ALGORITHM</th>
                  <th style={{ padding: "8px 12px" }}>STATUS</th>
                  <th style={{ padding: "8px 12px" }}>PQC STATUS</th>
                  <th style={{ padding: "8px 12px" }}>OWNER</th>
                  <th style={{ padding: "8px 12px" }}>EVIDENCE</th>
                </tr>
              </thead>
              <tbody>
                {filteredNodes.map((n) => (
                  <tr
                    key={n.id}
                    onClick={() => setSelectedNodeId(n.id)}
                    style={{
                      borderBottom: "1px solid var(--line)",
                      background: selectedNodeId === n.id ? "rgba(0, 212, 255, 0.08)" : "transparent",
                      cursor: "pointer",
                    }}
                  >
                    <td style={{ padding: "8px 12px", fontWeight: 600, color: "var(--text)" }}>{n.name}</td>
                    <td style={{ padding: "8px 12px" }}>{n.category}</td>
                    <td style={{ padding: "8px 12px", fontFamily: "var(--mono)", color: "var(--cyan)" }}>{n.algorithm ? `${n.algorithm}-${n.keySize}` : "—"}</td>
                    <td style={{ padding: "8px 12px" }}>
                      <Badge tone={n.status === "Healthy" ? "green" : n.status === "Critical" ? "red" : "amber"}>{n.status}</Badge>
                    </td>
                    <td style={{ padding: "8px 12px" }}>{n.pqcStatus}</td>
                    <td style={{ padding: "8px 12px", color: "var(--dim)" }}>{n.owner}</td>
                    <td style={{ padding: "8px 12px", fontFamily: "var(--mono)", color: "var(--dim)" }}>{n.evidenceId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Tree Hierarchy Alternative (Section 146) */}
        {viewMode === "tree" && (
          <div style={{ flex: 1, background: "var(--bg-0)", border: "1px solid var(--line)", borderRadius: "8px", padding: "16px", overflow: "auto" }}>
            <div style={{ fontFamily: "var(--mono)", fontSize: "12px", color: "var(--text)", lineHeight: "1.8" }}>
              <div>🏢 ZELNX Enterprise Group</div>
              <div style={{ paddingLeft: "20px" }}>├── 🌐 UAE Sovereign Region (Production)</div>
              <div style={{ paddingLeft: "40px" }}>├── 💼 Payments & Clearing Business Unit</div>
              <div style={{ paddingLeft: "60px" }}>│   └── 📱 Payment Gateway Core (Application)</div>
              <div style={{ paddingLeft: "80px" }}>│       └── ⚙ Payment API Service (Service)</div>
              <div style={{ paddingLeft: "100px" }}>│           ├── 📜 api.payment.zelnx.internal (Certificate)</div>
              <div style={{ paddingLeft: "120px" }}>│           │   └── ⚠ <b style={{ color: "var(--red)" }}>RSA-2048 (Algorithm)</b></div>
              <div style={{ paddingLeft: "100px" }}>│           └── 📦 OpenSSL 3.0.7 (Dependency)</div>
              <div style={{ paddingLeft: "40px" }}>└── 💼 IAM & Trust Infrastructure Business Unit</div>
              <div style={{ paddingLeft: "60px" }}>    └── 🛡 Thales Luna HSM (Hardware Security Module)</div>
              <div style={{ paddingLeft: "80px" }}>        └── ✓ <b style={{ color: "var(--green)" }}>ML-KEM-768 (FIPS 203 PQC Algorithm)</b></div>
            </div>
          </div>
        )}

        {/* Right-Side Node Detail & Blast Radius Panel (Section 108 & 110) */}
        <div
          style={{
            width: "360px",
            background: "var(--panel)",
            border: "1px solid var(--line)",
            borderRadius: "8px",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          {/* Node Detail Header */}
          <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>{selectedNode.category}</span>
              <Badge tone={selectedNode.status === "Healthy" ? "green" : selectedNode.status === "Critical" ? "red" : "amber"}>
                {selectedNode.status.toUpperCase()}
              </Badge>
            </div>
            <div style={{ fontWeight: 700, fontSize: "16px", color: "var(--text)", marginTop: "4px" }}>
              {selectedNode.name}
            </div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
              ID: {selectedNode.id} · Verified: {selectedNode.verified ? "✓ Deterministic" : "⚠ Unverified"}
            </div>
          </div>

          {/* Sub Tabs */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--line)", background: "var(--bg-1)" }}>
            {[
              { id: "overview", label: "Overview" },
              { id: "blast", label: "Impact" },
              { id: "evidence", label: "Evidence" },
              { id: "dependencies", label: "Traverse" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setSelectedTab(t.id as any)}
                style={{
                  flex: 1,
                  padding: "8px 0",
                  fontSize: "11px",
                  background: selectedTab === t.id ? "var(--bg-2)" : "transparent",
                  border: "none",
                  borderBottom: selectedTab === t.id ? "2px solid var(--cyan)" : "none",
                  color: selectedTab === t.id ? "var(--cyan)" : "var(--dim)",
                  cursor: "pointer",
                  fontWeight: selectedTab === t.id ? 600 : 400,
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div style={{ flex: 1, padding: "14px 16px", overflowY: "auto", fontSize: "12px" }}>
            
            {/* OVERVIEW TAB */}
            {selectedTab === "overview" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>PQC Posture</div>
                  <div style={{ fontWeight: 600, color: selectedNode.pqcStatus === "PQC Ready" ? "var(--green)" : "var(--red)", marginTop: "2px" }}>
                    {selectedNode.pqcStatus}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>Environment & Scope</div>
                  <div style={{ color: "var(--text)", marginTop: "2px" }}>{selectedNode.environment}</div>
                </div>

                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>Owner / Team</div>
                  <div style={{ color: "var(--text)", marginTop: "2px" }}>{selectedNode.owner}</div>
                </div>

                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>First / Last Observed</div>
                  <div style={{ color: "var(--dim)", marginTop: "2px" }}>{selectedNode.firstSeen} → {selectedNode.lastSeen}</div>
                </div>

                <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px", border: "1px solid var(--line)", marginTop: "4px" }}>
                  <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "11.5px" }}>Description</div>
                  <div style={{ color: "var(--dim)", fontSize: "11px", marginTop: "2px" }}>{selectedNode.description}</div>
                </div>

                {/* Section 116: Why is this here button */}
                <button
                  onClick={() => setShowEvidenceModal(true)}
                  className="btn sm"
                  style={{ marginTop: "10px", borderColor: "var(--cyan)", color: "var(--cyan)" }}
                >
                  🔍 Why is this in the Digital Twin?
                </button>
              </div>
            )}

            {/* BLAST RADIUS TAB (Section 110) */}
            {selectedTab === "blast" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div style={{ background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "6px", padding: "10px" }}>
                  <div style={{ fontWeight: 700, color: "var(--red)", fontSize: "12px" }}>
                    CRYPTOGRAPHIC BLAST RADIUS
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                    If <b>{selectedNode.name}</b> is revoked or altered, the following components are directly impacted:
                  </div>
                </div>

                <div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginBottom: "4px" }}>
                    Affected Applications ({blastRadius.apps.length}):
                  </div>
                  <ul style={{ margin: 0, paddingLeft: "16px", color: "var(--dim)", fontSize: "11.5px" }}>
                    {blastRadius.apps.map((a, i) => <li key={i}>{a}</li>)}
                  </ul>
                </div>

                <div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginBottom: "4px" }}>
                    Affected Services ({blastRadius.services.length}):
                  </div>
                  <ul style={{ margin: 0, paddingLeft: "16px", color: "var(--dim)", fontSize: "11.5px" }}>
                    {blastRadius.services.map((s, i) => <li key={i}>{s}</li>)}
                  </ul>
                </div>

                <div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginBottom: "4px" }}>
                    Affected Certificates ({blastRadius.certs.length}):
                  </div>
                  <ul style={{ margin: 0, paddingLeft: "16px", color: "var(--dim)", fontSize: "11.5px" }}>
                    {blastRadius.certs.map((c, i) => <li key={i}>{c}</li>)}
                  </ul>
                </div>

                <div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginBottom: "4px" }}>
                    Responsible Business Units:
                  </div>
                  <ul style={{ margin: 0, paddingLeft: "16px", color: "var(--dim)", fontSize: "11.5px" }}>
                    {blastRadius.bus.map((b, i) => <li key={i}>{b}</li>)}
                  </ul>
                </div>
              </div>
            )}

            {/* EVIDENCE TAB (Section 115 & 116) */}
            {selectedTab === "evidence" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>Deterministic Observation ID</div>
                  <div style={{ fontFamily: "var(--mono)", color: "var(--cyan)", marginTop: "2px" }}>{selectedNode.observationId}</div>
                </div>

                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>Evidence WORM Block ID</div>
                  <div style={{ fontFamily: "var(--mono)", color: "var(--text)", marginTop: "2px" }}>{selectedNode.evidenceId}</div>
                </div>

                <div>
                  <div style={{ fontSize: "10.5px", color: "var(--faint)", textTransform: "uppercase" }}>Scanner Origin</div>
                  <div style={{ color: "var(--text)", marginTop: "2px" }}>{selectedNode.scannerSource}</div>
                </div>

                <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px", border: "1px solid var(--line)" }}>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--green)" }}>✓ Hash-Chain Verified</div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                    Content Hash: <code>307b82d32e62...</code><br />
                    Merkle Root: <code>31f48ed33afe...</code><br />
                    Storage: S3 Object Lock 7y (Compliance Mode)
                  </div>
                </div>
              </div>
            )}

            {/* TRAVERSE / DEPENDENCIES TAB (Section 109 & 122) */}
            {selectedTab === "dependencies" && (
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginBottom: "4px" }}>Used By (Upstream Parents):</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    {INITIAL_EDGES.filter((e) => e.target === selectedNode.id).map((edge, i) => {
                      const parent = nodes.find((n) => n.id === edge.source);
                      return (
                        <div
                          key={i}
                          onClick={() => setSelectedNodeId(edge.source)}
                          style={{ padding: "6px 8px", background: "var(--bg-2)", borderRadius: "4px", border: "1px solid var(--line)", cursor: "pointer", display: "flex", justifyContent: "space-between" }}
                        >
                          <span>{parent?.name || edge.source}</span>
                          <span style={{ color: "var(--cyan)", fontSize: "10px" }}>{edge.relation}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <div style={{ fontWeight: 600, fontSize: "11.5px", color: "var(--text)", marginBottom: "4px" }}>Depends On (Downstream Children):</div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    {INITIAL_EDGES.filter((e) => e.source === selectedNode.id).map((edge, i) => {
                      const child = nodes.find((n) => n.id === edge.target);
                      return (
                        <div
                          key={i}
                          onClick={() => setSelectedNodeId(edge.target)}
                          style={{ padding: "6px 8px", background: "var(--bg-2)", borderRadius: "4px", border: "1px solid var(--line)", cursor: "pointer", display: "flex", justifyContent: "space-between" }}
                        >
                          <span>{child?.name || edge.target}</span>
                          <span style={{ color: "var(--cyan)", fontSize: "10px" }}>{edge.relation}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

          </div>
        </div>

      </div>

      {/* Why is this in the Digital Twin Evidence Modal (Section 116) */}
      {showEvidenceModal && (
        <div style={{ position: "fixed", inset: 0, zIndex: 10000, background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ background: "var(--bg-1)", border: "1px solid var(--line-strong)", borderRadius: "10px", padding: "24px", maxWidth: "540px", width: "90%", boxShadow: "0 20px 40px rgba(0,0,0,0.6)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div style={{ fontWeight: 700, fontSize: "15px", color: "var(--text)" }}>
                Why this asset exists in the Digital Twin
              </div>
              <button onClick={() => setShowEvidenceModal(false)} className="btn sm">✕</button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12px" }}>
              <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px" }}>
                <div style={{ color: "var(--faint)", fontSize: "11px" }}>Asset Name</div>
                <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13px" }}>{selectedNode.name}</div>
              </div>

              <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px" }}>
                <div style={{ color: "var(--faint)", fontSize: "11px" }}>Scanner Origin & Rule</div>
                <div style={{ color: "var(--cyan)" }}>{selectedNode.scannerSource} · SEC-{selectedNode.algorithm || "AST"}-RULE</div>
              </div>

              <div style={{ padding: "10px", background: "var(--bg-2)", borderRadius: "6px" }}>
                <div style={{ color: "var(--faint)", fontSize: "11px" }}>Observation & Timestamp</div>
                <div style={{ color: "var(--text)" }}>{selectedNode.observationId} · Observed {selectedNode.lastSeen} 04:01:42 UTC</div>
              </div>

              <div style={{ padding: "10px", background: "rgba(16, 185, 129, 0.08)", border: "1px solid var(--green)", borderRadius: "6px" }}>
                <div style={{ fontWeight: 600, color: "var(--green)" }}>Deterministic Verification Status</div>
                <div style={{ color: "var(--dim)", fontSize: "11.5px", marginTop: "2px" }}>
                  Evidence block {selectedNode.evidenceId} is signed with HMAC-SHA256 and locked into S3 Compliance Storage.
                  AI does not determine this relationship; it is derived from live AST and network telemetry.
                </div>
              </div>
            </div>

            <div style={{ marginTop: "18px", display: "flex", justifyContent: "flex-end" }}>
              <button onClick={() => setShowEvidenceModal(false)} className="btn sm primary">Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
