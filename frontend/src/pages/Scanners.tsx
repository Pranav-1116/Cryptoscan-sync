import React, { useState } from "react";
import { Badge, Button, ProgressBar } from "../components/ui";

type ScanTarget =
  | "Source Repository"
  | "Network"
  | "Cloud"
  | "Container"
  | "Hardware"
  | "Vendor"
  | "Certificate"
  | "Full Estate";

export default function Scanners() {
  const [step, setStep] = useState<"select" | "configure" | "running">("select");
  const [selectedTarget, setSelectedTarget] = useState<ScanTarget>("Full Estate");
  const [targetInput, setTargetInput] = useState("prod-cluster-us-east-1.bank.internal");
  const [accessMode, setAccessMode] = useState("Read-only");
  const [scope, setScope] = useState("In-scope payment switches & mTLS mesh");
  const [progress, setProgress] = useState(82);

  const targets: { id: ScanTarget; label: string; desc: string; icon: string }[] = [
    { id: "Source Repository", label: "Source Repository", desc: "150+ regex patterns & Shannon entropy &gt;4.5 for hardcoded crypto secrets", icon: "⬡" },
    { id: "Network", label: "Network", desc: "Passive TLS JA3/JA3S/JARM fingerprinting and cipher suite audit", icon: "◈" },
    { id: "Cloud", label: "Cloud", desc: "AWS KMS, Azure Key Vault, GCP Cloud KMS key hierarchy audit", icon: "☁" },
    { id: "Container", label: "Container", desc: "Trivy & Syft image SBOM crypto package extraction", icon: "⧉" },
    { id: "Hardware", label: "Hardware", desc: "FIPS 140-3 HSM fleet, TPM 2.0, Secure Boot UEFI measurements", icon: "⌬" },
    { id: "Vendor", label: "Vendor", desc: "Third-party API and vendor cryptographic risk assessment", icon: "▤" },
    { id: "Certificate", label: "Certificate", desc: "X.509 cert lifecycle, CT logs, and expiry monitoring", icon: "⊞" },
    { id: "Full Estate", label: "Full Estate", desc: "Comprehensive continuous cryptographic estate discovery", icon: "✦" },
  ];

  return (
    <div className="page" style={{ maxWidth: "880px", margin: "0 auto", padding: "20px 0 60px" }}>
      {/* 7. Scan Experience — Conversational Workflow */}
      {step === "select" && (
        <div>
          <div style={{ marginBottom: "28px" }}>
            <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", textTransform: "uppercase", letterSpacing: "0.1em" }}>Discovery Workflow</span>
            <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "6px 0 8px" }}>New Scan</h1>
            <p style={{ margin: 0, fontSize: "14px", color: "var(--dim)" }}>
              What would you like to discover in your cryptographic infrastructure?
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "14px", marginBottom: "28px" }}>
            {targets.map((t) => {
              const isSelected = selectedTarget === t.id;
              return (
                <div
                  key={t.id}
                  onClick={() => setSelectedTarget(t.id)}
                  style={{
                    padding: "16px 18px",
                    background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--panel)",
                    border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                    borderRadius: "10px",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
                    <span style={{ fontSize: "18px", color: isSelected ? "var(--cyan)" : "var(--faint)" }}>{t.icon}</span>
                    <span style={{ fontWeight: 600, fontSize: "14px", color: isSelected ? "var(--cyan)" : "var(--text)" }}>{t.label}</span>
                    <span style={{ marginLeft: "auto", fontSize: "14px", color: isSelected ? "var(--cyan)" : "var(--faint)" }}>
                      {isSelected ? "●" : "○"}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: "12px", color: "var(--dim)", lineHeight: 1.4 }}>
                    {t.desc}
                  </p>
                </div>
              );
            })}
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <Button variant="primary" size="lg" onClick={() => setStep("configure")}>
              Continue →
            </Button>
          </div>
        </div>
      )}

      {/* Configure Scan Step */}
      {step === "configure" && (
        <div>
          <div style={{ marginBottom: "28px" }}>
            <button
              onClick={() => setStep("select")}
              style={{ background: "none", border: "none", color: "var(--dim)", cursor: "pointer", fontSize: "13px", padding: 0, marginBottom: "12px" }}
            >
              ← Back to Discovery Selection
            </button>
            <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "0 0 8px" }}>Configure Scan</h1>
            <p style={{ margin: 0, fontSize: "14px", color: "var(--dim)" }}>
              Define targets and read-only access boundaries for <b>{selectedTarget}</b>.
            </p>
          </div>

          <div className="panel" style={{ padding: "28px", display: "flex", flexDirection: "column", gap: "20px", marginBottom: "24px" }}>
            <div>
              <label style={{ display: "block", fontSize: "12.5px", fontWeight: 600, color: "var(--text)", marginBottom: "8px" }}>
                Target Endpoint / Domain / ARN
              </label>
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                className="inp"
                placeholder="e.g. core-banking-switch.internal, arn:aws:kms:..., github.com/repo"
                style={{ fontSize: "13.5px" }}
              />
            </div>

            <div>
              <label style={{ display: "block", fontSize: "12.5px", fontWeight: 600, color: "var(--text)", marginBottom: "8px" }}>
                Access Permissions (Zero Write Impact)
              </label>
              <select
                value={accessMode}
                onChange={(e) => setAccessMode(e.target.value)}
                className="inp"
                style={{ fontSize: "13.5px" }}
              >
                <option value="Read-only">Read-only (Non-invasive passive inspection)</option>
                <option value="Network Mirror">Network Mirror (Out-of-band packet analysis)</option>
                <option value="API Audit">API Audit (Read-only metadata discovery)</option>
              </select>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "12.5px", fontWeight: 600, color: "var(--text)", marginBottom: "8px" }}>
                Scope & Tags
              </label>
              <input
                type="text"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                className="inp"
                placeholder="Environment tags, business units, or IP CIDR"
                style={{ fontSize: "13.5px" }}
              />
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "12px", color: "var(--faint)" }}>
              🔒 Passive read-only discovery. Production traffic is never modified or delayed.
            </span>
            <Button variant="primary" size="lg" onClick={() => setStep("running")}>
              Start Scan
            </Button>
          </div>
        </div>
      )}

      {/* 8. Live Scan Interface — Real-time Progress & Streaming Feedback */}
      {step === "running" && (
        <div>
          <div style={{ marginBottom: "24px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
              <h1 style={{ fontSize: "24px", fontWeight: 700, margin: 0 }}>Scanning production estate</h1>
              <Badge tone="cyan">LIVE SCAN IN PROGRESS</Badge>
            </div>
            <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
              Target: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{targetInput}</code> ({accessMode})
            </p>
          </div>

          <div className="panel" style={{ padding: "28px", marginBottom: "20px" }}>
            <div style={{ marginBottom: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "14px", fontWeight: 600, marginBottom: "8px" }}>
                <span>Discovering cryptographic assets...</span>
                <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{progress}%</span>
              </div>
              <ProgressBar value={progress} />
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "13px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--green)" }}>
                <span>✓</span> <span>Network discovery (TLS 1.2 / 1.3 JA3 passive sniff complete)</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--green)" }}>
                <span>✓</span> <span>Certificate discovery (1,204 X.509 certs validated against CT logs)</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--green)" }}>
                <span>✓</span> <span>TLS configuration & cipher suites mapped</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--green)" }}>
                <span>✓</span> <span>Application analysis & library version extraction</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--green)" }}>
                <span>✓</span> <span>Cloud KMS key hierarchy parsed</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--cyan)", fontWeight: 600 }}>
                <span>→</span> <span>Dependency mapping (Graph traversal depth 3...)</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--faint)" }}>
                <span>○</span> <span>Policy evaluation (Deterministic FIPS 203 & PCI-DSS check)</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--faint)" }}>
                <span>○</span> <span>Evidence verification (Sealing Merkle root into WORM log)</span>
              </div>
            </div>
          </div>

          {/* Metrics summary during scan */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: "12px", marginBottom: "24px" }}>
            <div className="panel" style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: "11px", color: "var(--dim)" }}>Assets discovered</div>
              <div style={{ fontSize: "20px", fontWeight: 700, fontFamily: "var(--mono)" }}>8,421</div>
            </div>
            <div className="panel" style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: "11px", color: "var(--dim)" }}>Cryptographic findings</div>
              <div style={{ fontSize: "20px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--amber)" }}>2,193</div>
            </div>
            <div className="panel" style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: "11px", color: "var(--dim)" }}>Certificates</div>
              <div style={{ fontSize: "20px", fontWeight: 700, fontFamily: "var(--mono)" }}>1,204</div>
            </div>
            <div className="panel" style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: "11px", color: "var(--dim)" }}>Dependencies</div>
              <div style={{ fontSize: "20px", fontWeight: 700, fontFamily: "var(--mono)" }}>4,827</div>
            </div>
            <div className="panel" style={{ padding: "14px 16px" }}>
              <div style={{ fontSize: "11px", color: "var(--dim)" }}>Evidence records</div>
              <div style={{ fontSize: "20px", fontWeight: 700, fontFamily: "var(--mono)", color: "var(--cyan)" }}>16,923</div>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Button variant="ghost" onClick={() => setStep("select")}>
              Cancel Scan
            </Button>
            <div style={{ display: "flex", gap: "10px" }}>
              <a href="#/cbom" className="btn outline" style={{ textDecoration: "none" }}>
                View Intermediate CBOM
              </a>
              <a href="#/command-center" className="btn primary" style={{ textDecoration: "none" }}>
                Return to Dashboard
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
