import React, { useState } from "react";
import { Badge, Button } from "../components/ui";

export default function Evidence() {
  const [selectedRecord, setSelectedRecord] = useState<any>({
    id: "OBS-8F93A21",
    source: "Network Scanner (JA3 Passive Sniffer)",
    timestamp: "2026-09-19 03:41:28 UTC",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    merkleRoot: "0x7f9a221bce401a88dfb90c12847aef981048b29184a29c11847120dbca8921fe",
    observation: "TLS 1.2 using RSA-2048 and TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    target: "api.production.internal:443",
    verification: "Verified",
    policyEvaluation: "Deterministic (Violates NIST SP 800-131A & PQC Deadline)",
    chainStatus: "Integrity Verified (S3 Object Lock Legal Hold 7y)",
    signedBy: "ZELNX Ingestion Daemon v1.0 [Ed25519-Signed]"
  });

  const records = [
    { id: "OBS-8F93A21", type: "Network Sniffer", finding: "TLS 1.2 with RSA-2048 handshake", time: "3 mins ago", status: "Verified" },
    { id: "OBS-8F93A22", type: "Container Scanner", finding: "OpenSSL 1.1.1u bundled in payment container", time: "12 mins ago", status: "Verified" },
    { id: "OBS-8F93A23", type: "Cloud KMS Auditor", finding: "AWS KMS Customer Master Key auto-rotation disabled", time: "25 mins ago", status: "Verified" },
    { id: "OBS-8F93A24", type: "HSM Fleet Scanner", finding: "Thales Luna firmware 7.8.1 PQC test slot online", time: "42 mins ago", status: "Verified" },
    { id: "OBS-8F93A25", type: "Certificate Monitor", finding: "Wildcard cert expiry in 14 days (*.bank.internal)", time: "1 hour ago", status: "Verified" },
  ];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 12. Evidence Chain Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Immutable WORM Audit Ledger
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Evidence Chain Management</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            ZELNX is <b>evidence-first</b>. Every cryptographic finding is sealed into an immutable SHA-256 HMAC Merkle tree with S3 Object Lock.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <Button variant="outline" onClick={() => alert("Exporting cryptographic evidence pack with Merkle inclusion proof...")}>
            Download Auditor Pack
          </Button>
          <Button variant="primary" onClick={() => alert("Deterministic verification executed: All 16,923 evidence records MATCH Merkle root 0x7f9a...fe")}>
            Verify Ledger Integrity
          </Button>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.2fr", gap: "24px" }}>
        {/* Left Column: Recent Evidence Log */}
        <div className="panel" style={{ padding: "20px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "15px", fontWeight: 600 }}>Evidence Records Log</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Real-time hash-chained stream from automated observation collectors.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {records.map((r) => {
              const isSelected = selectedRecord?.id === r.id;
              return (
                <div
                  key={r.id}
                  onClick={() => setSelectedRecord({ ...selectedRecord, id: r.id, observation: r.finding, source: r.type })}
                  style={{
                    padding: "12px 14px",
                    background: isSelected ? "rgba(0, 212, 255, 0.08)" : "var(--bg-2)",
                    border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                    borderRadius: "8px",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: "12px", fontWeight: 600, color: "var(--cyan)" }}>{r.id}</span>
                    <Badge tone="green">{r.status}</Badge>
                  </div>
                  <div style={{ fontSize: "13px", color: "var(--text)", marginBottom: "4px" }}>{r.finding}</div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--dim)" }}>
                    <span>{r.type}</span>
                    <span>{r.time}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Evidence Detail Card (Section 12 Layout) */}
        {selectedRecord && (
          <div className="panel" style={{ padding: "24px", border: "1px solid var(--line-strong)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", borderBottom: "1px solid var(--line)", paddingBottom: "12px" }}>
              <div>
                <span style={{ fontSize: "11px", fontFamily: "var(--mono)", color: "var(--dim)", textTransform: "uppercase" }}>Inspection View</span>
                <h2 style={{ margin: 0, fontSize: "18px", fontWeight: 600 }}>Evidence Record</h2>
              </div>
              <Badge tone="green">✓ INTEGRITY VERIFIED</Badge>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
                  Observation ID
                </div>
                <div style={{ fontFamily: "var(--mono)", fontSize: "14px", fontWeight: 600, color: "var(--cyan)" }}>
                  {selectedRecord.id}
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
                    Collector Source
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 500 }}>
                    {selectedRecord.source}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
                    Timestamp (UTC)
                  </div>
                  <div style={{ fontSize: "13px", fontFamily: "var(--mono)" }}>
                    {selectedRecord.timestamp}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "4px" }}>
                  Observation Finding
                </div>
                <div style={{ padding: "10px 14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", fontSize: "13px", color: "var(--text)" }}>
                  {selectedRecord.observation}
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "4px" }}>
                  SHA-256 Observation Hash
                </div>
                <div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--cyan)", wordBreak: "break-all" }}>
                  {selectedRecord.sha256}
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "4px" }}>
                  Merkle Tree Batch Root
                </div>
                <div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--text)", wordBreak: "break-all" }}>
                  {selectedRecord.merkleRoot}
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", borderTop: "1px solid var(--line)", paddingTop: "14px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginBottom: "4px" }}>Policy Evaluation</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12.5px", color: "var(--green)" }}>
                    <span>✓</span> <span>Deterministic Engine</span>
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginBottom: "4px" }}>WORM Immutability</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12.5px", color: "var(--green)" }}>
                    <span>✓</span> <span>S3 Object Lock (7y)</span>
                  </div>
                </div>
              </div>

              <div style={{ display: "flex", gap: "10px", marginTop: "8px" }}>
                <a href="#/audit-merkle" className="btn sm primary" style={{ textDecoration: "none", flex: 1, textAlign: "center" }}>
                  Verify Merkle Proof
                </a>
                <a href="#/whatif" className="btn sm outline" style={{ textDecoration: "none", flex: 1, textAlign: "center" }}>
                  Simulate Remediation
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
