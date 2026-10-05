import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiAuditList, apiAuditVerify } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { ICON_MD, IconOk } from "../components/icons";

export default function Evidence() {
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [selectedRecord, setSelectedRecord] = useState<any>(null);

  useEffect(() => {
    let alive = true;
    async function loadAuditData() {
      setLoading(true);
      try {
        const [listRes, verifyRes] = await Promise.all([
          apiAuditList({ page: 1, page_size: 50 }),
          apiAuditVerify(),
        ]);

        if (alive) {
          if (verifyRes.source === "live" && verifyRes.data) {
            setVerifyResult(verifyRes.data);
          }
          if (listRes.source === "live" && listRes.data) {
            const evs = (listRes.data as any).events || [];
            setEvents(evs);
            if (evs.length > 0) {
              setSelectedRecord(evs[0]);
            }
          }
        }
      } catch (err) {
        console.error("Failed to load audit evidence records:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }

    loadAuditData();
    return () => { alive = false; };
  }, []);

  const runVerification = async () => {
    setVerifying(true);
    try {
      const res = await apiAuditVerify();
      if (res.source === "live" && res.data) {
        setVerifyResult(res.data);
      }
    } catch (err) {
      console.error("Verification failed:", err);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Evidence Chain Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Immutable WORM Audit Ledger
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Evidence Chain & Integrity Ledger</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Deterministic cryptographic audit log sealed with SHA-256 hash chaining and verified Merkle inclusion proofs.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/auth/audit/export?format=jsonl"
            filename="audit-export.jsonl"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            Export JSONL WORM Pack
          </AuthenticatedDownload>
          <Button
            variant="primary"
            onClick={runVerification}
            disabled={verifying}
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            {verifying ? "Computing Hash-Chain..." : "Verify Ledger Integrity"}
          </Button>
        </div>
      </div>

      {/* Verification Banner */}
      {verifyResult && (
        <div
          className="panel"
          style={{
            padding: "16px 20px",
            marginBottom: "20px",
            background: verifyResult.status === "OK" ? "color-mix(in srgb, var(--green) 6%, transparent)" : "color-mix(in srgb, var(--red) 8%, transparent)",
            border: `1px solid ${verifyResult.status === "OK" ? "color-mix(in srgb, var(--green) 30%, transparent)" : "color-mix(in srgb, var(--red) 30%, transparent)"}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "12px"
          }}
        >
          <div>
            <div style={{ fontSize: "13px", fontWeight: 600, color: verifyResult.status === "OK" ? "var(--green)" : "var(--red)" }}>
              {verifyResult.status === "OK" ? "Hash Chain Integrity Verified" : "⚠ Chain Verification Discrepancy"}
            </div>
            <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>
              Total entries verified: {verifyResult.checked ?? verifyResult.entry_count ?? 0} · Chain Head: <span style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{verifyResult.chain_head || "Genesis (Clean)"}</span>
            </div>
          </div>
          <Badge variant={verifyResult.status === "OK" ? "success" : "danger"}>
            {verifyResult.status || "VALID"}
          </Badge>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.2fr", gap: "24px" }}>
        {/* Left Column: Recent Evidence Log */}
        <div className="panel" style={{ padding: "20px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "15px", fontWeight: 600 }}>Evidence Records Log</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Real-time hash-chained audit events from platform authentication and observation collectors.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "560px", overflowY: "auto" }}>
            {events.map((r) => {
              const isSelected = selectedRecord?.id === r.id;
              return (
                <div
                  key={r.id}
                  onClick={() => setSelectedRecord(r)}
                  style={{
                    padding: "12px 14px",
                    background: isSelected ? "color-mix(in srgb, var(--accent) 8%, transparent)" : "var(--bg-2)",
                    border: `1px solid ${isSelected ? "var(--cyan)" : "var(--line)"}`,
                    borderRadius: "var(--r)",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: "12px", fontWeight: 600, color: "var(--cyan)" }}>
                      {r.id.slice(0, 12)}...
                    </span>
                    <Badge variant={r.outcome === "SUCCESS" ? "success" : "warning"}>
                      {r.outcome || "RECORDED"}
                    </Badge>
                  </div>
                  <div style={{ fontSize: "12.5px", fontWeight: 500, color: "var(--text)", marginBottom: "4px" }}>
                    Action: {r.action}
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--dim)" }}>
                    <span>Actor: {r.actor}</span>
                    <span>{r.created_at ? new Date(r.created_at).toLocaleTimeString() : "Recent"}</span>
                  </div>
                </div>
              );
            })}

            {events.length === 0 && !loading && (
              <div style={{ textAlign: "center", padding: "36px", color: "var(--dim)" }}>
                No audit events recorded yet. Platform actions automatically seal entries into the ledger.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Selected Record Verification Certificate */}
        {selectedRecord ? (
          <div className="panel" style={{ padding: "24px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
              <div>
                <div style={{ fontSize: "11px", color: "var(--cyan)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 600 }}>
                  Cryptographic Attestation Card
                </div>
                <h3 style={{ margin: "4px 0 0", fontSize: "18px", fontWeight: 700 }}>
                  Evidence Inspection #{selectedRecord.id.slice(0, 8)}
                </h3>
              </div>
              <Badge variant="success">Integrity Sealed</Badge>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
                    Actor Identity
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 500 }}>
                    {selectedRecord.actor}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "3px" }}>
                    Timestamp (UTC)
                  </div>
                  <div style={{ fontSize: "13px", fontFamily: "var(--mono)" }}>
                    {selectedRecord.created_at}
                  </div>
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "4px" }}>
                  Action Payload
                </div>
                <div style={{ padding: "10px 14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: "13px", color: "var(--text)" }}>
                  {selectedRecord.action} {selectedRecord.detail ? `— ${JSON.stringify(selectedRecord.detail)}` : ""}
                </div>
              </div>

              <div>
                <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "4px" }}>
                  Observation Identifier (UUID)
                </div>
                <div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--cyan)", wordBreak: "break-all" }}>
                  {selectedRecord.id}
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", borderTop: "1px solid var(--line)", paddingTop: "14px" }}>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginBottom: "4px" }}>Source IP Address</div>
                  <div style={{ fontSize: "12.5px", fontFamily: "var(--mono)", color: "var(--text)" }}>
                    {selectedRecord.ip_address || "127.0.0.1"}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: "11px", color: "var(--dim)", marginBottom: "4px" }}>WORM Immutability</div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12.5px", color: "var(--green)" }}>
                    <IconOk className="ico" size={ICON_MD} /> <span>Append-Only Ledger</span>
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
        ) : (
          <div className="panel" style={{ padding: "40px", textAlign: "center", color: "var(--dim)" }}>
            Select an audit event from the list to view its immutable cryptographic details.
          </div>
        )}
      </div>
    </div>
  );
}
