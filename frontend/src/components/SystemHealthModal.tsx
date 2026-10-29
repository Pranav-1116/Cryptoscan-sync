import { Link } from "react-router-dom";
/* SystemHealthModal — quick platform health panel for the header.
 *
 * Data is real: it probes /healthz and the live ops SLO endpoint via the
 * shared api.ts helpers. When the backend is unreachable every service is
 * reported Offline — the modal never fabricates green.
 */
import React, { useEffect, useState } from "react";
import {
  apiScannerEnginesHealth, apiSystemHealthStatus,
  ScannerEngineHealth, SystemServiceHealth,
} from "../lib/api.js";
import { IconClose, IconHealth, ICON_MD, ICON_LG } from "./icons";

function statusColor(s: string): string {
  if (s === "Operational" || s === "Healthy") return "var(--green)";
  if (s === "Degraded" || s === "Paused") return "var(--amber)";
  if (s === "Not measured" || s === "On demand") return "var(--dim)";
  return "var(--red)";
}

export default function SystemHealthModal({
  isOpen, onClose,
}: {
  isOpen: boolean; onClose: () => void;
}) {
  const [services, setServices] = useState<SystemServiceHealth[]>([]);
  const [engines, setEngines] = useState<ScannerEngineHealth[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    setLoading(true);
    Promise.all([apiSystemHealthStatus(), apiScannerEnginesHealth()])
      .then(([s, e]) => {
        if (cancelled) return;
        setServices(s);
        setEngines(e);
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [isOpen]);

  if (!isOpen) return null;

  const allDown = services.length > 0 && services.every((s) => s.status === "Offline");

  return (
    <div
      style={{ position: "fixed", inset: 0, zIndex: 10001, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)", display: "flex", alignItems: "center", justifyContent: "center" }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{ background: "var(--bg-2)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", padding: "20px", width: "560px", maxWidth: "92vw", maxHeight: "82vh", overflowY: "auto", boxShadow: "0 20px 40px rgba(0,0,0,0.6)" }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
          <div style={{ fontWeight: 700, fontSize: "15px", color: "var(--text)" }} className="ico-row"><IconHealth className="ico" size={ICON_LG} /><span>Platform Health</span></div>
          <button onClick={onClose} className="icon-btn" aria-label="Close"><IconClose size={ICON_MD} /></button>
        </div>

        {loading && <div className="dim" style={{ fontSize: 12 }}>probing services…</div>}

        {!loading && allDown && (
          <div className="badge" style={{ display: "inline-block", marginBottom: 10, borderColor: "var(--red)", color: "var(--red)" }}>
            <span className="dot" /> backend offline — all services unreachable
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "16px" }}>
          {services.map((s) => (
            <div
              key={s.name}
              style={{ display: "flex", alignItems: "center", gap: "10px", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px", fontSize: "12.5px" }}
            >
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: statusColor(s.status), flexShrink: 0 }} />
              <span style={{ fontWeight: 600, flex: 1 }}>{s.name}</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>
                {s.latencyMs === null || s.status === "Offline" ? "—" : `${s.latencyMs} ms`}
              </span>
              <span style={{ fontSize: 11, color: statusColor(s.status), width: 92, textAlign: "right" }}>{s.status}</span>
            </div>
          ))}
        </div>

        <div style={{ fontWeight: 600, fontSize: "12px", color: "var(--dim)", marginBottom: "8px" }}>SCANNER ENGINES</div>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {engines.map((e) => (
            <div
              key={e.id}
              style={{ display: "flex", alignItems: "center", gap: "10px", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px", fontSize: "12.5px" }}
            >
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: statusColor(e.status), flexShrink: 0 }} />
              <span style={{ fontWeight: 600, flex: 1 }}>{e.name}</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>
                {e.estateAssets === null ? "—" : `${e.estateAssets} estate assets`}
              </span>
              <span style={{ fontSize: 11, color: statusColor(e.status), width: 72, textAlign: "right" }}>{e.status}</span>
            </div>
          ))}
        </div>

        <p className="dim" style={{ fontSize: 11, marginTop: "12px" }}>
          Live detail: <Link to="/system-health" onClick={onClose} style={{ color: "var(--cyan)" }}>System Health page</Link>
        </p>
      </div>
    </div>
  );
}
