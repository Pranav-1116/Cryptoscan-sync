import React, { useEffect, useState } from "react";
import {
  apiListSectors, apiActiveSector, apiSetActiveSector,
  type ApiResult, type SectorProfile,
} from "../lib/api.js";
import { Corners, Kicker } from "../components/ui.jsx";

/* Sector Layer — one universal scanning engine; the sector profile changes
   context only (criticality, policy packs, compliance frameworks, evidence,
   scan modes). This page lists the catalog and sets the org's active sector. */

const chip: React.CSSProperties = {
  fontFamily: "var(--mono)", fontSize: 10.5, padding: "3px 8px", borderRadius: 6,
  border: "1px solid var(--line-strong)", color: "var(--dim)", background: "transparent",
};
const chipActive: React.CSSProperties = { ...chip, color: "var(--cyan)", border: "1px solid var(--cyan)", background: "rgba(34,211,238,.1)" };

function Pill({ children, on }: { children: React.ReactNode; on?: boolean }) {
  return <span style={on ? chipActive : chip}>{children}</span>;
}

export default function Sectors() {
  const [sectors, setSectors] = useState<SectorProfile[]>([]);
  const [active, setActive] = useState<string>("generic");
  const [source, setSource] = useState<"live" | "offline">("offline");
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [roles, setRoles] = useState<string[]>([]);

  useEffect(() => {
    try { setRoles(JSON.parse(localStorage.getItem("zelinx_roles") || "[]")); } catch { /* ignore */ }
    void apiListSectors().then((r: ApiResult<{ sectors: SectorProfile[] }>) => {
      setSource(r.source);
      if (r.data?.sectors) setSectors(r.data.sectors);
    });
    void apiActiveSector().then((r: ApiResult<{ sector: string }>) => {
      if (r.data?.sector) setActive(r.data.sector);
    });
  }, []);

  const canSet = roles.some((role) => ["superadmin", "ciso", "admin"].includes(role));

  const select = async (id: string) => {
    if (id === active || !canSet) return;
    setBusy(id);
    setMsg(null);
    const res = await apiSetActiveSector(id);
    setBusy(null);
    if (res.ok) {
      setActive(id);
      setMsg({ ok: true, text: `Active sector set to ${id}` });
    } else {
      setMsg({ ok: false, text: res.error || "could not set sector" });
    }
  };

  return (
    <div style={{ padding: "26px 28px" }}>
      <div className="frame" style={{ position: "relative", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 16, padding: "26px 26px 22px", marginBottom: 22 }}>
        <Corners />
        <Kicker>Sector Layer · universal engine</Kicker>
        <h1 style={{ fontSize: 26, margin: "8px 0 6px" }}>Sector Profiles</h1>
        <p className="dim" style={{ fontSize: 13, margin: 0, maxWidth: 820, lineHeight: 1.6 }}>
          One scanning engine for every estate. The sector never forks the scanner — it changes <b>which assets
          matter most</b>, which <b>policy packs</b> and <b>compliance frameworks</b> apply, how <b>criticality</b> is
          weighted, what <b>evidence</b> is required, and which <b>scan modes</b> are recommended (e.g. passive-only for OT).
        </p>
        <div style={{ marginTop: 12, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ ...chip, color: "var(--cyan)" }}>active: {active}</span>
          <span className="dim" style={{ fontSize: 11.5 }}>
            {source === "live" ? "● live control plane" : "● control plane offline — no live data yet"}
          </span>
          {!canSet && (
            <span className="dim" style={{ fontSize: 11.5, color: "var(--amber)" }}>
              superadmin/ciso can change the active sector
            </span>
          )}
        </div>
        {msg && (
          <div style={{ marginTop: 10, fontFamily: "var(--mono)", fontSize: 12, color: msg.ok ? "var(--green)" : "var(--red)" }}>
            {msg.ok ? "✓ " : "✕ "}{msg.text}
          </div>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: 14 }}>
        {sectors.map((s) => {
          const isActive = s.id === active;
          return (
            <div key={s.id} className="frame" style={{
              position: "relative", background: "var(--panel)", border: `1px solid ${isActive ? "var(--cyan)" : "var(--line)"}`,
              borderRadius: 14, padding: "18px 18px 16px", opacity: s.id === "generic" ? 0.92 : 1,
            }}>
              <Corners />
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: isActive ? "var(--cyan)" : "var(--dim)", letterSpacing: ".06em" }}>
                    {s.id}
                  </div>
                  <h3 style={{ margin: "4px 0 6px", fontSize: 16 }}>{s.name}</h3>
                </div>
                {isActive && <span style={{ ...chipActive, whiteSpace: "nowrap" }}>● active</span>}
              </div>
              <p className="dim" style={{ fontSize: 12, lineHeight: 1.55, margin: "0 0 12px", minHeight: 34 }}>{s.description}</p>

              <div style={{ marginBottom: 10 }}>
                <div className="dim" style={labelStyle}>compliance frameworks</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {s.compliance_frameworks.slice(0, 6).map((fw) => <Pill key={fw} on={isActive}>{fw}</Pill>)}
                </div>
              </div>
              <div style={{ marginBottom: 10 }}>
                <div className="dim" style={labelStyle}>policy packs</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                  {s.policy_packs.map((p) => <Pill key={p} on={isActive}>{p}</Pill>)}
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
                <div>
                  <div className="dim" style={labelStyle}>scan modes</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                    {(s.recommended_modes || []).slice(0, 4).map((m) => (
                      <Pill key={m.id} on={isActive}>{m.ot_safe ? "🛰 " : ""}{m.id}</Pill>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="dim" style={labelStyle}>separation</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
                    {(s.environment_separation || []).map((e) => <Pill key={e} on={isActive}>{e}</Pill>)}
                  </div>
                </div>
              </div>
              {(s.required_evidence?.length ?? 0) > 0 && (
                <div className="dim" style={{ fontSize: 11, lineHeight: 1.5 }}>
                  evidence: {(s.required_evidence ?? []).slice(0, 3).join(" · ")}
                </div>
              )}

              <button
                className={`btn ${isActive ? "" : "primary"}`}
                disabled={isActive || !canSet || busy === s.id}
                onClick={() => void select(s.id)}
                style={{ width: "100%", marginTop: 12, opacity: isActive ? 0.6 : 1 }}
              >
                {busy === s.id ? "applying…" : isActive ? "active profile" : `set as active sector`}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  fontSize: 10.5, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 5,
};
