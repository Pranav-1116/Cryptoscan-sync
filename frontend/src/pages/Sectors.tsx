import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import {
  apiListSectors, apiActiveSector, apiSetActiveSector,
  type ApiResult, type SectorProfile,
} from "../lib/api.js";
import { RequireRole } from "../lib/auth.js";

/* Sector Layer — one universal scanning engine; the sector profile changes
   context only (criticality, policy packs, compliance frameworks, evidence,
   scan modes). This page lists the catalog and sets the org's active sector,
   rendered in the standard ZELNX panel system. RBAC: only superadmin/ciso/
   admin can change the active sector. */

export default function Sectors() {
  const [sectors, setSectors] = useState<SectorProfile[]>([]);
  const [active, setActive] = useState<string>("generic");
  const [source, setSource] = useState<"live" | "offline">("offline");
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    void apiListSectors().then((r: ApiResult<{ sectors: SectorProfile[] }>) => {
      setSource(r.source);
      if (r.data?.sectors) setSectors(r.data.sectors);
    });
    void apiActiveSector().then((r: ApiResult<{ sector: string }>) => {
      if (r.data?.sector) setActive(r.data.sector);
    });
  }, []);

  const activeProfile = useMemo(() => sectors.find((s) => s.id === active), [sectors, active]);

  const select = async (id: string) => {
    if (id === active) return;
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
    <>
      <PageHead
        crumb="govern / sector profiles"
        title="Multi-sector profiles"
        sub="One deterministic scanning engine — the sector only changes which assets matter, which policy packs and frameworks apply, criticality weighting, evidence and scan modes"
        right={
          <>
            <Badge tone={source === "live" ? "green" : "slate"}><span className="dot" /> {source === "live" ? "live control plane" : "offline"}</Badge>
            <Badge tone="cyan">active: {active}</Badge>
          </>
        }
      />

      {/* active sector summary */}
      {activeProfile && (
        <Panel
          title={activeProfile.name}
          sub={`active profile · ${activeProfile.id} · ${activeProfile.compliance_frameworks.length} frameworks · ${activeProfile.policy_packs.length} policy packs`}
        >
          <p className="dim" style={{ fontSize: 13, lineHeight: 1.6, margin: "0 0 12px", maxWidth: 900 }}>
            {activeProfile.description}
          </p>
          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            {activeProfile.compliance_frameworks.map((fw) => <Badge key={fw} tone="cyan">{fw}</Badge>)}
            {activeProfile.policy_packs.map((p) => <Badge key={p} tone="violet">{p}</Badge>)}
          </div>
        </Panel>
      )}

      <RequireRole
        anyOf={["superadmin", "admin", "ciso"]}
        fallback={
          <div className="dim" style={{ fontSize: 12, color: "var(--amber)", margin: "12px 2px" }}>
            Only superadmin / CISO / admin can change the active sector.
          </div>
        }
      />
      {msg && (
        <div style={{ margin: "10px 2px", fontFamily: "var(--mono)", fontSize: 12, color: msg.ok ? "var(--green)" : "var(--red)" }}>
          {msg.ok ? "✓ " : "✕ "}{msg.text}
        </div>
      )}

      <Panel
        title="Sector catalog"
        sub={`${sectors.length} profiles · select one to apply its policy context`}
        className="mt"
      >
        {sectors.length === 0 ? (
          <div className="dim" style={{ fontSize: 13 }}>
            {source === "live" ? "No sector profiles returned." : "Backend offline — sector catalog unavailable."}
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(330px, 1fr))", gap: 14 }}>
            {sectors.map((s) => {
              const isActive = s.id === active;
              return (
                <div
                  key={s.id}
                  className="plug-card"
                  style={{
                    borderColor: isActive ? "var(--cyan)" : undefined,
                    boxShadow: isActive ? "0 0 0 1px var(--cyan)" : undefined,
                    padding: 16,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                    <div>
                      <div style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: isActive ? "var(--cyan)" : "var(--faint)", letterSpacing: ".06em" }}>
                        {s.id}
                      </div>
                      <div style={{ fontSize: 15, fontWeight: 700, margin: "3px 0 6px" }}>{s.name}</div>
                    </div>
                    {isActive && <Badge tone="green"><span className="dot" /> active</Badge>}
                  </div>
                  <p className="dim" style={{ fontSize: 12, lineHeight: 1.55, margin: "0 0 12px", minHeight: 34 }}>{s.description}</p>

                  <div className="dim" style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 5 }}>compliance frameworks</div>
                  <div className="row" style={{ gap: 5, flexWrap: "wrap", marginBottom: 10 }}>
                    {s.compliance_frameworks.slice(0, 6).map((fw) => <span key={fw} className="cap-chip">{fw}</span>)}
                  </div>

                  <div className="dim" style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 5 }}>policy packs</div>
                  <div className="row" style={{ gap: 5, flexWrap: "wrap", marginBottom: 10 }}>
                    {s.policy_packs.map((p) => <span key={p} className="cap-chip">{p}</span>)}
                  </div>

                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
                    <div>
                      <div className="dim" style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 5 }}>scan modes</div>
                      <div className="row" style={{ gap: 5, flexWrap: "wrap" }}>
                        {(s.recommended_modes || []).slice(0, 4).map((m) => (
                          <span key={m.id} className="cap-chip" style={m.ot_safe ? { color: "var(--cyan)", borderColor: "#14637a" } : undefined}>
                            {m.ot_safe ? "🛰 " : ""}{m.id}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div className="dim" style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 5 }}>separation</div>
                      <div className="row" style={{ gap: 5, flexWrap: "wrap" }}>
                        {(s.environment_separation || []).map((e) => <span key={e} className="cap-chip">{e}</span>)}
                      </div>
                    </div>
                  </div>

                  {(s.required_evidence?.length ?? 0) > 0 && (
                    <div className="dim" style={{ fontSize: 10.5, lineHeight: 1.5, marginBottom: 8 }}>
                      evidence: {(s.required_evidence ?? []).slice(0, 3).join(" · ")}
                    </div>
                  )}

                  <RequireRole
                    anyOf={["superadmin", "admin", "ciso"]}
                    fallback={
                      <button
                        className={`btn sm ${isActive ? "" : "primary"}`}
                        disabled
                        title="Only superadmin, admin, or ciso can change the active sector"
                        style={{ width: "100%", marginTop: 4 }}
                      >
                        {isActive ? "active profile" : "read-only role"}
                      </button>
                    }
                  >
                    <button
                      className={`btn sm ${isActive ? "" : "primary"}`}
                      disabled={isActive || busy === s.id}
                      onClick={() => void select(s.id)}
                      style={{ width: "100%", marginTop: 4 }}
                    >
                      {busy === s.id ? "applying…" : isActive ? "active profile" : "set as active sector"}
                    </button>
                  </RequireRole>
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </>
  );
}
