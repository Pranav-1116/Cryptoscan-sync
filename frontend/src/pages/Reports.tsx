import React, { useState, useMemo } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconTarget, IconClock, IconSecurity, IconComponent, IconInfo } from "../components/icons";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { getToken, tenantFetch, apiReportTemplates, apiReportScheduleCreate, apiReportSnapshotPin, generateExitReport, downloadEngagementArchive } from "../lib/api.js";
import { StatusMark } from "../components/icons";
import { RequireRole } from "../lib/auth.js";
import { SCHEDULE_WRITE_ROLES } from "../lib/rbac.js";

export default function Reports() {
  const snaps = useLive<{ snapshots: any[]; total?: number }>("/api/v1/report-snapshots", { snapshots: [] });
  const sched = useLive<{ schedules: any[] }>("/api/v1/report-schedules", { schedules: [] });
  const tpl = useLive<{ templates: any[] }>("/api/v1/report-templates", { templates: [] });
  const snapshots = snaps.data.snapshots ?? [];
  const schedules = sched.data.schedules ?? [];
  const templates = tpl.data.templates ?? [];
  const [tplId, setTplId] = useState<string>(""); const [freq, setFreq] = useState<"monthly" | "quarterly">("quarterly"); const [name, setName] = useState(""); const [target, setTarget] = useState(""); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [pinScan, setPinScan] = useState(""); const [pinTpl, setPinTpl] = useState(""); const [pinBusy, setPinBusy] = useState(false); const [pinMsg, setPinMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [exitClient, setExitClient] = useState(""); const [exitWindow, setExitWindow] = useState(""); const [exitOwner, setExitOwner] = useState(""); const [exitAccepted, setExitAccepted] = useState(""); const [exitBusy, setExitBusy] = useState(false); const [exitHash, setExitHash] = useState<string | null>(null); const [exitMsg, setExitMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const runPin = async () => { setPinBusy(true); setPinMsg(null); const r = await apiReportSnapshotPin(pinScan.trim(), pinTpl || (templates[0]?.template_id ?? "pci-dss-4.0")); setPinBusy(false); if (r.ok && r.data) setPinMsg({ ok: true, text: `${r.data.created ? "pinned" : "already pinned (identical rendering)"} — ${r.data.id.slice(0, 8)}… payload ${r.data.payload_hash?.slice(0, 12) ?? "unhashed"}…` }); else setPinMsg({ ok: false, text: r.error ?? "pin failed" }); };
  const runArchive = async () => { setExitBusy(true); setExitMsg(null); const r = await downloadEngagementArchive({ client: exitClient, window: exitWindow, owner: exitOwner, accepted_by: exitAccepted }); setExitBusy(false); if (r.ok) setExitMsg({ ok: true, text: `archive downloaded — ${r.files} files, manifest included` }); else setExitMsg({ ok: false, text: r.error || "archive failed" }); };
  const runExit = async (format: "json" | "md") => { setExitBusy(true); setExitMsg(null); setExitHash(null); const r = await generateExitReport(format, { client: exitClient, window: exitWindow, owner: exitOwner, accepted_by: exitAccepted }); setExitBusy(false); if (r.ok) { setExitHash(r.hash ?? null); setExitMsg({ ok: true, text: format === "md" ? "markdown report downloaded — hash verified on screen" : "report generated; hash shown below" }); } else setExitMsg({ ok: false, text: r.error || "generation failed" }); };
  const reqCount = (t: any) => Array.isArray(t.requirements) ? t.requirements.length : (typeof t.requirements === "number" ? t.requirements : 0);
  const create = async () => { const id = tplId || templates.find((t) => t.id !== "custom")?.id; if (!id || !name.trim()) { setMsg({ ok: false, text: "pick a template and name the schedule" }); return; } setBusy(true); const r = await apiReportScheduleCreate({ name: name.trim(), template_id: id, frequency: freq, ...(target.trim() ? { scan_target: target.trim() } : {}) }); setBusy(false); if (r.ok) { setMsg({ ok: true, text: `scheduled (next run ${r.data?.next_run_at ?? "—"})` }); setName(""); sched.reload(); } else setMsg({ ok: false, text: r.error ?? "failed" }); };
  const downloadPdf = (id: string) => { const url = `/api/v1/report-snapshots/${encodeURIComponent(id)}/pdf`; tenantFetch(url, { headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) } }).then((r) => (r.ok ? r.blob() : Promise.reject(r.status))).then((blob) => { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `report-${id}.pdf`; a.click(); URL.revokeObjectURL(a.href); }).catch(() => {}); };
  const signedCount = snapshots.filter((r: any) => r.pdf_signature).length;
  const contentAddressed = snapshots.filter((r: any) => r.payload_hash).length;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--cyan) 12%, transparent)", border: "1px solid var(--cyan)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--cyan)" }} /> OUTPUT · FRAMEWORK REPORTS · HMAC-SIGNED
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--cyan)", color: "#fff" }}><IconComponent size={18} /></span>
            Reports
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            Framework compliance reports — <b style={{ color: "var(--text)" }}>generated deterministically from the evidence store and HMAC-signed</b>. Content-addressed: identical payloads collapse, every PDF carries its scan→BOM chain.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>SCAN → BOM → REPORT · SIGNED PDF · CONTENT-ADDRESSED</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={snapshots.length ? Math.min(1, signedCount / Math.max(1, snapshots.length)) : 0} label={String(snapshots.length)} sub="reports" tone={snapshots.length ? "cyan" : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>REPORT ESTATE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 135, lineHeight: 1.4 }}>{signedCount} signed · {contentAddressed} content-addressed · {schedules.length} schedules</div>
              <div style={{ marginTop: 6 }}><Bar value={snapshots.length ? contentAddressed / snapshots.length : 0} tone="cyan" /></div>
            </div>
          </Panel>
        </div>
      </div>

      <div style={{ marginBottom: 12 }}><LiveStatus loading={snaps.loading || sched.loading || tpl.loading} error={snaps.error || sched.error || tpl.error} /></div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>GENERATED REPORTS</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{snapshots.length}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{signedCount} HMAC-signed</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--cyan) 14%, transparent)", border: "1px solid var(--cyan)", color: "var(--cyan)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={snapshots.length ? signedCount / snapshots.length : 0} tone="cyan" /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Deterministic, signed, verifiable</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>TEMPLATES</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{templates.length}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>framework catalogs</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)", color: "var(--violet)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={Math.min(1, templates.length / 8)} tone="violet" /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--green)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SCHEDULED REPORTS</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{schedules.length}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>next run on cron</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--green) 14%, transparent)", border: "1px solid var(--green)", color: "var(--green)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={schedules.length ? 0.7 : 0} tone={schedules.length ? "green" : "slate"} /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${contentAddressed ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>CONTENT-ADDRESSED</div><div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{contentAddressed}/{snapshots.length || "—"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>payload SHA-256 — identical collapse</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: contentAddressed ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${contentAddressed ? "var(--green)" : "var(--line)"}`, color: contentAddressed ? "var(--green)" : "var(--faint)" }}><IconInfo size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={snapshots.length ? contentAddressed / snapshots.length : 0} tone={contentAddressed ? "green" : "slate"} /></div>
        </div>
      </div>

      <Panel title="Compliance frameworks" sub="Versioned requirement catalogs — schedule one to produce a signed report" style={{ padding: 0, overflow: "hidden" } as any}>
        <div style={{ padding: "10px 14px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>{templates.length} frameworks · requirements per catalog · native vs imported source</span>
          <Badge tone="cyan">{tplId ? "1 selected" : "choose one →"}</Badge>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead><tr><th>Framework</th><th>Source</th><th>Requirements</th><th>Select</th></tr></thead>
            <tbody>
              {templates.map((t: any) => (
                <tr key={t.id} style={tplId === t.id ? { background: "color-mix(in srgb, var(--cyan) 8%, transparent)" } : undefined}>
                  <td style={{ fontWeight: 700, fontSize: 12 }}>{t.name}</td>
                  <td><Badge tone={t.source === "native" ? "green" : "violet"}>{t.source ?? "—"}</Badge></td>
                  <td style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{reqCount(t)}</td>
                  <td><button onClick={() => { setTplId(t.id); setName((n) => n || `${t.id} report`); }} style={{ fontSize: 12, padding: "5px 12px", borderRadius: "var(--r)", border: `1px solid ${tplId === t.id ? "var(--cyan)" : "var(--line)"}`, background: tplId === t.id ? "var(--cyan)" : "var(--panel-2)", color: tplId === t.id ? "#fff" : "var(--text)", fontWeight: 700, cursor: "pointer" }}>{tplId === t.id ? "selected" : "choose"}</button></td>
                </tr>
              ))}
              {!templates.length && <tr><td colSpan={4} style={{ padding: 16, textAlign: "center", color: "var(--faint)" }}>No frameworks yet — loading…</td></tr>}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="New report schedule" sub="Reports render the chosen framework against the latest scan" style={{ marginTop: 14 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="schedule name (e.g. Q4 PCI-DSS)" style={{ flex: 1, minWidth: 200, background: "var(--bg)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, padding: "8px 10px" }} />
          <select value={freq} onChange={(e) => setFreq(e.target.value as "monthly" | "quarterly")} style={{ background: "var(--bg)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontSize: 12, padding: "8px 10px" }}><option value="quarterly">quarterly</option><option value="monthly">monthly</option></select>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="scan target (optional)" style={{ flex: 1, minWidth: 160, background: "var(--bg)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12, padding: "8px 10px" }} />
          <RequireRole anyOf={[...SCHEDULE_WRITE_ROLES]}>
            <button onClick={() => void create()} disabled={busy} style={{ padding: "8px 14px", borderRadius: "var(--r)", background: "var(--cyan)", color: "#fff", border: "1px solid var(--cyan)", fontWeight: 700, fontSize: 12, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}>{busy ? "Scheduling…" : "Create schedule"}</button>
          </RequireRole>
        </div>
        {msg && <div style={{ marginTop: 10, padding: "8px 10px", borderRadius: "var(--r)", background: msg.ok ? "color-mix(in srgb, var(--green) 10%, transparent)" : "color-mix(in srgb, var(--red) 10%, transparent)", border: `1px solid ${msg.ok ? "var(--green)" : "var(--red)"}`, fontSize: 12 }}><Badge tone={msg.ok ? "green" : "red"}>{msg.ok ? "OK" : "ERR"}</Badge> {msg.text}</div>}
      </Panel>

      {schedules.length > 0 && (
        <Panel title="Scheduled reports" sub={`${schedules.length} schedule${schedules.length === 1 ? "" : "s"}`} style={{ marginTop: 14, padding: 0, overflow: "hidden" } as any}>
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th>Name</th><th>Template</th><th>Frequency</th><th>Next run</th><th>Target</th></tr></thead>
              <tbody>
                {schedules.map((s: any, i: number) => (
                  <tr key={i}><td style={{ fontWeight: 700, fontSize: 12 }}>{s.name}</td><td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{s.template_id ?? s.framework ?? "—"}</td><td><Badge tone="cyan">{s.frequency ?? s.cron ?? "—"}</Badge></td><td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{s.next_run_at ? String(s.next_run_at).replace("T", " ").slice(0, 16) : "—"}</td><td style={{ fontSize: 11, color: "var(--dim)" }}>{s.scan_target ?? "all"}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <Panel title="PoC exit report" sub="Engagement deliverable — deterministic scoring against fab-poc success criteria, sealed SHA-256" style={{ marginTop: 14 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 8 }}>
          <input placeholder="client" value={exitClient} onChange={(e) => setExitClient(e.target.value)} style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontSize: 12 }} />
          <input placeholder="engagement window" value={exitWindow} onChange={(e) => setExitWindow(e.target.value)} style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontSize: 12 }} />
          <input placeholder="crypto owner" value={exitOwner} onChange={(e) => setExitOwner(e.target.value)} style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontSize: 12 }} />
          <input placeholder="accepted by (sign-off)" value={exitAccepted} onChange={(e) => setExitAccepted(e.target.value)} style={{ padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontSize: 12 }} />
        </div>
        <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
          <button disabled={exitBusy} onClick={() => void runExit("json")} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", cursor: exitBusy ? "not-allowed" : "pointer" }}>{exitBusy ? "Generating…" : "Generate (hash only)"}</button>
          <button disabled={exitBusy} onClick={() => void runExit("md")} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--cyan)", color: "#fff", border: "1px solid var(--cyan)", fontWeight: 700, cursor: exitBusy ? "not-allowed" : "pointer" }}>{exitBusy ? "Generating…" : "Download markdown report"}</button>
          <button disabled={exitBusy} onClick={() => void runArchive()} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", cursor: exitBusy ? "not-allowed" : "pointer" }}>{exitBusy ? "Bundling…" : "Download engagement archive (ZIP)"}</button>
          {exitHash && <Badge tone="green">SHA-256 {exitHash.slice(0, 16)}…</Badge>}
        </div>
        {exitMsg && <div style={{ marginTop: 8, fontSize: 12, color: exitMsg.ok ? "var(--green)" : "var(--red)", background: exitMsg.ok ? "color-mix(in srgb, var(--green) 8%, transparent)" : "color-mix(in srgb, var(--red) 8%, transparent)", border: `1px solid ${exitMsg.ok ? "var(--green)" : "var(--red)"}`, borderRadius: "var(--r)", padding: "8px 10px" }}>{exitMsg.text}</div>}
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>SC-4 (client acceptance) stays unmet until a name is entered — acceptance is human sign-off, never inferred. Verify any report by recomputing canonical-JSON SHA-256.</div>
      </Panel>

      <Panel title="Pin a scan's report now" sub="Content-addressed version authority — exact payload (signed PDF + scan→BOM chain) hashed SHA-256; identical pins collapse" style={{ marginTop: 14 }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input placeholder="scan id" value={pinScan} onChange={(e) => setPinScan(e.target.value)} style={{ flex: "1 1 220px", padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12 }} />
          <select value={pinTpl} onChange={(e) => setPinTpl(e.target.value)} style={{ flex: "0 1 200px", padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontSize: 12 }}>
            <option value="">template (default first)</option>
            {templates.map((t: any) => <option key={t.template_id ?? t.id} value={t.template_id ?? t.id}>{t.template_id ?? t.id}</option>)}
          </select>
          <button disabled={pinBusy || !pinScan.trim()} onClick={() => void runPin()} style={{ fontSize: 12, padding: "7px 14px", borderRadius: "var(--r)", background: pinScan.trim() ? "var(--cyan)" : "var(--panel-2)", color: pinScan.trim() ? "#fff" : "var(--faint)", border: "1px solid var(--line)", fontWeight: 700, cursor: pinScan.trim() ? "pointer" : "not-allowed" }}>{pinBusy ? "Pinning…" : "Pin report"}</button>
        </div>
        {pinMsg && <div style={{ marginTop: 8, fontSize: 12, color: pinMsg.ok ? "var(--green)" : "var(--red)", background: pinMsg.ok ? "color-mix(in srgb, var(--green) 8%, transparent)" : "color-mix(in srgb, var(--red) 8%, transparent)", border: `1px solid ${pinMsg.ok ? "var(--green)" : "var(--red)"}`, borderRadius: "var(--r)", padding: "8px 10px" }}>{pinMsg.text}</div>}
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8 }}>Schedules render “latest completed scan of target”; a pin freezes the EXACT scan you name. Pinned report cites scan's pinned CBOM snapshot (or says none exists).</div>
      </Panel>

      <Panel title="Generated reports" sub="Signed snapshots — each run produces a deterministic, HMAC-sealed PDF" style={{ marginTop: 14 }}>
        {snapshots.length === 0 ? <p style={{ fontSize: 12, color: "var(--dim)", textAlign: "center", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 16, margin: 0 }}>No reports yet. A schedule fires once a scan exists for its target; you can also run a compliance report on demand in Resilience. Every snapshot is sealed with HMAC — nothing fabricated.</p> : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 12 }}>
            {snapshots.map((r: any) => (
              <div key={r.id ?? r.snapshot_id} style={{ padding: 14, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: `3px solid ${r.pdf_signature ? "var(--green)" : "var(--slate)"}` }}>
                <div style={{ fontWeight: 800, fontSize: 13 }}>{r.title ?? r.name ?? r.report_type ?? "Report"}</div>
                <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 2 }}>{(r.framework ?? r.report_type ?? "report").toUpperCase()} · {(r.generated_at ?? r.created_at ?? "").replace("T", " ").slice(0, 19)}</div>
                <p style={{ fontSize: 12, color: "var(--dim)", margin: "8px 0" }}>{r.summary ?? "Signed report from live evidence store."}</p>
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <button disabled={!r.pdf_b64} onClick={() => downloadPdf(r.id ?? r.snapshot_id)} style={{ fontSize: 11, padding: "5px 10px", borderRadius: "var(--r)", background: r.pdf_b64 ? "var(--cyan)" : "var(--panel)", color: r.pdf_b64 ? "#fff" : "var(--faint)", border: "1px solid var(--line)", cursor: r.pdf_b64 ? "pointer" : "not-allowed", fontWeight: 700 }}>Download signed PDF</button>
                  {r.pdf_signature && <Badge tone="green">HMAC signed</Badge>}
                  {r.payload_hash ? <Badge tone="cyan">content-addressed {String(r.payload_hash).slice(0, 10)}…</Badge> : <span style={{ fontSize: 10, color: "var(--faint)" }}>legacy row — payload not content-addressed</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
