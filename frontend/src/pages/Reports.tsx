import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { getToken, apiReportTemplates, apiReportScheduleCreate } from "../lib/api.js";

export default function Reports() {
  const snaps = useLive<{ snapshots: any[]; total?: number }>("/api/v1/report-snapshots", { snapshots: [] });
  const sched = useLive<{ schedules: any[] }>("/api/v1/report-schedules", { schedules: [] });
  const tpl = useLive<{ templates: any[] }>("/api/v1/report-templates", { templates: [] });
  const snapshots = snaps.data.snapshots ?? [];
  const schedules = sched.data.schedules ?? [];
  const templates = tpl.data.templates ?? [];

  // create-schedule form
  const [tplId, setTplId] = useState<string>("");
  const [freq, setFreq] = useState<"monthly" | "quarterly">("quarterly");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const reqCount = (t: any) => Array.isArray(t.requirements) ? t.requirements.length : (typeof t.requirements === "number" ? t.requirements : 0);

  const create = async () => {
    const id = tplId || templates.find((t) => t.id !== "custom")?.id;
    if (!id || !name.trim()) { setMsg({ ok: false, text: "pick a template and name the schedule" }); return; }
    setBusy(true);
    const r = await apiReportScheduleCreate({ name: name.trim(), template_id: id, frequency: freq, ...(target.trim() ? { scan_target: target.trim() } : {}) });
    setBusy(false);
    if (r.ok) { setMsg({ ok: true, text: `scheduled (next run ${r.data?.next_run_at ?? "—"})` }); setName(""); sched.reload(); }
    else setMsg({ ok: false, text: r.error ?? "failed" });
  };

  const downloadPdf = (id: string) => {
    const url = `/api/v1/report-snapshots/${encodeURIComponent(id)}/pdf`;
    fetch(url, { headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) } })
      .then((r) => (r.ok ? r.blob() : Promise.reject(r.status)))
      .then((blob) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `report-${id}.pdf`;
        a.click();
        URL.revokeObjectURL(a.href);
      })
      .catch(() => {});
  };

  return (
    <>
      <PageHead
        crumb="operate / reports"
        title="Reports"
        sub="Framework compliance reports — generated deterministically from the evidence store and HMAC-signed"
        right={<Badge tone={snapshots.length ? "green" : ""}><span className="dot" /> {snapshots.length} GENERATED · {schedules.length} SCHEDULED</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={snaps.loading || sched.loading || tpl.loading} error={snaps.error || sched.error || tpl.error} /></div>

      <Panel title="Compliance frameworks" sub="versioned requirement catalogs — schedule one to produce a signed report">
        <Table
          head={["framework", "source", "requirements", "select"]}
          rows={templates.map((t) => [
            <span key="n" style={{ fontWeight: 600 }}>{t.name}</span>,
            <Badge key="s" tone={t.source === "native" ? "green" : "violet"}>{t.source ?? "—"}</Badge>,
            <span className="num" key="r">{reqCount(t)}</span>,
            <button key="b" className="btn sm" style={tplId === t.id ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => { setTplId(t.id); setName((n) => n || `${t.id} report`); }}>
              {tplId === t.id ? "selected" : "choose"}
            </button>,
          ])}
        />
      </Panel>

      <Panel title="New report schedule" sub="reports render the chosen framework against the latest scan" className="mt">
        <div className="row" style={{ flexWrap: "wrap", gap: 10 }}>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="schedule name (e.g. Q4 PCI-DSS)"
            style={{ flex: 1, minWidth: 200, background: "rgba(8,12,24,0.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "9px 12px" }} />
          <select value={freq} onChange={(e) => setFreq(e.target.value as "monthly" | "quarterly")}
            style={{ background: "rgba(8,12,24,0.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontSize: 13, padding: "9px 12px" }}>
            <option value="quarterly">quarterly</option>
            <option value="monthly">monthly</option>
          </select>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="scan target (optional)"
            style={{ flex: 1, minWidth: 160, background: "rgba(8,12,24,0.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "9px 12px" }} />
          <button className="btn primary" onClick={() => void create()} disabled={busy}>{busy ? "Scheduling…" : "Create schedule"}</button>
        </div>
        {msg && <div style={{ marginTop: 10 }}><Badge tone={msg.ok ? "green" : "red"}>{msg.ok ? "✓ " : ""}{msg.text}</Badge></div>}
      </Panel>

      {schedules.length > 0 && (
        <Panel title="Scheduled reports" sub={`${schedules.length} schedule${schedules.length === 1 ? "" : "s"}`} className="mt">
          <Table
            head={["name", "template", "frequency", "next run", "target"]}
            rows={schedules.map((s) => [
              <span key="n" style={{ fontWeight: 600 }}>{s.name}</span>,
              <span className="mono" key="t">{s.template_id ?? s.framework ?? "—"}</span>,
              <Badge key="f" tone="cyan">{s.frequency ?? s.cron ?? "—"}</Badge>,
              <span className="mono" key="d" style={{ fontSize: 12 }}>{s.next_run_at ? String(s.next_run_at).replace("T", " ").slice(0, 16) : "—"}</span>,
              <span className="dim" key="tg" style={{ fontSize: 12 }}>{s.scan_target ?? "all"}</span>,
            ])}
          />
        </Panel>
      )}

      <Panel title="Generated reports" sub="signed snapshots — each run produces a deterministic, HMAC-sealed PDF" className="mt">
        {snapshots.length === 0 ? (
          <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>
            No reports yet. A schedule fires once a scan exists for its target; you can also run a compliance report on demand in Resilience.
            Every snapshot is sealed with an HMAC — nothing is fabricated.
          </p>
        ) : (
          <div className="grid cols-2">
            {snapshots.map((r) => (
              <Panel key={r.id ?? r.snapshot_id} title={r.title ?? r.name ?? r.report_type ?? "Report"}
                sub={`${(r.framework ?? r.report_type ?? "report").toUpperCase()} · ${(r.generated_at ?? r.created_at ?? "").replace("T", " ").slice(0, 19)}`}>
                <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>{r.summary ?? "Signed report produced from the live evidence store."}</p>
                <div className="row">
                  <button className="btn sm primary" disabled={!r.pdf_b64} onClick={() => downloadPdf(r.id ?? r.snapshot_id)}>Download signed PDF</button>
                  {r.pdf_signature && <Badge tone="green">HMAC signed</Badge>}
                </div>
              </Panel>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}
