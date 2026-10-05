import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { getToken, tenantFetch, apiReportTemplates, apiReportScheduleCreate, generateExitReport, downloadEngagementArchive } from "../lib/api.js";
import { StatusMark } from "../components/icons";

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

  // PoC exit report state
  const [exitClient, setExitClient] = useState("");
  const [exitWindow, setExitWindow] = useState("");
  const [exitOwner, setExitOwner] = useState("");
  const [exitAccepted, setExitAccepted] = useState("");
  const [exitBusy, setExitBusy] = useState(false);
  const [exitHash, setExitHash] = useState<string | null>(null);
  const [exitMsg, setExitMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const runArchive = async () => {
    setExitBusy(true);
    setExitMsg(null);
    const r = await downloadEngagementArchive({
      client: exitClient, window: exitWindow, owner: exitOwner, accepted_by: exitAccepted,
    });
    setExitBusy(false);
    if (r.ok) {
      setExitMsg({ ok: true, text: `archive downloaded — ${r.files} files, manifest included` });
    } else {
      setExitMsg({ ok: false, text: r.error || "archive failed" });
    }
  };

  const runExit = async (format: "json" | "md") => {
    setExitBusy(true);
    setExitMsg(null);
    setExitHash(null);
    const r = await generateExitReport(format, {
      client: exitClient, window: exitWindow, owner: exitOwner, accepted_by: exitAccepted,
    });
    setExitBusy(false);
    if (r.ok) {
      setExitHash(r.hash ?? null);
      setExitMsg({ ok: true, text: format === "md" ? "markdown report downloaded — hash verified on screen" : "report generated; hash shown below" });
    } else {
      setExitMsg({ ok: false, text: r.error || "generation failed" });
    }
  };

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
    tenantFetch(url, { headers: { ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}) } })
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
            style={{ flex: 1, minWidth: 200, background: "color-mix(in srgb, var(--bg) 80%, transparent)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "9px 12px" }} />
          <select value={freq} onChange={(e) => setFreq(e.target.value as "monthly" | "quarterly")}
            style={{ background: "color-mix(in srgb, var(--bg) 80%, transparent)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontSize: 13, padding: "9px 12px" }}>
            <option value="quarterly">quarterly</option>
            <option value="monthly">monthly</option>
          </select>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="scan target (optional)"
            style={{ flex: 1, minWidth: 160, background: "color-mix(in srgb, var(--bg) 80%, transparent)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "9px 12px" }} />
          <button className="btn primary" onClick={() => void create()} disabled={busy}>{busy ? "Scheduling…" : "Create schedule"}</button>
        </div>
        {msg && <div style={{ marginTop: 10 }}><Badge tone={msg.ok ? "green" : "red"}>{msg.ok ? <StatusMark ok muted /> : null}{msg.text}</Badge></div>}
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

      {/* PoC exit report */}
      <Panel title="PoC exit report" sub="the engagement deliverable — deterministic scoring of the collected estate against the fab-poc success criteria, sealed with a SHA-256 report hash" className="mt">
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <input className="inp" placeholder="client" value={exitClient} onChange={(e) => setExitClient(e.target.value)} style={{ flex: "1 1 150px" }} />
          <input className="inp" placeholder="engagement window" value={exitWindow} onChange={(e) => setExitWindow(e.target.value)} style={{ flex: "1 1 150px" }} />
          <input className="inp" placeholder="crypto owner" value={exitOwner} onChange={(e) => setExitOwner(e.target.value)} style={{ flex: "1 1 150px" }} />
          <input className="inp" placeholder="accepted by (sign-off)" value={exitAccepted} onChange={(e) => setExitAccepted(e.target.value)} style={{ flex: "1 1 170px" }} />
        </div>
        <div className="row" style={{ gap: 8, marginTop: 10 }}>
          <button className="btn sm" disabled={exitBusy} onClick={() => void runExit("json")}>
            {exitBusy ? "Generating…" : "Generate (hash only)"}
          </button>
          <button className="btn sm primary" disabled={exitBusy} onClick={() => void runExit("md")}>
            {exitBusy ? "Generating…" : "Download markdown report"}
          </button>
          <button className="btn sm" disabled={exitBusy} onClick={() => void runArchive()}>
            {exitBusy ? "Bundling…" : "Download engagement archive (ZIP)"}
          </button>
          {exitHash && <Badge tone="green">SHA-256 {exitHash.slice(0, 16)}…</Badge>}
        </div>
        {exitMsg && (
          <div style={{ marginTop: 8, fontSize: 12.5, color: exitMsg.ok ? "var(--green)" : "var(--red)" }}>
            <StatusMark ok={exitMsg.ok} muted /> {exitMsg.text}
          </div>
        )}
        <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          SC-4 (client acceptance) stays unmet until a name is entered — acceptance is a human
          sign-off, the report never infers it. Verify any report independently by recomputing the
          canonical-JSON SHA-256.
        </div>
      </Panel>

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
