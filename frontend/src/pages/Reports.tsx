import React from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { getToken } from "../lib/api.js";

export default function Reports() {
  const snaps = useLive<{ snapshots: any[]; total?: number }>("/api/v1/report-snapshots", { snapshots: [] });
  const sched = useLive<{ schedules: any[] }>("/api/v1/report-schedules", { schedules: [] });
  const snapshots = snaps.data.snapshots ?? [];
  const schedules = sched.data.schedules ?? [];

  const downloadPdf = (id: string) => {
    const url = `/api/v1/report-snapshots/${encodeURIComponent(id)}/pdf`;
    // signed PDF is fetched with the bearer token, then opened as a blob
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
        sub="Executive · technical · compliance · PQC — generated deterministically from the evidence store"
        right={<Badge tone={snapshots.length ? "green" : ""}><span className="dot" /> {snapshots.length} GENERATED</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={snaps.loading || sched.loading} error={snaps.error || sched.error} /></div>
      <div className="grid cols-2">
        {snapshots.map((r) => (
          <Panel key={r.id ?? r.snapshot_id} title={r.title ?? r.name ?? r.report_type ?? "Report"}
            sub={`${(r.report_type ?? r.kind ?? "report").toUpperCase()} · generated ${(r.generated_at ?? r.created_at ?? "").replace("T", " ").slice(0, 19)}`}>
            <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>
              {r.summary ?? r.framework ?? "Signed report produced from the live evidence store."}
            </p>
            <div className="row">
              <button className="btn sm primary" disabled={!r.pdf_b64} onClick={() => downloadPdf(r.id ?? r.snapshot_id)}>
                Download signed PDF
              </button>
              {r.pdf_signature && <Badge tone="green">HMAC signed</Badge>}
            </div>
          </Panel>
        ))}
      </div>
      {snapshots.length === 0 && (
        <Panel title="No reports generated yet" sub="reports are produced by scheduled runs">
          <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>
            Configure a report schedule (Resilience → Compliance report, or the report scheduler) and run it.
            Each run produces a signed, deterministic PDF persisted as a snapshot — nothing is fabricated.
          </p>
        </Panel>
      )}
      {schedules.length > 0 && (
        <Panel title="Scheduled reports" sub={`${schedules.length} active schedule${schedules.length === 1 ? "" : "s"}`} className="mt">
          <ul className="dim" style={{ fontSize: 13, display: "flex", flexDirection: "column", gap: 6, paddingLeft: 18 }}>
            {schedules.map((s) => (
              <li key={s.id ?? s.schedule_id} className="mono">
                {s.framework ?? s.report_type ?? s.name} · {s.cron ?? s.schedule ?? `every ${s.interval_hours ?? "?"}h`}
                {s.active === false ? " · paused" : ""}
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </>
  );
}
