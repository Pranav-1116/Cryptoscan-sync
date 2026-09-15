import React, { useState } from "react";
import { Badge, Kpi, PageHead, Panel, Table } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiAttacks, apiAttackSummary, apiCbomLive, apiCbomVerify,
  apiCbomSystemVersions, apiStreamStats,
  AttackDetection, CbomVersion, StreamStats,
} from "../lib/api.js";

/* Live stream & Live CBOM — the realtime surface of the event-stream round.
   Everything shown comes from the signed event bus: attack detections are the
   output of 13 deterministic rules evaluated by the stream processor; the
   CBOM panel reads the JWS-signed, hash-chained version history for any
   system. Empty until real observations flow through /stream/ingest or the
   monitor daemon. No simulated data. */

const SEV_TONE: Record<string, string> = {
  CRITICAL: "bad", HIGH: "warn", ALERT: "warn", MEDIUM: "warn", LOW: "ok",
};

function StreamStatsPanel() {
  const stats = usePollingApi<StreamStats>(() => apiStreamStats(), 5000);
  const rows = Object.entries(stats.data?.topics ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([topic, st]) => [
      <code key={topic}>{topic}</code>,
      st.last_seq,
      st.in_memory,
      Object.keys(st.consumer_groups ?? {}).length,
      Math.max(0, ...Object.values(st.consumer_groups ?? {}).map((g) => g.lag)),
    ]);
  return (
    <Panel title="Event bus topics">
      {rows.length === 0 ? (
        <p className="sub">Bus not initialized yet — observations appear after the first ingest or daemon pass.</p>
      ) : (
        <Table
          head={["Topic", "Last seq", "In memory", "Consumer groups", "Max lag"]}
          rows={rows}
        />
      )}
    </Panel>
  );
}

function AttacksPanel() {
  const attacks = usePollingApi<{ detections: AttackDetection[] }>(() => apiAttacks(50), 5000);
  const summary = usePollingApi<{ by_rule: Record<string, number>; by_severity: Record<string, number> }>(
    () => apiAttackSummary(), 5000);
  const detections = attacks.data?.detections ?? [];
  const rows = detections.map((d, i) => [
    <Badge key={i} tone={SEV_TONE[d.severity] ?? ""}>{d.severity}</Badge>,
    <code key={`r${i}`}>{d.rule}</code>,
    d.endpoint || d.system || "—",
    d.detail,
    new Date(d.detected_at).toLocaleTimeString(),
  ]);
  const sev = summary.data?.by_severity ?? {};
  return (
    <>
      <div className="row" style={{ gap: 12, margin: "12px 0" }}>
        <Kpi k="Detections (recent)" v={detections.length} />
        <Kpi k="Critical" v={sev.CRITICAL ?? 0} tone="var(--bad)" />
        <Kpi k="High/Alert" v={(sev.HIGH ?? 0) + (sev.ALERT ?? 0)} tone="var(--warn)" />
        <Kpi k="Medium" v={sev.MEDIUM ?? 0} tone="var(--warn)" />
      </div>
      <Panel title="Real-time attack detections (13 deterministic rules)">
        {rows.length === 0 ? (
          <p className="sub">No detections yet. Baselines learn from clean traffic — downgrades, pin mismatches, revocations and rate anomalies appear here the moment they are observed.</p>
        ) : (
          <Table
            head={["Severity", "Rule", "Endpoint/System", "Detail", "Detected"]}
            rows={rows}
          />
        )}
      </Panel>
    </>
  );
}

function CbomPanel() {
  const [system, setSystem] = useState("");
  const [live, setLive] = useState<CbomVersion | null>(null);
  const [verdict, setVerdict] = useState<{ chain_valid: boolean; broke_at?: number | null } | null>(null);
  const [versions, setVersions] = useState<CbomVersion[]>([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async () => {
    if (!system.trim()) return;
    setBusy(true); setErr(""); setLive(null); setVerdict(null); setVersions([]);
    const res = await apiCbomLive(system.trim());
    if (!res.ok || !res.data) { setErr(res.error ?? "not found"); setBusy(false); return; }
    setLive(res.data);
    const v = await apiCbomVerify(system.trim());
    setVerdict((v.ok && v.data) ? v.data : { chain_valid: false });
    const vs = await apiCbomSystemVersions(system.trim());
    if (vs.ok && vs.data) setVersions(vs.data.versions ?? []);
    setBusy(false);
  };

  const fresh = live?.freshness as { stale: boolean; seconds_since_update: number } | undefined;
  return (
    <Panel title="Live CBOM (signed, hash-chained)">
      <div className="row" style={{ gap: 8 }}>
        <input
          value={system}
          onChange={(e) => setSystem(e.target.value)}
          placeholder="system id (e.g. core-1)"
          onKeyDown={(e) => { if (e.key === "Enter") void load(); }}
        />
        <button onClick={() => void load()} disabled={busy}>{busy ? "…" : "Inspect"}</button>
      </div>
      {err && <p className="sub" style={{ color: "var(--bad)" }}>{err}</p>}
      {live && (
        <div className="row" style={{ gap: 12, margin: "12px 0", flexWrap: "wrap" }}>
          <Kpi k="Version" v={String(live.version_no)} />
          <Kpi k="Assets" v={String(live.asset_count)} />
          <Kpi k="Freshness" v={fresh ? (fresh.stale ? "STALE" : `${Math.round(fresh.seconds_since_update)}s`) : "?"}
               tone={fresh?.stale ? "var(--warn)" : "var(--ok)"} />
          <Kpi k="Chain" v={verdict ? (verdict.chain_valid ? "VERIFIED" : `BROKEN @${verdict.broke_at}`) : "?"}
               tone={verdict?.chain_valid ? "var(--ok)" : "var(--bad)"} />
        </div>
      )}
      {live && (
        <Table
          head={["Version", "Generated", "Assets", "Version hash", "JWS"]}
          rows={versions.slice().reverse().map((v, i) => [
            `#${v.version_no}`,
            new Date(String(v.generated_at)).toLocaleString(),
            String(v.asset_count),
            <code key={`h${i}`}>{String(v.version_hash).slice(0, 16)}…</code>,
            <Badge key={`j${i}`} tone="ok">HS256</Badge>,
          ])}
        />
      )}
      {!live && !err && (
        <p className="sub">Enter a system id to inspect its current signed CBOM, chain verdict and version history. Versions exist once real observations for that system reach the stream.</p>
      )}
    </Panel>
  );
}

export default function LiveStream() {
  return (
    <>
      <PageHead
        crumb="Platform / Stream"
        title="Live stream & attack detection"
        sub="Signed event bus → deterministic pipeline → real-time detections and a hash-chained Live CBOM."
      />
      <AttacksPanel />
      <div className="grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <StreamStatsPanel />
        <CbomPanel />
      </div>
    </>
  );
}
