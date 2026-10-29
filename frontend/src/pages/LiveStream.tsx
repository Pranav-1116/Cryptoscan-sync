import React, { useState } from "react";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { GapBar, HBars, StackedBar, StateCell, TickStrip, VizEmpty, toneColor } from "../components/viz.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiAttacks, apiAttackSummary, apiCbomLive, apiCbomVerify,
  apiCbomSystemVersions, apiStreamStats,
  AttackDetection, CbomVersion, StreamStats,
} from "../lib/api.js";

/* Live stream & Live CBOM — the realtime surface of the event-stream round.
   Everything shown comes from the signed event bus: attack detections are the
   output of deterministic rules evaluated by the stream processor; the CBOM
   panel reads the JWS-signed, hash-chained version history for any system.
   Empty until real observations flow through stream ingest or the monitor
   daemon. No simulated data: an empty bus is drawn as an unmeasured bus, never
   as a row of zeros, and a lag of zero is only drawn when the payload says 0. */

const SEV_TONE: Record<string, string> = {
  CRITICAL: "red", HIGH: "amber", ALERT: "amber", MEDIUM: "amber", LOW: "green",
};
const SEV_ORDER = ["CRITICAL", "HIGH", "ALERT", "MEDIUM", "LOW"];
const sevColor = (s: string) => toneColor(SEV_TONE[s] ?? "slate");

function StreamStatsPanel() {
  const stats = usePollingApi<StreamStats>(() => apiStreamStats(), 5000);
  const topics = Object.entries(stats.data?.topics ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([topic, st]) => ({ topic, ...st }));
  const maxSeq = Math.max(0, ...topics.map((t) => t.last_seq ?? 0));
  const totalInMemory = topics.reduce((n, t) => n + (t.in_memory ?? 0), 0);
  const maxLag = topics.length ? Math.max(0, ...topics.map((t) => Math.max(0, ...Object.values(t.consumer_groups ?? {}).map((g) => g.lag)))) : null;
  const groups = topics.reduce((n, t) => n + Object.keys(t.consumer_groups ?? {}).length, 0);
  return (
    <Panel title="Event bus topics">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, marginBottom: 10 }}>
        <StateCell label="topics" value={stats.data ? topics.length : "—"} note={stats.data ? "in the bus registry" : "bus not read"} />
        <StateCell label="in memory" value={stats.data ? totalInMemory.toLocaleString() : "—"} note="events held, not a rate" />
        <StateCell label="consumer groups" value={stats.data ? groups : "—"} />
        <StateCell label="max lag" value={maxLag == null ? "—" : maxLag.toLocaleString()} tone={maxLag ? "amber" : ""} note={maxLag == null ? "no bus registry" : "largest group lag observed"} />
        <StateCell label="chain length" value={stats.data?.chain_len != null ? String(stats.data.chain_len) : "—"} note={stats.data?.chain_len != null ? "signed event chain" : "not reported"} />
      </div>
      {!topics.length ? (
        <VizEmpty title="No topics in the bus" note="Bus not initialized yet — observations appear after the first ingest or daemon pass. An absent bus is not an idle bus." />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
          {topics.map((t) => {
            const lag = Math.max(0, ...Object.values(t.consumer_groups ?? {}).map((g) => g.lag));
            return (
              <div key={t.topic} style={{ display: "grid", gridTemplateColumns: "minmax(110px, 1.2fr) minmax(60px, 2fr) auto", gap: 8, alignItems: "center" }}>
                <code style={{ fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={t.topic}>{t.topic}</code>
                <span style={{ display: "block", height: 8, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 2, overflow: "hidden" }} title={`last seq ${t.last_seq}`}>
                  <span style={{ display: "block", width: `${maxSeq > 0 ? (t.last_seq / maxSeq) * 100 : 0}%`, height: "100%", background: toneColor("") }} />
                </span>
                <span className="mono" style={{ fontSize: 10.5, color: "var(--dim)", fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>
                  seq {t.last_seq} · mem {t.in_memory} · grp {Object.keys(t.consumer_groups ?? {}).length} ·{" "}
                  <span style={{ color: lag > 0 ? sevColor("HIGH") : "var(--faint)" }}>lag {lag}</span>
                </span>
              </div>
            );
          })}
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>bar = last sequence relative to the busiest topic in this read</div>
        </div>
      )}
    </Panel>
  );
}

function AttacksPanel() {
  const attacks = usePollingApi<{ detections: AttackDetection[] }>(() => apiAttacks(50), 5000);
  const summary = usePollingApi<{ by_rule: Record<string, number>; by_severity: Record<string, number> }>(
    () => apiAttackSummary(), 5000);
  const detections = attacks.data?.detections ?? [];
  const sev = summary.data?.by_severity ?? {};
  const byRule = summary.data?.by_rule ?? {};
  const ticks = detections.slice().reverse().map((d) => ({
    ts: new Date(d.detected_at).toLocaleTimeString(),
    severity: (d.severity === "CRITICAL" ? "critical" : ["HIGH", "ALERT", "MEDIUM"].includes(d.severity) ? "warn" : "info") as "critical" | "warn" | "info",
  }));
  /* Only the severities the summary actually returned. Filling the missing ones
     with 0 would draw a composition the server never reported. */
  const severitySegments = [
    ...SEV_ORDER.filter((s) => sev[s] != null).map((s) => ({ key: s, label: s.toLowerCase(), value: Number(sev[s]), tone: SEV_TONE[s] ?? "slate" })),
    ...Object.keys(sev).filter((s) => !SEV_ORDER.includes(s)).map((s) => ({ key: s, label: s.toLowerCase(), value: Number(sev[s]), tone: "slate" })),
  ];
  const ruleRows = Object.entries(byRule).sort((a, b) => b[1] - a[1]).slice(0, 12)
    .map(([rule, n]) => ({ key: rule, label: rule, value: n }));
  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, margin: "12px 0" }}>
        <StateCell label="detections read" value={attacks.data ? detections.length : "—"} note={attacks.data ? "most recent page of the detection log" : "detection log not read"} />
        {SEV_ORDER.slice(0, 4).map((s) => (
          <StateCell
            key={s}
            label={s.toLowerCase()}
            // a severity the summary did not return is unmeasured, not zero
            value={summary.data ? (sev[s] == null ? "—" : Number(sev[s])) : "—"}
            tone={Number(sev[s] ?? 0) > 0 ? SEV_TONE[s] : ""}
            note="detections by server severity"
          />
        ))}
      </div>
      <div className="grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 12 }}>
        <Panel title="Severity composition">
          <StackedBar segments={severitySegments} note="Counts returned by the detector summary. A share of detections is not a share of exposure." />
        </Panel>
        <Panel title="Rules that fired">
          <HBars rows={ruleRows} emptyTitle="No rule has fired" emptyNote="The summary reports no fired rule for this window. Detection needs real observations first." />
        </Panel>
      </div>
      <Panel title="Real-time attack detections (13 deterministic rules)">
        <div style={{ marginBottom: 10 }}>
          <TickStrip ticks={ticks} label="observation ticks — newest first" emptyNote="No detection has been observed, so there are no ticks to draw." />
        </div>
        {!detections.length ? (
          <VizEmpty title="No detections observed" note="Baselines learn from clean traffic — downgrades, pin mismatches, revocations and rate anomalies appear the moment they are observed. Nothing here is assumed clean." />
        ) : (
          <div style={{ display: "flex", flexDirection: "column" }}>
            {detections.map((d, i) => (
              <div key={`${d.rule}-${i}`} style={{ display: "grid", gridTemplateColumns: "4px minmax(120px, 1fr) minmax(80px, 1fr) minmax(120px, 2fr) auto", gap: 10, alignItems: "center", padding: "7px 0", borderTop: i ? "1px solid var(--line)" : undefined }}>
                <span aria-hidden style={{ height: 22, background: sevColor(d.severity) }} />
                <span className="mono" style={{ fontSize: 10.5, letterSpacing: "0.05em", color: sevColor(d.severity), textTransform: "uppercase" }}>{d.severity}</span>
                <code style={{ fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={d.rule}>{d.rule}</code>
                <span style={{ fontSize: 11.5, color: "var(--dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={d.detail}>{d.endpoint || d.system || "—"}</span>
                <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)", whiteSpace: "nowrap" }}>{new Date(d.detected_at).toLocaleTimeString()}</span>
              </div>
            ))}
            <div style={{ display: "grid", gridTemplateColumns: "4px minmax(120px, 1fr) minmax(80px, 1fr) minmax(120px, 2fr) auto", gap: 10, marginTop: 6 }}>
              <span /><span className="mono" style={{ fontSize: 9.5, color: "var(--faint)", letterSpacing: "0.06em" }}>SEVERITY</span>
              <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)", letterSpacing: "0.06em" }}>RULE</span>
              <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)", letterSpacing: "0.06em" }}>ENDPOINT / SYSTEM</span>
              <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)", letterSpacing: "0.06em" }}>DETECTED</span>
            </div>
            <div style={{ marginTop: 10 }}>
              {detections.filter((d) => d.detail).slice(0, 1).map((d, i) => (
                <div key={i} style={{ fontSize: 11, color: "var(--dim)" }}>{d.detail}</div>
              ))}
            </div>
          </div>
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
    // `call()` reports absence through `data`/`error`, not through a flag: a
    // falsy check on `ok` here would silently refuse every real document.
    if (!res.data) { setErr(res.error ?? "not found"); setBusy(false); return; }
    setLive(res.data);
    const v = await apiCbomVerify(system.trim());
    // A verification that did not return is NOT a broken chain — it is unchecked.
    setVerdict(v.data ?? null);
    const vs = await apiCbomSystemVersions(system.trim());
    if (vs.data) setVersions(vs.data.versions ?? []);
    setBusy(false);
  };

  const fresh = live?.freshness as { stale: boolean; seconds_since_update: number } | undefined;
  const maxAssets = Math.max(0, ...versions.map((v) => v.asset_count ?? 0));
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
      {err && <p className="sub" style={{ color: "var(--red)" }}>{err}</p>}
      {live && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, margin: "12px 0" }}>
          <StateCell label="version" value={`#${live.version_no}`} note={new Date(String(live.generated_at)).toLocaleString()} />
          <StateCell label="assets" value={String(live.asset_count)} note="components in this signed document" />
          <StateCell
            label="freshness"
            value={fresh ? (fresh.stale ? "STALE" : `${Math.round(fresh.seconds_since_update)}s`) : "NOT REPORTED"}
            tone={fresh ? (fresh.stale ? "amber" : "green") : ""}
            note={fresh ? "record's own age, no extrapolation" : "payload carries no freshness block"}
          />
          <StateCell
            label="hash chain"
            value={verdict ? (verdict.chain_valid ? "VERIFIED" : `BROKEN @${verdict.broke_at}`) : "NOT CHECKED"}
            tone={verdict ? (verdict.chain_valid ? "green" : "red") : ""}
            note={verdict ? "checked against the stored chain" : "verification did not return"}
          />
        </div>
      )}
      {live && verdict && !verdict.chain_valid && (
        <div style={{ marginBottom: 10, border: `1px solid ${toneColor("red")}`, borderRadius: "var(--r)", background: "var(--panel-2)", backgroundImage: "repeating-linear-gradient(135deg, transparent 0 6px, color-mix(in srgb, var(--red) 10%, transparent) 6px 8px)", padding: "8px 10px" }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: toneColor("red") }}>chain does not verify</div>
          <div style={{ fontSize: 11.5, color: "var(--dim)", lineHeight: 1.5 }}>
            {`The hash chain does not verify for this system${verdict.broke_at != null ? ` — first break at version ${verdict.broke_at}` : ""}. Later versions are not provably linked to earlier ones.`}
          </div>
        </div>
      )}
      {live && verdict === null && (
        <div style={{ marginBottom: 10 }}>
          <GapBar label="chain integrity" reason="The verification read did not return, so no chain verdict exists. The document is shown as read, not as verified." />
        </div>
      )}
      {live && versions.length > 0 && (
        <div>
          <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 5 }}>
            version history — {versions.length} retained version(s)
          </div>
          <HBars unit="" rows={versions.slice().reverse().map((v) => ({
            key: `${v.version_no}`,
            label: `#${v.version_no} · ${String(v.version_hash).slice(0, 12)}…`,
            value: v.asset_count ?? 0,
            note: new Date(String(v.generated_at)).toLocaleString(),
          }))} emptyTitle="No retained versions" emptyNote="Versions exist once real observations for this system reach the stream." />
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)", marginTop: 5 }}>bar = asset count relative to the largest version in this history · JWS HS256 on every version</div>
        </div>
      )}
      {live && !versions.length && (
        <VizEmpty title="No retained version history" note="The current document exists but the system returned no earlier versions to draw." />
      )}
      {!live && !err && !busy && (
        <VizEmpty title="No system inspected" note="Enter a system id to read its current signed CBOM, the chain verdict and the retained version history. Nothing is drawn before a read." />
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
        right={<Badge tone=""><span className="dot" /> DETERMINISTIC RULES</Badge>}
      />
      <AttacksPanel />
      <div className="grid-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <StreamStatsPanel />
        <CbomPanel />
      </div>
    </>
  );
}
