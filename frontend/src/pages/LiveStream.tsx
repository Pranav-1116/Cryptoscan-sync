/* Activity — one timeline of what happened in the estate and to the agents watching it.
 *
 * Read from /api/v1/operations/activity: estate changes the agents' observations caused,
 * correlated threat patterns, agent lifecycle (enrolled, activated, refused, went silent) and
 * remediation actions — newest first, attributed to agents and systems where the record names
 * them. A change can be acknowledged here. The platform event bus, attack detector and Live
 * CBOM sit below, collapsed. */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { apiEstateChangeAcknowledge, apiOpsActivity, type OpsActivity, type OpsEvent } from "../lib/api.js";
import { IconLive } from "../components/icons";
import PlatformEventStream from "../components/PlatformEventStream";
import {
  Disclosure, KpiTile, LiveBar, OPS_SEV_COLOR, OpsHeader, OpsLoadStates, SevBadge, card, chip, fmtAge, fmtWhen,
  agoFrom, inputStyle, kicker, parseWhen, useLive,
} from "../components/opsUi";

const KIND_LABEL: Record<string, string> = { change: "Estate changes", pattern: "Threat patterns", agent: "Agents", task: "Remediation" };
const KIND_COLOR: Record<string, string> = { change: "var(--violet)", pattern: "var(--red)", agent: "var(--cyan)", task: "var(--amber)" };

const readActivity = () => apiOpsActivity(24);

function Histogram({ counts, from }: { counts: number[]; from: string }) {
  const max = Math.max(1, ...counts);
  const start = parseWhen(from)?.getTime() ?? Date.now() - 86400000;
  return (
    <figure aria-label="Events per hour" style={{ margin: 0 }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: 3, height: 64 }}>
        {counts.map((c, i) => {
          const hour = new Date(start + i * 3600000);
          return (
            <div key={i} title={`${hour.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}: ${c} event(s)`}
              style={{ flex: 1, height: `${Math.max(c ? 8 : 2, (c / max) * 100)}%`, borderRadius: 3,
                       background: c ? "color-mix(in srgb, var(--cyan) 70%, transparent)" : "var(--line)" }} />
          );
        })}
      </div>
      <figcaption style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)", marginTop: 4 }}>
        <span>24h ago</span><span>12h</span><span>now</span>
      </figcaption>
    </figure>
  );
}

function EventRow({ e, now, fresh, onAck }: { e: OpsEvent; now: number; fresh: boolean; onAck: (id: string) => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const color = KIND_COLOR[e.kind] ?? "var(--faint)";
  return (
    <li aria-label={`Event ${e.title}`} style={{
      position: "relative", padding: "10px 12px 10px 18px", borderRadius: "var(--r)",
      background: fresh ? "color-mix(in srgb, var(--cyan) 8%, var(--panel-2))" : "var(--panel-2)",
      border: "1px solid var(--line)", transition: "background 1.5s ease",
    }}>
      <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 3, borderRadius: "3px 0 0 3px", background: color }} />
      <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 10, alignItems: "start" }}>
        <SevBadge severity={e.severity} />
        <div style={{ minWidth: 0 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
            <span style={{ fontWeight: 700, fontSize: 13 }}>{e.title}</span>
            <span style={{ fontSize: 10.5, color, fontFamily: "var(--mono)", textTransform: "uppercase" }}>{e.kind}</span>
            {e.acknowledged === false ? <span style={{ fontSize: 10.5, color: "var(--amber)", fontWeight: 700 }}>unreviewed</span> : null}
            {e.acknowledged === true ? <span style={{ fontSize: 10.5, color: "var(--green)" }}>reviewed</span> : null}
            {fresh ? <span style={{ fontSize: 10.5, color: "var(--cyan)", fontWeight: 700 }}>new</span> : null}
          </div>
          {e.detail ? <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 2, overflowWrap: "anywhere" }}>{e.detail}</div> : null}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
            {e.systems.map((s) => <span key={s} style={{ fontSize: 10.5, padding: "1px 7px", borderRadius: 99, border: "1px solid var(--line)", color: "var(--text)" }}>{s}</span>)}
            {e.agents.slice(0, 4).map((a) => <span key={a} style={{ fontSize: 10.5, padding: "1px 7px", borderRadius: 99, background: "var(--panel)", color: "var(--dim)", fontFamily: "var(--mono)" }}>{a}</span>)}
            {e.agents.length > 4 ? <span style={{ fontSize: 10.5, color: "var(--faint)" }}>+{e.agents.length - 4}</span> : null}
            {e.actor ? <span style={{ fontSize: 10.5, color: "var(--faint)" }}>by {e.actor}</span> : null}
          </div>
        </div>
        <div style={{ textAlign: "right", fontSize: 11, color: "var(--dim)", whiteSpace: "nowrap", display: "grid", gap: 4, justifyItems: "end" }}>
          <span title={fmtWhen(e.at)}>{fmtAge(agoFrom(e.at, now))} ago</span>
          {e.items.length ? (
            <button className="btn" aria-expanded={open} aria-label={`Details of ${e.title} at ${e.at}`} style={{ padding: "2px 8px", fontSize: 11 }} onClick={() => setOpen(!open)}>
              {open ? "Hide" : `${e.item_total} detail(s)`}
            </button>
          ) : null}
          {e.kind === "change" && e.acknowledged === false && e.ref ? (
            <button className="btn" disabled={busy} aria-label={`Acknowledge ${e.ref}`} style={{ padding: "2px 8px", fontSize: 11 }}
              onClick={async () => { setBusy(true); await onAck(e.ref as string); setBusy(false); }}>
              {busy ? "…" : "Acknowledge"}
            </button>
          ) : null}
        </div>
      </div>
      {open ? (
        <div style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
          {e.next_action ? <div style={{ fontSize: 12, marginBottom: 8 }}><span style={{ color: "var(--faint)" }}>Next: </span>{e.next_action}</div> : null}
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
            <tbody>
              {e.items.map((it, i) => (
                <tr key={i} style={{ borderTop: i ? "1px solid var(--line)" : undefined, verticalAlign: "top" }}>
                  <td style={{ padding: "4px 8px 4px 0", fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--violet)", whiteSpace: "nowrap" }}>{it.kind}</td>
                  <td style={{ padding: "4px 8px 4px 0", overflowWrap: "anywhere" }}>{it.subject}</td>
                  <td style={{ padding: "4px 0", color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 10.5, whiteSpace: "nowrap" }}>
                    {it.before !== null && it.before !== undefined ? `${String(it.before)} → ` : ""}{it.after !== null && it.after !== undefined ? String(it.after) : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {e.item_total > e.items.length ? <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>{e.item_total - e.items.length} more not shown</div> : null}
          {e.link ? <Link to={e.link} style={{ fontSize: 11.5, color: "var(--cyan)" }}>Open →</Link> : null}
        </div>
      ) : null}
    </li>
  );
}

function dayLabel(iso: string): string {
  const d = parseWhen(iso);
  if (!d) return "Unknown day";
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const day = new Date(d); day.setHours(0, 0, 0, 0);
  const diff = Math.round((today.getTime() - day.getTime()) / 86400000);
  return diff === 0 ? "Today" : diff === 1 ? "Yesterday" : d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
}

export default function LiveStream() {
  const live = useLive<OpsActivity>(readActivity, 10000);
  const { data, state, error, refresh, now } = live;
  const [kinds, setKinds] = useState<Set<string>>(new Set());
  const [severity, setSeverity] = useState<string | null>(null);
  const [agent, setAgent] = useState("");
  const [query, setQuery] = useState("");
  const [unreviewed, setUnreviewed] = useState(false);
  const [limit, setLimit] = useState(60);
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());

  // highlight events that arrived after the first read of this screen
  useEffect(() => {
    if (!data) return;
    const ids = new Set(data.events.map((e) => e.id));
    if (seen.current === null) { seen.current = ids; return; }
    const arrived = data.events.filter((e) => !seen.current!.has(e.id)).map((e) => e.id);
    seen.current = ids;
    if (arrived.length) setFresh(new Set(arrived));
  }, [data]);

  const agents = useMemo(() => Array.from(new Set((data?.events ?? []).flatMap((e) => e.agents))).sort(), [data]);
  const events = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.events ?? []).filter((e) =>
      (kinds.size === 0 || kinds.has(e.kind)) && (!severity || e.severity === severity) &&
      (!agent || e.agents.includes(agent)) && (!unreviewed || e.acknowledged === false) &&
      (!q || [e.title, e.detail, ...e.systems, ...e.agents].some((v) => String(v ?? "").toLowerCase().includes(q))));
  }, [data, kinds, severity, agent, query, unreviewed]);

  const ack = async (id: string) => { await apiEstateChangeAcknowledge(id, "reviewed in Activity"); await refresh(); };
  const toggleKind = (k: string) => setKinds((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });

  let lastDay = "";
  const t = data?.totals;

  return (
    <>
      <OpsHeader
        crumb="Operations / Activity"
        title="Activity"
        icon={<IconLive size={18} />}
        sub="Everything that happened in the estate and to the agents watching it: changes their observations caused, correlated patterns, agent lifecycle and remediation actions — newest first."
        right={<LiveBar live={live} />}
      />
      {state !== "ready" || !data ? (
        <OpsLoadStates state={state} error={error} refresh={refresh} what="The activity timeline" />
      ) : (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
            <KpiTile label="Events · 24h" ariaLabel="Events in 24 hours" value={t?.last_24h ?? 0} sub={`${t?.events ?? 0} in the feed`} />
            <KpiTile label="Unreviewed changes" ariaLabel="Unreviewed changes" value={t?.unacknowledged_changes ?? 0}
              color={t?.unacknowledged_changes ? "var(--amber)" : "var(--green)"} active={unreviewed} onClick={() => setUnreviewed(!unreviewed)}
              sub="estate changes nobody acknowledged" />
            <KpiTile label="Critical & high" ariaLabel="Critical and high events" value={(t?.by_severity.CRITICAL ?? 0) + (t?.by_severity.HIGH ?? 0)}
              color={(t?.by_severity.CRITICAL ?? 0) + (t?.by_severity.HIGH ?? 0) ? "var(--red)" : "var(--green)"}
              active={severity === "HIGH"} onClick={() => setSeverity(severity === "HIGH" ? null : "HIGH")} sub="patterns, refusals, silent agents" />
            <div style={{ ...card, flex: "2 1 320px", minWidth: 280 }}>
              <div style={kicker}>Events per hour · last 24h</div>
              <div style={{ marginTop: 8 }}><Histogram counts={data.hourly.counts} from={data.hourly.from} /></div>
            </div>
          </div>

          <section aria-label="Timeline" style={card}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
              {Object.keys(KIND_LABEL).map((k) => (
                <button key={k} aria-label={`Show ${KIND_LABEL[k]}`} aria-pressed={kinds.has(k)} style={chip(kinds.has(k), KIND_COLOR[k])} onClick={() => toggleKind(k)}>
                  {KIND_LABEL[k]} {t?.by_kind[k] ?? 0}
                </button>
              ))}
              <select aria-label="Severity" value={severity ?? ""} onChange={(e) => setSeverity(e.target.value || null)} style={inputStyle}>
                <option value="">Any severity</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <select aria-label="Agent" value={agent} onChange={(e) => setAgent(e.target.value)} style={inputStyle}>
                <option value="">Any agent</option>
                {agents.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
              <input aria-label="Search activity" placeholder="Search…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ ...inputStyle, flex: "1 1 180px" }} />
              <label style={{ fontSize: 12, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}>
                <input type="checkbox" checked={unreviewed} onChange={(e) => setUnreviewed(e.target.checked)} /> unreviewed only
              </label>
            </div>
            {events.length === 0 ? (
              <div style={{ padding: 14, fontSize: 12.5, color: "var(--dim)" }}>
                {data.events.length === 0 ? "Nothing has happened yet: no change, pattern or agent event is stored." : "No event matches these filters."}
              </div>
            ) : (
              <ol aria-label="Events" style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
                {events.slice(0, limit).map((e) => {
                  const day = dayLabel(e.at);
                  const header = day !== lastDay ? day : null;
                  lastDay = day;
                  return (
                    <React.Fragment key={e.id}>
                      {header ? <li aria-hidden style={{ ...kicker, padding: "6px 2px 0" }}>{header}</li> : null}
                      <EventRow e={e} now={now} fresh={fresh.has(e.id)} onAck={ack} />
                    </React.Fragment>
                  );
                })}
              </ol>
            )}
            {events.length > limit ? (
              <button className="btn" style={{ marginTop: 10 }} onClick={() => setLimit(limit + 60)}>Show {Math.min(60, events.length - limit)} more</button>
            ) : null}
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 12, fontSize: 11, color: "var(--faint)" }}>
              {Object.entries(OPS_SEV_COLOR).map(([k, c]) => <span key={k}><b style={{ color: c, fontFamily: "var(--mono)" }}>{k}</b></span>)}
              <span>· an unchanged agent report stores a heartbeat, not an event — the feed lists changes, not every report</span>
            </div>
          </section>
        </>
      )}
      <Disclosure title="Platform event bus & attack detection" sub="The in-process event bus, the 13 deterministic attack-detection rules and the signed, hash-chained Live CBOM.">
        <PlatformEventStream embedded />
      </Disclosure>
    </>
  );
}
