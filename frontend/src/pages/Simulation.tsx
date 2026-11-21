/* Migration simulation over the Digital Twin and its six BOMs.
 *
 * One page, three answers, all read from the agents' estate graph (for the Meridian
 * sandbox: the synthetic bank's servers, mapped to its business systems by the CMDB):
 *
 *   1. What is in the twin — every business system, and every component of the CBOM,
 *      NBOM, SBOM, HBOM, VBOM and the technology BOM with the systems it belongs to.
 *   2. What breaks if we migrate — choose FROM and TO; every component gets AFFECTED,
 *      AT RISK, UNKNOWN, READY or NOT AFFECTED with its cause and the action, and the
 *      migration problems are filed under the BOM layer they come from.
 *   3. What the connections do — for each system-to-system connection, which side changes,
 *      what happens to the other side, which components both share, and how far the change
 *      ripples through the dependency chain.
 *
 * Read-only. An unknown capability is shown as UNKNOWN, never as a pass. The evidence-level
 * scenario & cascade workspace is still available, folded away under "Advanced".
 */
import React, { Suspense, lazy, useCallback, useEffect, useMemo, useState } from "react";
import { Panel, Badge } from "../components/ui";
import { IconTarget, IconSecurity } from "../components/icons";
import EstateDiscoveryCta from "../components/EstateDiscoveryCta";
import { apiTwinBoms, apiTwinBomImpact } from "../lib/api.js";
import type {
  TwinBomImpact, TwinBom, TwinBomKind, TwinBomStatus, TwinBomIssue, TwinBomConnection, TwinBomSystem,
  TwinConnectionStatus, MigrationStrategy,
} from "../lib/api.js";

const WhatIfWorkspace = lazy(() => import("../components/WhatIfWorkspace"));

const BOM_NAME: Record<TwinBomKind, string> = {
  CBOM: "CBOM", NBOM: "NBOM", SBOM: "SBOM", HBOM: "HBOM", VBOM: "VBOM", TECHBOM: "Tech BOM",
};
const STATUS_LABEL: Record<TwinBomStatus, string> = {
  AFFECTED: "Affected", AT_RISK: "At risk", UNKNOWN: "Unknown", READY: "Ready", NOT_AFFECTED: "Not affected",
};
const STATUS_TONE: Record<TwinBomStatus, string> = {
  AFFECTED: "red", AT_RISK: "amber", UNKNOWN: "slate", READY: "green", NOT_AFFECTED: "",
};
const STATUS_COLOR: Record<TwinBomStatus, string> = {
  AFFECTED: "var(--red)", AT_RISK: "var(--amber)", UNKNOWN: "var(--faint)", READY: "var(--green)",
  NOT_AFFECTED: "var(--line)",
};
const STATUSES: TwinBomStatus[] = ["AFFECTED", "AT_RISK", "UNKNOWN", "READY", "NOT_AFFECTED"];
const SEVERITY_TONE: Record<string, string> = { BLOCKER: "red", HIGH: "orange", MEDIUM: "amber", LOW: "slate", INFO: "slate" };
const STRATEGY_TONE: Record<MigrationStrategy, string> = {
  BLOCKED: "red", PARALLEL: "amber", DIRECT: "green", NOT_DETERMINED: "slate",
};
const STRATEGY_LABEL: Record<MigrationStrategy, string> = {
  BLOCKED: "Blocked", PARALLEL: "Parallel run", DIRECT: "Direct", NOT_DETERMINED: "Not determined",
};
const CONNECTION_LABEL: Record<TwinConnectionStatus, string> = {
  BOTH_CHANGE: "Both change", CALLER_CHANGES: "Caller changes", PROVIDER_CHANGES: "Provider changes",
  SHARED_COMPONENT: "Shared component changes", NOT_AFFECTED: "Unaffected",
};
const CONNECTION_COLOR: Record<TwinConnectionStatus, string> = {
  BOTH_CHANGE: "var(--amber)", CALLER_CHANGES: "var(--red)", PROVIDER_CHANGES: "var(--red)",
  SHARED_COMPONENT: "var(--amber)", NOT_AFFECTED: "var(--line)",
};
/* targets the migration engine has a capability profile for — offered, never forced */
const TARGETS = [
  "ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "X25519MLKEM768",
  "AES-256-GCM", "ChaCha20-Poly1305", "SHA-384", "RSA-3072", "ECDSA-P384",
];
const PAGE_ROWS = 60;

const inputStyle: React.CSSProperties = {
  padding: "8px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)",
  color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5, minWidth: 180,
};
const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--faint)" };
const cardStyle: React.CSSProperties = {
  padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)",
};
const kicker: React.CSSProperties = { fontSize: 9.5, letterSpacing: ".08em", color: "var(--faint)", fontFamily: "var(--mono)" };
const chip = (active: boolean): React.CSSProperties => ({
  padding: "4px 10px", fontSize: 11.5, borderRadius: 999, cursor: "pointer",
  border: `1px solid ${active ? "var(--violet)" : "var(--line)"}`,
  background: active ? "color-mix(in srgb, var(--violet) 14%, transparent)" : "transparent",
  color: active ? "var(--text)" : "var(--dim)", fontWeight: active ? 700 : 500,
});
const th: React.CSSProperties = { textAlign: "left", padding: "7px 8px", fontSize: 10.5, color: "var(--faint)", fontWeight: 700, borderBottom: "1px solid var(--line)", whiteSpace: "nowrap" };
const td: React.CSSProperties = { padding: "8px", fontSize: 12, borderBottom: "1px solid var(--line)", verticalAlign: "top" };

function criticalityTone(value?: string | null): string {
  const v = String(value || "").toLowerCase();
  if (v === "critical" || v === "tier-0") return "red";
  if (v === "high" || v === "tier-1") return "orange";
  if (v === "medium" || v === "tier-2") return "amber";
  return "slate";
}

function StatusBadge({ status }: { status: TwinBomStatus | null }) {
  if (!status) return null;
  return <Badge tone={STATUS_TONE[status] || "slate"}>{STATUS_LABEL[status]}</Badge>;
}

/* ------------------------------------------------------------------------------------- */

export default function Simulation() {
  const [inventory, setInventory] = useState<TwinBomImpact | null>(null);
  const [impact, setImpact] = useState<TwinBomImpact | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "none" | "error">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [from, setFrom] = useState("RSA");
  const [to, setTo] = useState("ML-KEM-768");
  const [scope, setScope] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [activeBom, setActiveBom] = useState<TwinBomKind>("CBOM");
  const [systemFilter, setSystemFilter] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);

  const load = useCallback(async () => {
    setLoadState("loading");
    const response = await apiTwinBoms();
    if (response.data && Array.isArray(response.data.boms)) {
      setInventory(response.data);
      setLoadState("ready");
      const held = response.data.context?.algorithms ?? [];
      if (held.length && !held.some((a) => a.algorithm.toUpperCase() === "RSA")) setFrom(held[0].algorithm);
    } else if (String(response.error || "").includes("404")) {
      setLoadState("none");
    } else {
      setLoadError(response.detail || response.error || "the twin could not be read");
      setLoadState("error");
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const run = async () => {
    if (!from.trim() || !to.trim()) return;
    setBusy(true);
    setRunError(null);
    const response = await apiTwinBomImpact({ from_algo: from.trim(), to_algo: to.trim(), systems: scope });
    setBusy(false);
    if (response.data && Array.isArray(response.data.boms)) {
      setImpact(response.data);
      const firstHit = response.data.boms.find((b) => (b.status_counts?.AFFECTED ?? 0) > 0);
      if (firstHit) setActiveBom(firstHit.bom);
    } else {
      setRunError(response.detail || response.error || "the simulation could not be run");
    }
  };

  const view = impact ?? inventory;
  const algorithms = inventory?.context?.algorithms ?? [];
  const systems = inventory?.systems ?? [];

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{
          display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999,
          background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))",
          fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em",
        }}>
          <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} />
          DIGITAL TWIN · TECH BOM · MIGRATION SIMULATION
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}>
            <IconTarget size={18} />
          </span>
          Migration simulation
        </h1>
        <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 820 }}>
          Everything the Digital Twin holds — CBOM, NBOM, SBOM, HBOM, VBOM and the technology BOM — and,
          for one algorithm change, what breaks in each layer, why, and what it does to the systems
          connected to each other.
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, fontSize: 11.5, color: "var(--dim)" }}>
          <IconSecurity size={13} />
          <span><b style={{ color: "var(--violet)" }}>Simulation only</b> — read from the live estate graph; nothing is changed.</span>
        </div>
      </div>

      {loadState === "loading" && <Panel title="Reading the Digital Twin"><div style={{ fontSize: 12, color: "var(--dim)" }}>Loading the six BOMs…</div></Panel>}
      {loadState === "none" && (
        <Panel title="No twin to simulate against" sub="the simulation reads the estate's own evidence">
          <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 10 }}>
            Nothing has been discovered yet. Run a discovery (or let the sandbox agents report) and the BOMs appear here.
          </div>
          <EstateDiscoveryCta onDiscovered={load} compact />
        </Panel>
      )}
      {loadState === "error" && (
        <Panel title="The twin could not be read">
          <div style={{ fontSize: 12.5, color: "var(--dim)" }}>{loadError} — that is not "the estate is empty".</div>
          <button className="btn" style={{ marginTop: 10 }} onClick={() => void load()}>Retry</button>
        </Panel>
      )}

      {view && (
        <>
          <EstateStrip view={view} active={activeBom} onPick={setActiveBom} />

          <Panel title="Simulate a migration" sub="choose the algorithm the estate holds today and the one it should move to">
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
              <label style={labelStyle}>
                Migrate from
                <input aria-label="Migrate from" list="twin-held-algorithms" value={from} onChange={(e) => setFrom(e.target.value)} style={inputStyle} />
                <datalist id="twin-held-algorithms">
                  {algorithms.map((a) => <option key={a.algorithm} value={a.algorithm}>{`${a.evidence} record(s) · ${a.systems.join(", ")}`}</option>)}
                </datalist>
              </label>
              <span style={{ paddingBottom: 9, color: "var(--faint)" }}>→</span>
              <label style={labelStyle}>
                Migrate to
                <input aria-label="Migrate to" list="twin-target-algorithms" value={to} onChange={(e) => setTo(e.target.value)} style={inputStyle} />
                <datalist id="twin-target-algorithms">
                  {TARGETS.map((t) => <option key={t} value={t} />)}
                </datalist>
              </label>
              <button className="btn primary" disabled={busy || !from.trim() || !to.trim()} onClick={() => void run()}>
                {busy ? "Simulating…" : "Run simulation"}
              </button>
              {impact && (
                <button className="btn" onClick={() => { setImpact(null); setRunError(null); }}>Back to inventory</button>
              )}
            </div>
            {algorithms.length > 0 && (
              <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <span style={kicker}>HELD IN THE ESTATE</span>
                {algorithms.slice(0, 10).map((a) => (
                  <button key={a.algorithm} type="button" style={chip(from === a.algorithm)} onClick={() => setFrom(a.algorithm)}
                    aria-label={`From ${a.algorithm}`}>
                    {a.algorithm} <span style={{ color: "var(--faint)" }}>· {a.evidence}</span>
                  </button>
                ))}
              </div>
            )}
            {systems.length > 0 && (
              <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <span style={kicker}>LIMIT TO SYSTEMS</span>
                <button type="button" style={chip(scope.length === 0)} onClick={() => setScope([])}>All systems that use it</button>
                {systems.map((s) => (
                  <button key={s.id} type="button" aria-pressed={scope.includes(s.name)} style={chip(scope.includes(s.name))}
                    onClick={() => setScope((cur) => cur.includes(s.name) ? cur.filter((x) => x !== s.name) : [...cur, s.name])}>
                    {s.name}
                  </button>
                ))}
              </div>
            )}
            {runError && <div role="alert" style={{ marginTop: 10, fontSize: 12, color: "var(--red)" }}>{runError}</div>}
          </Panel>

          {impact && <ImpactSummary view={impact} />}

          <SystemsSection systems={view.systems} simulating={!!impact} selected={systemFilter}
            onSelect={(name) => setSystemFilter((cur) => cur === name ? null : name)} />

          <BomSection view={view} active={activeBom} onPick={setActiveBom} systemFilter={systemFilter}
            onClearSystem={() => setSystemFilter(null)} />

          <ConnectionsSection view={view} simulating={!!impact} />

          {view.unknowns.length > 0 && (
            <details style={{ ...cardStyle, marginTop: 14 }}>
              <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 700 }}>
                What this simulation cannot see ({view.unknowns.length})
              </summary>
              <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--dim)", lineHeight: 1.6 }}>
                {view.unknowns.map((u) => <li key={u}>{u}</li>)}
              </ul>
            </details>
          )}
        </>
      )}

      <details style={{ ...cardStyle, marginTop: 14 }} onToggle={(e) => setAdvanced((e.target as HTMLDetailsElement).open)}>
        <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 700 }}>
          Advanced — evidence scenarios and failure cascades
        </summary>
        {advanced && (
          <div style={{ marginTop: 12 }}>
            <Suspense fallback={<div style={{ fontSize: 12, color: "var(--dim)" }}>Loading…</div>}>
              <WhatIfWorkspace embedded />
            </Suspense>
          </div>
        )}
      </details>
    </div>
  );
}

/* ------------------------------------------------------------------------------------- */

function EstateStrip({ view, active, onPick }: { view: TwinBomImpact; active: TwinBomKind; onPick: (b: TwinBomKind) => void }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, marginBottom: 14 }}>
      <div style={cardStyle}>
        <div style={kicker}>ESTATE</div>
        <div style={{ fontSize: 14, fontWeight: 800, marginTop: 4 }}>{view.estate || "estate"}</div>
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 2 }}>
          {view.totals.systems} systems · {view.totals.connections} connections
        </div>
      </div>
      {view.boms.map((b) => {
        const affected = b.status_counts?.AFFECTED;
        return (
          <button key={b.bom} type="button" onClick={() => onPick(b.bom)} aria-label={`Open ${BOM_NAME[b.bom]}`}
            style={{ ...cardStyle, textAlign: "left", cursor: "pointer", borderColor: active === b.bom ? "var(--violet)" : "var(--line)" }}>
            <div style={kicker}>{BOM_NAME[b.bom].toUpperCase()} · {b.label.toUpperCase()}</div>
            <div style={{ fontSize: 20, fontWeight: 800, marginTop: 2 }}>{b.total}</div>
            <div style={{ fontSize: 11, color: affected ? "var(--red)" : "var(--faint)" }}>
              {affected != null ? `${affected} affected` : `${b.relationships} relationships`}
            </div>
          </button>
        );
      })}
    </div>
  );
}

function ImpactSummary({ view }: { view: TwinBomImpact }) {
  const strategy = view.strategy?.recommended ?? "NOT_DETERMINED";
  const counts = view.problem_counts || {};
  return (
    <div aria-label="Migration result" style={{ ...cardStyle, margin: "14px 0", borderColor: "var(--violet)" }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <span style={kicker}>{view.change?.from_algo} → {view.change?.to_algo}</span>
        <Badge tone={STRATEGY_TONE[strategy]}>{STRATEGY_LABEL[strategy]}</Badge>
        <span style={{ fontSize: 12, color: "var(--dim)" }}>
          {view.totals.systems_in_change ?? 0} of {view.totals.systems} systems change
        </span>
        {(["BLOCKER", "HIGH", "MEDIUM"] as const).map((sev) => counts[sev] ? (
          <Badge key={sev} tone={SEVERITY_TONE[sev]}>{`${counts[sev]} ${sev.toLowerCase()}`}</Badge>
        ) : null)}
      </div>
      {view.headline && <div style={{ fontSize: 13, marginTop: 8, lineHeight: 1.5 }}>{view.headline}</div>}
      {view.strategy?.meaning && <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 4 }}>{view.strategy.meaning}</div>}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
        {view.boms.map((b) => (
          <span key={b.bom} style={{ fontSize: 11.5, padding: "3px 8px", border: "1px solid var(--line)", borderRadius: 999, color: "var(--dim)" }}>
            {BOM_NAME[b.bom]}: <b style={{ color: (b.status_counts?.AFFECTED ?? 0) > 0 ? "var(--red)" : "var(--text)" }}>{b.status_counts?.AFFECTED ?? 0}</b> affected
            {b.issues.length > 0 ? ` · ${b.issues.length} issue${b.issues.length === 1 ? "" : "s"}` : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------------------------- */

function SystemsSection({ systems, simulating, selected, onSelect }: {
  systems: TwinBomSystem[]; simulating: boolean; selected: string | null; onSelect: (name: string) => void;
}) {
  return (
    <Panel title="Digital Twin systems" sub="each business system with what it is built from in every BOM — select one to filter the BOMs below">
      {systems.length === 0 ? (
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No business system is mapped in this estate yet, so components cannot be grouped.</div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 10 }}>
          {systems.map((s) => (
            <button key={s.id} type="button" aria-label={`System ${s.name}`} aria-pressed={selected === s.name}
              onClick={() => onSelect(s.name)}
              style={{
                ...cardStyle, textAlign: "left", cursor: "pointer",
                borderColor: selected === s.name ? "var(--violet)" : simulating && s.in_change ? "color-mix(in srgb, var(--red) 55%, var(--line))" : "var(--line)",
              }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 6, alignItems: "center" }}>
                <b style={{ fontSize: 13.5 }}>{s.name}</b>
                <span style={{ display: "flex", gap: 4 }}>
                  {s.criticality && <Badge tone={criticalityTone(s.criticality)}>{s.criticality}</Badge>}
                  {simulating && (s.in_change
                    ? <Badge tone={STRATEGY_TONE[s.strategy ?? "NOT_DETERMINED"]}>{STRATEGY_LABEL[s.strategy ?? "NOT_DETERMINED"]}</Badge>
                    : <Badge tone="slate">No change</Badge>)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 3 }}>
                {[s.owner, s.hosts.length ? `${s.hosts.length} host${s.hosts.length === 1 ? "" : "s"}: ${s.hosts.slice(0, 3).join(", ")}` : null].filter(Boolean).join(" · ") || "no owner or host recorded"}
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 4, marginTop: 8 }}>
                {(Object.keys(BOM_NAME) as TwinBomKind[]).map((bom) => {
                  const c = s.bom_counts[bom] ?? { components: 0, affected: 0 };
                  return (
                    <div key={bom} style={{ textAlign: "center" }} title={`${BOM_NAME[bom]}: ${c.components} component(s)${simulating ? `, ${c.affected} affected` : ""}`}>
                      <div style={{ fontSize: 9, color: "var(--faint)" }}>{BOM_NAME[bom].replace(" BOM", "")}</div>
                      <div style={{ fontSize: 13, fontWeight: 700 }}>{c.components}</div>
                      {simulating && <div style={{ fontSize: 10, color: c.affected ? "var(--red)" : "var(--faint)" }}>{c.affected}</div>}
                    </div>
                  );
                })}
              </div>
              {(s.calls.length > 0 || s.called_by.length > 0) && (
                <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 8, lineHeight: 1.5 }}>
                  {s.calls.length > 0 && <div>calls → {s.calls.join(", ")}</div>}
                  {s.called_by.length > 0 && <div>called by ← {s.called_by.join(", ")}</div>}
                </div>
              )}
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------------------------- */

function BomSection({ view, active, onPick, systemFilter, onClearSystem }: {
  view: TwinBomImpact; active: TwinBomKind; onPick: (b: TwinBomKind) => void;
  systemFilter: string | null; onClearSystem: () => void;
}) {
  const bom = view.boms.find((b) => b.bom === active) ?? view.boms[0];
  return (
    <Panel title="Bills of materials" sub="every component of the twin, by layer — with the migration's effect on each when a change is simulated">
      <div role="tablist" aria-label="Bills of materials" style={{ display: "flex", gap: 4, flexWrap: "wrap", borderBottom: "1px solid var(--line)", marginBottom: 12 }}>
        {view.boms.map((b) => {
          const selected = b.bom === bom?.bom;
          const affected = b.status_counts?.AFFECTED ?? 0;
          return (
            <button key={b.bom} role="tab" aria-selected={selected} type="button" onClick={() => onPick(b.bom)}
              style={{
                padding: "8px 12px", border: "none", cursor: "pointer", background: "transparent",
                borderBottom: `2px solid ${selected ? "var(--violet)" : "transparent"}`,
                color: selected ? "var(--text)" : "var(--dim)", fontWeight: selected ? 800 : 600, fontSize: 12.5,
              }}>
              {BOM_NAME[b.bom]} <span style={{ color: "var(--faint)", fontWeight: 500 }}>{b.label}</span>{" "}
              <span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{b.total}</span>
              {affected > 0 && <span style={{ marginLeft: 6, color: "var(--red)", fontFamily: "var(--mono)", fontSize: 11 }}>{affected}!</span>}
            </button>
          );
        })}
      </div>
      {bom && <BomPanel key={bom.bom} bom={bom} simulating={!!view.change} systemFilter={systemFilter} onClearSystem={onClearSystem} />}
    </Panel>
  );
}

function BomPanel({ bom, simulating, systemFilter, onClearSystem }: {
  bom: TwinBom; simulating: boolean; systemFilter: string | null; onClearSystem: () => void;
}) {
  const [status, setStatus] = useState<TwinBomStatus | "ALL">("ALL");
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(PAGE_ROWS);
  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return bom.components.filter((r) =>
      (status === "ALL" || r.status === status)
      && (!systemFilter || r.systems.includes(systemFilter))
      && (!q || `${r.name} ${r.type} ${r.detail} ${r.systems.join(" ")}`.toLowerCase().includes(q)));
  }, [bom.components, status, search, systemFilter]);
  const total = bom.status_counts ? STATUSES.reduce((n, s) => n + (bom.status_counts?.[s] ?? 0), 0) : 0;

  return (
    <div role="tabpanel" aria-label={`${BOM_NAME[bom.bom]} — ${bom.label}`}>
      <div style={{ fontSize: 12.5, marginBottom: 2 }}><b>{bom.question}</b></div>
      {bom.boundary && <div style={{ fontSize: 11.5, color: "var(--faint)", marginBottom: 10 }}>Boundary: {bom.boundary}</div>}

      {simulating && bom.status_counts && total > 0 && (
        <div aria-label={`${BOM_NAME[bom.bom]} status`} style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", height: 8, borderRadius: 99, overflow: "hidden", background: "var(--panel-2)" }}>
            {STATUSES.map((s) => (bom.status_counts?.[s] ?? 0) > 0 && (
              <div key={s} title={`${STATUS_LABEL[s]}: ${bom.status_counts?.[s]}`}
                style={{ width: `${((bom.status_counts?.[s] ?? 0) / total) * 100}%`, background: STATUS_COLOR[s] }} />
            ))}
          </div>
        </div>
      )}

      {simulating && <IssueList bom={bom} />}

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", margin: "12px 0 8px" }}>
        <input aria-label={`Search ${BOM_NAME[bom.bom]}`} placeholder="Search components, types, systems…" value={search}
          onChange={(e) => { setSearch(e.target.value); setLimit(PAGE_ROWS); }} style={{ ...inputStyle, minWidth: 240, fontFamily: "inherit" }} />
        {simulating && bom.status_counts && (
          <>
            <button type="button" style={chip(status === "ALL")} onClick={() => setStatus("ALL")}>All · {bom.total}</button>
            {STATUSES.map((s) => (bom.status_counts?.[s] ?? 0) > 0 && (
              <button key={s} type="button" style={chip(status === s)} onClick={() => setStatus(s)} aria-label={`Show ${STATUS_LABEL[s]}`}>
                {STATUS_LABEL[s]} · {bom.status_counts?.[s]}
              </button>
            ))}
          </>
        )}
        {systemFilter && (
          <button type="button" style={chip(true)} onClick={onClearSystem} aria-label="Clear system filter">
            System: {systemFilter} ✕
          </button>
        )}
      </div>

      {bom.total === 0 ? (
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>The estate graph holds no {BOM_NAME[bom.bom]} component yet — nothing was collected for this layer.</div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table aria-label={`${BOM_NAME[bom.bom]} components`} style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {simulating && <th style={th}>Status</th>}
                <th style={th}>Component</th>
                <th style={th}>Type</th>
                <th style={th}>Details</th>
                <th style={th}>Systems</th>
                {simulating && <th style={th}>Why · what to do</th>}
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, limit).map((r) => (
                <tr key={`${r.kind}:${r.ref}`}>
                  {simulating && <td style={td}><StatusBadge status={r.status} /></td>}
                  <td style={{ ...td, fontWeight: 600 }}>
                    {r.name}
                    {r.kind === "crypto" && <span style={{ marginLeft: 6, fontSize: 10, color: "var(--violet)", fontFamily: "var(--mono)" }}>crypto</span>}
                  </td>
                  <td style={{ ...td, fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{r.type}</td>
                  <td style={{ ...td, fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)", maxWidth: 320 }}>{r.detail || "—"}</td>
                  <td style={{ ...td, fontSize: 11.5, color: "var(--dim)", maxWidth: 200 }}>{r.systems.length ? r.systems.join(", ") : <i>no system</i>}</td>
                  {simulating && (
                    <td style={{ ...td, maxWidth: 380, fontSize: 11.5, lineHeight: 1.45 }}>
                      {r.impact}
                      {r.action && <div style={{ color: "var(--violet)", marginTop: 3 }}>→ {r.action}</div>}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div style={{ fontSize: 12, color: "var(--dim)", padding: 8 }}>No component matches these filters.</div>}
          {rows.length > limit && (
            <button className="btn" style={{ marginTop: 8 }} onClick={() => setLimit((n) => n + 200)}>
              Show more ({rows.length - limit} not shown)
            </button>
          )}
          {bom.truncated && <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 6 }}>The server lists the first components only; the counts above cover all {bom.total}.</div>}
        </div>
      )}

      {bom.bom === "VBOM" && <VendorDeclarations bom={bom} />}
    </div>
  );
}

function IssueList({ bom }: { bom: TwinBom }) {
  if (bom.issues.length === 0) {
    return <div style={{ fontSize: 12, color: "var(--dim)", ...cardStyle }}>No migration issue is filed under the {BOM_NAME[bom.bom]} for this change.</div>;
  }
  return (
    <div aria-label={`${BOM_NAME[bom.bom]} issues`} style={{ display: "grid", gap: 8 }}>
      <div style={kicker}>ISSUES AND CAUSES IN THE {BOM_NAME[bom.bom].toUpperCase()} · {bom.issues.length}</div>
      {bom.issues.map((issue, i) => <IssueCard key={`${issue.code}-${i}`} issue={issue} />)}
    </div>
  );
}

function IssueCard({ issue }: { issue: TwinBomIssue }) {
  return (
    <div style={{ ...cardStyle, borderLeft: `3px solid var(--${SEVERITY_TONE[issue.severity] === "orange" ? "orange" : SEVERITY_TONE[issue.severity] || "line"})` }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Badge tone={SEVERITY_TONE[issue.severity] || "slate"}>{issue.severity}</Badge>
        <b style={{ fontSize: 12.5 }}>{issue.title}</b>
        {issue.systems.length > 0 && <span style={{ fontSize: 11, color: "var(--faint)" }}>{issue.systems.join(", ")}</span>}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10, marginTop: 8, fontSize: 11.5, lineHeight: 1.5 }}>
        {issue.cause && <div><div style={kicker}>CAUSE</div>{issue.cause}</div>}
        {issue.effect && <div><div style={kicker}>IF IGNORED</div>{issue.effect}</div>}
        {issue.action && <div><div style={kicker}>WHAT TO DO</div>{issue.action}{issue.who_acts ? <span style={{ color: "var(--faint)" }}> — {issue.who_acts}</span> : null}</div>}
      </div>
    </div>
  );
}

function VendorDeclarations({ bom }: { bom: TwinBom }) {
  const declared = bom.declared_capabilities ?? [];
  const contracts = bom.contracts ?? [];
  if (!declared.length && !contracts.length) return null;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 10, marginTop: 14 }}>
      {declared.length > 0 && (
        <div style={cardStyle}>
          <div style={kicker}>DECLARED BY VENDORS — NOT OBSERVED · {declared.length}</div>
          <ul style={{ margin: "6px 0 0", paddingLeft: 16, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
            {declared.slice(0, 30).map((d, i) => (
              <li key={i}>{[d.product, d.version, d.algorithm, d.pqc_ready == null ? null : d.pqc_ready ? "PQC ready" : "not PQC ready", d.support_lifecycle].filter(Boolean).join(" · ")}</li>
            ))}
          </ul>
        </div>
      )}
      {contracts.length > 0 && (
        <div style={cardStyle}>
          <div style={kicker}>CONTRACTS FROM THE REGISTER · {contracts.length}</div>
          <ul style={{ margin: "6px 0 0", paddingLeft: 16, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
            {contracts.slice(0, 30).map((c, i) => (
              <li key={i}>{[c.vendor, c.product, c.contract_state, c.support_level, c.end ? `ends ${c.end}` : null].filter(Boolean).join(" · ")}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------------------------- */

function ConnectionMap({ view }: { view: TwinBomImpact }) {
  const nodes = view.systems;
  if (nodes.length < 2) return null;
  const W = 640, H = Math.max(240, Math.min(420, 80 + nodes.length * 30));
  const R = Math.min(W, H) / 2 - 50;
  const pos = new Map(nodes.map((s, i) => {
    const a = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    return [s.id, { x: W / 2 + R * 1.35 * Math.cos(a), y: H / 2 + R * Math.sin(a) }];
  }));
  return (
    <svg role="img" aria-label="System connection map" viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", maxHeight: 420, display: "block" }}>
      <defs>
        <marker id="twin-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--faint)" />
        </marker>
      </defs>
      {view.connections.map((c, i) => {
        const a = pos.get(c.caller_id), b = pos.get(c.provider_id);
        if (!a || !b) return null;
        const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
        const pad = 34;
        return (
          <line key={i} x1={a.x + (dx / len) * pad} y1={a.y + (dy / len) * pad} x2={b.x - (dx / len) * pad} y2={b.y - (dy / len) * pad}
            stroke={c.status ? CONNECTION_COLOR[c.status] : "var(--faint)"} strokeWidth={c.status && c.status !== "NOT_AFFECTED" ? 2.4 : 1.4}
            markerEnd="url(#twin-arrow)">
            <title>{`${c.caller} → ${c.provider}${c.status ? ` · ${CONNECTION_LABEL[c.status]}` : ""}`}</title>
          </line>
        );
      })}
      {nodes.map((s) => {
        const p = pos.get(s.id)!;
        const changing = view.change ? s.in_change : false;
        return (
          <g key={s.id}>
            <circle cx={p.x} cy={p.y} r={26} fill="var(--panel-2)" stroke={changing ? "var(--red)" : "var(--violet)"} strokeWidth={changing ? 2.5 : 1.5} />
            <text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={10} fill="var(--text)" fontWeight={700}>
              {s.name.split(" ").map((w) => w[0]).join("").slice(0, 4)}
            </text>
            <text x={p.x} y={p.y + 42} textAnchor="middle" fontSize={10.5} fill="var(--dim)">{s.name}</text>
          </g>
        );
      })}
    </svg>
  );
}

function ConnectionsSection({ view, simulating }: { view: TwinBomImpact; simulating: boolean }) {
  return (
    <Panel title="Connected systems" sub={simulating
      ? "which system is connected to which, which side the change touches, and what that does to the other side"
      : "which system is connected to which — run a simulation to see what a change does to each connection"}>
      {view.connections.length === 0 ? (
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>
          No system-to-system connection is recorded in this estate (no declared dependency and no observed connection to another system's host), so connection effects cannot be shown.
        </div>
      ) : (
        <>
          <ConnectionMap view={view} />
          {simulating && (
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)", margin: "6px 0 10px" }}>
              {(Object.keys(CONNECTION_LABEL) as TwinConnectionStatus[]).map((k) => (
                <span key={k} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                  <span style={{ width: 14, height: 3, background: CONNECTION_COLOR[k], display: "inline-block" }} />{CONNECTION_LABEL[k]}
                </span>
              ))}
              <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 10, height: 10, borderRadius: 99, border: "2px solid var(--red)", display: "inline-block" }} />system in the change
              </span>
            </div>
          )}
          <div aria-label="Connection effects" style={{ display: "grid", gap: 8 }}>
            {view.connections.map((c) => <ConnectionCard key={`${c.caller_id}>${c.provider_id}>${c.relation}`} c={c} simulating={simulating} />)}
          </div>
          {simulating && view.ripple.length > 0 && (
            <div aria-label="Ripple through connections" style={{ ...cardStyle, marginTop: 12 }}>
              <div style={kicker}>RIPPLE — SYSTEMS REACHED THROUGH THE CONNECTIONS</div>
              <ul style={{ margin: "6px 0 0", paddingLeft: 16, fontSize: 12, lineHeight: 1.6 }}>
                {view.ripple.map((r) => (
                  <li key={r.system_id}>
                    <b>{r.name}</b> <span style={{ color: "var(--faint)" }}>({r.hops} hop{r.hops === 1 ? "" : "s"}: {r.path.join(" → ")})</span>
                    <div style={{ color: "var(--dim)", fontSize: 11.5 }}>{r.effect}</div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function ConnectionCard({ c, simulating }: { c: TwinBomConnection; simulating: boolean }) {
  return (
    <div style={{ ...cardStyle, borderLeft: `3px solid ${c.status ? CONNECTION_COLOR[c.status] : "var(--line)"}` }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <b style={{ fontSize: 13 }}>{c.caller}</b>
        <span style={{ color: "var(--faint)" }}>→</span>
        <b style={{ fontSize: 13 }}>{c.provider}</b>
        <span style={{ fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>
          {[c.relation, c.provenance, c.via].filter(Boolean).join(" · ")}
        </span>
        {simulating && c.status && <Badge tone={c.severity ? SEVERITY_TONE[c.severity] : "slate"}>{CONNECTION_LABEL[c.status]}</Badge>}
      </div>
      {simulating && c.status && c.status !== "NOT_AFFECTED" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 10, marginTop: 8, fontSize: 11.5, lineHeight: 1.5 }}>
          {c.effect_on_caller && <div><div style={kicker}>EFFECT ON {c.caller.toUpperCase()}</div>{c.effect_on_caller}</div>}
          {c.effect_on_provider && <div><div style={kicker}>EFFECT ON {c.provider.toUpperCase()}</div>{c.effect_on_provider}</div>}
          {c.action && <div><div style={kicker}>WHAT TO DO</div>{c.action}</div>}
        </div>
      )}
      {simulating && c.status === "NOT_AFFECTED" && c.effect_on_caller && (
        <div style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 6 }}>{c.effect_on_caller}</div>
      )}
      {(c.shared.length > 0 || c.provider_endpoints.length > 0) && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginTop: 8 }}>
          {c.shared.length > 0 && <span style={kicker}>SHARED</span>}
          {c.shared.map((s) => (
            <span key={s.asset_id} title={s.status ? STATUS_LABEL[s.status] : undefined}
              style={{ fontSize: 11, padding: "2px 8px", borderRadius: 999, border: `1px solid ${s.status ? STATUS_COLOR[s.status] : "var(--line)"}`, color: "var(--dim)" }}>
              {s.kind}: {s.name}
            </span>
          ))}
          {c.provider_endpoints.length > 0 && (
            <span style={{ fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>
              {c.provider} serves {c.provider_endpoints.slice(0, 2).join(" ; ")}
            </span>
          )}
        </div>
      )}
      {simulating && c.issues.length > 0 && (
        <div style={{ marginTop: 8, display: "grid", gap: 6 }}>
          {c.issues.map((issue, i) => <IssueCard key={i} issue={issue} />)}
        </div>
      )}
    </div>
  );
}
