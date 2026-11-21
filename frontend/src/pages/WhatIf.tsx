/* Migration what-if — the one-screen go / no-go answer for a crypto change.
 *
 * It reads the same live estate graph (for the Meridian sandbox: the agents' observations
 * of the bank's servers) and the same engine as the Simulation page, so the two can never
 * disagree: this page condenses the answer into a verdict, seven feasibility checks and the
 * migration plan; the Simulation page shows every component and connection behind it.
 *
 * Nothing is hard-coded: a check with nothing recorded says UNKNOWN, and "nothing uses the
 * old algorithm" is reported as such — never as "feasible".
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge } from "../components/ui";
import { IconTarget, IconSecurity } from "../components/icons";
import EstateDiscoveryCta from "../components/EstateDiscoveryCta";
import { apiTwinBoms, apiTwinBomImpact } from "../lib/api.js";
import type { TwinBomImpact, TwinBomComponent, TwinBomKind, MigrationStrategy } from "../lib/api.js";

const TARGETS = [
  "ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "X25519MLKEM768",
  "AES-256-GCM", "ChaCha20-Poly1305", "SHA-384", "RSA-3072", "ECDSA-P384",
];
/* a sensible target per family of what the estate holds — offered, never forced */
function suggestTarget(from: string): string {
  const f = from.toUpperCase();
  if (/3DES|DES|RC4|AES128|AES-128/.test(f)) return "AES-256-GCM";
  if (/ECDSA|DSA|SHA\d*WITH|ED25519/.test(f)) return "ML-DSA-65";
  if (/SHA-?1|MD5/.test(f)) return "SHA-384";
  return "ML-KEM-768";
}

const VERDICT: Record<MigrationStrategy, { label: string; tone: string; note: string }> = {
  BLOCKED: { label: "BLOCKED", tone: "red", note: "something on the path cannot run the target — clear it first" },
  PARALLEL: { label: "FEASIBLE — PARALLEL RUN", tone: "amber", note: "run old and new side by side, then retire the old" },
  DIRECT: { label: "FEASIBLE — DIRECT CUT-OVER", tone: "green", note: "one planned switch; nothing needs both algorithms" },
  NOT_DETERMINED: { label: "NOTHING TO MIGRATE", tone: "slate", note: "the estate holds no use of this algorithm — that is not 'no impact' elsewhere" },
};
type CheckState = "ready" | "action" | "blocked" | "unknown" | "none";
const CHECK_TONE: Record<CheckState, string> = { ready: "green", action: "amber", blocked: "red", unknown: "slate", none: "slate" };
const CHECK_LABEL: Record<CheckState, string> = {
  ready: "ready", action: "action needed", blocked: "blocked", unknown: "unknown", none: "not in estate",
};
const COLOR: Record<string, string> = { green: "var(--green)", amber: "var(--amber)", red: "var(--red)", slate: "var(--faint)" };

const inputStyle: React.CSSProperties = {
  padding: "8px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)",
  color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5, minWidth: 180,
};
const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--faint)" };
const kicker: React.CSSProperties = { fontSize: 9.5, letterSpacing: ".08em", color: "var(--faint)", fontFamily: "var(--mono)" };
const chip = (active: boolean): React.CSSProperties => ({
  padding: "4px 10px", fontSize: 11.5, borderRadius: 999, cursor: "pointer",
  border: `1px solid ${active ? "var(--violet)" : "var(--line)"}`,
  background: active ? "color-mix(in srgb, var(--violet) 14%, transparent)" : "transparent",
  color: active ? "var(--text)" : "var(--dim)", fontWeight: active ? 700 : 500,
});
const tile: React.CSSProperties = {
  padding: "14px 16px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)",
};

interface Check { key: string; name: string; state: CheckState; count: number; sub: string; items: string[] }

function rows(view: TwinBomImpact, bom: TwinBomKind): TwinBomComponent[] {
  return view.boms.find((b) => b.bom === bom)?.components ?? [];
}
function names(list: TwinBomComponent[]): string[] {
  return Array.from(new Set(list.map((r) => r.name))).slice(0, 6);
}
function hasBlocker(view: TwinBomImpact, bom: TwinBomKind): boolean {
  return (view.boms.find((b) => b.bom === bom)?.issues ?? []).some((i) => i.severity === "BLOCKER");
}

/* seven checks, each condensed from the same per-component statuses the Simulation page lists */
function checksOf(view: TwinBomImpact): Check[] {
  const cbom = rows(view, "CBOM");
  const crypto = cbom.filter((r) => r.kind === "crypto");
  const cryptoHit = crypto.filter((r) => r.status === "AFFECTED");
  const certs = cbom.filter((r) => r.kind === "asset" && (r.type === "CERTIFICATE" || r.type === "CA"));
  const certHit = certs.filter((r) => r.status === "AFFECTED");
  const libs = rows(view, "SBOM").filter((r) => r.type === "LIBRARY");
  const libHit = libs.filter((r) => r.status === "AFFECTED");
  const libUnknown = libs.filter((r) => r.status === "UNKNOWN");
  const libReady = libs.filter((r) => r.status === "READY");
  const hsms = rows(view, "TECHBOM").filter((r) => r.type === "HSM" || r.type === "KMS_KEY");
  const hsmHit = hsms.filter((r) => r.status === "AFFECTED");
  const hsmUnknown = hsms.filter((r) => r.status === "UNKNOWN");
  const vendors = rows(view, "VBOM");
  const vendorHit = vendors.filter((r) => r.status === "AFFECTED");
  const vendorUnknown = vendors.filter((r) => r.status === "UNKNOWN");
  const endpoints = rows(view, "NBOM").filter((r) => r.type === "NETWORK_ENDPOINT");
  const endpointHit = endpoints.filter((r) => r.status === "AFFECTED");
  const links = view.connections.filter((c) => c.status && c.status !== "NOT_AFFECTED");
  const pick = (hit: number, unknown: number, total: number, blocked = false): CheckState =>
    blocked ? "blocked" : hit > 0 ? "action" : unknown > 0 ? "unknown" : total > 0 ? "ready" : "none";
  return [
    { key: "crypto", name: "Crypto in use", state: pick(cryptoHit.length, 0, crypto.length, hasBlocker(view, "CBOM")),
      count: cryptoHit.length, sub: `of ${crypto.length} observed crypto uses must move`, items: names(cryptoHit) },
    { key: "certs", name: "Certificates & CAs", state: pick(certHit.length, 0, certs.length),
      count: certHit.length, sub: "to reissue, or CAs that must issue the target", items: names(certHit) },
    { key: "libs", name: "Crypto libraries", state: pick(libHit.length, libUnknown.length, libs.length),
      count: libHit.length, sub: `lack the target · ${libReady.length} ready · ${libUnknown.length} unknown`, items: names([...libHit, ...libUnknown]) },
    { key: "hsm", name: "HSMs & key stores", state: pick(hsmHit.length, hsmUnknown.length, hsms.length, hasBlocker(view, "HBOM")),
      count: hsmHit.length + hsmUnknown.length, sub: `${hsmHit.length} cannot run it · ${hsmUnknown.length} capability unknown`, items: names([...hsmHit, ...hsmUnknown]) },
    { key: "vendors", name: "Vendors (declared)", state: pick(vendorHit.length, vendorUnknown.length, vendors.length, hasBlocker(view, "VBOM")),
      count: vendorHit.length, sub: `not ready · ${vendorUnknown.length} without a declaration`, items: names([...vendorHit, ...vendorUnknown]) },
    { key: "network", name: "Network endpoints", state: pick(endpointHit.length, 0, endpoints.length),
      count: endpointHit.length, sub: `of ${endpoints.length} carry it or need TLS 1.3`, items: names(endpointHit) },
    { key: "links", name: "Connected systems", state: links.length ? "action" : view.connections.length ? "ready" : "unknown",
      count: links.length, sub: view.connections.length ? `of ${view.connections.length} connections are touched` : "no connection recorded",
      items: links.slice(0, 6).map((c) => `${c.caller} → ${c.provider}`) },
  ];
}

export default function WhatIf() {
  const [inventory, setInventory] = useState<TwinBomImpact | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "none" | "error">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [from, setFrom] = useState("RSA");
  const [to, setTo] = useState("ML-KEM-768");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<TwinBomImpact | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoadState("loading");
    const response = await apiTwinBoms();
    if (response.data && Array.isArray(response.data.boms)) {
      setInventory(response.data);
      setLoadState("ready");
      const held = response.data.context?.algorithms ?? [];
      if (held.length && !held.some((a) => a.algorithm.toUpperCase() === "RSA")) {
        setFrom(held[0].algorithm);
        setTo(suggestTarget(held[0].algorithm));
      }
    } else if (String(response.error || "").includes("404")) {
      setLoadState("none");
    } else {
      setLoadError(response.detail || response.error || "the estate could not be read");
      setLoadState("error");
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const check = async () => {
    if (!from.trim() || !to.trim()) return;
    setBusy(true);
    setRunError(null);
    const response = await apiTwinBomImpact({ from_algo: from.trim(), to_algo: to.trim() });
    setBusy(false);
    if (response.data && Array.isArray(response.data.boms)) setResult(response.data);
    else setRunError(response.detail || response.error || "the check could not be run");
  };

  const algorithms = inventory?.context?.algorithms ?? [];
  const checks = useMemo(() => (result ? checksOf(result) : []), [result]);
  const strategy: MigrationStrategy = result?.strategy?.recommended ?? "NOT_DETERMINED";
  const verdict = VERDICT[strategy];
  const counts = result?.problem_counts ?? {};

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{
          display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999,
          background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))",
          fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em",
        }}>
          <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} /> MIGRATION WHAT-IF · GO / NO-GO ON ONE SCREEN
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconTarget size={18} /></span>
          What-If Migration Simulator
        </h1>
        <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 760 }}>
          Can this bank move from one algorithm to another? A verdict, seven feasibility checks and the plan —
          read from the live estate the agents report. The Simulation page shows every component and connection behind it.
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, fontSize: 11.5, color: "var(--dim)" }}>
          <IconSecurity size={13} />
          <span><b style={{ color: "var(--violet)" }}>Simulation only</b> — nothing is re-keyed, deployed or changed.</span>
        </div>
      </div>

      {loadState === "loading" && <Panel title="Reading the estate"><div style={{ fontSize: 12, color: "var(--dim)" }}>Loading what the estate holds…</div></Panel>}
      {loadState === "none" && (
        <Panel title="No estate to check against" sub="the check reads the estate's own evidence">
          <div style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 10 }}>
            Nothing has been discovered yet. Run a discovery (or let the sandbox agents report) and the check can run.
          </div>
          <EstateDiscoveryCta onDiscovered={load} compact />
        </Panel>
      )}
      {loadState === "error" && (
        <Panel title="The estate could not be read">
          <div style={{ fontSize: 12.5, color: "var(--dim)" }}>{loadError} — that is not "the estate is empty".</div>
          <button className="btn" style={{ marginTop: 10 }} onClick={() => void load()}>Retry</button>
        </Panel>
      )}

      {inventory && (
        <Panel title="Scenario" sub={`${inventory.estate || "estate"} · ${inventory.totals.systems} systems · ${inventory.totals.connections} connections`}>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
            <label style={labelStyle}>
              Current algorithm
              <input aria-label="Current algorithm" list="whatif-held" value={from} onChange={(e) => { setFrom(e.target.value); setResult(null); }} style={inputStyle} />
              <datalist id="whatif-held">{algorithms.map((a) => <option key={a.algorithm} value={a.algorithm} />)}</datalist>
            </label>
            <span style={{ paddingBottom: 9, color: "var(--faint)" }}>→</span>
            <label style={labelStyle}>
              Target algorithm
              <input aria-label="Target algorithm" list="whatif-targets" value={to} onChange={(e) => { setTo(e.target.value); setResult(null); }} style={inputStyle} />
              <datalist id="whatif-targets">{TARGETS.map((t) => <option key={t} value={t} />)}</datalist>
            </label>
            <button className="btn primary" disabled={busy || !from.trim() || !to.trim()} onClick={() => void check()}>
              {busy ? "Checking…" : "Check feasibility"}
            </button>
          </div>
          {algorithms.length > 0 && (
            <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
              <span style={kicker}>IN USE IN THIS ESTATE</span>
              {algorithms.slice(0, 10).map((a) => (
                <button key={a.algorithm} type="button" aria-label={`Use ${a.algorithm}`} style={chip(from === a.algorithm)}
                  onClick={() => { setFrom(a.algorithm); setTo(suggestTarget(a.algorithm)); setResult(null); }}>
                  {a.algorithm} <span style={{ color: "var(--faint)" }}>· {a.systems.length} system{a.systems.length === 1 ? "" : "s"}</span>
                </button>
              ))}
            </div>
          )}
          {runError && <div role="alert" style={{ marginTop: 10, fontSize: 12, color: "var(--red)" }}>{runError}</div>}
        </Panel>
      )}

      {result && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 12, marginTop: 14 }}>
            <div aria-label="Feasibility verdict" style={{ ...tile, borderTop: `3px solid ${COLOR[verdict.tone]}` }}>
              <div style={kicker}>VERDICT · {result.change?.from_algo} → {result.change?.to_algo}</div>
              <div style={{ fontSize: 19, fontWeight: 800, margin: "6px 0 4px", color: COLOR[verdict.tone] }}>{verdict.label}</div>
              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>{verdict.note}</div>
            </div>
            <div style={{ ...tile, borderTop: "3px solid var(--violet)" }}>
              <div style={kicker}>SYSTEMS THAT CHANGE</div>
              <div style={{ fontSize: 24, fontWeight: 800, margin: "4px 0 2px" }}>
                {result.totals.systems_in_change ?? 0}<span style={{ fontSize: 13, color: "var(--faint)" }}> / {result.totals.systems}</span>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
                {result.systems.filter((s) => s.in_change).map((s) => s.name).join(", ") || "none"}
              </div>
            </div>
            <div style={{ ...tile, borderTop: `3px solid ${counts.BLOCKER ? "var(--red)" : counts.HIGH ? "var(--orange)" : "var(--line)"}` }}>
              <div style={kicker}>ISSUES FOUND</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
                <Badge tone="red">{`${counts.BLOCKER ?? 0} blocker`}</Badge>
                <Badge tone="orange">{`${counts.HIGH ?? 0} high`}</Badge>
                <Badge tone="amber">{`${counts.MEDIUM ?? 0} medium`}</Badge>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 6 }}>each with its cause and fix on the Simulation page</div>
            </div>
          </div>

          <Panel title="Feasibility checks" sub="condensed from every component of the estate's BOMs — unknown stays unknown" style={{ marginTop: 14 }}>
            <div aria-label="Feasibility checks" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10 }}>
              {checks.map((c) => {
                const tone = CHECK_TONE[c.state];
                return (
                  <div key={c.key} aria-label={`Check ${c.name}`} style={{ ...tile, padding: 12, borderTop: `2px solid ${COLOR[tone]}` }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 11.5, fontWeight: 700 }}>{c.name}</span>
                      <Badge tone={tone}>{CHECK_LABEL[c.state]}</Badge>
                    </div>
                    <div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", color: COLOR[tone] }}>{c.count}</div>
                    <div style={{ fontSize: 11, color: "var(--dim)" }}>{c.sub}</div>
                    {c.items.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 8 }}>
                        {c.items.map((x) => <span key={x} style={{ fontSize: 10, border: "1px solid var(--line)", borderRadius: 999, padding: "2px 7px", fontFamily: "var(--mono)", color: "var(--dim)" }}>{x}</span>)}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </Panel>

          <Panel title="Migration plan" sub="phased, providers before their callers — planned, never executed from here" style={{ marginTop: 14 }}>
            {result.plan.length === 0 ? (
              <div style={{ fontSize: 12, color: "var(--dim)" }}>No plan: nothing in the estate uses {result.change?.from_algo}.</div>
            ) : (
              <ol aria-label="Migration plan" style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 8 }}>
                {result.plan.map((step) => (
                  <li key={step.order} style={{ fontSize: 12.5 }}>
                    <b>{step.title}</b>
                    {step.systems.length > 0 && <span style={{ color: "var(--faint)", fontSize: 11 }}> · {step.systems.join(", ")}</span>}
                    {step.actions.length > 0 && (
                      <ul style={{ margin: "3px 0 0", paddingLeft: 16, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.5 }}>
                        {step.actions.slice(0, 3).map((a) => <li key={a}>{a}</li>)}
                      </ul>
                    )}
                  </li>
                ))}
              </ol>
            )}
          </Panel>

          {result.unknowns.length > 0 && (
            <details style={{ ...tile, marginTop: 14 }}>
              <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 700 }}>What this check cannot see ({result.unknowns.length})</summary>
              <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--dim)", lineHeight: 1.6 }}>
                {result.unknowns.map((u) => <li key={u}>{u}</li>)}
              </ul>
            </details>
          )}

          <div style={{ marginTop: 14 }}>
            <Link className="btn" to={`/simulation?from=${encodeURIComponent(result.change?.from_algo ?? from)}&to=${encodeURIComponent(result.change?.to_algo ?? to)}`}>
              See every component, issue and connection in the Simulation →
            </Link>
          </div>
        </>
      )}
    </div>
  );
}
