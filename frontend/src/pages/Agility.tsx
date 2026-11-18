import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { IconCertificate, IconCrypto, IconHardware, IconTarget, IconClock, IconSecurity, IconTrendUp, IconTrendDown, IconInfo, IconWarn } from "../components/icons";

interface AgilitySystem {
  system?: string;
  system_id?: string;
  agility_score?: number;
  category?: string;
  score_delta?: number;
}
interface AgilityResp {
  systems?: AgilitySystem[];
  /** null when nothing is scored — the API no longer answers a bare 0 here. */
  average?: number | null;
  average_basis?: string;
  scored_systems?: number;
}

export default function Agility() {
  const { data, loading, error } = useLive<AgilityResp>("/api/v1/agility", { systems: [], average: null });
  const systems = data.systems ?? [];
  // Nothing here is drawn until the read returned. The fallback shape carries
  // average 0, which used to render as "0/100 · RIGID" and, worse, as
  // "100% configurable" — arithmetic on an estate that was never read.
  const readOk = !loading && !error;
  const hasSystems = readOk && systems.length > 0;
  // The server sends `average: 0` for an estate with no scored systems. An
  // average over zero systems is not a measurement, so it renders as "—".
  const score = readOk && systems.length > 0 && data.average != null ? Math.round(data.average) : null;
  const pct = (n: number | null) => (n == null ? "—" : `${n}%`);

  // Bucket counts come from the per-system scores the server returned; the
  // percentages are shares of the systems actually scored, never of a
  // theoretical total.
  const agileCount = systems.filter((s) => (s.agility_score ?? 0) >= 70).length;
  const midCount = systems.filter((s) => (s.agility_score ?? 0) >= 40 && (s.agility_score ?? 0) < 70).length;
  const rigidCount = systems.filter((s) => (s.agility_score ?? 0) < 40).length;
  const pqcReady = hasSystems ? Math.round((agileCount / systems.length) * 100) : null;
  const hardCoded = hasSystems ? Math.round((rigidCount / systems.length) * 100) : null;
  const midTier = hasSystems ? Math.round((midCount / systems.length) * 100) : null;
  const configurable = hasSystems ? pqcReady : null;
  const avgPct = score == null ? 0 : score / 100;
  const categoryBreakdown = useMemo(() => {
    const m: Record<string, number> = {};
    systems.forEach((s) => { const c = s.category || "unclassified"; m[c] = (m[c] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [systems]);

  const tone = score == null ? "slate" : score >= 70 ? "green" : score >= 50 ? "amber" : "red";
  const scoreWord = score == null ? "not read" : score >= 70 ? "agile" : score >= 50 ? "moderate" : "rigid";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header — visual */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 420px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--accent)" }} /> NIST SP 1800-38 · CRYPTO AGILITY FRAMEWORK
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconSecurity size={18} /></span>
            Crypto Agility
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            How fast the estate can move off a vulnerable algorithm, measured from evidence.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={avgPct} label={score ?? "—"} sub="agility" tone={tone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>ENTERPRISE SCORE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{score == null ? "agility read did not return" : score >= 70 ? "Agile — configurable surface" : score >= 50 ? "Moderate — mixed surface" : "Rigid — hard-coded dominance"}</div>
              <div style={{ marginTop: 6 }}><Bar value={avgPct} tone={tone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Link to="/cbom" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Explore CBOM →</Link>
            <Link to="/migration" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Migration plan →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{readOk ? `${systems.length} systems scored` : "not read"}</span>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: 14 }}><LiveStatus loading={loading} error={error} /></div>

      {/* Top 4 metric cards — visual */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--red)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconTarget size={12} /> ENTERPRISE AGILITY</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : tone === "slate" ? "var(--slate)" : "var(--red)" }}>{loading ? "…" : score == null ? "—" : `${score}`}<span style={{ fontSize: 16, color: "var(--faint)" }}>{score == null ? "" : " / 100"}</span></div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Aggregate across estate</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: tone === "green" ? "color-mix(in srgb, var(--green) 14%, transparent)" : tone === "amber" ? "color-mix(in srgb, var(--amber) 14%, transparent)" : "color-mix(in srgb, var(--red) 14%, transparent)", border: `1px solid color-mix(in srgb, ${tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--red)"} 35%, var(--line))`, color: tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--red)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{readOk ? `${systems.length} systems` : "not read"}</span><span style={{ color: tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--slate)" }}>{scoreWord}</span></div>
            <Bar value={avgPct} tone={tone} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{score == null ? "no aggregate in this read" : "server-computed estate average"}</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${rigidCount ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconWarn size={12} /> HARD-CODED CRYPTO</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: hardCoded == null ? "var(--slate)" : rigidCount ? "var(--red)" : "var(--dim)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : pct(hardCoded)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{readOk ? `${rigidCount} systems · code change required` : "not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: rigidCount ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid color-mix(in srgb, ${rigidCount ? "var(--red)" : "var(--green)"} 35%, var(--line))`, color: rigidCount ? "var(--red)" : "var(--green)" }}>{rigidCount ? <IconTrendUp size={16} /> : <IconSecurity size={16} />}</span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>blocker systems</span><span style={{ color: rigidCount ? "var(--red)" : "var(--green)" }}>{rigidCount ? "action needed" : "clear"}</span></div>
            <Bar value={(hardCoded ?? 0) / 100} tone={rigidCount ? "red" : "green"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>In binary / firmware / source</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCrypto size={12} /> CONFIGURABLE SURFACE</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: configurable == null ? "var(--slate)" : "var(--text)" }}>{loading ? "…" : pct(configurable)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{readOk ? `${systems.length - rigidCount} systems above the rigid band` : "not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", color: "var(--accent)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>re-configurable</span><span style={{ color: "var(--accent)" }}>● fast path</span></div>
            <Bar value={(configurable ?? 0) / 100} tone="cyan" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>share of scored systems scoring ≥ 70</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--green)", background: "color-mix(in srgb, var(--green) 4%, var(--panel))" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>AGILE BAND (≥ 70)</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: pqcReady == null ? "var(--slate)" : "var(--green)" }}>{loading ? "…" : pct(pqcReady)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{readOk ? `${agileCount} systems ≥ 70 agility` : "not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--green) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--green) 35%, var(--line))", color: "var(--green)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, height: 8, background: "var(--bg-2)", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: `${pqcReady ?? 0}%`, height: "100%", background: "var(--green)", opacity: .95 }} />
              <div style={{ width: `${midTier ?? 0}%`, height: "100%", background: "var(--amber)", opacity: .9 }} />
              <div style={{ width: `${hardCoded ?? 0}%`, height: "100%", background: "var(--red)", opacity: .85 }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>{agileCount} agile</span><span>{midCount} transit</span><span>{rigidCount} rigid</span></div>
          </div>
        </div>
      </div>

      {/* Agility spectrum — visual strip */}
      <div className="panel" style={{ padding: "14px 16px", marginBottom: 18, borderLeft: `3px solid ${tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--red)"}`, background: tone === "green" ? "color-mix(in srgb, var(--green) 4%, var(--panel))" : tone === "red" ? "color-mix(in srgb, var(--red) 4%, var(--panel))" : "var(--panel)" }}>
        <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 32, height: 32, borderRadius: 999, display: "grid", placeItems: "center", background: tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--red)", color: tone === "amber" ? "#000" : "#fff" }}><IconClock size={14} /></span>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : "var(--red)" }}>Agility spectrum — {readOk ? `${systems.length} systems` : "not read"}</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>From hard-coded (code change) → configurable (policy flip) → PQC ready</div>
            </div>
          </div>
          <div style={{ flex: "1 1 220px", minWidth: 200 }}>
            <div style={{ height: 10, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: `${hardCoded ?? 0}%`, background: "var(--red)" }} title={`${rigidCount} rigid`} />
              <div style={{ width: `${midTier ?? 0}%`, background: "var(--amber)" }} title={`${midCount} transitional`} />
              <div style={{ width: `${pqcReady ?? 0}%`, background: "var(--green)" }} title={`${agileCount} agile`} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 4 }}><span>● rigid</span><span>● transitional</span><span>● agile</span></div>
          </div>
          <div style={{ display: "flex", gap: 6 }}>
            <Badge tone="red">{rigidCount} rigid</Badge>
            <Badge tone="amber">{midCount} transit</Badge>
            <Badge tone="green">{agileCount} agile</Badge>
          </div>
        </div>
      </div>

      {/* Analytics strip — 3 visual panels */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Agility distribution" sub="systems by agility band" style={{ padding: "14px 16px" }}>
          {[
            ["Agile ≥ 70", (pqcReady ?? 0) / 100, "green", agileCount],
            ["Transitional 40-69", (midTier ?? 0) / 100, "amber", midCount],
            ["Rigid < 40", (hardCoded ?? 0) / 100, "red", rigidCount],
          ].map(([label, v, t, n]) => (
            <div key={label as string} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ width: 130, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{label as string}</span>
              <div style={{ flex: 1 }}><Bar value={v as number} tone={t as string} /></div>
              <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 52, textAlign: "right" }}>{n as number} · {Math.round((v as number) * 100)}%</span>
            </div>
          ))}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Thresholds: NIST SP 1800-38C agility model</div>
        </Panel>

        <Panel title="Migration velocity" sub="score trend per system" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: score == null ? "var(--panel-2)" : score >= 50 ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `2px solid ${score == null ? "var(--line)" : score >= 70 ? "var(--green)" : score >= 50 ? "var(--amber)" : "var(--red)"}`, display: "grid", placeItems: "center", color: score == null ? "var(--slate)" : score >= 70 ? "var(--green)" : score >= 50 ? "var(--amber)" : "var(--red)", fontSize: 18, fontWeight: 800 }}>{score ?? "—"}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Enterprise velocity</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{systems.filter((s) => (s.score_delta ?? 0) > 0).length} improving · {systems.filter((s) => (s.score_delta ?? 0) < 0).length} declining</div>
              <div style={{ fontSize: 10, color: score == null ? "var(--faint)" : score >= 70 ? "var(--green)" : "var(--amber)", marginTop: 2 }}>{score == null ? "no aggregate returned" : score >= 70 ? "on track" : "needs acceleration"}</div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--green) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: hasSystems ? "var(--green)" : "var(--slate)" }}>{hasSystems ? systems.filter((s) => (s.score_delta ?? 0) > 0).length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>IMPROVING</div></div>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: hasSystems ? undefined : "var(--slate)" }}>{hasSystems ? systems.filter((s) => (s.score_delta ?? 0) === 0 || s.score_delta === undefined).length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>FLAT</div></div>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--red) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: hasSystems ? "var(--red)" : "var(--slate)" }}>{hasSystems ? systems.filter((s) => (s.score_delta ?? 0) < 0).length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>DECLINING</div></div>
          </div>
        </Panel>

        <Panel title="Category exposure" sub="systems per business domain" style={{ padding: "14px 16px" }}>
          {categoryBreakdown.length ? categoryBreakdown.map(([cat, cnt]) => {
            const pct = cnt / Math.max(1, systems.length);
            return (
              <div key={cat as string} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <span style={{ width: 120, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{cat as string}</span>
                <div style={{ flex: 1 }}><Bar value={pct} tone="violet" /></div>
                <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 28, textAlign: "right" }}>{cnt as number}</span>
              </div>
            );
          }) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No category data — run discovery to classify estate</div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>{categoryBreakdown.length} domains · source: inventory spine</div>
        </Panel>
      </div>

      {/* System-level drill-down — visual */}
      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> System-level Agility Drill-down</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11.5, color: "var(--dim)" }}>Per-system agility score — <span style={{ color: "var(--accent)" }}>Bar length = score · dot = category · trend = delta</span> — live from evidence chain</p>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Badge tone="green">{agileCount} agile</Badge>
            <Badge tone="red">{rigidCount} rigid</Badge>
            <Badge tone="slate">{systems.length} total</Badge>
          </div>
        </div>

        {/* Visual card grid */}
        {systems.length > 0 ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12, padding: 16 }}>
            {systems.map((a) => {
              const sc = a.agility_score ?? 0;
              const t: string = sc >= 70 ? "green" : sc >= 50 ? "amber" : "red";
              const label: string = sc >= 70 ? "AGILE" : sc >= 50 ? "TRANSITIONAL" : "RIGID";
              const delta = a.score_delta;
              return (
                <div key={a.system || a.system_id} style={{ padding: 14, background: "var(--panel-2)", border: "1px solid var(--line)", borderTop: `2px solid ${t === "green" ? "var(--green)" : t === "amber" ? "var(--amber)" : "var(--red)"}`, borderRadius: "var(--r)", display: "flex", flexDirection: "column", gap: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <Badge tone={t}>{label}</Badge>
                    <Badge tone="violet">{a.category ?? "unclassified"}</Badge>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.system || a.system_id}</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 800, fontFamily: "var(--mono)", color: t === "green" ? "var(--green)" : t === "amber" ? "var(--amber)" : "var(--red)", minWidth: 38 }}>{sc}</div>
                    <div style={{ flex: 1 }}><Bar value={sc / 100} tone={t} /></div>
                    <span style={{ fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>/100</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: 8, borderTop: "1px dashed var(--line)", fontSize: 11 }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--dim)" }}>
                      {delta === undefined ? <span style={{ color: "var(--faint)" }}>— flat</span> : delta > 0 ? <><IconTrendUp size={12} style={{ color: "var(--green)" }} /> <span style={{ color: "var(--green)", fontWeight: 700, fontFamily: "var(--mono)" }}>+{delta}</span></> : delta < 0 ? <><IconTrendDown size={12} style={{ color: "var(--red)" }} /> <span style={{ color: "var(--red)", fontWeight: 700, fontFamily: "var(--mono)" }}>{delta}</span></> : <span style={{ color: "var(--faint)" }}>→ flat</span>}
                      <span style={{ color: "var(--faint)" }}>trend</span>
                    </span>
                    <span style={{ fontFamily: "var(--mono)", color: "var(--faint)", fontSize: 10 }}>{a.system_id ?? ""}</span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}>
            <div style={{ width: 44, height: 44, borderRadius: 12, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", margin: "0 auto 10px" }}><IconHardware size={18} style={{ color: "var(--faint)" }} /></div>
            <div style={{ fontWeight: 600, color: "var(--text)" }}>No systems scored yet</div>
            <div style={{ fontSize: 12, marginTop: 4, maxWidth: 420, marginInline: "auto" }}><span title={"Run a discovery scan to populate crypto agility — hard-coded algorithms will be flagged with their file location so teams can plan the code change."}>{"Run a discovery scan to populate crypto agility"}</span></div>
          </div>
        )}

        {/* Legend */}
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--green)", display: "inline-block" }} /> Agile ≥70 — configurable</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--amber)", display: "inline-block" }} /> Transitional 40–69</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--red)", display: "inline-block" }} /> Rigid &lt;40 — hard-coded</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>NIST SP 1800-38C · live evidence</span>
        </div>
      </div>
    </div>
  );
}
