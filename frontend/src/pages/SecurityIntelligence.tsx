import React, { useEffect, useState } from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import {
  apiScanProfiles, apiScanProfileResolve, apiIdentityResolve, apiCorrelateFindings,
  apiRiskChain, apiAssetState, apiScanSchedule,
  ScanProfileResolve, IdentityAsset, ApiResult,
} from "../lib/api.js";

/* Security Intelligence — the deterministic decision engines (spec #1, #8,
   #10/#11/#12, #21–#25). Each panel drives one backend endpoint. All of them
   are read-mostly / pure: they compute a decision and never start a scan or
   mutate the estate. */

const inp: React.CSSProperties = {
  padding: "6px 10px", borderRadius: 6, border: "1px solid var(--line-strong)",
  background: "var(--bg)", color: "var(--text)", fontSize: 13, fontFamily: "var(--mono)",
};

function K({ k, v, tone }: { k: string; v: React.ReactNode; tone?: string }) {
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "baseline", padding: "3px 0" }}>
      <span style={{ width: 150, color: "var(--muted)", fontSize: 12.5 }}>{k}</span>
      <span className="mono" style={{ fontSize: 13, color: tone ? `var(--${tone})` : "var(--text)" }}>{v}</span>
    </div>
  );
}

export default function SecurityIntelligence() {
  const [profiles, setProfiles] = useState<string[]>([]);
  const [selProfile, setSelProfile] = useState("");
  const [selSector, setSelSector] = useState("generic");
  const [resolved, setResolved] = useState<ScanProfileResolve | null>(null);

  const [obsJson, setObsJson] = useState("");
  const [assets, setAssets] = useState<IdentityAsset[] | null>(null);
  const [merges, setMerges] = useState<number | null>(null);

  const [findJson, setFindJson] = useState("");
  const [riskAssetId, setRiskAssetId] = useState("");
  const [riskCritical, setRiskCritical] = useState(false);
  const [riskBusinessValue, setRiskBusinessValue] = useState("");
  const [dedup, setDedup] = useState<{ count: number; inputs: number; deduped_by: number } | null>(null);
  const [chain, setChain] = useState<{ overall_severity: string; compound_risk: boolean } | null>(null);

  const [sources, setSources] = useState("");
  const [ageSec, setAgeSec] = useState("");
  const [verified, setVerified] = useState(false);
  const [state, setState] = useState<Record<string, unknown> | null>(null);

  const [cadence, setCadence] = useState("on_change");
  const [event, setEvent] = useState("certificate.changed");
  const [sched, setSched] = useState<Record<string, unknown> | null>(null);

  const [err, setErr] = useState("");

  useEffect(() => {
    apiScanProfiles().then((r) => {
      if (r.ok && r.data) {
        const ids = r.data.profiles.map((p) => p.id);
        setProfiles(ids);
        setSelProfile((current) => current || ids[0] || "");
      }
    });
  }, []);

  const run = async <T,>(fn: () => Promise<ApiResult<T>>, then: (d: T) => void) => {
    setErr("");
    const r = await fn();
    if (r.data != null) then(r.data);
    else setErr(`HTTP error: ${r.error || "unknown"}`);
  };

  const resolveProfile = () => {
    if (!selProfile) { setErr("Select a scan profile returned by the live control plane"); return; }
    run(() => apiScanProfileResolve({ profile: selProfile, sector: selSector }), setResolved);
  };

  const resolveIdentity = () => {
    let obs: unknown;
    if (!obsJson.trim()) { setErr("Paste observations returned by an authorized scanner"); return; }
    try { obs = JSON.parse(obsJson); } catch { setErr("Observations must be valid JSON"); return; }
    run(() => apiIdentityResolve({ observations: obs as unknown as never[] as { source: string; ids: Record<string, string> }[] }),
      (d) => { setAssets(d.assets); setMerges(d.merges); });
  };

  const correlate = () => {
    let f: unknown;
    if (!findJson.trim()) { setErr("Paste findings returned by an authorized scanner"); return; }
    try { f = JSON.parse(findJson); } catch { setErr("Findings must be valid JSON"); return; }
    run(() => apiCorrelateFindings({ findings: f as Record<string, unknown>[] }),
      (d) => setDedup({ count: d.count, inputs: d.inputs, deduped_by: d.deduped_by }));
  };

  const chainIt = () => {
    let f: unknown;
    if (!riskAssetId.trim()) { setErr("Enter the asset identifier from the live inventory"); return; }
    if (!findJson.trim()) { setErr("Paste findings returned by an authorized scanner"); return; }
    try { f = JSON.parse(findJson); } catch { setErr("Findings must be valid JSON"); return; }
    run(() => apiRiskChain({ asset_id: riskAssetId.trim(), findings: f as Record<string, unknown>[], critical_asset: riskCritical, business_value: riskBusinessValue.trim() || undefined }),
      (d) => setChain({ overall_severity: String(d.overall_severity), compound_risk: Boolean(d.compound_risk) }));
  };

  const computeState = () => {
    const src: Record<string, string> = {};
    sources.split(",").forEach((p) => {
      const [k, v] = p.split(":").map((s) => s.trim());
      if (k && v) src[k] = v;
    });
    if (!Object.keys(src).length) { setErr("Enter source freshness values returned by the live inventory"); return; }
    run(() => apiAssetState({ sources: src, verification: verified ? "VERIFIED" : undefined, last_seen_epoch: ageSec.trim() ? Date.now() / 1000 - Number(ageSec) : null }),
      setState);
  };

  const computeSched = () => run(() => apiScanSchedule({ cadence, event, scan_type: "standard" }), setSched);

  const stateHealth = state?.health as { display_status?: string; verification?: string; freshness?: string } | undefined;
  const stateConf = state?.confidence as { tier?: string; score?: number; quality?: string } | undefined;
  const schedObj = sched?.schedule as { kind?: string; interval_s?: number | null; events?: string[] } | undefined;
  const scansForEvent = sched?.scans_for_event as string[] | undefined;

  return (
    <>
      <PageHead
        crumb="security / intelligence"
        title="Security Intelligence"
        sub="Deterministic decision engines — identity resolution, scan profiles, finding dedup, verification state and scan triggers. Read-mostly: nothing here starts a scan or mutates the estate."
      />
      {err && <div style={{ color: "var(--red)", marginBottom: 12, fontSize: 13 }}>{err}</div>}

      <div className="row" style={{ gap: 14, alignItems: "flex-start", flexWrap: "wrap" }}>

        {/* Scan profiles */}
        <Panel title="Scan profiles" sub="Spec #8 — name a policy, never loosen a sector" style={{ flex: "1 1 380px", minWidth: 380 }}>
          {profiles.length === 0 && <div className="dim" style={{ fontSize: 13 }}>Loading profiles…</div>}
          {profiles.length > 0 && (
            <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
              {profiles.map((p) => (
                <button key={p} onClick={() => setSelProfile(p)} style={{
                  padding: "4px 10px", borderRadius: 6, border: "1px solid var(--line-strong)",
                  background: selProfile === p ? "var(--accent)" : "var(--bg)",
                  color: selProfile === p ? "#fff" : "var(--text)", cursor: "pointer", fontSize: 12,
                }}>{p}</button>
              ))}
            </div>
          )}
          <K k="sector" v={
            <select value={selSector} onChange={(e) => setSelSector(e.target.value)} style={inp}>
              {["generic", "banking", "healthcare", "energy", "telecom", "government"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          } />
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <button className="btn btn-primary" onClick={resolveProfile}>Resolve profile</button>
          </div>
          {resolved && (
            <div style={{ marginTop: 12 }}>
              <K k="profile" v={resolved.profile.name} />
              <K k="mode" v={resolved.policy.scan.mode} />
              <K k="intensity" v={resolved.policy.scan.intensity} />
              <K k="production" v={String(resolved.policy.scan.production_protection)} tone={resolved.policy.scan.production_protection ? "green" : "red"} />
              <K k="collect_secrets" v={String(resolved.policy.privacy.collect_secrets)} tone={resolved.policy.privacy.collect_secrets ? "red" : "green"} />
              <K k="qps" v={String((resolved.limits as Record<string, unknown>).requests_per_second ?? "—")} />
              <K k="connections" v={String((resolved.limits as Record<string, unknown>).max_connections ?? "—")} />
              <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
                A regulated sector can only tighten this profile — it can never loosen it.
              </div>
            </div>
          )}
        </Panel>

        {/* Identity resolution */}
        <Panel title="Universal asset identity" sub="Spec #1 — cross-scanner collision into ONE asset" style={{ flex: "1 1 380px", minWidth: 380 }}>
          <textarea value={obsJson} onChange={(e) => setObsJson(e.target.value)} rows={7} placeholder="Paste observations returned by an authorized scanner" style={{ width: "100%", ...inp, resize: "vertical" }} />
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <button className="btn" onClick={resolveIdentity}>Resolve identity</button>
          </div>
          {assets && (
            <div style={{ marginTop: 12 }}>
              <K k="observations" v={String(assets.length)} />
              <K k="merges" v={String(merges ?? 0)} tone={(merges ?? 0) > 0 ? "green" : "slate"} />
              {assets.map((a) => (
                <div key={a.id} style={{ marginTop: 8, padding: "8px 10px", border: "1px solid var(--line)", borderRadius: 6 }}>
                  <div className="mono" style={{ fontSize: 12.5 }}>{a.id} <span className="dim">· {a.asset_type}</span></div>
                  <div className="dim" style={{ fontSize: 11.5 }}>{a.aliases.join(" · ")}</div>
                  <div className="dim" style={{ fontSize: 11.5 }}>sources: {a.sources.join(", ")}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Verification / freshness state */}
        <Panel title="Verification & freshness" sub="Spec #23/#24/#25 — a stale asset is never shown healthy" style={{ flex: "1 1 340px", minWidth: 340 }}>
          <K k="sources" v={<input value={sources} onChange={(e) => setSources(e.target.value)} style={{ width: 200, ...inp }} />} />
          <K k="last seen (s ago)" v={<input value={ageSec} onChange={(e) => setAgeSec(e.target.value)} style={{ width: 80, ...inp }} />} />
          <K k="verified" v={
            <button onClick={() => setVerified(!verified)} style={verified ? { padding: "4px 10px", borderRadius: 6, border: "1px solid var(--line-strong)", background: "var(--green)", color: "#fff" } : { padding: "4px 10px", borderRadius: 6, border: "1px solid var(--line-strong)", background: "var(--bg)", color: "var(--text)" }}>
              {verified ? "VERIFIED" : "UNVERIFIED"}
            </button>
          } />
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <button className="btn" onClick={computeState}>Compute state</button>
          </div>
          {stateHealth && (
            <div style={{ marginTop: 12 }}>
              <K k="display status" v={stateHealth.display_status?.toUpperCase()} tone={stateHealth.display_status === "healthy" ? "green" : "red"} />
              <K k="verification" v={stateHealth.verification} />
              <K k="freshness" v={stateHealth.freshness} />
              <K k="confidence" v={`${(stateConf?.score ?? 0).toFixed(3)} (${stateConf?.tier ?? "unknown"})`} />
            </div>
          )}
        </Panel>

        {/* Finding dedup + chain */}
        <Panel title="Finding deduplication & risk chain" sub="Spec #21/#22 — uses findings and asset context returned by the live scanners" style={{ flex: "1 1 380px", minWidth: 380 }}>
          <textarea value={findJson} onChange={(e) => setFindJson(e.target.value)} rows={8} placeholder="Paste the JSON findings payload from an authorized scanner" style={{ width: "100%", ...inp, resize: "vertical" }} />
          <div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap" }}>
            <input value={riskAssetId} onChange={(e) => setRiskAssetId(e.target.value)} placeholder="live asset ID for risk chain" style={{ ...inp, flex: "1 1 180px" }} />
            <input value={riskBusinessValue} onChange={(e) => setRiskBusinessValue(e.target.value)} placeholder="business value (optional)" style={{ ...inp, flex: "1 1 150px" }} />
            <label style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12 }}>
              <input type="checkbox" checked={riskCritical} onChange={(e) => setRiskCritical(e.target.checked)} /> critical asset
            </label>
          </div>
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <button className="btn" onClick={correlate}>Deduplicate</button>
            <button className="btn" onClick={chainIt}>Build risk chain</button>
          </div>
          {dedup && (
            <div style={{ marginTop: 12 }}>
              <K k="inputs" v={String(dedup.inputs)} />
              <K k="deduplicated" v={String(dedup.count)} tone="green" />
              <K k="deduped_by" v={String(dedup.deduped_by)} />
            </div>
          )}
          {chain && (
            <div style={{ marginTop: 10 }}>
              <K k="overall severity" v={chain.overall_severity.toUpperCase()} tone={chain.overall_severity === "critical" ? "red" : "orange"} />
              <K k="compound risk" v={String(chain.compound_risk)} tone={chain.compound_risk ? "red" : "green"} />
            </div>
          )}
        </Panel>

        {/* Scan triggers */}
        <Panel title="Scan triggers & scheduling" sub="Spec #10/#11/#12 — cadence, event mapping, incremental safety" style={{ flex: "1 1 380px", minWidth: 380 }}>
          <K k="cadence" v={
            <select value={cadence} onChange={(e) => setCadence(e.target.value)} style={inp}>
              {["on_change", "on_demand", "every_5_minutes", "hourly", "daily", "weekly",
                "after_deployment", "after_certificate_change", "after_cloud_change"].map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          } />
          <K k="change event" v={
            <select value={event} onChange={(e) => setEvent(e.target.value)} style={inp}>
              {["asset.created", "asset.changed", "certificate.changed", "certificate.expiring",
                "firmware.changed", "cloud.resource_changed", "application.deployed"].map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          } />
          <div className="row" style={{ gap: 10, marginTop: 10 }}>
            <button className="btn" onClick={computeSched}>Resolve schedule</button>
          </div>
          {sched && (
            <div style={{ marginTop: 12 }}>
              <K k="kind" v={schedObj?.kind ?? "—"} />
              <K k="interval" v={schedObj?.interval_s ? `${schedObj.interval_s}s` : "event-driven"} />
              <K k="event → scans" v={(scansForEvent ?? []).join(", ") || "—"} />
              {Boolean(sched?.incremental) && (
                <K k="incremental" v={String((sched?.incremental as { incremental: boolean }).incremental)} tone={(sched?.incremental as { incremental: boolean }).incremental ? "green" : "red"} />
              )}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
