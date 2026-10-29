import React, { useEffect, useState, useMemo } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconComponent, IconTarget, IconClock, IconSecurity, IconHardware, IconInfo } from "../components/icons";
import { apiSecurityPolicyGet, apiSecurityPolicyPut, SecurityPolicy as SecurityPolicyData } from "../lib/api";

const row: React.CSSProperties = { display: "grid", gridTemplateColumns: "260px 1fr auto", gap: 14, alignItems: "center", padding: "9px 0", borderBottom: "1px solid var(--line)" };
const label: React.CSSProperties = { fontSize: 13 };
const hint: React.CSSProperties = { fontSize: 11, color: "var(--dim)", maxWidth: 420 };

function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button type="button" onClick={() => onChange(!on)} style={{ width: 44, height: 24, borderRadius: 999, border: "1px solid var(--line-strong)", background: on ? "var(--green)" : "var(--line)", position: "relative", cursor: "pointer" }}>
      <span style={{ position: "absolute", top: 2, left: on ? 22 : 2, width: 18, height: 18, borderRadius: "50%", background: "var(--panel)", transition: "left .12s", boxShadow: "0 1px 4px rgba(0,0,0,.25)" }} />
    </button>
  );
}
function Num({ v, onChange, min = 0, max = 1e6 }: { v: number; onChange: (n: number) => void; min?: number; max?: number }) {
  return <input type="number" value={v} min={min} max={max} onChange={(e) => onChange(Math.max(min, Math.min(max, Number(e.target.value) || 0)))} style={{ width: 96, padding: "5px 8px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--bg)", color: "var(--text)", fontSize: 13 }} />;
}
function Seg({ options, value, onChange }: { options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div style={{ display: "inline-flex", gap: 4 }}>
      {options.map((o) => (
        <button key={o} onClick={() => onChange(o)} style={{ padding: "5px 12px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: value === o ? "var(--violet)" : "var(--bg)", color: value === o ? "#fff" : "var(--text)", cursor: "pointer", fontSize: 12, fontWeight: value === o ? 700 : 500 }}>{o}</button>
      ))}
    </div>
  );
}
const EMPTY: SecurityPolicyData = {
  scan: { mode: "read-only", intensity: "low", max_concurrent_jobs: 20, max_targets_per_scan: 200, max_connections: 50, rate_limit_qps: 5, rate_limit_per_minute: 300, scan_timeout_seconds: 300, retry_limit: 2, production_protection: true, hsm_protection: true, require_special_approval: true, maintenance_window_start: "22:00", maintenance_window_end: "05:00" },
  privacy: { collect_pii: false, collect_private_keys: false, collect_secrets: false, redact_secrets: true, mask_sensitive_fields: true, tokenize_identifiers: true, enforce_payload_limits: true, max_payload_bytes: 65536, retention_days: 90, data_minimization: true, alert_on_private_key: true, allow_evidence_metadata: true },
};

export default function SecurityPolicy() {
  const [policy, setPolicy] = useState<SecurityPolicyData>(EMPTY);
  const [sector, setSector] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [policyLive, setPolicyLive] = useState<boolean | null>(null);
  const [policyReadError, setPolicyReadError] = useState<string | null>(null);
  const setScan = (k: string, v: unknown) => setPolicy((p) => ({ ...p, scan: { ...p.scan, [k]: v } }));
  const setPriv = (k: string, v: unknown) => setPolicy((p) => ({ ...p, privacy: { ...p.privacy, [k]: v } }));

  useEffect(() => {
    let alive = true;
    (async () => {
      const r = await apiSecurityPolicyGet();
      if (!alive) return;
      if (r.source === "live" && r.data?.policy) {
        setPolicy({ scan: { ...EMPTY.scan, ...r.data.policy.scan }, privacy: { ...EMPTY.privacy, ...r.data.policy.privacy } });
        if (r.data.sector) setSector(r.data.sector);
        setPolicyLive(true);
        setPolicyReadError(null);
      } else {
        // The stored policy was not read. The form still shows the platform's
        // documented conservative defaults, and must say so — otherwise these
        // look like this deployment's configured state.
        setPolicyLive(false);
        setPolicyReadError(r.detail || r.error || "no policy returned");
      }
      setLoading(false);
    })();
    return () => { alive = false; };
  }, []);
  const save = async () => {
    setSaving(true); setError(null); setSaved(null);
    const r = await apiSecurityPolicyPut(policy); setSaving(false);
    if (r.ok && r.data) { setSaved(r.data.policy?.scan?.mode ?? "updated"); setPolicy({ scan: { ...policy.scan, ...(r.data.policy?.scan ?? {}) }, privacy: { ...policy.privacy, ...(r.data.policy?.privacy ?? {}) } }); if (r.data.sector) setSector(r.data.sector); }
    else setError(r.error ?? "save failed");
  };

  const intensityPct = ({ off: 0.1, low: 0.35, medium: 0.65, high: 0.95 } as any)[policy.scan.intensity] ?? 0.35;
  const intensityTone = policy.scan.intensity === "high" ? "red" as const : policy.scan.intensity === "medium" ? "amber" as const : "green" as const;
  const productionOn = !!policy.scan.production_protection;
  const hsmOn = !!policy.scan.hsm_protection;
  const privacyStrict = !policy.privacy.collect_pii && !policy.privacy.collect_private_keys && !policy.privacy.collect_secrets && !!policy.privacy.redact_secrets;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {policyLive === false && (
        <div role="alert" style={{ marginBottom: 14, padding: "10px 14px", borderRadius: "var(--r)", border: "1px solid var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", fontSize: 12.5, color: "var(--amber)", display: "flex", gap: 8, flexWrap: "wrap" }}>
          <b>Policy not read from the control plane</b>
          <span style={{ color: "var(--dim)" }}>— the values below are the platform's documented conservative defaults, not this deployment's stored policy ({policyReadError}). Saving writes them.</span>
        </div>
      )}

      {/* Hero */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid var(--violet)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} /> GOVERNANCE · SCANNING POLICY · PRIVACY ENGINE
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconSecurity size={18} /></span>
            Security & Scanning Policy
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 660 }}>
            Company-administrator controls — <b style={{ color: "var(--text)" }}>what may be scanned, how aggressively, and what may be retained</b>. Three engines kept separate: <span style={{ color: "var(--violet)" }}>Scanner / Policy / Privacy</span>. Every change is signed to the scanner gate.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>READ-ONLY DEFAULT · HSM-GATED · 4-LAYER RATE LIMIT</span>
            {sector && <Badge tone="violet">SECTOR · {sector}</Badge>}
          </div>
          {sector && <div style={{ marginTop: 8, fontSize: 11, color: "var(--dim)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "6px 10px" }}>Policy is loaded from the live <b>{sector}</b> sector profile (read-only, conservative intensity, sensitive-data collection off) and can never be looser than it.</div>}
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 170, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={intensityPct} label={policy.scan.intensity.toUpperCase()} sub="intensity" tone={intensityTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>SCAN POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 145, lineHeight: 1.4 }}>{String(policy.scan.mode)} · ≤{policy.scan.max_concurrent_jobs} jobs · {policy.scan.rate_limit_per_minute}/min</div>
              <div style={{ marginTop: 6 }}><Bar value={intensityPct} tone={intensityTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button className="btn btn-primary" disabled={saving || loading} onClick={save} style={{ background: "var(--violet)", borderColor: "var(--violet)", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>{saving ? "Saving…" : "Save policy"}</button>
            {saved && <Badge tone="green">saved · {saved}</Badge>}
            {error && <Badge tone="red">{error}</Badge>}
            {!saved && !error && <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{loading ? "loading…" : "SIGNED TO GATE §21"}</span>}
          </div>
        </div>
      </div>

      {/* KPI strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${policy.scan.mode === "read-only" ? "var(--green)" : "var(--amber)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SCAN MODE</div><div style={{ fontSize: 16, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{String(policy.scan.mode).replace("_", " " )}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{policy.scan.mode === "read-only" ? "Non-intrusive by default" : "Active probes require approval"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: policy.scan.mode === "read-only" ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `1px solid ${policy.scan.mode === "read-only" ? "var(--green)" : "var(--amber)"}`, color: policy.scan.mode === "read-only" ? "var(--green)" : "var(--amber)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={policy.scan.mode === "read-only" ? 0.45 : 0.85} tone={policy.scan.mode === "read-only" ? "green" : "amber"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Scanner gate enforces floor</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid var(--${intensityTone})` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>NETWORK INTENSITY</div><div style={{ fontSize: 20, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{String(policy.scan.intensity).toUpperCase()}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{policy.scan.rate_limit_qps} qps · {policy.scan.max_connections} conns</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: `color-mix(in srgb, var(--${intensityTone}) 14%, transparent)`, border: `1px solid var(--${intensityTone})`, color: `var(--${intensityTone})` }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={intensityPct} tone={intensityTone} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Higher = more concurrent probes</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${productionOn && hsmOn ? "var(--green)" : "var(--red)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PRODUCTION + HSM SHIELD</div><div style={{ fontSize: 13, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{productionOn && hsmOn ? "PROTECTED" : !productionOn && !hsmOn ? "UNSHIELDED" : "PARTIAL"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>prod {productionOn ? "low" : "full"} · HSM {hsmOn ? "approval" : "full"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: productionOn && hsmOn ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--red) 14%, transparent)", border: `1px solid ${productionOn && hsmOn ? "var(--green)" : "var(--red)"}`, color: productionOn && hsmOn ? "var(--green)" : "var(--red)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={productionOn && hsmOn ? 1 : productionOn || hsmOn ? 0.5 : 0.2} tone={productionOn && hsmOn ? "green" : productionOn || hsmOn ? "amber" : "red"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Special approval required: {policy.scan.require_special_approval ? "yes" : "no"}</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${privacyStrict ? "var(--green)" : "var(--amber)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PRIVACY POSTURE</div><div style={{ fontSize: 13, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{privacyStrict ? "MINIMAL COLLECTION" : "PERMISSIVE"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>retain {policy.privacy.retention_days}d · cap {policy.privacy.max_payload_bytes}B</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: privacyStrict ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `1px solid ${privacyStrict ? "var(--green)" : "var(--amber)"}`, color: privacyStrict ? "var(--green)" : "var(--amber)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={privacyStrict ? 0.9 : 0.4} tone={privacyStrict ? "green" : "amber"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Redaction {policy.privacy.redact_secrets ? "on" : "off"} · masking {policy.privacy.mask_sensitive_fields ? "on" : "off"}</div></div>
        </div>
      </div>

      <Panel title="Scanning policy" sub="the POLICY engine — what am I allowed to scan, and how aggressively?">
        <div className="row" style={{ gap: 28, flexWrap: "wrap", marginBottom: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "12px 14px" }}>
          <div><div className="kicker">mode</div><div style={{ marginTop: 6 }}><Seg options={["read-only", "controlled_active"]} value={policy.scan.mode} onChange={(v) => setScan("mode", v)} /></div></div>
          <div style={{ width: 1, background: "var(--line)", alignSelf: "stretch" }} />
          <div><div className="kicker">network intensity</div><div style={{ marginTop: 6 }}><Seg options={["off", "low", "medium", "high"]} value={policy.scan.intensity} onChange={(v) => setScan("intensity", v)} /></div></div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "var(--faint)" }}><span style={{ width: 8, height: 8, borderRadius: 99, background: `var(--${intensityTone})` }} /> {Math.round(intensityPct*100)}% intensity budget</div>
        </div>
        <div style={row}><div style={hint}>Cloud API rate — requests/minute<div style={{ fontSize: 13, color: "var(--text)", marginTop: 2 }}>Cloud API rate</div></div><Num v={policy.scan.rate_limit_per_minute} onChange={(v) => setScan("rate_limit_per_minute", v)} /></div>
        <div style={row}><div>Max concurrent jobs</div><Num v={policy.scan.max_concurrent_jobs} onChange={(v) => setScan("max_concurrent_jobs", v)} /></div>
        <div style={row}><div>Max targets / scan</div><Num v={policy.scan.max_targets_per_scan} onChange={(v) => setScan("max_targets_per_scan", v)} /></div>
        <div style={row}><div>Max connections</div><Num v={policy.scan.max_connections} onChange={(v) => setScan("max_connections", v)} /></div>
        <div style={row}><div>Scan timeout (s)</div><Num v={policy.scan.scan_timeout_seconds} onChange={(v) => setScan("scan_timeout_seconds", v)} /></div>
        <div style={row}><div>Maintenance window</div><div style={{ display: "flex", gap: 6, alignItems: "center" }}><input value={policy.scan.maintenance_window_start} onChange={(e) => setScan("maintenance_window_start", e.target.value)} style={inp} /><span className="dim">→</span><input value={policy.scan.maintenance_window_end} onChange={(e) => setScan("maintenance_window_end", e.target.value)} style={inp} /></div></div>
        {( [ ["production_protection", "Production protection", "production scope is read-only + low intensity"], ["hsm_protection", "HSM protection", "HSMs require a special approval policy"], ["require_special_approval", "Special approval required", "HSM / production-db targets need explicit approval"], ] as [string,string,string][] ).map(([k,t,h]) => (
          <div key={k} style={row}><div>{t}<div style={hint}>{h}</div></div><Toggle on={policy.scan[k as keyof typeof policy.scan] as boolean} onChange={(v) => setScan(k, v)} /></div>
        ))}
      </Panel>

      <Panel title="Rate limiting — 4 layers" sub="per-layer budgets so scanning can never become a denial-of-service source (§15–§18)">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14, marginBottom: 12 }}>
          <div style={{ padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: "3px solid var(--cyan)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--cyan)" }}>LAYER 1 · USER / API</div><div style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>per-minute request budget<div style={hint}>Layer 1 · user / API · per-minute request budget</div></div>
            <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8 }}><Num v={policy.scan.rate_limit_per_minute} onChange={(v) => setScan("rate_limit_per_minute", v)} /><span style={{ fontSize: 11, color: "var(--faint)" }}>/min</span></div>
          </div>
          <div style={{ padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: "3px solid var(--violet)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--violet)" }}>LAYER 2 · SCANNER</div><div style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>requests/sec · concurrency · connections</div>
            <div style={{ marginTop: 8, display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}><Num v={policy.scan.rate_limit_qps} onChange={(v) => setScan("rate_limit_qps", v)} /><span className="dim">·</span><Num v={policy.scan.max_concurrent_jobs} onChange={(v) => setScan("max_concurrent_jobs", v)} /><span className="dim">·</span><Num v={policy.scan.max_connections} onChange={(v) => setScan("max_connections", v)} /></div>
          </div>
          <div style={{ padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: "3px solid var(--amber)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--amber)" }}>LAYER 3 · TARGET SAFETY</div><div style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>production gets 50%, HSM 10% of scanner budget</div>
            <div style={{ fontSize: 12, color: productionOn ? "var(--green)" : "var(--red)", marginTop: 6, fontWeight: 600 }}>production={productionOn ? "low" : "full"}, HSM={hsmOn ? "low" : "full"}</div>
          </div>
          <div style={{ padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: "3px solid var(--slate)" }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--slate)" }}>LAYER 4 · TENANT / INFRA</div><div style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>active scans, env concurrency, workers</div>
            <div className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>evaluated live per request via the scanner gate</div>
          </div>
        </div>
      </Panel>

      <Panel title="Privacy policy" sub="the PRIVACY engine — what am I allowed to store, expose, and retain? (§13)">
        {( [ ["collect_pii", "PII collection", "collect personal data"], ["collect_private_keys", "Private-key collection", "copy private key material"], ["collect_secrets", "Secret collection", "store credential/secret values"], ] as [string,string,string][] ).map(([k,t,h]) => (
          <div key={k} style={{ ...row, background: (policy.privacy[k as keyof typeof policy.privacy] as boolean) ? "color-mix(in srgb, var(--red) 6%, transparent)" : undefined, borderRadius: "var(--r)", paddingLeft: 8, paddingRight: 8 }}><div>{t}<div style={hint}>{h}</div></div><Toggle on={policy.privacy[k as keyof typeof policy.privacy] as boolean} onChange={(v) => setPriv(k, v)} /></div>
        ))}
        {( [ ["redact_secrets", "Sensitive-data redaction", "detected secrets are dropped, not stored"], ["mask_sensitive_fields", "Field masking", "mask emails / cards / SSN / names"], ["tokenize_identifiers", "Identifier tokenization", "asset / hostname ids stored as tokens"], ["data_minimization", "Data minimization", "store only the field allowlist per observation"], ["enforce_payload_limits", "Payload limits", "truncate over-size observation values"], ["alert_on_private_key", "Private-key alert", "alert when a private key is detected"], ["allow_evidence_metadata", "Evidence metadata", "store hash/source, not content"], ] as [string,string,string][] ).map(([k,t,h]) => (
          <div key={k} style={row}><div>{t}<div style={hint}>{h}</div></div><Toggle on={policy.privacy[k as keyof typeof policy.privacy] as boolean} onChange={(v) => setPriv(k, v)} /></div>
        ))}
        <div style={row}><div>Max payload bytes<div style={hint}>per-observation cap</div></div><Num v={policy.privacy.max_payload_bytes} onChange={(v) => setPriv("max_payload_bytes", v)} /></div>
        <div style={row}><div>Retention (days)</div><Num v={policy.privacy.retention_days} onChange={(v) => setPriv("retention_days", v)} /></div>
      </Panel>

      <div className="row" style={{ gap: 12, marginTop: 14, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 14px" }}>
        <button className="btn btn-primary" disabled={saving || loading} onClick={save} style={{ background: "var(--violet)", borderColor: "var(--violet)" }}>{saving ? "Saving…" : "Save policy"}</button>
        {saved && <Badge tone="green">saved · mode {saved}</Badge>}
        {error && <Badge tone="red">{error}</Badge>}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--faint)" }}>Every change is persisted as a normalized policy and reflected in the scanner gate</span>
      </div>
    </div>
  );
}

const inp: React.CSSProperties = { width: 84, padding: "4px 8px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--bg)", color: "var(--text)", fontSize: 13 };
