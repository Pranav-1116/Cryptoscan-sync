import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  apiOnboardingState, apiCreateOrg, apiAddEnv, apiAddScope,
  apiAddConnection, apiTestConnection, apiStartDiscovery, apiListSectors,
  type OnboardingState, type DiscoveryPlan, type SectorProfile,
} from "../lib/api.js";
import { Corners, Kicker } from "../components/ui.jsx";

/* Enterprise onboarding wizard — the customer journey:
   1 Create organization · 2 Select sector · 3 Create environment
   4 Authorized scope · 5 Connect infrastructure · 6 Test access · 7 Start discovery.
   The sector changes context only (the universal engine does all scanning).
   Connectors store NON-SECRET references — read-only access is granted
   out-of-band; no key material is ever collected or stored. */

const STEPS = [
  "Organization", "Sector", "Environment", "Authorized scope",
  "Connect infrastructure", "Test access", "Start discovery",
];

const card: React.CSSProperties = {
  position: "relative", background: "var(--panel)", border: "1px solid var(--line)",
  borderRadius: 16, padding: 24,
};
const field: React.CSSProperties = {
  width: "100%", padding: "10px 12px", borderRadius: 10, border: "1px solid var(--line-strong)",
  background: "rgba(0,0,0,.25)", color: "var(--fg)", fontSize: 13, fontFamily: "var(--mono)",
};
const label: React.CSSProperties = { fontSize: 11, color: "var(--dim)", textTransform: "uppercase", letterSpacing: ".08em", marginBottom: 6, display: "block" };
const btn: React.CSSProperties = {
  padding: "10px 18px", borderRadius: 10, border: "1px solid var(--cyan)", background: "rgba(34,211,238,.12)",
  color: "var(--cyan)", fontSize: 13, cursor: "pointer", fontFamily: "var(--mono)",
};
const btnGhost: React.CSSProperties = { ...btn, border: "1px solid var(--line-strong)", background: "transparent", color: "var(--dim)" };
const chip: React.CSSProperties = {
  fontFamily: "var(--mono)", fontSize: 10.5, padding: "3px 9px", borderRadius: 6,
  border: "1px solid var(--line-strong)", color: "var(--dim)",
};
const okChip: React.CSSProperties = { ...chip, color: "#34d399", border: "1px solid rgba(52,211,153,.5)", background: "rgba(52,211,153,.08)" };
const badChip: React.CSSProperties = { ...chip, color: "#f87171", border: "1px solid rgba(248,113,113,.5)", background: "rgba(248,113,113,.08)" };
const warnChip: React.CSSProperties = { ...chip, color: "#fbbf24", border: "1px solid rgba(251,191,36,.5)", background: "rgba(251,191,36,.08)" };

const SECTORS_FALLBACK = ["banking", "healthcare", "government", "energy", "manufacturing", "retail", "technology", "telecom", "generic"];

const ENV_TYPES = ["production", "staging", "development", "ot", "cloud", "air_gapped"];
const SCAN_MODES = ["discovery", "standard", "deep", "passive", "continuous", "targeted", "compliance", "pqc"];
const CONNECTORS = [
  { kind: "aws", label: "AWS", method: "iam_role", refs: [["role_arn", "IAM role ARN (read-only)"], ["account", "Account ID / alias"]] },
  { kind: "azure", label: "Azure", method: "service_principal", refs: [["tenant_id", "Tenant ID"], ["subscription_id", "Subscription ID"], ["service_principal", "Service principal (app ID)"]] },
  { kind: "gcp", label: "GCP", method: "service_account", refs: [["project_id", "Project ID"], ["service_account", "Service account email"]] },
  { kind: "kubernetes", label: "Kubernetes", method: "api", refs: [["api_server", "API server URL"], ["cluster", "Cluster name"]] },
  { kind: "git", label: "Git / source", method: "api", refs: [["repo_url", "Repository URL"], ["org", "Organization"]] },
  { kind: "network", label: "Network device", method: "snmp", refs: [["host", "Host / endpoint"], ["cidr", "Authorized CIDR"]] },
  { kind: "vmware", label: "VMware", method: "api", refs: [["vcenter", "vCenter host"], ["host", "Host"]] },
  { kind: "hardware", label: "Hardware", method: "agent", refs: [["host", "Host"], ["asset", "Asset tag"]] },
  { kind: "hsm", label: "HSM", method: "api", refs: [["host", "HSM host"], ["partition_ref", "Partition reference"]] },
  { kind: "siem", label: "SIEM", method: "syslog", refs: [["endpoint", "Endpoint URL"], ["host", "Host"]] },
];

function Btn({ children, onClick, disabled, ghost, busy }: { children: React.ReactNode; onClick?: () => void; disabled?: boolean; ghost?: boolean; busy?: boolean }) {
  return (
    <button style={{ ...(ghost ? btnGhost : btn), opacity: disabled || busy ? 0.5 : 1, cursor: disabled || busy ? "wait" : "pointer" }}
      disabled={disabled} onClick={onClick}>
      {busy ? "…" : children}
    </button>
  );
}

export default function Onboarding() {
  const [state, setState] = useState<OnboardingState | null>(null);
  const [sectors, setSectors] = useState<SectorProfile[]>([]);
  const [step, setStep] = useState(0);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [plan, setPlan] = useState<DiscoveryPlan | null>(null);
  const [roles, setRoles] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    const r = await apiOnboardingState();
    if (r.data) {
      setState(r.data);
      if (r.data.organization?.onboarding_complete) setStep(6);
    }
    return r;
  }, []);

  useEffect(() => {
    try { setRoles(JSON.parse(localStorage.getItem("zelinx_roles") || "[]")); } catch { /* ignore */ }
    void refresh();
    void apiListSectors().then((r) => { if (r.data?.sectors) setSectors(r.data.sectors); });
  }, [refresh]);

  const canWrite = roles.some((r) => ["superadmin", "admin", "ciso", "security_analyst"].includes(r));
  const sectorIds = useMemo(() => (sectors.length ? sectors.map((s) => s.id) : SECTORS_FALLBACK), [sectors]);

  const done = (key: string) => !!state?.checklist.find((c) => c.step === key)?.done;
  const connectedCount = state?.connected_count ?? 0;

  const flash = (ok: boolean, text: string) => { setMsg({ ok, text }); window.setTimeout(() => setMsg(null), 5000); };

  return (
    <div style={{ padding: "26px 28px", maxWidth: 1080, margin: "0 auto" }}>
      <div className="frame" style={card}>
        <Corners />
        <Kicker>Enterprise setup · universal engine</Kicker>
        <h1 style={{ fontSize: 24, margin: "8px 0 6px" }}>Onboarding</h1>
        <p className="dim" style={{ fontSize: 13, margin: 0, lineHeight: 1.6 }}>
          Connect your estate to the single scanning engine. You authorize explicit scope and grant
          <b> read-only / least-privilege</b> access out-of-band — the platform never asks for or stores secrets.
          Your sector configures <b>policy packs, criticality and compliance</b>, not a separate scanner.
        </p>
        {/* stepper */}
        <div style={{ display: "flex", gap: 6, marginTop: 18, flexWrap: "wrap" }}>
          {STEPS.map((s, i) => {
            const stepKey = ["organization", "sector", "environment", "scope", "connections", "connections", "discovery"][i];
            const isDone = i === 6 ? (state?.organization?.onboarding_complete ?? false) : done(stepKey) || (i === 5 && connectedCount > 0);
            const active = i === step;
            return (
              <button key={s} onClick={() => setStep(i)} style={{
                display: "flex", alignItems: "center", gap: 7, padding: "7px 12px", borderRadius: 10, cursor: "pointer",
                border: `1px solid ${active ? "var(--cyan)" : "var(--line)"}`,
                background: active ? "rgba(34,211,238,.1)" : "transparent",
                color: isDone ? "#34d399" : active ? "var(--cyan)" : "var(--dim)", fontSize: 12, fontFamily: "var(--mono)",
              }}>
                <span>{isDone ? "✓" : i + 1}</span>{s}
              </button>
            );
          })}
        </div>
        {msg && (
          <div style={{ marginTop: 14, padding: "10px 14px", borderRadius: 10, fontSize: 12.5, fontFamily: "var(--mono)",
            border: `1px solid ${msg.ok ? "rgba(52,211,153,.5)" : "rgba(248,113,113,.5)"}`,
            color: msg.ok ? "#34d399" : "#f87171", background: msg.ok ? "rgba(52,211,153,.06)" : "rgba(248,113,113,.06)" }}>
            {msg.ok ? "✓ " : "✕ "}{msg.text}
          </div>
        )}
        {!canWrite && state && (
          <div style={{ ...warnChip, marginTop: 12, display: "inline-block" }}>view-only role — changes require admin / ciso / security_analyst</div>
        )}
      </div>

      {step === 0 && <OrgStep state={state} sectors={sectorIds} canWrite={canWrite} busy={busy} setBusy={setBusy} refresh={refresh} flash={flash} onNext={() => setStep(1)} />}
      {step === 1 && <SectorStep state={state} sectors={sectors} />}
      {step === 2 && <EnvStep state={state} canWrite={canWrite} busy={busy} setBusy={setBusy} refresh={refresh} flash={flash} />}
      {step === 3 && <ScopeStep state={state} canWrite={canWrite} busy={busy} setBusy={setBusy} refresh={refresh} flash={flash} />}
      {step === 4 && <ConnectStep state={state} canWrite={canWrite} busy={busy} setBusy={setBusy} refresh={refresh} flash={flash} />}
      {step === 5 && <TestStep state={state} canWrite={canWrite} busy={busy} setBusy={setBusy} refresh={refresh} flash={flash} onNext={() => setStep(6)} />}
      {step === 6 && <DiscoveryStep state={state} plan={plan} setPlan={setPlan} busy={busy} setBusy={setBusy} flash={flash} />}
    </div>
  );
}

/* ---- shared section wrapper ---- */
function Section({ title, hint, children, actions }: { title: string; hint?: string; children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="frame" style={{ ...card, marginTop: 18 }}>
      <Corners />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
        <div>
          <Kicker>{title}</Kicker>
          {hint && <p className="dim" style={{ fontSize: 12.5, margin: "8px 0 0", lineHeight: 1.6, maxWidth: 720 }}>{hint}</p>}
        </div>
        {actions}
      </div>
      <div style={{ marginTop: 18 }}>{children}</div>
    </div>
  );
}

/* ---- step 1: organization ---- */
function OrgStep({ state, sectors, canWrite, busy, setBusy, refresh, flash, onNext }: {
  state: OnboardingState | null; sectors: string[]; canWrite: boolean; busy: string | null;
  setBusy: (b: string | null) => void; refresh: () => Promise<unknown>; flash: (ok: boolean, t: string) => void; onNext: () => void;
}) {
  const [name, setName] = useState("");
  const [sector, setSector] = useState("banking");
  const [industry, setIndustry] = useState("");
  const existing = state?.organization;

  const submit = async () => {
    if (!name.trim()) return flash(false, "Organization name is required");
    setBusy("org");
    const r = await apiCreateOrg(name.trim(), sector, industry.trim() || undefined);
    setBusy(null);
    if (r.source === "live" && r.data) { await refresh(); flash(true, "Organization created"); onNext(); }
    else flash(false, r.error || "could not create organization (is the backend live?)");
  };

  return (
    <Section title="Step 1 · Create organization" hint="The root entity for all environments, scope, connections and findings.">
      {existing ? (
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span style={okChip}>✓ {existing.name}</span>
          <span style={chip}>sector: {existing.sector}</span>
          {existing.industry && <span style={chip}>{existing.industry}</span>}
          <Btn ghost onClick={onNext}>Continue to sector →</Btn>
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div><label style={label}>Organization name</label>
            <input style={field} value={name} placeholder="Acme Bank PLC" onChange={(e) => setName(e.target.value)} /></div>
          <div><label style={label}>Industry (optional)</label>
            <input style={field} value={industry} placeholder="Financial services" onChange={(e) => setIndustry(e.target.value)} /></div>
          <div><label style={label}>Sector profile</label>
            <select style={field} value={sector} onChange={(e) => setSector(e.target.value)}>
              {sectors.map((s) => <option key={s} value={s}>{s}</option>)}
            </select></div>
          <div style={{ display: "flex", alignItems: "flex-end" }}>
            <Btn busy={busy === "org"} disabled={!canWrite} onClick={submit}>Create organization</Btn>
          </div>
        </div>
      )}
    </Section>
  );
}

/* ---- step 2: sector context ---- */
function SectorStep({ state, sectors }: { state: OnboardingState | null; sectors: SectorProfile[] }) {
  const ctx = state?.sector_context;
  const prof = sectors.find((s) => s.id === ctx?.sector);
  if (!state?.organization) return <Section title="Step 2 · Sector profile"><p className="dim">Create an organization first.</p></Section>;
  return (
    <Section title="Step 2 · Select sector" hint="The sector never forks the scanner. It changes context: which assets are critical, which policy packs and compliance frameworks apply, how criticality is weighted, and which scan modes are recommended.">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
        <span style={{ ...chip, color: "var(--cyan)", border: "1px solid var(--cyan)" }}>active: {ctx?.sector}</span>
        {(ctx?.recommended_modes ?? (prof?.recommended_modes ?? []).map((m) => m.id) ?? []).map((m: string) => <span key={m} style={chip}>mode: {m}</span>)}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div>
          <label style={label}>Policy packs applied</label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {(ctx?.policy_packs ?? prof?.policy_packs ?? []).map((p) => <span key={p} style={okChip}>{p}</span>)}
            {!(ctx?.policy_packs ?? prof?.policy_packs)?.length && <span className="dim" style={{ fontSize: 12 }}>default packs</span>}
          </div>
        </div>
        <div>
          <label style={label}>Compliance frameworks</label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {(ctx?.compliance_frameworks ?? prof?.compliance_frameworks ?? []).map((p) => <span key={p} style={chip}>{p}</span>)}
          </div>
        </div>
      </div>
      {(prof?.critical_asset_classes?.length || prof?.scanning_notes?.length) ? (
        <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {prof?.critical_asset_classes?.length ? (
            <div><label style={label}>Critical asset classes</label>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>{prof.critical_asset_classes.map((a: string) => <span key={a} style={warnChip}>{a}</span>)}</div></div>
          ) : null}
          {prof?.scanning_notes?.length ? (
            <div><label style={label}>Scanning guidance</label>
              <ul className="dim" style={{ fontSize: 12.5, margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
                {prof.scanning_notes.map((n) => <li key={n}>{n}</li>)}
              </ul></div>
          ) : null}
        </div>
      ) : null}
    </Section>
  );
}

/* ---- step 3: environment ---- */
function EnvStep({ state, canWrite, busy, setBusy, refresh, flash }: {
  state: OnboardingState | null; canWrite: boolean; busy: string | null; setBusy: (b: string | null) => void;
  refresh: () => Promise<unknown>; flash: (ok: boolean, t: string) => void;
}) {
  const [name, setName] = useState("");
  const [envType, setEnvType] = useState("production");
  const [scanMode, setScanMode] = useState("standard");
  const isOt = envType === "ot";

  const submit = async () => {
    if (!name.trim()) return flash(false, "Environment name is required");
    setBusy("env");
    const r = await apiAddEnv({
      name: name.trim(), env_type: envType,
      scan_mode: isOt ? "passive" : scanMode, active_probing: !isOt,
    });
    setBusy(null);
    if (r.source === "live" && r.data) { setName(""); await refresh(); flash(true, `Environment created${isOt ? " — OT forces passive mode" : ""}`); }
    else flash(false, r.error || "could not create environment");
  };

  return (
    <Section title="Step 3 · Create environment" hint="Environments group scope and set the scanning posture. Operational (OT/ICS) environments are forced to passive/no active probing — safety first.">
      {isOt && <div style={{ ...warnChip, marginBottom: 14, display: "inline-block" }}>⚠ OT/ICS environment — active probing disabled, passive-only scanning; maintenance windows are respected</div>}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr auto", gap: 14, alignItems: "flex-end" }}>
        <div><label style={label}>Name</label><input style={field} value={name} placeholder="Production" onChange={(e) => setName(e.target.value)} /></div>
        <div><label style={label}>Type</label>
          <select style={field} value={envType} onChange={(e) => setEnvType(e.target.value)}>
            {ENV_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select></div>
        <div><label style={label}>Scan mode</label>
          <select style={field} value={isOt ? "passive" : scanMode} disabled={isOt} onChange={(e) => setScanMode(e.target.value)}>
            {SCAN_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
          </select></div>
        <Btn busy={busy === "env"} disabled={!canWrite} onClick={submit}>Add environment</Btn>
      </div>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 18 }}>
        {(state?.environments ?? []).map((e) => (
          <span key={e.id} style={e.env_type === "ot" ? warnChip : okChip}>
            {e.name} · {e.env_type} · {e.scan_mode}{e.env_type === "ot" ? " · no active probing" : ""}
          </span>
        ))}
        {!state?.environments?.length && <span className="dim" style={{ fontSize: 12 }}>No environments yet.</span>}
      </div>
    </Section>
  );
}

/* ---- step 4: authorized scope ---- */
function ScopeStep({ state, canWrite, busy, setBusy, refresh, flash }: {
  state: OnboardingState | null; canWrite: boolean; busy: string | null; setBusy: (b: string | null) => void;
  refresh: () => Promise<unknown>; flash: (ok: boolean, t: string) => void;
}) {
  const [kind, setKind] = useState("network");
  const [target, setTarget] = useState("");
  const hints: Record<string, string> = {
    network: "CIDR (10.10.0.0/16), IP range, domain, or 'vlan:..' / 'snmp:..' reference",
    cloud: "AWS account ID/ARN, Azure subscription, or GCP project",
    application: "Repository URL, app name, container registry, API, or Kubernetes namespace",
    hardware: "Server, HSM, TPM device, network appliance (host or asset tag)",
  };
  const submit = async () => {
    if (!target.trim()) return flash(false, "Scope target is required");
    setBusy("scope");
    const r = await apiAddScope(kind, target.trim());
    setBusy(null);
    if (r.source === "live" && r.data) { setTarget(""); await refresh(); flash(true, "Scope added"); }
    else flash(false, r.error || "could not add scope (check the target format)");
  };
  const counts = state?.scope?.counts ?? {};
  return (
    <Section title="Step 4 · Authorized scope" hint="The scanner only ever operates inside explicitly authorized targets. Nothing is scanned unless it is in scope.">
      <div style={{ display: "grid", gridTemplateColumns: "180px 1fr auto", gap: 14, alignItems: "flex-end" }}>
        <div><label style={label}>Domain</label>
          <select style={field} value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="network">Network</option><option value="cloud">Cloud</option>
            <option value="application">Application</option><option value="hardware">Hardware</option>
          </select></div>
        <div><label style={label}>Target</label>
          <input style={field} value={target} placeholder={hints[kind]} onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()} /></div>
        <Btn busy={busy === "scope"} disabled={!canWrite} onClick={submit}>Add to scope</Btn>
      </div>
      <p className="dim" style={{ fontSize: 11.5, margin: "10px 0 0" }}>{hints[kind]}</p>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 16 }}>
        {Object.entries(counts).map(([k, n]) => <span key={k} style={n ? okChip : chip}>{k}: {n}</span>)}
        <span style={{ ...chip, color: "var(--cyan)" }}>total authorized: {state?.scope?.total ?? 0}</span>
      </div>
    </Section>
  );
}

/* ---- step 5: connections center ---- */
function ConnectStep({ state, canWrite, busy, setBusy, refresh, flash }: {
  state: OnboardingState | null; canWrite: boolean; busy: string | null; setBusy: (b: string | null) => void;
  refresh: () => Promise<unknown>; flash: (ok: boolean, t: string) => void;
}) {
  const [kind, setKind] = useState("aws");
  const [name, setName] = useState("");
  const [cfg, setCfg] = useState<Record<string, string>>({});
  const connDef = CONNECTORS.find((c) => c.kind === kind)!;
  const setKindAndReset = (k: string) => { setKind(k); setCfg({}); };
  const submit = async () => {
    if (!name.trim()) return flash(false, "Connection name is required");
    setBusy("conn");
    const r = await apiAddConnection({ kind, name: name.trim(), method: connDef.method, config: cfg });
    setBusy(null);
    if (r.source === "live" && r.data) { setName(""); setCfg({}); await refresh(); flash(true, "Connection configured — now test access"); }
    else flash(false, r.error || "could not create connection");
  };
  return (
    <Section title="Step 5 · Connect infrastructure" hint="Connections Center — register how the engine reaches each domain. Provide NON-SECRET references only (role ARN, project, repo URL, host). Grant read-only access out-of-band; key material is never collected.">
      <div style={{ ...okChip, display: "inline-block", marginBottom: 16 }}>
        ✓ No secret fields — enter references like IAM role ARN or project ID. Grant read-only access out-of-band.
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: 14 }}>
        <div><label style={label}>Connector</label>
          <select style={field} value={kind} onChange={(e) => setKindAndReset(e.target.value)}>
            {CONNECTORS.map((c) => <option key={c.kind} value={c.kind}>{c.label}</option>)}
          </select></div>
        <div><label style={label}>Connection name</label>
          <input style={field} value={name} placeholder={`${connDef.label} read-only`} onChange={(e) => setName(e.target.value)} /></div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 14 }}>
        {connDef.refs.map(([key, ph]) => (
          <div key={key}><label style={label}>{key} <span className="dim">(reference, not a secret)</span></label>
            <input style={field} value={cfg[key] || ""} placeholder={ph}
              onChange={(e) => setCfg({ ...cfg, [key]: e.target.value })} /></div>
        ))}
      </div>
      <div style={{ marginTop: 14 }}><Btn busy={busy === "conn"} disabled={!canWrite} onClick={submit}>Register connection</Btn></div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 12, marginTop: 20 }}>
        {(state?.connections ?? []).map((c) => (
          <div key={c.id} style={{ border: "1px solid var(--line)", borderRadius: 12, padding: 14, background: "rgba(0,0,0,.2)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <b style={{ fontSize: 13 }}>{c.name}</b>
              <span style={c.status === "connected" ? okChip : c.status === "error" ? badChip : chip}>{c.status}</span>
            </div>
            <div className="dim" style={{ fontSize: 11.5, marginTop: 4, fontFamily: "var(--mono)" }}>{c.kind} · {c.method}</div>
          </div>
        ))}
      </div>
    </Section>
  );
}

/* ---- step 6: test access ---- */
function TestStep({ state, canWrite, busy, setBusy, refresh, flash, onNext }: {
  state: OnboardingState | null; canWrite: boolean; busy: string | null; setBusy: (b: string | null) => void;
  refresh: () => Promise<unknown>; flash: (ok: boolean, t: string) => void; onNext: () => void;
}) {
  const test = async (id: string) => {
    setBusy(id);
    const r = await apiTestConnection(id);
    setBusy(null);
    if (r.source === "live" && r.data) {
      await refresh();
      flash(r.data.all_ok, r.data.all_ok ? "All pre-scan checks passed" : "Some checks failed — review below");
    } else flash(false, r.error || "test failed");
  };
  const testAll = async () => {
    for (const c of state?.connections ?? []) { if (c.status !== "connected") await test(c.id); }
  };
  const conns = state?.connections ?? [];
  return (
    <Section title="Step 6 · Test access" hint="Pre-scan gate — each connection must pass connectivity, credential model, scope and agent-health checks before discovery is allowed. Checks are safe and non-intrusive."
      actions={<Btn busy={busy === "all"} disabled={!canWrite || !conns.length} onClick={testAll}>Test all</Btn>}>
      {!conns.length && <p className="dim" style={{ fontSize: 12.5 }}>Register a connection in the previous step first.</p>}
      <div style={{ display: "grid", gap: 12 }}>
        {conns.map((c) => {
          const checks = c.test_result?.checks ?? [];
          return (
            <div key={c.id} style={{ border: "1px solid var(--line)", borderRadius: 12, padding: 14, background: "rgba(0,0,0,.2)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: checks.length ? 10 : 0 }}>
                <b style={{ fontSize: 13 }}>{c.name} <span className="dim" style={{ fontFamily: "var(--mono)", fontSize: 11 }}>· {c.kind}</span></b>
                <Btn ghost busy={busy === c.id} disabled={!canWrite} onClick={() => test(c.id)}>
                  {c.status === "connected" ? "Re-test" : "Run checks"}
                </Btn>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {checks.map((chk) => (
                  <span key={chk.check} style={chk.ok ? okChip : badChip} title={chk.detail}>
                    {chk.ok ? "✓" : "✕"} {chk.check}
                  </span>
                ))}
                {!checks.length && <span className="dim" style={{ fontSize: 12 }}>Not tested yet.</span>}
              </div>
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 18, display: "flex", justifyContent: "flex-end" }}>
        <Btn disabled={!state?.ready} onClick={onNext}>Continue to discovery →</Btn>
      </div>
    </Section>
  );
}

/* ---- step 7: start discovery ---- */
function DiscoveryStep({ state, plan, setPlan, busy, setBusy, flash }: {
  state: OnboardingState | null; plan: DiscoveryPlan | null;
  setPlan: (p: DiscoveryPlan | null) => void; busy: string | null; setBusy: (b: string | null) => void;
  flash: (ok: boolean, t: string) => void;
}) {
  const otEnv = (state?.environments ?? []).some((e) => e.env_type === "ot");
  const start = async () => {
    setBusy("disc");
    const r = await apiStartDiscovery();
    setBusy(null);
    if (r.source === "live" && r.data) { setPlan(r.data); flash(true, "Initial discovery started across authorized scope"); }
    else flash(false, r.error || "discovery blocked — complete environments, scope and a tested connection");
  };
  return (
    <Section title="Step 7 · Start discovery" hint="The universal engine then takes over: asset identification → specialized scans auto-selected by asset type → evidence fusion → CBOM/HBOM → dependency graph → sector policy → risk → PQC, followed by 24/7 event-driven monitoring.">
      {otEnv && <div style={{ ...warnChip, marginBottom: 14, display: "inline-block" }}>⚠ OT estate present — network/hardware domains will use passive discovery</div>}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 18 }}>
        <span style={state?.environments?.length ? okChip : badChip}>{state?.environments?.length ? "✓" : "✕"} {state?.environments?.length ?? 0} environment(s)</span>
        <span style={(state?.scope?.total ?? 0) > 0 ? okChip : badChip}>{(state?.scope?.total ?? 0) > 0 ? "✓" : "✕"} {state?.scope?.total ?? 0} authorized target(s)</span>
        <span style={(state?.connected_count ?? 0) > 0 ? okChip : badChip}>{(state?.connected_count ?? 0) > 0 ? "✓" : "✕"} {state?.connected_count ?? 0} connected connector(s)</span>
      </div>
      {!plan ? (
        <Btn busy={busy === "disc"} disabled={!state?.ready} onClick={start}>
          {state?.ready ? "Start initial discovery" : "Complete the previous steps to enable discovery"}
        </Btn>
      ) : (
        <div>
          <div style={{ ...okChip, display: "inline-block", marginBottom: 14 }}>✓ Discovery run {plan.run_id.slice(0, 8)} planned over {plan.connectors_used.join(", ")}</div>
          <label style={label}>Domain plan (auto-derived from scope)</label>
          <div style={{ display: "grid", gap: 8 }}>
            {plan.plan.map((d) => (
              <div key={d.domain} style={{ display: "flex", justifyContent: "space-between", border: "1px solid var(--line)", borderRadius: 10, padding: "10px 14px", background: "rgba(0,0,0,.2)" }}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>{d.domain}</span>
                <span className="dim" style={{ fontFamily: "var(--mono)", fontSize: 12 }}>targets: {d.targets} · mode: {d.mode}</span>
              </div>
            ))}
          </div>
          <label style={{ ...label, marginTop: 16 }}>Then the engine proceeds automatically</label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {plan.next_steps.map((s) => <span key={s} style={chip}>{s}</span>)}
          </div>
        </div>
      )}
    </Section>
  );
}
