import React, { useEffect, useState } from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import {
  apiSecurityPolicyGet, apiSecurityPolicyPut,
  SecurityPolicy as SecurityPolicyData,
} from "../lib/api.js";

/* Security & Scanning Policy (§25) — the company-administrator controls screen.
   Three concepts kept separate (spec §27): Scanner (what it can see), Policy
   engine (what it may scan / how aggressively) and Privacy engine (what it may
   store / expose / retain). Every change is persisted as a normalized policy
   and reflected in the scanner gate. */

const row: React.CSSProperties = {
  display: "grid", gridTemplateColumns: "260px 1fr auto", gap: 14,
  alignItems: "center", padding: "9px 0", borderBottom: "1px solid var(--line)",
};
const label: React.CSSProperties = { fontSize: 13 };
const hint: React.CSSProperties = { fontSize: 11.5, color: "var(--muted)", maxWidth: 420 };

function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button type="button" onClick={() => onChange(!on)} style={{
      width: 44, height: 24, borderRadius: 12, border: "1px solid var(--line-strong)",
      background: on ? "var(--green)" : "var(--line)", position: "relative", cursor: "pointer",
    }}>
      <span style={{
        position: "absolute", top: 2, left: on ? 22 : 2, width: 18, height: 18,
        borderRadius: "50%", background: "#fff", transition: "left .12s",
      }} />
    </button>
  );
}

function Num({ v, onChange, min = 0, max = 1e6 }: { v: number; onChange: (n: number) => void; min?: number; max?: number }) {
  return (
    <input type="number" value={v} min={min} max={max}
      onChange={(e) => onChange(Math.max(min, Math.min(max, Number(e.target.value) || 0)))}
      style={{ width: 96, padding: "4px 8px", borderRadius: 6, border: "1px solid var(--line-strong)",
        background: "var(--bg)", color: "var(--text)", fontSize: 13 }} />
  );
}

function Seg({ options, value, onChange }: { options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div style={{ display: "inline-flex", gap: 4 }}>
      {options.map((o) => (
        <button key={o} onClick={() => onChange(o)} style={{
          padding: "4px 12px", borderRadius: 6, border: "1px solid var(--line-strong)",
          background: value === o ? "var(--accent)" : "var(--bg)",
          color: value === o ? "#fff" : "var(--text)", cursor: "pointer", fontSize: 12.5,
        }}>{o}</button>
      ))}
    </div>
  );
}

const EMPTY: SecurityPolicyData = {
  scan: {
    mode: "read-only", intensity: "low", max_concurrent_jobs: 20, max_targets_per_scan: 200,
    max_connections: 50, rate_limit_qps: 5, rate_limit_per_minute: 300, scan_timeout_seconds: 300,
    retry_limit: 2, production_protection: true, hsm_protection: true, require_special_approval: true,
    maintenance_window_start: "22:00", maintenance_window_end: "05:00",
  },
  privacy: {
    collect_pii: false, collect_private_keys: false, collect_secrets: false,
    redact_secrets: true, mask_sensitive_fields: true, tokenize_identifiers: true,
    enforce_payload_limits: true, max_payload_bytes: 65536, retention_days: 90,
    data_minimization: true, alert_on_private_key: true, allow_evidence_metadata: true,
  },
};

export default function SecurityPolicy() {
  const [policy, setPolicy] = useState<SecurityPolicyData>(EMPTY);
  const [policyRaw, setPolicyRaw] = useState<SecurityPolicyData | null>(null);
  const [sector, setSector] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const setScan = (k: string, v: unknown) => setPolicy((p) => ({ ...p, scan: { ...p.scan, [k]: v } }));
  const setPriv = (k: string, v: unknown) => setPolicy((p) => ({ ...p, privacy: { ...p.privacy, [k]: v } }));

  useEffect(() => {
    (async () => {
      const r = await apiSecurityPolicyGet();
      if (r.data?.policy) { setPolicy({ scan: { ...EMPTY.scan, ...r.data.policy.scan }, privacy: { ...EMPTY.privacy, ...r.data.policy.privacy } }); setPolicyRaw(r.data.policy); }
      if (r.data?.sector) setSector(r.data.sector);
      setLoading(false);
    })();
  }, []);

  const save = async () => {
    setSaving(true); setError(null); setSaved(null);
    const r = await apiSecurityPolicyPut(policy);
    setSaving(false);
    if (r.ok && r.data) { setSaved(r.data.policy?.scan?.mode ?? "updated"); setPolicy({ scan: { ...policy.scan, ...(r.data.policy?.scan ?? {}) }, privacy: { ...policy.privacy, ...(r.data.policy?.privacy ?? {}) } }); if (r.data.sector) setSector(r.data.sector); }
    else setError(r.error ?? "save failed");
  };

  return (
    <>
      <PageHead
        crumb="security / scanning policy"
        title="Security & Scanning policy"
        sub="Company-administrator controls — what may be scanned, how aggressively, and what may be retained. Signed to the scanner gate (§21)."
        right={loading ? <Badge>loading…</Badge> : <Badge tone="green">POLICY ACTIVE</Badge>}
      />

      {sector && (
        <div style={{ marginBottom: 14, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span className="badge" style={{ background: "var(--accent-2, #123)", color: "#fff" }}>SECTOR · {sector}</span>
          <span className="dim" style={{ fontSize: 12.5 }}>
            Policy is loaded from the live <b>{sector}</b> sector profile (read-only, conservative intensity, sensitive-data collection off) and can never be looser than it.
          </span>
        </div>
      )}

      <Panel title="Scanning policy" sub="the POLICY engine — what am I allowed to scan, and how aggressively?">
        <div className="row" style={{ gap: 40, flexWrap: "wrap", marginBottom: 8 }}>
          <div>
            <div className="kicker">mode</div>
            <Seg options={["read-only", "controlled_active"]} value={policy.scan.mode} onChange={(v) => setScan("mode", v)} />
          </div>
          <div>
            <div className="kicker">network intensity</div>
            <Seg options={["off", "low", "medium", "high"]} value={policy.scan.intensity} onChange={(v) => setScan("intensity", v)} />
          </div>
        </div>
        <div style={row}>
          <div>Cloud API rate <div style={hint}>requests/minute</div></div>
          <Num v={policy.scan.rate_limit_per_minute} onChange={(v) => setScan("rate_limit_per_minute", v)} />
        </div>
        <div style={row}>
          <div>Max concurrent jobs</div>
          <Num v={policy.scan.max_concurrent_jobs} onChange={(v) => setScan("max_concurrent_jobs", v)} />
        </div>
        <div style={row}>
          <div>Max targets / scan</div>
          <Num v={policy.scan.max_targets_per_scan} onChange={(v) => setScan("max_targets_per_scan", v)} />
        </div>
        <div style={row}>
          <div>Max connections</div>
          <Num v={policy.scan.max_connections} onChange={(v) => setScan("max_connections", v)} />
        </div>
        <div style={row}>
          <div>Scan timeout (s)</div>
          <Num v={policy.scan.scan_timeout_seconds} onChange={(v) => setScan("scan_timeout_seconds", v)} />
        </div>
        <div style={row}>
          <div>Maintenance window</div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input value={policy.scan.maintenance_window_start} onChange={(e) => setScan("maintenance_window_start", e.target.value)} style={inp} />
            <span className="dim">→</span>
            <input value={policy.scan.maintenance_window_end} onChange={(e) => setScan("maintenance_window_end", e.target.value)} style={inp} />
          </div>
        </div>
        {( [
          ["production_protection", "Production protection", "production scope is read-only + low intensity"],
          ["hsm_protection", "HSM protection", "HSMs require a special approval policy"],
          ["require_special_approval", "Special approval required", "HSM / production-db targets need explicit approval"],
        ] as [string, string, string][] ).map(([k, t, h]) => (
          <div key={k} style={row}>
            <div>{t}<div style={hint}>{h}</div></div>
            <Toggle on={policy.scan[k as keyof typeof policy.scan] as boolean} onChange={(v) => setScan(k, v)} />
          </div>
        ))}
      </Panel>

      <Panel title="Rate limiting (4 layers)" sub="per-layer budgets so scanning can never become a denial-of-service source (§15–§18)">
        <div style={row}>
          <div>Layer 1 · user / API<div style={hint}>per-minute request budget</div></div>
          <Num v={policy.scan.rate_limit_per_minute} onChange={(v) => setScan("rate_limit_per_minute", v)} />
        </div>
        <div style={row}>
          <div>Layer 2 · scanner<div style={hint}>requests/second, concurrency, connections</div></div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Num v={policy.scan.rate_limit_qps} onChange={(v) => setScan("rate_limit_qps", v)} />
            <span className="dim">·</span>
            <Num v={policy.scan.max_concurrent_jobs} onChange={(v) => setScan("max_concurrent_jobs", v)} />
            <span className="dim">·</span>
            <Num v={policy.scan.max_connections} onChange={(v) => setScan("max_connections", v)} />
          </div>
        </div>
        <div style={row}>
          <div>Layer 3 · target safety<div style={hint}>production gets 50%, HSM 10% of scanner budget</div></div>
          <div className="dim" style={{ fontSize: 12.5 }}>
            production={policy.scan.production_protection ? "low" : "full"}, HSM={policy.scan.hsm_protection ? "low" : "full"}
          </div>
        </div>
        <div style={row}>
          <div>Layer 4 · tenant / infra<div style={hint}>active scans, env concurrency, workers — enforced by the gate</div></div>
          <div className="dim" style={{ fontSize: 12.5 }}>evaluated live per request via the scanner gate</div>
        </div>
      </Panel>

      <Panel title="Privacy policy" sub="the PRIVACY engine — what am I allowed to store, expose, and retain? (§13)">
        {( [
          ["collect_pii", "PII collection", "collect personal data", false],
          ["collect_private_keys", "Private-key collection", "copy private key material", false],
          ["collect_secrets", "Secret collection", "store credential/secret values", false],
        ] as [string, string, string, boolean][] ).map(([k, t, h]) => (
          <div key={k} style={row}>
            <div>{t}<div style={hint}>{h}</div></div>
            <Toggle on={policy.privacy[k as keyof typeof policy.privacy] as boolean} onChange={(v) => setPriv(k, v)} />
          </div>
        ))}
        {( [
          ["redact_secrets", "Sensitive-data redaction", "detected secrets are dropped, not stored"],
          ["mask_sensitive_fields", "Field masking", "mask emails / cards / SSN / names"],
          ["tokenize_identifiers", "Identifier tokenization", "asset / hostname ids stored as tokens"],
          ["data_minimization", "Data minimization", "store only the field allowlist per observation"],
          ["enforce_payload_limits", "Payload limits", "truncate over-size observation values"],
          ["alert_on_private_key", "Private-key alert", "alert when a private key is detected"],
          ["allow_evidence_metadata", "Evidence metadata", "store hash/source, not content"],
        ] as [string, string, string][] ).map(([k, t, h]) => (
          <div key={k} style={row}>
            <div>{t}<div style={hint}>{h}</div></div>
            <Toggle on={policy.privacy[k as keyof typeof policy.privacy] as boolean} onChange={(v) => setPriv(k, v)} />
          </div>
        ))}
        <div style={row}>
          <div>Max payload bytes<div style={hint}>per-observation cap</div></div>
          <Num v={policy.privacy.max_payload_bytes} onChange={(v) => setPriv("max_payload_bytes", v)} />
        </div>
        <div style={row}>
          <div>Retention (days)</div>
          <Num v={policy.privacy.retention_days} onChange={(v) => setPriv("retention_days", v)} />
        </div>
      </Panel>

      <div className="row" style={{ gap: 12, marginTop: 14 }}>
        <button className="btn btn-primary" disabled={saving || loading} onClick={save}>
          {saving ? "Saving…" : "Save policy"}
        </button>
        {saved && <Badge tone="green">saved · mode {saved}</Badge>}
        {error && <Badge tone="red">{error}</Badge>}
      </div>

    </>
  );
}

const inp: React.CSSProperties = {
  width: 84, padding: "4px 8px", borderRadius: 6, border: "1px solid var(--line-strong)",
  background: "var(--bg)", color: "var(--text)", fontSize: 13,
};
