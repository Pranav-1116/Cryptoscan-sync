import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import {
  apiIntegrations, apiDeliveries, apiTestIntegration, apiFlushDeliveries, apiRegisterIntegration,
  apiVaultCredentials, apiVaultCredentialCreate, apiVaultCredentialLease,
  apiVaultLeaseRelease, apiVaultCredentialRotate, apiVaultLeases,
  LiveBadge,
} from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { StatusMark } from "../components/icons";

const CRED_KINDS = ["cloud", "network_device", "hsm", "database", "kubernetes", "git", "siem", "api", "other"];

// Integration kind is a type, not a status: cmdb was amber ("warning")
// and soar green ("pass") purely to tell four connectors apart.
const KIND_TONE: Record<string, string> = { siem: "cyan", itsm: "violet", cmdb: "slate", soar: "slate" };

function statusTone(status: string): "green" | "red" | "amber" | "cyan" {
  if (status === "delivered" || status === "resolved") return "green";
  if (status === "failed") return "red";
  return "amber";
}

function VaultPanel() {
  const creds = usePollingApi(apiVaultCredentials, 12000);
  const leases = usePollingApi(apiVaultLeases, 12000);
  useRealtimeRefresh(creds.run, leases.run);
  const [f, setF] = useState({ name: "", kind: "cloud", vault_provider: "aws_secretsmanager", secret_ref: "", least_privilege_scope: "", rotation_policy_days: 90 });
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const set = (k: string, v: string | number) => setF((p) => ({ ...p, [k]: v }));
  const input: React.CSSProperties = { flex: 1, minWidth: 130, background: "color-mix(in srgb, var(--bg) 80%, transparent)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5, padding: "7px 11px" };

  const credentialList = (creds.data as any)?.credentials ?? [];
  const leaseList = (leases.data as any)?.leases ?? [];
  const activeLeases = leaseList.filter((l: any) => l.status === "ACTIVE" && !l.expired);

  const register = async () => {
    if (!f.name.trim() || !f.secret_ref.trim()) { setMsg({ ok: false, text: "name and a vault reference (ARN/URI/name) are required" }); return; }
    setBusy("reg");
    const r = await apiVaultCredentialCreate({
      name: f.name.trim(), kind: f.kind, vault_provider: f.vault_provider, secret_ref: f.secret_ref.trim(),
      ...(f.least_privilege_scope.trim() ? { least_privilege_scope: f.least_privilege_scope.trim() } : {}),
      rotation_policy_days: Number(f.rotation_policy_days) || 90,
    });
    setBusy(null);
    if (r.ok) { setMsg({ ok: true, text: `registered ${f.name} — reference only, no secret stored` }); setF({ ...f, name: "", secret_ref: "", least_privilege_scope: "" }); void creds.run(); }
    else setMsg({ ok: false, text: r.error ?? "rejected (inline secret material is fail-closed)" });
  };

  const lease = async (id: string) => {
    setBusy(`lease-${id}`);
    const r = await apiVaultCredentialLease(id, { component: "scanner", ttl_seconds: 900 });
    setBusy(null);
    if (r.ok) { setMsg({ ok: true, text: `lease ${(r.data?.lease?.handle ?? "").slice(0, 16)}… issued · secret resolved out-of-band, never returned` }); void leases.run(); }
    else setMsg({ ok: false, text: r.error ?? "lease denied by policy" });
  };

  const release = async (handle: string) => {
    const r = await apiVaultLeaseRelease(handle);
    if (r.ok) { setMsg({ ok: true, text: `lease ${handle.slice(0, 16)}… released` }); void leases.run(); }
    else setMsg({ ok: false, text: r.error ?? "release failed" });
  };

  const rotate = async (id: string) => {
    setBusy(`rot-${id}`);
    const r = await apiVaultCredentialRotate(id);
    setBusy(null);
    if (r.ok) { setMsg({ ok: true, text: "rotation recorded (rotate the secret in the external vault)" }); void creds.run(); }
    else setMsg({ ok: false, text: r.error ?? "rotate failed" });
  };

  return (
    <Panel title="Credential vault" sub="vault-reference only — secrets never enter the platform; short-lived leases with deterministic policy gates" className="mt">
      <div className="row" style={{ flexWrap: "wrap", gap: 8, marginBottom: 10 }}>
        <input style={input} placeholder="credential name" value={f.name} onChange={(e) => set("name", e.target.value)} />
        <select style={{ ...input, minWidth: 130 }} value={f.kind} onChange={(e) => set("kind", e.target.value)}>
          {CRED_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
        </select>
        <select style={{ ...input, minWidth: 150 }} value={f.vault_provider} onChange={(e) => set("vault_provider", e.target.value)}>
          {["aws_secretsmanager", "azure_keyvault", "gcp_secretmanager", "hashicorp_vault", "hsm", "manual_out_of_band"].map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <input style={{ ...input, minWidth: 220 }} placeholder="vault reference (ARN/URI/name) — never the secret" value={f.secret_ref} onChange={(e) => set("secret_ref", e.target.value)} />
        <input style={input} placeholder="least-privilege scope (e.g. cloud:read)" value={f.least_privilege_scope} onChange={(e) => set("least_privilege_scope", e.target.value)} />
        <button className="btn primary" onClick={() => void register()} disabled={busy === "reg"}>{busy === "reg" ? "Registering…" : "Register reference"}</button>
      </div>
      {msg && <div style={{ marginBottom: 10 }}><Badge tone={msg.ok ? "green" : "red"}>{msg.ok ? <StatusMark ok muted /> : null}{msg.text}</Badge></div>}

      <Table
        head={["credential", "kind", "vault", "health", "rotation due", "actions"]}
        rows={credentialList.map((c: any) => [
          <span style={{ fontWeight: 600 }} key="n">{c.name}</span>,
          <Badge key="k" tone="cyan">{c.kind}</Badge>,
          <span className="mono" key="v" style={{ fontSize: 11.5 }}>{c.vault_provider}</span>,
          <Badge key="h" tone={c.health?.healthy ? "green" : "red"}>{c.health?.status ?? "—"}</Badge>,
          <Badge key="r" tone={c.health?.rotation_due ? "amber" : "green"}>{c.health?.rotation_due ? "due" : "fresh"}</Badge>,
          <span key="a" className="row" style={{ gap: 6 }}>
            <button className="btn sm" disabled={busy === `lease-${c.id}`} onClick={() => void lease(c.id)}>lease</button>
            <button className="btn sm" disabled={busy === `rot-${c.id}`} onClick={() => void rotate(c.id)}>{busy === `rot-${c.id}` ? "…" : "rotate"}</button>
          </span>,
        ])}
      />
      {credentialList.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No credentials registered. Provide only a non-secret vault locator; the platform rejects inline key material (fail-closed).</p>}

      {leaseList.length > 0 && (
        <>
          <h3 style={{ margin: "18px 0 8px", fontSize: 14 }}>Leases ({activeLeases.length} active)</h3>
          <Table
            head={["handle", "credential", "component", "scope", "ttl", "status", ""]}
            rows={leaseList.slice(0, 15).map((l: any) => [
              <span className="mono" key="h" style={{ fontSize: 11.5 }}>{String(l.handle ?? "").slice(0, 20)}…</span>,
              <span key="c">{l.credential_name}</span>,
              <span className="mono" key="p" style={{ fontSize: 12 }}>{l.component}</span>,
              <span className="mono" key="s" style={{ fontSize: 12 }}>{l.scope ?? "—"}</span>,
              <span className="num" key="t">{l.ttl_seconds}s</span>,
              <Badge key="st" tone={l.status === "ACTIVE" && !l.expired ? "green" : l.expired ? "amber" : ""}>{l.expired ? "EXPIRED" : l.status}</Badge>,
              l.status === "ACTIVE" && !l.expired
                ? <button key="x" className="btn sm" style={{ borderColor: "var(--red)", color: "var(--red)" }} onClick={() => void release(l.handle)}>release</button>
                : <span key="x" className="dim">—</span>,
            ])}
          />
        </>
      )}
    </Panel>
  );
}

export default function Integrations() {
  const ints = usePollingApi(apiIntegrations, 12000);
  const deliv = usePollingApi(apiDeliveries, 12000);
  useRealtimeRefresh(ints.run, deliv.run);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [form, setForm] = useState({ kind: "siem", provider: "", name: "", endpoint: "", credential_id: "" });
  const setField = (k: string, v: string) => setForm((p) => ({ ...p, [k]: v }));

  async function register() {
    if (!form.name.trim() || !form.provider.trim()) { setMsg({ ok: false, text: "name and provider are required" }); return; }
    setBusy("register");
    const r = await apiRegisterIntegration({
      kind: form.kind, provider: form.provider.trim(), name: form.name.trim(),
      ...(form.endpoint.trim() ? { endpoint: form.endpoint.trim() } : {}),
      ...(form.credential_id.trim() ? { credential_id: form.credential_id.trim() } : {}),
    });
    setBusy(null);
    if (r.source === "live" && r.data) {
      const id = (r.data as { integration_id?: string }).integration_id;
      setMsg({ ok: true, text: `registered ${form.name.trim()}${id ? ` · ${String(id).slice(0, 8)}…` : ""} — endpoint is non-secret, credentials resolve from the vault` });
      setForm({ kind: form.kind, provider: "", name: "", endpoint: "", credential_id: "" });
      void ints.run();
    } else {
      setMsg({ ok: false, text: `registration refused: ${r.detail || r.error || "request failed"}` });
    }
  }

  const liveInts = (ints.data?.integrations ?? []) as Array<Record<string, unknown>>;
  const deliveries = (deliv.data?.deliveries ?? []) as Array<Record<string, unknown>>;
  const stats = (deliv.data?.stats ?? {}) as Record<string, number>;
  const live = ints.source === "live";

  async function test(id: string) {
    setBusy(id);
    setMsg(null);
    const r = await apiTestIntegration(id);
    setBusy(null);
    if (r.ok) {
      setMsg({ ok: true, text: `Delivery test: ${r.status ?? "—"} (HTTP ${r.http_status ?? "—"})` });
      void deliv.run();
      void ints.run();
    } else {
      setMsg({ ok: false, text: `Test failed: ${r.error}` });
    }
  }

  async function flush() {
    setBusy("flush");
    const r = await apiFlushDeliveries(25);
    setBusy(null);
    setMsg(r.ok
      ? { ok: true, text: `Flushed ${r.events_flushed ?? 0} events · ${r.delivered ?? 0} delivered · ${r.failed ?? 0} failed` }
      : { ok: false, text: `Flush failed: ${r.error}` });
    void deliv.run();
  }

  const rows = live
    ? liveInts.map((i) => {
        const id = String(i.id);
        const lastSync = String(i.last_sync_status ?? "—");
        return [
          <span style={{ fontWeight: 600 }}>{String(i.name)}</span>,
          <Badge tone={KIND_TONE[String(i.kind)] || "cyan"}>{String(i.kind)}</Badge>,
          <Badge tone={statusTone(lastSync)}>{lastSync}</Badge>,
          <span style={{ fontSize: 12.5 }} className="dim">
            {i.endpoint ? String(i.endpoint) : "outbox only (air-gap)"}
          </span>,
          <button className="btn" style={{ padding: "4px 10px", fontSize: 12 }}
                  disabled={busy === id} onClick={() => void test(id)}>
            {busy === id ? "…" : "Test"}
          </button>,
        ];
      })
    : [];

  return (
    <>
      <PageHead
        crumb="operate / integrations"
        title="Integrations"
        sub="Real signed HTTP fan-out to SIEM / SOC, ticketing (ITSM) and CMDB — every attempt audited"
        right={
          <div className="row">
            <LiveBadge source={live ? "live" : "offline"} label={live ? "LIVE PLATFORM" : "BACKEND OFFLINE"} />
            {live && <Badge tone="violet"><span className="dot" /> {liveInts.length} REGISTERED</Badge>}
          </div>
        }
      />

      <Panel title="Connected systems" sub="SIEM / ITSM / CMDB / SOAR — endpoint URL is non-secret; credentials resolve from the vault at delivery time">
        <Table
          head={["integration", "kind", "last delivery", "endpoint", ""]}
          rows={rows}
        />
        {rows.length === 0 && (
          <div className="dim" style={{ fontSize: 13, marginTop: 12 }}>
            No integrations registered yet. Register a SIEM/SOC, ticketing (ITSM), CMDB or SOAR
            destination in the form below; the endpoint URL is non-secret and credentials are
            referenced from the vault, never stored.
          </div>
        )}
        {live && (
          <>
            <div className="row" style={{ marginTop: 12, gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "grid", gap: 3 }}>
                kind
                <select value={form.kind} onChange={(e) => setField("kind", e.target.value)} style={{ fontSize: 12, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--bg)", color: "var(--text)" }}>
                  {["siem", "itsm", "cmdb", "soar"].map((k) => <option key={k} value={k}>{k}</option>)}
                </select>
              </label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "grid", gap: 3 }}>
                provider
                <input value={form.provider} onChange={(e) => setField("provider", e.target.value)} placeholder="splunk / servicenow" style={{ fontSize: 12, padding: "6px 8px", minWidth: 150, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
              </label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "grid", gap: 3 }}>
                name
                <input value={form.name} onChange={(e) => setField("name", e.target.value)} placeholder="SIEM prod" style={{ fontSize: 12, padding: "6px 8px", minWidth: 140, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
              </label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "grid", gap: 3 }}>
                endpoint (https, non-secret)
                <input value={form.endpoint} onChange={(e) => setField("endpoint", e.target.value)} placeholder="https://siem.internal/ingest" style={{ fontSize: 12, padding: "6px 8px", minWidth: 230, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
              </label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "grid", gap: 3 }}>
                vault credential id (optional)
                <input value={form.credential_id} onChange={(e) => setField("credential_id", e.target.value)} placeholder="credential uuid" style={{ fontSize: 12, padding: "6px 8px", minWidth: 170, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
              </label>
              <button className="btn primary" disabled={busy === "register"} onClick={() => void register()}>
                {busy === "register" ? "Registering…" : "Register destination"}
              </button>
            </div>
            <div className="row" style={{ marginTop: 12, gap: 10 }}>
              <button className="btn" disabled={busy === "flush"} onClick={() => void flush()}>
                {busy === "flush" ? "Flushing…" : "Flush outbox now (real delivery)"}
              </button>
              {msg && <Badge tone={msg.ok ? "green" : "red"}>{msg.text}</Badge>}
            </div>
          </>
        )}
      </Panel>

      {live && (
        <Panel title="Outbound delivery log" sub="cp_delivery_logs — real HTTP POST results to external systems" className="mt">
          <div className="row" style={{ gap: 8, marginBottom: 12 }}>
            {(["delivered", "failed", "skipped"] as const).map((k) => (
              <Badge key={k} tone={stats[k] == null ? "slate" : k === "delivered" ? "green" : k === "failed" ? "red" : "amber"}>
                {stats[k] == null ? `${k.toUpperCase()} — NOT REPORTED` : `${stats[k]} ${k.toUpperCase()}`}
              </Badge>
            ))}
            {deliveries.length === 0 && <span className="dim" style={{ fontSize: 12 }}>no delivery attempts recorded yet</span>}
          </div>
          <Table
            head={["time", "provider", "kind", "event", "status", "HTTP", "attempts"]}
            rows={deliveries.slice(0, 20).map((d) => [
              <span className="mono faint" style={{ fontSize: 11.5 }}>{String(d.created_at ?? "").slice(11, 19)}</span>,
              <span style={{ fontWeight: 600 }}>{String(d.provider)}</span>,
              String(d.kind),
              <span className="mono" style={{ fontSize: 11.5 }}>{String(d.event_type)}</span>,
              <Badge tone={statusTone(String(d.status))}>{String(d.status)}</Badge>,
              d.http_status != null ? String(d.http_status) : <span className="faint">—</span>,
              String(d.attempts ?? 0),
            ])}
          />
        </Panel>
      )}

      {live && <VaultPanel />}
    </>
  );
}
