import React, { useCallback, useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Code, Tabs } from "../components/ui.jsx";
import { LiveBadge, ApiResult } from "../lib/api.js";
import {
  apiSsoStatus,
  apiScimUsers,
  apiScimCreateUser,
  apiScimDeactivate,
  apiScimSetActive,
  apiKeyRotationReport,
  apiUpdateKeyPolicy,
  apiWorkloadCa,
  apiWorkloadIssueSvid,
  apiWorkloadVerify,
  ScimList,
  RotationReport,
  Svid,
} from "../lib/api.js";

/* Identity & access administration — SAML 2.0 SSO, LDAP/AD, SCIM 2.0
   provisioning, API-key IP allowlist/rotation, and SPIFFE workload identity.
   Every panel is driven by the live backend; there is no demo dataset. When
   the backend is unreachable or the principal lacks rights, panels render
   empty with an explicit status. */

const ROLES = ["readonly", "auditor", "security_analyst", "developer",
  "business_owner", "ciso", "scanner", "supervisor", "superadmin"];

function useReload<T>(fn: () => Promise<ApiResult<T>>, deps: unknown[] = []) {
  const [res, setRes] = useState<ApiResult<T> | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(() => {
    setLoading(true);
    fn().then((r) => { setRes(r); setLoading(false); }).catch(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { res, loading, reload };
}

function State({ res, loading }: { res: ApiResult<unknown> | null; loading: boolean }) {
  if (loading) return <span className="faint">loading…</span>;
  if (res?.source === "live" && res.ok)
    return <LiveBadge source="live" label="LIVE" />;
  return <LiveBadge source="offline" label={res?.error ? `UNAVAILABLE · ${res.error}` : "BACKEND OFFLINE"} />;
}

/* ----------------------------- SSO / LDAP -------------------------------- */
function SsoPanel() {
  const { res, loading, reload } = useReload(apiSsoStatus);
  const d = res?.data;
  return (
    <Panel title="Single sign-on & directory" sub="SAML 2.0 (Okta / Entra / ADFS) and LDAP / Active Directory — configured server-side"
      className="mt">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <div className="row">
          <Badge tone={d?.saml_enabled ? "green" : ""}><span className="dot" /> SAML SSO {d?.saml_enabled ? "ENABLED" : "NOT CONFIGURED"}</Badge>
          <Badge tone={d?.ldap_enabled ? "green" : ""}><span className="dot" /> LDAP / AD {d?.ldap_enabled ? "ENABLED" : "NOT CONFIGURED"}</Badge>
        </div>
        <div className="row"><State res={res} loading={loading} />
          <button className="btn sm" onClick={() => reload()}>Refresh</button></div>
      </div>
      <Table
        head={["capability", "endpoint", "status"]}
        rows={[
          ["SAML metadata", <span className="mono">GET /auth/saml/metadata</span>, d ? <Badge tone={d.saml_enabled ? "green" : ""}>{d.saml_enabled ? "available" : "404 unconfigured"}</Badge> : "—"],
          ["SAML login (SP-initiated)", <span className="mono">GET /auth/saml/login</span>, d ? <Badge tone={d.saml_enabled ? "green" : ""}>{d.saml_enabled ? "ready" : "disabled"}</Badge> : "—"],
          ["SAML ACS (assertion consumer)", <span className="mono">POST /auth/saml/acs</span>, d ? <Badge tone={d.saml_enabled ? "green" : ""}>signed-assertion + CSRF check</Badge> : "—"],
          ["LDAP bind + group→role", <span className="mono">POST /auth/ldap/login</span>, d ? <Badge tone={d.ldap_enabled ? "green" : ""}>{d.ldap_enabled ? "ready" : "disabled"}</Badge> : "—"],
        ]}
      />
      <p className="faint" style={{ marginTop: 12, fontSize: 12 }}>
        Assertions are validated deterministically: enveloped XML signature (RS256), reference
        digest binding, issuer/audience/time-window checks, and strict InResponseTo correlation.
        Directory groups map to the 8-role RBAC catalog; unmapped users default to read-only.
      </p>
    </Panel>
  );
}

/* ----------------------------- SCIM users -------------------------------- */
function ScimPanel() {
  const { res, loading, reload } = useReload(apiScimUsers);
  const list = res?.data as ScimList | null | undefined;
  const [form, setForm] = useState({ userName: "", displayName: "", email: "", roles: "readonly" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const create = async () => {
    if (!form.userName.trim()) { setMsg("userName is required"); return; }
    setBusy(true); setMsg(null);
    const r = await apiScimCreateUser({
      userName: form.userName.trim(),
      displayName: form.displayName.trim() || undefined,
      email: form.email.trim() || undefined,
      roles: [form.roles],
    });
    setBusy(false);
    setMsg(r.ok ? `Provisioned ${form.userName}` : `Failed: ${r.error}`);
    if (r.ok) { setForm({ userName: "", displayName: "", email: "", roles: "readonly" }); reload(); }
  };
  const toggle = async (u: string, active: boolean) => {
    const r = active ? await apiScimSetActive(u, true) : await apiScimDeactivate(u);
    setMsg(r.ok ? `${active ? "Reactivated" : "Deprovisioned"} ${u}` : `Failed: ${r.error}`);
    reload();
  };

  const users = list?.Resources ?? [];
  return (
    <Panel title="SCIM 2.0 user provisioning" sub="Deterministic REST sync from the identity provider — deprovisioning soft-deactivates and preserves the audit chain" className="mt">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <div className="row"><Badge tone="green"><span className="dot" /> {list ? `${list.totalResults} provisioned` : "—"}</Badge>
          <State res={res} loading={loading} /></div>
        <button className="btn sm" onClick={() => reload()}>Refresh</button>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 14 }}>
        <input className="inp" placeholder="userName (login)" value={form.userName}
          onChange={(e) => setForm({ ...form, userName: e.target.value })} />
        <input className="inp" placeholder="display name" value={form.displayName}
          onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
        <input className="inp" placeholder="email" value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <div className="row">
          <select className="inp" value={form.roles} onChange={(e) => setForm({ ...form, roles: e.target.value })}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <button className="btn sm" onClick={() => void create()} disabled={busy}>{busy ? "…" : "Provision"}</button>
        </div>
      </div>
      {msg && <p className="faint" style={{ fontSize: 12, marginBottom: 8 }}>{msg}</p>}

      <Table
        head={["user", "name", "email", "roles", "status", ""]}
        rows={users.length ? users.map((u) => [
          <span className="mono" style={{ fontWeight: 600 }}>{u.userName}</span>,
          u.displayName || "—",
          u.emails?.[0]?.value || "—",
          <span className="mono">{(u.roles || []).map((r) => r.value).join(", ") || "readonly"}</span>,
          <Badge tone={u.active ? "green" : ""}>{u.active ? "active" : "deprovisioned"}</Badge>,
          <button className="btn sm" onClick={() => void toggle(u.userName, !u.active)}>
            {u.active ? "Deprovision" : "Reactivate"}
          </button>,
        ]) : [[<span className="faint">No provisioned users — when an IdP syncs (or you provision above), users appear here.</span>, "", "", "", "", ""]]}
      />
    </Panel>
  );
}

/* -------------------------- API-key rotation ----------------------------- */
function toneFor(state?: string): string {
  if (!state) return "";
  if (["REVOKED", "EXPIRED", "ROTATION_DUE"].includes(state)) return "red";
  if (["EXPIRING_SOON", "ROTATION_SOON"].includes(state)) return "amber";
  return "green";
}
function KeyPanel() {
  const { res, loading, reload } = useReload(apiKeyRotationReport);
  const rep = res?.data as RotationReport | null | undefined;
  const [sel, setSel] = useState<string | null>(null);
  const [ips, setIps] = useState("");
  const [days, setDays] = useState("90");
  const [msg, setMsg] = useState<string | null>(null);

  const counts = rep?.counts ?? {};
  const save = async (id: string) => {
    const allowed_ips = ips.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    const r = await apiUpdateKeyPolicy(id, {
      ...(allowed_ips.length ? { allowed_ips } : {}),
      rotate_after_days: Math.max(1, Math.min(3650, parseInt(days || "90", 10) || 90)),
    });
    setMsg(r.ok ? `Policy updated for ${id.slice(0, 12)}…` : `Failed: ${r.error}`);
    setSel(null); reload();
  };

  return (
    <Panel title="API-key IP allowlist & rotation" sub="Per-endpoint keys locked to client networks (CIDR/exact IP) with deterministic expiry-rotation reminders" className="mt">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <div className="row">
          <Badge tone="green"><span className="dot" /> {rep ? `${rep.total_active} active` : "—"}</Badge>
          {rep?.actionable ? <Badge tone="red"><span className="dot" /> {rep.actionable} need attention</Badge> : null}
          <State res={res} loading={loading} />
        </div>
        <button className="btn sm" onClick={() => reload()}>Refresh</button>
      </div>

      {Object.keys(counts).length > 0 && (
        <div className="grid" style={{ gridTemplateColumns: "repeat(6,1fr)", gap: 8, marginBottom: 14 }}>
          {Object.entries(counts).map(([state, n]) => (
            <div key={state} className="kpi" style={{ padding: 10 }}>
              <div className="num" style={{ fontSize: 22, color: `var(--${toneFor(state)})` }}>{n}</div>
              <div className="faint" style={{ fontSize: 10 }}>{state}</div>
            </div>
          ))}
        </div>
      )}
      {msg && <p className="faint" style={{ fontSize: 12 }}>{msg}</p>}

      <Table
        head={["key", "state", "ip allowlist", "rotate after", ""]}
        rows={rep?.keys?.length ? rep.keys.map((k) => [
          <span className="mono">{(k.key_prefix || (k.id || "").slice(0, 18)).toString()}</span>,
          <Badge tone={toneFor(k.state)}>{k.state || "OK"}</Badge>,
          <span className="mono">{(k.allowed_ips && k.allowed_ips.length) ? k.allowed_ips.join(", ") : "any (0.0.0.0/0)"}</span>,
          <span className="num">{k.rotate_after_days ?? 90} d</span>,
          <button className="btn sm" onClick={() => { setSel(sel === k.id ? null : k.id); setIps((k.allowed_ips || []).join(", ")); setDays(String(k.rotate_after_days ?? 90)); }}>
            {sel === k.id ? "Close" : "Policy"}
          </button>,
        ]) : [[<span className="faint">No active API keys.</span>, "", "", "", ""]]}
      />
      {sel && (
        <div className="grid mt" style={{ gridTemplateColumns: "2fr 1fr auto", gap: 8, alignItems: "center" }}>
          <input className="inp" placeholder="allowed IPs / CIDR, comma-separated (e.g. 203.0.113.7, 10.0.0.0/8)"
            value={ips} onChange={(e) => setIps(e.target.value)} />
          <input className="inp" type="number" min={1} max={3650} placeholder="rotate after days"
            value={days} onChange={(e) => setDays(e.target.value)} />
          <button className="btn sm" onClick={() => void save(sel)}>Save policy</button>
        </div>
      )}
      <p className="faint" style={{ marginTop: 12, fontSize: 12 }}>
        A request from a non-allowlisted address is rejected with 403 before any scope/quota check
        (fail-closed). Leave the list empty to allow any address.
      </p>
    </Panel>
  );
}

/* --------------------------- Workload identity --------------------------- */
function WorkloadPanel() {
  const ca = useReload(apiWorkloadCa);
  const [workload, setWorkload] = useState("scanner/edge-1");
  const [ttl, setTtl] = useState("60");
  const [svid, setSvid] = useState<Svid | null>(null);
  const [busy, setBusy] = useState(false);
  const [verify, setVerify] = useState<string | null>(null);

  const issue = async () => {
    setBusy(true); setVerify(null);
    const r = await apiWorkloadIssueSvid(workload.trim(), Math.max(5, Math.min(1440, parseInt(ttl || "60", 10) || 60)));
    setBusy(false);
    if (r.ok && r.data) {
      setSvid(r.data);
      const v = await apiWorkloadVerify(r.data.cert_pem, [workload.trim()]);
      setVerify(v.ok ? `Verified: ${v.data?.spiffe_id}` : `Verify failed: ${v.error}`);
    } else {
      setVerify(`Issue failed: ${r.error}`);
    }
  };

  return (
    <Panel title="Workload identity (SPIFFE / mTLS)" sub="Short-lived X.509 SVIDs carrying spiffe:// URI SANs for scanner↔API service-to-service auth" className="mt">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <div className="row">
          <Badge tone={ca.res?.data ? "green" : ""}><span className="dot" /> trust domain: {ca.res?.data?.trust_domain || "—"}</Badge>
          <State res={ca.res} loading={ca.loading} />
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "2fr 1fr auto", gap: 8, alignItems: "center", marginBottom: 12 }}>
        <input className="inp" placeholder="workload path (e.g. scanner/edge-1)" value={workload}
          onChange={(e) => setWorkload(e.target.value)} />
        <input className="inp" type="number" min={5} max={1440} placeholder="TTL minutes" value={ttl}
          onChange={(e) => setTtl(e.target.value)} />
        <button className="btn sm" onClick={() => void issue()} disabled={busy}>{busy ? "Issuing…" : "Issue SVID"}</button>
      </div>
      {verify && <p className="faint" style={{ fontSize: 12, marginBottom: 8 }}>{verify}</p>}
      {svid && (
        <Table
          head={["field", "value"]}
          rows={[
            ["SPIFFE id", <span className="mono">{svid.spiffe_id}</span>],
            ["valid until", <span className="mono">{svid.not_after}</span>],
            ["leaf certificate", <Code>{svid.cert_pem}</Code>],
            ["CA bundle", <Code>{svid.ca_cert_pem}</Code>],
          ]}
        />
      )}
      {!svid && <p className="faint">Issue an SVID to retrieve the leaf certificate and CA bundle for mTLS. Peers are validated against the CA, validity window, and a workload allowlist (fail-closed).</p>}
    </Panel>
  );
}

export default function Identity() {
  const [tab, setTab] = useState(0);
  const tabs = ["SSO & directory", "SCIM users", "API keys", "Workload identity"];
  return (
    <>
      <PageHead
        crumb="operate / identity & access"
        title="Identity & access"
        sub="SAML 2.0 SSO · LDAP/AD · SCIM 2.0 provisioning · API-key IP allowlist & rotation · SPIFFE workload identity — all enforced server-side, deterministic, fail-closed"
        right={<Badge tone=""><span className="dot" /> ENTERPRISE IDENTITY</Badge>}
      />
      <div className="mt"><Tabs tabs={tabs} active={tab} onChange={setTab} /></div>
      {tab === 0 && <SsoPanel />}
      {tab === 1 && <ScimPanel />}
      {tab === 2 && <KeyPanel />}
      {tab === 3 && <WorkloadPanel />}
    </>
  );
}
