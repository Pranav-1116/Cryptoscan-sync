import React, { useMemo, useState } from "react";
import { Badge, PageHead, Table, Panel } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiSaasWhoami, apiSaasUsage, apiSaasMembers, apiSaasAddMember, apiSaasRemoveMember,
  apiSaasAdminTenants, apiSaasSuspend, apiSaasRestore, apiSaasSetPlan,
  apiSaasInvites, apiSaasCreateInvite, apiSaasRevokeInvite,
  SaasWhoami, SaasMember, SaasAdminTenant, SaasInvite, activeTenantId, setActiveTenantId,
} from "../lib/api.js";

/* Tenancy — the multi-tenant SaaS control surface: your organization, plan
   usage against limits, members and roles, and (for platform admins) the
   tenant registry with suspend/restore. Everything renders from the LIVE
   /saas endpoints; a fresh deployment shows an empty state, never demo data. */

function MeterBar({ label, used, limit }: { label: string; used: number; limit: number | null }) {
  const pct = limit === null ? 0 : Math.min(100, Math.round((used / Math.max(1, limit)) * 100));
  const tone = limit === null ? "ok" : pct >= 100 ? "fail" : pct >= 80 ? "warn" : "ok";
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
        <span>{label}</span>
        <span>
          {used} / {limit === null ? "unlimited" : limit}
        </span>
      </div>
      <div style={{ background: "var(--border, #333)", height: 6, borderRadius: 3, marginTop: 3 }}>
        <div
          data-tone={tone}
          style={{
            width: `${limit === null ? 0 : pct}%`,
            height: 6,
            borderRadius: 3,
            background: tone === "ok" ? "var(--ok, #3fb950)" : tone === "warn" ? "var(--warn, #d29922)" : "var(--bad, #f85149)",
          }}
        />
      </div>
    </div>
  );
}

function MembersPanel({ whoami }: { whoami: SaasWhoami }) {
  const membersRes = usePollingApi(apiSaasMembers, 20000);
  const members = useMemo(() => membersRes.data?.members ?? [], [membersRes.data]);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("member");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const canManage = whoami.tenant_role === "owner" || whoami.tenant_role === "admin";

  async function add() {
    if (!username.trim()) return;
    const r = await apiSaasAddMember({
      username: username.trim(),
      tenant_role: role,
      password: password || undefined,
    });
    setMsg(r.data ? `added ${r.data.username} (${r.data.tenant_role})` : r.error ?? "failed");
    if (r.data) {
      setUsername("");
      setPassword("");
      membersRes.run();
    }
  }

  async function remove(name: string) {
    const r = await apiSaasRemoveMember(name);
    setMsg(r.data ? `removed ${r.data.removed}` : r.error ?? "failed");
    membersRes.run();
  }

  return (
    <Panel title={`Members (${members.length})`}>
      {canManage && (
        <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
          <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {["viewer", "member", "admin"].map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <input placeholder="initial password (new users)" value={password} onChange={(e) => setPassword(e.target.value)} type="password" />
          <button onClick={add}>Add member</button>
        </div>
      )}
      {msg && (
        <p style={{ fontSize: 12, opacity: 0.8 }}>
          {msg}
        </p>
      )}
      <Table
        head={["username", "role", "added", ...(canManage ? [""] : [])]}
        rows={members.map((m) => [
          m.username,
          <Badge key={m.username} tone={m.tenant_role === "owner" ? "green" : undefined}>{m.tenant_role}</Badge>,
          m.added_at ? new Date(m.added_at).toLocaleDateString() : "—",
          ...(canManage
            ? [
                <button key={`${m.username}-rm`} onClick={() => remove(m.username)} disabled={m.tenant_role === "owner"}>
                  remove
                </button>,
              ]
            : []),
        ])}
      />
    </Panel>
  );
}

function InvitesPanel() {
  const invitesRes = usePollingApi(apiSaasInvites, 20000);
  const invites = useMemo(() => invitesRes.data?.invites ?? [], [invitesRes.data]);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("member");
  const [msg, setMsg] = useState<string | null>(null);
  const [freshToken, setFreshToken] = useState<string | null>(null);

  async function invite() {
    if (!username.trim()) return;
    const r = await apiSaasCreateInvite({ username: username.trim(), tenant_role: role });
    if (r.ok) {
      setFreshToken(r.token ?? null);
      setMsg(`invite created for ${r.username} (${r.tenant_role}) — deliver the token out-of-band`);
      setUsername("");
      invitesRes.run();
    } else {
      setFreshToken(null);
      setMsg(r.error ?? "failed");
    }
  }

  async function revoke(id: string) {
    const r = await apiSaasRevokeInvite(id);
    setMsg(r.data ? `revoked invite for ${r.data.revoked}` : r.error ?? "failed");
    invitesRes.run();
  }

  return (
    <Panel title={`Pending invites (${invites.length})`}>
      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
        <input placeholder="username to invite" value={username} onChange={(e) => setUsername(e.target.value)} />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {["viewer", "member", "admin"].map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <button onClick={invite}>Create invite</button>
      </div>
      {freshToken && (
        <p style={{ fontSize: 12, background: "var(--bg, #161b22)", padding: 8, borderRadius: 6 }}>
          one-time token (shown once): <code>{freshToken}</code>
        </p>
      )}
      {msg && (
        <p style={{ fontSize: 12, opacity: 0.8 }}>
          {msg}
        </p>
      )}
      <Table
        head={["username", "role", "invited by", "expires", ""]}
        rows={invites.map((i) => [
          i.username,
          <Badge key={`${i.invite_id}-r`} tone={i.tenant_role === "owner" ? "green" : undefined}>{i.tenant_role}</Badge>,
          i.invited_by ?? "—",
          i.expires_at ? new Date(i.expires_at).toLocaleDateString() : "—",
          <button key={`${i.invite_id}-x`} onClick={() => revoke(i.invite_id)}>
            revoke
          </button>,
        ])}
      />
    </Panel>
  );
}

function AdminPanel() {
  const tenantsRes = usePollingApi(apiSaasAdminTenants, 20000);
  const tenants = useMemo(() => tenantsRes.data?.tenants ?? [], [tenantsRes.data]);
  const [reason, setReason] = useState("non-payment");
  const [msg, setMsg] = useState<string | null>(null);

  async function act(fn: () => Promise<{ data: unknown; error?: string }>) {
    const r = await fn();
    setMsg(r.error ?? "done");
    tenantsRes.run();
  }

  return (
    <Panel title={`Tenant registry (${tenants.length}) — platform admin`}>
      <div style={{ marginBottom: 8 }}>
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="suspension reason" />
      </div>
      {msg && (
        <p style={{ fontSize: 12, opacity: 0.8 }}>
          {msg}
        </p>
      )}
      <Table
        head={["org", "plan", "status", "members", "targets", "scans/mo", "actions"]}
        rows={tenants.map((t) => [
          `${t.name} (${t.slug})`,
          <select key={`${t.id}-plan`} defaultValue={t.plan} onChange={(e) => act(() => apiSaasSetPlan(t.id, e.target.value))}>
            {["FREE", "PRO", "ENTERPRISE"].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>,
          <Badge key={`${t.id}-st`} tone={t.status === "ACTIVE" ? "green" : "red"}>{t.status}</Badge>,
          String(t.members),
          String(t.targets),
          String(t.scans_this_month),
          t.status === "ACTIVE" ? (
            <button key={`${t.id}-s`} onClick={() => act(() => apiSaasSuspend(t.id, reason))}>
              suspend
            </button>
          ) : (
            <button key={`${t.id}-r`} onClick={() => act(() => apiSaasRestore(t.id))}>
              restore
            </button>
          ),
        ])}
      />
    </Panel>
  );
}

export default function Tenancy() {
  const whoami = usePollingApi<SaasWhoami>(apiSaasWhoami, 15000);
  const usage = usePollingApi(apiSaasUsage, 20000);
  const w = whoami.data;
  const meters = useMemo(() => Object.entries(usage.data?.meters ?? {}), [usage.data]);

  return (
    <div>
      <PageHead
        crumb="SaaS"
        title="Tenancy"
        sub="Your organization, plan usage, and members — multi-tenant SaaS control plane"
      />
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 }}>
        <Panel title="Organization">
          {w ? (
            <>
              <p>
                <strong>{w.tenant_name ?? "platform estate"}</strong>{" "}
                {w.tenant_slug ? <span style={{ opacity: 0.6 }}>({w.tenant_slug})</span> : null}
              </p>
              <p>
                signed in as <strong>{w.username}</strong> · role{" "}
                <Badge tone={w.tenant_role === "owner" ? "green" : undefined}>{w.tenant_role ?? "platform"}</Badge> · plan{" "}
                <Badge tone={w.plan === "ENTERPRISE" ? "green" : undefined}>{w.plan ?? "—"}</Badge>
                {w.tenant_status === "SUSPENDED" ? (
                  <Badge tone="red">SUSPENDED</Badge>
                ) : null}
              </p>
              {w.tenant_id && (
                <p style={{ fontSize: 12, opacity: 0.7 }}>
                  tenant: <code>{w.tenant_id}</code> — active in this browser; switch orgs by signing in
                  with a member of the other organization.
                </p>
              )}
            </>
          ) : (
            <p>loading…</p>
          )}
        </Panel>
        <Panel title="Plan usage">
          {meters.length === 0 ? (
            <p>{w?.tenant_id ? "loading…" : "platform context has no meters"}</p>
          ) : (
            meters.map(([label, m]) => <MeterBar key={label} label={label.replace(/_/g, " ")} used={m.used} limit={m.limit} />)
          )}
        </Panel>
      </div>
      {w?.tenant_id && (w.tenant_role === "owner" || w.tenant_role === "admin") && <InvitesPanel />}
      {w?.tenant_id && <MembersPanel whoami={w} />}
      {w?.is_platform_admin && <AdminPanel />}
    </div>
  );
}
