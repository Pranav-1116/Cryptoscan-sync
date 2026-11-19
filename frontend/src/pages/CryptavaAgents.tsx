import React from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import {
  apiControlAgents, apiAgentContributions, apiEnrollAgent, apiReissueAgentToken, apiAgentUpgrade,
  LiveBadge,
} from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { StatusMark } from "../components/icons";

/* Cryptava — the host agent. One agent per server; each sends one signed report
   that feeds the six BOMs. This page is the fleet: who is online, what each one
   last reported per BOM, and whether its reports are verified. */

/** No heartbeat for this long and the agent is shown offline (it beats every 60s). */
export const OFFLINE_AFTER_MS = 3 * 60 * 1000;

export const BOMS = [
  { key: "HBOM", label: "Hardware", to: "/hbom" },
  { key: "SBOM", label: "Software", to: "/sbom" },
  { key: "CBOM", label: "Cryptography", to: "/cbom" },
  { key: "NBOM", label: "Network", to: "/nbom" },
  { key: "VBOM", label: "Vendors", to: "/vbom" },
  { key: "TechBOM", label: "Technology", to: "/live-asset-intelligence" },
] as const;

type Agent = Record<string, any>;
type Contribution = Record<string, any>;
type Plane = { plane?: string; status?: string; reason?: string };

export type AgentState = "online" | "offline" | "waiting" | "retired";

export function agentState(agent: Agent, now = Date.now()): AgentState {
  const status = String(agent.status || "");
  if (status === "retired") return "retired";
  const seen = agent.last_seen || agent.last_heartbeat_at;
  if (!seen) return "waiting";
  const age = now - new Date(seen).getTime();
  return Number.isFinite(age) && age <= OFFLINE_AFTER_MS ? "online" : "offline";
}

const STATE_TONE: Record<AgentState, string> = { online: "green", offline: "red", waiting: "amber", retired: "" };
const STATE_HINT: Record<AgentState, string> = {
  online: "Heartbeat in the last 3 minutes",
  offline: "No heartbeat for over 3 minutes",
  waiting: "Enrolled — waiting for the server to connect",
  retired: "Retired — its key no longer works",
};

export function planeOf(planes: Plane[] | undefined, key: string): Plane | undefined {
  return (planes || []).find((p) => String(p.plane || "").split(" ")[0] === key);
}

function planeTone(status?: string): string {
  const s = String(status || "").toUpperCase();
  if (s === "COMPLETE") return "green";
  if (s === "PARTIAL") return "amber";
  if (s === "FAILED") return "red";
  return "";
}

export function ago(iso?: string | null, now = Date.now()): string {
  if (!iso) return "never";
  const secs = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (!Number.isFinite(secs)) return "—";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h ago`;
  return `${Math.floor(secs / 86400)} d ago`;
}

function BomDots({ planes }: { planes?: Plane[] }) {
  return (
    <span className="cv-dots" style={{ display: "inline-flex", gap: 4 }}>
      {BOMS.map((b) => {
        const p = planeOf(planes, b.key);
        const tone = planeTone(p?.status);
        return (
          <span key={b.key} className={`badge ${tone}`} title={`${b.key}: ${p?.status || "no report"}`}
            style={{ padding: "2px 6px", fontSize: 11, opacity: p ? 1 : 0.45 }}>
            {b.key === "TechBOM" ? "T" : b.key[0]}
          </span>
        );
      })}
    </span>
  );
}

function Field({ k, v, mono = false }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="muted">{k}</span>
      <span className={mono ? "mono" : undefined} style={{ textAlign: "right", wordBreak: "break-all" }}>{v ?? "—"}</span>
    </div>
  );
}

export default function CryptavaAgents() {
  const agents = usePollingApi(apiControlAgents, 15000);
  const contributions = usePollingApi(apiAgentContributions, 20000);
  useRealtimeRefresh(agents.run, contributions.run);

  const [now, setNow] = React.useState(Date.now());
  React.useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), 15000); return () => window.clearInterval(t); }, []);

  const [notice, setNotice] = React.useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const flash = (kind: "ok" | "err", text: string) => { setNotice({ kind, text }); window.setTimeout(() => setNotice(null), 5000); };
  const [busy, setBusy] = React.useState("");
  const [name, setName] = React.useState("");
  const [issued, setIssued] = React.useState<{ agent_id: string; name: string; enrollment_token: string } | null>(null);
  const [openId, setOpenId] = React.useState<string | null>(null);

  const agentRows = ((agents.data ?? []) as Agent[]);
  const byName = React.useMemo(() => {
    const m = new Map<string, Contribution>();
    for (const c of (contributions.data ?? []) as Contribution[]) m.set(String(c.contributor), c);
    return m;
  }, [contributions.data]);

  const live = agentRows.filter((a) => agentState(a, now) !== "retired");
  const counts = {
    total: live.length,
    online: live.filter((a) => agentState(a, now) === "online").length,
    offline: live.filter((a) => agentState(a, now) === "offline").length,
    verified: live.filter((a) => byName.get(String(a.name))?.authenticity === "VALID").length,
  };

  const enrol = async () => {
    const clean = name.trim();
    if (!clean) return;
    setBusy("enrol");
    try {
      const res = await apiEnrollAgent(clean);
      if (res.ok && res.data) { setIssued(res.data); setName(""); await agents.run(); }
      else flash("err", res.error || "enrolment failed");
    } finally { setBusy(""); }
  };
  const newToken = async (id: string) => {
    setBusy(`token-${id}`);
    try {
      const res = await apiReissueAgentToken(id);
      if (res.ok && res.data) { setIssued(res.data); setOpenId(null); }
      else flash("err", res.error || "could not issue a token");
    } finally { setBusy(""); }
  };
  const retire = async (agent: Agent) => {
    if (!window.confirm(`Retire ${agent.name}? Its key stops working immediately.`)) return;
    setBusy(`retire-${agent.id}`);
    try {
      const res = await apiAgentUpgrade(String(agent.id), "retire");
      if (res.ok === false) flash("err", res.error || "retire failed");
      else { flash("ok", `${agent.name} retired`); await agents.run(); }
    } finally { setBusy(""); }
  };

  const command = issued
    ? `sudo ./install.sh --server ${window.location.origin} --agent-id ${issued.agent_id} --token ${issued.enrollment_token}`
    : "";
  const open = openId ? agentRows.find((a) => String(a.id) === openId) : undefined;
  const openReport = open ? byName.get(String(open.name)) : undefined;

  return (
    <div className="page cryptava-agents">
      <PageHead
        crumb="discovery / cryptava"
        title="Cryptava agents"
        sub="One agent per server · signed reports · six BOMs per host"
        right={<LiveBadge source={agents.source} />}
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {([
          ["agents", counts.total, "cyan"],
          ["online", counts.online, "green"],
          ["offline", counts.offline, counts.offline ? "red" : "green"],
          ["verified reports", counts.verified, "green"],
        ] as const).map(([k, v, tone]) => (
          <div className="kpi" key={k}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{v}</span>
          </div>
        ))}
      </div>

      {notice && (
        <div role="status" className={`badge ${notice.kind === "ok" ? "green" : "red"}`} style={{ display: "block", marginBottom: 12, padding: "8px 12px" }}>
          <StatusMark ok={notice.kind === "ok"} muted />{notice.text}
        </div>
      )}

      <Panel title="Agents" sub="Click an agent for its last report">
        {agents.ok === false && <div className="muted" role="alert" style={{ marginBottom: 8 }}>Could not load agents: {agents.error}</div>}
        {agentRows.length ? (
          <Table
            clickable
            onSelect={(i) => setOpenId(String(agentRows[i].id))}
            head={["agent", "status", "last seen", "BOMs", "assets", "report", "version"]}
            total={agentRows.length}
            rows={agentRows.map((a) => {
              const state = agentState(a, now);
              const report = byName.get(String(a.name));
              return [
                <span className="mono" style={{ fontWeight: 600 }} title={String(a.name)}>{String(a.name)}</span>,
                <span title={STATE_HINT[state]}><Badge tone={STATE_TONE[state]}>{state}</Badge></span>,
                <span className="muted">{ago(a.last_seen, now)}</span>,
                report ? <BomDots planes={report.planes} /> : <span className="muted">no report yet</span>,
                <span className="num">{report ? report.assets : "—"}</span>,
                report?.authenticity
                  ? <Badge tone={report.authenticity === "VALID" ? "green" : "red"}>{report.authenticity === "VALID" ? "verified" : String(report.authenticity).toLowerCase()}</Badge>
                  : <span className="muted">—</span>,
                <span className="num">{String(a.version ?? "—")}</span>,
              ];
            })}
          />
        ) : (
          <div className="cv-empty">
            <p style={{ marginTop: 0 }}><strong>No agents yet.</strong></p>
            <p className="muted" style={{ marginBottom: 6 }}>Sandbox — start the four bank-host agents:</p>
            <pre className="mono" style={{ margin: "0 0 12px" }}>bash sandbox/run_sandbox.sh agents</pre>
            <p className="muted" style={{ margin: 0 }}>Real server — enrol it below, then run the command shown on that server.</p>
          </div>
        )}
      </Panel>

      <Panel title="Add a server" sub="Unique name, then run the install command on that server">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input className="input mono" style={{ flex: "1 1 260px" }} aria-label="agent name"
            placeholder="mrdn-prod-dc1-swiftgw01" value={name}
            title="bank-environment-datacenter-hostname"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void enrol(); }} />
          <button className="btn" disabled={!name.trim() || busy === "enrol"} onClick={() => void enrol()}>
            {busy === "enrol" ? "…" : "enrol"}
          </button>
        </div>
        {issued && (
          <div className="cv-token" role="status" style={{ border: "1px solid var(--line-strong)", borderRadius: 8, padding: 12, marginTop: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
              <strong className="mono">{issued.name}</strong>
              <span className="muted">token shown once</span>
            </div>
            <pre className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", margin: "8px 0", fontSize: 12 }}>{command}</pre>
            <span style={{ display: "flex", gap: 6 }}>
              <button className="btn" onClick={() => {
                void navigator.clipboard?.writeText(command).then(() => flash("ok", "copied"), () => flash("err", "copy failed"));
              }}>copy</button>
              <button className="btn" onClick={() => setIssued(null)}>done</button>
            </span>
          </div>
        )}
      </Panel>

      {open && (
        <Drawer title={String(open.name)} sub={STATE_HINT[agentState(open, now)]} onClose={() => setOpenId(null)}>
          <div style={{ marginBottom: 14 }}>
            <Badge tone={STATE_TONE[agentState(open, now)]}>{agentState(open, now)}</Badge>{" "}
            {openReport?.authenticity && (
              <Badge tone={openReport.authenticity === "VALID" ? "green" : "red"}>
                {openReport.authenticity === "VALID" ? "signature verified" : `signature ${String(openReport.authenticity).toLowerCase()}`}
              </Badge>
            )}
          </div>

          <h4 style={{ margin: "0 0 6px" }}>Last report</h4>
          {openReport ? (
            <div className="cv-planes" style={{ marginBottom: 16 }}>
              {BOMS.map((b) => {
                const p = planeOf(openReport.planes, b.key);
                return (
                  <div key={b.key} style={{ padding: "8px 0", borderBottom: "1px solid var(--line)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                      <span><strong>{b.key}</strong> <span className="muted">{b.label}</span></span>
                      <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <Badge tone={planeTone(p?.status)}>{p?.status ? String(p.status).toLowerCase() : "no data"}</Badge>
                        <Link to={b.to}>open</Link>
                      </span>
                    </div>
                    {p?.reason && <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{p.reason}</div>}
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="muted">No report received yet.</p>
          )}

          {openReport?.asset_types && Object.keys(openReport.asset_types).length > 0 && (
            <>
              <h4 style={{ margin: "0 0 6px" }}>Found on this server</h4>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 16 }}>
                {Object.entries(openReport.asset_types as Record<string, number>).map(([kind, n]) => (
                  <Badge key={kind} tone="cyan">{kind.toLowerCase().replace(/_/g, " ")} · {n}</Badge>
                ))}
              </div>
            </>
          )}

          <h4 style={{ margin: "0 0 6px" }}>Details</h4>
          <div style={{ marginBottom: 16 }}>
            <Field k="Host" v={open.config?.identity?.hostname} mono />
            <Field k="IP" v={open.last_seen_ip} mono />
            <Field k="Version" v={open.version} />
            <Field k="Last heartbeat" v={ago(open.last_seen, now)} />
            <Field k="Last change" v={openReport?.received_at ? ago(openReport.received_at, now) : "—"} />
            <Field k="Signing key" v={open.cert_serial} mono />
            <Field k="Agent ID" v={open.id} mono />
          </div>

          {String(open.status) !== "retired" && (
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn" disabled={busy === `token-${open.id}`} title="For a rebuilt server: keeps the name, replaces the key"
                onClick={() => void newToken(String(open.id))}>
                {busy === `token-${open.id}` ? "…" : "new token"}
              </button>
              <button className="btn" disabled={busy === `retire-${open.id}`} onClick={() => void retire(open)}>
                {busy === `retire-${open.id}` ? "…" : "retire"}
              </button>
            </div>
          )}
        </Drawer>
      )}
    </div>
  );
}
