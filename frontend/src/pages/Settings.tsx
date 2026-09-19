import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import {
  apiActiveSector,
  apiListSectors,
  apiSetActiveSector,
  apiNotificationRoutingGet,
  apiNotificationRoutingPut,
  apiSafeScanPolicy,
  apiSsoStatus,
  apiScope,
} from "../lib/api.js";

/* Settings is entirely live: every section reads a real control-plane
   endpoint. There is no fake configuration — values the backend does not
   expose are shown as an honest "configured server-side" note. */

const CHANNELS = ["inApp", "email", "webhook", "siem"] as const;
type Channel = typeof CHANNELS[number];

interface RouteItem {
  id: string; name: string; severity: string; channels: Record<string, boolean>;
}

export default function Settings() {
  const sector = useApi(apiActiveSector, []);
  const sectors = useApi(() => apiListSectors(), []);
  const scope = useApi(apiScope, []);
  const sso = useApi(apiSsoStatus, []);
  const policy = useApi(apiSafeScanPolicy, []);
  const routing = useApi(apiNotificationRoutingGet, []);

  const [routes, setRoutes] = useState<RouteItem[] | null>(null);
  const [sectorSel, setSectorSel] = useState("");
  const [sectorMsg, setSectorMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [routeMsg, setRouteMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const data = routing.data as { routing?: RouteItem[] } | null;
    if (data?.routing && routes === null) setRoutes(data.routing);
    if (sector.data?.sector) setSectorSel(sector.data.sector);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routing.source, routing.data, sector.data]);

  const saveSector = async () => {
    setSectorMsg(null);
    if (!sectorSel) return;
    const r = await apiSetActiveSector(sectorSel);
    setSectorMsg({ ok: r.ok, text: r.ok ? `Active sector → ${sectorSel}` : r.error || "failed" });
  };

  const saveRouting = async () => {
    if (!routes) return;
    setSaving(true);
    setRouteMsg(null);
    const r = await apiNotificationRoutingPut(routes);
    setSaving(false);
    setRouteMsg(r.ok ? { ok: true, text: "Notification routing saved" } : { ok: false, text: r.error || "failed" });
  };

  const ssoData = sso.data as { saml_enabled?: boolean; ldap_enabled?: boolean } | null;

  return (
    <>
      <PageHead
        crumb="platform / settings"
        title="Settings"
        sub="Organization sector, notification routing and platform configuration — all read from the live control plane"
        right={<LiveBadge source={scope.source === "live" ? "live" : "offline"} label={scope.source === "live" ? "LIVE CONFIG" : "BACKEND OFFLINE"} />}
      />

      <div className="grid cols-2">
        {/* Sector */}
        <Panel title="Organization sector" sub="the active sector profile drives the risk engine & policy packs">
          {sectorMsgs(sectorMsg)}
          <div className="row" style={{ gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
            <select
              value={sectorSel}
              onChange={(e) => setSectorSel(e.target.value)}
              style={{ flex: "1 1 220px", padding: "8px 10px" }}
            >
              {(sectors.data?.sectors ?? []).map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
            <button className="btn primary" onClick={() => void saveSector()} disabled={saving || !sectorSel}>Save</button>
          </div>
          {sector.data && (
            <div className="dim" style={{ fontSize: 12.5, marginTop: 10 }}>
              Active: <b>{sector.data.sector}</b> — {sector.data.profile?.description ?? ""}
            </div>
          )}
        </Panel>

        {/* Identity */}
        <Panel title="Identity & SSO" sub="bring-your-own-IdP — configured server-side, status read live">
          <div className="mono-list">
            <Row k="SAML 2.0" v={ssoData?.saml_enabled ? <Badge tone="green">enabled</Badge> : <Badge tone="">disabled</Badge>} />
            <Row k="LDAP / AD" v={ssoData?.ldap_enabled ? <Badge tone="green">enabled</Badge> : <Badge tone="">disabled</Badge>} />
            <Row k="Directory groups" v="map to the 8-role RBAC catalog" />
            <Row k="Unmapped users" v="default to read-only" />
          </div>
        </Panel>

        {/* Safe-scan policy */}
        <Panel title="Safe-scan policy" sub="guardrails the platform applies before any active probe">
          {policy.source !== "live" && (
            <div className="dim" style={{ fontSize: 13 }}>Backend offline — safe-scan policy unavailable.</div>
          )}
          {policy.data && (
            <div className="mono-list">
              {((policy.data as { policies?: Array<Record<string, unknown>> }).policies ?? []).map((p, i) => (
                <div key={i} className="spread" style={{ fontSize: 13, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
                  <span className="mono">{String(p.mode ?? "—")}</span>
                  <span className="dim">{String(p.scope_region ?? "—")} · {String(p.environment ?? "—")}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Notification routing */}
        <Panel title="Notification routing" sub="which channels carry each event severity (in-app / email / webhook / SIEM)">
          {routeMsg && <div className={`auth-alert ${routeMsg.ok ? "ok" : "err"}`}>{routeMsg.ok ? "✓ " : "✕ "}{routeMsg.text}</div>}
          {!routes && routing.source !== "live" && (
            <div className="dim" style={{ fontSize: 13 }}>Backend offline — routing unavailable.</div>
          )}
          {routes && (
            <>
              <Table
                head={["event", "severity", ...CHANNELS]}
                rows={routes.map((r) => [
                  <span>{r.name}</span>,
                  <Badge tone={sev(r.severity)}>{r.severity || "—"}</Badge>,
                  ...CHANNELS.map((ch) => (
                    <button
                      key={ch}
                      className="chk"
                      style={{ width: 34, height: 26 }}
                      onClick={() =>
                        setRoutes((prev) => (prev ?? []).map((x) => x.id === r.id ? { ...x, channels: { ...x.channels, [ch]: !x.channels[ch] } } : x))
                      }
                    >
                      {r.channels?.[ch] ? "✓" : "·"}
                    </button>
                  )),
                ])}
              />
              <div className="row" style={{ justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                <button className="btn sm" onClick={() => setRoutes((routing.data as { routing?: RouteItem[] })?.routing ? [...((routing.data as { routing?: RouteItem[] }).routing as RouteItem[])] : (routes ?? []))}>
                  Reset
                </button>
                <button className="btn primary sm" onClick={() => void saveRouting()} disabled={saving}>
                  {saving ? "Saving…" : "Save routing"}
                </button>
              </div>
            </>
          )}
        </Panel>
      </div>

      <Panel title="Platform scope" sub="GET /api/v1/platform/scope — the single source of truth for what the platform scans">
        {scope.data ? <Code>{JSON.stringify(scope.data, null, 2)}</Code> : <div className="dim" style={{ fontSize: 13 }}>Backend offline — scope unavailable.</div>}
      </Panel>
    </>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="spread" style={{ fontSize: 13, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="dim">{k}</span>
      <span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}

function sev(s?: string): string {
  const up = String(s || "").toUpperCase();
  return up === "CRITICAL" || up === "HIGH" ? "red" : up === "MEDIUM" ? "amber" : "";
}

function sectorMsgs(m: { ok: boolean; text: string } | null) {
  if (!m) return null;
  return <div className={`auth-alert ${m.ok ? "ok" : "err"}`} style={{ marginBottom: 8 }}>{m.ok ? "✓ " : "✕ "}{m.text}</div>;
}
