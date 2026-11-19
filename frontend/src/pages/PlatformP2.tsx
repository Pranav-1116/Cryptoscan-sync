import React from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import {
  apiP2Plugins, apiP2AnomalyFlags, apiP2GovernanceRequests, apiP2LakeBatches,
  apiP2ApiKeys, apiOtMaintenanceWindows, apiSlaPosture, apiCredentialLeases,
  apiAutomationRuns, apiAutomationRules, apiCbomVersions, apiHealthSweep,
  apiPostMigrationValidate,
  apiRunRealBenchmark, apiBenchmarkRuns,
  apiGovernanceDecide, apiLakeExportLive, apiLakeVerify,
  apiPluginEnable, apiPluginDisable, apiAnomalyAck,
  apiControlAgents,
  apiOtAuthorize, apiOtCancelWindow,
  apiExceptions, apiExceptionDecision,
  LiveBadge,
} from "../lib/api.js";
import { usePollingApi, useApi } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { StatusMark } from "../components/icons";

/* P2 enterprise platform — deterministic:
   - Plugin marketplace: hash-pinned, Ed25519-signed plugins (quarantine on failure)
   - Data lake: append-only hash-chained export batches
   - Anomaly: statistical (z-score / EWMA / rate-of-change / frequency)
   - Governance: rule-based approval policy + migration validation
   All panels read live data from the API. */

function stateTone(state: string): "green" | "red" | "amber" | "cyan" {
  const s = (state || "").toUpperCase();
  if (s === "ENABLED" || s === "AUTO_APPROVED" || s === "APPROVED" || s === "PASS" || s === "SEALED") return "green";
  if (s === "QUARANTINED" || s === "DENIED" || s === "FAIL" || s === "HIGH") return "red";
  if (s === "PENDING" || s === "REQUIRES_APPROVAL" || s === "VERIFIED" || s === "MEDIUM" || s === "OPEN") return "amber";
  return "cyan";
}

export default function PlatformP2() {
  const plugins = usePollingApi(apiP2Plugins, 15000);
  const flags = usePollingApi(apiP2AnomalyFlags, 15000);
  const reqs = usePollingApi(apiP2GovernanceRequests, 15000);
  const lake = usePollingApi(() => apiP2LakeBatches("primary"), 20000);
  const keys = usePollingApi(apiP2ApiKeys, 20000);
  const windows = usePollingApi(apiOtMaintenanceWindows, 20000);
  const sla = usePollingApi(apiSlaPosture, 20000);
  const leases = usePollingApi(apiCredentialLeases, 20000);
  const autoRuns = usePollingApi(apiAutomationRuns, 10000);
  const autoRules = usePollingApi(apiAutomationRules, 30000);
  const cbomVersions = usePollingApi(apiCbomVersions, 20000);
  const health = usePollingApi(apiHealthSweep, 30000);
  const benchmarkRuns = usePollingApi(apiBenchmarkRuns, 60000);
  const agents = usePollingApi(apiControlAgents, 20000);
  const exceptions = usePollingApi(apiExceptions, 20000);
  const realBenchmark = useApi(apiRunRealBenchmark);
  // Live: refresh these operational panels the moment the platform changes
  // (SSE) rather than only on their poll interval. benchmarkRuns/realBenchmark
  // are excluded — they reflect an on-demand action, not live estate state.
  useRealtimeRefresh(
    plugins.run, flags.run, reqs.run, lake.run, keys.run, windows.run, sla.run,
    leases.run, autoRuns.run, autoRules.run, cbomVersions.run, health.run,
    agents.run, exceptions.run,
  );
  const latestBenchmark = realBenchmark.data
    ?? ((benchmarkRuns.data ?? []).find((r) => r.scanner_id === "universal-crypto-real") as any) ?? null;
  const runBenchmark = async () => {
    await realBenchmark.run();
    await benchmarkRuns.run();
  };

  // ── interactive deterministic action gates (human approval / verification) ──
  const [notice, setNotice] = React.useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [busyId, setBusyId] = React.useState<string>("");
  const [migration, setMigration] = React.useState<{ pre: string; post: string; result: any | null }>({ pre: "", post: "", result: null });
  const [otGate, setOtGate] = React.useState<{ operation: string; deviceId: string; result: any | null }>({ operation: "active_probe", deviceId: "", result: null });
  const flash = (kind: "ok" | "err", text: string) => {
    setNotice({ kind, text });
    window.setTimeout(() => setNotice(null), 5000);
  };
  const runAction = async (id: string, fn: () => Promise<any>, refresh?: () => Promise<unknown>) => {
    setBusyId(id);
    try {
      const res = await fn();
      if (res?.ok === false) flash("err", res.error || "action failed");
      else { flash("ok", "action completed"); if (refresh) await refresh(); }
    } finally { setBusyId(""); }
  };
  const decide = (pk: string, approve: boolean) =>
    runAction(`gov-${pk}-${approve}`, () => apiGovernanceDecide(pk, approve), reqs.run);
  const exportLive = () =>
    runAction("lake-export", () => apiLakeExportLive("primary"), lake.run);
  const verifyBatch = (pk: string) => runAction(`lake-verify-${pk}`, async () => {
    const res = await apiLakeVerify(pk);
    if (res.ok && res.data?.verified === false) return { ok: false, error: "chain verification FAILED (tamper detected)" };
    return res;
  });
  const togglePlugin = (pk: string, enable: boolean) =>
    runAction(`plugin-${pk}-${enable}`, () => (enable ? apiPluginEnable(pk) : apiPluginDisable(pk)), plugins.run);
  const runOtAuthorize = async () => {
    setBusyId("ot-authorize");
    try {
      const res = await apiOtAuthorize(otGate.operation, otGate.deviceId || undefined);
      if (res.ok && res.data) setOtGate((g) => ({ ...g, result: res.data }));
      else flash("err", res.error || "OT authorization check failed");
    } finally { setBusyId(""); }
  };
  const cancelWindow = (ref: string) =>
    runAction(`ot-cancel-${ref}`, () => apiOtCancelWindow(ref), windows.run);
  const exceptionDecision = (id: string, action: "approve" | "reject" | "revoke") =>
    runAction(`exc-${id}-${action}`, () => apiExceptionDecision(id, action), exceptions.run);
  const validateMigration = async () => {
    let pre: any[] = [];
    let post: any[] = [];
    try { pre = migration.pre.trim() ? JSON.parse(migration.pre) : []; } catch { flash("err", "PRE findings must be a JSON array"); return; }
    try { post = migration.post.trim() ? JSON.parse(migration.post) : []; } catch { flash("err", "POST findings must be a JSON array"); return; }
    const res = await apiPostMigrationValidate({ pre_findings: pre, post_findings: post });
    if (res.ok) { setMigration((m) => ({ ...m, result: res.data })); flash("ok", res.data?.passed ? "migration PASS — findings remediated" : "migration FAIL — regressions detected"); }
    else flash("err", res.error || "validation failed");
  };

  const pluginRows = (plugins.data ?? []) as Array<Record<string, unknown>>;
  const flagRows = (flags.data ?? []) as Array<Record<string, unknown>>;
  const reqRows = (reqs.data ?? []) as Array<Record<string, unknown>>;
  const batchRows = (lake.data ?? []) as Array<Record<string, unknown>>;
  const keyRows = (keys.data ?? []) as Array<Record<string, unknown>>;
  const windowRows = (windows.data ?? []) as Array<Record<string, unknown>>;
  const leaseRows = (leases.data ?? []) as Array<Record<string, unknown>>;
  const runRows = (autoRuns.data ?? []) as Array<Record<string, unknown>>;
  const ruleRows = (autoRules.data ?? []) as Array<Record<string, unknown>>;
  const cbomRows = (cbomVersions.data ?? []) as Array<Record<string, unknown>>;
  const agentRows = (agents.data ?? []) as Array<Record<string, any>>;
  const exceptionRows = (exceptions.data ?? []) as Array<Record<string, any>>;
  const slaData = (sla.data ?? null) as Record<string, unknown> | null;

  return (
    <>
      <PageHead
        crumb="platform / P2"
        title="P2 enterprise platform"
        sub="Plugin marketplace, tamper-evident data lake, statistical anomaly detection, rule-based governance — live and deterministic"
        right={<><LiveBadge source={plugins.source} /> <Badge tone="cyan">DETERMINISTIC</Badge></>}
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["plugins", pluginRows.length, "cyan"],
          ["anomaly flags", flagRows.length, flagRows.length ? "red" : "green"],
          ["open approvals", reqRows.filter((r) => r.status === "PENDING").length, "amber"],
          ["lake batches", batchRows.length, "green"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={String(k)}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{String(v)}</span>
          </div>
        ))}
      </div>

      {notice && (
        <div className={`badge ${notice.kind === "ok" ? "green" : "red"}`} style={{ display: "block", marginBottom: 12, padding: "8px 12px" }}>
          <StatusMark ok={notice.kind === "ok"} muted />{notice.text}
        </div>
      )}

      <div className="grid cols-2">
        <Panel title="Plugin marketplace" sub="hash-pinned · Ed25519-signed · fail-closed quarantine">
          <Table
            head={["plugin", "version", "type", "state", "trusted", ""]}
            total={pluginRows.length} rows={pluginRows.slice(0, 12).map((p) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(p.plugin_id)}</span>,
              <span className="num">{String(p.version)}</span>,
              <Badge tone="cyan">{String(p.plugin_type)}</Badge>,
              <Badge tone={stateTone(String(p.state))}>{String(p.state)}</Badge>,
              p.trusted ? <Badge tone="green">signed</Badge> : <span className="muted">—</span>,
              (() => {
                const state = String(p.state);
                const enabled = state === "ENABLED";
                const locked = state === "QUARANTINED" || !p.trusted;
                return (
                  <button
                    className="btn"
                    disabled={locked || busyId === `plugin-${p.id}-${!enabled}`}
                    title={locked ? "quarantined/untrusted plugins stay disabled (fail-closed)" : undefined}
                    onClick={() => togglePlugin(String(p.id), !enabled)}
                  >
                    {busyId === `plugin-${p.id}-${!enabled}` ? "…" : enabled ? "disable" : "enable"}
                  </button>
                );
              })(),
            ])}
          />
        </Panel>

        <Panel title="Statistical anomaly flags" sub="z-score · EWMA control · rate-of-change · frequency · human triage">
          <Table
            head={["severity", "rule", "metric", "status", ""]}
            total={flagRows.length} rows={flagRows.slice(0, 12).map((f) => {
              const open = String(f.status ?? "OPEN") === "OPEN";
              return [
                <Badge tone={stateTone(String(f.severity))}>{String(f.severity)}</Badge>,
                <span className="mono">{String(f.rule)}</span>,
                <span className="mono">{String(f.metric)}</span>,
                <Badge tone={open ? "red" : "green"}>{String(f.status ?? "OPEN")}</Badge>,
                open ? (
                  <button className="btn" disabled={busyId === `ack-${f.id}`}
                    onClick={() => runAction(`ack-${f.id}`, () => apiAnomalyAck(String(f.id)), flags.run)}>
                    {busyId === `ack-${f.id}` ? "…" : "acknowledge"}
                  </button>
                ) : <span className="muted">—</span>,
              ];
            })}
          />
        </Panel>

        <Panel title="Governance approvals" sub="rule-based policy gates · human approval required for changes (SoD enforced)">
          <Table
            head={["type", "risk", "decision", "status", ""]}
            total={reqRows.length} rows={reqRows.slice(0, 12).map((r) => {
              const pending = String(r.status) === "PENDING";
              return [
                <span className="mono">{String(r.request_type)}</span>,
                <Badge tone={stateTone(String(r.risk_level))}>{String(r.risk_level)}</Badge>,
                <span className="mono">{String(r.decision ?? "—")}</span>,
                <Badge tone={stateTone(String(r.status))}>{String(r.status)}</Badge>,
                pending ? (
                  <span style={{ display: "flex", gap: 6 }}>
                    <button className="btn" disabled={busyId === `gov-${r.id}-true`}
                      onClick={() => decide(String(r.id), true)}>
                      {busyId === `gov-${r.id}-true` ? "…" : "approve"}
                    </button>
                    <button className="btn" disabled={busyId === `gov-${r.id}-false`}
                      onClick={() => decide(String(r.id), false)}>
                      {busyId === `gov-${r.id}-false` ? "…" : "deny"}
                    </button>
                  </span>
                ) : <span className="muted">—</span>,
              ];
            })}
          />
        </Panel>

        <Panel title="Policy exceptions" sub="time-boxed risk acceptance · HMAC-signed approval · periodic review · auto-expire">
          <Table
            head={["type", "justification", "expires", "status", ""]}
            rows={exceptionRows.length ? exceptionRows.slice(0, 12).map((x) => {
              const st = String(x.status ?? "PENDING");
              const exp = x.expiration_date ? new Date(x.expiration_date).toISOString().slice(0, 10) : "—";
              return [
                <Badge tone="cyan">{String(x.exception_type)}</Badge>,
                <span className="muted" title={String(x.justification ?? "")}>{String(x.justification ?? "").slice(0, 38) || "—"}</span>,
                <span className="num">{exp}</span>,
                <Badge tone={stateTone(st)}>{st}</Badge>,
                st === "PENDING" ? (
                  <span style={{ display: "flex", gap: 6 }}>
                    <button className="btn" disabled={busyId === `exc-${x.id}-approve`}
                      onClick={() => exceptionDecision(String(x.id), "approve")}>
                      {busyId === `exc-${x.id}-approve` ? "…" : "approve"}
                    </button>
                    <button className="btn" disabled={busyId === `exc-${x.id}-reject`}
                      onClick={() => exceptionDecision(String(x.id), "reject")}>
                      {busyId === `exc-${x.id}-reject` ? "…" : "reject"}
                    </button>
                  </span>
                ) : st === "APPROVED" ? (
                  <button className="btn" disabled={busyId === `exc-${x.id}-revoke`}
                    onClick={() => exceptionDecision(String(x.id), "revoke")}>
                    {busyId === `exc-${x.id}-revoke` ? "…" : "revoke"}
                  </button>
                ) : <span className="muted">—</span>,
              ];
            }) : [[<span className="muted" key="none">No policy exceptions on record.</span>, "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Data-lake export chain" sub="append-only · hash-chained · tamper-evident">
          <div style={{ marginBottom: 10, display: "flex", gap: 10, alignItems: "center" }}>
            <button className="btn" disabled={busyId === "lake-export"} onClick={exportLive}>
              {busyId === "lake-export" ? "sealing…" : "seal live evidence batch"}
            </button>
            {lake.head && <span className="muted mono">head: {String(lake.head).slice(0, 16)}…</span>}
          </div>
          <Table
            head={["batch", "records", "batch digest", "chain digest", ""]}
            total={batchRows.length} rows={batchRows.slice(0, 12).map((b) => [
              <span className="num">#{String(b.batch_id)}</span>,
              <span className="num">{String(b.record_count)}</span>,
              <span className="mono muted">{String(b.batch_digest).slice(0, 12)}…</span>,
              <span className="mono">{String(b.chain_digest).slice(0, 12)}…</span>,
              <button className="btn" disabled={busyId === `lake-verify-${b.id}`}
                onClick={() => verifyBatch(String(b.id))}>
                {busyId === `lake-verify-${b.id}` ? "…" : "verify"}
              </button>,
            ])}
          />
        </Panel>

        <Panel title="Machine API keys" sub="scope + method allowlist · per-key rate quota · fail-closed">
          <Table
            head={["name", "scopes", "methods", "rate/min", "requests", "denied", "state"]}
            rows={keyRows.length ? keyRows.slice(0, 12).map((k) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(k.name)}</span>,
              <span className="muted">{(k.scopes as string[] || []).length ? (k.scopes as string[]).join(", ") : "all endpoints"}</span>,
              <span className="mono">{((k.allowed_methods as string[]) || []).join(" ") || "—"}</span>,
              <span className="num">{Number(k.rate_per_minute) ? String(k.rate_per_minute) : "∞"}</span>,
              <span className="num">{String(k.request_count)}</span>,
              <span className="num" style={{ color: Number(k.denied_count) ? "var(--red)" : undefined }}>{String(k.denied_count)}</span>,
              <Badge tone={k.active ? "green" : "red"}>{k.active ? "active" : "disabled"}</Badge>,
            ]) : [[<span className="muted" key="none">No API keys provisioned yet.</span>, "", "", "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Remediation SLA posture" sub="fixed deadline-per-severity · critical-asset window halved · deterministic breach detection">
          {slaData ? (
            <>
              <div className="grid cols-4" style={{ marginBottom: 10 }}>
                {[
                  ["breached", Number(slaData.breached ?? 0), Number(slaData.breached ?? 0) ? "red" : "green"],
                  ["at risk", Number(slaData.at_risk ?? 0), Number(slaData.at_risk ?? 0) ? "amber" : "green"],
                  ["on track", Number(slaData.on_track ?? 0), "green"],
                  ["breach rate", `${Math.round(Number(slaData.breach_rate ?? 0) * 100)}%`, Number(slaData.breach_rate ?? 0) > 0 ? "red" : "green"],
                ].map(([k, v, tone]) => (
                  <div className="kpi" key={String(k)}>
                    <span className="k">{String(k)}</span>
                    <span className="v" style={{ color: `var(--${tone})` }}>{String(v)}</span>
                  </div>
                ))}
              </div>
              <Table
                head={["finding", "severity", "state", "due", "days"]}
                rows={((slaData.items as any[]) || []).slice(0, 8).map((it) => [
                  <span className="mono">{String(it.finding_id).slice(0, 16)}</span>,
                  <Badge tone="cyan">{String(it.severity)}</Badge>,
                  <Badge tone={stateTone(String(it.state))}>{String(it.state)}</Badge>,
                  <span className="num muted">{String(it.due_at).slice(0, 10)}</span>,
                  it.state === "BREACHED"
                    ? <span className="num" style={{ color: "var(--red)" }}>+{String(it.days_overdue)}d late</span>
                    : <span className="num muted">{it.days_remaining != null ? `${String(it.days_remaining)}d left` : "—"}</span>,
                ])}
              />
            </>
          ) : <span className="muted">No SLA posture available.</span>}
        </Panel>

        <Panel title="OT safety gate + maintenance windows" sub="passive-first · active ops only in approved windows · SIS/ESD never probed (fail-closed)">
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 10 }}>
            <select className="btn" style={{ width: "auto" }}
              value={otGate.operation}
              onChange={(e) => setOtGate((g) => ({ ...g, operation: e.target.value }))}>
              {["passive_capture", "inventory", "pcap_read", "active_probe", "credentialed_scan", "firmware_pull", "firmware_push", "config_change"].map((op) => (
                <option key={op} value={op}>{op}</option>
              ))}
            </select>
            <input placeholder="device id (optional)" value={otGate.deviceId}
              onChange={(e) => setOtGate((g) => ({ ...g, deviceId: e.target.value }))}
              style={{ fontFamily: "monospace", fontSize: 12, padding: "6px 8px", minWidth: 200 }} />
            <button className="btn" disabled={busyId === "ot-authorize"} onClick={() => void runOtAuthorize()}>
              {busyId === "ot-authorize" ? "checking…" : "authorize"}
            </button>
            {otGate.result && (
              <Badge tone={otGate.result.allowed ? "green" : "red"}>
                {otGate.result.allowed ? "ALLOW" : `DENY — ${otGate.result.reason || ""}`}
              </Badge>
            )}
          </div>
          <Table
            head={["window", "scope", "class", "ticket", "in effect", ""]}
            rows={windowRows.length ? windowRows.slice(0, 12).map((w) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(w.window_ref)}</span>,
              <span className="muted">{[...(w.device_ids as string[] || []), ...(w.zones as string[] || [])].slice(0, 3).join(", ") || "—"}</span>,
              <Badge tone="cyan">{String(w.allowed_action_class)}</Badge>,
              <span className="mono">{String(w.change_ticket)}</span>,
              <Badge tone={w.in_effect ? "green" : "amber"}>{w.in_effect ? "in effect" : "scheduled/closed"}</Badge>,
              <button className="btn" disabled={busyId === `ot-cancel-${w.window_ref}`}
                onClick={() => cancelWindow(String(w.window_ref))}>
                {busyId === `ot-cancel-${w.window_ref}` ? "…" : "cancel"}
              </button>,
            ]) : [[<span className="muted" key="none">No maintenance windows scheduled.</span>, "", "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Vault credential leases" sub="short-lived · scoped TTL · reference-only (no key material)">
          <Table
            head={["credential", "component", "TTL", "scope", "status"]}
            rows={leaseRows.length ? leaseRows.slice(0, 12).map((l) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(l.credential_name)}</span>,
              <span className="mono">{String(l.component)}</span>,
              <span className="num">{String(l.ttl_seconds)}s</span>,
              <span className="muted">{String(l.scope ?? "—").slice(0, 28)}</span>,
              <Badge tone={l.status === "ACTIVE" && !l.expired ? "green" : "amber"}>{l.expired ? "expired" : String(l.status)}</Badge>,
            ]) : [[<span className="muted" key="none">No credential leases issued.</span>, "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Automation runs" sub="event-driven · auto-selected scanners · approval-gated changes">
          {runRows.length ? (
            <Table
              head={["event", "asset", "scanners", "auto → gate", "human"]}
              total={runRows.length} rows={runRows.slice(0, 12).map((r) => [
                <span className="mono" style={{ fontWeight: 600 }}>{String(r.event_kind)}</span>,
                <span className="mono muted">{String(r.asset_id ?? "—").slice(0, 16)}</span>,
                <span className="num">{(r.scanners as string[] || []).length}</span>,
                <span className="num">{(r.auto_actions as any[] || []).length} → {(r.gated_actions as any[] || []).length}</span>,
                r.needs_human ? <Badge tone="amber">approval</Badge> : <Badge tone="green">auto</Badge>,
              ])}
            />
          ) : <span className="muted">No automation runs yet.</span>}
        </Panel>

        <Panel title="Automation rules" sub="WHEN event · IF conditions · THEN actions (rule builder)">
          {ruleRows.length ? (
            <Table
              head={["rule", "WHEN", "severity", "actions", "enabled"]}
              total={ruleRows.length} rows={ruleRows.slice(0, 12).map((r) => [
                <span className="mono" style={{ fontWeight: 600 }}>{String(r.rule_id)}</span>,
                <span className="mono">{String(r.when)}</span>,
                <Badge tone={stateTone(String(r.severity))}>{String(r.severity)}</Badge>,
                <span className="muted">{((r.then as string[]) || []).join(", ")}</span>,
                r.enabled ? <Badge tone="green">on</Badge> : <Badge tone="amber">off</Badge>,
              ])}
            />
          ) : <span className="muted">No custom automation rules — playbooks run by default.</span>}
        </Panel>

        <Panel title="Live CBOM versions" sub="content-addressed · immutable versions · added/removed crypto diffed on change">
          {cbomRows.length ? (
            <Table
              head={["version", "components", "added", "removed", "fingerprint"]}
              total={cbomRows.length} rows={cbomRows.slice(0, 12).map((v) => [
                <span className="num" style={{ fontWeight: 600 }}>v{String(v.version)}</span>,
                <span className="num">{String(v.component_count)}</span>,
                <span className="num" style={{ color: (v.added as any[] || []).length ? "var(--green)" : undefined }}>
                  +{(v.added as any[] || []).length}
                </span>,
                <span className="num" style={{ color: (v.removed as any[] || []).length ? "var(--red)" : undefined }}>
                  −{(v.removed as any[] || []).length}
                </span>,
                <span className="mono muted">{String(v.fingerprint).slice(0, 12)}…</span>,
              ])}
            />
          ) : <span className="muted">No CBOM versions yet.</span>}
        </Panel>

        <Panel title="Operational health" sub="connectors + agents swept live · fixed SLO thresholds · critical targets raise alerts">
          {(() => {
            const h = health.data as any;
            if (!h) return <span className="muted">Sweeping connectors and agents…</span>;
            const conns = h.connectors?.states || {};
            const agents = h.agents?.states || {};
            const alerts = [...(h.connectors?.targets || []), ...(h.agents?.targets || [])]
              .filter((t) => ["UNHEALTHY", "OFFLINE"].includes(t.state));
            return (
              <>
                <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 10 }}>
                  {[
                    ["connectors total", h.connectors?.total],
                    ["agents total", h.agents?.total],
                    ["healthy conns", conns.HEALTHY ?? 0],
                    ["healthy agents", agents.HEALTHY ?? 0],
                  ].map(([k, v]) => (
                    <Badge key={String(k)} tone="cyan">
                      <strong className="num">{String(v ?? 0)}</strong> {k}
                    </Badge>
                  ))}
                  <Badge tone={h.alert_count ? "red" : "green"}>
                    {h.alert_count ? `${h.alert_count} alert(s)` : "all systems nominal"}
                  </Badge>
                </div>
                {alerts.length ? (
                  <Table
                    head={["target", "kind", "state", "reason"]}
                    total={alerts.length} rows={alerts.slice(0, 12).map((t) => [
                      <span className="mono">{String(t.target_id).slice(0, 18)}</span>,
                      <span className="muted">{t.kind}</span>,
                      <Badge tone={t.state === "OFFLINE" ? "red" : "amber"}>{t.state}</Badge>,
                      <span className="muted">{(t.reasons || []).join("; ").slice(0, 70)}</span>,
                    ])}
                  />
                ) : <span className="muted">No unhealthy connectors or agents. Offline agents ({">"}180s heartbeat), stale links ({">"}24h), and auth failures are flagged automatically.</span>}
              </>
            );
          })()}
        </Panel>

        <Panel title="Agent fleet" sub="Cryptava host agents">
          <p style={{ marginTop: 0 }}>
            <strong className="num">{agentRows.filter((a) => String(a.status) !== "retired").length}</strong>{" "}
            <span className="muted">agents enrolled</span>
          </p>
          <Link to="/cryptava" className="btn" style={{ textDecoration: "none", display: "inline-block" }}>
            Open Cryptava agents →
          </Link>
        </Panel>

        <Panel
          title="Detection accuracy — real benchmark"
          sub="shipping detector scored against labelled ground truth (85 cases / 9 datasets) · live benchmark only"
        >
          <div style={{ marginBottom: 10 }}>
            <button className="btn" onClick={() => void runBenchmark()} disabled={realBenchmark.running}>
              {realBenchmark.running ? "running…" : "run real benchmark"}
            </button>
          </div>
          {(() => {
            const b = latestBenchmark as any;
            if (!b) return <span className="muted">No benchmark run yet — run the real detector over the labelled datasets to measure precision/recall/F1.</span>;
            const pct = (x: unknown) => (x == null ? "—" : `${(Number(x) * 100).toFixed(1)}%`);
            const per = (b.detail?.per_dataset || {}) as Record<string, any>;
            const meets = b.meets_95_target ?? b.detail?.meets_95_target;
            return (
              <>
                <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 10, alignItems: "center" }}>
                  {[
                    ["precision", pct(b.precision)], ["recall", pct(b.recall)],
                    ["f1", pct(b.f1)], ["false-pos rate", pct(b.false_positive_rate)],
                    ["accuracy", pct(b.accuracy)], ["cases", b.total_cases ?? b.detail?.total_cases ?? "—"],
                  ].map(([k, v]) => (
                    <Badge key={String(k)} tone="cyan">
                      <strong className="num">{String(v)}</strong> {k}
                    </Badge>
                  ))}
                  <Badge tone={meets ? "green" : "red"}>
                    {meets ? "meets ≥95% target" : "BELOW 95% target"}
                  </Badge>
                </div>
                {Object.keys(per).length > 0 && (
                  <Table
                    head={["dataset", "cases", "precision", "recall", "f1"]}
                    rows={Object.entries(per).map(([name, m]: [string, any]) => [
                      <span className="mono">{name}</span>,
                      <span className="num">{m.cases}</span>,
                      <span className="num">{pct(m.precision)}</span>,
                      <span className="num">{pct(m.recall)}</span>,
                      <span className="num" style={{ color: Number(m.f1) >= 0.95 ? "var(--green)" : "var(--red)" }}>{pct(m.f1)}</span>,
                    ])}
                  />
                )}
              </>
            );
          })()}
        </Panel>

        <Panel title="Post-migration verification" sub="DETECT→ANALYZE→VERIFY · deterministic weak-crypto regression check · PASS closes findings, FAIL raises a critical ticket">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
            <label className="muted" style={{ fontSize: 12 }}>PRE-migration findings (JSON array)
              <textarea
                rows={4} style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                placeholder='[{"id":"f1","asset_id":"a1","algorithm":"RSA","key_size":1024,"status":"DISALLOWED"}]'
                value={migration.pre}
                onChange={(e) => setMigration((m) => ({ ...m, pre: e.target.value }))}
              />
            </label>
            <label className="muted" style={{ fontSize: 12 }}>POST-migration findings (JSON array)
              <textarea
                rows={4} style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                placeholder='[{"id":"f1","asset_id":"a1","algorithm":"ECDSA","key_size":256,"status":"CURRENT"}]'
                value={migration.post}
                onChange={(e) => setMigration((m) => ({ ...m, post: e.target.value }))}
              />
            </label>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <button className="btn" onClick={() => void validateMigration()}>validate migration</button>
            {migration.result && (
              <Badge tone={migration.result.passed ? "green" : "red"}>
                {migration.result.passed ? "PASS" : "FAIL"} — {migration.result.action || ""}
              </Badge>
            )}
          </div>
          {migration.result && (
            <div style={{ marginTop: 10 }} className="muted">
              <span className="num" style={{ color: "var(--green)" }}>{migration.result.remediated?.length ?? 0} remediated</span>
              {" · "}
              <span className="num" style={{ color: migration.result.regressions?.length ? "var(--red)" : undefined }}>
                {migration.result.regressions?.length ?? 0} regression(s)
              </span>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
