import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import {
  apiRuntimeFindings,
  apiLiveInventory,
  ApiResult,
  LiveInventory,
  apiRuntimeCryptoScope,
  apiRuntimeCryptoScopeSave,
  apiRuntimeCryptoEvents,
  apiRuntimeCryptoRisk,
  apiRuntimeCryptoAdapters,
  RuntimeCryptoScope,
  RuntimeCryptoEvent,
  RuntimeCryptoSummary,
  RuntimeRiskReport,
  RuntimeAdapterCatalog,
} from "../lib/api.js";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";

/* Runtime host agents — live process-level cryptography observed on real
   hosts by the runtime agent (`python -m runtime.main once --submit`).
   Every row here is a real observation submitted over the API; nothing is
   synthesised. Empty until an agent reports in. */

interface RuntimeFindingRow {
  id: string;
  scanner_id: string;
  kind: string;
  hostname: string;
  process_name: string;
  pid: number | null;
  algorithm: string | null;
  status: string | null;
  weak_tls: boolean;
  observation_count: number;
  last_seen_at: string | null;
  extra: Record<string, unknown>;
}

interface RuntimeFindingsResponse {
  total_count: number;
  summary: {
    total_findings?: number;
    weak_findings?: number;
    hosts?: number;
    observations_last_24h?: number;
    top_algorithms?: Array<{ algorithm: string; observations: number }>;
  };
  findings: RuntimeFindingRow[];
}

const TONE: Record<string, string> = {
  DISALLOWED: "red",
  DEPRECATED: "amber",
  RESTRICTED: "amber",
  ALLOWED: "green",
  OK: "green",
  CURRENT: "green",
  UNKNOWN: "",
};

function statusTone(status: string | null): string {
  if (!status) return "";
  return TONE[status.toUpperCase()] ?? "";
}

function fmtAgo(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso.includes("Z") || iso.includes("+") ? iso : iso + "Z").getTime();
  if (Number.isNaN(then)) return "—";
  const s = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export default function Runtime() {
  const { data, source } = usePollingApi<RuntimeFindingsResponse>(
    () => apiRuntimeFindings(100) as unknown as Promise<ApiResult<RuntimeFindingsResponse>>,
    15000,
    [],
  );
  const [selected, setSelected] = useState<RuntimeFindingRow | null>(null);

  const findings = data?.findings ?? [];
  const summary = data?.summary ?? {};

  // live host inventory from the on-box runtime scanner (this platform node)
  const liveInv = usePollingApi(
    () => apiLiveInventory() as unknown as Promise<ApiResult<LiveInventory>>,
    8000,
    [],
  );
  useRealtimeRefresh(liveInv.run);
  const hostProcs = liveInv.data?.processes ?? [];
  const hostLibs = liveInv.data?.libraries ?? [];

  const hosts = useMemo(() => {
    const map = new Map<string, { host: string; procs: Set<string>; weak: number; total: number; last: string | null }>();
    for (const f of findings) {
      const key = f.hostname || "unknown";
      const e = map.get(key) ?? { host: key, procs: new Set<string>(), weak: 0, total: 0, last: null };
      e.total += 1;
      if (f.weak_tls) e.weak += 1;
      if (f.process_name) e.procs.add(f.process_name);
      if (f.last_seen_at && (!e.last || f.last_seen_at > e.last)) e.last = f.last_seen_at;
      map.set(key, e);
    }
    return Array.from(map.values());
  }, [findings]);

  // risks first, then unknown (unmanaged), then healthy/current
  const statusRank = (s: string | null): number =>
    ({ DISALLOWED: 0, DEPRECATED: 1, RESTRICTED: 2, UNKNOWN: 3, ALLOWED: 4 } as Record<string, number>)[(s ?? "UNKNOWN").toUpperCase()] ?? 5;
  const orderedFindings = useMemo(
    () =>
      [...findings].sort((a, b) => {
        const sa = ((a.extra ?? {}).library_status as string) ?? a.status ?? "UNKNOWN";
        const sb = ((b.extra ?? {}).library_status as string) ?? b.status ?? "UNKNOWN";
        return statusRank(sa) - statusRank(sb);
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [findings],
  );

  const hasData = findings.length > 0;

  return (
    <>
      <PageHead
        crumb="operate / runtime hosts"
        title="Runtime hosts"
        sub="Live process-level cryptography observed on real machines by the runtime agent — TLS libraries, versions and listening endpoints"
        right={
          <div className="row">
            <Badge tone={hasData ? "green" : ""}><span className="dot" /> {summary.hosts ?? hosts.length} HOST{hosts.length === 1 ? "" : "S"}</Badge>
            {summary.weak_findings ? <Badge tone="red">{summary.weak_findings} WEAK / EOL</Badge> : null}
            <LiveBadge source={source} label={source === "live" ? "LIVE AGENT FEED" : "WAITING FOR AGENT"} />
          </div>
        }
      />

      {hostProcs.length > 0 && (
        <Panel
          title={`This node · live host crypto (${liveInv.data?.host ?? "?"})`}
          sub="processes with TLS/crypto libraries mapped, from the live runtime scanner"
        >
          <div className="row" style={{ gap: 10, marginBottom: 12 }}>
            <LiveBadge source="live" label="LIVE HOST SCAN" />
            <Badge tone="cyan">{hostProcs.length} crypto procs</Badge>
            <Badge>{hostLibs.length} libraries</Badge>
            <Badge tone="green">{hostProcs.filter((p) => p.status === "OK").length} OK</Badge>
            {hostProcs.filter((p) => p.status === "RISK").length > 0 && (
              <Badge tone="red">{hostProcs.filter((p) => p.status === "RISK").length} RISK</Badge>
            )}
          </div>
          <Table
            head={["pid", "process", "runtime", "TLS libraries", "listening", "status"]}
            rows={hostProcs.map((p) => [
              <span className="num">{p.pid ?? "—"}</span>,
              <span className="mono">{p.process}</span>,
              p.runtime || "—",
              <span style={{ fontSize: 12 }}>{(p.tls_libraries || []).join(", ") || "—"}</span>,
              p.listening_ports?.length ? <Badge tone="cyan">{p.listening_ports.join(", ")}</Badge> : <span className="faint">—</span>,
              <Badge tone={p.status === "RISK" ? "red" : "green"}>{p.status}</Badge>,
            ])}
          />
        </Panel>
      )}

      {!hasData ? (
        <Panel title="No runtime agents reporting yet" sub="install and run the lightweight runtime agent on a machine to see its live cryptography">
          <div style={{ display: "grid", placeItems: "center", padding: "26px 10px" }}>
            <div className="frame" style={{ minHeight: 120, maxWidth: 760, width: "100%", display: "grid", placeItems: "center", border: "1px dashed var(--line-strong)", borderRadius: "var(--r)", color: "var(--faint)", fontSize: 13, padding: 24, textAlign: "center" }}>
              No host has reported in yet. Run the runtime agent on a Linux machine to inventory its TLS libraries,
              versions and listening endpoints — findings appear here within seconds of submission.
            </div>
          </div>
          <AgentInstructions />
        </Panel>
      ) : (
        <>
          <div className="grid cols-3" style={{ marginBottom: 16 }}>
            <Panel title="Hosts reporting" sub="distinct machines with an agent">
              <div className="num" style={{ fontSize: 34, fontWeight: 700 }}>{summary.hosts ?? hosts.length}</div>
              <div className="dim mono" style={{ fontSize: 12, marginTop: 6 }}>
                {hosts.map((h) => h.host).join(", ")}
              </div>
            </Panel>
            <Panel title="Weak / EOL observations" sub="libraries past end-of-life or capable of weak TLS">
              <div className="num" style={{ fontSize: 34, fontWeight: 700, color: summary.weak_findings ? "var(--red)" : undefined }}>
                {summary.weak_findings ?? 0}
              </div>
              <div className="dim mono" style={{ fontSize: 12, marginTop: 6 }}>of {summary.total_findings ?? findings.length} total observations</div>
            </Panel>
            <Panel title="Library status" sub="verified versions across reporting hosts">
              {(() => {
                const byStatus = new Map<string, number>();
                for (const f of findings) {
                  const s = ((f.extra ?? {}).library_status as string) ?? f.status ?? "UNKNOWN";
                  byStatus.set(s, (byStatus.get(s) ?? 0) + 1);
                }
                const order = ["DISALLOWED", "DEPRECATED", "RESTRICTED", "UNKNOWN", "ALLOWED"];
                const entries = order.filter((s) => byStatus.has(s)).map((s) => [s, byStatus.get(s) ?? 0] as [string, number]);
                if (entries.length === 0) return <span className="dim">—</span>;
                return (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 4 }}>
                    {entries.map(([s, n]) => (
                      <div key={s} className="spread mono" style={{ fontSize: 12.5 }}>
                        <Badge tone={statusTone(s)}>{s}</Badge>
                        <span className="num">{n}</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </Panel>
          </div>

          <div className="grid cols-2">
            <Panel title="Hosts" sub="one row per machine running the runtime agent">
              <Table
                head={["host", "processes", "weak", "last seen"]}
                rows={hosts.map((h) => [
                  <span className="mono">{h.host}</span>,
                  <span className="num">{h.procs.size}</span>,
                  h.weak > 0 ? <Badge tone="red">{h.weak}</Badge> : <Badge tone="green">0</Badge>,
                  <span className="mono">{fmtAgo(h.last)}</span>,
                ])}
              />
            </Panel>
            <Panel title="Runtime observations" sub="every verified TLS library — risks first, then unmanaged, then current (click for detail)">
              <Table
                clickable
                head={["host", "process", "library", "status", "port(s)", "seen"]}
                rows={orderedFindings.map((f) => {
                  const e = f.extra ?? {};
                  const lib = [e.library, e.library_version].filter(Boolean).join(" ") || f.algorithm || "—";
                  const pkgLabel: string = e.package ? ` via ${e.package}${e.version_source ? ` (${e.version_source})` : ""}` : "";
                  const pkg = e.package ? <span className="dim mono">{pkgLabel}</span> : null;
                  const ports = (e.listening_ports as number[] | undefined) ?? [];
                  const st = (e.library_status as string) ?? f.status ?? "UNKNOWN";
                  return [
                    <span className="mono">{f.hostname}</span>,
                    <span>{f.process_name}{f.pid ? <span className="dim mono"> · {f.pid}</span> : null}</span>,
                    <span className="mono">{lib}{pkg}</span>,
                    <Badge tone={statusTone(st)}>{st}</Badge>,
                    <span className="mono num">{ports.length ? ports.join(", ") : "—"}</span>,
                    <span className="mono">{fmtAgo(f.last_seen_at)}</span>,
                  ];
                })}
                onSelect={(i: number) => setSelected(orderedFindings[i] ?? null)}
              />
            </Panel>
          </div>

          <RuntimeScopePanel />
          <RuntimeOperationsPanel />

          <Panel title="Deploy the runtime agent" sub="run on any Linux host to inventory its live cryptography — read-only, no root needed" className="mt">
            <AgentInstructions />
          </Panel>
        </>
      )}

      {selected && (
        <DrawerLite onClose={() => setSelected(null)} title={`${selected.process_name} · ${selected.hostname}`} sub={selected.scanner_id}>
          <Code>{JSON.stringify(selected, null, 2)}</Code>
        </DrawerLite>
      )}
    </>
  );
}

/* ── Runtime crypto scan engine (spec 92) ──
   Scope → observation → attribution level → risk. Everything shown here is an
   observed operation; an application with no event stays NOT_OBSERVED. */

const LEVEL_TONE: Record<number, string> = { 1: "green", 2: "cyan", 3: "violet", 4: "slate", 5: "amber", 6: "red" };

function levelLabel(level: number): string {
  if (level === 1) return "L1 crypto API";
  if (level === 2) return "L2 framework";
  if (level === 3) return "L3 audit";
  if (level === 4) return "L4 network";
  if (level === 5) return "L5 binary";
  return "L6 unknown";
}

function RuntimeScopePanel() {
  const scope = usePollingApi(() => apiRuntimeCryptoScope() as unknown as Promise<ApiResult<RuntimeCryptoScope>>, 20000, []);
  const [hosts, setHosts] = useState("");
  const [app, setApp] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const state = scope.data;

  const save = async () => {
    setBusy(true);
    setMsg(null);
    const now = Date.now();
    const result = await apiRuntimeCryptoScopeSave({
      name: "runtime-scope",
      hosts: hosts.split(",").map((item) => item.trim()).filter(Boolean),
      applications: app ? [app.trim()] : [],
      runtime_methods: ["CRYPTO_API_TRACE", "PROCESS_TELEMETRY"],
      data_restrictions: ["NO_PLAINTEXT", "NO_PRIVATE_KEYS", "NO_SECRET_KEYS", "NO_CUSTOMER_DATA"],
      collection_window: {
        from: new Date(now - 5 * 60 * 1000).toISOString(),
        to: new Date(now + 8 * 60 * 60 * 1000).toISOString(),
      },
    });
    if (result.data) {
      setMsg(result.data.permitted ? "scope saved — window open" : "scope saved — window closed");
      scope.run();
    } else {
      setMsg(result.error || "scope refused");
    }
    setBusy(false);
  };

  return (
    <Panel
      title="Runtime scope — what may be instrumented"
      sub="no approved scope, no observation: hosts, applications, methods, collection window and data restrictions are enforced per batch"
      className="mt"
    >
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <Badge tone={state?.configured ? "green" : "red"}>{state?.configured ? "SCOPE SAVED" : "NO SCOPE"}</Badge>
        <Badge tone={state?.permitted ? "green" : "amber"}>{state?.window?.state ?? "—"}</Badge>
        <span className="dim" style={{ fontSize: 11 }}>
          {state?.scope?.hosts?.length ? state.scope.hosts.join(", ") : "no approved host"}
          {state?.scope?.applications?.length ? ` · ${state.scope.applications.join(", ")}` : ""}
        </span>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
        <input
          value={hosts}
          onChange={(event) => setHosts(event.target.value)}
          aria-label="Approved hosts"
          placeholder="payments-prod-01, payments-prod-02"
          style={{ flex: "1 1 220px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
        />
        <input
          value={app}
          onChange={(event) => setApp(event.target.value)}
          aria-label="Approved application"
          placeholder="payments-api"
          style={{ flex: "0 1 160px", fontSize: 11, padding: "6px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }}
        />
        <button className="btn sm" type="button" onClick={() => void save()} disabled={busy}>
          {busy ? "Saving…" : "Approve scope"}
        </button>
        {msg && <span className="dim" style={{ fontSize: 11 }}>{msg}</span>}
      </div>
      <div className="faint" style={{ fontSize: 10.5, marginTop: 8 }}>
        plaintext, key material and customer data are refused per batch · the window closes collection automatically
      </div>
    </Panel>
  );
}

function RuntimeOperationsPanel() {
  const events = usePollingApi(
    () => apiRuntimeCryptoEvents(50) as unknown as Promise<ApiResult<{ events: RuntimeCryptoEvent[]; summary: RuntimeCryptoSummary }>>,
    15000,
    [],
  );
  const risk = usePollingApi(() => apiRuntimeCryptoRisk() as unknown as Promise<ApiResult<RuntimeRiskReport>>, 30000, []);
  const adapters = usePollingApi(() => apiRuntimeCryptoAdapters() as unknown as Promise<ApiResult<RuntimeAdapterCatalog>>, 60000, []);
  const rows = events.data?.events ?? [];
  const summary = events.data?.summary;
  const report = risk.data;

  return (
    <Panel
      title="Runtime crypto operations"
      sub="one row per observed operation — algorithm, mode, key size and parameters as reported, with the attribution level it came from"
      className="mt"
    >
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <Badge tone="slate">{summary?.events ?? 0} events</Badge>
        <Badge tone="cyan">{summary?.applications ?? 0} applications</Badge>
        {Object.entries(summary?.operations ?? {}).map(([operation, count]) => (
          <Badge key={operation} tone="violet">{operation} · {count as number}</Badge>
        ))}
        {(summary?.level6_events ?? 0) > 0 && <Badge tone="red">{summary?.level6_events} Level 6 blind spot</Badge>}
        {report && <Badge tone={report.verdict === "FAIL" ? "red" : report.verdict === "PASS" ? "green" : "amber"}>{report.verdict}</Badge>}
        {report?.pqc && <Badge tone="slate">PQC {report.pqc.verdict}</Badge>}
      </div>

      {rows.length === 0 && (
        <div className="dim" style={{ fontSize: 12, marginTop: 10 }}>
          no runtime event yet — an application with no event is NOT_OBSERVED, not crypto-free
        </div>
      )}

      {rows.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <Table
            head={["application", "process", "algorithm", "key size", "mode", "operation", "level", "provider"]}
            rows={rows.map((event) => [
              <span>{event.identity.application ?? "—"}</span>,
              <span className="mono" style={{ fontSize: 11 }}>{event.identity.process ?? "—"}</span>,
              <span className="mono" style={{ fontSize: 11 }}>{event.algorithm ?? "UNKNOWN"}</span>,
              <span className="num">{String(event.key_size)}</span>,
              <span className="mono" style={{ fontSize: 10.5 }}>{event.decomposition.mode ?? "—"}</span>,
              <Badge tone="violet">{event.operation}</Badge>,
              <Badge tone={LEVEL_TONE[event.attribution_level] ?? "slate"}>{levelLabel(event.attribution_level)}</Badge>,
              <span className="dim" style={{ fontSize: 10.5 }}>{event.source}</span>,
            ])}
          />
        </div>
      )}

      {report && report.failed.length > 0 && (
        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
          {report.failed.slice(0, 8).map((finding) => (
            <div key={`${finding.rule_id}-${finding.application}-${finding.algorithm}`} style={{ display: "flex", gap: 8 }}>
              <Badge tone={finding.severity === "critical" ? "red" : "amber"}>{finding.severity}</Badge>
              <div>
                <div style={{ fontSize: 11 }}>
                  <span className="mono" style={{ color: "var(--cyan)" }}>{finding.rule_id}</span>
                  <span className="dim"> · {finding.application ?? "—"} · {finding.algorithm ?? "UNKNOWN"}</span>
                </div>
                <div className="dim" style={{ fontSize: 11 }}>{finding.message}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {adapters.data && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 12 }}>
          {adapters.data.adapters.map((adapter) => (
            <Badge key={adapter.id} tone="slate">{adapter.framework}</Badge>
          ))}
        </div>
      )}
    </Panel>
  );
}

function DrawerLite({ title, sub, onClose, children }: { title: string; sub?: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "color-mix(in srgb, var(--bg) 55%, transparent)", zIndex: 60, display: "grid", placeItems: "center", padding: 24 }}
    >
      <div onClick={(e) => e.stopPropagation()} className="frame" style={{ width: "min(720px, 96vw)", maxHeight: "86vh", overflow: "auto", borderRadius: "var(--r)", padding: 20 }}>
        <div className="spread" style={{ marginBottom: 12 }}>
          <div>
            <div style={{ fontWeight: 700 }}>{title}</div>
            {sub ? <div className="dim mono" style={{ fontSize: 11.5 }}>{sub}</div> : null}
          </div>
          <button className="btn sm" onClick={onClose}>Close</button>
        </div>
        {children}
      </div>
    </div>
  );
}

function AgentInstructions() {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <p className="dim" style={{ fontSize: 13, margin: 0 }}>
        The runtime agent walks <span className="mono">/proc</span> (Linux) to find which processes have TLS libraries mapped
        (OpenSSL, GnuTLS, NSS, wolfSSL, mbedTLS, BoringSSL, LibreSSL), their versions, listening TCP ports, and flags
        end-of-life / weak-TLS libraries. It is read-only and does not require root for same-user processes.
      </p>
      <Code>{`# 1. point the agent at this platform
export CRYPTOSCAN_API_URL="<platform-url>"
export CRYPTOSCAN_API_TOKEN="<api-token>"

# 2. one-shot inventory of this machine + submit
python -m runtime.main once --submit

# or just print the inventory without submitting
python -m runtime.main processes`}</Code>
      <p className="dim mono" style={{ fontSize: 11.5, margin: 0 }}>
        Linux hosts only for process discovery. On macOS/Windows use <span className="mono">tap</span> (TLS forward proxy) or{" "}
        <span className="mono">import</span> (openssl s_client captures) — both are OS-agnostic.
      </p>
    </div>
  );
}
