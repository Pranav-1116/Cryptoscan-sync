import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiRuntimeFindings, ApiResult } from "../lib/api.js";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";

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
  OK: "green",
  CURRENT: "green",
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

      {!hasData ? (
        <Panel title="No runtime agents reporting yet" sub="install and run the lightweight runtime agent on a machine to see its live cryptography">
          <div style={{ display: "grid", placeItems: "center", padding: "26px 10px" }}>
            <div className="frame" style={{ minHeight: 120, maxWidth: 760, width: "100%", display: "grid", placeItems: "center", border: "1px dashed var(--line-strong)", borderRadius: 12, color: "var(--faint)", fontSize: 13, padding: 24, textAlign: "center" }}>
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
              <div className="num" style={{ fontSize: 34, fontWeight: 700, color: summary.weak_findings ? "var(--red,#f87171)" : undefined }}>
                {summary.weak_findings ?? 0}
              </div>
              <div className="dim mono" style={{ fontSize: 12, marginTop: 6 }}>of {summary.total_findings ?? findings.length} total observations</div>
            </Panel>
            <Panel title="Top cryptography" sub="observed algorithm families (24h)">
              <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 4 }}>
                {(summary.top_algorithms ?? []).length === 0 && <span className="dim">—</span>}
                {(summary.top_algorithms ?? []).map((a) => (
                  <div key={a.algorithm} className="spread mono" style={{ fontSize: 12.5 }}>
                    <span>{a.algorithm}</span>
                    <span className="num">{a.observations}</span>
                  </div>
                ))}
              </div>
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
            <Panel title="Runtime observations" sub="click a row for full detail">
              <Table
                clickable
                head={["host", "process", "library", "status", "port(s)", "seen"]}
                rows={findings.map((f) => {
                  const e = f.extra ?? {};
                  const lib = [e.library, e.library_version].filter(Boolean).join(" ") || f.algorithm || "—";
                  const ports = (e.listening_ports as number[] | undefined) ?? [];
                  return [
                    <span className="mono">{f.hostname}</span>,
                    <span>{f.process_name}{f.pid ? <span className="dim mono"> · {f.pid}</span> : null}</span>,
                    <span className="mono">{lib}</span>,
                    <Badge tone={statusTone((e.library_status as string) ?? f.status)}>{(e.library_status as string) ?? f.status ?? "—"}</Badge>,
                    <span className="mono num">{ports.length ? ports.join(", ") : "—"}</span>,
                    <span className="mono">{fmtAgo(f.last_seen_at)}</span>,
                  ];
                })}
                onSelect={(i: number) => setSelected(findings[i] ?? null)}
              />
            </Panel>
          </div>

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

function DrawerLite({ title, sub, onClose, children }: { title: string; sub?: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "rgba(2,6,17,0.55)", zIndex: 60, display: "grid", placeItems: "center", padding: 24 }}
    >
      <div onClick={(e) => e.stopPropagation()} className="frame" style={{ width: "min(720px, 96vw)", maxHeight: "86vh", overflow: "auto", borderRadius: 14, padding: 20 }}>
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
