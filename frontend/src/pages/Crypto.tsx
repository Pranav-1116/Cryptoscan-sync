import React, { useMemo } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useApi, usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import {
  apiAlgorithmCatalog,
  apiProtocolCatalog,
  apiLiveInventory,
  AlgorithmEntry,
  ProtocolEntry,
  LiveInventory,
} from "../lib/api.js";

/* Cryptography overview — live catalogs (canonical algorithm + network
   registries) plus the live scan inventory (libraries, certificates).
   Zero demo data; honest empty/offline states until a scan runs. */

const TONE: Record<string, string> = {
  DISALLOWED: "red", DEPRECATED: "amber", RESTRICTED: "amber",
  ALLOWED: "green", REQUIRED: "green", UNKNOWN: "",
};

function quantumBadge(a: AlgorithmEntry) {
  if (a.quantum_vulnerable) return <Badge tone="red">Shor — vulnerable</Badge>;
  if (a.quantum_impact === "grover") return <Badge tone="cyan">Grover</Badge>;
  if (String(a.family).includes("pqc")) return <Badge tone="green">PQC safe</Badge>;
  return <Badge tone="amber">—</Badge>;
}

export default function Crypto() {
  const algo = useApi(() => apiAlgorithmCatalog(), []);
  const proto = useApi(() => apiProtocolCatalog(), []);
  const inv = usePollingApi(apiLiveInventory, 9000);

  const algorithms: AlgorithmEntry[] = useMemo(() => algo.data?.algorithms ?? [], [algo.data]);
  const protocols: ProtocolEntry[] = useMemo(() => proto.data?.protocols ?? [], [proto.data]);
  const inventory: LiveInventory | null = inv.data ?? null;

  const live = algo.source === "live";
  const statusCounts = algo.data?.counts_by_status ?? {};
  const quantumVulnerable = algorithms.filter((a) => a.quantum_vulnerable).length;
  const pqcSafe = algorithms.filter((a) => String(a.family).includes("pqc")).length;
  const cleartextServices = protocols.filter((p) => !p.encrypted).length;

  const kpis: Array<[string, number]> = [
    ["algorithms catalog", algorithms.length],
    ["quantum-vulnerable", quantumVulnerable],
    ["PQC algorithms", pqcSafe],
    ["network services", protocols.length],
    ["cleartext services", cleartextServices],
    ["crypto libraries (live)", inventory?.counts.libraries ?? 0],
    ["certificates (live)", inventory?.counts.certificates ?? 0],
  ];

  // Top disallowed / vulnerable algorithms surfaced for action.
  const priority = useMemo(() => {
    const flagged = algorithms
      .filter((a) => a.status === "DISALLOWED" || a.quantum_vulnerable)
      .sort((a, b) => (a.status === "DISALLOWED" ? -1 : 1) - (b.status === "DISALLOWED" ? -1 : 1))
      .slice(0, 12);
    return flagged;
  }, [algorithms]);

  return (
    <>
      <PageHead
        crumb="discovery / cryptography"
        title="Cryptography"
        sub="Canonical algorithm & network-service catalogs with quantum/risk verdicts, plus live libraries and certificates"
        right={
          <>
            <LiveBadge source={live ? "live" : "offline"} />
            <Badge tone={live ? "cyan" : ""}><span className="dot" /> {algorithms.length.toLocaleString()} ALGORITHMS</Badge>
          </>
        }
      />

      <div className="grid cols-5" style={{ marginBottom: 16 }}>
        {kpis.map(([k, v]) => (
          <div className="kpi" key={k}><span className="k">{k}</span><span className="v">{v.toLocaleString()}</span></div>
        ))}
      </div>

      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        {Object.entries(statusCounts).sort().map(([s, n]) => (
          <Badge key={s} tone={TONE[s] ?? ""}>{s}: {n}</Badge>
        ))}
      </div>

      <Panel title="Priority algorithms" sub="disallowed or quantum-vulnerable entries from the canonical registry">
        <Table
          head={["algorithm", "family", "key/digest", "status", "quantum", "notes"]}
          rows={priority.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.algorithm}</span>,
            <Badge tone="violet">{a.family}</Badge>,
            <span className="num">{a.key_size ?? "—"}</span>,
            <Badge tone={TONE[a.status] ?? ""}>{a.status}</Badge>,
            quantumBadge(a),
            <span className="dim" style={{ fontSize: 12 }}>{a.notes ?? ""}</span>,
          ])}
        />
        {!priority.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live ? "No disallowed/vulnerable algorithms in catalog." : "Backend offline — algorithm catalog unavailable."}
          </div>
        )}
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Network service posture" sub="cleartext vs encrypted from the network registry">
          <Table
            head={["service", "port", "encryption", "status"]}
            rows={protocols
              .slice()
              .sort((a, b) => Number(a.encrypted) - Number(b.encrypted))
              .slice(0, 10)
              .map((p) => [
                <span className="mono">{p.protocol}</span>,
                <span className="num">{p.port ?? "—"}</span>,
                p.encrypted ? <Badge tone="green">TLS</Badge> : <Badge tone="red">cleartext</Badge>,
                <Badge tone={TONE[p.status] ?? ""}>{p.status}</Badge>,
              ])}
          />
          {!protocols.length && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>Backend offline — network catalog unavailable.</div>}
        </Panel>
        <Panel title="Crypto libraries (live)" sub="libraries observed on runtime hosts">
          <Table
            head={["library", "version", "status", "processes"]}
            rows={(inventory?.libraries ?? []).slice(0, 10).map((l) => [
              <span className="mono">{l.name ?? "—"}</span>,
              <span className="num">{l.version ?? "—"}</span>,
              <Badge tone={String(l.status || "").toLowerCase().includes("deprecat") ? "amber" : "green"}>{l.status ?? "—"}</Badge>,
              <span className="num">{l.processes ?? 0}</span>,
            ])}
          />
          {!(inventory?.libraries?.length) && (
            <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
              No live libraries yet — run a runtime scan in Operations → Realtime scanners.
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
