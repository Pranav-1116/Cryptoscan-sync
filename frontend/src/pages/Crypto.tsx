import React, { useMemo } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { KpiMeter, GapBar, HBars, StackedBar, StateCell, VizEmpty } from "../components/viz.jsx";
import { useApi, usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useChannelRefresh } from "../lib/realtime.js";
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
   Zero demo data; honest empty/offline states until a scan runs.
   Every bar is scaled inside its own group; a live count that no scan has
   produced is drawn hatched, not as a zero. */

const TONE: Record<string, string> = {
  DISALLOWED: "red", DEPRECATED: "amber", RESTRICTED: "amber",
  ALLOWED: "green", REQUIRED: "green", UNKNOWN: "slate",
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
  const inv = usePollingApi(apiLiveInventory, 9000, [], { channels: ["crypto", "estate"] });
  useChannelRefresh(["crypto", "estate"], [inv.run]);

  const algorithms: AlgorithmEntry[] = useMemo(() => algo.data?.algorithms ?? [], [algo.data]);
  const protocols: ProtocolEntry[] = useMemo(() => proto.data?.protocols ?? [], [proto.data]);
  const inventory: LiveInventory | null = inv.data ?? null;

  const live = algo.source === "live";
  const statusCounts = algo.data?.counts_by_status ?? {};
  const quantumVulnerable = algorithms.filter((a) => a.quantum_vulnerable).length;
  const grover = algorithms.filter((a) => !a.quantum_vulnerable && a.quantum_impact === "grover").length;
  const pqcSafe = algorithms.filter((a) => String(a.family).includes("pqc")).length;
  const quantumOther = Math.max(0, algorithms.length - quantumVulnerable - grover - pqcSafe);
  const cleartextServices = protocols.filter((p) => !p.encrypted).length;
  const encryptedServices = protocols.length - cleartextServices;
  const liveObserved = Boolean(inventory && (inventory.generated_at || inventory.counts.libraries || inventory.counts.certificates));

  const kpis: Array<[string, number]> = [
    ["algorithms catalog", algorithms.length],
    ["quantum-vulnerable", quantumVulnerable],
    ["PQC algorithms", pqcSafe],
    ["network services", protocols.length],
    ["cleartext services", cleartextServices],
    ["crypto libraries (live)", inventory?.counts.libraries ?? 0],
    ["certificates (live)", inventory?.counts.certificates ?? 0],
  ];
  const kpiMax = Math.max(1, ...kpis.map(([, v]) => v));

  // Top disallowed / vulnerable algorithms surfaced for action.
  const priority = useMemo(() => {
    const flagged = algorithms
      .filter((a) => a.status === "DISALLOWED" || a.quantum_vulnerable)
      .sort((a, b) => (a.status === "DISALLOWED" ? -1 : 1) - (b.status === "DISALLOWED" ? -1 : 1))
      .slice(0, 12);
    return flagged;
  }, [algorithms]);

  const center = inventory?.cert_center;
  const centerOther = center ? Math.max(0, center.total - center.expired - center.expiring30 - center.weak_algorithm - center.unknown_owner) : 0;
  const certDays = (inventory?.certificates ?? []).filter((c) => typeof c.days === "number");
  const certUnknownAge = (inventory?.certificates ?? []).length - certDays.length;
  const libs = inventory?.libraries ?? [];

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

      <div className="grid cols-5" style={{ marginBottom: 12 }}>
        {kpis.slice(0, 5).map(([k, v]) => (
          <KpiMeter key={k} k={k} v={v.toLocaleString()} ratio={algorithms.length || protocols.length ? v / kpiMax : null} />
        ))}
      </div>

      <Panel title="Catalog composition" sub="what the registries contain — not an exposure estimate">
        <div className="grid cols-2" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div>
            <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 5 }}>algorithm status</div>
            <StackedBar
              segments={Object.entries(statusCounts).sort().map(([s, n]) => ({ key: s, label: s.toLowerCase(), value: n, tone: TONE[s] ?? "slate" }))}
              note={live ? "Every catalogued algorithm falls in exactly one status." : "Catalog offline — no status composition to draw."}
            />
          </div>
          <div>
            <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 5 }}>quantum posture</div>
            <StackedBar
              segments={[
                { key: "shor", label: "Shor-vulnerable", value: quantumVulnerable, tone: "red" },
                { key: "grover", label: "Grover-affected", value: grover, tone: "amber" },
                { key: "pqc", label: "PQC family", value: pqcSafe, tone: "green" },
                { key: "other", label: "no quantum verdict", value: quantumOther, tone: "slate" },
              ]}
              note="Verdicts as catalogued. PQC presence is not a migration plan and no percentage of a target is implied."
            />
          </div>
        </div>
        {!algorithms.length && <div style={{ marginTop: 10 }}><GapBar label="algorithm catalog" reason={live ? "The catalog returned no entries." : "Backend offline — algorithm catalog unavailable."} /></div>}
      </Panel>

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

      <div className="grid cols-2 mt" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <Panel title="Network service posture" sub="cleartext vs encrypted from the network registry">
          <div style={{ marginBottom: 10 }}>
            <StackedBar
              segments={[
                { key: "tls", label: "TLS", value: encryptedServices, tone: "green" },
                { key: "clear", label: "cleartext", value: cleartextServices, tone: "red" },
              ]}
              note="Service counts from the registry. Observed posture per host is on the network screen."
            />
          </div>
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

        <Panel title="Certificates observed (live)" sub="from the last runtime scan — expiry as the scan measured it">
          {!center ? (
            <GapBar label="certificate health" reason="No runtime scan has reported certificates for this estate, so none of these counts exists. Not measured is not zero." />
          ) : center.total === 0 ? (
            <VizEmpty title="No certificate in the last scan" note={`The scan on ${inventory?.host ?? "this host"} reported 0 certificates. That is its count over what it read, not proof the estate has none.`} />
          ) : (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(110px, 1fr))", gap: 8, marginBottom: 10 }}>
                <StateCell label="certificates" value={center.total} note="seen by the scan" />
                <StateCell label="expired" value={center.expired} tone={center.expired ? "red" : ""} />
                <StateCell label="expiring ≤30d" value={center.expiring30} tone={center.expiring30 ? "amber" : ""} />
                <StateCell label="weak algorithm" value={center.weak_algorithm} tone={center.weak_algorithm ? "amber" : ""} />
                <StateCell label="unknown owner" value={center.unknown_owner} tone={center.unknown_owner ? "amber" : ""} />
              </div>
              <StackedBar
                segments={[
                  { key: "expired", label: "expired", value: center.expired, tone: "red" },
                  { key: "expiring", label: "expiring ≤30d", value: center.expiring30, tone: "amber" },
                  { key: "weak", label: "weak algorithm", value: center.weak_algorithm, tone: "amber" },
                  { key: "owner", label: "unknown owner", value: center.unknown_owner, tone: "violet" },
                  { key: "other", label: "no flag", value: centerOther, tone: "green" },
                ]}
                note="A certificate can carry more than one flag, so these segments can overlap; they are the scan's own counters."
              />
              {certDays.length > 10 && (
                <div className="dim" style={{ fontSize: 11, marginTop: 8 }} role="status">
                  showing the first 10 of {certDays.length.toLocaleString()} measured certificates
                </div>
              )}
              <div style={{ marginTop: 10 }}>
                <HBars
                  unit="d"
                  rows={certDays.slice(0, 10).map((c) => ({ key: `${c.cn}-${c.endpoint}`, label: c.cn || c.endpoint || "unidentified", value: c.days as number, tone: (c.days as number) <= 30 ? "amber" : "green", note: `${c.endpoint} · ${c.status}` }))}
                  emptyTitle="No certificate expiry measured"
                  emptyNote="The scan reported certificates but no day counts, so no bar is drawn."
                />
                {certUnknownAge > 0 && <div className="mono" style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>{certUnknownAge} certificate(s) with no expiry figure — drawn as unknown, not as 0d</div>}
                <div className="mono" style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>bar = days remaining relative to the longest-lived certificate in this page</div>
              </div>
            </>
          )}
        </Panel>
      </div>

      <Panel title="Crypto libraries (live)" sub="libraries observed on runtime hosts">
        {!liveObserved ? (
          <GapBar label="crypto libraries" reason="No live inventory: run a runtime scan in Operations → Realtime scanners. An unrun scan is not an empty host." />
        ) : !libs.length ? (
          <VizEmpty title="No library in the last scan" note={`The scan on ${inventory?.host ?? "this host"} reported 0 libraries. That is its count over the processes it read, not proof the host loads none.`} />
        ) : (
          <>
            <HBars
              rows={libs.filter((l) => typeof l.processes === "number").slice(0, 12).map((l) => ({
                key: `${l.name}@${l.version}`,
                label: `${l.name ?? "unidentified"} ${l.version ?? ""}`.trim(),
                value: l.processes as number,
                tone: String(l.status || "").toLowerCase().includes("deprecat") ? "amber" : "green",
                note: `${l.status ?? "no status"} · ${l.package ?? "package not reported"}`,
              }))}
              emptyTitle="No library process counts"
              emptyNote="The scan returned libraries but no process counts, so no bar is drawn."
            />
            <div className="mono" style={{ fontSize: 10, color: "var(--faint)", marginTop: 5 }}>bar = processes using the library, relative to the most-used library in this page</div>
            <div style={{ marginTop: 10 }} className="dim">
              {(inventory?.counts.libraries ?? 0)} libraries · {(inventory?.counts.certificates ?? 0)} certificates · {inventory?.host ?? "host not reported"}
            </div>
          </>
        )}
      </Panel>
    </>
  );
}
