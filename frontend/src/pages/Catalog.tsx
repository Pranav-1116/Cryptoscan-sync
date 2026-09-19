import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Tabs } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import {
  apiAlgorithmCatalog,
  apiProtocolCatalog,
  apiHardwareCatalog,
  AlgorithmEntry,
  ProtocolEntry,
  HardwareEntry,
} from "../lib/api.js";

/* Unified canonical catalogs — every algorithm (195), network service
   (100) and crypto-hardware device (60) the scanner can name, with live
   risk/quantum verdicts. Pure reference data from the real registries via
   GET /api/v1/{algorithms,network/protocols,hardware/catalog}. Zero demo
   data — empty until the backend answers. */

const TONE: Record<string, string> = {
  DISALLOWED: "red",
  DEPRECATED: "amber",
  RESTRICTED: "amber",
  UNKNOWN: "",
  ALLOWED: "green",
  REQUIRED: "green",
};

function StatusCounts({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
      {Object.entries(counts)
        .sort()
        .map(([s, n]) => (
          <Badge key={s} tone={TONE[s] ?? ""}>{s}: {n}</Badge>
        ))}
    </div>
  );
}

function Search({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={{ padding: "6px 10px", minWidth: 220 }}
    />
  );
}

function AlgorithmsTab() {
  const res = useApi(() => apiAlgorithmCatalog(), []);
  const rows: AlgorithmEntry[] = useMemo(() => res.data?.algorithms ?? [], [res.data]);
  const counts = res.data?.counts_by_status ?? {};
  const [q, setQ] = useState("");
  const [vulnOnly, setVulnOnly] = useState(false);
  const filtered = useMemo(() => {
    const n = q.trim().toLowerCase();
    return rows
      .filter((a) => (vulnOnly ? a.quantum_vulnerable : true))
      .filter((a) =>
        !n ? true : `${a.algorithm} ${a.family} ${a.notes ?? ""}`.toLowerCase().includes(n),
      )
      .sort((a, b) => String(a.algorithm).localeCompare(String(b.algorithm)));
  }, [rows, q, vulnOnly]);

  return (
    <>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        <StatusCounts counts={counts} />
        <label style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <input type="checkbox" checked={vulnOnly} onChange={(e) => setVulnOnly(e.target.checked)} />
          quantum-vulnerable only
        </label>
        <Search value={q} onChange={setQ} placeholder="search algorithm…" />
      </div>
      <Panel title={`Algorithms — ${filtered.length} of ${rows.length}`} sub="Shor = quantum-vulnerable · Grover = symmetric/hash (halved)">
        <Table
          head={["algorithm", "family", "key/digest", "status", "quantum", "notes"]}
          rows={filtered.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.algorithm}</span>,
            <Badge tone="violet">{a.family}</Badge>,
            <span className="num">{a.key_size ?? "—"}</span>,
            <Badge tone={TONE[a.status] ?? ""}>{a.status}</Badge>,
            a.quantum_vulnerable ? <Badge tone="red">Shor</Badge>
              : a.quantum_impact === "grover" ? <Badge tone="cyan">Grover</Badge>
              : a.family?.includes("pqc") ? <Badge tone="green">PQC safe</Badge> : <Badge>—</Badge>,
            <span className="dim" style={{ fontSize: 12 }}>{a.notes ?? ""}</span>,
          ])}
        />
        {!filtered.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {res.source === "live" ? "No algorithms match." : "Backend offline — algorithm catalog unavailable."}
          </div>
        )}
      </Panel>
    </>
  );
}

function ProtocolsTab() {
  const res = useApi(() => apiProtocolCatalog(), []);
  const rows: ProtocolEntry[] = useMemo(() => res.data?.protocols ?? [], [res.data]);
  const counts = res.data?.status_counts ?? {};
  const [q, setQ] = useState("");
  const [clearOnly, setClearOnly] = useState(false);
  const filtered = useMemo(() => {
    const n = q.trim().toLowerCase();
    return rows
      .filter((p) => (clearOnly ? !p.encrypted : true))
      .filter((p) => !n ? true : `${p.protocol} ${p.category} ${p.port ?? ""} ${p.notes ?? ""}`.toLowerCase().includes(n))
      .sort((a, b) => String(a.protocol).localeCompare(String(b.protocol)));
  }, [rows, q, clearOnly]);

  return (
    <>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        <StatusCounts counts={counts} />
        <label style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <input type="checkbox" checked={clearOnly} onChange={(e) => setClearOnly(e.target.checked)} />
          cleartext only
        </label>
        <Search value={q} onChange={setQ} placeholder="search service / port…" />
      </div>
      <Panel title={`Network services — ${filtered.length} of ${rows.length}`} sub="cleartext/broken services drive highest risk; OT/ICS passive-only">
        <Table
          head={["service", "port", "transport", "category", "encryption", "exposure", "status"]}
          rows={filtered.map((p) => [
            <span className="mono" style={{ fontWeight: 600 }}>{p.protocol}</span>,
            <span className="num">{p.port ?? "—"}</span>,
            (p.transport ?? "—").toUpperCase(),
            <Badge tone="violet">{p.category}</Badge>,
            p.encrypted ? <Badge tone="green">TLS</Badge> : <Badge tone="red">cleartext</Badge>,
            <span className="mono">{p.exposure ?? "—"}</span>,
            <Badge tone={TONE[p.status] ?? ""}>{p.status}</Badge>,
          ])}
        />
        {!filtered.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {res.source === "live" ? "No services match." : "Backend offline — network catalog unavailable."}
          </div>
        )}
      </Panel>
    </>
  );
}

function HardwareTab() {
  const res = useApi(() => apiHardwareCatalog(), []);
  const rows: HardwareEntry[] = useMemo(() => res.data?.devices ?? [], [res.data]);
  const counts = res.data?.status_counts ?? {};
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    const n = q.trim().toLowerCase();
    return rows
      .filter((d) => !n ? true : `${d.device} ${d.category} ${d.manufacturer ?? ""} ${d.notes ?? ""}`.toLowerCase().includes(n))
      .sort((a, b) => String(a.device).localeCompare(String(b.device)));
  }, [rows, q]);

  return (
    <>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
        <StatusCounts counts={counts} />
        <div style={{ marginLeft: "auto" }}><Search value={q} onChange={setQ} placeholder="search device…" /></div>
      </div>
      <Panel title={`Hardware devices — ${filtered.length} of ${rows.length}`} sub="TPM roots of trust · HSMs · secure elements · enclaves · accelerators">
        <Table
          head={["device", "category", "manufacturer", "attestation", "PQC-ready", "status"]}
          rows={filtered.map((d) => [
            <span className="mono" style={{ fontWeight: 600 }}>{d.device}</span>,
            <Badge tone="violet">{d.category}</Badge>,
            d.manufacturer || "—",
            d.attestation ? <Badge tone="cyan">attested</Badge> : "—",
            d.quantum_resistant ? <Badge tone="green">yes</Badge> : "—",
            <Badge tone={TONE[d.status] ?? ""}>{d.status}</Badge>,
          ])}
        />
        {!filtered.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {res.source === "live" ? "No devices match." : "Backend offline — hardware catalog unavailable."}
          </div>
        )}
      </Panel>
    </>
  );
}

export default function Catalog() {
  const [tab, setTab] = useState(0);
  const tabs = ["Algorithms", "Network services", "Hardware"];
  return (
    <>
      <PageHead
        crumb="catalogs / reference data"
        title="Canonical catalogs"
        sub="Every algorithm, network service and crypto-hardware device the scanner can name — with deterministic risk and quantum verdicts"
        right={<Badge tone="cyan">REFERENCE CATALOG</Badge>}
      />
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === 0 && <AlgorithmsTab />}
      {tab === 1 && <ProtocolsTab />}
      {tab === 2 && <HardwareTab />}
    </>
  );
}
