import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, Drawer, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiAlgorithmCatalog, AlgorithmEntry } from "../lib/api.js";

/* Algorithm explorer — the canonical algorithm catalog (live, from
   GET /api/v1/algorithms). Quantum status, lifecycle status, family and key
   size per entry; click a row for detail. Zero demo data. */

const FILTERS = ["all", "quantum vulnerable", "PQC safe", "disallowed / deprecated"];

const TONE: Record<string, string> = {
  DISALLOWED: "red", DEPRECATED: "amber", RESTRICTED: "amber",
  ALLOWED: "green", REQUIRED: "green", UNKNOWN: "",
};

function quantumBadge(a: AlgorithmEntry) {
  if (a.quantum_vulnerable) return <Badge tone="red">Shor — vulnerable</Badge>;
  if (String(a.family).includes("pqc")) return <Badge tone="green">PQC safe</Badge>;
  if (a.quantum_impact === "grover") return <Badge tone="cyan">Grover</Badge>;
  return <Badge>—</Badge>;
}

export default function CryptoAssets() {
  const res = useApi(() => apiAlgorithmCatalog(), []);
  const algos: AlgorithmEntry[] = useMemo(() => res.data?.algorithms ?? [], [res.data]);
  const live = res.source === "live";

  const [f, setF] = useState(0);
  const [sel, setSel] = useState(-1);
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return algos
      .filter((a) => {
        if (f === 1) return !!a.quantum_vulnerable;
        if (f === 2) return String(a.family).includes("pqc");
        if (f === 3) return a.status === "DISALLOWED" || a.status === "DEPRECATED";
        return true;
      })
      .filter((a) => !needle || `${a.algorithm} ${a.family} ${a.notes ?? ""}`.toLowerCase().includes(needle))
      .sort((a, b) => a.algorithm.localeCompare(b.algorithm));
  }, [algos, f, q]);

  return (
    <>
      <PageHead
        crumb="inventory / crypto assets"
        title="Crypto assets"
        sub="Algorithm explorer — every algorithm the scanner can name, with quantum and lifecycle verdicts. Click a row for detail."
        right={
          <>
            <LiveBadge source={res.source} />
            <Badge tone={live ? "cyan" : ""}><span className="dot" /> {algos.length.toLocaleString()} ALGORITHMS</Badge>
          </>
        }
      />
      <div className="tabs">
        {FILTERS.map((t, i) => (
          <button key={t} className={i === f ? "active" : ""} onClick={() => setF(i)}>{t}</button>
        ))}
        <input
          placeholder="search algorithm…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ padding: "6px 10px", marginLeft: 12, minWidth: 200 }}
        />
      </div>
      <Panel title="Algorithm explorer" sub="deterministic classification from the shared canonical registry">
        <Table
          clickable
          selected={sel}
          onSelect={setSel}
          head={["algorithm", "family", "key/digest", "lifecycle", "quantum"]}
          rows={filtered.map((a) => [
            <span className="mono" style={{ fontWeight: 600 }}>{a.algorithm}</span>,
            <Badge tone="violet">{a.family}</Badge>,
            <span className="num">{a.key_size ?? "—"}</span>,
            <Badge tone={TONE[a.status] ?? ""}>{a.status}</Badge>,
            quantumBadge(a),
          ])}
        />
        {!filtered.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live ? "No algorithms match the current filter." : "Backend offline — algorithm catalog unavailable."}
          </div>
        )}
      </Panel>
      {sel >= 0 && filtered[sel] && <DetailDrawer alg={filtered[sel]} onClose={() => setSel(-1)} />}
    </>
  );
}

function DetailDrawer({ alg, onClose }: { alg: AlgorithmEntry; onClose: () => void }) {
  return (
    <Drawer title={alg.algorithm} sub={`${alg.family} · key/digest ${alg.key_size ?? "—"} bits`} onClose={onClose}>
      <div className="row" style={{ marginBottom: 16 }}>
        <Badge tone={TONE[alg.status] ?? ""}>{alg.status}</Badge>
        {quantumBadge(alg)}
      </div>
      <div className="kpi" style={{ marginBottom: 8 }}><span className="k">family</span><span className="v" style={{ fontSize: 18 }}>{alg.family}</span></div>
      <div className="kpi" style={{ marginBottom: 8 }}><span className="k">key / digest size</span><span className="v" style={{ fontSize: 18 }}>{alg.key_size ?? "—"}</span></div>
      <div className="kpi" style={{ marginBottom: 16 }}><span className="k">parameter kind</span><span className="v" style={{ fontSize: 18 }}>{alg.parameter_kind ?? "—"}</span></div>
      <Panel title="Verdict" sub="deterministic registry assessment">
        <div className="mono dim" style={{ fontSize: 12.5 }}>
          quantum impact: {alg.quantum_impact ?? "none (PQC / not asymmetric)"}<br />
          quantum-vulnerable: {alg.quantum_vulnerable ? "yes — Shor" : "no"}<br />
          {alg.notes || "no additional notes"}
        </div>
      </Panel>
      <Panel title="Usage & evidence" sub="from live scans" frame className="mt">
        <span className="dim" style={{ fontSize: 12.5 }}>
          Observed usage and confidence are linked from live scans/CBOM — run a universal source scan and check the
          dependency graph for where this algorithm appears.
        </span>
        <br /><a href="#/cbom" className="mono" style={{ fontSize: 12 }}>open CBOM →</a>
      </Panel>
    </Drawer>
  );
}
