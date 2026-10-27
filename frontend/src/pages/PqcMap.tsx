import { Link } from "react-router-dom";
import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

/* PQC migration map (spec §21): live quantum-risk inventory by family +
   the deterministic migration waves. Candidate algorithms are the NIST
   FIPS 203/204 standards (real reference data); usage counts come only from
   the live inventory — never fabricated. */

interface Plan {
  inventory?: { total_sites?: number; vulnerable_sites?: number; pqc_ready_sites?: number; by_family?: Record<string, number>; by_threat_type?: Record<string, number> };
  waves?: Record<string, { focus?: string; site_count?: number }>;
  summary?: string;
}

const CANDIDATES = [
  { alg: "ML-KEM-768", use: "key encapsulation (FIPS 203)" },
  { alg: "ML-DSA-65", use: "digital signature (FIPS 204)" },
  { alg: "SLH-DSA", use: "stateless hash-based signature (FIPS 205)" },
];

export default function PqcMap() {
  const { data, loading, error } = useLive<Plan>("/api/v1/quantum/plan", {});
  const inv = data.inventory ?? {};
  const byFamily = inv.by_family ?? {};
  const total = inv.total_sites ?? 0;
  const ready = inv.pqc_ready_sites ?? 0;
  const overall = total ? Math.round((ready / total) * 100) : 0;

  return (
    <>
      <PageHead
        crumb="post-quantum / pqc migration map"
        title="PQC migration map"
        sub="Current state → vulnerable inventory by family → candidate PQC → migration waves"
        right={<Badge tone="violet">OVERALL READINESS {overall}%</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>

      <Panel title="Migration path" sub="current quantum-vulnerable crypto → NIST PQC targets, phased in waves">
        {total > 0 ? (
          <div className="tree" style={{ fontSize: 13.5, lineHeight: 2.0 }}>
            {inv.vulnerable_sites} vulnerable of {total} inventoried sites<br />
            {"  ↓ wave 1 (HNDL critical/high): "}{data.waves?.["1"]?.site_count ?? 0} sites<br />
            {"  ↓ wave 2 (remaining Shor-vulnerable): "}{data.waves?.["2"]?.site_count ?? 0} sites<br />
            {"  ↓ wave 3 (Grover symmetric sizing): "}{data.waves?.["3"]?.site_count ?? 0} sites
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13.5 }}>
            No inventory yet. Run discovery and a scan; the map derives vulnerable families and migration
            waves from the live CBOM. Use the <Link to="/what-if">what-if simulator</Link> for a specific current → target transition.
          </div>
        )}
        {data.summary && <p className="dim" style={{ fontSize: 12.5, marginTop: 10 }}>{data.summary}</p>}
      </Panel>

      <div className="grid cols-3 mt">
        <Panel title="Vulnerable by family" sub="what must migrate (live inventory)">
          <Table
            head={["family", "usages"]}
            rows={Object.entries(byFamily).length
              ? Object.entries(byFamily).map(([fam, n]) => [fam.toUpperCase(), <span className="num" key={fam}>{n}</span>])
              : [["—", <span className="dim" key="e">no data until a scan runs</span>]]}
          />
        </Panel>
        <Panel title="Candidate algorithms" sub="NIST FIPS 203 / 204 / 205 standards">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {CANDIDATES.map((c) => (
              <div key={c.alg}>
                <div className="spread" style={{ fontSize: 13.5 }}>
                  <span className="mono" style={{ fontWeight: 600 }}>{c.alg}</span>
                  <Badge tone="green">STANDARD</Badge>
                </div>
                <div className="dim" style={{ fontSize: 12 }}>{c.use}</div>
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Migration complexity" sub="per stage (deterministic guidance)">
          <Table
            head={["stage", "complexity"]}
            rows={[
              ["library upgrades", <Badge tone="green" key="1">LOW</Badge>],
              ["certificate re-key", <Badge tone="green" key="2">LOW</Badge>],
              ["protocol config", <Badge tone="amber" key="3">MEDIUM</Badge>],
              ["application code", <Badge tone="amber" key="4">MEDIUM</Badge>],
              ["HSM firmware", <Badge tone="red" key="5">HIGH</Badge>],
            ]}
          />
        </Panel>
      </div>

      <Panel title="Actions" className="mt">
        <div className="row">
          <Link to="/what-if" className="btn sm">Run what-if</Link>
          <Link to="/migration" className="btn sm">Open migration planner</Link>
        </div>
      </Panel>
    </>
  );
}
