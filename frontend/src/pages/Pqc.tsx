import React, { useMemo } from "react";
import { Panel, Badge, Bar, Ring, Table, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiAlgorithmCatalog, AlgorithmEntry } from "../lib/api.js";

/* PQC readiness — quantum posture derived from the live algorithm catalog
   (Shor = vulnerable, PQC families = safe, Grover = symmetric/hash). The
   estate-wide readiness % over observed usage comes from scans/CBOM; the
   catalog here gives the deterministic algorithm-level picture. Zero demo. */

const PQC_FAMILIES = ["kem-pqc", "signature-pqc"];

export default function Pqc() {
  const res = useApi(() => apiAlgorithmCatalog(), []);
  const algos: AlgorithmEntry[] = useMemo(() => res.data?.algorithms ?? [], [res.data]);
  const live = res.source === "live";

  const vulnerable = algos.filter((a) => a.quantum_vulnerable);
  const pqcSafe = algos.filter((a) => PQC_FAMILIES.includes(String(a.family)));
  const grover = algos.filter((a) => a.quantum_impact === "grover" && !a.quantum_vulnerable);
  const total = algos.length || 1;

  // catalog readiness = share of recognized algorithms that are quantum-safe
  // (PQC + Grover symmetric/hash) vs Shor-vulnerable.
  const safeCount = pqcSafe.length + grover.length;
  const readiness = Math.round((safeCount / total) * 100);

  const byFamily = useMemo(() => {
    const groups: Record<string, { vuln: AlgorithmEntry[]; safe: AlgorithmEntry[] }> = {};
    for (const a of algos) {
      const g = a.family || "other";
      groups[g] ??= { vuln: [], safe: [] };
      if (a.quantum_vulnerable) groups[g].vuln.push(a);
      else if (PQC_FAMILIES.includes(g) || a.quantum_impact === "grover") groups[g].safe.push(a);
    }
    return Object.entries(groups)
      .map(([group, v]) => ({ group, vuln: v.vuln, safe: v.safe }))
      .sort((x, y) => y.vuln.length - x.vuln.length);
  }, [algos]);

  const shorByName = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of vulnerable) {
      const bucket = /rsa/i.test(a.algorithm) ? "RSA / RSA-PSS / OAEP"
        : /ec|ecdsa|ecdh|ed25519|ed448|x25519|curve|p-|sm2|sm9|bls|brainpool/i.test(a.algorithm) ? "ECC / ECDH / EdDSA / curves"
        : /dh|mqv|srp|elgamal|opaque|cpace/i.test(a.algorithm) ? "DH / key agreement / PAKE"
        : /dsa/i.test(a.algorithm) ? "DSA"
        : "Other asymmetric";
      counts[bucket] = (counts[bucket] ?? 0) + 1;
    }
    return counts;
  }, [vulnerable]);

  return (
    <>
      <PageHead
        crumb="post-quantum / pqc readiness"
        title="PQC readiness"
        sub="Quantum posture of the algorithm catalog: Shor-vulnerable vs PQC-safe vs Grover (symmetric/hash)"
        right={<><LiveBadge source={res.source} /><Badge tone="violet">{vulnerable.length} SHOR-VULNERABLE</Badge></>}
      />
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Catalog quantum readiness" sub="share of recognized algorithms that are quantum-safe">
          <div style={{ display: "flex", alignItems: "center", gap: 26, flexWrap: "wrap" }}>
            <Ring pct={readiness / 100} label={`${readiness}%`} sub="SAFE SHARE" tone="violet" />
            <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: 1, minWidth: 240 }}>
              {[
                { k: `PQC-safe (${pqcSafe.length})`, v: (pqcSafe.length / total) * 100, tone: "green" },
                { k: `Grover symmetric/hash (${grover.length})`, v: (grover.length / total) * 100, tone: "cyan" },
                { k: `Shor-vulnerable (${vulnerable.length})`, v: (vulnerable.length / total) * 100, tone: "red" },
              ].map((r) => (
                <div key={r.k}>
                  <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                    <span>{r.k}</span><span className="mono">{Math.round(r.v)}%</span>
                  </div>
                  <Bar value={r.v / 100} tone={r.tone} />
                </div>
              ))}
            </div>
          </div>
        </Panel>
        <Panel title="Shor-vulnerable algorithms" sub="by class — these need PQC migration">
          <Table
            head={["class", "count"]}
            rows={Object.entries(shorByName)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => [k, <span className="num" key={k}>{v}</span>])}
          />
          {!vulnerable.length && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>{live ? "No Shor-vulnerable algorithms." : "Backend offline."}</div>}
        </Panel>
      </div>
      <Panel title="By cryptographic family" sub="quantum-safe vs Shor-vulnerable entries per family">
        <Table
          head={["family", "quantum-safe", "shor-vulnerable"]}
          rows={byFamily.map((p) => [
            <Badge tone="cyan">{p.group}</Badge>,
            <span className="row">{p.safe.slice(0, 8).map((s) => <Badge key={s.algorithm} tone="green">{s.algorithm}</Badge>)}{p.safe.length > 8 && <span className="dim"> +{p.safe.length - 8}</span>}</span>,
            <span className="row">{p.vuln.slice(0, 8).map((v) => <Badge key={v.algorithm} tone="red">{v.algorithm}</Badge>)}{p.vuln.length > 8 && <span className="dim"> +{p.vuln.length - 8}</span>}</span>,
          ])}
        />
      </Panel>
      <Panel title="Migration map" sub="current → affected → dependencies → candidate PQC → compatibility → complexity" className="mt">
        <div className="dim" style={{ fontSize: 13.5 }}>
          Estate migration mapping is produced by the deterministic what-if engine after a scan (from the live CBOM).
          <br /><a href="#/whatif" className="mono" style={{ fontSize: 12 }}>run the what-if simulator →</a>
        </div>
      </Panel>
    </>
  );
}
