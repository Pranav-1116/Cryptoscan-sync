import React, { useMemo } from "react";
import { Panel, Badge, Bar, Ring, Table, PageHead } from "../components/ui.jsx";
import { useApi, usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiAlgorithmCatalog, apiLiveBom, AlgorithmEntry, LiveBomResponse } from "../lib/api.js";

/* PQC readiness dashboard — two complementary views of quantum posture:
   1. ESTATE (top): the actual crypto components observed in live scans
      (GET /live-scan/bom) bucketed by quantum verdict — this is what's really
      deployed and needs migration.
   2. CATALOG (below): the deterministic algorithm-level picture
      (Shor-vulnerable vs PQC-safe vs Grover) from GET /algorithms/catalog.
   Both are real data; an estate with no scans shows an honest empty state. */

const PQC_FAMILIES = ["kem-pqc", "signature-pqc"];

function quantumBucket(status: string | null | undefined): "vulnerable" | "at_risk" | "safe" | "unclassified" {
  const q = String(status ?? "").toLowerCase();
  if (q.includes("vuln") || q.includes("broken")) return "vulnerable";
  if (q.includes("risk") || q.includes("deprecat")) return "at_risk";
  if (q.includes("safe") || q.includes("pqc") || q.includes("ready")) return "safe";
  return "unclassified";
}

export default function Pqc() {
  const res = useApi(() => apiAlgorithmCatalog(), []);
  const algos: AlgorithmEntry[] = useMemo(() => res.data?.algorithms ?? [], [res.data]);
  const live = res.source === "live";

  // estate BOM (real deployed components)
  const bomRes = usePollingApi(apiLiveBom, 8000);
  const bom = ((bomRes.data as LiveBomResponse | null)?.cbom ?? {}) as any;
  const estateComps: any[] = bom.components ?? [];
  const estateCounts: Record<string, number> = bom.counts ?? {};
  const bomLive = bomRes.source === "live";

  const vulnerable = algos.filter((a) => a.quantum_vulnerable);
  const pqcSafe = algos.filter((a) => PQC_FAMILIES.includes(String(a.family)));
  const grover = algos.filter((a) => a.quantum_impact === "grover" && !a.quantum_vulnerable);
  const total = algos.length || 1;
  const safeCount = pqcSafe.length + grover.length;
  const readiness = Math.round((safeCount / total) * 100);

  // estate exposure buckets from real components
  const estateBuckets = useMemo(() => {
    const b = { vulnerable: [] as any[], at_risk: [] as any[], safe: [] as any[], unclassified: [] as any[] };
    for (const c of estateComps) b[quantumBucket(c.quantum_status)].push(c);
    return b;
  }, [estateComps]);
  const estateTotal = estateComps.length;

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

  const exposureRows: Array<{ k: string; n: number; tone: string; items: any[] }> = [
    { k: "quantum vulnerable", n: estateBuckets.vulnerable.length, tone: "red", items: estateBuckets.vulnerable },
    { k: "at risk / deprecated", n: estateBuckets.at_risk.length, tone: "amber", items: estateBuckets.at_risk },
    { k: "quantum safe / PQC", n: estateBuckets.safe.length, tone: "green", items: estateBuckets.safe },
    { k: "unclassified", n: estateBuckets.unclassified.length, tone: "slate", items: estateBuckets.unclassified },
  ];

  return (
    <>
      <PageHead
        crumb="post-quantum / pqc readiness"
        title="PQC readiness dashboard"
        sub="Estate exposure from live scans, backed by the deterministic algorithm catalog (Shor · Grover · PQC)"
        right={<><LiveBadge source={res.source} /><Badge tone="violet">{vulnerable.length} shor-vulnerable algos</Badge></>}
      />

      {/* ── ESTATE exposure (real deployed components) ────────────────── */}
      <Panel
        title="Estate quantum exposure"
        sub={estateTotal
          ? `${estateTotal} deployed crypto component${estateTotal === 1 ? "" : "s"} from live scans · colored by quantum verdict`
          : "deployed components from the live scan-derived CBOM"}
      >
        {estateTotal === 0 ? (
          <div className="dim" style={{ fontSize: 13, padding: "16px 4px" }}>
            {bomLive
              ? "No deployed crypto components yet — run runtime + universal/container scans in Operations → Realtime scanners. Estate exposure is measured from observed components only."
              : "Backend offline — live CBOM unavailable."}
          </div>
        ) : (
          <div className="pqc-exposure">
            {exposureRows.map((r) => (
              <div key={r.k} className="pqc-row">
                <span className="pqc-name">{r.k}</span>
                <div className="pqc-bar"><Bar value={estateTotal ? r.n / estateTotal : 0} tone={r.tone} /></div>
                <span className="pqc-n" style={{ color: r.n && r.tone === "red" ? "var(--red)" : r.n && r.tone === "amber" ? "var(--amber)" : r.n && r.tone === "green" ? "var(--green)" : undefined }}>
                  {r.n}
                </span>
              </div>
            ))}
            <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 4 }}>
              {estateBuckets.vulnerable.concat(estateBuckets.at_risk).slice(0, 12).map((c, i) => (
                <Badge key={`${c.name}-${i}`} tone={quantumBucket(c.quantum_status) === "vulnerable" ? "red" : "amber"}>
                  {c.name}{c.version ? ` ${c.version}` : ""}
                </Badge>
              ))}
              {estateCounts.quantum_vulnerable != null && (
                <span className="dim mono" style={{ fontSize: 11.5, marginInlineStart: "auto" }}>
                  classifier flags {estateCounts.quantum_vulnerable} quantum-vulnerable
                </span>
              )}
            </div>
          </div>
        )}
      </Panel>

      {/* ── CATALOG posture (deterministic algorithm registry) ───────── */}
      <div className="grid cols-2 mt">
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

      <Panel title="By cryptographic family" sub="quantum-safe vs Shor-vulnerable entries per family" className="mt">
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
          Estate migration mapping is produced by the deterministic what-if engine from the live CBOM
          (affected libraries · PQC-capable hardware · vendor roadmap · cloud readiness, with honest unknowns).
          <br /><a href="#/whatif" className="mono" style={{ fontSize: 12 }}>run the what-if simulator →</a>
        </div>
      </Panel>
    </>
  );
}
