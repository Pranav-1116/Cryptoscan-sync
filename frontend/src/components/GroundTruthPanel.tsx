import React, { useMemo, useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import {
  apiEstateTwinGroundTruth,
  type EstateGroundTruthMeasurement,
  type EstateGroundTruthClaimResult,
} from "../lib/api.js";

/* ─── The declaration, measured ──────────────────────────────────────────────
   Spec 94 §4 draws a coverage table with a denominator the platform cannot compute:
   "Servers 118/120" is a fact about the *bank's* inventory, not about a collector run.
   So the bank declares it, and this panel reports the disagreement.

   Three things it refuses to do, because each one would turn a question into a claim:
     · print a percentage for a class nobody declared a count for;
     · print 112% — finding more than was declared is a disagreement, not coverage;
     · call an estate missing an asset "wrong" — the bank may simply not have told us.
──────────────────────────────────────────────────────────────────────────── */

const tone = (status: string) =>
  status === "COMPLETE" ? "green"
    : status === "PARTIAL" ? "amber"
      : status === "OVER_DECLARED" || status === "EMPTY" ? "red"
        : "slate";

const claimTone = (verdict: string) =>
  verdict === "MATCHED" ? "green"
    : verdict === "CONTRADICTED" ? "red"
      : verdict === "MISSING_FROM_ESTATE" ? "amber"
        : "slate";

const SAMPLE = `declared_by,asset_population,claims
bank/inventory-2026Q4,
  HOST=120;APPLICATION=400;HSM=8;DATABASE=50;LOAD_BALANCER=35,
  see the API schema`;

export default function GroundTruthPanel() {
  const [declaredBy, setDeclaredBy] = useState("bank/inventory");
  const [population, setPopulation] = useState("HOST=120\nAPPLICATION=400\nHSM=8\nDATABASE=50\nLOAD_BALANCER=35");
  const [claims, setClaims] = useState(
    '[\n  {"claim_id": "c1", "type": "ASSET_PRESENCE", "asset": "Payment API"},\n'
    + '  {"claim_id": "c2", "type": "OWNERSHIP", "asset": "Payment API", "owner": "Payments Platform"}\n]',
  );
  const [data, setData] = useState<EstateGroundTruthMeasurement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const parsedPopulation = useMemo(() => {
    const result: Record<string, number> = {};
    for (const line of population.split("\n")) {
      const [key, value] = line.split("=");
      if (!key || key.trim() === "") continue;
      const count = Number((value ?? "").trim());
      // a non-number is passed through as-is so the engine can say it has no denominator
      result[key.trim().toUpperCase()] = Number.isFinite(count) ? count : Number.NaN;
    }
    return result;
  }, [population]);

  const run = async () => {
    setBusy(true);
    setError(null);
    let parsedClaims: Array<Record<string, unknown>> = [];
    try {
      parsedClaims = claims.trim() ? JSON.parse(claims) : [];
    } catch {
      setData(null);
      setError("the claims are not valid JSON — nothing was measured");
      setBusy(false);
      return;
    }
    const result = await apiEstateTwinGroundTruth({
      declared_by: declaredBy,
      asset_population: parsedPopulation,
      claims: parsedClaims,
    });
    if (result.ok) setData(result.data);
    else {
      setData(null);
      // a refused declaration is not a clean estate
      setError("the declaration could not be measured — that is not 'the estate agrees'");
    }
    setBusy(false);
  };

  const rows = data?.population?.rows ?? [];
  const results = data?.claims?.results ?? [];
  const disagreements = data?.population?.disagreements ?? [];

  return (
    <Panel
      title="Declared population"
      sub="what the bank says is there, measured against what the evidence holds"
      style={{ padding: "12px 14px" }}
    >
      <div style={{ display: "grid", gap: 8, marginBottom: 10 }}>
        <label style={{ fontSize: 11, color: "var(--dim)" }}>
          declared by
          <input
            value={declaredBy}
            onChange={(event) => setDeclaredBy(event.target.value)}
            aria-label="declared by"
            style={{ display: "block", width: "100%", marginTop: 3, fontFamily: "var(--mono)", fontSize: 11 }}
          />
        </label>
        <label style={{ fontSize: 11, color: "var(--dim)" }}>
          asset population — one CLASS=count per line
          <textarea
            value={population}
            onChange={(event) => setPopulation(event.target.value)}
            rows={5}
            aria-label="asset population"
            style={{ display: "block", width: "100%", marginTop: 3, fontFamily: "var(--mono)", fontSize: 11 }}
          />
        </label>
        <label style={{ fontSize: 11, color: "var(--dim)" }}>
          claims (JSON)
          <textarea
            value={claims}
            onChange={(event) => setClaims(event.target.value)}
            rows={5}
            aria-label="claims"
            style={{ display: "block", width: "100%", marginTop: 3, fontFamily: "var(--mono)", fontSize: 11 }}
          />
        </label>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <button onClick={() => void run()} disabled={busy} style={{ padding: "4px 12px", fontSize: 11.5 }}>
            {busy ? "measuring…" : "measure"}
          </button>
          <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{SAMPLE.split("\n")[0]}</span>
        </div>
      </div>

      {error && <div style={{ fontSize: 11, color: "var(--red)" }}>{error}</div>}

      {data && (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginBottom: 8 }}>
            <Badge tone="violet">DECLARED BY {data.declared_by}</Badge>
            <Badge tone="slate">{data.population?.classes_with_a_denominator ?? 0} classes with a count</Badge>
            {disagreements.length > 0 && <Badge tone="red">{disagreements.length} disagreement(s)</Badge>}
          </div>

          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr><th>Class</th><th>Declared</th><th>Collected</th><th>Evidenced</th><th>Status</th></tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.asset_type}>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{row.asset_type}</td>
                  <td style={{ fontSize: 11 }}>{row.declared === null ? "— not declared" : row.declared}</td>
                  <td style={{ fontSize: 11 }}>{row.collected}</td>
                  <td style={{ fontSize: 11, color: row.unevidenced > 0 ? "var(--amber)" : "var(--dim)" }}>
                    {row.evidenced}{row.unevidenced > 0 ? ` (${row.unevidenced} with no evidence)` : ""}
                  </td>
                  <td>
                    <Badge tone={tone(row.status)}>{row.status}</Badge>
                    {/* a percentage only where a denominator means something */}
                    {row.collected_percent !== null && (
                      <span style={{ fontSize: 10.5, color: "var(--faint)", marginLeft: 6 }}>
                        {row.collected_percent}%
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)", lineHeight: 1.5 }}>
            {data.population?.meaning}
          </div>

          {results.length > 0 && (
            <div style={{ marginTop: 12, borderTop: "1px dashed var(--line)", paddingTop: 8 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
                {Object.entries(data.claims?.by_type ?? {}).map(([type, counts]) => (
                  counts.declared > 0 && (
                    <Badge key={type} tone={counts.CONTRADICTED > 0 ? "red" : "slate"}>
                      {type}: {counts.MATCHED}/{counts.declared} agreed
                    </Badge>
                  )
                ))}
              </div>
              {results.map((claim: EstateGroundTruthClaimResult, index: number) => (
                <div key={claim.claim_id ?? index} style={{ fontSize: 11, lineHeight: 1.6 }}>
                  <Badge tone={claimTone(claim.verdict)}>{claim.verdict}</Badge>{" "}
                  <span style={{ fontFamily: "var(--mono)" }}>{claim.type}</span>{" "}
                  <span style={{ color: "var(--dim)" }}>{claim.reason}</span>
                </div>
              ))}
              <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)", lineHeight: 1.5 }}>
                {data.claims?.meaning}
              </div>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
