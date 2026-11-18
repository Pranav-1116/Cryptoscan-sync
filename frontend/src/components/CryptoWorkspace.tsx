/**
 * Cryptographic Performance (docs/performance/03_UI_SPEC.md §6): the ten
 * categories — observed production telemetry only. Controlled benchmark
 * results live in the Benchmark Laboratory and are never mixed in here.
 * Gaps are named (encryption/decryption have no collector family; PQC is
 * benchmark-only), never zero-filled.
 */
import React from "react";
import { Panel } from "./ui.jsx";
import { SummaryTable } from "./InfraWorkspace";

const CATEGORY_LABELS: Record<string, string> = {
  tls: "TLS",
  encryption: "Encryption",
  decryption: "Decryption",
  signatures: "Digital signatures",
  keygen: "Key generation",
  algorithms: "Algorithms",
  libraries: "Crypto libraries",
  pqc: "PQC (ML-KEM & ML-DSA)",
  errors: "Errors",
  resources: "Resources",
};

interface CryptoCategory {
  state: string;
  metrics: Record<string, unknown>;
  basis: string;
}

export default function CryptoWorkspace({ data }: {
  data: { categories?: Record<string, CryptoCategory>; measurement_kind?: string; note?: string } | null | undefined;
}) {
  const categories = data?.categories ?? {};
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: 10, marginBottom: 14 }}>
        {Object.keys(CATEGORY_LABELS).map((key) => {
          const cat = categories[key];
          const measured = cat?.state === "measured";
          const benchmarkOnly = cat?.state === "benchmark-only";
          const count = Object.keys(cat?.metrics ?? {}).length;
          return (
            <div key={key} style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: "8px 10px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{CATEGORY_LABELS[key]}</span>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 999, whiteSpace: "nowrap",
                  border: `1px solid ${measured ? "var(--green, #3ecf8e)" : benchmarkOnly ? "var(--violet, #8b7cf6)" : "var(--slate, #64748b)"}`,
                  color: measured ? "var(--green, #3ecf8e)" : benchmarkOnly ? "var(--violet, #8b7cf6)" : "var(--slate, #64748b)",
                }}>{measured ? "measured" : benchmarkOnly ? "benchmark-only" : "not collected"}</span>
              </div>
              <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4 }}>
                {count ? `${count} series delivered` : "no production series in window"}
              </div>
              {cat?.basis ? <div style={{ fontSize: 10.5, opacity: 0.65, marginTop: 3 }}>{cat.basis}</div> : null}
            </div>
          );
        })}
      </div>

      <Panel title="Observed production performance" sub="delivered families in the window">
        {Object.keys(categories).every((k) => Object.keys(categories[k]?.metrics ?? {}).length === 0) ? (
          <div style={{ fontSize: 12, opacity: 0.75 }}>
            <span title={"No cryptographic production telemetry is stored in this window — absence of telemetry is not healthy cryptography."}>{"No cryptographic production telemetry is stored in this window"}</span>
          </div>
        ) : (
          Object.keys(CATEGORY_LABELS).map((key) => (
            Object.keys(categories[key]?.metrics ?? {}).length > 0 ? (
              <div key={key} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>{CATEGORY_LABELS[key]}</div>
                <SummaryTable metrics={categories[key]?.metrics as Record<string, never>} />
              </div>
            ) : null
          ))
        )}
      </Panel>

      <div style={{ fontSize: 11, opacity: 0.75, marginTop: 10 }}>{data?.note ?? ""}</div>
    </div>
  );
}
