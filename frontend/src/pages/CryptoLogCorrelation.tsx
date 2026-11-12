import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologCorrelation, type ApiResult,
  type CryptologCorrelation, type CryptologCorrelationGroup,
} from "../lib/api.js";

/* Workspace 5 — Event Correlation. Deterministic correlation over the
   recorded event store: shared evidence references and recorded asset
   identity are evidence-backed relations; a shared algorithm name is a
   possible dependency — a hypothesis, never an established edge. An empty
   result is absence of recorded correlation, never proof that nothing
   relates. */

const BASIS_COPY: Record<string, { title: string; tone: "green" | "slate" | "amber"; label: string }> = {
  shared_evidence: { title: "Shared evidence references", tone: "green", label: "evidence-backed" },
  shared_asset: { title: "Same recorded asset", tone: "green", label: "evidence-backed" },
  shared_algorithm: { title: "Possible dependencies (shared algorithm name)", tone: "slate", label: "hypothesis" },
};

function GroupRow({ group }: { group: CryptologCorrelationGroup }) {
  const basis = BASIS_COPY[group.basis] ?? { title: group.basis, tone: "slate" as const, label: "unclassified" };
  return (
    <div style={{
      border: "1px solid var(--rule)", borderRadius: 6, padding: "10px 12px",
      display: "grid", gap: 6,
    }}>
      <div className="row" style={{ gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <span className="mono" style={{ fontSize: 12 }}>{group.key}</span>
        <Badge tone={group.evidence_backed ? "green" : "slate"}>{basis.label}</Badge>
        <span className="dim" style={{ fontSize: 11 }}>
          {group.event_count} event{group.event_count === 1 ? "" : "s"} · {group.asset_ids.length} asset{group.asset_ids.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
        {group.event_ids.map((id) => (
          <span key={id} className="mono" style={{
            fontSize: 10.5, border: "1px solid var(--rule)", borderRadius: 4,
            padding: "1px 6px",
          }}>{id}</span>
        ))}
      </div>
      <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
        {group.asset_ids.map((asset) => (
          <span key={asset} className="dim mono" style={{ fontSize: 10.5 }}>{asset}</span>
        ))}
      </div>
      <div className="dim" style={{ fontSize: 11.5, lineHeight: 1.5 }}>{group.note}</div>
    </div>
  );
}

export default function CryptoLogCorrelation() {
  const [data, setData] = useState<CryptologCorrelation | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    apiCryptologCorrelation().then((result: ApiResult<CryptologCorrelation>) => {
      if (!result.data) {
        setFailure(result.error ?? "the correlation read did not load");
        return;
      }
      setData(result.data);
    });
  }, []);

  const byBasis = (basis: string) => (data?.groups ?? []).filter((g) => g.basis === basis);

  return (
    <div data-testid="cryptolog-correlation">
      <Panel title="Event correlation" sub="related events across assets — patterns, unexpected changes and possible dependencies, computed from the recorded store">
        {failure ? (
          <div className="dim" data-testid="correlation-failure">
            {failure} A failed read is a failure — never an uncorrelated estate.
          </div>
        ) : !data ? (
          <div className="dim">Reading the recorded events…</div>
        ) : (
          <>
            <div className="dim" data-testid="correlation-note" style={{ fontSize: 12, lineHeight: 1.55, marginBottom: 12 }}>
              {data.note} {data.event_count} recorded event{data.event_count === 1 ? "" : "s"} examined.
            </div>
            {data.groups.length === 0 ? (
              <div
                data-testid="correlation-empty"
                style={{
                  display: "flex", gap: 10, alignItems: "flex-start",
                  border: "1px dashed var(--rule)", borderRadius: 8, padding: "12px 14px",
                  background: "var(--panel-2)",
                }}
              >
                <span
                  aria-hidden
                  style={{ width: 8, height: 8, borderRadius: 99, border: "1.5px dashed var(--slate, #64748b)", marginTop: 4, flex: "0 0 auto" }}
                />
                <div className="dim" style={{ fontSize: 12, lineHeight: 1.5 }}>
                  No correlation groups in the recorded events. Absence of recorded
                  correlation is never proof that nothing relates.
                </div>
              </div>
            ) : (
              ["shared_evidence", "shared_asset", "shared_algorithm"].map((basis) => {
                const groups = byBasis(basis);
                if (!groups.length) return null;
                const copy = BASIS_COPY[basis];
                return (
                  <section key={basis} style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 8 }}>
                      {copy.title.toUpperCase()} — {copy.label.toUpperCase()}
                    </div>
                    <div style={{ display: "grid", gap: 8 }}>
                      {groups.map((group) => (
                        <GroupRow key={`${group.basis}:${group.key}`} group={group} />
                      ))}
                    </div>
                  </section>
                );
              })
            )}
          </>
        )}
      </Panel>
    </div>
  );
}
