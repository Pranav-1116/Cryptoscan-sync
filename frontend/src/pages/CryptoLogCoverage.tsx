import React, { useEffect, useState } from "react";
import { Panel } from "../components/ui.jsx";
import {
  apiCryptologOverview, type ApiResult, type CryptologOverview,
} from "../lib/api.js";

/* Workspace 8 — Collector & Coverage Health (docs/cryptolog §9 collection
   health). Which collectors are generating events, which assets they cover,
   when each was last seen. Missing sources, collector errors and quiet
   windows are named as gaps: a collection gap is not a healthy zero, and a
   source that cannot be read is not a source with no events. */

interface CollectorRow {
  collector_id: string;
  event_count: number;
  telemetry_modes: Record<string, number>;
  first_seen?: string | null;
  last_seen?: string | null;
  asset_count: number;
  assets: string[];
}

export default function CryptoLogCoverage() {
  const [data, setData] = useState<CryptologOverview | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    apiCryptologOverview().then((result: ApiResult<CryptologOverview>) => {
      if (!result.data) {
        setFailure(result.error ?? "the collection health read did not load");
        return;
      }
      setData(result.data);
    });
  }, []);

  const collectors = (data?.collectors ?? []) as unknown as CollectorRow[];

  return (
    <div data-testid="cryptolog-coverage">
      <Panel title="Collector & coverage health" sub="which sources are generating events, when each was last seen, and where the gaps are">
        {failure ? (
          <div className="dim" data-testid="coverage-failure">
            {failure} A failed read is a failure — never zero collectors, never a clean map.
          </div>
        ) : !data ? (
          <div className="dim">Reading collection health…</div>
        ) : collectors.length === 0 ? (
          <div
            data-testid="coverage-collectors-empty"
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
              No collectors have recorded events. This is a collection gap, not a
              healthy estate — an empty store is never drawn as coverage.
            </div>
          </div>
        ) : (
          <>
            <div data-testid="coverage-collectors" style={{ display: "grid", gap: 8 }}>
              {collectors.map((collector) => (
                <div key={collector.collector_id} style={{
                  border: "1px solid var(--rule)", borderRadius: 6, padding: "10px 12px",
                  display: "grid", gap: 6,
                }}>
                  <div className="row" style={{ gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                    <span className="mono" style={{ fontSize: 12 }}>{collector.collector_id}</span>
                    <span className="dim" style={{ fontSize: 11.5 }}>
                      {collector.event_count} event{collector.event_count === 1 ? "" : "s"} ·{" "}
                      {collector.asset_count} asset{collector.asset_count === 1 ? "" : "s"}
                    </span>
                    <span className="dim" style={{ fontSize: 11.5, marginLeft: "auto" }}>
                      last seen {collector.last_seen ?? "unknown — no timestamp recorded"}
                    </span>
                  </div>
                  <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                    <span className="dim" style={{ fontSize: 11 }}>
                      modes: {Object.entries(collector.telemetry_modes)
                        .map(([mode, count]) => `${mode} ×${count}`).join(" · ") || "none recorded"}
                    </span>
                  </div>
                  <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                    {collector.assets.slice(0, 12).map((asset) => (
                      <span key={asset} className="mono" style={{
                        fontSize: 10.5, border: "1px solid var(--rule)", borderRadius: 4,
                        padding: "1px 6px",
                      }}>{asset}</span>
                    ))}
                    {collector.assets.length > 12 && (
                      <span className="dim" style={{ fontSize: 10.5 }}>
                        +{collector.assets.length - 12} more
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
            <div className="dim" style={{ fontSize: 12, marginTop: 10, lineHeight: 1.55 }}>
              {data.note}
            </div>
          </>
        )}
      </Panel>

      <div className="grid cols-2">
        <Panel title="Missing sources & collector errors" sub="recorded gaps only — never assumed health">
          <div
            data-testid="coverage-unmeasured"
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
              No collector-error record exists in this build: missing sources and
              collector errors are <strong>unmeasured</strong> here, never zero and
              never healthy. A source that cannot be read is not a source with no
              events — it is a gap named as a gap.
            </div>
          </div>
        </Panel>
        <Panel title="Observation gaps" sub="quiet windows are gaps in the record, never proof of quiet">
          <div className="dim" style={{ fontSize: 12, lineHeight: 1.55 }}>
            Each collector above reports its own last-seen timestamp. A collector
            quiet since that timestamp is an <strong>observation gap</strong> — the
            record holds nothing after it, and nothing is extrapolated into the
            silence. Sampling or aggregation never claims complete event coverage.
          </div>
        </Panel>
      </div>
    </div>
  );
}
