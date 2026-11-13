/* CryptoLog — Crypto timeline (docs/cryptolog/01_PRODUCT_SPEC.md §9):
   historical event-level change volume, bucketed server-side. A gap is a
   gap in the record, never a quiet-estate claim; every count names what
   it counts. */
import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologTimeline,
  type ApiResult, type CryptologTimeline,
} from "../lib/api.js";

const CONTROL_STYLE: React.CSSProperties = {
  padding: "6px 8px", borderRadius: 6, border: "1px solid var(--line)",
  background: "var(--panel)", color: "var(--ink)", fontSize: 12,
};

function describeTimelineRead(result: ApiResult<unknown>, subject: string): string {
  const status = result.error?.match(/HTTP (\d{3})/)?.[1];
  if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
  if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
  return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
}

export default function CryptoLogTimeline() {
  const [bucket, setBucket] = useState<"day" | "hour">("day");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [assetId, setAssetId] = useState("");
  const [query, setQuery] = useState({ bucket: "day" as "day" | "hour", start: "", end: "", assetId: "" });
  const [data, setData] = useState<CryptologTimeline | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setFailure(null);
    apiCryptologTimeline({
      bucket: query.bucket,
      asset_id: query.assetId || undefined,
      start_occurred: query.start || undefined,
      end_occurred: query.end || undefined,
    }).then((result) => {
      if (!alive) return;
      if (!result.data) {
        setData(null);
        setFailure(describeTimelineRead(result, "read the CryptoLog timeline"));
        return;
      }
      setData(result.data);
    });
    return () => { alive = false; };
  }, [query]);

  return (
    <div data-testid="cryptolog-timeline" style={{ display: "grid", gap: 16 }}>
      <Panel title="Crypto timeline" sub="Recorded change history, bucketed server-side — the filters travel to the event store, never a page-local filter">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <select aria-label="timeline bucket" value={bucket}
            onChange={(e) => setBucket(e.target.value as "day" | "hour")} style={CONTROL_STYLE}>
            <option value="day">Daily buckets</option>
            <option value="hour">Hourly buckets</option>
          </select>
          <input aria-label="timeline asset" placeholder="Asset ID (blank: all recorded assets)" value={assetId}
            onChange={(e) => setAssetId(e.target.value)} style={CONTROL_STYLE} />
          <input aria-label="timeline start" placeholder="Start (e.g. 2026-11-01)" value={start}
            onChange={(e) => setStart(e.target.value)} style={CONTROL_STYLE} />
          <input aria-label="timeline end" placeholder="End (e.g. 2026-11-08)" value={end}
            onChange={(e) => setEnd(e.target.value)} style={CONTROL_STYLE} />
          <button className="btn" data-testid="apply-timeline"
            onClick={() => setQuery({ bucket, start, end, assetId: assetId.trim() })}>Apply</button>
          <button className="btn" onClick={() => {
            setBucket("day"); setStart(""); setEnd(""); setAssetId("");
            setQuery({ bucket: "day", start: "", end: "", assetId: "" });
          }}>Reset</button>
        </div>

        {failure ? (
          <div className="dim" data-testid="timeline-failure" style={{ marginTop: 12 }}>
            {failure} A source that could not be read is not a timeline with no events.
          </div>
        ) : !data ? (
          <div className="dim" data-testid="timeline-loading" style={{ marginTop: 12 }}>Reading the recorded events…</div>
        ) : data.buckets.length === 0 ? (
          <div className="dim" data-testid="timeline-empty" style={{ marginTop: 12 }}>
            No recorded events {query.assetId ? `for asset ${query.assetId}` : "across the selected estate"} in this window. That is a gap in the record — this screen never invents events or quiet.
          </div>
        ) : (
          <div data-testid="timeline-buckets" style={{ marginTop: 12, display: "grid", gap: 6 }}>
            {data.buckets.map((b) => (
              <div key={b.bucket_start} data-testid="timeline-bucket"
                style={{ padding: "8px 10px", borderRadius: 6, border: "1px solid var(--line)", fontSize: 12 }}>
                <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <strong style={{ fontFamily: "var(--mono)" }}>{b.bucket_start}</strong>
                  <Badge tone="violet">{b.total} event{b.total === 1 ? "" : "s"}</Badge>
                  {b.critical_changes > 0 && (
                    <Badge tone="red">{b.critical_changes} critical change{b.critical_changes === 1 ? "" : "s"}</Badge>
                  )}
                </div>
                <div className="dim" style={{ marginTop: 4, fontSize: 11 }}>
                  {Object.entries(b.by_category).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
                    .map(([k, v]) => `${k} ${v}`).join(" · ")}
                  {" · severity: "}
                  {Object.entries(b.by_severity).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
                    .map(([k, v]) => `${k} ${v}`).join(" · ")}
                </div>
              </div>
            ))}
            <div className="dim" data-testid="timeline-count" style={{ fontSize: 11 }}>
              {data.event_count} recorded event{data.event_count === 1 ? "" : "s"} across {data.buckets.length} bucket{data.buckets.length === 1 ? "" : "s"}
              {data.window.asset_id ? ` · asset ${data.window.asset_id}` : " · all recorded assets"}
              {data.window.start_occurred ? ` · window from ${data.window.start_occurred}` : ""}
              {data.window.end_occurred ? ` · window to ${data.window.end_occurred}` : ""}
            </div>
            <div className="dim" data-testid="timeline-note" style={{ fontSize: 11 }}>{data.note}</div>
          </div>
        )}
      </Panel>
    </div>
  );
}
