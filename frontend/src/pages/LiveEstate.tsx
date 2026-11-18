/* Live estate — the bank's estate as it is connected to, changed and correlated.
 *
 * This screen exists because the product no longer copies an estate: it keeps a twin and
 * stores changes. So the questions it answers are the live ones:
 *
 *   is the estate connected right now, and how is that known?
 *   what changed today, and what was dropped because nothing moved?
 *   which of the six BOMs can be downloaded, and from which projection?
 *   do the stored changes correlate into a pattern — and what does that pattern NOT prove?
 *
 * Every block is drawn, not narrated: a missing measurement is a hatched "not measured"
 * row with its reason, a quiet estate is an explicit absence rather than a zero, and no
 * percentage is ever computed client-side.
 */

import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Button, Panel, PageHead } from "../components/ui";
import { GapBar, HBars, StackedBar, StateCell, VizEmpty } from "../components/viz";
import { usePollingApi } from "../lib/apiUi";
import {
  apiLiveEstateStatus,
  apiThreatPatterns,
  downloadBom,
  type AttackPattern,
  type LiveEstateStatus,
} from "../lib/api";

const BOM_KINDS = ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"] as const;

const nf = (n: number | null | undefined) => (typeof n === "number" ? n.toLocaleString() : "—");

const age = (seconds: number | null | undefined): string => {
  if (typeof seconds !== "number") return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d`;
};

const LEVEL_TONE = ["", "warn", "warn", "critical", "critical"];

function ConnectionBand({ status }: { status: LiveEstateStatus | null }) {
  const connection = status?.connection;
  if (!connection) {
    return <VizEmpty title="No connection read" note="the control plane did not answer, so nothing here is known" />;
  }
  const state = connection.state;
  const tone = state === "LIVE" ? "ok" : state === "STALE" ? "warn" : "critical";
  const measured = typeof connection.seconds_since === "number";
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8 }}>
        <StateCell label="connection" value={state} tone={tone} note={connection.meaning} />
        <StateCell
          label="last observation"
          value={connection.last_observation ? new Date(connection.last_observation).toLocaleTimeString() : "never"}
          note={connection.last_observation ? new Date(connection.last_observation).toLocaleDateString() : "no accepted observation"}
        />
        <StateCell
          label="age"
          value={age(connection.seconds_since)}
          note={`stale after ${age(connection.stale_after_seconds)} (${connection.interval_seconds}s interval)`}
          tone={measured ? tone : ""}
        />
        <StateCell
          label="trust keys"
          value={nf(status?.trust?.trust_keys_configured ?? 0)}
          note={status?.trust?.signatures_required ? "signatures required" : "signatures optional"}
          tone={(status?.trust?.trust_keys_configured ?? 0) > 0 ? "ok" : "warn"}
        />
      </div>
      {measured ? (
        <div>
          <div
            style={{
              height: 8,
              border: "1px solid var(--line)",
              borderRadius: 2,
              background: "var(--bg-2)",
              overflow: "hidden",
            }}
            title={`${connection.seconds_since}s since the last observation`}
          >
            <span
              style={{
                display: "block",
                height: "100%",
                width: `${Math.min(100, Math.max(1, (connection.seconds_since! / connection.stale_after_seconds) * 100))}%`,
                background: tone === "ok" ? "var(--green)" : tone === "warn" ? "var(--amber)" : "var(--red)",
              }}
            />
          </div>
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>
            age against the {age(connection.stale_after_seconds)} staleness threshold — bar length is
            this observation&apos;s age, not a health score
          </div>
        </div>
      ) : (
        <GapBar
          label="observation interval"
          reason="no observation has been accepted, so there is no age to draw — NOT_OBSERVED is not an estate without cryptography"
        />
      )}
      {(status?.trust?.findings ?? []).map((finding) => (
        <div key={finding} className="mono" style={{ fontSize: 10.5, color: "var(--red)", lineHeight: 1.45 }}>
          {finding}
        </div>
      ))}
    </div>
  );
}

function TwinBlock({ status }: { status: LiveEstateStatus | null }) {
  const twin = status?.twin;
  if (!twin) {
    return <VizEmpty title="No twin read" note="the control plane did not answer" />;
  }
  if (twin.state !== "OBSERVED") {
    return (
      <VizEmpty
        title={`twin ${twin.state.toLowerCase().replace("_", " ")}`}
        note={"reason" in twin ? twin.reason : "nothing has been observed for this estate"}
      />
    );
  }
  const coverage = (twin.coverage ?? {}) as Record<string, unknown>;
  const coverageState = String(coverage.state ?? "UNKNOWN");
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8 }}>
        <StateCell label="assets" value={nf(twin.assets)} note="distinct identities in the twin" />
        <StateCell label="evidence" value={nf(twin.evidence)} note="content-addressed records" />
        <StateCell label="relationships" value={nf(twin.relationships)} note="edges with a stated basis" />
        <StateCell
          label="coverage"
          value={coverageState}
          tone={coverageState === "COMPLETE" ? "ok" : coverageState === "PARTIAL" ? "warn" : "critical"}
          note="attempted vs expected targets, never % of crypto found"
        />
      </div>
      <div className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
        projection {String(twin.projection_id).slice(0, 16)}… · written{" "}
        {twin.recorded_at ? new Date(twin.recorded_at).toLocaleString() : "—"}
      </div>
    </div>
  );
}

function BomDownloadGrid({ status }: { status: LiveEstateStatus | null }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [result, setResult] = useState<{ kind: string; ok: boolean; text: string } | null>(null);
  const counts = status?.boms?.counts ?? {};
  const available = status?.twin?.state === "OBSERVED";

  const run = useCallback(async (kind: string, fmt: "cyclonedx" | "json") => {
    setBusy(`${kind}:${fmt}`);
    const outcome = await downloadBom(kind, fmt);
    setBusy(null);
    setResult({
      kind,
      ok: outcome.ok,
      text: outcome.ok
        ? `${kind} ${fmt} written (${outcome.filename}) — a projection of the current twin`
        : `${kind} download failed: ${outcome.error}; no file was written`,
    });
  }, []);

  if (!available) {
    return (
      <VizEmpty
        title="no BOM to download"
        note="a download projects the twin; with no observation this would be a document about no evidence"
        height={110}
      />
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8 }}>
        {BOM_KINDS.map((kind) => (
          <div
            key={kind}
            style={{
              border: "1px solid var(--line)",
              borderLeft: "2px solid var(--line-strong)",
              borderRadius: "var(--r)",
              background: "var(--panel-2)",
              padding: "8px 10px",
              display: "flex",
              flexDirection: "column",
              gap: 6,
            }}
          >
            <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)" }}>
              {kind}
            </div>
            <div className="mono" style={{ fontSize: 18, fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
              {nf(counts[kind] ?? 0)}
            </div>
            <div style={{ display: "flex", gap: 4 }}>
              <Button onClick={() => void run(kind, "cyclonedx")} disabled={busy === `${kind}:cyclonedx`}>
                {busy === `${kind}:cyclonedx` ? "…" : "CycloneDX"}
              </Button>
              <Button onClick={() => void run(kind, "json")} disabled={busy === `${kind}:json`}>
                {busy === `${kind}:json` ? "…" : "JSON"}
              </Button>
            </div>
          </div>
        ))}
      </div>
      {result && (
        <div
          role="status"
          className="mono"
          style={{ fontSize: 10.5, color: result.ok ? "var(--green)" : "var(--red)", lineHeight: 1.45 }}
        >
          {result.text}
        </div>
      )}
      <div style={{ fontSize: 10, color: "var(--faint)" }}>
        each file names the projection it was computed from; downloading the same projection twice
        produces the same document.
      </div>
    </div>
  );
}

function PatternRow({ pattern }: { pattern: AttackPattern }) {
  const tone = LEVEL_TONE[pattern.level] || "";
  return (
    <div
      style={{
        border: "1px solid var(--line)",
        borderLeft: `2px solid ${tone === "critical" ? "var(--red)" : tone === "warn" ? "var(--amber)" : "var(--line-strong)"}`,
        borderRadius: "var(--r)",
        background: "var(--panel-2)",
        padding: "9px 11px",
        display: "flex",
        flexDirection: "column",
        gap: 6,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
          {pattern.pattern_id}
        </span>
        <Badge tone={tone || "muted"}>{`L${pattern.level} ${pattern.level_name}`}</Badge>
        <span style={{ fontSize: 12.5, fontWeight: 600 }}>{pattern.headline}</span>
      </div>
      <div style={{ fontSize: 11.5, color: "var(--dim)", lineHeight: 1.45 }}>{pattern.why}</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {pattern.change_kinds.map((kind) => (
          <span
            key={kind}
            className="mono"
            style={{
              fontSize: 9.5,
              letterSpacing: "0.04em",
              padding: "2px 6px",
              border: "1px solid var(--line)",
              borderRadius: 2,
              color: "var(--slate)",
            }}
          >
            {kind}
          </span>
        ))}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
        <span className="mono" style={{ fontSize: 9.5, letterSpacing: "0.06em", color: "var(--faint)" }}>
          sources
        </span>
        {pattern.corroboration?.collectors?.length ? (
          pattern.corroboration.collectors.map((collector) => (
            <span
              key={collector}
              className="mono"
              style={{
                fontSize: 9.5,
                padding: "2px 6px",
                border: "1px solid var(--line)",
                borderRadius: 2,
                color: pattern.corroboration.single_source ? "var(--amber)" : "var(--green)",
              }}
            >
              {collector}
            </span>
          ))
        ) : (
          <span className="mono" style={{ fontSize: 9.5, color: "var(--amber)" }}>
            none traced to stored evidence
          </span>
        )}
        <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)" }}>
          {pattern.corroboration?.independent_sources ?? 0} independent
          {pattern.corroboration?.single_source ? " · single source, not confirmed by a second plane" : ""}
        </span>
      </div>
      <div style={{ fontSize: 10.5, color: "var(--faint)", lineHeight: 1.45 }}>
        next: {pattern.next_action}
      </div>
      <div style={{ fontSize: 10.5, color: "var(--faint)", lineHeight: 1.45 }}>
        not proven: {pattern.not_proven[0]}
      </div>
    </div>
  );
}

export default function LiveEstate() {
  const status = usePollingApi<LiveEstateStatus>(apiLiveEstateStatus, 10000);
  const patterns = usePollingApi(useCallback(() => apiThreatPatterns(3600), []), 15000);
  const data = status.data;
  const view = patterns.data;

  const severitySegments = Object.entries(data?.changes_today?.by_severity ?? {}).map(([key, value]) => ({
    key,
    label: key.toLowerCase(),
    value,
    tone: key.toUpperCase() === "CRITICAL" ? "red" : key.toUpperCase() === "WARNING" || key.toUpperCase() === "HIGH" ? "amber" : "slate",
  }));

  const levelRows = view
    ? [4, 3, 2, 1, 0].map((level) => ({
        key: String(level),
        label: `L${level} ${view.level_definitions?.[String(level)]?.name ?? ""}`.trim(),
        value: view.by_level?.[String(level)] ?? 0,
        tone: level >= 3 ? "critical" : level === 2 ? "amber" : level === 1 ? "slate" : "",
      }))
    : [];

  return (
    <div>
      <PageHead
        crumb="Overview"
        title="Live estate"
        sub="connected estate, stored changes, current BOMs and correlated activity — measured, never assumed"
        right={
          <Badge tone={(data?.connection?.state ?? "") === "LIVE" ? "green" : "amber"}>
            {data?.connection?.state ?? (status.error ? "READ FAILED" : "READING")}
          </Badge>
        }
      />

      {status.error && (
        <div role="alert" style={{ marginBottom: 10, fontSize: 11.5, color: "var(--red)" }}>
          live state unavailable ({status.error}) — nothing below is a current reading
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 10, alignItems: "start" }}>
        <Panel title="Connection" sub="age of the last accepted observation, against the expected interval">
          <ConnectionBand status={data} />
        </Panel>
        <Panel title="Twin" sub="one evidence graph; the six BOMs are projections of it">
          <TwinBlock status={data} />
        </Panel>
      </div>

      <div style={{ height: 10 }} />

      <Panel title="Current BOMs" sub="download projects the twin — no scan, no stored document">
        <BomDownloadGrid status={data} />
      </Panel>

      <div style={{ height: 10 }} />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", gap: 10, alignItems: "start" }}>
        <Panel title="Changes today" sub={data?.changes_today?.note ?? "counted from the stored change feed"}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {/* A count that was never read is not zero. When the status read has
                not returned, these tiles say so instead of drawing an empty feed. */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 8 }}>
              <StateCell
                label="changes"
                value={data ? nf(data.changes_today?.count) : "—"}
                note={data ? "stored events (UTC today)" : "the live-state read did not return"}
              />
              <StateCell
                label="unacknowledged"
                value={data ? nf(data.changes_today?.unacknowledged) : "—"}
                tone={data && (data.changes_today?.unacknowledged ?? 0) > 0 ? "amber" : ""}
                note="nobody has marked these seen"
              />
              <StateCell
                label="highest level"
                value={view ? `L${view.highest_level ?? 0}` : "—"}
                tone={view && (view.highest_level ?? 0) >= 2 ? "amber" : ""}
                note={view ? "correlation level, not probability" : "no correlation run returned"}
              />
            </div>
            {severitySegments.length ? (
              <StackedBar segments={severitySegments} note="share of today's stored changes by stored severity" />
            ) : (
              <VizEmpty
                title="no change stored today"
                note="that is the live model working: an unchanged poll stores a heartbeat, not an estate copy"
                height={72}
              />
            )}
            <Link to="/drift" style={{ fontSize: 11, color: "var(--dim)" }}>
              open the full change feed →
            </Link>
          </div>
        </Panel>

        <Panel title="Attack patterns" sub={`stored changes correlated over the last ${Math.round((view?.window_seconds ?? 3600) / 60)} minutes`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
            <HBars
              rows={levelRows}
              emptyTitle="no correlation run"
              emptyNote="the patterns endpoint returned nothing, so no level can be shown"
            />
            <div className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
              <span title={"L3 SECURITY_INCIDENT is never assigned by this engine — a correlated change feed is not an incident declaration. L4 means several patterns in one window, not more certainty."}>{"L3 SECURITY_INCIDENT is never assigned by this engine"}</span>
            </div>
            {(view?.patterns ?? []).length ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {(view?.patterns ?? []).map((pattern) => (
                  <PatternRow key={pattern.pattern_id} pattern={pattern} />
                ))}
              </div>
            ) : (
              <VizEmpty
                title="no pattern met a correlation rule"
                note="this is not a statement that the estate is safe; a blind plane is reported as COLLECTION_LOSS, never as quiet"
                height={92}
              />
            )}
          </div>
        </Panel>
      </div>

      <div style={{ height: 10 }} />

      <Panel title="What this screen cannot say" sub="stated, because a green band would say it by accident">
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {(data?.limits ?? []).map((limit) => (
            <div key={limit} style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.5 }}>
              · {limit}
            </div>
          ))}
          {(view?.limits ?? []).map((limit) => (
            <div key={limit} style={{ fontSize: 11, color: "var(--faint)", lineHeight: 1.5 }}>
              · {limit}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
