/* The twin chain — Estate → Assets → Relationships → Crypto graph → Evidence graph →
 * History → Impact analysis → Simulation.
 *
 * The eight links are a dependency order, not a table of contents: relationships
 * cannot exist without assets, the crypto graph is drawn over the relationships,
 * impact is a traversal of that graph, and a simulation is an impact calculation
 * run against a hypothetical edit. So the only question this screen answers is the
 * one an operator actually asks of a twin: **how far down the chain does this
 * estate's evidence reach?**
 *
 * Three refusals are rendered as states, never as zeros:
 *   NOT_EVALUATED  — the store was not read in this call; nothing is claimed
 *   EMPTY          — it was read and holds nothing, with the server's reason
 *   no snapshot    — there is no discovery run yet, so there is no chain at all
 *
 * Every number below is echoed from `/estate/evidence/twin/chain`. The console
 * computes no percentage, no score and no ordering of its own.
 */

import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui";
import { LiveBadge, useApi } from "../lib/apiUi";
import { apiEstateTwinChain, type EstateTwinChain, type TwinChainStage } from "../lib/api";

const STATUS_TONE: Record<string, string> = {
  POPULATED: "green",
  EMPTY: "amber",
  NOT_EVALUATED: "slate",
  AWAITING_INPUT: "cyan",
};

/* Where each link's full view lives in this console. The API endpoint that serves
   the link is printed too — the console path is a convenience, not the source. */
const CONSOLE_PATH: Record<string, string> = {
  ESTATE: "/live",
  ASSETS: "/assets",
  RELATIONSHIPS: "/graph",
  CRYPTO_GRAPH: "/crypto",
  EVIDENCE_GRAPH: "/evidence",
  HISTORY: "/live-asset-intelligence",
  IMPACT: "/dependency-graph",
  SIMULATION: "/simulation",
};

const fmt = (value: unknown): string => {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.length ? value.map(String).join(", ") : "none";
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k.replace(/_/g, " ")} ${String(v)}`)
      .join(" · ");
  }
  return String(value);
};

function DetailGrid({ detail }: { detail: Record<string, unknown> }) {
  const entries = Object.entries(detail);
  if (entries.length === 0) {
    return <p className="faint" style={{ fontSize: 11.5, margin: 0 }}>no measurement returned for this link</p>;
  }
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, marginTop: 8 }}>
      {entries.map(([key, value]) => (
        <div key={key} style={{ padding: "7px 10px", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
          <div style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)", fontFamily: "var(--mono)" }}>
            {key.replace(/_/g, " ").toUpperCase()}
          </div>
          <div style={{ fontSize: 12.5, fontWeight: 600, wordBreak: "break-word", marginTop: 2 }}>{fmt(value)}</div>
        </div>
      ))}
    </div>
  );
}

function Stage({ stage, isStop }: { stage: TwinChainStage; isStop: boolean }) {
  const tone = STATUS_TONE[stage.status] ?? "slate";
  return (
    <div
      data-testid={`chain-stage-${stage.stage}`}
      style={{
        display: "grid",
        gridTemplateColumns: "34px 1fr",
        gap: 12,
        padding: "12px 0",
        borderTop: stage.index === 0 ? "none" : "1px solid var(--line)",
      }}
    >
      <div
        className="mono"
        style={{
          width: 26,
          height: 26,
          borderRadius: 8,
          display: "grid",
          placeItems: "center",
          fontSize: 11.5,
          fontWeight: 700,
          border: "1px solid var(--line-strong)",
          color: isStop ? "var(--danger)" : "var(--dim)",
        }}
        title={isStop ? "the chain stops here for this estate" : undefined}
      >
        {stage.index + 1}
      </div>
      <div>
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <b style={{ fontSize: 13 }}>{stage.label}</b>
          <Badge tone={tone}>{stage.status}</Badge>
          {isStop && <Badge tone="red">first incomplete</Badge>}
          <span className="faint" style={{ fontSize: 11 }}>{stage.question}</span>
        </div>
        <DetailGrid detail={stage.detail} />
        {stage.reason && (
          <p
            role="status"
            style={{ margin: "8px 0 0", fontSize: 11.5, color: tone === "amber" ? "var(--amber)" : "var(--dim)" }}
          >
            {stage.status === "NOT_EVALUATED" ? "not read — " : "why — "}
            {stage.reason}
          </p>
        )}
        <div style={{ display: "flex", gap: 12, marginTop: 8, flexWrap: "wrap", fontSize: 11 }}>
          <Link to={CONSOLE_PATH[stage.stage] ?? "/"} style={{ color: "var(--accent)" }}>
            open {stage.label.toLowerCase()} →
          </Link>
          <code className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>{stage.endpoint}</code>
        </div>
      </div>
    </div>
  );
}

export default function EstateTwin() {
  const read = useApi<EstateTwinChain>(apiEstateTwinChain, []);
  const doc = read.data;

  return (
    <>
      <PageHead
        crumb="twin / chain"
        title="Twin chain"
        sub="estate → assets → relationships → crypto graph → evidence graph → history → impact → simulation"
        right={<LiveBadge source={read.source} label={read.source === "live" ? "TWIN SNAPSHOT" : "BACKEND OFFLINE"} />}
      />

      {!doc && !read.running && (
        <Panel title="No chain read" sub={read.source === "live" ? "the twin has no snapshot to walk" : "the control plane did not answer"}>
          <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
            {read.source === "live"
              ? `The chain could not be read — ${read.detail || read.error || "no reason returned"}. An unread chain is not an empty estate; nothing is claimed about it here.`
              : "The control plane did not answer, so no link of the chain is known in this view."}
          </p>
          <p style={{ margin: "10px 0 0", fontSize: 11.5, color: "var(--dim)" }}>
            The chain starts at the first stored discovery run.{" "}
            <Link to="/scanners" style={{ color: "var(--accent)" }}>Run a discovery sweep →</Link>
          </p>
        </Panel>
      )}

      {read.running && !doc && <p className="faint" style={{ fontSize: 12 }}>Reading the chain…</p>}

      {doc && (
        <>
          <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", marginBottom: 10 }}>
            <Badge tone="violet">{doc.estate}</Badge>
            <span className="mono faint" style={{ fontSize: 10.5 }}>projection {doc.projection_id}</span>
            {doc.first_incomplete_stage ? (
              <Badge tone="red">stops at {doc.first_incomplete_stage}</Badge>
            ) : (
              <Badge tone="green">all links populated or awaiting input</Badge>
            )}
          </div>

          <Panel
            title="The chain, link by link"
            sub="each link is measured on the stored snapshot — a POPULATED link means the twin holds records on it, nothing more"
          >
            {doc.stages.map((stage) => (
              <Stage key={stage.stage} stage={stage} isStop={doc.first_incomplete_stage === stage.stage} />
            ))}
          </Panel>

          <Panel title="Status vocabulary" sub="what the server means by each state" style={{ marginTop: 14 }}>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
              {Object.entries(doc.status_meaning).map(([status, meaning]) => (
                <li key={status}>
                  <Badge tone={STATUS_TONE[status] ?? "slate"}>{status}</Badge> {meaning}
                </li>
              ))}
            </ul>
          </Panel>

          <Panel title="What this is" sub="the claim, as the server words it" style={{ marginTop: 14 }}>
            <p style={{ margin: 0, fontSize: 12, color: "var(--text)" }}>{doc.claim}</p>
            <p style={{ margin: "10px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{doc.note}</p>
          </Panel>
        </>
      )}
    </>
  );
}
