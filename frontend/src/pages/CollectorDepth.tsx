/* Collector depth — how far discovery actually reaches, four ways.
 *
 * Every figure on this page comes from the server, computed from the collectors
 * that resolve in this build. The page adds no percentage, no score and no
 * ordering of its own, because the whole point of the four matrices is that
 * "we discover crypto" is only true one surface, one protocol, one platform and
 * one BOM at a time.
 *
 *   Runtime   installed ≠ executed. Only one family has call-level evidence.
 *   Network   TLS is a handshake reader; SSH/IPsec are offer readers; several
 *             protocols have no reader at all and are listed as such.
 *   Windows   substrate and configuration only — the server's own verdict is NO.
 *   BOMs      six projections of one graph, six different depths, no percentages.
 */

import { Donut, FlowStrip, type FlowState } from "../components/viz";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui";
import { LiveBadge, useApi } from "../lib/apiUi";
import {
  apiBomMaturity,
  apiEstateBomComponents,
  apiMaturityRegister,
  apiNetworkProtocols,
  apiRuntimeDepth,
  apiSimulationScenarios,
  apiWindowsCollector,
  type BomMaturity,
  type EstateBomDocument,
  type CapabilityBoundary,
  type MaturityRegister,
  type MaturitySurface,
  type NetworkProtocols,
  type RuntimeDepth,
  type EnterpriseSimulationCatalogue,
  type WindowsCollector,
} from "../lib/api";

const DEPTH_TONE: Record<string, string> = {
  INVOCATION: "green",
  CONFIGURATION: "amber",
  PROCESS_LIBRARY: "amber",
  INGEST_ONLY: "slate",
  ABSENT: "red",
};

const STRENGTH_TONE: Record<string, string> = {
  NEGOTIATED: "green",
  OFFERED: "amber",
  SESSION_CONFIG: "cyan",
  PASSIVE: "blue",
  ABSENT: "red",
};

const STATE_TONE: Record<string, string> = {
  PRESENT: "green",
  PARTIAL: "amber",
  ABSENT: "red",
};

const ESTABLISHES_TONE: Record<string, string> = {
  INVOCATION: "green",
  CONFIGURATION: "amber",
  SUBSTRATE: "slate",
};

const USAGE_TONE: Record<string, string> = {
  OBSERVED: "green",
  NEGOTIATED: "green",
  CONFIGURED: "amber",
  SUPPORTED: "slate",
  DECLARED_ONLY: "slate",
};

/* Register states, not scores. Only SUBSTANTIAL reads green: everything else is
 * a named gap, and the missing list beside it is the point of the page. */
const REGISTER_TONE: Record<string, string> = {
  SUBSTANTIAL: "green",
  PARTIAL: "amber",
  CANDIDATE: "amber",
  FOUNDATION: "slate",
  IMPORT_ONLY: "slate",
  ABSENT: "red",
};

/* Readiness is about what may be said, not how much is covered. A candidate
 * collector reads real facts and is still not something to run a bank on. */
const READINESS_TONE: Record<string, string> = {
  OPERATIONAL: "green",
  CANDIDATE: "amber",
  FOUNDATION: "slate",
};

const SIMULATION_TONE: Record<string, string> = {
  EXISTS: "green",
  PARTIAL: "amber",
  ABSENT: "red",
};

const MATURITY_TONE: Record<string, string> = {
  OBSERVED: "green",
  CONFIGURED: "amber",
  DECLARED_ONLY: "violet",
  UNBACKED: "red",
  EMPTY: "slate",
};

const human = (value: string) => value.replace(/_/g, " ").toLowerCase();

function Grid({ rows }: { rows: Array<{ key: string; value: string }> }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8, marginTop: 8 }}>
      {rows.map((row) => (
        <div key={row.key} style={{ padding: "7px 10px", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
          <div style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)", fontFamily: "var(--mono)" }}>
            {row.key.replace(/_/g, " ").toUpperCase()}
          </div>
          <div style={{ fontSize: 12.5, fontWeight: 600, marginTop: 2 }}>{row.value}</div>
        </div>
      ))}
    </div>
  );
}

function Limit({ text }: { text: string }) {
  return (
    <p style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--amber)", lineHeight: 1.5 }}>
      <b>Cannot claim:</b> {text}
    </p>
  );
}

function Gaps({ gaps }: { gaps: string[] }) {
  if (gaps.length === 0) return null;
  return (
    <div style={{ margin: "6px 0 0", display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
      <span style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)", fontFamily: "var(--mono)" }}>GAPS</span>
      {gaps.map((gap) => (
        <span
          key={gap}
          style={{
            fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)",
            border: "1px dashed var(--line)", borderRadius: 999, padding: "1px 8px",
          }}
        >
          {gap}
        </span>
      ))}
    </div>
  );
}

/* The measurement chain, drawn: a mapped library, ingested rows and a counted
   call are three different facts. The ladder lights only the stages the
   DEPTH actually asserts; everything past the measurement is dashed
   ("not observed"), never a pass and never a failure. */
const DEPTH_STAGES: Record<string, number> = {
  INVOCATION: 2,
  INGEST_ONLY: 1,
  EXISTS: 0,
  PARTIAL: 0,
};

function DepthLadder({ depth }: { depth: string }) {
  const reached = DEPTH_STAGES[depth];
  const stages: { label: string; state: FlowState; note: string }[] = [
    {
      label: "mapped / installed",
      state: reached === undefined ? "unknown" : "done",
      note:
        reached === undefined
          ? "not observed as present — never assumed installed"
          : "the library or provider is present in the process or store",
    },
    {
      label: "rows ingested",
      state: reached === undefined ? "unknown" : reached >= 1 ? "done" : "unknown",
      note:
        reached !== undefined && reached >= 1
          ? "records arrive through the ingest path"
          : "no ingest rows — not observed, never 'did not run'",
    },
    {
      label: "call-level (invoked)",
      state: reached === 2 ? "done" : "unknown",
      note:
        reached === 2
          ? "counted calls under the shim — invocation evidence"
          : "no call-level evidence: installed is not executed",
    },
  ];
  return <FlowStrip label={`measurement chain for depth ${depth}`} stages={stages} />;
}

function RuntimeSection() {
  const read = useApi<RuntimeDepth>(apiRuntimeDepth, []);
  const doc = read.data;
  if (!doc) {
    return (
      <Panel title="Runtime" sub="what this build can observe while code runs">
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {read.running
            ? "Reading the runtime depth matrix…"
            : `Runtime depth not read — ${read.detail || read.error || "the control plane did not answer"}. No family is claimed either way.`}
        </p>
      </Panel>
    );
  }
  const observed = doc.observed;
  return (
    <Panel title="Runtime — installed is not executed" sub={doc.claim}>
      <p style={{ margin: "0 0 10px", fontSize: 12.5, color: "var(--text)", lineHeight: 1.5 }}>{doc.axiom}</p>
      <div style={{ display: "flex", gap: 18, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
        <Donut
          size={104}
          segments={[
            { label: "call-level evidence", value: doc.rollup.call_level_paths, tone: "green" },
            { label: "ingest-only", value: doc.rollup.ingest_only_paths, tone: "slate" },
            { label: "absent", value: doc.rollup.absent_paths, tone: "red" },
            {
              label: "other depth",
              value: Math.max(
                0,
                doc.rollup.paths - doc.rollup.call_level_paths - doc.rollup.ingest_only_paths - doc.rollup.absent_paths,
              ),
              tone: "amber",
            },
          ]}
          centerLabel={doc.rollup.paths}
          centerSub="families"
        />
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <Badge tone="cyan">{doc.rollup.paths} runtime families</Badge>
          <Badge tone="green">{doc.rollup.call_level_paths} with call-level evidence</Badge>
          <Badge tone="slate">{doc.rollup.ingest_only_paths} ingest-only</Badge>
          <Badge tone={doc.rollup.absent_paths ? "red" : "slate"}>{doc.rollup.absent_paths} absent</Badge>
          {observed && (
            <Badge tone={observed.state === "INVOCATION_OBSERVED" ? "green" : observed.state === "NOT_EVALUATED" ? "red" : "amber"}>
              store: {human(observed.state)}
            </Badge>
          )}
        </div>
      </div>

      {observed && (
        <div style={{ marginBottom: 14, padding: "10px 12px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel-2)" }}>
          {observed.reason && (
            <p style={{ margin: "0 0 8px", fontSize: 11.5, color: "var(--amber)" }}>{observed.reason}</p>
          )}
          <Grid
            rows={[
              { key: "stored rows", value: observed.rows == null ? "not read" : String(observed.rows) },
              { key: "invocation rows", value: observed.invocation_rows == null ? "—" : String(observed.invocation_rows) },
              { key: "calls counted", value: observed.invocation_calls == null ? "—" : String(observed.invocation_calls) },
              { key: "wire rows", value: observed.wire_rows == null ? "—" : String(observed.wire_rows) },
              { key: "library risk rows", value: observed.library_risk_rows == null ? "—" : String(observed.library_risk_rows) },
              { key: "hosts", value: observed.host_count == null ? "—" : String(observed.host_count) },
            ]}
          />
        </div>
      )}

      <div style={{ display: "grid", gap: 8 }}>
        {doc.paths.map((path) => (
          <div key={path.id} data-testid={`runtime-path-${path.id}`} style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <b style={{ fontSize: 13 }}>{path.label}</b>
              <Badge tone={DEPTH_TONE[path.depth] ?? "slate"}>{path.depth.replace(/_/g, " ")}</Badge>
              {path.depth !== path.declared_depth && <Badge tone="red">declared {path.declared_depth.replace(/_/g, " ")}</Badge>}
              {path.ingest_only.length > 0 && <Badge tone="slate">engine accepts: {path.ingest_only.join(", ")}</Badge>}
              <span className="faint" style={{ fontSize: 11 }}>{path.family}</span>
            </div>
            <div style={{ margin: "8px 0 2px", maxWidth: 620 }}>
              <DepthLadder depth={path.depth} />
            </div>
            <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{path.reads}</p>
            <Limit text={path.cannot_claim} />
            <Gaps gaps={path.gaps} />
            {path.notes.length > 0 && (
              <p style={{ margin: "6px 0 0", fontSize: 11, color: "var(--red)" }}>{path.notes.join(" · ")}</p>
            )}
            <p style={{ margin: "6px 0 0", fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)" }}>
              {path.producers.length === 0
                ? "no producer in this build"
                : path.producers
                    .map((producer) => `${producer.present ? "✓" : "✗"} ${producer.ref}`)
                    .join("  ")}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function NetworkSection() {
  const read = useApi<NetworkProtocols>(apiNetworkProtocols, []);
  const doc = read.data;
  if (!doc) {
    return (
      <Panel title="Network protocols" sub="which protocols can be read, per protocol">
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {read.running
            ? "Reading the protocol matrix…"
            : `Protocol matrix not read — ${read.detail || read.error || "the control plane did not answer"}. No protocol is claimed either way.`}
        </p>
      </Panel>
    );
  }
  const measured = doc.measured;
  return (
    <Panel title="Network — one protocol at a time" sub={doc.claim}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <Badge tone="cyan">{doc.rollup.protocols} protocols</Badge>
        <Badge tone="green">{doc.rollup.negotiated} handshake readers</Badge>
        <Badge tone="amber">{doc.rollup.offered_only} offer readers</Badge>
        <Badge tone="red">{doc.rollup.absent} with no reader</Badge>
      </div>

      <div style={{ marginBottom: 14, padding: "10px 12px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel-2)" }}>
        {measured?.state !== "OBSERVED" ? (
          <p style={{ margin: 0, fontSize: 11.5, color: "var(--amber)" }} data-testid="network-measured">
            Estate-backed counts not read — {measured?.reason ?? "no measurement returned"}. The matrix above is a
            capability statement, not a claim about this estate.
          </p>
        ) : (
          <div data-testid="network-measured">
            <p style={{ margin: 0, fontSize: 11.5, color: "var(--dim)" }}>{measured.note}</p>
            <Grid
              rows={Object.entries(measured.by_asset_class ?? {}).map(([klass, counts]) => ({
                key: klass,
                value: `${counts.with_network_evidence}/${counts.assets} with network evidence`,
              }))}
            />
          </div>
        )}
      </div>

      {doc.port_table && (
        <div style={{ marginBottom: 14, padding: "10px 12px", border: "1px solid var(--line)", borderRadius: "var(--r)" }} data-testid="port-table">
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <b style={{ fontSize: 12.5 }}>Crypto-bearing ports probed at the TLS layer</b>
            <Badge tone="cyan">{doc.port_table.counts.ports} ports</Badge>
            <Badge tone="slate">{doc.port_table.counts.iana} IANA-registered</Badge>
            <Badge tone="slate">{doc.port_table.counts.convention} vendor convention</Badge>
          </div>
          <p style={{ margin: "6px 0 8px", fontSize: 11.5, color: "var(--dim)" }}>{doc.port_table.claim}</p>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {doc.port_table.ports.map((entry) => (
              <span
                key={entry.port}
                title={`${entry.source} — message layer ${entry.message_layer} is NOT read`}
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: 10.5,
                  padding: "2px 8px",
                  borderRadius: 999,
                  border: "1px solid var(--line)",
                  color: entry.plaintext_variant ? "var(--amber)" : "var(--dim)",
                }}
              >
                {entry.port} {entry.protocol}
              </span>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: "grid", gap: 8 }}>
        {doc.protocols.map((protocol) => (
          <div key={protocol.id} data-testid={`protocol-${protocol.id}`} style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <b style={{ fontSize: 13 }}>{protocol.label}</b>
              <Badge tone={STRENGTH_TONE[protocol.strength] ?? "slate"}>{protocol.strength.replace(/_/g, " ")}</Badge>
              {protocol.strength !== protocol.declared_strength && (
                <Badge tone="red">declared {protocol.declared_strength.replace(/_/g, " ")}</Badge>
              )}
              {protocol.ingest_only.length > 0 && (
                <Badge tone="slate">engine accepts: {protocol.ingest_only.join(", ")}</Badge>
              )}
              <span className="faint" style={{ fontSize: 11 }}>{protocol.strength_meaning}</span>
            </div>
            <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{protocol.reads}</p>
            <Limit text={protocol.cannot_claim} />
            <Gaps gaps={protocol.gaps} />
          </div>
        ))}
      </div>
    </Panel>
  );
}

function WindowsSection() {
  const read = useApi<WindowsCollector>(apiWindowsCollector, []);
  const doc = read.data;
  if (!doc) {
    return (
      <Panel title="Windows" sub="how far the Windows candidate reaches">
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {read.running
            ? "Reading the Windows layer matrix…"
            : `Windows matrix not read — ${read.detail || read.error || "the control plane did not answer"}.`}
        </p>
      </Panel>
    );
  }
  const verdict = doc.verdict;
  return (
    <Panel title="Windows — a substrate collector, not a crypto collector" sub={doc.claim}>
      <div
        role="status"
        data-testid="windows-verdict"
        style={{
          marginBottom: 12,
          padding: "10px 12px",
          borderRadius: "var(--r)",
          border: `1px solid ${verdict.complete_collector ? "var(--green)" : "var(--amber)"}`,
          background: "var(--panel-2)",
        }}
      >
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <b style={{ fontSize: 13 }}>Complete Windows crypto collector?</b>
          <Badge tone={verdict.complete_collector ? "green" : "red"}>{verdict.answer}</Badge>
          <span className="faint" style={{ fontSize: 11 }}>
            {doc.rollup.invocation_layers} of {doc.rollup.layers} layers observe an operation
          </span>
        </div>
        <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{verdict.reason}</p>
      </div>

      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <Badge tone="green">{doc.rollup.by_state.PRESENT ?? 0} present</Badge>
        <Badge tone="amber">{doc.rollup.by_state.PARTIAL ?? 0} partial</Badge>
        <Badge tone="red">{doc.rollup.by_state.ABSENT ?? 0} absent</Badge>
        {doc.measured?.state === "OBSERVED" ? (
          <Badge tone="cyan">
            {doc.measured.windows_hosts_with_evidence ?? 0}/{doc.measured.windows_hosts ?? 0} Windows hosts with evidence
          </Badge>
        ) : (
          <Badge tone="slate">Windows hosts not read</Badge>
        )}
      </div>

      <div style={{ display: "grid", gap: 8 }}>
        {doc.layers.map((layer) => (
          <div key={layer.id} data-testid={`windows-layer-${layer.id}`} style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <b style={{ fontSize: 13 }}>{layer.label}</b>
              <Badge tone={STATE_TONE[layer.state] ?? "slate"}>{layer.state}</Badge>
              <Badge tone={ESTABLISHES_TONE[layer.establishes] ?? "slate"}>
                establishes {layer.establishes.toLowerCase()}
              </Badge>
            </div>
            <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{layer.reads}</p>
            <Limit text={layer.cannot_claim} />
            <Gaps gaps={layer.gaps} />
            {layer.requires && (
              <p style={{ margin: "6px 0 0", fontSize: 11, color: "var(--faint)" }}>Requires: {layer.requires}</p>
            )}
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* One BOM's component list, fetched only when the reader asks for it.
 *
 * This is the answer to "what is actually inside that depth number": the depth
 * badge says how deep the *best* component is, and this says which components
 * stop shallower. Rows are printed as the server labelled them — no state is
 * inferred here, and an empty list is displayed as the server's own words.
 */
function BomComponents({ kind }: { kind: string }) {
  const read = useApi<EstateBomDocument>(() => apiEstateBomComponents(kind), [kind]);
  const doc = read.data;
  if (!doc) {
    return (
      <p role="status" style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--amber)" }}>
        {read.running
          ? `Reading ${kind} components…`
          : `${kind} components not read — ${read.detail || read.error || "the control plane did not answer"}.`}
      </p>
    );
  }
  const rows = doc.components ?? [];
  if (rows.length === 0) {
    return (
      <p role="status" data-testid={`bom-components-empty-${kind}`} style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--amber)" }}>
        This BOM has no components in the stored observation ({doc.estate ?? "no estate named"}). {doc.question ?? ""}
      </p>
    );
  }
  const byUsage = rows.reduce<Record<string, number>>((acc, row) => {
    const key = (row.usage_state || "—").toUpperCase();
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  const shown = rows.slice(0, 200);
  return (
    <div style={{ marginTop: 10 }}>
      <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
        <Badge tone="cyan">{rows.length} components</Badge>
        {Object.entries(byUsage).map(([state, count]) => (
          <Badge key={state} tone={USAGE_TONE[state] ?? "slate"}>{state.replace(/_/g, " ")} {count}</Badge>
        ))}
        <span className="faint" style={{ fontSize: 10.5 }}>
          estate {doc.estate ?? "—"} · projection {(doc.projection_id ?? "—").slice(0, 12)}
        </span>
      </div>
      <div style={{ overflowX: "auto", maxHeight: 320, overflowY: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11.5 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--faint)" }}>
              <th style={{ padding: "4px 8px" }}>component</th>
              <th style={{ padding: "4px 8px" }}>type</th>
              <th style={{ padding: "4px 8px" }}>usage state</th>
              <th style={{ padding: "4px 8px" }}>evidence</th>
              <th style={{ padding: "4px 8px" }}>asset</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((row, index) => (
              <tr key={row.bom_ref ?? row.artifact_id ?? row.component_id ?? `${kind}-${index}`} style={{ borderTop: "1px solid var(--line)" }}>
                <td style={{ padding: "4px 8px" }}>
                  {row.algorithm || row.name || row.component_id || row.bom_ref || "—"}
                  {row.version ? <span className="faint"> {row.version}</span> : null}
                </td>
                <td style={{ padding: "4px 8px", color: "var(--dim)" }}>{row.type ?? "—"}</td>
                <td style={{ padding: "4px 8px" }}>
                  {row.usage_state
                    ? <Badge tone={USAGE_TONE[row.usage_state.toUpperCase()] ?? "slate"}>{row.usage_state.replace(/_/g, " ")}</Badge>
                    : <span className="faint">—</span>}
                </td>
                <td style={{ padding: "4px 8px", color: "var(--dim)" }}>
                  {row.evidence_type ?? "—"}
                  {row.evidence_ids?.length ? <span className="faint"> · {row.evidence_ids.length} id(s)</span> : null}
                </td>
                <td style={{ padding: "4px 8px", color: "var(--dim)" }}>{row.asset_name ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p style={{ margin: "8px 0 0", fontSize: 10.5, color: "var(--faint)" }}>
        {rows.length > shown.length
          ? `Showing ${shown.length} of ${rows.length} components; the rest are in the API response.`
          : `All ${rows.length} components shown.`} Usage state is the server's: a capability list can never read as use.
      </p>
    </div>
  );
}

function BomSection() {
  const read = useApi<BomMaturity>(apiBomMaturity, []);
  const [open, setOpen] = useState<string | null>(null);
  const doc = read.data;
  if (!doc) {
    return (
      <Panel title="Six BOMs" sub="how deep each projection is on this estate">
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {read.running
            ? "Reading BOM depth…"
            : `BOM depth not read — ${read.detail || read.error || "the control plane did not answer"}.`}
        </p>
      </Panel>
    );
  }
  if (doc.state === "NOT_OBSERVED" || doc.boms.length === 0) {
    return (
      <Panel title="Six BOMs" sub="how deep each projection is on this estate">
        <p role="status" data-testid="bom-unobserved" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {doc.reason ?? "no stored snapshot"}. Nothing is claimed about any BOM's depth.{" "}
          <Link to="/scanners" style={{ color: "var(--accent)" }}>Run a discovery sweep →</Link>
        </p>
        <p style={{ margin: "10px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{doc.claim}</p>
      </Panel>
    );
  }
  return (
    <Panel title="Six BOMs — one projection engine, six depths" sub={doc.claim}>
      {doc.rollup && (
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <Badge tone="cyan">{doc.rollup.boms} BOMs</Badge>
          <Badge tone="green">{doc.rollup.observed} at observed depth</Badge>
          <Badge tone="slate">{doc.rollup.at_ceiling} at their ceiling</Badge>
          {doc.deepest && doc.deepest.length > 0 && <Badge tone="green">deepest: {doc.deepest[0]}</Badge>}
          {doc.shallowest && doc.shallowest.length > 0 && <Badge tone="amber">shallowest: {doc.shallowest[0]}</Badge>}
        </div>
      )}
      <div style={{ display: "grid", gap: 8 }}>
        {doc.boms.map((bom) => (
          <div key={bom.kind} data-testid={`bom-${bom.kind}`} style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <b style={{ fontSize: 13 }}>{bom.kind}</b>
              <Badge tone={MATURITY_TONE[bom.depth] ?? "slate"}>{bom.depth.replace(/_/g, " ")}</Badge>
              <span className="faint" style={{ fontSize: 11 }}>
                ceiling {bom.ceiling.replace(/_/g, " ")}
                {bom.at_ceiling ? " · at ceiling" : ""}
              </span>
              <span className="faint" style={{ fontSize: 11 }}>{bom.label}</span>
            </div>
            <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{bom.question}</p>
            <Grid
              rows={[
                { key: "components", value: String(bom.components) },
                { key: "observed", value: String(bom.observed_components) },
                { key: "configured", value: String(bom.configured_components) },
                { key: "declared only", value: String(bom.declared_components) },
                { key: "unbacked", value: String(bom.unbacked_components) },
                { key: "evidence ids", value: String(bom.evidence_ids) },
              ]}
            />
            <Limit text={bom.cannot_claim} />
            <button
              type="button"
              className="btn ghost sm"
              aria-expanded={open === bom.kind}
              aria-label={`${open === bom.kind ? "Hide" : "Show"} ${bom.kind} components`}
              onClick={() => setOpen(open === bom.kind ? null : bom.kind)}
              style={{ marginTop: 8, fontSize: 11 }}
            >
              {open === bom.kind ? "Hide" : "Show"} {bom.kind} components
            </button>
            {open === bom.kind && <BomComponents kind={bom.kind} />}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function SurfaceRow({ surface }: { surface: MaturitySurface }) {
  return (
    <div
      data-testid={`surface-${surface.id}`}
      style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <b style={{ fontSize: 13 }}>{surface.label}</b>
        <Badge tone={REGISTER_TONE[surface.state] ?? "slate"}>{surface.state.replace(/_/g, " ")}</Badge>
        {surface.collector ? (
          <span className="faint" style={{ fontSize: 11, fontFamily: "var(--mono)" }}>{surface.collector}</span>
        ) : (
          <span className="faint" style={{ fontSize: 11 }}>no collector in this build</span>
        )}
      </div>
      <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{surface.note}</p>
      {surface.missing.length > 0 && (
        <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--amber)" }}>
          {surface.missing.map((gap) => (
            <li key={gap}>{gap}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* The five boundaries, in the product's own words. Rendered above the register
 * because a reader should meet the limits before the coverage numbers. */
function BoundariesPanel({ rows }: { rows: CapabilityBoundary[] }) {
  return (
    <Panel
      title="Five capabilities this build does not present as operational"
      sub="each row names the artifact that exists, and what it does not entitle anyone to"
    >
      <div style={{ display: "grid", gap: 8 }}>
        {rows.map((row) => (
          <div
            key={row.id}
            data-testid={`boundary-${row.id}`}
            style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}
          >
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <b style={{ fontSize: 13 }}>{row.capability}</b>
              <span data-testid={`boundary-status-${row.id}`}>
                <Badge tone={READINESS_TONE[row.status] ?? "slate"}>{row.status}</Badge>
              </span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{row.check_at}</span>
            </div>
            <p style={{ margin: "6px 0 0", fontSize: 12 }}>{row.says}</p>
            <p style={{ margin: "4px 0 0", fontSize: 11.5, color: "var(--green)" }}>
              real: {row.what_is_real}
            </p>
            <p style={{ margin: "4px 0 0", fontSize: 11.5, color: "var(--red)" }}>
              not: {row.not_operational}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function MaturitySection() {
  const read = useApi<MaturityRegister>(apiMaturityRegister, []);
  const doc = read.data;
  if (!doc) {
    return (
      <Panel title="Maturity register" sub="where each capability reaches, and where it stops">
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {read.running
            ? "Reading the maturity register…"
            : `Register not read — ${read.detail || read.error || "the control plane did not answer"}.`}
        </p>
      </Panel>
    );
  }
  return (
    <>
      {doc.boundaries && doc.boundaries.length > 0 && <BoundariesPanel rows={doc.boundaries} />}
      <Panel title="What the product may claim" sub={doc.claims.why}>
        <div style={{ border: "1px solid var(--green)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}>
          <Badge tone="green">may claim</Badge>
          <p style={{ margin: "6px 0 0", fontSize: 12.5 }}>{doc.claims.may_claim}</p>
        </div>
        <div style={{ marginTop: 10, border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}>
          <Badge tone="red">may not claim</Badge>
          <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12.5 }}>
            {doc.claims.may_not_claim.map((claim) => (
              <li key={claim}>{claim}</li>
            ))}
          </ul>
        </div>
      </Panel>

      {doc.areas.map((area) => (
        <Panel key={area.id} title={area.label} sub={area.summary}>
          <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
            <Badge tone={REGISTER_TONE[area.state] ?? "slate"}>{area.state.replace(/_/g, " ")}</Badge>
            <span data-testid={`readiness-${area.id}`}>
              <Badge tone={READINESS_TONE[area.readiness] ?? "slate"}>{area.readiness}</Badge>
            </span>
            <span className="faint" style={{ fontSize: 11 }}>
              {area.surfaces.length} surfaces · {area.missing.length} open items
            </span>
          </div>
          <p style={{ margin: "0 0 10px", fontSize: 11.5, color: "var(--dim)" }}>{area.readiness_meaning}</p>
          {area.must_not_be_presented_as.length > 0 && (
            <div
              data-testid={`maynot-${area.id}`}
              style={{
                border: "1px solid var(--red)",
                borderRadius: "var(--r)",
                padding: "8px 12px",
                background: "var(--panel-2)",
                marginBottom: 10,
              }}
            >
              <Badge tone="red">must not be presented as</Badge>
              <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--red)" }}>
                {area.must_not_be_presented_as.map((sentence) => (
                  <li key={sentence}>{sentence}</li>
                ))}
              </ul>
            </div>
          )}
          <div style={{ display: "grid", gap: 8 }}>
            {area.surfaces.map((surface) => (
              <SurfaceRow key={surface.id} surface={surface} />
            ))}
          </div>
          {area.missing.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div className="faint" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6 }}>
                Still missing in this area
              </div>
              <ul style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--amber)" }}>
                {area.missing.map((gap) => (
                  <li key={gap}>{gap}</li>
                ))}
              </ul>
            </div>
          )}
          <p style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{area.claim}</p>
          <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
            {area.measured_by.map((route) => (
              <span key={route} style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>
                {route}
              </span>
            ))}
          </div>
        </Panel>
      ))}
    </>
  );
}

function SimulationSection() {
  const read = useApi<EnterpriseSimulationCatalogue>(apiSimulationScenarios, []);
  const doc = read.data;
  if (!doc) {
    return (
      <Panel title="Simulation scenarios" sub="what the engine can compute, and what it cannot">
        <p role="status" style={{ margin: 0, fontSize: 12.5, color: "var(--amber)" }}>
          {read.running
            ? "Reading the scenario catalogue…"
            : `Catalogue not read — ${read.detail || read.error || "the control plane did not answer"}.`}
        </p>
      </Panel>
    );
  }
  const unresolved = doc.unresolved ?? [];
  return (
    <>
      <Panel
        title="Simulation is scenario-specific"
        sub={`${doc.rollup.scenarios} scenarios · ${doc.rollup.EXISTS ?? 0} computed · ${doc.rollup.PARTIAL ?? 0} partial · ${doc.rollup.ABSENT ?? 0} absent`}
      >
        <div
          style={{ border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "10px 12px", background: "var(--panel-2)" }}
        >
          <Badge tone="red">may not claim</Badge>
          <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 12.5 }}>
            {doc.cannot_claim.map((sentence) => (
              <li key={sentence}>{sentence}</li>
            ))}
          </ul>
        </div>
        {doc.note && <p style={{ margin: "8px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{doc.note}</p>}
        {unresolved.length > 0 && (
          <p role="alert" style={{ margin: "8px 0 0", fontSize: 12, color: "var(--red)" }}>
            The catalogue advertises {unresolved.length} scenario(s) this build does not execute:{" "}
            {unresolved.join(", ")}.
          </p>
        )}
      </Panel>

      {doc.scenarios.map((row) => (
        <Panel key={row.id} title={row.label} sub={row.status_meaning}>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <span data-testid={`simulation-${row.id}`}>
              <Badge tone={SIMULATION_TONE[row.status] ?? "slate"}>{row.status}</Badge>
            </span>
            {row.covered_by.length === 0 ? (
              <span className="faint" style={{ fontSize: 11 }}>nothing computes this</span>
            ) : (
              row.covered_by.map((entry) => (
                <span
                  key={`${entry.engine}-${entry.scenario}`}
                  style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}
                >
                  {entry.engine}/{entry.scenario}
                  {entry.present === false ? " (missing)" : ""}
                </span>
              ))
            )}
          </div>
          {row.cannot.length > 0 && (
            <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--amber)" }}>
              {row.cannot.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          )}
          {row.requires.length > 0 && (
            <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>
              needs: {row.requires.join("; ")}
            </p>
          )}
          {row.note && <p style={{ margin: "6px 0 0", fontSize: 11.5, color: "var(--dim)" }}>{row.note}</p>}
        </Panel>
      ))}
    </>
  );
}

export default function CollectorDepth() {
  const [tab, setTab] = useState<"runtime" | "network" | "windows" | "boms" | "maturity" | "simulation">("runtime");
  const tabs: Array<{ id: typeof tab; label: string }> = [
    { id: "runtime", label: "Runtime" },
    { id: "network", label: "Network" },
    { id: "windows", label: "Windows" },
    { id: "boms", label: "Six BOMs" },
    { id: "maturity", label: "Maturity" },
    { id: "simulation", label: "Simulation" },
  ];
  return (
    <>
      <PageHead
        crumb="discovery / collector depth"
        title="Collector depth"
        sub="how far each collector actually reaches — measured per family, protocol, platform and BOM"
        right={<LiveBadge source="live" label="BUILD-DERIVED" />}
      />
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
        {tabs.map((entry) => (
          <button
            key={entry.id}
            type="button"
            onClick={() => setTab(entry.id)}
            aria-pressed={tab === entry.id}
            style={{
              padding: "6px 14px",
              borderRadius: 999,
              fontSize: 12,
              fontWeight: tab === entry.id ? 700 : 500,
              cursor: "pointer",
              background: tab === entry.id ? "var(--accent)" : "var(--panel-2)",
              color: tab === entry.id ? "#fff" : "var(--text)",
              border: `1px solid ${tab === entry.id ? "var(--accent)" : "var(--line)"}`,
            }}
          >
            {entry.label}
          </button>
        ))}
      </div>
      {tab === "runtime" && <RuntimeSection />}
      {tab === "network" && <NetworkSection />}
      {tab === "windows" && <WindowsSection />}
      {tab === "boms" && <BomSection />}
      {tab === "maturity" && <MaturitySection />}
      {tab === "simulation" && <SimulationSection />}
    </>
  );
}
