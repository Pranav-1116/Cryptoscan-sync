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

import { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui";
import { LiveBadge, useApi } from "../lib/apiUi";
import {
  apiBomMaturity,
  apiNetworkProtocols,
  apiRuntimeDepth,
  apiWindowsCollector,
  type BomMaturity,
  type NetworkProtocols,
  type RuntimeDepth,
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
    <p style={{ margin: "6px 0 0", fontSize: 11, color: "var(--dim)" }}>
      <b>Gaps:</b> {gaps.join(" · ")}
    </p>
  );
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
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
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

function BomSection() {
  const read = useApi<BomMaturity>(apiBomMaturity, []);
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
          </div>
        ))}
      </div>
    </Panel>
  );
}

export default function CollectorDepth() {
  const [tab, setTab] = useState<"runtime" | "network" | "windows" | "boms">("runtime");
  const tabs: Array<{ id: typeof tab; label: string }> = [
    { id: "runtime", label: "Runtime" },
    { id: "network", label: "Network" },
    { id: "windows", label: "Windows" },
    { id: "boms", label: "Six BOMs" },
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
    </>
  );
}
