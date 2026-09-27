import React, { useCallback, useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import {
  apiNbomLive,
  NbomCascadeEntry,
  NbomComponent,
  NbomResponse,
} from "../lib/api.js";

/* NBOM — Network Bill of Materials.
 *
 * The CBOM covers cryptography in the estate's source. This covers what is
 * exposed on the wire, which is a different inventory that misses different
 * things: no repository mentions the load balancer terminating TLS 1.0 for a
 * legacy partner, and no network probe sees an algorithm picked at runtime.
 *
 * The table that earns the page is "migration priority": components ranked by
 * severity and then by blast radius, so the first row is the single change
 * that removes the most risk. A flat inventory cannot produce that ordering —
 * it needs the dependency graph.
 */

const SEV_TONE: Record<string, string> = {
  critical: "red", high: "orange", medium: "amber", low: "blue", info: "slate",
};

function prop(component: NbomComponent, key: string): string | undefined {
  return component.properties.find((p) => p.name === `cryptoscan:${key}`)?.value;
}

export default function Nbom() {
  const [data, setData] = useState<NbomResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<NbomCascadeEntry | null>(null);

  // Derived from stored network scans, not declared here: the scanner finds
  // the listeners. Until a scan has run there is nothing to inventory, and the
  // page says so rather than showing an invented estate.
  const load = useCallback(async () => {
    setLoading(true);
    const res = await apiNbomLive();
    if (res.ok && res.data) {
      setData(res.data);
      setError(null);
    } else {
      setError(res.error || "No network inventory available yet.");
      setData(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => { void load(); }, [load]);

  const summary = data?.summary;
  const components = data?.nbom.components ?? [];
  const sev = summary?.by_severity ?? {};

  return (
    <>
      <PageHead
        crumb="boms / nbom"
        title="NBOM"
        sub="Network Bill of Materials — listeners · certificates · cipher suites · tunnels, with the dependency graph"
        right={
          <>
            <Badge tone={components.length ? "green" : ""}>
              <span className="dot" /> {components.length} COMPONENTS
            </Badge>
            {summary?.unobserved ? (
              <Badge tone="slate">{summary.unobserved} UNOBSERVED</Badge>
            ) : null}
          </>
        }
      />

      <div className="grid cols-5">
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => (
          <Panel key={s} className="stat">
            <div className="label">{s}</div>
            <div className="value" style={{ color: sev[s] ? `var(--${SEV_TONE[s]})` : undefined }}>
              {sev[s] ?? 0}
            </div>
          </Panel>
        ))}
      </div>

      <Panel
        className="mt"
        title="Migration priority"
        sub="ranked by severity, then by how much of the estate a replacement touches — the top row removes the most risk"
      >
        <Table
          head={["component", "kind", "severity", "blast radius", "affected"]}
          rows={(summary?.migration_priority ?? []).map((m) => [
            <span className="mono" style={{ fontWeight: 600 }}>{m.name ?? m.ref}</span>,
            <span className="dim">
              {Object.keys(m.by_kind ?? {}).join(", ") || "—"}
            </span>,
            m.worst_severity
              ? <Badge tone={SEV_TONE[m.worst_severity]}><span className="dot" />{m.worst_severity}</Badge>
              : <span className="dim">—</span>,
            <span className="num">{m.affected_count}</span>,
            <button className="btn sm" onClick={() => setSelected(m)}>trace</button>,
          ])}
        />
        {!summary?.migration_priority?.length && !loading && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {error ?? "No findings — run a network scan in Operations to populate the NBOM."}
          </div>
        )}
      </Panel>

      {selected && (
        <Panel
          className="mt"
          title={`Blast radius — ${selected.name ?? selected.ref}`}
          sub="everything that must change if this component is replaced"
        >
          <Table
            head={["affected component", "kind"]}
            rows={selected.affected.map((a) => [
              <span className="mono">{a.name}</span>,
              <Badge>{a.kind ?? "—"}</Badge>,
            ])}
          />
          {!selected.affected.length && (
            <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
              Nothing depends on this component — it can be replaced in isolation.
            </div>
          )}
        </Panel>
      )}

      <Panel className="mt" title="Inventory" sub="every component on the wire, with what was actually observed">
        <Table
          head={["component", "kind", "detail", "observed", "findings"]}
          rows={components.map((c) => {
            const kind = prop(c, "kind") ?? "—";
            const observed = prop(c, "observed") !== "False";
            const detail = prop(c, "tls_version") ?? prop(c, "public_key_algorithm")
              ?? prop(c, "encryption") ?? prop(c, "protocol") ?? "—";
            const worst = c["cryptoscan:findings"][0]?.severity;
            return [
              <span className="mono" style={{ fontWeight: 600 }}>{c.name}</span>,
              <Badge tone={kind === "certificate" ? "violet" : ""}>{kind}</Badge>,
              <span className="mono">{detail}</span>,
              observed
                ? <Badge tone="green"><span className="dot" />observed</Badge>
                : <span title="never successfully probed — unknown, not healthy">
                    <Badge tone="slate"><span className="dot" />unobserved</Badge>
                  </span>,
              worst
                ? <Badge tone={SEV_TONE[worst]}>{c["cryptoscan:findings"].length}</Badge>
                : <span className="dim">—</span>,
            ];
          })}
        />
        {!components.length && !loading && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            Nothing on the wire has been inventoried yet.
          </div>
        )}
      </Panel>
    </>
  );
}
