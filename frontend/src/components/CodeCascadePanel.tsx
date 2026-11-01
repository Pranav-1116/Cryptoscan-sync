import React, { useEffect, useState } from "react";
import { Badge, Panel, Table, Bar, Ring } from "./ui";
import { apiScanCascade, apiScansRecent, CascadeReport, ScanSummaryRow } from "../lib/api";
import { CountUp, StaggerGroup, StaggerItem } from "../lib/motion";
import { IconCode, IconHardware } from "./icons";

/** Code-level dependency & cascade for one scan: which files do crypto, who depends on them, in what order to migrate. */
export default function CodeCascadePanel() {
  const [scans, setScans] = useState<ScanSummaryRow[]>([]);
  const [scanId, setScanId] = useState<string>("");
  const [system, setSystem] = useState<string>("");
  const [report, setReport] = useState<CascadeReport | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "none" | "offline">("loading");

  useEffect(() => {
    let alive = true;
    (async () => {
      const r = await apiScansRecent(25);
      if (!alive) return;
      if (r.source !== "live" || !r.data) { setState("offline"); return; }
      const withCascade = r.data.scans.filter((s) => s.statistics && s.statistics.cascade_summary);
      setScans(withCascade);
      if (withCascade.length) setScanId(withCascade[0].scan_id); else setState("none");
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    setState("loading");
    (async () => {
      const r = await apiScanCascade(scanId, system || undefined);
      if (!alive) return;
      if (r.source === "live" && r.data) { setReport(r.data); setState("ready"); } else { setReport(null); setState("none"); }
    })();
    return () => { alive = false; };
  }, [scanId, system]);

  const s = report?.summary || {};
  return (
    <Panel
      title={
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <IconCode size={14} style={{ color: "var(--accent)" }} /> Code-level cascade
          <Badge tone="cyan">DETERMINISTIC</Badge>
          <Badge tone="slate">BFS</Badge>
        </span>
      }
      sub="Code → system → dependents. Only registered edges. No inference."
      className="mt"
      style={{ borderTop: "2px solid var(--accent)", padding: 0, overflow: "hidden" }}
    >
      <div style={{ padding: "14px 16px", background: "var(--panel)", borderBottom: state === "ready" ? "1px solid var(--line)" : "none" }}>
        <div style={{ display: "grid", gridTemplateColumns: "minmax(280px,1fr) 160px auto", gap: 10, alignItems: "end" }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "var(--dim)", textTransform: "uppercase" }}>Source scan</span>
            <select className="inp" value={scanId} onChange={(e) => { setScanId(e.target.value); setSystem(""); }} aria-label="scan" style={{ fontFamily: "var(--mono)", fontSize: 12 }}>
              {scans.map((sc) => (
                <option key={sc.scan_id} value={sc.scan_id}>{sc.target_location.replace(/^https?:\/\//, "")} · {(sc.scan_end || "").slice(0, 16)}</option>
              ))}
            </select>
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "var(--dim)", textTransform: "uppercase" }}>System filter</span>
            {report?.systems && report.systems.length > 0 ? (
              <select className="inp" value={system} onChange={(e) => setSystem(e.target.value)} aria-label="system" style={{ fontSize: 12 }}>
                <option value="">All systems</option>
                {report.systems.map((sy) => <option key={sy.system} value={sy.system}>{sy.system}</option>)}
              </select>
            ) : (
              <span style={{ fontSize: 11, color: "var(--faint)", padding: "8px 0" }}>No system filter — all providers</span>
            )}
          </label>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "transparent", textTransform: "uppercase" }}>filter</span>
            {system && <Badge tone="cyan">{system} <button onClick={() => setSystem("")} style={{ marginLeft: 6, background: "none", border: "none", cursor: "pointer", color: "inherit", fontWeight: 700 }}>×</button></Badge>}
          </div>
        </div>
        <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8 }}>Scope determines entry edge — code providers are resolved to their owning system, then BFS walks the dependency graph.</div>
      </div>

      {state === "offline" && <p style={{ color: "var(--dim)", fontSize: 13 }}>Backend offline.</p>}
      {state === "none" && <p style={{ color: "var(--dim)", fontSize: 13 }}>No scan with a cascade report yet — run a source scan (scanner ≥ 1.1, <code>CRYPTOSCAN_CASCADE</code> on).</p>}
      {state === "loading" && <p style={{ color: "var(--dim)", fontSize: 13 }}>Loading…</p>}

      {state === "ready" && report && (
        <>
          <StaggerGroup step={0.04} style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 14 }}>
            {[
              ["Crypto providers", s.providers, "files that perform crypto"],
              ["With dependents", s.providers_with_dependents, "other files import them"],
              ["Libraries", s.libraries, `${s.libraries_declared_but_unused ?? 0} declared-unused · ${s.libraries_used_but_undeclared ?? 0} undeclared`],
              ["Shared key ids", s.shared_key_identifiers, "keystores / aliases / env vars in ≥2 files"],
              ["Weak parameters", s.weak_parameters, "key size below floor"],
              ["Migration waves", s.migration_waves, "topological order"],
            ].map(([k, v, sub]) => (
              <StaggerItem key={String(k)} className="panel cascade-stat" style={{ padding: 12 }}>
                <div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{k}</div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>
                  {typeof v === "number" ? <CountUp value={v} /> : (v ?? "—")}
                </div>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>{sub}</div>
              </StaggerItem>
            ))}
          </StaggerGroup>

          {report.systems && report.systems.length > 0 && (
            <>
              <h4 style={{ margin: "10px 0 6px" }}>Business systems</h4>
              <Table
                head={["System", "Criticality", "Providers", "Algorithms", "Weak", "Depended on by", "Depends on", "Earliest wave"]}
                rows={report.systems.map((sy) => [
                  <button key={sy.system} className="btn outline" style={{ fontSize: 11, padding: "2px 8px" }} onClick={() => setSystem(sy.system)}>{sy.system}</button>,
                  sy.criticality || "—", sy.providers, sy.algorithms.slice(0, 6).join(", "), sy.weak_parameters,
                  sy.dependent_systems.join(", ") || "—", sy.depends_on_systems.join(", ") || "—", sy.earliest_wave ?? "—",
                ])}
              />
            </>
          )}

          <h4 style={{ margin: "14px 0 6px" }}>Providers by blast radius</h4>
          <Table
            head={["#", "Wave", "File", "Algorithms", "Findings", "Direct dependents", "Transitive", "Origin"]}
            total={report.providers.length} rows={report.providers.slice(0, 25).map((p) => [
              p.rank, <Badge key={p.file} tone={p.wave === 1 ? "cyan" : undefined}>wave {p.wave}</Badge>, <code key={p.file + "f"} style={{ fontSize: 11 }}>{p.file}</code>,
              p.algorithms.slice(0, 5).join(", "), p.findings, p.direct_dependents, p.transitive_dependents, p.code_origin || "source",
            ])}
          />

          <h4 style={{ margin: "14px 0 6px" }}>Migration waves</h4>
          <Table
            head={["Wave", "Providers", "Dependents affected", "Why"]}
            rows={report.migration_waves.map((w) => [w.wave, w.providers.length, w.dependents_affected, <span key={w.wave} style={{ fontSize: 12 }}>{w.why}</span>])}
          />

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 14, marginTop: 14 }}>
            <div>
              <h4 style={{ margin: "0 0 6px" }}>Crypto libraries</h4>
              <Table
                head={["Library", "Versions", "Files using", "Flags"]}
                total={report.libraries.length} rows={report.libraries.slice(0, 20).map((l) => [
                  l.library, l.versions.join(", ") || "—", l.files_using,
                  <span key={l.library}>{l.declared_but_unused && <Badge tone="warn">declared, unused</Badge>}{l.used_but_undeclared && <Badge tone="warn">used, undeclared</Badge>}</span>,
                ])}
              />
            </div>
            <div>
              <h4 style={{ margin: "0 0 6px" }}>Shared key material</h4>
              <Table
                head={["Kind", "Identifier", "Files", "Algorithms"]}
                total={report.shared_keys.length} rows={report.shared_keys.slice(0, 20).map((k) => [k.kind, <code key={k.identifier} style={{ fontSize: 11 }}>{k.identifier}</code>, k.files.length, k.algorithms.join(", ")])}
              />
              <h4 style={{ margin: "14px 0 6px" }}>Key sizes below the floor</h4>
              <Table
                head={["Algorithm", "Size", "Minimum", "Location"]}
                total={report.weak_parameters.length} rows={report.weak_parameters.slice(0, 20).map((w) => [w.algorithm, w.key_size, w.minimum, <code key={w.file + w.line} style={{ fontSize: 11 }}>{w.file}:{w.line}</code>])}
              />
            </div>
          </div>
          {report.truncated && Object.values(report.truncated).some((n) => n > 0) && (
            <p style={{ fontSize: 11, color: "var(--dim)", marginTop: 8 }}>Report truncated for size; full data via the scan JSON export.</p>
          )}
        </>
      )}
    </Panel>
  );
}
