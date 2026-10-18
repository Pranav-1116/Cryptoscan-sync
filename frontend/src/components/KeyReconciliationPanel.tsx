import React, { useEffect, useState } from "react";
import { Badge, Panel, Table } from "./ui";
import { apiKeyReconciliation, apiScansRecent, KeyReconciliation, ScanSummaryRow } from "../lib/api";

/** HSM / KMS / keystore / certificate exports (key-inventory scans) reconciled with the key identifiers referenced by scanned source. */
export default function KeyReconciliationPanel() {
  const [scans, setScans] = useState<ScanSummaryRow[]>([]);
  const [scanId, setScanId] = useState("");
  const [report, setReport] = useState<KeyReconciliation | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "none" | "offline">("loading");

  useEffect(() => {
    let alive = true;
    (async () => {
      const r = await apiScansRecent(50);
      if (!alive) return;
      if (r.source !== "live" || !r.data) { setState("offline"); return; }
      const inv = r.data.scans.filter((s) => (s.statistics?.evidence_sources?.KEY_INVENTORY ?? 0) > 0);
      setScans(inv);
      if (inv.length) setScanId(inv[0].scan_id); else setState("none");
    })();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    setState("loading");
    (async () => {
      const r = await apiKeyReconciliation(scanId);
      if (!alive) return;
      if (r.source === "live" && r.data) { setReport(r.data); setState("ready"); } else { setReport(null); setState("none"); }
    })();
    return () => { alive = false; };
  }, [scanId]);

  const s = report?.summary;
  return (
    <Panel title="Key inventory ↔ source reconciliation" sub="Compare HSM, KMS, keystore and certificate inventories with the key identifiers referenced in code" className="mt">
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
        <label style={{ fontSize: 12, color: "var(--dim)" }}>Inventory scan</label>
        <select value={scanId} onChange={(e) => setScanId(e.target.value)} style={{ fontSize: 12, padding: "4px 8px" }} aria-label="inventory scan">
          {scans.map((sc) => <option key={sc.scan_id} value={sc.scan_id}>{sc.target_location} · {(sc.scan_end || "").slice(0, 16)} · {sc.statistics?.evidence_sources?.KEY_INVENTORY} keys</option>)}
        </select>
        {report && <span style={{ fontSize: 11, color: "var(--dim)" }}>against {report.source_scans.length} source scan(s)</span>}
      </div>
      {state === "offline" && <p style={{ color: "var(--dim)", fontSize: 13 }}>Backend offline.</p>}
      {state === "none" && <p style={{ color: "var(--dim)", fontSize: 13 }}>No key-inventory scan yet — scan the key-export drop with <code>CRYPTOSCAN_KEY_INVENTORY=1</code>.</p>}
      {state === "loading" && <p style={{ color: "var(--dim)", fontSize: 13 }}>Loading…</p>}
      {state === "ready" && report && s && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 14 }}>
            {[["Inventory keys", s.inventory_keys, ""], ["With consumers", s.consumers, "referenced by scanned code"], ["Orphans", s.orphans, "no scanned repo uses them"], ["In code, in no inventory", s.not_in_inventory, "aliases / keystores unaccounted for"]].map(([k, v, sub]) => (
              <div key={String(k)} className="panel" style={{ padding: 12 }}>
                <div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>{k}</div>
                <div style={{ fontSize: 22, fontWeight: 700, color: k === "Orphans" && Number(v) > 0 ? "var(--amber)" : k === "In code, in no inventory" && Number(v) > 0 ? "var(--red)" : undefined }}>{v}</div>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>{sub}</div>
              </div>
            ))}
          </div>
          <h4 style={{ margin: "10px 0 6px" }}>Keys with consumers</h4>
          <Table head={["System", "Label", "Algorithm", "Store", "Referenced as", "Files"]}
            rows={report.consumers.slice(0, 50).map((c) => [c.system, <code key={c.label} style={{ fontSize: 11 }}>{c.label}</code>, `${c.algorithm || ""}${c.key_size ? "-" + c.key_size : ""}`, c.key_store || "—",
              c.references.map((r) => `${r.kind}:${r.identifier}`).join(", "), c.references.reduce((n, r) => n + r.files, 0)])} />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 14, marginTop: 14 }}>
            <div>
              <h4 style={{ margin: "0 0 6px" }}>Orphans <Badge tone="warn">{report.orphans.length}</Badge></h4>
              <Table head={["System", "Label", "Algorithm", "State", "Expires"]}
                rows={report.orphans.slice(0, 50).map((o) => [o.system, <code key={o.label} style={{ fontSize: 11 }}>{o.label}</code>, `${o.algorithm || ""}${o.key_size ? "-" + o.key_size : ""}`, o.state || "—", o.not_after || "—"])} />
            </div>
            <div>
              <h4 style={{ margin: "0 0 6px" }}>In code, in no inventory <Badge tone="red">{report.not_in_inventory.length}</Badge></h4>
              <Table head={["Kind", "Identifier", "Files", "Example"]}
                rows={report.not_in_inventory.slice(0, 50).map((n) => [n.kind, <code key={n.identifier} style={{ fontSize: 11 }}>{n.identifier}</code>, n.files, <code key={n.identifier + "f"} style={{ fontSize: 11 }}>{n.sample_files[0]}</code>])} />
            </div>
          </div>
        </>
      )}
    </Panel>
  );
}
