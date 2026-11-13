// Shared asset detail (docs/boms/01_PRODUCT_SPEC.md §7) — one canonical
// detail surface for every BOM record: header record, asset information
// fields, the cross-BOM relationships panel (linked / not established /
// unknown / primary record, never conflated) and the nine detail tabs.
// Relationships exist only where stored evidence establishes them; usage
// states are never equated; hardware detail never emits secrets.
import React, { useState } from "react";
import { Badge, Panel } from "./ui.jsx";
import { useApi } from "../lib/apiUi.jsx";
import {
  apiAssetDetailHeader,
  apiAssetDetailTab,
  type AssetDetailHeader,
  type AssetDetailTab,
} from "../lib/api.js";

const DETAIL_TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "components", label: "Components" },
  { id: "cryptography", label: "Cryptography" },
  { id: "hardware", label: "Hardware" },
  { id: "network", label: "Network" },
  { id: "vendors", label: "Vendors" },
  { id: "dependencies", label: "Dependencies" },
  { id: "evidence", label: "Evidence" },
  { id: "history", label: "History" },
];

const TAB_COLUMNS: Record<string, string[]> = {
  overview: ["field", "value"],
  components: ["component_ref", "name", "type", "version", "evidence"],
  cryptography: ["crypto_ref", "algorithm", "key_size", "mode", "purpose", "usage_state", "basis"],
  hardware: ["asset_ref", "manufacturer", "model", "device_type", "serial", "firmware_version", "risk_level", "first_seen", "last_seen", "last_verified"],
  network: ["endpoint", "protocol", "service", "tls_version", "cipher_suite", "certificate_subject", "observed", "basis"],
  vendors: ["vendor_ref", "name", "supplies_system", "system_name", "vendor_type", "criticality", "dependency_type", "basis"],
  dependencies: ["from", "to", "type", "evidence"],
  evidence: ["evidence_id", "algorithm", "confidence", "content_hash", "chain_position", "file_path", "captured_at", "freshness"],
  history: ["event", "captured_at", "created_at", "updated_at", "basis"],
};

function RelationBadge({ state }: { state: string }) {
  const tone = state === "PRIMARY_RECORD" ? "pass" : state === "LINKED" ? "cyan" : state === "UNKNOWN" ? "slate" : "default";
  const label = state === "PRIMARY_RECORD" ? "primary record" : state === "LINKED" ? "linked" : state === "NOT_ESTABLISHED" ? "not established" : "unknown";
  return <Badge tone={tone}>{label}</Badge>;
}

const TAB_IDS = ["overview", "components", "cryptography", "hardware", "network", "vendors", "dependencies", "evidence", "history"];

export default function AssetDetail({ assetRef, onBack, initialTab }: { assetRef: string; onBack?: () => void; initialTab?: string | null }) {
  const [tab, setTab] = useState(initialTab && TAB_IDS.includes(initialTab) ? initialTab : "overview");
  const header = useApi(() => apiAssetDetailHeader(assetRef), [assetRef]);
  const detail = useApi(() => apiAssetDetailTab(assetRef, tab), [assetRef, tab]);
  const h = header.data as unknown as AssetDetailHeader | null;
  const t = detail.data as unknown as AssetDetailTab | null;

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <Panel title="Asset record" sub="one canonical record — the same asset in every BOM view">
        {header.source !== "live" || !h ? (
          <p role="status" style={{ margin: 0, fontSize: 12, color: "var(--amber)" }}>
            {header.running ? "Reading the asset record…" : `The asset record could not be read${header.detail ? ` — ${header.detail}` : ""}. An unread record is not an empty one.`}
          </p>
        ) : (
          <div style={{ display: "grid", gap: 12 }}>
            <div style={{ fontSize: 13, lineHeight: 1.5 }}>
              <code style={{ fontSize: 12 }}>{h.asset_ref}</code>
              <span style={{ fontWeight: 802, margin: "0 8px", fontSize: 15 }}>{h.name}</span>
              <Badge tone="slate">{h.status}</Badge>
              {h.description ? <span style={{ color: "var(--dim)", marginLeft: 8 }}>{h.description}</span> : null}
              <div style={{ color: "var(--dim)", fontSize: 12, marginTop: 4 }}>
                {h.environment || "—"} · {h.primary_bom} · {h.chips.join(" · ")}
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 8 }}>
              {[["Asset ID", h.asset_id], ["Environment", h.environment || "—"], ["Category", h.category],
                ["Owner", h.owner || "—"], ["Source", h.source], ["Last observed", String(h.last_observed ?? "—").slice(0, 10)]]
                .map(([label, value]) => (
                  <div key={String(label)} style={{ border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "7px 9px" }}>
                    <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>{label}</div>
                    <div style={{ fontSize: 11.5, color: "var(--text)", marginTop: 2, wordBreak: "break-all" }}>{String(value)}</div>
                  </div>
                ))}
            </div>
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>CROSS-BOM RELATIONSHIPS</div>
              {h.related.map((rel) => (
                <div key={rel.bom} style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 11.5, color: "var(--dim)", marginBottom: 3 }}>
                  <span style={{ width: 62, fontWeight: 600, color: "var(--text)" }}>{rel.bom}</span>
                  <RelationBadge state={rel.state} />
                  <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{rel.basis}</span>
                </div>
              ))}
            </div>
            {onBack ? (
              <div><button className="btn outline" style={{ fontSize: 11.5 }} onClick={onBack}>← back to the inventory</button></div>
            ) : null}
          </div>
        )}
      </Panel>

      <div role="tablist" aria-label="Asset detail sections" style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {DETAIL_TABS.map((d) => (
          <button key={d.id} role="tab" aria-selected={tab === d.id}
            onClick={() => setTab(d.id)}
            style={{
              fontSize: 11, padding: "6px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${tab === d.id ? "var(--accent)" : "var(--line-strong)"}`,
              background: tab === d.id ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)",
              color: tab === d.id ? "var(--accent)" : "var(--dim)", fontFamily: "var(--mono)",
            }}>{d.label}</button>
        ))}
      </div>

      <Panel title={DETAIL_TABS.find((d) => d.id === tab)?.label ?? tab} sub={t?.note ?? ""}>
        {detail.source !== "live" || !t ? (
          <p role="status" style={{ margin: 0, fontSize: 12, color: "var(--amber)" }}>
            {detail.running ? "Reading the section…" : `The section could not be read${detail.detail ? ` — ${detail.detail}` : ""}. An unread record is not an empty one.`}
          </p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead>
                <tr>{(TAB_COLUMNS[tab] ?? []).filter((c) => (t.rows ?? []).some((r) => c in r)).map((c) => <th key={c}>{c}</th>)}</tr>
              </thead>
              <tbody>
                {(t.rows ?? []).length ? (t.rows ?? []).map((row, i) => (
                  <tr key={i}>
                    {(TAB_COLUMNS[tab] ?? []).filter((c) => c in row).map((c) => (
                      <td key={c}>
                        {c === "observed" ? (
                          <Badge tone={row[c] ? "pass" : "slate"}>{row[c] ? "observed" : "unknown"}</Badge>
                        ) : c === "usage_state" ? (
                          <Badge tone={row[c] === "operation_observed" ? "pass" : row[c] === "vendor_declared" ? "amber" : "slate"}>{String(row[c])}</Badge>
                        ) : c === "freshness" ? (
                          <Badge tone={row[c] === "CURRENT" ? "green" : row[c] === "STALE" ? "amber" : "slate"}>{String(row[c])}</Badge>
                        ) : (
                          <span style={{ fontSize: 11, fontFamily: ["key_size", "chain_position", "serial", "content_hash", "captured_at", "first_seen", "last_seen", "last_verified", "created_at", "updated_at"].includes(c) ? "var(--mono)" : undefined, wordBreak: "break-all" }}>
                            {row[c] === null || row[c] === undefined || row[c] === "" ? "—" : String(row[c])}
                          </span>
                        )}
                      </td>
                    ))}
                  </tr>
                )) : (
                  <tr><td colSpan={(TAB_COLUMNS[tab] ?? []).length || 1} style={{ padding: 26, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>
                    <div style={{ fontWeight: 600, color: "var(--text)" }}>Nothing stored yet</div>
                    <div style={{ fontSize: 11.5, marginTop: 4 }}>{t.note || "Empty rows here mean no stored observations — not a healthy zero."}</div>
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

/** Open the same nine-tab detail from any BOM inventory without discarding
 * that BOM's specialist drawer. No asset reference means no claimed link. */
export function CanonicalDetailLink({ assetRef }: { assetRef?: string | null }) {
  const [open, setOpen] = useState(false);
  if (!assetRef) return <p className="faint">No canonical asset reference was recorded for this row.</p>;
  return (
    <div style={{ marginTop: 12, borderTop: "1px solid var(--line)", paddingTop: 12 }}>
      <button className="btn outline" type="button" aria-expanded={open}
        onClick={() => setOpen((value) => !value)}>
        {open ? "Close shared asset detail" : "Open shared asset detail"}
      </button>
      {open && <div style={{ marginTop: 12 }}>
        <AssetDetail assetRef={assetRef} onBack={() => setOpen(false)} />
      </div>}
    </div>
  );
}
