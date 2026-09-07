import React from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

/* Unified live environment visualization (spec §5) — the five discovery
   domains feeding cryptography → applications → CBOM. All counts come from
   the live platform (/assets + /stats/summary); they are 0 until discovery. */

export default function LiveEnvironment() {
  const assetsLive = useLive<{ assets?: any[] }>("/api/v1/assets", { assets: [] });
  const stats = useLive<Record<string, any>>("/api/v1/stats/summary", {});
  const assetList = assetsLive.data.assets ?? [];
  const cov = (stats.data.coverage ?? {}) as Record<string, any>;

  const counts = {
    network: assetList.filter((a) => (a.kind ?? a.type ?? a.asset_type) === "network").length,
    cloud: assetList.filter((a) => (a.kind ?? a.type ?? a.asset_type) === "cloud").length,
    vendor: assetList.filter((a) => (a.kind ?? a.type ?? a.asset_type) === "vendor").length,
    hardware: assetList.filter((a) => (a.kind ?? a.type ?? a.asset_type) === "hardware").length,
    crypto: cov.with_cbom ?? 0,
    apps: assetList.filter((a) => (a.kind ?? a.type ?? a.asset_type) === "application").length,
    cbom: cov.with_cbom ?? 0,
    hbom: cov.with_hbom ?? 0,
  };
  const reconciled = cov.systems ?? assetList.length;
  const hasData = reconciled > 0 || counts.network + counts.cloud + counts.vendor + counts.hardware + counts.crypto > 0;

  return (
    <>
      <PageHead
        crumb="command center / live environment"
        title="Live environment"
        sub="One graph across network, cloud, vendor, hardware, cryptography and applications"
        right={<Badge tone={reconciled ? "green" : ""}><span className="dot" /> {Number(reconciled).toLocaleString()} SYSTEMS</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={assetsLive.loading || stats.loading} error={assetsLive.error || stats.error} /></div>

      <Panel title="Unified map" sub="every domain feeds the cryptography layer — populated by discovery (global → region → org → environment → asset → crypto dependency)">
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, padding: "18px 0 8px", overflowX: "auto" }}>
          <div className="row" style={{ justifyContent: "center", gap: 18 }}>
            <EnvNode name="Network" icon="◈" count={`${counts.network} assets`} active={counts.network > 0} />
            <EnvNode name="Cloud" icon="☁" count={`${counts.cloud} resources`} active={counts.cloud > 0} />
            <EnvNode name="Vendor" icon="▤" count={`${counts.vendor} vendors`} active={counts.vendor > 0} />
          </div>
          <svg width="420" height="26"><path d="M210 0 v14 H80 v-14" stroke="rgba(56,189,248,.5)" fill="none" /><path d="M210 0 v14 H210 v-14" stroke="rgba(56,189,248,.5)" fill="none" /><path d="M210 0 v14 H340 v-14" stroke="rgba(56,189,248,.5)" fill="none" /></svg>
          <div className="row" style={{ justifyContent: "center", gap: 18 }}>
            <EnvNode name="Hardware" icon="⌬" count={`${counts.hardware} devices`} active={counts.hardware > 0} />
            <EnvNode name="Cryptography" icon="⚿" count={`${counts.crypto} assets`} highlight={counts.crypto > 0} active={counts.crypto > 0} />
          </div>
          <svg width="300" height="26"><path d="M150 0 v14 H150 v-14" stroke="rgba(56,189,248,.5)" fill="none" /></svg>
          <div className="row" style={{ justifyContent: "center", gap: 18 }}>
            <EnvNode name="Applications" icon="▣" count={`${counts.apps} apps`} active={counts.apps > 0} />
            <EnvNode name="CBOM" icon="⬡" count={counts.cbom ? `v${counts.cbom}` : "v0"} active={counts.cbom > 0} />
            <EnvNode name="HBOM" icon="⬢" count={counts.hbom ? `v${counts.hbom}` : "v0"} active={counts.hbom > 0} />
          </div>
        </div>
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Zoom levels" sub="drill from planet to crypto dependency">
          <ol style={{ fontFamily: "var(--mono)", fontSize: 13, color: "var(--dim)", margin: 0, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 6 }}>
            <li>Global</li>
            <li>Region</li>
            <li>Organization</li>
            <li>Environment</li>
            <li>Asset</li>
            <li>Crypto dependency</li>
          </ol>
          {!hasData && (
            <div className="dim" style={{ fontSize: 12.5, marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
              Hierarchy populates from onboarding scope and discovery. Configure your estate in <a href="#/onboarding">Onboarding</a>, then run discovery.
            </div>
          )}
        </Panel>
        <Panel title="Dependency topology" sub="interactive graph — click any asset for full detail">
          {reconciled > 0 ? (
            <div className="graphwrap">
              <a className="mono" href="#/graph" style={{ fontSize: 12 }}>open full dependency graph →</a>
            </div>
          ) : (
            <div style={{ padding: "26px 10px", textAlign: "center" }}>
              <div className="frame" style={{ minHeight: 150, display: "grid", placeItems: "center", border: "1px dashed var(--line-strong)", borderRadius: 12, color: "var(--faint)", fontSize: 13, padding: 24 }}>
                No dependency graph yet — run discovery and a scan to build the crypto dependency topology.
              </div>
              <a className="mono" href="#/graph" style={{ fontSize: 12, marginTop: 12, display: "inline-block" }}>open dependency graph →</a>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

function EnvNode({ name, icon, count, highlight, active }: { name: string; icon: string; count: string; highlight?: boolean; active?: boolean }) {
  return (
    <div className="frame" style={{
      border: "1px solid var(--line-strong)", borderRadius: 12, padding: "14px 26px",
      background: highlight ? "rgba(124,156,255,0.10)" : "rgba(8,12,24,0.6)",
      opacity: active ? 1 : 0.55, textAlign: "center", minWidth: 150,
    }}>
      <div style={{ fontSize: 22 }}>{icon}</div>
      <div style={{ fontWeight: 700, fontSize: 15, marginTop: 4 }}>{name}</div>
      <div className="mono faint" style={{ fontSize: 11 }}>{count}</div>
    </div>
  );
}
