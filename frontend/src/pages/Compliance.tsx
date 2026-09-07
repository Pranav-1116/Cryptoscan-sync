import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

export default function Compliance() {
  const sec = useLive<{ sector: string; profile: any }>("/api/v1/sectors/organization/active", { sector: "", profile: null });
  const drift = useLive<{ total: number; open: number; by_severity: Record<string, number> }>("/api/v1/drift/digest", { total: 0, open: 0, by_severity: {} });

  const profile = sec.data.profile;
  const frameworks: string[] = profile?.compliance_frameworks ?? [];
  const open = drift.data.open ?? 0;
  const loading = sec.loading || drift.loading;
  const offline = sec.error || drift.error;

  return (
    <>
      <PageHead
        crumb="govern / compliance"
        title="Compliance"
        sub="Framework → requirement → control → evidence → status · versioned, configurable mappings"
        right={<Badge tone={open ? "amber" : "green"}>{open} OPEN DRIFT</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={offline} /></div>
      <Panel title="Applicable frameworks" sub={profile ? `derived from active sector: ${sec.data.sector}` : "no active sector — set one in Organization/Onboarding"}>
        <Table
          head={["framework", "applies to", "policy pack", "status"]}
          rows={frameworks.map((fw, i) => [
            <span className="mono" style={{ fontWeight: 600 }}>{fw}</span>,
            (profile?.critical_asset_classes ?? []).join(", ") || "all in-scope assets",
            <span className="mono" style={{ fontSize: 12 }}>{(profile?.policy_packs ?? [])[i] ?? "standard"}</span>,
            <Badge tone={open ? "amber" : "green"}>{open ? "controls under review" : "mapped"}</Badge>,
          ])}
        />
        {frameworks.length === 0 && (
          <p className="dim" style={{ fontSize: 13 }}>
            No sector selected yet. Compliance mappings are derived deterministically from the active
            organization sector and the live evidence store — nothing is shown until an organization is onboarded.
          </p>
        )}
      </Panel>
      <Panel title="Evidence status" sub="controls are satisfied only by hash-chained evidence" className="mt">
        <Table
          head={["source", "open items", "critical", "high", "medium"]}
          rows={[[
            <span className="mono">drift / finding digest</span>,
            <span className="num">{drift.data.total ?? 0}</span>,
            <span className="num">{drift.data.by_severity?.CRITICAL ?? 0}</span>,
            <span className="num">{drift.data.by_severity?.HIGH ?? 0}</span>,
            <span className="num">{drift.data.by_severity?.MEDIUM ?? 0}</span>,
          ]]}
        />
        <p className="dim" style={{ fontSize: 12.5, marginTop: 8 }}>
          Run a compliance report (Resilience → Compliance report) to generate the signed, framework-mapped control assessment.
        </p>
      </Panel>
    </>
  );
}
