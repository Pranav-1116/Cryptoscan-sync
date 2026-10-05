import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

/* Global organization view (spec §34): org → region → business unit →
   environment → assets → crypto. Built from the LIVE onboarding state
   (environments declared during onboarding) — there is no static org chart;
   until an organization is onboarded the view is empty. */

interface Env { id?: string; name: string; env_type?: string; region?: string | null; scan_mode?: string; active_probing?: boolean; enabled?: boolean; }
interface OrgState {
  organization: { name?: string } | null;
  environments?: Env[];
  scope?: { entries?: any[]; total?: number };
}

export default function Organization() {
  const { data, loading, error } = useLive<OrgState>("/api/v1/onboarding/state", { organization: null, environments: [], scope: { entries: [] } });
  const environments = data.environments ?? [];

  // group environments into region → business-unit hierarchy from real data
  const regions = useMemo(() => {
    const map = new Map<string, Map<string, Env[]>>();
    for (const e of environments) {
      const region = e.region || "unassigned";
      // business unit is derived from the env name prefix (e.g. "payments-prod" → "payments")
      const bu = (e.name.split(/[-_./]/)[0] || "default").toLowerCase();
      if (!map.has(region)) map.set(region, new Map());
      const bum = map.get(region)!;
      if (!bum.has(bu)) bum.set(bu, []);
      bum.get(bu)!.push(e);
    }
    return [...map.entries()].map(([name, bum]) => ({
      name,
      bus: [...bum.entries()].map(([bu, envs]) => ({ id: bu, name: bu, envs })),
    }));
  }, [environments]);

  const [regionIdx, setRegionIdx] = useState(0);
  const region = regions[Math.min(regionIdx, Math.max(0, regions.length - 1))];
  const [bu, setBu] = useState<string | null>(null);
  const activeBu = region?.bus.find((b) => b.id === bu) ?? region?.bus[0];

  const totalEnvs = environments.length;
  const passive = environments.filter((e) => e.scan_mode === "passive" || e.active_probing === false).length;

  return (
    <>
      <PageHead
        crumb="command center / organization"
        title="Global organization view"
        sub="Organization → region → business unit → environment → assets → crypto"
        right={<Badge tone={regions.length ? "green" : ""}><span className="dot" /> {regions.length} REGION{regions.length === 1 ? "" : "S"} · {totalEnvs} ENVIRONMENT{totalEnvs === 1 ? "" : "S"}</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={error} /></div>

      {!loading && !data.organization && (
        <Panel title="No organization onboarded" sub="the hierarchy is built from real onboarding data">
          <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>
            Create your organization, environments and authorized scope in <a href="#/onboarding">Onboarding</a>.
            Regions and business units are derived from the environments you declare — nothing is fabricated.
          </p>
        </Panel>
      )}

      {regions.length > 0 && region && (
        <>
          <Panel title="Regions" sub="derived from declared environment regions">
            <div className="row">
              {regions.map((r, i) => (
                <button key={r.name} className="btn sm"
                  style={i === regionIdx ? { borderColor: "var(--cyan)", color: "var(--accent)", background: "color-mix(in srgb, var(--accent) 10%, transparent)" } : {}}
                  onClick={() => { setRegionIdx(i); setBu(null); }}>
                  {r.name}
                </button>
              ))}
            </div>
          </Panel>

          <div className="grid cols-2 mt">
            <Panel title={`${region.name} — business units`} sub="grouped from environment naming">
              <Table
                clickable
                selected={region.bus.findIndex((b) => b.id === activeBu?.id)}
                onSelect={(i) => setBu(region.bus[i].id)}
                head={["business unit", "environments", "scan mode"]}
                rows={region.bus.map((b) => [
                  <span style={{ fontWeight: 600 }}>{b.name}</span>,
                  <span className="num">{b.envs.length}</span>,
                  <Badge tone={b.envs.some((e) => e.scan_mode === "passive") ? "cyan" : "green"}>
                    {b.envs.some((e) => e.scan_mode === "passive") ? "passive" : "standard"}
                  </Badge>,
                ])}
              />
            </Panel>
            <Panel title={`${activeBu?.name ?? ""} — environments`} sub="environment → scan posture">
              <Table
                head={["environment", "type", "mode", "active probing"]}
                rows={(activeBu?.envs ?? []).map((e) => [
                  <span className="mono" style={{ fontWeight: 600 }}>{e.name}</span>,
                  <span className="mono" style={{ fontSize: 12 }}>{e.env_type ?? "production"}</span>,
                  <Badge tone={e.scan_mode === "passive" ? "cyan" : ""}>{e.scan_mode ?? "standard"}</Badge>,
                  <Badge tone={e.active_probing === false ? "amber" : "green"}>{e.active_probing === false ? "disabled (passive-only)" : "permitted"}</Badge>,
                ])}
              />
            </Panel>
          </div>

          <Panel title="Region comparison" sub={`${regions.length} region(s) · ${passive} passive-only environment(s)`} className="mt">
            <Table
              head={["region", "business units", "environments", "passive-only"]}
              rows={regions.map((r) => {
                const envs = r.bus.flatMap((b) => b.envs);
                const pasv = envs.filter((e) => e.scan_mode === "passive" || e.active_probing === false).length;
                return [
                  <span style={{ fontWeight: 600 }}>{r.name}</span>,
                  <span className="num">{r.bus.length}</span>,
                  <span className="num">{envs.length}</span>,
                  <span className="num">{pasv}</span>,
                ];
              })}
            />
          </Panel>
        </>
      )}
    </>
  );
}
