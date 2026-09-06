import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, Tabs, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiCloudAccounts, CloudAccount } from "../lib/api.js";

/* Cloud — connected read-only cloud accounts (AWS/Azure/GCP) from
   GET /api/v1/cloud/accounts. Scans are read-only; vault references hold
   credentials. Empty until an account is registered via onboarding. */

const PROVIDERS = ["All", "AWS", "AZURE", "GCP"];

export default function Cloud() {
  const res = useApi(() => apiCloudAccounts(), []);
  const live = res.source === "live";
  const accounts: CloudAccount[] = useMemo(() => res.data?.accounts ?? [], [res.data]);
  const [tab, setTab] = useState(0);

  const providerOf = (a: CloudAccount) =>
    String(a.cloud_provider || a.provider || "").toUpperCase();
  const rows = accounts.filter((a) => tab === 0 || providerOf(a) === PROVIDERS[tab]);
  const providerCount = new Set(accounts.map(providerOf)).size;

  return (
    <>
      <PageHead
        crumb="discovery / cloud"
        title="Cloud"
        sub="Read-only AWS · Azure · GCP accounts — regions, role references, and scan status (credentials stay vaulted)"
        right={
          <>
            <LiveBadge source={res.source} />
            <Badge tone={live && accounts.length ? "green" : ""}><span className="dot" /> {accounts.length.toLocaleString()} ACCOUNTS · {providerCount} PROVIDERS</Badge>
          </>
        }
      />
      <Tabs tabs={PROVIDERS.map((p) => (p === "All" ? "All" : p[0] + p.slice(1).toLowerCase()))} active={tab} onChange={setTab} />
      <Panel title="Connected cloud accounts" sub="read-only scanning; no secrets stored in scan records">
        <Table
          head={["provider", "account identifier", "role / access reference", "regions", "status"]}
          rows={rows.map((c) => [
            <Badge tone="violet">{providerOf(c) || "—"}</Badge>,
            <span className="mono">{c.account_identifier ?? c.account_id ?? "—"}</span>,
            <span className="mono dim" style={{ fontSize: 12 }}>{c.role_arn ? "vault-ref / role configured" : "—"}</span>,
            <span className="dim">{Array.isArray(c.regions) ? c.regions.join(", ") : (c.regions || "—")}</span>,
            c.enabled === false ? <Badge tone="amber">disabled</Badge> : <Badge tone="green">{c.status || "connected"}</Badge>,
          ])}
        />
        {!rows.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live
              ? "No cloud accounts connected yet — register one in Onboarding (read-only; credentials are vault references)."
              : "Backend offline — cloud accounts unavailable."}
            <br /><a href="#/onboarding" className="mono" style={{ fontSize: 12 }}>go to onboarding →</a>
          </div>
        )}
      </Panel>
    </>
  );
}
