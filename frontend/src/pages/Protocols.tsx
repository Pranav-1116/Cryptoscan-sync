import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, Tabs, PageHead } from "../components/ui.jsx";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiProtocolCatalog, ProtocolEntry } from "../lib/api.js";

/* Network protocols & services — real catalog from the canonical network
   registry (GET /api/v1/network/protocols). Every service the scanner can
   name: port, transport, category, encryption, exposure and risk verdict.
   Zero demo data — empty until the backend answers. */

const STATUS_TONE: Record<string, string> = {
  DISALLOWED: "red",
  DEPRECATED: "amber",
  RESTRICTED: "amber",
  ALLOWED: "green",
  REQUIRED: "green",
  UNKNOWN: "",
};

export default function Protocols() {
  const res = useApi(() => apiProtocolCatalog(), []);
  const live = res.source === "live";
  const body = res.data;
  const protocols: ProtocolEntry[] = useMemo(() => body?.protocols ?? [], [body]);

  const [cat, setCat] = useState("all");
  const [q, setQ] = useState("");
  const [encOnly, setEncOnly] = useState(false);

  const counts = body?.status_counts ?? {};
  const tabs = ["all", "web", "remote-access", "database", "ot-ics", "vpn", "mail", "file-sharing"];
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return protocols
      .filter((p) => (cat === "all" ? true : p.category === cat))
      .filter((p) => (encOnly ? p.encrypted : true))
      .filter((p) =>
        !needle
          ? true
          : `${p.protocol} ${p.category} ${p.notes ?? ""} ${p.port ?? ""}`.toLowerCase().includes(needle),
      )
      .sort((a, b) => String(a.protocol).localeCompare(String(b.protocol)));
  }, [protocols, cat, q, encOnly]);

  return (
    <>
      <PageHead
        crumb="inventory / network protocols"
        title="Network protocols & services"
        sub="Every named network service — port, transport, category, encryption, exposure and risk verdict (canonical registry)"
        right={
          <>
            <LiveBadge source={res.source} />
            <Badge tone={live && protocols.length ? "cyan" : ""}><span className="dot" /> {protocols.length.toLocaleString()} SERVICES</Badge>
          </>
        }
      />

      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        {(["DISALLOWED", "DEPRECATED", "RESTRICTED", "ALLOWED"] as const).map((s) => (
          <Badge key={s} tone={STATUS_TONE[s]}>{s}: {counts[s] ?? 0}</Badge>
        ))}
        <label style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <input type="checkbox" checked={encOnly} onChange={(e) => setEncOnly(e.target.checked)} />
          encrypted only
        </label>
        <input
          placeholder="search service / port…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ padding: "6px 10px", minWidth: 200 }}
        />
      </div>

      <Tabs tabs={tabs} active={Math.max(0, tabs.indexOf(cat))} onChange={(i) => setCat(tabs[i])} />

      <Panel title={`${cat === "all" ? "All services" : cat} — ${filtered.length}`} sub="cleartext/broken services drive the highest risk; OT/ICS are passive-only">
        <Table
          head={["service", "port", "transport", "category", "encrypted", "exposure", "status", "notes"]}
          rows={filtered.map((p) => [
            <span className="mono">{p.protocol}</span>,
            <span className="num">{p.port ?? "—"}</span>,
            (p.transport ?? "—").toUpperCase(),
            <Badge tone="violet">{p.category}</Badge>,
            p.encrypted ? <Badge tone="green">TLS</Badge> : <Badge tone="red">cleartext</Badge>,
            <span className="mono">{p.exposure ?? "—"}</span>,
            <Badge tone={STATUS_TONE[p.status] ?? ""}>{p.status}</Badge>,
            <span className="dim" style={{ fontSize: 12 }}>{p.risk_reason || p.notes || ""}</span>,
          ])}
        />
        {!filtered.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live
              ? "No services match the current filter."
              : "Backend offline — protocol catalog unavailable. Run the platform and retry."}
          </div>
        )}
      </Panel>
    </>
  );
}
