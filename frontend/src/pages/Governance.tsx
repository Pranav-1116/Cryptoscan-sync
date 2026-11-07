import React from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";

export default function Governance() {
  const exc = useLive<{ exceptions: any[] }>("/api/v1/exceptions", { exceptions: [] });
  const own = useLive<{ owners: any[] }>("/api/v1/business/owners", { owners: [] });
  const req = useLive<{ requests: any[] }>("/api/v1/governance/requests", { requests: [] });
  const evt = useLive<{ events: any[] }>("/api/v1/events/recent", { events: [] });

  const exceptions = exc.data.exceptions ?? [];
  const owners = own.data.owners ?? [];
  const requests = req.data.requests ?? [];
  const audit = (evt.data.events ?? []).slice(0, 20);
  const loading = exc.loading || own.loading || req.loading || evt.loading;
  const offline = exc.error || own.error || req.error || evt.error;

  return (
    <>
      <PageHead
        crumb="govern / governance"
        title="Governance"
        sub="Ownership · approvals · exceptions · risk acceptance · change approvals · migration approvals · policy · audit trail"
        right={<Badge tone={exceptions.length ? "amber" : "green"}>{exceptions.length} ACTIVE EXCEPTION{exceptions.length === 1 ? "" : "S"}</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={offline} /></div>
      <div className="grid cols-2">
        <Panel title="Ownership" sub="every crypto asset has an accountable owner">
          <Table
            head={["asset / system", "owner", "role", "status"]}
            rows={owners.map((o) => [
              <span className="mono">{o.asset ?? o.system ?? o.name ?? "—"}</span>,
              o.owner ?? o.display_name ?? "—",
              o.role ?? o.owner_role ?? "—",
              <Badge tone={o.approved || o.status === "active" ? "green" : ""}>{o.status ?? (o.approved ? "approved" : "pending")}</Badge>,
            ])}
          />
          {owners.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No owners recorded yet — assign owners during onboarding/discovery.</p>}
        </Panel>
        <Panel title="Exceptions" sub="risk acceptances are time-boxed and reviewed">
          <Table
            head={["id", "asset", "reason", "expires", "status"]}
            rows={exceptions.map((e) => [
              <span className="mono">{e.id ?? e.exception_id ?? "—"}</span>,
              <span className="mono">{e.asset ?? e.asset_id ?? e.system ?? "—"}</span>,
              <span style={{ fontSize: 12.5 }}>{e.reason ?? e.justification ?? "—"}</span>,
              <span className="mono">{e.expires ?? e.expires_at ?? "—"}</span>,
              <Badge tone="violet">{e.approved_by ?? e.status ?? "open"}</Badge>,
            ])}
          />
          {exceptions.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No active exceptions.</p>}
        </Panel>
      </div>
      <Panel title="Approval requests" sub="change / migration / risk-acceptance approvals" className="mt">
        <Table
          head={["id", "type", "subject", "state", "requested by"]}
          rows={requests.map((r) => [
            <span className="mono">{r.request_pk ?? r.id ?? "—"}</span>,
            <Badge tone="cyan">{r.kind ?? r.request_type ?? r.type ?? "—"}</Badge>,
            <span className="mono">{r.subject ?? r.target ?? r.asset_id ?? "—"}</span>,
            <Badge tone={r.state === "approved" ? "green" : r.state === "denied" ? "red" : "amber"}>{r.state ?? r.status ?? "pending"}</Badge>,
            <span className="mono" style={{ fontSize: 12 }}>{r.requested_by ?? r.actor ?? "—"}</span>,
          ])}
        />
        {requests.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No approval requests.</p>}
      </Panel>
      <Panel title="Audit trail" sub="append-only · hash-chained · live event bus" className="mt">
        <p className="dim" style={{ fontSize: 12.5, margin: "0 0 8px" }} data-testid="governance-audited">
          Every ownership change, approval, exception and risk acceptance on this page is
          recorded in the append-only audit trail — <Link to="/audit">open the full audit ledger</Link>.
        </p>
        <div className="timeline">
          {audit.map((a, i) => (
            <div className="tl" key={a.id ?? i}>
              <span className="mono faint">{a.ts ?? a.timestamp ?? ""}</span>{" "}
              <span className="mono" style={{ fontSize: 12.5 }}>{a.source ?? a.actor ?? "system"}</span>
              <span className="dim" style={{ fontSize: 13 }}> — {a.type ?? a.action} {a.payload?.target ? `(${a.payload.target})` : ""}</span>
            </div>
          ))}
          {audit.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No audit events yet.</p>}
        </div>
      </Panel>
    </>
  );
}
