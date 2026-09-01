import React from "react";
import { Badge, PageHead, Panel, Table } from "../components/ui.jsx";
import { migrationBoard, migrationDetail, globalState } from "../data/demo.js";

export default function Migration() {
  return (
    <>
      <PageHead
        crumb="plan / migration planning"
        title="Migration planning"
        sub="Roadmap · priorities · dependencies · teams · applications · vendors · hardware · cloud · milestones"
        right={<Badge tone="cyan">PROGRESS {globalState.migrationProgressPct}%</Badge>}
      />
      <div className="kanban">
        {migrationBoard.map((col) => (
          <div className="col" key={col.col}>
            <h4>{col.col} · {col.cards.length}</h4>
            {col.cards.map((card) => (
              <div className="card" key={card.id}>
                <div style={{ fontWeight: 600, fontSize: 12.5 }}>{card.title}</div>
                <div className="meta">
                  <span>{card.apps} apps</span>
                  <Badge tone={card.risk === "HIGH" ? "red" : card.risk === "MEDIUM" ? "amber" : "green"}>{card.risk}</Badge>
                </div>
                <div className="meta"><span>owner: {card.owner}</span></div>
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="grid cols-2 mt">
        <Panel title="Teams" sub="who owns what — status per team">
          <Table
            head={["team", "applications", "owner", "status"]}
            rows={migrationDetail.teams.map((t) => [
              <span className="mono" style={{ fontWeight: 600 }}>{t.name}</span>,
              <span className="num">{t.apps}</span>,
              t.owner,
              <Badge tone={t.status === "MIGRATING" ? "amber" : t.status === "COMPLETED" ? "green" : "violet"}>{t.status}</Badge>,
            ])}
          />
        </Panel>
        <Panel title="Vendors" sub="PQC commitments in the migration window">
          <Table
            head={["vendor", "commitment", "status"]}
            rows={migrationDetail.vendors.map((v) => [
              <span style={{ fontWeight: 600 }}>{v.name}</span>,
              <span style={{ fontSize: 12.5 }} className="dim">{v.commitment}</span>,
              <Badge tone={v.status === "ON TRACK" ? "green" : "red"}>{v.status}</Badge>,
            ])}
          />
        </Panel>
        <Panel title="Hardware" sub="HSM / accelerator readiness">
          <Table
            head={["device", "action", "status"]}
            rows={migrationDetail.hardware.map((h) => [
              <span className="mono">{h.device}</span>,
              <span style={{ fontSize: 12.5 }} className="dim">{h.action}</span>,
              <Badge tone={h.status === "READY" ? "green" : "red"}>{h.status}</Badge>,
            ])}
          />
        </Panel>
        <Panel title="Cloud" sub="KMS readiness per provider">
          <Table
            head={["service", "action", "status"]}
            rows={migrationDetail.cloud.map((c) => [
              <span className="mono">{c.service}</span>,
              <span style={{ fontSize: 12.5 }} className="dim">{c.action}</span>,
              <Badge tone="green">{c.status}</Badge>,
            ])}
          />
        </Panel>
      </div>

      <Panel title="Roadmap milestones" sub="deterministic program plan" className="mt">
        <div className="timeline">
          {[
            { t: "Q3", e: "Complete inventory + dependency mapping (CBOM v1843 frozen)", hi: false },
            { t: "Q4", e: "Re-key 17 high-value certificates to ML-DSA-65 hybrid", hi: true },
            { t: "Q1", e: "Migrate 184 applications off RSA-2048 (what-if plan executed)", hi: false },
            { t: "Q2", e: "Retire 3DES and MD5 — remove legacy trust anchors", hi: false },
            { t: "Q3", e: "Full PQC readiness: 100% of TLS/SSH/IPsec on ML-KEM/ML-DSA", hi: true },
          ].map((x) => (
            <div className={`tl ${x.hi ? "hi" : ""}`} key={x.t}>
              <span className="mono faint">{x.t}</span> <span className="dim" style={{ fontSize: 13 }}>{x.e}</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
