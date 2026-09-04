import React from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { reports } from "../data/initial.js";

export default function Reports() {
  return (
    <>
      <PageHead
        crumb="operate / reports"
        title="Reports"
        sub="Executive · technical · compliance · PQC — generated deterministically from the evidence store"
        right={<Badge tone="green"><span className="dot" /> 4 READY</Badge>}
      />
      <div className="grid cols-2">
        {reports.map((r) => (
          <Panel key={r.kind} title={r.title} sub={`${r.kind} REPORT · generated ${r.generated}`}>
            <p className="dim" style={{ fontSize: 13, marginTop: 0 }}>{r.desc}</p>
            <div className="row">
              <button className="btn sm primary">Generate</button>
              <button className="btn sm">Download PDF</button>
              <Badge tone="green">{r.status}</Badge>
            </div>
          </Panel>
        ))}
      </div>
    </>
  );
}
