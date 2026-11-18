/* CryptoLog — Reports (docs/cryptolog/01_PRODUCT_SPEC.md §9):
   auditor and management exports. One archive whose manifest hashes every
   file: an examiner proves the pack is untouched with any sha256sum-style
   check, and a missing artifact is unverifiable, not valid. */
import CryptoLogRetention from "./CryptoLogRetention.js";
import React, { useState } from "react";
import { Panel } from "../components/ui.jsx";
import {
  apiCryptologReportExport,
  type CryptologReportExportResult,
} from "../lib/api.js";

const CONTROL_STYLE: React.CSSProperties = {
  padding: "6px 8px", borderRadius: 6, border: "1px solid var(--line)",
  background: "var(--panel)", color: "var(--ink)", fontSize: 12,
};

export default function CryptoLogReports() {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [state, setState] = useState<"idle" | "working" | "done" | "failed">("idle");
  const [failure, setFailure] = useState<string | null>(null);
  const [result, setResult] = useState<CryptologReportExportResult | null>(null);

  const runExport = () => {
    setState("working");
    setFailure(null);
    setResult(null);
    apiCryptologReportExport({
      start_occurred: start || undefined,
      end_occurred: end || undefined,
    }).then((r) => {
      if (!r.ok || !r.blob) {
        setState("failed");
        setFailure(r.error === "offline"
          ? "Unable to build the auditor pack; the service is offline or unreachable."
          : `Unable to build the auditor pack (HTTP ${r.error?.replace("HTTP ", "") || "unknown"}).`);
        return;
      }
      setResult(r);
      setState("done");
      const url = URL.createObjectURL(r.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `cryptolog-report-${(r.reportId || "export").replace(/[^A-Za-z0-9_-]/g, "")}.zip`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    });
  };

  return (
    <div data-testid="cryptolog-reports" style={{ display: "grid", gap: 16 }}>
      <Panel title="Audit & export" sub="Auditor and management exports — one archive, every file hashed into its manifest">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input aria-label="report start" placeholder="Window start (e.g. 2026-11-01)" value={start}
            onChange={(e) => setStart(e.target.value)} style={CONTROL_STYLE} />
          <input aria-label="report end" placeholder="Window end (e.g. 2026-11-30)" value={end}
            onChange={(e) => setEnd(e.target.value)} style={CONTROL_STYLE} />
          <button className="btn" data-testid="export-pack" onClick={runExport} disabled={state === "working"}>
            {state === "working" ? "Building pack…" : "Export auditor pack"}
          </button>
          <button className="btn" onClick={() => {
            setStart(""); setEnd(""); setState("idle"); setResult(null); setFailure(null);
          }}>Reset</button>
        </div>

        {state === "failed" ? (
          <div className="dim" data-testid="report-failure" style={{ marginTop: 12 }}>
            {failure} A refused export is a named refusal, never an empty archive drawn as a report.
          </div>
        ) : state === "done" && result ? (
          <div data-testid="report-done" style={{ marginTop: 12, fontSize: 12 }}>
            <div>
              Pack <strong>{result.reportId || "report"}</strong> downloaded
              {result.fileCount ? ` — ${result.fileCount} files` : ""}.
            </div>
            <div className="dim" style={{ marginTop: 6 }}>
              <span title={"The archive contains events.json, alerts.json, integrity.json, report.md and manifest.json. The manifest records a SHA-256 for every file: verify it with any sha256sum-style check. A missing artifact is unverifiable, not valid."}>{"The archive contains events.json, alerts.json, integrity.json, report.md and manifest.json."}</span>
            </div>
          </div>
        ) : (
          <div className="dim" data-testid="report-idle" style={{ marginTop: 12, fontSize: 12 }}>
            No export built yet. The pack reports what is proven and what is NOT proven;
            recorded counts are never presented as complete estate coverage.
          </div>
        )}
      </Panel>
    <CryptoLogRetention />
    </div>
  );
}
