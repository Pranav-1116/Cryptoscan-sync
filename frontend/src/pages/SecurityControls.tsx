/* Security controls console (review item 17) — the estate model, on a page.

   What this page is for
   ---------------------
   The integration layer answers four questions and this page is where a bank operator asks
   them: which of our controls did we read, what did each one say, what did it refuse to say,
   and which relationships carry evidence. "No findings" is not one of the answers — it is
   four different facts (never asked, refused, unreachable, read with nothing to report) and
   this page renders each of them by name.

   What it will not do
   -------------------
   It does not offer a write, a probe, a "fix" button or a fabricated green state. A control
   that refused appears under "refused to tell us" with the reason the device gave. A control
   with no integration says so instead of looking healthy, and the observation class
   (CONFIGURED / OBSERVED / RUNTIME_OBSERVED) is shown next to every state, because the
   difference between a config file and a running device is the whole point. */
import React, { useEffect, useState } from "react";
import {
  apiSecurityControlsFindings, apiSecurityControlsHealth, apiSecurityControlsVerify,
  apiSecurityControlExportUrl, tenantFetch,
} from "../lib/api.js";
import { useI18n } from "../i18n/I18n.jsx";

type AnyRecord = Record<string, any>;

function Err({ e }: { e: string | undefined }) {
  if (!e) return null;
  return <div role="alert" style={{ color: "var(--red)", fontSize: 12, marginTop: 8 }}>{e}</div>;
}

function stateColor(state: string): string {
  if (["OK", "ENFORCED", "PRESENT", "WITHIN_LIMIT"].includes(state)) return "var(--green)";
  if (["REFUSED", "FAILED", "UNREADABLE", "AUTH_FAILED", "UNREACHABLE"].includes(state)) return "var(--red)";
  return "var(--amber)";
}

function Chip({ state, label }: { state: string; label?: string }) {
  return (
    <span className="badge" style={{
      background: "color-mix(in srgb, " + stateColor(state) + " 12%, transparent)",
      color: stateColor(state),
    }}>{label ?? state}</span>
  );
}

export default function SecurityControls() {
  const { t } = useI18n();
  const [health, setHealth] = useState<AnyRecord | null>(null);
  const [findings, setFindings] = useState<AnyRecord | null>(null);
  const [verify, setVerify] = useState<AnyRecord | null>(null);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("controls");

  const load = async () => {
    setBusy(true); setErr(undefined);
    const [h, f, v] = await Promise.all([
      apiSecurityControlsHealth(), apiSecurityControlsFindings(), apiSecurityControlsVerify(),
    ]);
    setBusy(false);
    if (!h.ok) { setErr(h.error); return; }
    setHealth(h.data);
    if (f.ok) setFindings(f.data);
    if (v.ok) setVerify(v.data);
  };

  useEffect(() => { void load(); }, []);

  const download = async (format: "cyclonedx" | "cef") => {
    setErr(undefined);
    const r = await tenantFetch(apiSecurityControlExportUrl(format), {
      credentials: "include",
    });
    if (!r.ok) { setErr(`HTTP ${r.status}`); return; }
    const body = await r.text();
    const url = URL.createObjectURL(new Blob([body], {
      type: format === "cyclonedx" ? "application/json" : "text/plain",
    }));
    const a = document.createElement("a");
    a.href = url;
    a.download = format === "cyclonedx" ? "security-controls.cdx.json" : "security-controls.cef";
    a.click();
    URL.revokeObjectURL(url);
  };

  const controls: AnyRecord[] = health?.controls ?? [];
  const coverage = health?.coverage ?? {};
  const taxonomy: AnyRecord = health?.taxonomy ?? {};
  const refused = controls.filter((row) => row.state === "REFUSED");
  const unintegrated = controls.filter((row) =>
    ["NOT_CONFIGURED", "UNSUPPORTED_DIALECT"].includes(row.state));
  const snapshots = health?.snapshot;

  const TABS = ["controls", "findings", "refused", "chain", "export"];

  return (
    <div className="page" style={{ padding: 24 }}>
      <h1 style={{ fontSize: 22, margin: 0 }}>{t("securityControls.title")}</h1>
      <p style={{ color: "var(--faint)", fontSize: 13, marginTop: 6 }}>
        {t("securityControls.positioning")}
      </p>

      <div style={{ display: "flex", gap: 8, margin: "16px 0", flexWrap: "wrap" }}>
        {TABS.map((name) => (
          <button key={name} className={`btn sm ${tab === name ? "primary" : ""}`}
            onClick={() => setTab(name)}>{t(`securityControls.tab.${name}`)}</button>
        ))}
        <button className="btn sm" onClick={load} disabled={busy}>
          {busy ? t("common.loading") : t("securityControls.refresh")}
        </button>
      </div>

      {!snapshots && !busy && (
        <div className="card" style={{ padding: 16, marginBottom: 14 }}>
          <b>{t("securityControls.neverRead")}</b>
          <p style={{ fontSize: 12, color: "var(--faint)", marginBottom: 0 }}>
            {t("securityControls.neverReadHelp")}
          </p>
        </div>
      )}

      {snapshots && (
        <div className="card" style={{ padding: 14, marginBottom: 14, fontSize: 12 }}>
          <Chip state={String(snapshots.read_state || "UNKNOWN")}
            label={`${t("securityControls.readState")}: ${snapshots.read_state}`} />
          <span style={{ marginLeft: 10 }}>
            {t("securityControls.sequence")} {snapshots.sequence} · {snapshots.captured_at}
          </span>
          {coverage?.statement && (
            <div style={{ marginTop: 6, color: "var(--faint)" }}>{coverage.statement}</div>
          )}
        </div>
      )}

      <Err e={err} />

      {tab === "controls" && (
        <table className="table" style={{ width: "100%", fontSize: 12 }}>
          <thead>
            <tr>
              <th>{t("securityControls.colControl")}</th>
              <th>{t("securityControls.colState")}</th>
              <th>{t("securityControls.colMeaning")}</th>
              <th>{t("securityControls.colAction")}</th>
            </tr>
          </thead>
          <tbody>
            {controls.map((row) => (
              <tr key={row.control}>
                <td style={{ fontFamily: "var(--mono)" }}>{row.control}</td>
                <td><Chip state={String(row.state)} /></td>
                <td>{taxonomy[row.state]?.meaning ?? row.detail}</td>
                <td style={{ color: "var(--faint)" }}>{taxonomy[row.state]?.action ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === "findings" && (
        <div>
          <p style={{ fontSize: 12, color: "var(--faint)" }}>
            {t("securityControls.findingsHelp")}
          </p>
          <table className="table" style={{ width: "100%", fontSize: 12 }}>
            <thead>
              <tr>
                <th>{t("securityControls.colControl")}</th>
                <th>{t("securityControls.colVendor")}</th>
                <th>{t("securityControls.colState")}</th>
                <th>{t("securityControls.colSubject")}</th>
                <th>{t("securityControls.colEvidence")}</th>
                <th>{t("securityControls.colReason")}</th>
              </tr>
            </thead>
            <tbody>
              {(findings?.findings ?? []).map((row: AnyRecord) => (
                <tr key={row.finding_id}>
                  <td style={{ fontFamily: "var(--mono)" }}>{row.control}</td>
                  <td>{row.vendor ?? "—"}</td>
                  <td><Chip state={String(row.state)} /></td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{row.subject ?? "—"}</td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                    {(row.evidence_ids ?? []).join(", ") || t("securityControls.noEvidence")}
                  </td>
                  <td style={{ color: "var(--faint)" }}>{row.reason ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {Object.keys(findings?.summary ?? {}).length === 0 && (
            <p style={{ fontSize: 12, color: "var(--faint)" }}>{t("securityControls.noFindings")}</p>
          )}
        </div>
      )}

      {tab === "refused" && (
        <div>
          <p style={{ fontSize: 12, color: "var(--faint)" }}>{t("securityControls.refusedHelp")}</p>
          {refused.length === 0 && unintegrated.length === 0 && (
            <p style={{ fontSize: 12 }}>{t("securityControls.nothingRefused")}</p>
          )}
          {refused.map((row) => (
            <div key={row.control} className="card" style={{ padding: 12, marginBottom: 8 }}>
              <Chip state="REFUSED" />
              <b style={{ marginLeft: 8, fontFamily: "var(--mono)" }}>{row.control}</b>
              <div style={{ fontSize: 12, marginTop: 4 }}>{row.detail}</div>
            </div>
          ))}
          {unintegrated.length > 0 && (
            <div className="card" style={{ padding: 12 }}>
              <b>{t("securityControls.notIntegrated")}</b>
              <ul style={{ fontSize: 12, marginTop: 6 }}>
                {unintegrated.map((row) => (
                  <li key={row.control}>
                    <span style={{ fontFamily: "var(--mono)" }}>{row.control}</span> — {row.state}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {tab === "chain" && (
        <div className="card" style={{ padding: 14, fontSize: 12 }}>
          <Chip state={verify?.verified ? "OK" : "FAILED"}
            label={verify?.verified ? t("securityControls.chainVerified") : t("securityControls.chainBroken")} />
          <div style={{ marginTop: 8 }}>
            {t("securityControls.snapshots")}: {verify?.snapshots ?? 0}
          </div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 10, marginTop: 4 }}>
            {t("securityControls.chainHead")}: {verify?.head || "—"}
          </div>
          {(verify?.problems ?? []).map((problem: AnyRecord, index: number) => (
            <div key={index} role="alert" style={{ color: "var(--red)", marginTop: 6 }}>
              {problem.code} @ {problem.at}
            </div>
          ))}
          {(verify?.problems ?? []).length === 0 && (
            <p style={{ color: "var(--faint)", marginBottom: 0 }}>
              {t("securityControls.chainNoProblems")}
            </p>
          )}
        </div>
      )}

      {tab === "export" && (
        <div className="card" style={{ padding: 14, fontSize: 12 }}>
          <p style={{ color: "var(--faint)" }}>{t("securityControls.exportHelp")}</p>
          <button className="btn sm" onClick={() => download("cyclonedx")}>
            {t("securityControls.exportCycloneDx")}
          </button>
          <button className="btn sm" style={{ marginLeft: 8 }} onClick={() => download("cef")}>
            {t("securityControls.exportCef")}
          </button>
          <p style={{ color: "var(--faint)", marginTop: 10, marginBottom: 0 }}>
            {t("securityControls.exportCaveat")}
          </p>
        </div>
      )}
    </div>
  );
}
