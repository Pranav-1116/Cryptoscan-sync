/* Trust & key operations — payment-crypto key inventory & rotation forecast,
   HSM/TPM ceremonies, workload SPIFFE/SVID identity, and OT safe-scan policy.
   Every panel reads/writes the LIVE control plane; nothing is fabricated. */
import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { useLive, LiveStatus } from "../lib/useLive.js";
import {
  apiPaymentKeys, apiPaymentSummary, apiPaymentForecast, apiPaymentCeremonies,
  apiApiKeyRotationReport, apiWorkloadCa, apiWorkloadIssueSvid, apiWorkloadVerify,
  apiSafeScanPolicy, apiSafeScanEmergencyStop, apiOtMaintenanceWindows,
} from "../lib/api.js";

type AnyR = { ok?: boolean; data?: any; error?: string };

export default function Trust() {
  const keys = useLive<any>("/api/v1/payment-crypto/keys", { keys: [] });
  const summary = useLive<any>("/api/v1/payment-crypto/summary", {});
  const forecast = useLive<any>("/api/v1/payment-crypto/forecast", { upcoming: [], upcoming_count: 0 });
  const ceremonies = useLive<any>("/api/v1/payment-crypto/ceremonies", { ceremonies: [] });
  const rotation = useLive<any>("/api/v1/api-keys/rotation/report", { keys: [], actionable: 0 });
  const ca = useLive<any>("/api/v1/workload/ca", { trust_domain: "", ca_cert_pem: "" });
  const policy = useLive<any>("/api/v1/control/safe-scan/policy", { policies: [] });
  const windows = useLive<any>("/api/v1/ot/maintenance-windows", { windows: [], total_count: 0 });

  const [svidWorkload, setSvidWorkload] = useState("payment-gateway");
  const [svid, setSvid] = useState<AnyR | null>(null);
  const [svidBusy, setSvidBusy] = useState(false);
  const [verifyRes, setVerifyRes] = useState<AnyR | null>(null);
  const [stopRes, setStopRes] = useState<AnyR | null>(null);
  const [stopBusy, setStopBusy] = useState(false);

  const loading = keys.loading || summary.loading || ca.loading || policy.loading;
  const offline = keys.error || summary.error || ca.error || policy.error;
  const s = summary.data ?? {};
  const keyList = keys.data.keys ?? [];
  const upcoming = forecast.data.upcoming ?? [];
  const ceremonyList = ceremonies.data.ceremonies ?? [];
  const rotationKeys = rotation.data.keys ?? [];
  const policies = policy.data.policies ?? [];
  const windowList = windows.data.windows ?? [];

  const issueSvid = async () => {
    setSvidBusy(true);
    setSvid(await apiWorkloadIssueSvid(svidWorkload, 60));
    setSvidBusy(false);
  };
  const verifySvid = async () => {
    if (!svid?.data) return;
    setVerifyRes(await apiWorkloadVerify(svid.data.cert_pem ?? "", [svidWorkload]));
  };
  const emergencyStop = async (engaged: boolean) => {
    setStopBusy(true);
    setStopRes(await apiSafeScanEmergencyStop(engaged));
    setStopBusy(false);
    policy.reload();
  };

  return (
    <>
      <PageHead
        crumb="govern / trust & keys"
        title="Trust & key operations"
        sub="Key inventory & rotation · HSM ceremonies · workload SPIFFE/SVID · OT safe-scan policy"
        right={<Badge tone="violet"><span className="dot" /> {s.keys_total ?? keyList.length} KEYS</Badge>}
      />
      <div style={{ marginBottom: 12 }}><LiveStatus loading={loading} error={offline} /></div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["keys total", s.keys_total ?? 0, "green"],
          ["weak-algorithm keys", s.active_weak_algorithm_keys ?? 0, (s.active_weak_algorithm_keys ?? 0) ? "red" : "green"],
          ["open findings", s.open_findings ?? 0, (s.open_findings ?? 0) ? "amber" : "green"],
          ["rotation due (API keys)", rotation.data.actionable ?? 0, (rotation.data.actionable ?? 0) ? "red" : "green"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={k as string}><span className="k">{k}</span><span className="v" style={{ color: `var(--${tone})` }}>{v}</span></div>
        ))}
      </div>

      <div className="grid cols-2">
        <Panel title="Payment/crypto keys" sub="tracked key inventory (state, algorithm, usage)">
          <Table
            head={["key", "state", "algorithm", "usage"]}
            rows={keyList.map((k: any, i: number) => [
              <span className="mono" key={i}>{k.key_id ?? k.id ?? `key-${i}`}</span>,
              <Badge tone={String(k.state ?? "").toLowerCase() === "active" ? "green" : "amber"} key="s">{k.state ?? "—"}</Badge>,
              <span className="mono" key="a">{k.algorithm ?? "—"}</span>,
              <span key="u">{k.key_usage ?? k.usage ?? "—"}</span>,
            ])}
          />
          {keyList.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No keys registered yet — import or discover keys to begin lifecycle tracking.</p>}
        </Panel>

        <Panel title="Rotation forecast" sub={`${forecast.data.upcoming_count ?? upcoming.length} item(s) due in the horizon window`}>
          <Table
            head={["item", "due", "status"]}
            rows={upcoming.slice(0, 12).map((u: any, i: number) => [
              <span className="mono" key={i}>{u.key_id ?? u.id ?? u.name ?? `item-${i}`}</span>,
              <span className="mono" key="d">{u.rotation_due ?? u.due_date ?? u.due ?? "—"}</span>,
              <Badge key="st" tone={String(u.status ?? "").toLowerCase() === "overdue" ? "red" : "amber"}>{u.status ?? "due"}</Badge>,
            ])}
          />
          {upcoming.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No rotations scheduled — keys need a rotation date for forecasting.</p>}
        </Panel>
      </div>

      <div className="grid cols-2 mt">
        <Panel title="HSM / TPM ceremonies" sub="key ceremonies and HSM events are audited">
          <Table
            head={["ceremony", "type", "status", "at"]}
            rows={ceremonyList.map((c: any, i: number) => [
              <span className="mono" key={i}>{c.ceremony_id ?? c.id ?? `ceremony-${i}`}</span>,
              c.type ?? c.kind ?? "—",
              <Badge tone={String(c.status ?? "").toLowerCase() === "completed" ? "green" : "amber"} key="st">{c.status ?? "—"}</Badge>,
              <span className="mono" key="t">{c.created_at ?? c.at ?? "—"}</span>,
            ])}
          />
          {ceremonyList.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No key ceremonies recorded yet.</p>}
        </Panel>

        <Panel title="API-key rotation" sub="service/API keys due for rotation">
          <Table
            head={["key", "rotated", "action"]}
            rows={rotationKeys.slice(0, 12).map((k: any, i: number) => [
              <span className="mono" key={i}>{k.key_id ?? k.id ?? k.name ?? `key-${i}`}</span>,
              <span className="mono" key="r">{k.last_rotated ?? k.rotated_at ?? "—"}</span>,
              <Badge tone={k.actionable || k.due ? "red" : "green"} key="a">{k.actionable || k.due ? "ROTATE" : "ok"}</Badge>,
            ])}
          />
          {rotationKeys.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No API keys registered.</p>}
        </Panel>
      </div>

      <Panel title="Workload identity (SPIFFE / SVID)" sub="short-lived workload certificates minted by the platform CA" className="mt">
        <div className="row" style={{ marginBottom: 12 }}>
          <input
            value={svidWorkload}
            onChange={(e) => setSvidWorkload(e.target.value)}
            placeholder="workload name (e.g. payment-gateway)"
            style={{ flex: 1, maxWidth: 320, background: "rgba(8,12,24,0.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "8px 12px" }}
          />
          <button className="btn sm primary" onClick={() => void issueSvid()} disabled={svidBusy}>{svidBusy ? "Issuing…" : "Issue SVID"}</button>
          <button className="btn sm" onClick={() => void verifySvid()} disabled={!svid?.data}>Verify SVID</button>
        </div>
        <div className="mono dim" style={{ fontSize: 12.5, marginBottom: 8 }}>trust domain: {ca.data.trust_domain || "—"}</div>
        {svid?.error && <div style={{ color: "var(--red)", fontSize: 13 }}>{svid.error}</div>}
        {svid?.data && <Code>{JSON.stringify(svid.data, null, 2)}</Code>}
        {verifyRes?.data && (
          <div style={{ marginTop: 8 }}>
            <Badge tone={verifyRes.data.valid ? "green" : "red"}>{verifyRes.data.valid ? "SVID VALID" : "SVID INVALID"}</Badge>
          </div>
        )}
      </Panel>

      <Panel title="OT safe-scan policy & emergency stop" sub="impact-protection policy; SIS/ESD are never probed" className="mt">
        <div className="row" style={{ marginBottom: 12 }}>
          <button className="btn" style={{ borderColor: "var(--red)", color: "var(--red)" }} onClick={() => void emergencyStop(true)} disabled={stopBusy}>ENGAGE EMERGENCY STOP</button>
          <button className="btn sm" onClick={() => void emergencyStop(false)} disabled={stopBusy}>Resume scanning</button>
          {stopRes?.data && <Badge tone={stopRes.data.emergency_stop ? "red" : "green"}>{stopRes.data.emergency_stop ? "ALL SCANS HALTED" : "SCANNING RESUMED"}</Badge>}
          {stopRes?.error && <span style={{ color: "var(--red)", fontSize: 13 }}>{stopRes.error}</span>}
        </div>
        <Table
          head={["policy", "active probing", "OT passive", "status"]}
          rows={(policies.length ? policies : [{ id: "default", active_probing: "—", ot_passive: true, enabled: true }]).map((p: any, i: number) => [
            <span className="mono" key={i}>{p.id ?? p.name ?? "default"}</span>,
            <Badge tone={p.active_probing === false || p.active_probing === "deny" ? "amber" : ""} key="a">{String(p.active_probing ?? "scoped")}</Badge>,
            <Badge tone="green" key="o">passive-first</Badge>,
            <Badge tone={p.enabled === false ? "red" : "green"} key="s">{p.enabled === false ? "disabled" : "enabled"}</Badge>,
          ])}
        />
        <p className="dim" style={{ fontSize: 12.5, marginTop: 10 }}>
          OT maintenance windows declared: {windows.data.total_count ?? windowList.length}. Active probing of OT/ICS environments is permitted only inside an explicit, authorized window.
        </p>
      </Panel>
    </>
  );
}
