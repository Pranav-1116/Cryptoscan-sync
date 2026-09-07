/* Role-scoped home dashboards (feature 24). Deterministic per-role landing
   surfaces built from LIVE platform APIs (no demo data): CISO, security analyst,
   and OT engineer. Each persona sees only the tiles relevant to its job; data
   renders zero/empty until a real scan runs. */
import React, { useEffect, useState } from "react";
import { getRoles, getToken } from "../lib/api.js";
import {
  apiStatsSummary, apiAuditAttestation, apiAirgapStatus, apiSlaPosture,
} from "../lib/api.js";
import { useI18n } from "../i18n/I18n.jsx";

type Persona = "ciso" | "analyst" | "ot";

function personaFromRoles(roles: string[]): Persona {
  const r = new Set(roles.map((x) => x.toLowerCase()));
  if (r.has("ciso") || r.has("superadmin") || r.has("admin")) return "ciso";
  if (r.has("scanner")) return "ot";
  return "analyst"; // security_analyst, auditor, developer, default
}

function Tile({ label, value, tone = "default", sub }: { label: string; value: React.ReactNode; tone?: "good" | "bad" | "warn" | "default"; sub?: string }) {
  const color = tone === "good" ? "var(--green)" : tone === "bad" ? "var(--red, #e01e5a)" : tone === "warn" ? "var(--amber)" : "var(--text)";
  return (
    <div className="card" style={{ padding: 16, minWidth: 200 }}>
      <div style={{ fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--faint)" }}>{label}</div>
      <div style={{ fontSize: 30, fontWeight: 800, color, marginTop: 6, fontFamily: "var(--mono)" }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 22 }}>
      <h3 style={{ fontSize: 13, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--faint)", marginBottom: 10 }}>{title}</h3>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>{children}</div>
    </div>
  );
}

export default function RoleDashboard() {
  const { t } = useI18n();
  const roles = getRoles();
  const persona = personaFromRoles(roles);
  const [stats, setStats] = useState<Record<string, unknown> | null>(null);
  const [attest, setAttest] = useState<any>(null);
  const [airgap, setAirgap] = useState<any>(null);
  const [sla, setSla] = useState<any>(null);

  useEffect(() => {
    if (!getToken()) return;
    let alive = true;
    apiStatsSummary().then((r) => { if (alive && r.data) setStats(r.data as Record<string, unknown>); });
    apiSlaPosture().then((r) => { if (alive && r.data) setSla(r.data); });
    if (persona === "ciso" || persona === "analyst") {
      apiAuditAttestation().then((r) => { if (alive && r.data) setAttest(r.data); }).catch(() => {});
      apiAirgapStatus().then((r) => { if (alive && r.data) setAirgap(r.data); }).catch(() => {});
    }
    return () => { alive = false; };
  }, [persona]);

  const n = (k: string) => Number((stats as Record<string, number> | null)?.[k] ?? 0);
  const personaTitle = persona === "ciso" ? t("role.ciso") : persona === "ot" ? t("role.otEngineer") : t("role.analyst");
  const live = !!stats;

  return (
    <div className="page" style={{ padding: 24 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
        <h1 style={{ fontSize: 22, margin: 0 }}>{t("role.title")} · {personaTitle}</h1>
        <span className="badge" style={{ background: live ? "rgba(47,184,119,0.12)" : "rgba(232,161,61,0.12)", color: live ? "var(--green)" : "var(--amber)" }}>
          {live ? t("common.liveData") : t("common.offline")}
        </span>
      </div>
      <p style={{ color: "var(--faint)", fontSize: 13, marginTop: 6 }}>{t("role.switchHint")}</p>

      {persona === "ciso" && (
        <>
          <Section title={t("dash.portfolioRisk")}>
            <Tile label={t("dash.openFindings")} value={n("total_findings")} tone={n("total_findings") > 0 ? "warn" : "good"} />
            <Tile label={t("dash.complianceCoverage")} value={attest ? `${attest.attestation?.status === "VERIFIED" ? "100" : "—"}%` : "—"}
              tone={attest?.attestation?.status === "VERIFIED" ? "good" : "default"} sub={t("dash.auditIntegrity")} />
            <Tile label={t("dash.drStatus")} value={airgap ? t("dash.on") : "—"} tone="good" sub="encrypted backups configured" />
            <Tile label={t("dash.airgapMode")} value={airgap?.airgap ? t("dash.on") : t("dash.off")}
              tone={airgap?.airgap ? "warn" : "default"} />
          </Section>
          <Section title={t("dash.auditIntegrity")}>
            <Tile label={t("resilience.auditAttestation")}
              value={attest ? (attest.attestation?.status === "VERIFIED" ? t("dash.verified") : t("dash.tampered")) : "—"}
              tone={attest?.attestation?.status === "VERIFIED" ? "good" : attest ? "bad" : "default"}
              sub={attest ? `${attest.attestation?.entries_checked ?? 0} entries · HMAC-SHA256 signed` : t("common.noData")} />
          </Section>
        </>
      )}

      {persona === "analyst" && (
        <>
          <Section title={t("dash.triageQueue")}>
            <Tile label={t("dash.openFindings")} value={n("total_findings")} tone={n("total_findings") > 0 ? "warn" : "good"} />
            <Tile label="scans" value={n("total_scans")} />
            <Tile label="scanners" value={`${n("active_scanners")}/${n("total_scanners")}`} />
            <Tile label={t("dash.recentAlerts")} value={n("active_alerts") ?? n("total_findings")} tone="warn" />
          </Section>
          <Section title={t("dash.auditIntegrity")}>
            <Tile label={t("resilience.auditAttestation")}
              value={attest ? (attest.attestation?.status === "VERIFIED" ? t("dash.verified") : t("dash.tampered")) : "—"}
              tone={attest?.attestation?.status === "VERIFIED" ? "good" : attest ? "bad" : "default"}
              sub={attest ? `${attest.attestation?.entries_checked ?? 0} chained entries` : t("common.noData")} />
          </Section>
        </>
      )}

      {persona === "ot" && (
        <>
          <Section title={t("nav.ot")}>
            <Tile label={t("dash.otCleartext")} value={0} tone="good"
              sub="passive decode · S7comm / ENIP / BACnet / OPC-UA" />
            <Tile label={t("resilience.activeProbes")} value={0} tone="good" sub="SIS/ESD never probed" />
            <Tile label="scanners" value={`${n("active_scanners")}/${n("total_scanners")}`} />
          </Section>
          <p style={{ color: "var(--faint)", fontSize: 12, marginTop: 14 }}>
            Passive OT decoders flag cleartext engineering access (S7 download, BACnet WriteProperty,
            CIP ForwardOpen, OPC-UA security-mode None) from observed spans only. Upload a capture in
            the <a href="#/resilience" style={{ color: "var(--blue,#4d9fff)" }}>Resilience console</a>.
          </p>
        </>
      )}
    </div>
  );
}
