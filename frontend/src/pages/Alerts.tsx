import React, { useMemo, useState } from "react";
import { Badge, PageHead, Table, Panel, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { apiLiveAlerts, LiveAlert, LiveAlertsResponse } from "../lib/api.js";

/* Alerts — deterministic, cross-scanner risk aggregation from the live scans
   (GET /api/v1/live-scan/alerts), plus a strip of the most recent high-severity
   SSE events. Empty until scans produce findings. No static/seed data.
   Click a finding to open its deterministic detail: Why → Evidence →
   Dependencies → Recommendation → Remediation → Verification. All guidance is
   a static rule map keyed on the finding's kind (no fabricated data). */

// Deterministic, rule-based guidance per finding kind. Every field is derived
// from the scanner/kind — there is no model inference and no invented facts.
const GUIDANCE: Record<string, { why: string; recommend: string; remediate: string[]; verifyLink: string }> = {
  WEAK_LIBRARY: {
    why: "A crypto library classified DISALLOWED (EOL/banned) is loaded by a running process. Known-broken or unpatched crypto is in the active attack surface.",
    recommend: "Replace the disallowed library with a supported version/fork before any protocol change; track it on the PQC queue if it also lacks post-quantum agility.",
    remediate: ["Identify every process/package loading the library (CBOM dependencies).", "Upgrade or swap to an approved build; rebuild and redeploy the affected service.", "Re-run the runtime scanner to confirm the library no longer appears."],
    verifyLink: "#/evidence",
  },
  DEPRECATED_LIBRARY: {
    why: "A crypto library marked DEPRECATED/RESTRICTED is near or past end-of-life and may stop receiving security fixes.",
    recommend: "Schedule an upgrade to a supported version; review migration windows with the service owner.",
    remediate: ["Confirm the installed version against the CBOM.", "Upgrade the package across affected processes.", "Rescan to verify the new version is classified ALLOWED."],
    verifyLink: "#/cbom",
  },
  UNMANAGED_LIBRARY: {
    why: "A crypto library's version cannot be resolved (bundled/venv/static), so its posture cannot be classified — an unknown, never assumed safe.",
    recommend: "Manually identify the provenance and version; add it to the managed inventory or replace with a managed package.",
    remediate: ["Locate the bundled/static copy on disk or in the image.", "Record its origin/version or replace it with a managed dependency.", "Rescan so it classifies to a known verdict."],
    verifyLink: "#/libraries",
  },
  RISK_PROCESS: {
    why: "A running process is linked against a weak/EOL crypto library, exposing that service's TLS and key operations.",
    recommend: "Patch the process's crypto dependency and restart the service; prioritise externally-reachable processes.",
    remediate: ["Map the process to its service/owner.", "Update the weak library the process loads.", "Restart and rescan; confirm the process leaves the RISK set."],
    verifyLink: "#/runtime",
  },
  WEAK_TLS: {
    why: "The endpoint negotiates a weak TLS version or disallowed cipher suite, weakening confidentiality/integrity of the channel.",
    recommend: "Enforce modern TLS (1.2+/1.3) with GCM/ChaCha20 and ECDHE; remove legacy cipher/protocol support.",
    remediate: ["Update the endpoint TLS configuration to the approved cipher policy.", "Disable SSLv3/TLS1.0/1.1 and CBC/RC4/3DES suites.", "Rescan the network target to confirm only strong suites are offered."],
    verifyLink: "#/network",
  },
  CBC_CIPHER: {
    why: "CBC-mode ciphers are accepted, which without constant-time hardening is susceptible to Lucky13-style timing attacks.",
    recommend: "Restrict negotiated suites to AEAD (GCM/ChaCha20-Poly1305) on TLS 1.2+.",
    remediate: ["Remove CBC cipher suites from the server policy.", "Prefer TLS 1.3 where possible.", "Rescan to confirm CBC is no longer offered."],
    verifyLink: "#/network",
  },
  CHAIN_INVALID: {
    why: "The served certificate chain failed validation (missing/intermediate mismatch, untrusted root, or name mismatch), so clients cannot establish trust.",
    recommend: "Install the complete, correct chain and verify against the trust store before expiry-driven renewal.",
    remediate: ["Re-issue or re-install the full certificate chain (leaf + intermediates).", "Confirm the CN/SAN matches the endpoint and the root is trusted.", "Rescan to confirm chain validation passes."],
    verifyLink: "#/certificates",
  },
  CERT_EXPIRED: {
    why: "A certificate in service is past its notAfter date; TLS handshakes to that endpoint will fail or require insecure overrides.",
    recommend: "Renew/re-issue immediately from the certificate inventory; rotate the serving key.",
    remediate: ["Request/issue a replacement certificate.", "Deploy it to the endpoint and reload the service.", "Rescan to confirm the new cert is valid and not expired."],
    verifyLink: "#/certificates",
  },
  CERT_EXPIRING: {
    why: "A certificate is within the expiry warning window; without renewal it will lapse and cause an outage.",
    recommend: "Schedule renewal ahead of the SLA tier; automate renewal where supported.",
    remediate: ["Raise/route a renewal ticket to the certificate owner.", "Renew and deploy before expiry.", "Confirm the new expiry on rescan."],
    verifyLink: "#/certificates",
  },
  WEAK_SIGNATURE: {
    why: "A certificate is signed with a deprecated hash (MD5/SHA-1), which does not provide collision resistance and is untrusted by modern clients.",
    recommend: "Re-issue using SHA-256 or stronger; add the issuing CA to the remediation queue.",
    remediate: ["Re-issue the certificate with a SHA-256 (or stronger) signature.", "Replace it on the endpoint.", "Rescan to confirm the signature algorithm is strong."],
    verifyLink: "#/certificates",
  },
  TPM_ABSENT: {
    why: "No TPM was detected on the host, so there is no hardware root of trust for measured boot, sealed key storage, or attestation.",
    recommend: "Enable/verify TPM in firmware (or provision a vTPM/HSM) for hosts handling key material.",
    remediate: ["Check BIOS/UEFI for a disabled TPM and enable it.", "Where physical TPM is absent, provision a vTPM or HSM.", "Rescan hardware to confirm a TPM is reported."],
    verifyLink: "#/hardware",
  },
  STATIC_FINDINGS: {
    why: "A static source/container/universal scan reported high-confidence cryptographic findings in the codebase or image.",
    recommend: "Triage each finding in the code-rule results; remediate weak primitives at the call site.",
    remediate: ["Open the scan detail for file/line evidence.", "Replace weak primitive usage with the approved API.", "Re-run the static scan to clear the finding."],
    verifyLink: "#/crypto-assurance",
  },
  SCANNER_ERROR: {
    why: "A scanner failed to complete, so that domain's coverage is missing — an observability gap, not a clean result.",
    recommend: "Fix the scanner/target configuration (credentials in vault, reachable target) and rerun to restore coverage.",
    remediate: ["Read the scanner error detail.", "Correct target/credential/permission issues.", "Re-run the live scan and confirm the scanner reports ok."],
    verifyLink: "#/live-scanners",
  },
};

function guidanceFor(kind: string) {
  return GUIDANCE[kind] ?? {
    why: "This finding was raised by a deterministic scanner rule. Open the evidence record for the exact observation that triggered it.",
    recommend: "Review the linked evidence and apply the domain's approved remediation pattern.",
    remediate: ["Inspect the evidence for this finding.", "Apply the relevant approved control.", "Rescan to verify the condition is cleared."],
    verifyLink: "#/evidence",
  };
}

interface AlertRow {
  id: string;
  severity: string;
  scanner: string;
  kind: string;
  title: string;
  detail: string;
  asset: string;
  ts?: string;
}

const SEV_TONE: Record<string, "red" | "amber" | "cyan" | "green" | ""> = {
  CRITICAL: "red",
  HIGH: "red",
  MEDIUM: "amber",
  LOW: "cyan",
};

export default function Alerts() {
  const [filter, setFilter] = useState("all");
  const [acked, setAcked] = useState<Set<string>>(new Set());
  const [sel, setSel] = useState<AlertRow | null>(null);
  const res = usePollingApi(apiLiveAlerts, 6000);
  useRealtimeRefresh(res.run);
  const live = res.source === "live";
  const data = (res.data ?? null) as LiveAlertsResponse | null;
  const counts = data?.counts ?? {};

  const rows: AlertRow[] = useMemo(
    () =>
      (data?.alerts ?? []).map((a: LiveAlert, i) => ({
        id: `${a.scanner}-${a.kind}-${a.asset}-${i}`,
        severity: a.severity,
        scanner: a.scanner,
        kind: a.kind,
        title: a.title,
        detail: a.detail,
        asset: a.asset,
        ts: (a as { ts?: string }).ts,
      })),
    [data],
  );

  const visible = rows
    .filter((r) => (filter === "all" ? true : r.severity === filter.toUpperCase()))
    .filter((r) => !acked.has(r.id));

  return (
    <>
      <PageHead
        crumb="post-quantum / alerts"
        title="Alerts"
        sub="Cross-scanner risk aggregation — weak/EOL libraries, weak TLS & ciphers, certificate expiry/signature, chain failures, hardware root-of-trust, static findings"
        right={
          <div className="row">
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone="red">{visible.length} UNACKED</Badge>
          </div>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["CRITICAL", counts.CRITICAL ?? 0, "red"], ["HIGH", counts.HIGH ?? 0, "red"],
          ["MEDIUM", counts.MEDIUM ?? 0, "amber"], ["LOW", counts.LOW ?? 0, "cyan"]].map(([k, v, tone]) => (
          <div className="kpi" key={k as string}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{v as number}</span>
          </div>
        ))}
      </div>

      <div className="tabs">
        {["all", "critical", "high", "medium", "low"].map((t) => (
          <button key={t} className={filter === t ? "active" : ""} onClick={() => setFilter(t)}>{t}</button>
        ))}
      </div>

      {live && visible.length === 0 && (
        <div className="dim" style={{ padding: 30, textAlign: "center" }}>
          No unacked alerts in this view — run scans from Operations → Realtime scanners; findings aggregate here.
        </div>
      )}
      {!live && (
        <div className="dim" style={{ padding: 30, textAlign: "center" }}>
          Backend offline — start the control plane and run a scan to see risk alerts.
        </div>
      )}

      {visible.map((a) => (
        <div className={`alertcard ${a.severity.toLowerCase()}`} key={a.id}
             style={{ cursor: "pointer" }} onClick={() => setSel(a)}>
          <div>
            <div className="ttl">
              <Badge tone={SEV_TONE[a.severity]}>{a.severity}</Badge>
              <Badge>{a.scanner}</Badge> {a.title}
            </div>
            <div className="det">{a.detail}{a.asset ? <span className="dim mono"> · {a.asset}</span> : null}</div>
          </div>
          <div className="row" style={{ gap: 6 }} onClick={(e) => e.stopPropagation()}>
            <button className="btn sm" onClick={() => setSel(a)}>details</button>
            <button className="btn sm" onClick={() => setAcked((s) => new Set(s).add(a.id))}>ack</button>
          </div>
        </div>
      ))}

      <Panel title="All findings" sub="sorted by severity" className="mt" >
        <Table
          head={["severity", "scanner", "finding", "detail", "asset", ""]}
          onSelect={(i) => setSel(rows[i])}
          clickable
          rows={rows.map((r) => [
            <Badge tone={SEV_TONE[r.severity]}>{r.severity}</Badge>,
            r.scanner,
            <span style={{ fontWeight: 600 }}>{r.title}</span>,
            <span style={{ fontSize: 12 }}>{r.detail}</span>,
            <span className="mono" style={{ fontSize: 12 }}>{r.asset || "—"}</span>,
            <span className="row" style={{ gap: 6 }}>
              <button className="btn sm" onClick={() => setSel(r)}>details</button>
              <button className="btn sm" onClick={() => setAcked((s) => new Set(s).add(r.id))}>ack</button>
            </span>,
          ])}
        />
        {rows.length === 0 && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>No findings yet.</div>}
      </Panel>

      {sel && (
        <FindingDetail finding={sel} onClose={() => setSel(null)} />
      )}
    </>
  );
}

function FindingDetail({ finding, onClose }: { finding: AlertRow; onClose: () => void }) {
  const g = guidanceFor(finding.kind);
  return (
    <Drawer
      title={finding.title}
      sub={`${finding.severity} · ${finding.scanner} · ${finding.kind}${finding.asset ? ` · ${finding.asset}` : ""}`}
      onClose={onClose}
    >
      <div className="fd-sections">
        <section className="fd-sec">
          <h4><span className="fd-num">1</span> Why this matters</h4>
          <p>{g.why}</p>
          <div className="fd-kv" style={{ marginTop: 10 }}>
            <span className="k">observation</span><span className="v">{finding.detail}</span>
            <span className="k">scanner</span><span className="v mono">{finding.scanner}</span>
            <span className="k">rule</span><span className="v mono">{finding.kind}</span>
            {finding.ts && <><span className="k">detected</span><span className="v mono">{new Date(finding.ts).toLocaleString()}</span></>}
          </div>
        </section>

        <section className="fd-sec">
          <h4><span className="fd-num">2</span> Evidence</h4>
          <p>The raw observation recorded by the deterministic scanner:</p>
          <ul>
            <li className="mono" style={{ wordBreak: "break-word" }}>{finding.detail}</li>
            {finding.asset && <li className="mono">asset: {finding.asset}</li>}
          </ul>
          <a href="#/evidence" className="mono" style={{ fontSize: 12, display: "inline-block", marginTop: 8 }}>
            open hash-chained evidence chain →
          </a>
        </section>

        <section className="fd-sec">
          <h4><span className="fd-num">3</span> Dependencies</h4>
          <p>Identify every component that depends on the affected crypto before changing anything:</p>
          <ul>
            <li>Trace the asset/library in the CBOM dependency graph and blast-radius view.</li>
            <li>Confirm affected processes/services from the runtime inventory.</li>
          </ul>
          <a href="#/graph" className="mono" style={{ fontSize: 12, display: "inline-block", marginTop: 8 }}>
            open dependency graph / blast radius →
          </a>
        </section>

        <section className="fd-sec">
          <h4><span className="fd-num">4</span> Recommendation</h4>
          <p>{g.recommend}</p>
        </section>

        <section className="fd-sec">
          <h4><span className="fd-num">5</span> Remediation</h4>
          <ul>
            {g.remediate.map((step, i) => <li key={i}>{step}</li>)}
          </ul>
          <p style={{ marginTop: 8, color: "var(--amber)" }}>
            Production changes are approval-gated under change control — the platform never auto-remediates.
          </p>
        </section>

        <section className="fd-sec verify">
          <h4><span className="fd-num">6</span> Verification</h4>
          <p>After remediation, re-run the relevant scanner and confirm the finding no longer appears. The
             result is sealed into the hash-chained evidence lake for audit.</p>
          <a href={g.verifyLink} className="mono" style={{ fontSize: 12, display: "inline-block", marginTop: 4 }}>
            go to the relevant surface to rescan and verify →
          </a>
        </section>
      </div>
    </Drawer>
  );
}
