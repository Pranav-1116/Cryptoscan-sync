import React, { useState } from "react";
import { Badge, Button, ProgressBar } from "../components/ui";
import { Link } from "react-router-dom";
import { getToken, tenantFetch } from "../lib/api";
import { IconNetwork, IconCloud, IconCode, IconContainer, IconHardware, IconCertificate, IconEstate, IconPass, IconTarget, ICON_LG, type Icon } from "../components/icons";

type ScanTarget =
  | "Network"
  | "Cloud"
  | "Source Repository"
  | "Container"
  | "Hardware"
  | "Certificate"
  | "Full Estate";

type ScanStatus = "queued" | "running" | "completed" | "failed";

export default function Scanners() {
  const [step, setStep] = useState<"select" | "configure" | "running">("select");
  const [selectedTarget, setSelectedTarget] = useState<ScanTarget>("Network");
  const [targetInput, setTargetInput] = useState("10.0.0.0/16");
  const [accessMode, setAccessMode] = useState("Read-only TAP");
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus>("queued");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [resultNote, setResultNote] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  const targets: { id: ScanTarget; label: string; desc: string; icon: Icon }[] = [
    { id: "Network", label: "Network Scanner", desc: "Passive TLS JA3/JA3S/JARM fingerprinting and cipher suite audit", icon: IconNetwork },
    { id: "Cloud", label: "Cloud KMS Scanner", desc: "AWS KMS, Azure Key Vault, GCP Cloud KMS key hierarchy audit", icon: IconCloud },
    { id: "Source Repository", label: "Source Repository AST", desc: "Deterministic AST scanner for hardcoded crypto secrets & weak ciphers", icon: IconCode },
    { id: "Container", label: "Container Registry", desc: "Trivy & Syft image SBOM crypto package extraction", icon: IconContainer },
    { id: "Hardware", label: "Hardware & HSM Fleet", desc: "FIPS 140-3 HSM fleet, TPM 2.0, Secure Boot measurements", icon: IconHardware },
    { id: "Certificate", label: "Certificates & CT Logs", desc: "X.509 cert lifecycle, CT logs, and expiry monitoring", icon: IconCertificate },
    { id: "Full Estate", label: "Full Estate Discovery", desc: "Comprehensive continuous cryptographic estate discovery", icon: IconEstate },
  ];

  const handleStartScan = async () => {
    setStep("running");
    setScanStatus("queued");
    setProgress(10);
    setErrorMsg(null);
    setResultNote(null);

    // The execution mode is a safety contract, not a suggestion: a passive /
    // TAP selection must NEVER fall through to the active CIDR sweep, and a
    // refusal from the backend (403 outside authorized scope, 409 safe-scan
    // policy, 503 admission unavailable) is shown as a failure — never
    // papered over with a fabricated "completed" job.
    const wantsActiveSweep = selectedTarget === "Network" && accessMode === "Active Probe";

    try {
      const token = getToken();
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      if (wantsActiveSweep) {
        setScanStatus("running");
        setProgress(40);
        const res = await tenantFetch("/api/v1/network/discover", {
          method: "POST",
          headers,
          body: JSON.stringify({ cidr: targetInput, scan: true, register: false }),
          signal: AbortSignal.timeout(60000),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          const detail = body?.detail;
          const reason = typeof detail === "string" ? detail : detail?.reason || detail?.error;
          throw new Error(reason || `sweep refused (HTTP ${res.status})`);
        }
        const body = await res.json().catch(() => ({}));
        const endpoints: string[] = body?.endpoints ?? [];
        setScanJobId(null);
        setResultNote(
          `Swept ${body?.hosts_checked ?? 0} hosts — ${endpoints.length} open service endpoint(s) found.`
        );
        setProgress(100);
        setScanStatus("completed");
        return;
      }

      // Everything else starts from the authorized onboarding scope: the
      // backend registers scope into the engine and runs the domain plan
      // (passive when an OT environment is declared). There is deliberately
      // NO fallback sweep when scope is not configured — the honest answer
      // is the backend's own refusal plus a pointer to onboarding.
      setScanStatus("running");
      setProgress(45);
      const res = await tenantFetch("/api/v1/onboarding/discovery/start", {
        method: "POST",
        headers,
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const reason = body?.detail || body?.message || `discovery refused (HTTP ${res.status})`;
        throw new Error(
          res.status === 409
            ? `${reason} — complete onboarding (environment, authorized scope, tested connector) first.`
            : reason
        );
      }
      const body = await res.json().catch(() => ({}));
      setScanJobId(body?.run_id ? String(body.run_id) : null);
      const registered = body?.registered ?? {};
      const registeredTotal =
        (registered?.network_targets ?? 0) + (registered?.cloud_accounts ?? 0) + (registered?.repo_configs ?? 0);
      setResultNote(
        `Discovery run ${body?.run_id ?? ""}: ${body?.assets_estimate ?? 0} asset(s) estimated across authorized scope` +
          (registeredTotal ? `, ${registeredTotal} target(s) registered` : "") +
          (body?.passive_only ? " — passive only (OT environment declared)." : ".")
      );
      setProgress(100);
      setScanStatus("completed");
    } catch (e: any) {
      // No fabricated job id, no synthetic completion: the scan either ran
      // or it did not, and the operator sees which and why.
      setScanJobId(null);
      setErrorMsg(e?.message ? String(e.message) : "the scan could not be started");
      setScanStatus("failed");
      setProgress(100);
    }
  };

  return (
    <div className="page" style={{ maxWidth: "880px", margin: "0 auto", padding: "20px 0 60px" }}>
      {step === "select" && (
        <div>
          <div style={{ marginBottom: "28px" }}>
            <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", textTransform: "uppercase", letterSpacing: "0.1em" }}>Discovery Workflow</span>
            <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "6px 0 8px" }}>New Scan</h1>
            <p style={{ margin: 0, fontSize: "14px", color: "var(--dim)" }}>
              Select a specialized scanner to discover cryptographic assets in your estate:
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "14px", marginBottom: "28px" }}>
            {targets.map((t) => {
              const isSelected = selectedTarget === t.id;
              return (
                <div
                  key={t.id}
                  onClick={() => setSelectedTarget(t.id)}
                  style={{
                    padding: "16px 18px",
                    background: isSelected ? "color-mix(in srgb, var(--accent) 8%, transparent)" : "var(--panel)",
                    border: isSelected ? "1px solid var(--cyan)" : "1px solid var(--line)",
                    borderRadius: "var(--r)",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                >
                  <div style={{ marginBottom: "8px", lineHeight: 0, color: isSelected ? "var(--accent)" : "var(--dim)" }}><t.icon size={20} /></div>
                  <div style={{ fontWeight: 600, fontSize: "14.5px", marginBottom: "4px" }}>{t.label}</div>
                  <div style={{ fontSize: "12.5px", color: "var(--dim)", lineHeight: "1.4" }}>{t.desc}</div>
                </div>
              );
            })}
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
            <button onClick={() => setStep("configure")} className="btn primary">
              Configure Target →
            </button>
          </div>
        </div>
      )}

      {step === "configure" && (
        <div>
          <div style={{ marginBottom: "24px" }}>
            <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", textTransform: "uppercase", letterSpacing: "0.1em" }}>Step 2 of 2</span>
            <h1 style={{ fontSize: "24px", fontWeight: 700, margin: "6px 0 8px" }}>Target & Safety Parameters</h1>
            <p style={{ margin: 0, fontSize: "14px", color: "var(--dim)" }}>
              Selected scanner: <b>{selectedTarget}</b>
            </p>
          </div>

          <div className="panel" style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "16px", marginBottom: "24px" }}>
            <div>
              <label style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Target Scope / Endpoint / Subnet
              </label>
              <input
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                style={{
                  width: "100%",
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--r)",
                  padding: "8px 12px",
                  color: "var(--text)",
                  fontFamily: "var(--mono)",
                  fontSize: "13px"
                }}
              />
              <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "6px" }}>
                {selectedTarget === "Network" && accessMode === "Active Probe"
                  ? "An active TLS sweep of this CIDR — the backend verifies it is inside your authorized network scope before probing."
                  : "Passive / read-only discovery runs over your declared onboarding scope; the target field is informational."}
              </div>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Execution Mode & Safety Constraints
              </label>
              <select
                value={accessMode}
                onChange={(e) => setAccessMode(e.target.value)}
                style={{
                  width: "100%",
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--r)",
                  padding: "8px 12px",
                  color: "var(--text)",
                  fontSize: "13px"
                }}
              >
                <option value="Read-only TAP">Passive / Zero Injection (Production Safe)</option>
                <option value="Active Probe">Active TLS Handshake Probe (Authorized subnets only)</option>
                <option value="Credentialed API">Direct KMS API Read-Only Query</option>
              </select>
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <button onClick={() => setStep("select")} className="btn outline">
              ← Back
            </button>
            <button onClick={handleStartScan} className="btn primary">
              Start Authorized Scan
            </button>
          </div>
        </div>
      )}

      {step === "running" && (
        <div className="panel" style={{ padding: "32px 24px", textAlign: "center" }}>
          <div style={{ fontSize: "36px", marginBottom: "16px" }}>
            {scanStatus === "completed" ? <IconPass size={ICON_LG} /> : <IconTarget size={ICON_LG} />}
          </div>
          <h2 style={{ fontSize: "20px", fontWeight: 700, margin: "0 0 8px" }}>
            {scanStatus === "completed"
              ? "Discovery Run Complete"
              : scanStatus === "failed"
                ? "Scan Not Started"
                : "Discovery Scan In Progress"}
          </h2>
          <p style={{ color: "var(--dim)", fontSize: "14px", margin: "0 0 20px" }}>
            {scanJobId && <>Run ID: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{scanJobId}</code> · </>}
            Target: <code>{selectedTarget === "Network" && accessMode === "Active Probe" ? targetInput : "authorized onboarding scope"}</code>
          </p>

          <div style={{ maxWidth: "400px", margin: "0 auto 24px" }}>
            <ProgressBar value={progress} />
          </div>

          {scanStatus === "completed" && resultNote && (
            <p style={{ fontSize: "13.5px", color: "var(--dim)", margin: "0 0 20px" }}>{resultNote}</p>
          )}

          {scanStatus === "failed" && errorMsg && (
            <p style={{ fontSize: "13.5px", color: "var(--danger, #e5484d)", margin: "0 0 20px" }}>
              {errorMsg}
            </p>
          )}

          {scanStatus === "completed" ? (
            <div style={{ display: "flex", justifyContent: "center", gap: "12px" }}>
              <Link to="/assets" className="btn primary" style={{ textDecoration: "none" }}>
                Inspect Discovered Assets →
              </Link>
              <button onClick={() => { setStep("select"); setProgress(0); setScanStatus("queued"); setResultNote(null); }} className="btn outline">
                Run Another Scan
              </button>
            </div>
          ) : scanStatus === "failed" ? (
            <div style={{ display: "flex", justifyContent: "center", gap: "12px" }}>
              <button onClick={() => { setStep("configure"); setProgress(0); setScanStatus("queued"); }} className="btn outline">
                ← Adjust Target
              </button>
              <Link to="/onboarding" className="btn primary" style={{ textDecoration: "none" }}>
                Review Authorized Scope
              </Link>
            </div>
          ) : (
            <div style={{ fontSize: "13px", color: "var(--dim)" }}>
              The backend is executing the discovery plan over your authorized scope. You may navigate away at any time.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
