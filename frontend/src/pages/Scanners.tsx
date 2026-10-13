import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { activeTenantId, getToken, tenantFetch } from "../lib/api";
import { IconNetwork, IconCloud, IconCode, IconContainer, IconHardware, IconCertificate, IconEstate, IconPass, IconTarget, ICON_LG, type Icon } from "../components/icons";

type ScanTarget = "Network" | "Cloud" | "Source Repository" | "Container" | "Hardware" | "Certificate" | "Full Estate";
type ScanStatus = "verifying" | "queued" | "running" | "completed" | "failed" | "cancelled" | "unknown";
type Mode = "passive" | "active" | "registration";

const targets: { id: ScanTarget; label: string; desc: string; icon: Icon; available: boolean; reason?: string }[] = [
  { id: "Network", label: "Network Scanner", desc: "Authorized active CIDR sweep and TLS endpoint probes", icon: IconNetwork, available: true },
  { id: "Cloud", label: "Cloud KMS Scanner", desc: "IaC tree inspection with a durable per-run record (admission + coverage)", icon: IconCloud, available: true },
  { id: "Source Repository", label: "Source Repository AST", desc: "Source crypto analysis", icon: IconCode, available: false, reason: "The source job trigger does not enforce the declared application scope at execution." },
  { id: "Container", label: "Container Registry", desc: "Image/filesystem crypto inventory with a durable per-run record", icon: IconContainer, available: true },
  { id: "Hardware", label: "Hardware & HSM Fleet", desc: "Hardware inventory", icon: IconHardware, available: false, reason: "No scoped, per-run hardware job contract is available here." },
  { id: "Certificate", label: "Certificates & CT Logs", desc: "Certificate inventory", icon: IconCertificate, available: false, reason: "No scoped, per-run certificate job contract is available here." },
  { id: "Full Estate", label: "Register Authorized Scope", desc: "Register onboarding targets and compute an inventory estimate; does not execute scanner jobs", icon: IconEstate, available: true },
];

function detail(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const value = (body as { detail?: unknown; message?: unknown }).detail ?? (body as { message?: unknown }).message;
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const reason = (value as { reason?: unknown; error?: unknown }).reason ?? (value as { error?: unknown }).error;
    if (typeof reason === "string") return reason;
  }
  return null;
}

async function readResponse(res: Response): Promise<unknown> {
  return res.json().catch(() => null);
}

function responseError(res: Response, body: unknown): Error {
  return new Error(`${detail(body) || "Request refused"} (HTTP ${res.status})`);
}

function runStatus(raw: unknown): ScanStatus | null {
  switch (String(raw || "").toLowerCase()) {
    case "planned": case "queued": return "queued";
    case "running": return "running";
    case "complete": case "completed": return "completed";
    case "failed": case "blocked": return "failed";
    case "cancelled": case "canceled": return "cancelled";
    default: return null;
  }
}

export default function Scanners() {
  const [step, setStep] = useState<"select" | "configure" | "running">("select");
  const [selectedTarget, setSelectedTarget] = useState<ScanTarget>("Network");
  const [targetInput, setTargetInput] = useState("");
  const [mode, setMode] = useState<Mode>("passive");
  const [activeAuthorized, setActiveAuthorized] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [pollKind, setPollKind] = useState<"discovery" | "job" | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus>("queued");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [resultNote, setResultNote] = useState<string | null>(null);
  const [trackedSession, setTrackedSession] = useState<{ token: string | null; tenant: string | null } | null>(null);
  const generation = useRef(0);
  const submitting = useRef(false);
  const stepRef = useRef(step);
  stepRef.current = step;

  useEffect(() => {
    const invalidate = () => {
      const hadRequest = submitting.current || stepRef.current === "running";
      generation.current += 1;
      submitting.current = false;
      setScanJobId(null);
      setPollKind(null);
      setTrackedSession(null);
      setResultNote(null);
      if (hadRequest) {
        setStep("running");
        setScanStatus("unknown");
        setErrorMsg("Session or tenant changed. Tracking stopped; the prior run's outcome is unknown. Start a new request in the current session.");
      }
    };
    const onStorage = (event: StorageEvent) => {
      if (event.key === "zelinx_token" || event.key === "cryptoscan_tenant" || event.key === null) invalidate();
    };
    window.addEventListener("zelinx:tenant", invalidate);
    window.addEventListener("zelinx:auth", invalidate);
    window.addEventListener("storage", onStorage);
    return () => {
      generation.current += 1;
      window.removeEventListener("zelinx:tenant", invalidate);
      window.removeEventListener("zelinx:auth", invalidate);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  // ID-bearing scoped workflows this page can poll: onboarding discovery
  // runs and the durable job records the specialized scanners leave behind
  // (GET /jobs/{id} — status, admission decision, bounded coverage). A shared
  // latest-cycle listing can never identify this request, so it is not used.
  useEffect(() => {
    if (!scanJobId || !trackedSession) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const expectedGeneration = generation.current;
    const current = () => !stopped && generation.current === expectedGeneration
      && getToken() === trackedSession.token && activeTenantId() === trackedSession.tenant;
    const poll = async () => {
      if (!current()) return;
      try {
        const path = pollKind === "job"
          ? `/api/v1/jobs/${encodeURIComponent(scanJobId)}`
          : `/api/v1/onboarding/discovery/${encodeURIComponent(scanJobId)}`;
        const res = await tenantFetch(path, {
          signal: AbortSignal.timeout(10000),
        });
        if (!current()) return;
        const body = await readResponse(res);
        if (!current()) return;
        if (!res.ok) {
          if (res.status === 401 || res.status === 403 || res.status === 404) {
            setScanStatus("unknown");
            setErrorMsg(`${responseError(res, body).message}. Tracking stopped; the run's outcome is unknown.`);
            return;
          }
          setErrorMsg(`${responseError(res, body).message}. Status unavailable; retrying.`);
        } else if (!body || typeof body !== "object") {
          setScanStatus("unknown");
          setErrorMsg("Run status did not identify the requested run. Tracking stopped; outcome unknown.");
          return;
        } else if (pollKind === "job") {
          if ((body as { job_id?: unknown }).job_id !== scanJobId) {
            setScanStatus("unknown");
            setErrorMsg("Run status did not identify the requested run. Tracking stopped; outcome unknown.");
            return;
          }
          const record = body as {
            status?: unknown; error_message?: unknown;
            progress?: { coverage?: Record<string, unknown>; admission?: { mode?: unknown } };
          };
          const status = runStatus(record.status);
          if (!status) {
            setScanStatus("unknown");
            setErrorMsg(`Unsupported run status: ${String(record.status ?? "missing")}. Outcome unknown.`);
            return;
          }
          setScanStatus(status);
          setErrorMsg(null);
          if (status === "completed") {
            const cov = record.progress?.coverage;
            const covLine = cov && typeof cov === "object" && Object.keys(cov).length > 0
              ? Object.entries(cov).map(([k, v]) => `${k.replace(/_/g, " ")}: ${String(v)}`).join(" · ")
              : "no counts recorded";
            setResultNote(`Durable run completed. Coverage: ${covLine}. Counts summarize the scan result; the full findings live in the scanner's own surfaces.`);
            return;
          }
          if (status === "failed" || status === "cancelled") {
            setErrorMsg(typeof record.error_message === "string" && record.error_message ? record.error_message : `Run ${status}.`);
            return;
          }
        } else if ((body as { id?: unknown }).id !== scanJobId) {
          setScanStatus("unknown");
          setErrorMsg("Run status did not identify the requested run. Tracking stopped; outcome unknown.");
          return;
        } else {
          const record = body as { status?: unknown; error?: unknown; summary?: { assets_estimate?: unknown; registered?: Record<string, unknown> }; targets_registered?: unknown };
          const status = runStatus(record.status);
          if (!status) {
            setScanStatus("unknown");
            setErrorMsg(`Unsupported run status: ${String(record.status ?? "missing")}. Outcome unknown.`);
            return;
          }
          setScanStatus(status);
          setErrorMsg(null);
          if (status === "completed") {
            const estimate = record.summary?.assets_estimate;
            setResultNote(`Onboarding scope registration complete${typeof estimate === "number" ? `; ${estimate} asset(s) estimated` : ""}. This is not a completed asset scan.`);
            return;
          }
          if (status === "failed" || status === "cancelled") {
            setErrorMsg(typeof record.error === "string" && record.error ? record.error : `Discovery run ${status}.`);
            return;
          }
        }
      } catch (err) {
        if (!current()) return;
        setErrorMsg(`Run status unavailable (${err instanceof Error ? err.message : "network error"}); retrying.`);
      }
      if (current()) timer = setTimeout(poll, 3000);
    };
    void poll();
    return () => { stopped = true; if (timer) clearTimeout(timer); };
  }, [scanJobId, trackedSession, pollKind]);

  const selected = targets.find((t) => t.id === selectedTarget)!;
  const reset = () => {
    generation.current += 1;
    submitting.current = false;
    setScanJobId(null);
    setPollKind(null);
    setTrackedSession(null);
    setScanStatus("queued");
    setErrorMsg(null);
    setResultNote(null);
  };

  const handleStartScan = async () => {
    if (submitting.current || !selected.available || (selectedTarget === "Network" && (mode !== "active" || !activeAuthorized || !targetInput.trim()))) return;
    submitting.current = true;
    reset();
    submitting.current = true;
    const requestGeneration = generation.current;
    const token = getToken();
    const tenant = activeTenantId();
    const sameSession = () => generation.current === requestGeneration && token === getToken() && tenant === activeTenantId();
    setStep("running");
    setScanStatus(selectedTarget === "Network" ? "running" : "verifying");
    let requestRefused = false;
    try {
      if (selectedTarget === "Network") {
        // This synchronous endpoint performs a real active sweep. It enforces
        // admission + CIDR containment in tenant scope; never use it for TAP.
        const res = await tenantFetch("/api/v1/network/discover", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cidr: targetInput.trim(), scan: true, register: false }),
          signal: AbortSignal.timeout(60000),
        });
        if (!sameSession()) return;
        const body = await readResponse(res);
        if (!sameSession()) return;
        if (!res.ok) { requestRefused = true; throw responseError(res, body); }
        if (!body || typeof body !== "object" || !Array.isArray((body as { endpoints?: unknown }).endpoints)) {
          setScanStatus("unknown");
          setErrorMsg("Sweep response did not contain endpoint results; outcome unknown.");
          return;
        }
        const result = body as { hosts_checked?: unknown; endpoints: unknown[] };
        setResultNote(`Sweep finished${typeof result.hosts_checked === "number" ? `: ${result.hosts_checked} host(s) checked` : ""}; ${result.endpoints.length} open service endpoint(s) returned.`);
        setScanStatus("completed");
      } else if (selectedTarget === "Cloud" || selectedTarget === "Container") {
        // Synchronous specialized scan, now with a durable run identity:
        // the server returns job_id and GET /jobs/{id} carries status,
        // the admission decision and bounded coverage for THIS run.
        const endpoint = selectedTarget === "Cloud" ? "/api/v1/cloud-scans" : "/api/v1/container-scans";
        const payload = selectedTarget === "Cloud"
          ? { path: targetInput.trim(), live: false }
          : { path: targetInput.trim(), live_cve: false };
        const res = await tenantFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(120000),
        });
        if (!sameSession()) return;
        const body = await readResponse(res);
        if (!sameSession()) return;
        if (!res.ok) { requestRefused = true; throw responseError(res, body); }
        const jobId = body && typeof body === "object" ? (body as { job_id?: unknown }).job_id : null;
        if (typeof jobId !== "string" || !jobId) {
          setScanStatus("unknown");
          setErrorMsg("Scan response did not identify a durable run; outcome unknown.");
          return;
        }
        setTrackedSession({ token, tenant });
        setPollKind("job");
        setScanJobId(jobId);
        // A 200 response is not the status record: poll the job before
        // displaying completion, same rule as discovery runs.
        setScanStatus("verifying");
      } else {
        // Onboarding registers ALL declared targets. It has no target/mode
        // parameters; never route a specialized selection to this endpoint.
        const res = await tenantFetch("/api/v1/onboarding/discovery/start", {
          method: "POST", signal: AbortSignal.timeout(30000),
        });
        if (!sameSession()) return;
        const body = await readResponse(res);
        if (!sameSession()) return;
        if (!res.ok) { requestRefused = true; throw responseError(res, body); }
        const runId = body && typeof body === "object" ? (body as { run_id?: unknown }).run_id : null;
        if (typeof runId !== "string" || !runId) {
          setScanStatus("unknown");
          setErrorMsg("Discovery accepted without a run ID; outcome unknown.");
          return;
        }
        setTrackedSession({ token, tenant });
        setPollKind("discovery");
        setScanJobId(runId);
        const acceptedStatus = runStatus((body as { status?: unknown }).status);
        setScanStatus(acceptedStatus === "queued" || acceptedStatus === "running" ? acceptedStatus : "verifying");
        // Even a 202 response claiming 'complete' is not the status record.
        // Poll GET /discovery/{run_id} before displaying completion.
      }
    } catch (err) {
      if (!sameSession()) return;
      setErrorMsg(`${err instanceof Error ? err.message : "Scan request unavailable"}${requestRefused ? "" : "; request outcome unknown (no response)"}`);
      setScanStatus(requestRefused ? "failed" : "unknown");
    } finally {
      submitting.current = false;
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
              Choose an available workflow. Unavailable scanner families cannot be started from this page.
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "14px", marginBottom: "28px" }}>
            {targets.map((t) => {
              const isSelected = selectedTarget === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  aria-pressed={isSelected}
                  onClick={() => { reset(); setSelectedTarget(t.id); setMode(t.id === "Full Estate" ? "registration" : "passive"); setActiveAuthorized(false); }}
                  style={{
                    textAlign: "left",
                    color: "var(--text)",
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
                  {!t.available && <div style={{ fontSize: 12, color: "var(--amber)", marginTop: 8 }}>Unavailable: {t.reason}</div>}
                </button>
              );
            })}
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
            <button onClick={() => setStep("configure")} disabled={!selected.available} className="btn primary">
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
              Selected workflow: <b>{selected.label}</b>
            </p>
          </div>

          <div className="panel" style={{ padding: "20px", display: "flex", flexDirection: "column", gap: "16px", marginBottom: "24px" }}>
            {selectedTarget === "Cloud" || selectedTarget === "Container" ? <>
            <div>
              <label htmlFor="scan-path" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                {selectedTarget === "Cloud" ? "IaC tree path (inside declared source roots)" : "Container filesystem path (inside declared source roots)"}
              </label>
              <input id="scan-path" placeholder="/workspace/infra"
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
                The server refuses any path outside the declared source roots before scanning. This run leaves a durable job record — status, the admission decision and bounded coverage — under its run ID{selectedTarget === "Cloud" ? ". Live provider reads are not requested here (IaC tree analysis only)." : ". Live CVE enrichment is off for this run."}
              </div>
            </div>
            </> : selectedTarget === "Network" ? <>
            <div>
              <label htmlFor="network-cidr" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Authorized network IP / CIDR
              </label>
              <input id="network-cidr" placeholder="10.0.0.0/24"
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
                The server verifies the CIDR against your tenant's declared scope and scan safety policy. A passive selection never starts an active sweep.
              </div>
            </div>

            <div>
              <label htmlFor="scan-mode" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Execution mode
              </label>
              <select id="scan-mode"
                value={mode}
                onChange={(e) => { setMode(e.target.value as Mode); setActiveAuthorized(false); }}
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
                <option value="passive">Passive / TAP — unavailable (no passive capture endpoint)</option>
                <option value="active">Active CIDR sweep + TLS probe (authorized scope only)</option>
              </select>
            </div>
            {mode === "active" && <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
              <input type="checkbox" checked={activeAuthorized} onChange={(e) => setActiveAuthorized(e.target.checked)} />
              I authorize active probes of this declared network scope.
            </label>}
            </> : <p style={{ margin: 0, fontSize: 13, color: "var(--dim)" }}>
              Registers all declared onboarding scope into domain tables and stores an asset estimate. This does not run specialized scans. Configure environments, scope and a tested connector in onboarding first.
            </p>}
          </div>

          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <button onClick={() => setStep("select")} className="btn outline">
              ← Back
            </button>
            <button
              onClick={handleStartScan}
              disabled={(selectedTarget === "Network" && (mode !== "active" || !activeAuthorized || !targetInput.trim()))
                || ((selectedTarget === "Cloud" || selectedTarget === "Container") && !targetInput.trim())}
              className="btn primary"
            >
              {selectedTarget === "Network" ? "Start Authorized Sweep"
                : selectedTarget === "Cloud" ? "Start Cloud Scan"
                : selectedTarget === "Container" ? "Start Container Scan"
                : "Register Authorized Scope"}
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
            {scanStatus === "completed" ? (selectedTarget === "Network" ? "Network Sweep Complete"
              : selectedTarget === "Cloud" ? "Cloud Scan Complete"
              : selectedTarget === "Container" ? "Container Scan Complete"
              : "Scope Registration Complete")
              : scanStatus === "failed" ? "Request Failed" : scanStatus === "cancelled" ? "Run Cancelled"
                : scanStatus === "unknown" ? "Outcome Unknown" : scanStatus === "verifying" ? "Checking Run Status" : scanStatus === "queued" ? "Discovery Run Queued" : "Scan Running"}
          </h2>
          <p role="status" style={{ color: "var(--dim)", fontSize: "14px", margin: "0 0 20px" }}>
            {scanJobId && <>Run ID: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{scanJobId}</code> · </>}
            Target: <code>{selectedTarget === "Network" || selectedTarget === "Cloud" || selectedTarget === "Container" ? targetInput : "authorized onboarding scope"}</code> · Status: {scanStatus}
          </p>

          {scanStatus === "completed" && resultNote && (
            <p style={{ fontSize: "13.5px", color: "var(--dim)", margin: "0 0 20px" }}>{resultNote}</p>
          )}

          {errorMsg && (
            <p role="alert" style={{ fontSize: "13.5px", color: "var(--danger, #e5484d)", margin: "0 0 20px" }}>
              {errorMsg}
            </p>
          )}

          {scanStatus === "completed" ? (
            <div style={{ display: "flex", justifyContent: "center", gap: "12px" }}>
              {selectedTarget === "Network" && <Link to="/assets" className="btn primary" style={{ textDecoration: "none" }}>
                Inspect Assets →
              </Link>}
              <button onClick={() => { reset(); setStep("select"); }} className="btn outline">
                Run Another Workflow
              </button>
            </div>
          ) : ["failed", "cancelled", "unknown"].includes(scanStatus) ? (
            <div style={{ display: "flex", justifyContent: "center", gap: "12px" }}>
              <button onClick={() => { reset(); setStep("configure"); }} className="btn outline">
                ← Adjust Target
              </button>
              <Link to="/onboarding" className="btn primary" style={{ textDecoration: "none" }}>
                Review Authorized Scope
              </Link>
            </div>
          ) : (
            <div style={{ fontSize: "13px", color: "var(--dim)" }}>
              {selectedTarget === "Network" ? "The server is performing the authorized active sweep." : "Waiting for this run's status record. No percentage is reported by this workflow."}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
