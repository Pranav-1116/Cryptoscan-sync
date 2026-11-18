import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { activeTenantId, getToken, tenantFetch } from "../lib/api";
import { IconNetwork, IconCloud, IconCode, IconContainer, IconHardware, IconCertificate, IconEstate, IconPass, IconTarget, ICON_LG, type Icon } from "../components/icons";
import { HBars, Meter, StateCell, VizEmpty } from "../components/viz";
import SurfaceCoverage from "../components/SurfaceCoverage.jsx";

type ScanTarget = "Network" | "Cloud" | "Source Repository" | "Container" | "Hardware" | "Certificate" | "Full Estate";
type ScanStatus = "verifying" | "queued" | "running" | "completed" | "failed" | "cancelled" | "unknown";
type Mode = "passive" | "active" | "registration";

const targets: { id: ScanTarget; label: string; desc: string; icon: Icon; available: boolean; reason?: string }[] = [
  { id: "Network", label: "Network Scanner", desc: "Authorized active CIDR sweep and TLS endpoint probes", icon: IconNetwork, available: true },
  { id: "Cloud", label: "Cloud KMS Scanner", desc: "IaC tree inspection with a durable per-run record (admission + coverage)", icon: IconCloud, available: true },
  { id: "Source Repository", label: "Source Repository AST", desc: "Queued source scan with a durable job record and an execution-time safety gate", icon: IconCode, available: true },
  { id: "Container", label: "Container Registry", desc: "Image/filesystem crypto inventory with a durable per-run record", icon: IconContainer, available: true },
  { id: "Hardware", label: "Hardware & HSM Fleet", desc: "HSM/KMS key-residence check with a durable per-run record (admission + coverage)", icon: IconHardware, available: true },
  { id: "Certificate", label: "Certificates & CT Logs", desc: "CT-log monitoring for rogue/new certificates with a durable per-run record", icon: IconCertificate, available: true },
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
  const [branchInput, setBranchInput] = useState("main");
  const [providerInput, setProviderInput] = useState("aws_kms");
  const [keyRefInput, setKeyRefInput] = useState("");
  const [mode, setMode] = useState<Mode>("passive");
  const [activeAuthorized, setActiveAuthorized] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [pollKind, setPollKind] = useState<"discovery" | "job" | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus>("queued");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [resultNote, setResultNote] = useState<string | null>(null);
  // What the run record itself reports about this run: its stage list, the
  // server's own stage count, and its timestamps. Nothing here is estimated by
  // the console — an absent field stays absent and renders as unobserved.
  const [jobProgress, setJobProgress] = useState<Record<string, unknown> | null>(null);
  const [jobTimes, setJobTimes] = useState<{ created_at: string | null; started_at: string | null; completed_at: string | null } | null>(null);
  const [requestedAt, setRequestedAt] = useState<string | null>(null);
  const [sweep, setSweep] = useState<{ hosts_checked: number | null; endpoints: string[] } | null>(null);
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
      if (event.key === "zelinx_signed_in" || event.key === "cryptoscan_tenant" || event.key === null) invalidate();
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
            created_at?: unknown; started_at?: unknown; completed_at?: unknown;
            progress?: {
              coverage?: Record<string, unknown>;
              admission?: { mode?: unknown };
              stages?: Array<{ name?: unknown; index?: unknown; state?: unknown }>;
              logs?: Array<{ ts?: unknown; stage?: unknown; level?: unknown; message?: unknown }>;
              percent?: unknown; total_stages?: unknown; stages_complete?: unknown;
              current_stage?: unknown;
            };
          };
          setJobTimes({
            created_at: typeof record.created_at === "string" ? record.created_at : null,
            started_at: typeof record.started_at === "string" ? record.started_at : null,
            completed_at: typeof record.completed_at === "string" ? record.completed_at : null,
          });
          if (record.progress && typeof record.progress === "object") {
            setJobProgress(record.progress as Record<string, unknown>);
          }
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
    setJobProgress(null);
    setJobTimes(null);
    setRequestedAt(null);
    setSweep(null);
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
    setRequestedAt(new Date().toISOString());
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
        setSweep({
          hosts_checked: typeof result.hosts_checked === "number" ? result.hosts_checked : null,
          endpoints: result.endpoints.filter((e): e is string => typeof e === "string"),
        });
        setResultNote(`Sweep finished${typeof result.hosts_checked === "number" ? `: ${result.hosts_checked} host(s) checked` : ""}; ${result.endpoints.length} open service endpoint(s) returned.`);
        setScanStatus("completed");
      } else if (selectedTarget === "Source Repository") {
        // Queued source scan: 202 + job_id, then this run's own /jobs/{id}
        // record. The worker's execution gate re-checks the safe-scan policy
        // and source-root containment at dequeue time.
        const res = await tenantFetch("/api/v1/scans/trigger", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repo_url: targetInput.trim(), branch: branchInput.trim() || "main" }),
          signal: AbortSignal.timeout(30000),
        });
        if (!sameSession()) return;
        const body = await readResponse(res);
        if (!sameSession()) return;
        if (!res.ok) { requestRefused = true; throw responseError(res, body); }
        const jobId = body && typeof body === "object" ? (body as { job_id?: unknown }).job_id : null;
        if (typeof jobId !== "string" || !jobId) {
          setScanStatus("unknown");
          setErrorMsg("Trigger accepted without a job ID; outcome unknown.");
          return;
        }
        setTrackedSession({ token, tenant });
        setPollKind("job");
        setScanJobId(jobId);
        const acceptedStatus = runStatus((body as { status?: unknown }).status);
        setScanStatus(acceptedStatus === "queued" || acceptedStatus === "running" ? acceptedStatus : "verifying");
      } else if (selectedTarget === "Cloud" || selectedTarget === "Container"
        || selectedTarget === "Hardware" || selectedTarget === "Certificate") {
        // Synchronous specialized scan, now with a durable run identity:
        // the server returns job_id and GET /jobs/{id} carries status,
        // the admission decision and bounded coverage for THIS run.
        const endpoint = selectedTarget === "Cloud" ? "/api/v1/cloud-scans"
          : selectedTarget === "Container" ? "/api/v1/container-scans"
          : selectedTarget === "Hardware" ? "/api/v1/hsm-scans"
          : "/api/v1/ct-scans";
        const payload = selectedTarget === "Cloud"
          ? { path: targetInput.trim(), live: false }
          : selectedTarget === "Container"
            ? { path: targetInput.trim(), live_cve: false }
            : selectedTarget === "Hardware"
              // submitted mode: attests collector-reported key attributes
              ? { keys: [{ key_ref: keyRefInput.trim(), provider: providerInput.trim() }], live: false }
              : { domains: targetInput.split(",").map((d) => d.trim()).filter(Boolean) };
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
      <Stepper step={step} />
      {step === "select" && (
        <div>
          <div style={{ marginBottom: "28px" }}>
            <span style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", textTransform: "uppercase", letterSpacing: "0.1em" }}>Discovery Workflow</span>
            <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "6px 0 8px" }}>New Scan</h1>
            <p style={{ margin: 0, fontSize: "14px", color: "var(--dim)" }}>
              Choose a workflow.
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
            {selectedTarget === "Source Repository" ? <>
            <div>
              <label htmlFor="repo-url" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Repository URL (local target must sit inside declared source roots)
              </label>
              <input id="repo-url" placeholder="/workspace/project or https://github.com/org/repo"
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
                The job is queued behind the central admission, and the worker re-checks the safe-scan policy and source-root containment again at execution — an emergency stop engaged after queuing still prevents the scan. Poll /jobs/{"{id}"} for this run's own status.
              </div>
            </div>
            <div>
              <label htmlFor="repo-branch" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Branch
              </label>
              <input id="repo-branch" placeholder="main"
                type="text"
                value={branchInput}
                onChange={(e) => setBranchInput(e.target.value)}
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
            </div>
            </> : selectedTarget === "Cloud" || selectedTarget === "Container" ? <>
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
            </> : selectedTarget === "Hardware" ? <>
            <div>
              <label htmlFor="hsm-provider" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Provider
              </label>
              <input id="hsm-provider" placeholder="aws_kms"
                type="text"
                value={providerInput}
                onChange={(e) => setProviderInput(e.target.value)}
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
            </div>
            <div>
              <label htmlFor="hsm-key-ref" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Key reference
              </label>
              <input id="hsm-key-ref" placeholder="arn:aws:kms:us-east-1:…:key/…"
                type="text"
                value={keyRefInput}
                onChange={(e) => setKeyRefInput(e.target.value)}
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
                Submitted mode — live verification needs CRYPTOSCAN_HSM_LIVE.
              </div>
            </div>
            </> : selectedTarget === "Certificate" ? <>
            <div>
              <label htmlFor="ct-domains" style={{ display: "block", fontSize: "12.5px", fontWeight: 600, marginBottom: "6px" }}>
                Monitored domains (comma-separated)
              </label>
              <input id="ct-domains" placeholder="api.example.com, internal.example.org"
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
                Polls public CT logs for the monitored domains and flags NEW (not in the known inventory) and ROGUE (issuer not on the approved list) certificates. The CT fetch is an outbound network read, admitted through the same safe-scan policy as every scan; a domain that cannot be checked is reported as an error, never folded into a green summary. This run leaves a durable job record under its run ID.
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
                CIDR is checked against your approved scope.
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
              <span title={"Registers onboarding scope and estimates assets. Requires a tested connector."}>{"Registers onboarding scope and estimates assets."}</span>
            </p>}
          </div>

          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <button onClick={() => setStep("select")} className="btn outline">
              ← Back
            </button>
            <button
              onClick={handleStartScan}
              disabled={(selectedTarget === "Network" && (mode !== "active" || !activeAuthorized || !targetInput.trim()))
                || ((selectedTarget === "Cloud" || selectedTarget === "Container" || selectedTarget === "Source Repository" || selectedTarget === "Certificate") && !targetInput.trim())
                || (selectedTarget === "Hardware" && !keyRefInput.trim())}
              className="btn primary"
            >
              {selectedTarget === "Network" ? "Start Authorized Sweep"
                : selectedTarget === "Cloud" ? "Start Cloud Scan"
                : selectedTarget === "Container" ? "Start Container Scan"
                : selectedTarget === "Source Repository" ? "Queue Source Scan"
                : selectedTarget === "Hardware" ? "Run HSM Key Check"
                : selectedTarget === "Certificate" ? "Run CT Monitor"
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
              : selectedTarget === "Source Repository" ? "Source Scan Complete"
              : selectedTarget === "Hardware" ? "HSM Key Check Complete"
              : selectedTarget === "Certificate" ? "CT Monitor Complete"
              : "Scope Registration Complete")
              : scanStatus === "failed" ? "Request Failed" : scanStatus === "cancelled" ? "Run Cancelled"
                : scanStatus === "unknown" ? "Outcome Unknown" : scanStatus === "verifying" ? "Checking Run Status" : scanStatus === "queued" ? (selectedTarget === "Source Repository" ? "Source Scan Queued" : "Discovery Run Queued") : "Scan Running"}
          </h2>
          <p role="status" style={{ color: "var(--dim)", fontSize: "14px", margin: "0 0 20px" }}>
            {scanJobId && <>Run ID: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{scanJobId}</code> · </>}
            Target: <code>{selectedTarget === "Hardware" ? `${providerInput}:${keyRefInput}` : selectedTarget === "Network" || selectedTarget === "Cloud" || selectedTarget === "Container" || selectedTarget === "Source Repository" || selectedTarget === "Certificate" ? targetInput : "authorized onboarding scope"}</code> · Status: {scanStatus}
          </p>

          {scanStatus === "completed" && resultNote && (
            <p style={{ fontSize: "13.5px", color: "var(--dim)", margin: "0 0 20px" }}>{resultNote}</p>
          )}

          {errorMsg && (
            <p role="alert" style={{ fontSize: "13.5px", color: "var(--danger, #e5484d)", margin: "0 0 20px" }}>
              {errorMsg}
            </p>
          )}

          <div style={{ textAlign: "left", margin: "0 0 20px" }}>
            <RunPhases
              requestedAt={requestedAt}
              created={jobTimes?.created_at ?? null}
              started={jobTimes?.started_at ?? null}
              completed={jobTimes?.completed_at ?? null}
              terminal={["completed", "failed", "cancelled"].includes(scanStatus)}
            />
            {jobProgress && <StagePipeline progress={jobProgress} />}
            {jobProgress && <RunCoverage progress={jobProgress} />}
            {sweep && <SweepResult sweep={sweep} />}
            {jobProgress && <RunLog progress={jobProgress} />}
          </div>

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

      {/* What this build can read, per crypto surface — the registry is echoed,
          never a coverage claim the console invents. */}
      <SurfaceCoverage />
    </div>
  );
}


/* ── workflow rail ─────────────────────────────────────────────────────────
   Three steps, and only the step the operator is on is marked current. The
   rail is a position indicator: it carries no progress percentage, because the
   run's own record is the only thing allowed to report one. */
function Stepper({ step }: { step: "select" | "configure" | "running" }) {
  const steps: Array<{ id: typeof step; label: string }> = [
    { id: "select", label: "Select workflow" },
    { id: "configure", label: "Target & safety" },
    { id: "running", label: "Run" },
  ];
  const current = steps.findIndex((item) => item.id === step);
  return (
    <div role="list" aria-label="Scan workflow progress" style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 22 }}>
      {steps.map((item, index) => {
        const done = index < current;
        const active = index === current;
        const color = done ? "var(--green)" : active ? "var(--accent)" : "var(--line-strong)";
        return (
          <React.Fragment key={item.id}>
            <div role="listitem" style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span
                aria-hidden
                style={{
                  width: 22,
                  height: 22,
                  display: "grid",
                  placeItems: "center",
                  borderRadius: 999,
                  border: `1px solid ${color}`,
                  background: active ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "transparent",
                  color: done ? "var(--green)" : active ? "var(--accent)" : "var(--faint)",
                  fontFamily: "var(--mono)",
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                {done ? "✓" : index + 1}
              </span>
              <span
                className="mono"
                style={{ fontSize: 11, letterSpacing: "0.05em", textTransform: "uppercase", color: active ? "var(--text)" : "var(--faint)" }}
                aria-current={active ? "step" : undefined}
              >
                {item.label}
              </span>
            </div>
            {index < steps.length - 1 && (
              <span aria-hidden style={{ flex: 1, height: 1, background: done ? "var(--green)" : "var(--line)", minWidth: 16 }} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

/* ── phase timing ─────────────────────────────────────────────────────────
   Two intervals the platform can actually timestamp: the wait between
   submission and the worker picking the job up, and the run itself. A phase
   the record does not timestamp is drawn as unknown, never as zero. */
function RunPhases({ requestedAt, created, started, completed, terminal }: {
  requestedAt: string | null;
  created: string | null;
  started: string | null;
  completed: string | null;
  terminal: boolean;
}) {
  const ms = (a: string | null, b: string | null): number | null => {
    if (!a || !b) return null;
    const from = new Date(a).getTime();
    const to = new Date(b).getTime();
    if (Number.isNaN(from) || Number.isNaN(to) || to < from) return null;
    return (to - from) / 1000;
  };
  const queued = ms(requestedAt, started);
  const run = ms(started, terminal ? completed : new Date().toISOString());
  const known = [queued, run].filter((v): v is number => v !== null);
  const max = Math.max(1, ...known);
  const rows: Array<{ key: string; label: string; value: number | null; tone: string }> = [
    { key: "queued", label: "submitted → worker start", value: queued, tone: "amber" },
    { key: "run", label: terminal ? "worker start → finish" : "worker start → now", value: run, tone: terminal ? "green" : "accent" },
  ];
  if (!known.length) {
    return (
      <div style={{ marginBottom: 12 }}>
        <VizEmpty
          title="No phase timing recorded"
          note="The run record has not returned its timestamps yet; nothing here is estimated."
          height={52}
        />
      </div>
    );
  }
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase", marginBottom: 6 }}>
        Run phases
      </div>
      {rows.map((row) => (
        <div key={row.key} style={{ display: "grid", gridTemplateColumns: "minmax(140px, 1fr) 2fr 62px", gap: 8, alignItems: "center", marginBottom: 5 }}>
          <span style={{ fontSize: 11.5, color: row.value === null ? "var(--faint)" : "var(--text)" }}>{row.label}</span>
          <span style={{ height: 6, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1, overflow: "hidden" }}>
            {row.value !== null && (
              <span style={{ display: "block", height: "100%", width: `${Math.max(2, (row.value / max) * 100)}%`, background: `var(--${row.tone})` }} />
            )}
          </span>
          <span className="mono" style={{ fontSize: 10.5, textAlign: "right", color: "var(--dim)", fontVariantNumeric: "tabular-nums" }}>
            {row.value === null ? "unknown" : `${row.value.toFixed(1)}s`}
          </span>
        </div>
      ))}
      <p style={{ margin: "4px 0 0", fontSize: 10, color: "var(--faint)" }}>
        <span title={"Timestamps come from the run record; the console adds no estimate."}>{"Timestamps come from the run record"}</span>  </p>
    </div>
  );
}

const STAGE_TONE: Record<string, string> = {
  COMPLETED: "green",
  RUNNING: "accent",
  PENDING: "slate",
  FAILED: "red",
  SKIPPED: "slate",
};

/* ── pipeline stages ──────────────────────────────────────────────────────
   The worker publishes the stage list and the stage count. Both are drawn as
   the server reported them; when the record carries a percent it is shown
   verbatim and labelled as the record's figure, not the console's. */
function StagePipeline({ progress }: { progress: Record<string, unknown> }) {
  const rawStages = Array.isArray(progress.stages) ? (progress.stages as Array<Record<string, unknown>>) : [];
  const stages = rawStages
    .map((stage, index) => ({
      name: typeof stage.name === "string" ? stage.name : `stage ${index + 1}`,
      index: typeof stage.index === "number" ? stage.index : index + 1,
      state: typeof stage.state === "string" ? stage.state.toUpperCase() : "PENDING",
    }))
    .sort((a, b) => a.index - b.index);
  const percent = typeof progress.percent === "number" && Number.isFinite(progress.percent) ? progress.percent : null;
  const complete = typeof progress.stages_complete === "number" ? progress.stages_complete : null;
  const total = typeof progress.total_stages === "number" ? progress.total_stages : stages.length;
  const current = typeof progress.current_stage === "string" ? progress.current_stage : null;

  if (!stages.length) {
    return (
      <div style={{ marginBottom: 12 }}>
        <VizEmpty
          title="No stage list in this run record"
          note="Synchronous scanner runs record a coverage summary instead of pipeline stages."
          height={52}
        />
      </div>
    );
  }

  return (
    <div style={{ marginBottom: 12 }}>
      <div className="spread" style={{ marginBottom: 6 }}>
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase" }}>
          Pipeline stages{current ? ` · ${current.replace(/_/g, " ")}` : ""}
        </span>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--dim)" }}>
          {percent !== null ? `${percent}% reported · ` : ""}
          {complete !== null ? `${complete}/${total} stages complete` : `${total} stages`}
        </span>
      </div>
      {percent !== null && <Meter value={percent} label="Stages complete (as reported by the run record)" tone="accent" />}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 8 }}>
        {stages.map((stage) => {
          const tone = STAGE_TONE[stage.state] ?? "slate";
          return (
            <span
              key={`${stage.index}-${stage.name}`}
              title={`${stage.index}. ${stage.name} — ${stage.state}`}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                fontFamily: "var(--mono)",
                fontSize: 10.5,
                padding: "2px 6px",
                borderRadius: 2,
                border: `1px solid ${tone === "accent" ? "var(--accent)" : tone === "slate" ? "var(--line)" : `var(--${tone})`}`,
                color: tone === "slate" ? "var(--faint)" : `var(--${tone})`,
                background: tone === "slate" ? "transparent" : `color-mix(in srgb, var(--${tone}) 10%, transparent)`,
              }}
            >
              <span aria-hidden style={{ width: 5, height: 5, borderRadius: 999, background: tone === "slate" ? "var(--line-strong)" : `var(--${tone})` }} />
              {stage.name.replace(/_/g, " ")}
            </span>
          );
        })}
      </div>
    </div>
  );
}

/* ── coverage counts from the run record ─────────────────────────────── */
function RunCoverage({ progress }: { progress: Record<string, unknown> }) {
  const coverage = progress.coverage;
  if (!coverage || typeof coverage !== "object" || Array.isArray(coverage)) return null;
  const rows = Object.entries(coverage as Record<string, unknown>)
    .map(([key, value]) => ({ key, label: key.replace(/_/g, " "), value: typeof value === "number" ? value : Number(value) }))
    .filter((row) => Number.isFinite(row.value) && row.value >= 0)
    .map((row) => ({ ...row, tone: "accent" }));
  if (!rows.length) return null;
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase", marginBottom: 6 }}>
        Coverage counts in this run
      </div>
      <HBars rows={rows} emptyTitle="No coverage count recorded" emptyNote="The run record carried no numeric coverage." />
      <p style={{ margin: "4px 0 0", fontSize: 10, color: "var(--faint)" }}>
        <span title={"Bar length is relative to the largest count in this run. These summarize the scan result; the findings live in the scanner's own surfaces."}>{"Bar length is relative to the largest count in this run."}</span>
      </p>
    </div>
  );
}

/* ── the run's own log ───────────────────────────────────────────────── */
function RunLog({ progress }: { progress: Record<string, unknown> }) {
  const raw = Array.isArray(progress.logs) ? (progress.logs as Array<Record<string, unknown>>) : [];
  const lines = raw.map((line) => ({
    ts: typeof line.ts === "string" ? line.ts : "",
    stage: typeof line.stage === "string" ? line.stage : "",
    level: typeof line.level === "string" ? line.level.toUpperCase() : "INFO",
    message: typeof line.message === "string" ? line.message : "",
  }));
  if (!lines.length) {
    return (
      <div style={{ marginBottom: 12 }}>
        <VizEmpty
          title="No run log yet"
          note="The worker appends one entry per stage; an empty log means no stage has reported."
          height={48}
        />
      </div>
    );
  }
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="spread" style={{ marginBottom: 6 }}>
        <span className="mono" style={{ fontSize: 10, letterSpacing: "0.08em", color: "var(--faint)", textTransform: "uppercase" }}>
          Run log
        </span>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--dim)" }}>{lines.length} entr{lines.length === 1 ? "y" : "ies"}</span>
      </div>
      <div style={{ maxHeight: 200, overflowY: "auto", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel-2)" }}>
        {lines.map((line, index) => (
          <div
            key={`${line.ts}-${index}`}
            style={{ display: "grid", gridTemplateColumns: "58px 96px 40px 1fr", gap: 8, padding: "4px 8px", borderTop: index ? "1px solid var(--line)" : undefined, alignItems: "baseline" }}
          >
            <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
              {line.ts ? new Date(line.ts).toLocaleTimeString() : "—"}
            </span>
            <span className="mono" style={{ fontSize: 10, color: "var(--dim)", overflow: "hidden", textOverflow: "ellipsis" }}>
              {line.stage.replace(/_/g, " ")}
            </span>
            <span className="mono" style={{ fontSize: 9.5, color: line.level === "ERROR" ? "var(--red)" : "var(--green)" }}>{line.level}</span>
            <span style={{ fontSize: 11, color: line.level === "ERROR" ? "var(--red)" : "var(--text)", overflowWrap: "anywhere" }}>{line.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── active sweep result ──────────────────────────────────────────────────
   The sweep returns individual open endpoints. Grouping them by port is the
   one thing an operator needs first; the count of endpoints that did not carry
   a parseable port is shown rather than dropped. */
function SweepResult({ sweep }: { sweep: { hosts_checked: number | null; endpoints: string[] } }) {
  const byPort = new Map<string, number>();
  let unparsed = 0;
  for (const endpoint of sweep.endpoints) {
    const match = /:(\d+)$/.exec(endpoint);
    if (match) byPort.set(match[1], (byPort.get(match[1]) ?? 0) + 1);
    else unparsed += 1;
  }
  const rows = [...byPort.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([port, value]) => ({ key: port, label: `port ${port}`, value, tone: "cyan" }));
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 8, marginBottom: 8 }}>
        <StateCell label="Hosts checked" value={sweep.hosts_checked ?? "—"} tone="accent" note="from the sweep response" />
        <StateCell label="Open endpoints" value={sweep.endpoints.length} tone={sweep.endpoints.length ? "amber" : "green"} note="services that answered" />
        <StateCell label="No port parsed" value={unparsed} tone={unparsed ? "slate" : "green"} note="kept out of the port chart" />
      </div>
      <HBars rows={rows} emptyTitle="No open endpoint listed" emptyNote="The sweep returned no endpoint with a port." />
    </div>
  );
}
