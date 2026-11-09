import React, { useCallback, useState } from "react";
import { Donut, HBars, FlowStrip, Meter } from "../components/viz";
import { Badge, Panel, PageHead } from "../components/ui";
import {
  apiBinaryArtifactScan, apiBinaryBom, apiBinaryComparison,
  apiBinaryCoverage, apiBinaryDrift, apiBinaryEstate, apiBinaryFindings,
  apiBinaryFirmwareScan, apiBinaryHistory,
  type BinaryDriftSeries, type BinaryEstate, type BinaryFirmwareReport,
  type BinaryHistory,
  type ApiResult, type BinaryBom, type BinaryComparison,
  type BinaryCoverage, type BinaryFinding, type BinaryScanResult,
} from "../lib/api.js";

/* Binary Intelligence (docs/binary-intelligence/01_PRODUCT_SPEC.md §16):
   a cryptographic threat-intelligence console — not an AI chatbot, no
   gradients, no glow, no assistant panel. The honesty rules are display
   rules: an unknown key size renders "unknown"; a function reference is
   not proof of runtime use; 'not detected' is never 'absent'; every
   comparison delta carries its caveat; relationships carry provenance. */

type View =
  | "submit" | "analysis" | "findings" | "pqc" | "evidence"
  | "comparison" | "coverage" | "twin" | "drift" | "history" | "estate"
  | "firmware";

const VIEWS: Array<{ key: View; label: string }> = [
  { key: "submit", label: "Artifact Inventory & Scan" },
  { key: "analysis", label: "Binary Analysis" },
  { key: "findings", label: "Crypto Findings" },
  { key: "pqc", label: "PQC Exposure" },
  { key: "evidence", label: "Evidence Viewer" },
  { key: "comparison", label: "Version Comparison" },
  { key: "coverage", label: "Coverage" },
  { key: "twin", label: "Digital Twin" },
  { key: "drift", label: "Drift Series" },
  { key: "history", label: "History" },
  { key: "estate", label: "Estate View" },
  { key: "firmware", label: "Firmware" },
];

const CONTROL_STYLE: React.CSSProperties = {
  background: "transparent", color: "inherit", border: "1px solid var(--rule)",
  borderRadius: 6, padding: "5px 8px", fontSize: 12, fontFamily: "var(--mono)",
};

function ReadFailed({ error, detail }: { error: string; detail?: string }) {
  return (
    <Panel title="Read failed">
      <p style={{ margin: 0, fontSize: 12, color: "var(--muted)" }}>
        {error}{detail ? ` — ${detail}` : ""}. This page reports the failure
        and never prints zeros in its place.
      </p>
    </Panel>
  );
}

function KeySize({ bits }: { bits: number | null }) {
  if (bits === null || bits === undefined) {
    return (
      <span title="the evidence did not establish a key size — unknown, never guessed">
        <span style={{ fontFamily: "var(--mono)" }}>unknown</span>
        <span style={{ marginLeft: 6, color: "var(--muted)", fontSize: 11 }}>
          (never guessed)
        </span>
      </span>
    );
  }
  return (
    <span>
      <span style={{ fontFamily: "var(--mono)" }}>{bits}</span>
      <span style={{ marginLeft: 4, color: "var(--muted)", fontSize: 11 }}>bits</span>
    </span>
  );
}

function FindingRow({ finding, onEvidence }: {
  finding: BinaryFinding & { evidence?: Array<{ type: string; location: string; description: string; excerpt: string }> };
  onEvidence?: () => void;
}) {
  const tone = finding.confidence === "not_detected" ? "gray"
    : finding.confidence === "strongly_supported" || finding.confidence === "observed" ? "green"
    : finding.confidence === "indicated" ? "amber" : "gray";
  return (
    <tr>
      <td style={{ padding: "6px 8px", fontSize: 12 }}>
        <span style={{ fontFamily: "var(--mono)" }}>
          {finding.finding_type === "cryptographic_library"
            ? finding.library
            : [finding.algorithm, finding.variant].filter(Boolean).join(" · ") || "—"}
        </span>
        {finding.operation ? (
          <span style={{ marginLeft: 6, color: "var(--muted)", fontSize: 11 }}>
            {finding.operation}
          </span>
        ) : null}
      </td>
      <td style={{ padding: "6px 8px", fontSize: 12 }}>
        <Badge tone={tone}>{finding.confidence}</Badge>
      </td>
      <td style={{ padding: "6px 8px", fontSize: 12, fontFamily: "var(--mono)" }}>
        {finding.usage_status}
      </td>
      <td style={{ padding: "6px 8px", fontSize: 12 }}>
        <KeySize bits={finding.key_size_bits} />
      </td>
      <td style={{ padding: "6px 8px", fontSize: 11, color: "var(--muted)" }}>
        {finding.runtime_confirmed
          ? "runtime confirmed"
          : "static evidence only — not proof of runtime use (§5)"}
        {(finding.limitations ?? []).slice(0, 1).map((l) => (
          <div key={l} style={{ fontStyle: "italic", marginTop: 2 }}>{l}</div>
        ))}
        {onEvidence ? (
          <button
            onClick={onEvidence}
            style={{ ...CONTROL_STYLE, marginLeft: 8, cursor: "pointer" }}
          >
            evidence ({finding.evidence?.length ?? 0})
          </button>
        ) : null}
      </td>
    </tr>
  );
}

export default function Binary() {
  const [view, setView] = useState<View>("submit");
  const [tenant, setTenant] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const [againstId, setAgainstId] = useState("");
  const [filename, setFilename] = useState("payments-engine");
  const [profile, setProfile] = useState("standard");
  const [busy, setBusy] = useState(false);
  const [scan, setScan] = useState<BinaryScanResult | null>(null);
  const [findings, setFindings] = useState<ApiResult<{ findings: Array<BinaryFinding & { evidence: Array<{ type: string; location: string; description: string; excerpt: string }> }>; note: string }> | null>(null);
  const [coverage, setCoverage] = useState<ApiResult<BinaryCoverage> | null>(null);
  const [bom, setBom] = useState<ApiResult<{ bom: BinaryBom; note: string }> | null>(null);
  const [comparison, setComparison] = useState<ApiResult<BinaryComparison> | null>(null);
  const [drift, setDrift] = useState<ApiResult<BinaryDriftSeries> | null>(null);
  const [history, setHistory] = useState<ApiResult<BinaryHistory> | null>(null);
  const [estate, setEstate] = useState<ApiResult<BinaryEstate> | null>(null);
  const [subject, setSubject] = useState("");
  const [firmware, setFirmware] = useState<ApiResult<BinaryFirmwareReport> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<BinaryFinding | null>(null);

  const submitScan = useCallback(async (file: File | null) => {
    if (!tenant || !file) return;
    setBusy(true);
    setError(null);
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      }
      const result = await apiBinaryArtifactScan({
        tenant_id: tenant,
        artifact_base64: btoa(binary),
        original_filename: file.name || filename,
        source_type: "upload",
        scan_profile: profile,
      });
      if (result.data === null) {
        setError(result.error || "scan refused");
      } else {
        setScan(result.data);
        setArtifactId(result.data.artifact.artifact_id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "scan failed");
    } finally {
      setBusy(false);
    }
  }, [tenant, filename, profile]);

  const loadFindings = useCallback(async () => {
    if (!tenant || !artifactId) return;
    setBusy(true);
    setFindings(await apiBinaryFindings(artifactId, { tenant_id: tenant }));
    setBusy(false);
  }, [tenant, artifactId]);

  const loadCoverage = useCallback(async () => {
    if (!tenant || !artifactId) return;
    setBusy(true);
    setCoverage(await apiBinaryCoverage(artifactId, { tenant_id: tenant }));
    setBusy(false);
  }, [tenant, artifactId]);

  const loadBom = useCallback(async () => {
    if (!tenant || !artifactId) return;
    setBusy(true);
    setBom(await apiBinaryBom(artifactId, { tenant_id: tenant }));
    setBusy(false);
  }, [tenant, artifactId]);

  const loadComparison = useCallback(async () => {
    if (!tenant || !artifactId || !againstId) return;
    setBusy(true);
    setComparison(await apiBinaryComparison(artifactId, {
      tenant_id: tenant, against_artifact_id: againstId,
    }));
    setBusy(false);
  }, [tenant, artifactId, againstId]);

  const loadDrift = useCallback(async () => {
    if (!tenant) return;
    setBusy(true);
    setDrift(await apiBinaryDrift({ tenant_id: tenant, subject: subject || undefined }));
    setBusy(false);
  }, [tenant, subject]);

  const loadHistory = useCallback(async () => {
    if (!tenant || !artifactId) return;
    setBusy(true);
    setHistory(await apiBinaryHistory(artifactId, { tenant_id: tenant }));
    setBusy(false);
  }, [tenant, artifactId]);

  const loadEstate = useCallback(async () => {
    if (!tenant) return;
    setBusy(true);
    setEstate(await apiBinaryEstate({ tenant_id: tenant }));
    setBusy(false);
  }, [tenant]);

  return (
    <div data-page="binary" style={{ padding: 16 }}>
      <PageHead
        crumb="Intelligence"
        title="Binary Intelligence"
        sub="Binary Intelligence — evidence-backed cryptographic discovery from compiled artifacts. Static analysis only: submitted artifacts are never executed."
      />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        <label style={{ fontSize: 11, color: "var(--muted)" }}>
          Tenant{" "}
          <input
            aria-label="Tenant"
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
            style={CONTROL_STYLE}
            placeholder="tenant_001"
          />
        </label>
        <label style={{ fontSize: 11, color: "var(--muted)" }}>
          Artifact{" "}
          <input
            aria-label="Artifact"
            value={artifactId}
            onChange={(e) => setArtifactId(e.target.value)}
            style={CONTROL_STYLE}
            placeholder="bin-..."
          />
        </label>
        {VIEWS.map((entry) => (
          <button
            key={entry.key}
            onClick={() => setView(entry.key)}
            disabled={!tenant}
            style={{
              ...CONTROL_STYLE,
              cursor: tenant ? "pointer" : "not-allowed",
              borderColor: view === entry.key ? "var(--accent)" : "var(--rule)",
            }}
          >
            {entry.label}
          </button>
        ))}
      </div>

      {error ? <ReadFailed error={error} /> : null}

      {view === "submit" ? (
        <Panel title="Artifact Inventory & Scan">
          <p style={{ marginTop: 0, fontSize: 12, color: "var(--muted)" }}>
            Every submitted artifact is identified by content and an immutable
            SHA-256 digest — a file extension is only a hint. The artifact is
            validated and analyzed statically; it is never executed (§14).
          </p>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <label style={{ fontSize: 11, color: "var(--muted)" }}>
              File{" "}
              <input
                type="file"
                aria-label="Artifact file"
                disabled={!tenant || busy}
                onChange={(e) => void submitScan(e.target.files?.[0] ?? null)}
              />
            </label>
            <label style={{ fontSize: 11, color: "var(--muted)" }}>
              Profile{" "}
              <select
                aria-label="Scan profile"
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                style={CONTROL_STYLE}
              >
                <option value="quick">quick</option>
                <option value="standard">standard</option>
                <option value="deep">deep</option>
              </select>
            </label>
          </div>
          {scan ? (
            <div style={{ marginTop: 12, display: "grid", gap: 8 }}>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>
                    {scan.artifact.detected_format}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>
                    format from content — {scan.artifact.format_reason}
                  </div>
                </div>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>
                    {scan.finding_count}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>crypto findings</div>
                </div>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 14 }}>
                    {scan.artifact.sha256.slice(0, 16)}…
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>
                    SHA-256 identity (immutable)
                  </div>
                </div>
              </div>
              <div style={{ fontSize: 11, color: "var(--muted)" }}>
                {scan.notes.join(" · ")}
              </div>
              {scan.private_key_events.length > 0 ? (
                <div style={{ fontSize: 12 }}>
                  <Badge tone="amber">{scan.private_key_events.length} private-key detection event(s)</Badge>
                  <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                    presence and location recorded only — contents are never
                    exported, displayed or stored as findings (§6)
                  </span>
                </div>
              ) : null}
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "analysis" && scan ? (
        <Panel title="Binary Analysis">
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
            <FlowStrip
              label="analysis pipeline"
              stages={[
                { label: "ingest", state: "done", note: "artifact received and hashed" },
                { label: "identify", state: "done", note: `format from content: ${scan.artifact.detected_format}` },
                { label: "static analysis", state: "done", note: "analyzed statically; never executed (§14)" },
                {
                  label: "crypto detect",
                  state: scan.finding_count > 0 ? "done" : "done",
                  note: `${scan.finding_count} finding(s)`,
                },
                {
                  label: "private-key scan",
                  state: scan.private_key_events.length > 0 ? "done" : "done",
                  note:
                    scan.private_key_events.length > 0
                      ? `${scan.private_key_events.length} detection event(s) — presence only (§6)`
                      : "no detection events",
                },
              ]}
            />
          </div>
          <div style={{ maxWidth: 360, marginBottom: 12 }}>
            {scan.coverage.sections_total > 0 ? (
              <Meter
                value={Math.round((scan.coverage.sections_inspected / scan.coverage.sections_total) * 100)}
                label="sections inspected"
                tone={scan.coverage.sections_inspected >= scan.coverage.sections_total ? "green" : "amber"}
                note={`${scan.coverage.sections_inspected} of ${scan.coverage.sections_total} sections`}
              />
            ) : (
              <p style={{ fontSize: 11, color: "var(--muted)", margin: 0 }}>
                section coverage unknown — never assumed complete
              </p>
            )}
          </div>
          <div style={{ display: "grid", gap: 8, fontSize: 12 }}>
            <div>
              <span style={{ color: "var(--muted)" }}>Format: </span>
              <span style={{ fontFamily: "var(--mono)" }}>{scan.artifact.detected_format}</span>
              <span style={{ marginLeft: 8, color: "var(--muted)" }}>{scan.artifact.format_reason}</span>
            </div>
            <div>
              <span style={{ color: "var(--muted)" }}>Size: </span>
              <span style={{ fontFamily: "var(--mono)" }}>{scan.artifact.file_size}</span>
              <span style={{ marginLeft: 4, color: "var(--muted)", fontSize: 11 }}>bytes</span>
            </div>
            <div>
              <span style={{ color: "var(--muted)" }}>Sections inspected: </span>
              <span style={{ fontFamily: "var(--mono)" }}>{scan.coverage.sections_inspected}</span>
              <span style={{ marginLeft: 4, color: "var(--muted)", fontSize: 11 }}>of {scan.coverage.sections_total}</span>
            </div>
            <div>
              <span style={{ color: "var(--muted)" }}>Symbols: </span>
              <span style={{ fontFamily: "var(--mono)" }}>{scan.coverage.symbols_found}</span>
              {scan.coverage.symbols_stripped ? (
                <span style={{ marginLeft: 8 }}><Badge tone="amber">stripped</Badge></span>
              ) : null}
            </div>
            {scan.certificates.length > 0 ? (
              <div>
                <span style={{ color: "var(--muted)" }}>Certificates: </span>
                <span style={{ fontFamily: "var(--mono)" }}>{scan.certificates.length}</span>
              </div>
            ) : null}
          </div>
        </Panel>
      ) : null}

      {view === "findings" ? (
        <Panel title="Crypto Findings">
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadFindings()}
              disabled={!tenant || !artifactId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load findings
            </button>
          </div>
          {findings && findings.data === null ? (
            <ReadFailed error={findings.error || "read failed"} detail={findings.detail} />
          ) : null}
          {findings?.data ? (
            <div>
              <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center", margin: "4px 0 12px" }}>
                {findings.data.findings.length > 0 ? (
                  <>
                    <Donut
                      size={108}
                      segments={Object.entries(
                        findings.data.findings.reduce<Record<string, number>>((acc, f) => {
                          acc[f.algorithm] = (acc[f.algorithm] ?? 0) + 1;
                          return acc;
                        }, {}),
                      ).map(([label, value], i) => ({
                        label,
                        value,
                        tone: ["orange", "amber", "violet", "accent", "green", "red", "slate"][i % 7],
                      }))}
                      centerLabel={findings.data.findings.length}
                      centerSub="findings"
                    />
                    <div style={{ flex: 1, minWidth: 220, maxWidth: 380 }}>
                      <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--muted)", marginBottom: 6 }}>
                        BY FINDING TYPE
                      </div>
                      <HBars
                        rows={Object.entries(
                          findings.data.findings.reduce<Record<string, number>>((acc, f) => {
                            acc[f.finding_type] = (acc[f.finding_type] ?? 0) + 1;
                            return acc;
                          }, {}),
                        ).map(([label, value]) => ({ key: label, label, value, tone: "accent" }))}
                        emptyTitle="no finding types"
                        emptyNote="a finding is a detection, never a verdict"
                      />
                    </div>
                  </>
                ) : (
                  <p style={{ fontSize: 11, color: "var(--muted)", margin: 0 }}>
                    no crypto findings — a detection count of zero is never a
                    clean verdict
                  </p>
                )}
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Finding", "Evidence class", "Usage status", "Key size", "Limits"].map((h) => (
                      <th key={h} style={{ textAlign: "left", padding: "6px 8px", fontSize: 11, color: "var(--muted)", borderBottom: "1px solid var(--rule)" }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {findings.data.findings.map((f) => (
                    <FindingRow
                      key={f.finding_id}
                      finding={f}
                      onEvidence={() => setSelectedEvidence(f)}
                    />
                  ))}
                </tbody>
              </table>
              <p style={{ fontSize: 11, color: "var(--muted)" }}>
                {findings.data.note}
              </p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "pqc" ? (
        <Panel title="PQC Exposure">
          <p style={{ marginTop: 0, fontSize: 12, color: "var(--muted)" }}>
            Quantum-vulnerable indicators, PQC implementation indicators and
            migration blockers — reported separately. Presence is not usage,
            and a classical algorithm is not automatically an immediate
            vulnerability (§9).
          </p>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadFindings()}
              disabled={!tenant || !artifactId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              assess exposure
            </button>
          </div>
          {findings?.data ? (
            <div style={{ display: "grid", gap: 8, fontSize: 12 }}>
              <div>
                <span style={{ color: "var(--muted)" }}>Quantum-vulnerable indicators: </span>
                <Badge tone={findings.data.findings.some((f) => f.quantum_vulnerable) ? "amber" : "gray"}>
                  {findings.data.findings.some((f) => f.quantum_vulnerable) ? "Detected" : "Not detected"}
                </Badge>
                <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                  within the analyzed scope — not detected is never absent
                </span>
              </div>
              <div>
                <span style={{ color: "var(--muted)" }}>PQC implementation indicators: </span>
                <Badge tone={findings.data.findings.some((f) => f.pqc_family) ? "green" : "gray"}>
                  {findings.data.findings.some((f) => f.pqc_family) ? "Detected" : "Not detected"}
                </Badge>
                <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                  presence is not usage — may be unused library functionality
                </span>
              </div>
              <div>
                <span style={{ color: "var(--muted)" }}>Migration readiness: </span>
                <Badge tone="gray">Not established</Badge>
                <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                  readiness requires source, vendor and runtime evidence a
                  static scan cannot provide
                </span>
              </div>
              <ul style={{ fontSize: 12, color: "var(--muted)" }}>
                {findings.data.findings
                  .filter((f) => f.quantum_vulnerable || f.pqc_family)
                  .map((f) => (
                    <li key={f.finding_id}>
                      {[f.algorithm, f.variant].filter(Boolean).join(" · ")}
                      {" — "}
                      {f.confidence}, {f.usage_status}
                    </li>
                  ))}
              </ul>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "evidence" ? (
        <Panel title="Evidence Viewer">
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadFindings()}
              disabled={!tenant || !artifactId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load evidence
            </button>
          </div>
          {findings?.data ? (
            <div style={{ display: "grid", gap: 10 }}>
              {findings.data.findings.map((f) => (
                <div key={f.finding_id} style={{ borderTop: "1px solid var(--rule)", paddingTop: 8 }}>
                  <div style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                    {[f.algorithm, f.variant].filter(Boolean).join(" · ") || f.library || f.finding_type}
                    <span style={{ marginLeft: 8 }}><Badge tone="gray">{f.confidence}</Badge></span>
                  </div>
                  {(f.evidence ?? []).map((e, i) => (
                    <div key={i} style={{ fontSize: 11, color: "var(--muted)", marginLeft: 12, marginTop: 4 }}>
                      <span style={{ fontFamily: "var(--mono)" }}>{e.type}</span>
                      {" at "}
                      <span style={{ fontFamily: "var(--mono)" }}>{e.location}</span>
                      {" — "}
                      {e.description}
                    </div>
                  ))}
                  {f.limitations.map((l, i) => (
                    <div key={`l${i}`} style={{ fontSize: 11, color: "var(--muted)", marginLeft: 12, fontStyle: "italic" }}>
                      limitation: {l}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "comparison" ? (
        <Panel title="Version Comparison">
          <div style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
            <label style={{ fontSize: 11, color: "var(--muted)" }}>
              Against{" "}
              <input
                aria-label="Against"
                value={againstId}
                onChange={(e) => setAgainstId(e.target.value)}
                style={CONTROL_STYLE}
                placeholder="bin-..."
              />
            </label>
            <button
              onClick={() => void loadComparison()}
              disabled={!tenant || !artifactId || !againstId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              compare
            </button>
          </div>
          {comparison && comparison.data === null ? (
            <ReadFailed error={comparison.error || "read failed"} detail={comparison.detail} />
          ) : null}
          {comparison?.data ? (
            <div>
              <div style={{ display: "flex", gap: 16, marginBottom: 8, flexWrap: "wrap" }}>
                {Object.entries(comparison.data.summary).map(([k, v]) => (
                  <div key={k}>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>{v}</div>
                    <div style={{ fontSize: 11, color: "var(--muted)" }}>{k}</div>
                  </div>
                ))}
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <tbody>
                  {comparison.data.deltas.filter((d) => d.change !== "unchanged").map((d, i) => (
                    <tr key={i}>
                      <td style={{ padding: "6px 8px", fontSize: 12 }}>
                        <Badge tone={d.change === "added" ? "green" : d.change === "removed" ? "amber" : "gray"}>
                          {d.change}
                        </Badge>
                      </td>
                      <td style={{ padding: "6px 8px", fontSize: 12, fontFamily: "var(--mono)" }}>
                        {[d.algorithm, d.variant].filter(Boolean).join(" · ")}
                      </td>
                      <td style={{ padding: "6px 8px", fontSize: 11, color: "var(--muted)" }}>
                        {d.detail}
                        <div style={{ fontStyle: "italic" }}>{d.caveat}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p style={{ fontSize: 11, color: "var(--muted)" }}>{comparison.data.note}</p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "coverage" ? (
        <Panel title="Coverage">
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadCoverage()}
              disabled={!tenant || !artifactId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load coverage
            </button>
          </div>
          {coverage && coverage.data === null ? (
            <ReadFailed error={coverage.error || "read failed"} detail={coverage.detail} />
          ) : null}
          {coverage?.data ? (
            <div style={{ display: "grid", gap: 8, fontSize: 12 }}>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>
                    {Math.round(coverage.data.coverage_fraction * 100)}
                    <span style={{ fontSize: 12, marginLeft: 2 }}>%</span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>
                    bytes inspected ({coverage.data.bytes_inspected} of {coverage.data.total_bytes})
                  </div>
                </div>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>
                    {coverage.data.symbols_found}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>recognized symbols</div>
                </div>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>
                    {coverage.data.unresolved_dependencies.length}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>unresolved dependencies</div>
                </div>
              </div>
              {coverage.data.symbols_stripped ? (
                <div><Badge tone="amber">symbols stripped</Badge>
                  <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                    detection relies on imports and strings; absence of a
                    finding is not proof of absence
                  </span>
                </div>
              ) : null}
              <p style={{ fontSize: 11, color: "var(--muted)", fontStyle: "italic" }}>
                {coverage.data.note}
              </p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "drift" ? (
        <Panel title="Drift Series">
          <p style={{ marginTop: 0, fontSize: 12, color: "var(--muted)" }}>
            Artifacts grouped by subject (filename / source location),
            compared consecutively — drift of static INDICATORS, never
            drift of runtime behavior; every delta carries its caveat.
          </p>
          <div style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center" }}>
            <label style={{ fontSize: 11, color: "var(--muted)" }}>
              Subject{" "}
              <input
                aria-label="Subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                style={CONTROL_STYLE}
                placeholder="payments-engine"
              />
            </label>
            <button
              onClick={() => void loadDrift()}
              disabled={!tenant || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load series
            </button>
          </div>
          {drift && drift.data === null ? (
            <ReadFailed error={drift.error || "read failed"} detail={drift.detail} />
          ) : null}
          {drift?.data ? (
            <div>
              <div style={{ display: "flex", gap: 16, marginBottom: 8, flexWrap: "wrap" }}>
                {Object.entries(drift.data.summary).map(([k, v]) => (
                  <div key={k}>
                    <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>{v}</div>
                    <div style={{ fontSize: 11, color: "var(--muted)" }}>{k}</div>
                  </div>
                ))}
              </div>
              {drift.data.points.map((point) => (
                <div key={point.artifact_id} style={{ borderTop: "1px solid var(--rule)", paddingTop: 8, marginTop: 8 }}>
                  <div style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                    {point.artifact_id}
                    <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                      {point.detected_format} · {point.received_at ?? "unknown time"} · {point.scan_count} scan(s)
                    </span>
                  </div>
                  {point.delta_vs_previous === null ? (
                    <div style={{ fontSize: 11, color: "var(--muted)", fontStyle: "italic", marginLeft: 12 }}>
                      the first version has no predecessor to compare
                    </div>
                  ) : (
                    (point.delta_vs_previous.deltas ?? [])
                      .filter((d) => d.change !== "unchanged")
                      .map((d, i) => (
                        <div key={i} style={{ fontSize: 11, marginLeft: 12, marginTop: 4 }}>
                          <Badge tone={d.change === "added" ? "green" : d.change === "removed" ? "amber" : "gray"}>
                            {d.change}
                          </Badge>
                          <span style={{ fontFamily: "var(--mono)", marginLeft: 8 }}>
                            {[d.algorithm, d.variant].filter(Boolean).join(" · ")}
                          </span>
                          <div style={{ color: "var(--muted)", fontStyle: "italic" }}>{d.caveat}</div>
                        </div>
                      ))
                  )}
                </div>
              ))}
              {drift.data.points.length === 0 ? (
                <p style={{ fontSize: 12, color: "var(--muted)" }}>
                  no artifacts in this series — empty, never zero-filled with guesses
                </p>
              ) : null}
              <p style={{ fontSize: 11, color: "var(--muted)", fontStyle: "italic" }}>
                {drift.data.limitations.join(" · ")}
              </p>
              <p style={{ fontSize: 11, color: "var(--muted)" }}>{drift.data.note}</p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "history" ? (
        <Panel title="History — one immutable artifact">
          <p style={{ marginTop: 0, fontSize: 12, color: "var(--muted)" }}>
            How findings moved across scan runs of ONE immutable artifact —
            a change between runs is a change of scanner, profile or
            signature database, never of the artifact.
          </p>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadHistory()}
              disabled={!tenant || !artifactId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load history
            </button>
          </div>
          {history && history.data === null ? (
            <ReadFailed error={history.error || "read failed"} detail={history.detail} />
          ) : null}
          {history?.data ? (
            <div>
              <div style={{ fontSize: 12, marginBottom: 8 }}>
                <span style={{ color: "var(--muted)" }}>Runs: </span>
                <span style={{ fontFamily: "var(--mono)" }}>{history.data.runs.length}</span>
                <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                  {(history.data.runs as Array<Record<string, string>>)
                    .map((r) => r.scan_profile).join(", ")}
                </span>
              </div>
              {history.data.finding_timeline.map((entry) => (
                <div key={`${entry.algorithm}-${entry.variant}`}
                     style={{ borderTop: "1px solid var(--rule)", paddingTop: 8, marginTop: 8 }}>
                  <div style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                    {[entry.algorithm, entry.variant].filter(Boolean).join(" · ") || entry.finding_type}
                    <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                      first seen {entry.first_seen ?? "unknown"} ({entry.first_scan}) ·
                      last seen {entry.last_seen ?? "unknown"} ({entry.last_scan})
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)", marginLeft: 12 }}>
                    {entry.observations.length} observation(s) across runs —
                    evidence class per run:{" "}
                    {(entry.observations as Array<Record<string, string>>)
                      .map((o) => o.evidence_class).join(", ")}
                  </div>
                </div>
              ))}
              <p style={{ fontSize: 11, color: "var(--muted)", fontStyle: "italic" }}>
                {history.data.limitations.join(" · ")}
              </p>
              <p style={{ fontSize: 11, color: "var(--muted)" }}>{history.data.note}</p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "estate" ? (
        <Panel title="Estate View — recorded findings">
          <p style={{ marginTop: 0, fontSize: 12, color: "var(--muted)" }}>
            Findings grouped by format, source, library and algorithm.
            Counts are counts of RECORDED findings, never of running
            cryptography; grouping is metadata, not proof of common origin.
          </p>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadEstate()}
              disabled={!tenant || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load estate
            </button>
          </div>
          {estate && estate.data === null ? (
            <ReadFailed error={estate.error || "read failed"} detail={estate.detail} />
          ) : null}
          {estate?.data ? (
            <div>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 8 }}>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>{estate.data.findings_total}</div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>recorded findings</div>
                </div>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>{estate.data.quantum_vulnerable_findings}</div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>quantum-vulnerable indicators</div>
                </div>
                <div>
                  <div style={{ fontFamily: "var(--mono)", fontSize: 18 }}>{estate.data.pqc_family_findings}</div>
                  <div style={{ fontSize: 11, color: "var(--muted)" }}>PQC indicators</div>
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
                {([
                  ["by_format", "Format"],
                  ["by_source_type", "Source"],
                  ["by_library", "Library"],
                  ["by_algorithm", "Algorithm"],
                ] as const).map(([key, label]) => (
                  <div key={key}>
                    <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 4 }}>{label}</div>
                    {Object.entries(estate.data![key]).map(([name, count]) => (
                      <div key={name} style={{ fontSize: 12, display: "flex", justifyContent: "space-between" }}>
                        <span style={{ fontFamily: "var(--mono)" }}>{name}</span>
                        <span style={{ fontFamily: "var(--mono)", color: "var(--muted)" }}>{count}</span>
                      </div>
                    ))}
                    {Object.keys(estate.data![key]).length === 0 ? (
                      <div style={{ fontSize: 11, color: "var(--muted)", fontStyle: "italic" }}>
                        empty — never zero-filled with guesses
                      </div>
                    ) : null}
                  </div>
                ))}
              </div>
              <p style={{ fontSize: 11, color: "var(--muted)" }}>{estate.data.note}</p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "firmware" ? (
        <Panel title="Firmware Analysis">
          <p style={{ marginTop: 0, fontSize: 12, color: "var(--muted)" }}>
            Bounded signature analysis via the Binwalk tool — the tool runs
            under a hard timeout; the artifact itself is never executed.
            Third-party output is a LEAD, never definitive evidence; carved
            content is untrusted; firmware version data is not proof of
            firmware contents.
          </p>
          <label style={{ fontSize: 11, color: "var(--muted)" }}>
            Firmware image{" "}
            <input
              type="file"
              aria-label="Firmware image"
              disabled={!tenant || busy}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (!file || !tenant) return;
                void (async () => {
                  setBusy(true);
                  try {
                    const buffer = await file.arrayBuffer();
                    const bytes = new Uint8Array(buffer);
                    let binary = "";
                    for (let i = 0; i < bytes.length; i += 0x8000) {
                      binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
                    }
                    setFirmware(await apiBinaryFirmwareScan({
                      tenant_id: tenant,
                      artifact_base64: btoa(binary),
                      original_filename: file.name,
                      source_type: "firmware",
                    }));
                  } finally {
                    setBusy(false);
                  }
                })();
              }}
            />
          </label>
          {firmware && firmware.data === null ? (
            <ReadFailed error={firmware.error || "read failed"} detail={firmware.detail} />
          ) : null}
          {firmware?.data ? (
            <div style={{ marginTop: 10 }}>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 8, fontSize: 12 }}>
                <Badge tone={firmware.data.analysis_completed ? "green" : "amber"}>
                  {firmware.data.analysis_completed ? "analysis completed" : "NOT COMPLETED"}
                </Badge>
                <span style={{ color: "var(--muted)" }}>
                  {firmware.data.tool_name} {firmware.data.tool_version}
                  {!firmware.data.tool_available ? " — tool unavailable" : ""}
                </span>
                <span style={{ color: "var(--muted)" }}>
                  {firmware.data.leads.length} lead(s) · {firmware.data.carved.length} carved
                </span>
              </div>
              {firmware.data.leads.map((lead, i) => (
                <div key={i} style={{ fontSize: 11, borderTop: "1px solid var(--rule)", paddingTop: 6, marginTop: 6 }}>
                  <span style={{ fontFamily: "var(--mono)" }}>0x{lead.offset.toString(16)}</span>
                  <Badge tone={lead.validated ? "gray" : "amber"}>{lead.kind}</Badge>
                  <span style={{ marginLeft: 8, color: "var(--muted)" }}>{lead.description}</span>
                  <div style={{ color: "var(--muted)", fontStyle: "italic" }}>{lead.validation_note}</div>
                </div>
              ))}
              {firmware.data.carved.map((c) => (
                <div key={c.index} style={{ fontSize: 11, borderTop: "1px solid var(--rule)", paddingTop: 6, marginTop: 6 }}>
                  <span style={{ fontFamily: "var(--mono)" }}>
                    carved@0x{c.offset.toString(16)} · {c.kind} · {c.size} bytes · {c.sha256.slice(0, 16)}…
                  </span>
                  {(c.findings ?? []).map((f, i) => (
                    <div key={i} style={{ marginLeft: 12 }}>
                      {[f.algorithm, f.variant].filter(Boolean).join(" · ") || f.subject}
                      {" — "}
                      <span style={{ fontFamily: "var(--mono)" }}>{f.confidence}</span>,{" "}
                      <span style={{ fontFamily: "var(--mono)" }}>{f.usage_status}</span>
                    </div>
                  ))}
                  {(c.notes ?? []).map((n, i) => (
                    <div key={`n${i}`} style={{ marginLeft: 12, color: "var(--muted)", fontStyle: "italic" }}>{n}</div>
                  ))}
                </div>
              ))}
              <p style={{ fontSize: 11, color: "var(--muted)", fontStyle: "italic" }}>
                {firmware.data.limitations.join(" · ")}
              </p>
              {(firmware.data.notes ?? []).map((n, i) => (
                <p key={i} style={{ fontSize: 11, color: "var(--muted)" }}>{n}</p>
              ))}
              <p style={{ fontSize: 11, color: "var(--muted)" }}>{firmware.data.note}</p>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {view === "twin" ? (
        <Panel title="Digital Twin — relationships with provenance">
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            <button
              onClick={() => void loadBom()}
              disabled={!tenant || !artifactId || busy}
              style={{ ...CONTROL_STYLE, cursor: "pointer" }}
            >
              load relationships
            </button>
          </div>
          {bom && bom.data === null ? (
            <ReadFailed error={bom.error || "read failed"} detail={bom.detail} />
          ) : null}
          {bom?.data ? (
            <div>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr>
                    {["Source", "Relationship", "Target", "Provenance", "Evidence"].map((h) => (
                      <th key={h} style={{ textAlign: "left", padding: "6px 8px", fontSize: 11, color: "var(--muted)", borderBottom: "1px solid var(--rule)" }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {bom.data.bom.relationships.map((r, i) => (
                    <tr key={i}>
                      <td style={{ padding: "6px 8px", fontSize: 12, fontFamily: "var(--mono)" }}>{r.source}</td>
                      <td style={{ padding: "6px 8px", fontSize: 12 }}>
                        <Badge tone={r.relationship_type === "uses" ? "green" : r.relationship_type === "provides" ? "gray" : "amber"}>
                          {r.relationship_type}
                        </Badge>
                      </td>
                      <td style={{ padding: "6px 8px", fontSize: 12, fontFamily: "var(--mono)" }}>{r.target}</td>
                      <td style={{ padding: "6px 8px", fontSize: 11, color: "var(--muted)" }}>{r.provenance}</td>
                      <td style={{ padding: "6px 8px", fontSize: 11, color: "var(--muted)" }}>{r.evidence_class}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p style={{ fontSize: 11, color: "var(--muted)" }}>{bom.data.note}</p>
            </div>
          ) : null}
        </Panel>
      ) : null}
    </div>
  );
}
