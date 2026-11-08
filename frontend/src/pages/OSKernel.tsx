import React, { useCallback, useEffect, useState } from "react";
import { Badge, Panel, PageHead } from "../components/ui.jsx";
import {
  apiOSAssets, apiOSAsset, apiOSCapabilities, apiOSModules,
  apiOSConfigFlags, apiOSStorage, apiOSHardwareTrust, apiOSFindings,
  apiOSCoverage, apiOSRules, apiOSRuleEvaluation, apiOSBom,
  type ApiResult, type OSAssetRecord, type OSCapability, type OSCoverage,
  type OSFindingRecord, type OSModule, type OSConfigFlag,
  type OSStorageFact, type OSTrustFact, type OSRuleEvaluation, type OSBom,
} from "../lib/api.js";

/* OS & Kernel Intelligence (docs/os-kernel-intelligence/01_PRODUCT_SPEC.md):
   a read-only inventory console — not an assistant, no gradients, no glow.
   The honesty rules are display rules: an unavailable source renders its
   reason, never zeros; 'not detected' is never 'absent'; a registered
   kernel capability is never proof of runtime use; one host is never
   enterprise qualification; a detection is never a verdict. */

type View =
  | "assets" | "capabilities" | "modules" | "config" | "storage"
  | "trust" | "findings" | "coverage" | "rules" | "bom";

const VIEWS: Array<{ key: View; label: string }> = [
  { key: "assets", label: "Hosts & Identity" },
  { key: "capabilities", label: "Kernel Crypto API" },
  { key: "modules", label: "Kernel Modules" },
  { key: "config", label: "Kernel Configuration" },
  { key: "storage", label: "Disk Encryption" },
  { key: "trust", label: "Hardware Trust" },
  { key: "findings", label: "Findings" },
  { key: "coverage", label: "Coverage" },
  { key: "rules", label: "OS-CRYPTO Rules" },
  { key: "bom", label: "BOM Projection" },
];

const CONTROL_STYLE: React.CSSProperties = {
  background: "transparent", color: "inherit", border: "1px solid var(--rule)",
  borderRadius: 6, padding: "5px 8px", fontSize: 12, fontFamily: "var(--mono)",
};

function ReadFailed({ error }: { error: string }) {
  return (
    <Panel title="Read failed">
      <p style={{ margin: 0, fontSize: 12, color: "var(--muted)" }}>
        {error}. This page reports the failure and never prints zeros in its
        place.
      </p>
    </Panel>
  );
}

function Unknown({ why }: { why: string }) {
  return (
    <span title={why}>
      <span style={{ fontFamily: "var(--mono)" }}>unknown</span>
      <span style={{ marginLeft: 6, color: "var(--muted)", fontSize: 11 }}>
        (never guessed)
      </span>
    </span>
  );
}

function RuntimeFlag({ confirmed }: { confirmed: boolean }) {
  return confirmed ? (
    <Badge tone="green">runtime usage confirmed</Badge>
  ) : (
    <span title="a registered capability or static observation is never proof of runtime use (§2.2)">
      <Badge tone="gray">runtime usage not confirmed</Badge>
    </span>
  );
}

function EvidenceClass({ value }: { value: string }) {
  const tone = value === "observed" || value === "strongly_supported"
    ? "green" : value === "not_detected" ? "gray" : "amber";
  return (
    <span title="evidence classification, distinct from any score">
      <Badge tone={tone as "green" | "gray" | "amber"}>{value}</Badge>
      {value === "not_detected" && (
        <span style={{ marginLeft: 6, color: "var(--muted)", fontSize: 11 }}>
          (not detected — never "absent", §2.1)
        </span>
      )}
    </span>
  );
}

function Notes({ notes }: { notes?: string[] | null }) {
  if (!notes || notes.length === 0) return null;
  return (
    <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 11, color: "var(--muted)" }}>
      {notes.map((n, i) => <li key={i}>{n}</li>)}
    </ul>
  );
}

export default function OSKernel() {
  const [view, setView] = useState<View>("assets");
  const [tenant, setTenant] = useState("demo-tenant");
  const [assetId, setAssetId] = useState("");
  const [assets, setAssets] = useState<ApiResult<{ assets: OSAssetRecord[]; note: string }> | null>(null);
  const [asset, setAsset] = useState<ApiResult<OSAssetRecord> | null>(null);
  const [caps, setCaps] = useState<ApiResult<{ capabilities: OSCapability[]; note: string }> | null>(null);
  const [modules, setModules] = useState<ApiResult<{ modules: OSModule[]; note: string }> | null>(null);
  const [flags, setFlags] = useState<ApiResult<{ flags: OSConfigFlag[]; note: string }> | null>(null);
  const [storage, setStorage] = useState<ApiResult<{ storage: OSStorageFact[]; note: string }> | null>(null);
  const [trust, setTrust] = useState<ApiResult<{ hardware_trust: OSTrustFact[]; note: string }> | null>(null);
  const [findings, setFindings] = useState<ApiResult<{ findings: OSFindingRecord[]; note: string }> | null>(null);
  const [coverage, setCoverage] = useState<ApiResult<OSCoverage> | null>(null);
  const [rules, setRules] = useState<ApiResult<{ rules: Array<{ rule_id: string; detection: string; potential_impact: string }>; note: string }> | null>(null);
  const [evaluation, setEvaluation] = useState<ApiResult<OSRuleEvaluation> | null>(null);
  const [bom, setBom] = useState<ApiResult<OSBom> | null>(null);
  const [bomKind, setBomKind] = useState("techbom");
  const [busy, setBusy] = useState(false);

  const loadAssets = useCallback(async () => {
    setBusy(true);
    setAssets(await apiOSAssets({ tenant_id: tenant }));
    setBusy(false);
  }, [tenant]);

  useEffect(() => { void loadAssets(); }, [loadAssets]);

  const loadAssetView = useCallback(async () => {
    if (!assetId) return;
    setBusy(true);
    const t = { tenant_id: tenant };
    switch (view) {
      case "assets":
        setAsset(await apiOSAsset(assetId, t)); break;
      case "capabilities":
        setCaps(await apiOSCapabilities(assetId, t)); break;
      case "modules":
        setModules(await apiOSModules(assetId, t)); break;
      case "config":
        setFlags(await apiOSConfigFlags(assetId, t)); break;
      case "storage":
        setStorage(await apiOSStorage(assetId, t)); break;
      case "trust":
        setTrust(await apiOSHardwareTrust(assetId, t)); break;
      case "findings":
        setFindings(await apiOSFindings(assetId, t)); break;
      case "coverage":
        setCoverage(await apiOSCoverage(assetId, t)); break;
      case "rules":
        setEvaluation(await apiOSRuleEvaluation(assetId, t)); break;
      case "bom":
        setBom(await apiOSBom(assetId, { ...t, kind: bomKind })); break;
    }
    setBusy(false);
  }, [assetId, tenant, view, bomKind]);

  useEffect(() => {
    if (view === "rules" && !rules) {
      void apiOSRules().then(setRules);
    }
    void loadAssetView();
  }, [view, loadAssetView, rules]);

  return (
    <div>
      <PageHead
        crumb="Intelligence"
        title="OS & Kernel Intelligence"
        sub="Read-only OS and kernel cryptographic inventory. Registered capabilities are never proof of runtime use — every row carries its evidence class and limits."
      />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
        {VIEWS.map((v) => (
          <button
            key={v.key}
            onClick={() => setView(v.key)}
            style={{
              ...CONTROL_STYLE,
              borderColor: view === v.key ? "var(--accent)" : "var(--rule)",
              cursor: "pointer",
            }}
          >
            {v.label}
          </button>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center", flexWrap: "wrap" }}>
        <label style={{ fontSize: 12, color: "var(--muted)" }}>tenant</label>
        <input
          style={{ ...CONTROL_STYLE, width: 140 }}
          aria-label="Tenant"
          value={tenant}
          onChange={(e) => setTenant(e.target.value)}
        />
        <label style={{ fontSize: 12, color: "var(--muted)" }}>asset</label>
        <input
          style={{ ...CONTROL_STYLE, width: 220 }}
          aria-label="Asset"
          value={assetId}
          placeholder="host-under-test"
          onChange={(e) => setAssetId(e.target.value)}
        />
        <button
          style={{ ...CONTROL_STYLE, cursor: "pointer", opacity: busy ? 0.6 : 1 }}
          aria-busy={busy}
          onClick={() => void loadAssetView()}
        >
          read
        </button>
      </div>

      {view === "assets" && (
        <Panel title="Observed hosts">
          {assets && assets.error && !assets.data ? (
            <ReadFailed error={assets.error} />
          ) : assets && assets.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>
                {assets.data.note}
              </p>
              {assets.data.assets.length === 0 ? (
                <p style={{ fontSize: 12, margin: 0 }}>
                  No collection recorded. A missing asset is never a clean asset.
                </p>
              ) : (
                <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                      <th>asset</th><th>kernel</th><th>OS</th><th>arch</th>
                      <th>taints</th><th>collected</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.data.assets.map((a) => (
                      <tr key={a.asset_id + a.collection_id} style={{ borderTop: "1px solid var(--rule)" }}>
                        <td style={{ fontFamily: "var(--mono)" }}>{a.asset_id}</td>
                        <td style={{ fontFamily: "var(--mono)" }}>
                          {a.kernel_release === "unknown"
                            ? <Unknown why="kernel release not collected — unknown, never guessed" />
                            : a.kernel_release}
                        </td>
                        <td>{a.os_pretty_name === "unknown"
                          ? <Unknown why="os-release not collected" />
                          : a.os_pretty_name}</td>
                        <td>{a.arch === "unknown"
                          ? <Unknown why="architecture not established" />
                          : a.arch}</td>
                        <td>
                          {a.tainted_meanings.length > 0
                            ? <span title="a taint is a state record, never a defect verdict">
                                <Badge tone="amber">{a.tainted_meanings.join(", ")}</Badge>
                              </span>
                            : <span style={{ color: "var(--muted)" }}>none recorded</span>}
                        </td>
                        <td style={{ color: "var(--muted)" }}>{a.collected_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {assets.data.assets.map((a) => (
                <div key={a.asset_id + "-q"} style={{ marginTop: 10, fontSize: 11, color: "var(--muted)" }}>
                  <strong>{a.asset_id}:</strong>{" "}
                  {a.environment_development_only
                    ? "environment: development-only — "
                    : ""}
                  {a.qualification_note || "one collection is never enterprise qualification (§12)"}
                </div>
              ))}
            </>
          ) : (
            <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>
          )}
        </Panel>
      )}

      {view === "capabilities" && (
        <Panel title="Kernel Crypto API registrations">
          {caps && caps.error && !caps.data ? <ReadFailed error={caps.error} /> : caps && caps.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{caps.data.note}</p>
              <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                    <th>algorithm</th><th>implementation driver</th><th>type</th>
                    <th>key size</th><th>selftest</th><th>usage</th>
                  </tr>
                </thead>
                <tbody>
                  {caps.data.capabilities.map((c, i) => (
                    <tr key={i} style={{ borderTop: "1px solid var(--rule)" }}>
                      <td style={{ fontFamily: "var(--mono)" }}>{c.algorithm}</td>
                      <td style={{ fontFamily: "var(--mono)", color: "var(--muted)" }}>
                        {c.driver || "(unreported)"} — distinct from the generic algorithm name
                      </td>
                      <td>{c.type || <Unknown why="type unreported" />}</td>
                      <td>
                        {c.key_size_range === null
                          ? <Unknown why="the evidence did not establish a key size — unknown, never guessed" />
                          : `${c.key_size_range[0] ?? "?"}–${c.key_size_range[1] ?? "?"} bits`}
                      </td>
                      <td>{c.selftest || "unreported"}</td>
                      <td><RuntimeFlag confirmed={c.runtime_usage_confirmed} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "modules" && (
        <Panel title="Loaded kernel modules">
          {modules && modules.error && !modules.data ? <ReadFailed error={modules.error} /> : modules && modules.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{modules.data.note}</p>
              {modules.data.modules.length === 0 ? (
                <p style={{ fontSize: 12, margin: 0 }}>
                  No module rows in this collection. A missing row is never
                  evidence that a feature is unavailable — it may be built into
                  the kernel (§2.1).
                </p>
              ) : (
                <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                      <th>module</th><th>size</th><th>refcount</th><th>used by</th><th>state</th>
                    </tr>
                  </thead>
                  <tbody>
                    {modules.data.modules.map((m) => (
                      <tr key={m.name} style={{ borderTop: "1px solid var(--rule)" }}>
                        <td style={{ fontFamily: "var(--mono)" }}>{m.name}</td>
                        <td>{m.size ?? <Unknown why="size unreported" />}</td>
                        <td>{m.refcount ?? <Unknown why="refcount unreported" />}</td>
                        <td>{m.used_by.length ? m.used_by.join(", ") : "—"}</td>
                        <td>{m.state}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "config" && (
        <Panel title="Kernel configuration states">
          {flags && flags.error && !flags.data ? <ReadFailed error={flags.error} /> : flags && flags.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{flags.data.note}</p>
              {flags.data.flags.length === 0 ? (
                <p style={{ fontSize: 12, margin: 0 }}>
                  No recorded flag states in this collection. A flag missing
                  from an unavailable config source is never reported as
                  "disabled" (§2.1).
                </p>
              ) : (
                <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                      <th>flag</th><th>recorded state</th>
                    </tr>
                  </thead>
                  <tbody>
                    {flags.data.flags.map((f) => (
                      <tr key={f.flag} style={{ borderTop: "1px solid var(--rule)" }}>
                        <td style={{ fontFamily: "var(--mono)" }}>{f.flag}</td>
                        <td>
                          <span style={{ fontFamily: "var(--mono)" }}>{f.value}</span>
                          {f.explicitly_disabled && (
                            <span style={{ marginLeft: 8, color: "var(--muted)", fontSize: 11 }}>
                              explicit "not set" state — not a missing source
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "storage" && (
        <Panel title="Disk-encryption metadata">
          {storage && storage.error && !storage.data ? <ReadFailed error={storage.error} /> : storage && storage.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{storage.data.note}</p>
              {storage.data.storage.length === 0 ? (
                <p style={{ fontSize: 12, margin: 0 }}>
                  No storage rows in this collection. Encryption state is
                  UNKNOWN for the host — never "not encrypted".
                </p>
              ) : (
                <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                      <th>device</th><th>fstype</th><th>notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {storage.data.storage.map((s) => (
                      <tr key={s.device} style={{ borderTop: "1px solid var(--rule)" }}>
                        <td style={{ fontFamily: "var(--mono)" }}>{s.device}</td>
                        <td>{s.fstype === "unavailable"
                          ? <Unknown why="fstype unreported in this view" />
                          : s.fstype}</td>
                        <td><Notes notes={s.notes} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "trust" && (
        <Panel title="Hardware trust facts">
          {trust && trust.error && !trust.data ? <ReadFailed error={trust.error} /> : trust && trust.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{trust.data.note}</p>
              {trust.data.hardware_trust.map((t) => (
                <div key={t.subject} style={{ marginBottom: 10, borderTop: "1px solid var(--rule)", paddingTop: 8 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <strong style={{ fontFamily: "var(--mono)" }}>{t.subject}</strong>
                    <Badge tone={t.state === "present" ? "green" : t.state === "unavailable" ? "gray" : "amber"}>
                      {t.state}
                    </Badge>
                    <EvidenceClass value={t.evidence_class} />
                  </div>
                  <Notes notes={t.notes} />
                </div>
              ))}
              {trust.data.hardware_trust.length === 0 && (
                <p style={{ fontSize: 12, margin: 0 }}>
                  No hardware trust source in this collection — recorded as
                  unavailable, never as "no TPM" (§2.1).
                </p>
              )}
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "findings" && (
        <Panel title="Findings — detections, not verdicts">
          {findings && findings.error && !findings.data ? <ReadFailed error={findings.error} /> : findings && findings.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{findings.data.note}</p>
              {findings.data.findings.length === 0 ? (
                <p style={{ fontSize: 12, margin: 0 }}>
                  No findings recorded. A collection with no findings is never
                  "no issues" (§2.1).
                </p>
              ) : findings.data.findings.map((f, i) => (
                <div key={i} style={{ borderTop: "1px solid var(--rule)", paddingTop: 8, marginBottom: 10 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <strong style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{f.finding_type}</strong>
                    <EvidenceClass value={f.evidence_class} />
                    <RuntimeFlag confirmed={f.runtime_usage_confirmed} />
                    {f.severity_label && (
                      <Badge tone={f.severity_label === "critical" || f.severity_label === "high" ? "red" : "amber"}>
                        severity: {f.severity_label} (computed{f.risk_model_version ? ` · ${f.risk_model_version}` : ""})
                      </Badge>
                    )}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>
                    evidence source: {f.evidence_source || "(unreported)"} ·
                    observation: {f.observation_type}
                  </div>
                  {f.severity_factors && (
                    <details style={{ marginTop: 4, fontSize: 11 }}>
                      <summary style={{ cursor: "pointer", color: "var(--muted)" }}>
                        computed severity factors — preserved, never a multiplied score
                      </summary>
                      <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                        {Object.entries(f.severity_factors.factors).map(([k, v]) => (
                          <li key={k}><span style={{ fontFamily: "var(--mono)" }}>{k}</span>: {v}</li>
                        ))}
                        {f.severity_factors.derivation.map((d, j) => (
                          <li key={`d${j}`} style={{ color: "var(--muted)" }}>{d}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                  <Notes notes={f.limitations} />
                </div>
              ))}
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "coverage" && (
        <Panel title="Collection coverage">
          {coverage && coverage.error && !coverage.data ? <ReadFailed error={coverage.error} /> : coverage && coverage.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>
                {coverage.data.note || "coverage is collection completeness — never finding confidence"}
              </p>
              <div style={{ fontSize: 12 }}>
                <div style={{ marginBottom: 6 }}>
                  <strong>collected:</strong>{" "}
                  {coverage.data.sources_collected.length
                    ? coverage.data.sources_collected.join(", ")
                    : <span style={{ color: "var(--muted)" }}>none — recorded, never drawn as complete</span>}
                </div>
                <div>
                  <strong>unavailable:</strong>{" "}
                  {coverage.data.sources_unavailable.length === 0
                    ? <span style={{ color: "var(--muted)" }}>none recorded</span>
                    : <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                        {coverage.data.sources_unavailable.map((u, i) => (
                          <li key={i}>
                            <span style={{ fontFamily: "var(--mono)" }}>{u.source}</span>: {u.reason}
                          </li>
                        ))}
                      </ul>}
                </div>
              </div>
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}

      {view === "rules" && (
        <Panel title="OS-CRYPTO rule catalogue">
          {rules && rules.data && (
            <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>{rules.data.note}</p>
          )}
          {evaluation && evaluation.error && !evaluation.data ? (
            <ReadFailed error={evaluation.error} />
          ) : evaluation && evaluation.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>
                {evaluation.data.note} (model {evaluation.data.rule_model_version})
              </p>
              {evaluation.data.results.map((r) => (
                <div key={r.rule_id} style={{ borderTop: "1px solid var(--rule)", paddingTop: 8, marginBottom: 10 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <strong style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{r.rule_id}</strong>
                    <Badge tone={r.status === "evaluated" ? "green" : "gray"}>{r.status}</Badge>
                    <span style={{ fontSize: 12 }}>{r.detection}</span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>
                    {r.evaluation_note}
                  </div>
                  {r.findings.map((f, i) => (
                    <div key={i} style={{ fontSize: 11, marginTop: 4, paddingLeft: 10, borderLeft: "2px solid var(--rule)" }}>
                      <EvidenceClass value={f.evidence_class} />{" "}
                      {f.severity_label && (
                        <Badge tone={f.severity_label === "high" || f.severity_label === "critical" ? "red" : "amber"}>
                          {f.severity_label} (computed)
                        </Badge>
                      )}{" "}
                      <RuntimeFlag confirmed={f.runtime_usage_confirmed} />
                      <Notes notes={f.limitations} />
                    </div>
                  ))}
                </div>
              ))}
            </>
          ) : (
            <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>
              {rules && rules.error ? rules.error : "reading…"} — select an
              asset and press read to evaluate the catalogue over its latest
              collection.
            </p>
          )}
        </Panel>
      )}

      {view === "bom" && (
        <Panel title="BOM projection — the shared ecosystem, never a seventh BOM">
          <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
            {["sbom", "cbom", "hbom", "techbom"].map((k) => (
              <button
                key={k}
                onClick={() => setBomKind(k)}
                style={{
                  ...CONTROL_STYLE,
                  cursor: "pointer",
                  borderColor: bomKind === k ? "var(--accent)" : "var(--rule)",
                }}
              >
                {k}
              </button>
            ))}
          </div>
          {bom && bom.error && !bom.data ? <ReadFailed error={bom.error} /> : bom && bom.data ? (
            <>
              <p style={{ fontSize: 11, color: "var(--muted)", margin: "0 0 8px" }}>
                {bom.data.note}
              </p>
              <div style={{ fontSize: 11, color: "var(--muted)", marginBottom: 8 }}>
                {bom.data.components.length} component(s) ·{" "}
                {bom.data.relationships.length} relationship(s) · schema{" "}
                <span style={{ fontFamily: "var(--mono)" }}>{bom.data.schema}</span>
              </div>
              <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--muted)" }}>
                    <th>type</th><th>name</th><th>version</th><th>usage</th>
                  </tr>
                </thead>
                <tbody>
                  {bom.data.components.slice(0, 40).map((c, i) => (
                    <tr key={i} style={{ borderTop: "1px solid var(--rule)" }}>
                      <td>{c.type}</td>
                      <td style={{ fontFamily: "var(--mono)" }}>{c.name}</td>
                      <td>
                        {c.version
                          ? c.version
                          : <Unknown why="this source reports no version — unknown, never guessed" />}
                      </td>
                      <td>
                        <RuntimeFlag confirmed={!!c.properties.runtime_usage_confirmed} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {bom.data.components.length > 40 && (
                <p style={{ fontSize: 11, color: "var(--muted)", marginTop: 6 }}>
                  showing the first 40 of {bom.data.components.length} components —
                  the remainder is in the API response.
                </p>
              )}
              <div style={{ marginTop: 12, fontSize: 12 }}>
                <strong>relationships:</strong>{" "}
                {bom.data.relationships.length === 0
                  ? <span style={{ color: "var(--muted)" }}>
                      none — this engine never invents edges
                    </span>
                  : (
                    <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                      {bom.data.relationships.slice(0, 20).map((r, i) => (
                        <li key={i}>
                          <span style={{ fontFamily: "var(--mono)" }}>{r.source}</span>
                          {" —"}
                          <span style={{ color: "var(--accent)" }}> {r.relationship} </span>
                          {"→ "}
                          <span style={{ fontFamily: "var(--mono)" }}>{r.target}</span>
                          <span style={{ color: "var(--muted)", fontSize: 11 }}>
                            {" "}({r.provenance})
                          </span>
                          <Notes notes={r.limitations} />
                        </li>
                      ))}
                    </ul>
                  )}
              </div>
            </>
          ) : <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>reading…</p>}
        </Panel>
      )}
    </div>
  );
}
