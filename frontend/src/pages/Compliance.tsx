import { Link } from "react-router-dom";
import React, { useEffect, useState, useMemo } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconTarget, IconClock, IconSecurity, IconInfo, IconHardware, IconComponent } from "../components/icons";
import { apiComplianceEvidence, apiCompliancePinEvidence, apiComplianceRequirements, apiComplianceRetention, apiComplianceSignOff } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";

const STANDARD_CONTROL_KEYS: Record<string, RegExp[]> = {
  "SOC2": [/^access\./, /^config\./, /^audit\./, /^deploy\./, /^protection\./, /^retention\./],
  "PCI-DSS": [], "NIST": [], "DORA": [], "FIPS": [],
};
type EvidenceState = { phase: "loading" } | { phase: "live"; controls: any[] } | { phase: "offline" };

export default function Compliance() {
  const [evidence, setEvidence] = useState<EvidenceState>({ phase: "loading" });
  const [retentionData, setRetentionData] = useState<any>(null);
  const [retentionLive, setRetentionLive] = useState(false);
  const [selectedStandard, setSelectedStandard] = useState("SOC2");
  const [register, setRegister] = useState<any>(null);
  const [registerLive, setRegisterLive] = useState(false);
  const [reviewer, setReviewer] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function loadRegister() {
    const res = await apiComplianceRequirements();
    if (res.source === "live" && res.data) { setRegister(res.data); setRegisterLive(true); } else setRegisterLive(false);
  }
  useEffect(() => {
    let alive = true;
    async function loadCompliance() {
      setEvidence({ phase: "loading" });
      try {
        const [evRes, retRes] = await Promise.all([apiComplianceEvidence(), apiComplianceRetention()]);
        if (!alive) return;
        if (evRes.source === "live" && evRes.data) setEvidence({ phase: "live", controls: Array.isArray(evRes.data.controls) ? evRes.data.controls : [] });
        else setEvidence({ phase: "offline" });
        if (retRes.source === "live" && retRes.data) { setRetentionData(retRes.data); setRetentionLive(true); } else setRetentionLive(false);
      } catch { if (alive) setEvidence({ phase: "offline" }); }
      loadRegister();
    }
    loadCompliance();
    return () => { alive = false; };
  }, []);
  async function pinEvidence() { setBusy("pin"); const res = await apiCompliancePinEvidence(); setBusy(null); if (res.source === "live") await loadRegister(); }
  async function signOff(scope: string) { const sha = register?.pack?.pack_sha256; if (!sha || !reviewer.trim()) return; setBusy(scope); const res = await apiComplianceSignOff(scope, reviewer.trim(), sha); setBusy(null); if (res.source === "live") await loadRegister(); }

  const allControls = evidence.phase === "live" ? evidence.controls : [];
  const passCount = allControls.filter((c: any) => c.status === "pass").length;
  const failCount = allControls.filter((c: any) => c.status === "fail").length;
  const unknownCount = allControls.filter((c: any) => c.status !== "pass" && c.status !== "fail").length;
  const totalCount = allControls.length;
  const evaluated = totalCount > 0 && evidence.phase === "live";
  const complianceScore = evaluated ? Math.round((passCount / totalCount) * 100) : null;
  const patterns = STANDARD_CONTROL_KEYS[selectedStandard] ?? [];
  const controls = patterns.length ? allControls.filter((c: any) => patterns.some((p) => p.test(String(c.control ?? "")))) : [];
  const standardMapped = patterns.length > 0;
  const standards = [
    { id: "SOC2", name: "SOC 2 Type II (CC-series)", tag: "Platform controls" },
    { id: "PCI-DSS", name: "PCI-DSS v4.0.1", tag: "Not mapped" },
    { id: "NIST", name: "NIST SP 800-131A / IR 8547", tag: "Not mapped" },
    { id: "DORA", name: "DORA (EU 2022/2554)", tag: "Not mapped" },
    { id: "FIPS", name: "FIPS 140-3", tag: "Not mapped" },
  ];
  const retentionYears = retentionLive ? retentionData?.policy?.audit_log_years : undefined;
  const mappedFrameworks = Object.values(STANDARD_CONTROL_KEYS).filter((p) => p.length > 0).length;
  const heroPct = complianceScore === null ? 0 : complianceScore / 100;
  const heroTone = complianceScore === null ? "slate" as const : complianceScore >= 90 ? "green" as const : complianceScore >= 70 ? "amber" as const : "red" as const;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Hero */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--green) 12%, transparent)", border: "1px solid var(--green)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--green)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--green)" }} /> GOVERNANCE · CONTINUOUS COMPLIANCE · WORM RETENTION
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--green)", color: "#fff" }}><IconSecurity size={18} /></span>
            Continuous Regulatory Compliance
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 650 }}>
            Deterministic policy verification over platform controls. <b style={{ color: "var(--text)" }}>Framework certifications are external</b> — this page reports what the engine has actually evaluated. <span style={{ color: "var(--green)" }}>Empty is not 100%.</span>
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>SOC 2 · WORM · PINNED EVIDENCE PACK</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{mappedFrameworks} of {Object.keys(STANDARD_CONTROL_KEYS).length} frameworks mapped</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 165, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={heroPct} label={complianceScore === null ? "—" : `${complianceScore}%`} sub="posture" tone={heroTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>COMPLIANCE POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 135, lineHeight: 1.4 }}>{evaluated ? `${passCount}/${totalCount} passing · ${failCount} fail · ${unknownCount} unknown` : "Not evaluated — no controls returned"}</div>
              <div style={{ marginTop: 6 }}><Bar value={heroPct} tone={heroTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <AuthenticatedDownload path="/api/v1/compliance/evidence" filename="compliance-evidence.json" className="btn outline" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" } as any}>Export Evidence</AuthenticatedDownload>
            <Link to="/evidence" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", background: "var(--green)", borderColor: "var(--green)" }}>Evidence Lake →</Link>
          </div>
        </div>
      </div>

      {evidence.phase === "offline" && (
        <div className="panel" style={{ padding: "12px 16px", marginBottom: 16, border: "1px solid var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", borderRadius: "var(--r)", display: "flex", gap: 10, alignItems: "center" }}>
          <Badge tone="amber">OFFLINE</Badge><span style={{ color: "var(--amber)", fontWeight: 700, fontSize: 13 }}>Compliance evidence unavailable.</span><span style={{ color: "var(--dim)", fontSize: 12.5 }}>Nothing below is evaluated — no score is shown while the evidence source is unreachable.</span>
        </div>
      )}

      {/* 4 KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid var(--${heroTone})` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>COMPLIANCE POSTURE SCORE</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: complianceScore === null ? "var(--dim)" : `var(--${heroTone})` }}>{evidence.phase === "loading" ? "…" : complianceScore === null ? "—" : `${complianceScore}%`}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{evaluated ? `${passCount} passing of ${totalCount} controls` : "No controls — not 100%"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: `color-mix(in srgb, var(--${heroTone}) 14%, transparent)`, border: `1px solid var(--${heroTone})`, color: `var(--${heroTone})` }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={heroPct} tone={heroTone} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Deterministic over platform state</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${failCount ? "var(--red)" : evaluated ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>ACTIVE VIOLATIONS</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: failCount ? "var(--red)" : evaluated ? "var(--green)" : "var(--dim)" }}>{evidence.phase === "loading" ? "…" : evaluated ? failCount : "—"}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{evaluated ? (unknownCount ? `${failCount} failed · ${unknownCount} unknown` : "Requiring remediation") : "No evaluation — no claim"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: failCount ? "color-mix(in srgb, var(--red) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${failCount ? "var(--red)" : "var(--line)"}`, color: failCount ? "var(--red)" : "var(--faint)" }}><IconInfo size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={evaluated ? failCount / Math.max(1, totalCount) : 0} tone={failCount ? "red" : "slate"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Unknown ≠ FAIL — own status</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${retentionYears != null ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>WORM RETENTION POLICY</div><div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1 }}>{evidence.phase === "loading" ? "…" : retentionYears != null ? `${retentionYears} Years` : "Not configured"}</div><div style={{ fontSize: 11, color: retentionYears != null ? "var(--green)" : "var(--dim)" }}>{retentionYears != null ? "Configured · enforcement per-write" : "Default is not enforcement"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: retentionYears != null ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${retentionYears != null ? "var(--green)" : "var(--line)"}`, color: retentionYears != null ? "var(--green)" : "var(--faint)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={retentionYears != null ? Math.min(1, retentionYears / 7) : 0} tone={retentionYears != null ? "green" : "slate"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Missing is “not configured”, not “7 years”</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>FRAMEWORK COVERAGE</div><div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: "var(--cyan)" }}>{mappedFrameworks} of {Object.keys(STANDARD_CONTROL_KEYS).length} mapped</div><div style={{ fontSize: 11, color: "var(--dim)" }}>SOC2 platform controls only</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--cyan) 14%, transparent)", border: "1px solid var(--cyan)", color: "var(--cyan)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={mappedFrameworks / Object.keys(STANDARD_CONTROL_KEYS).length} tone="cyan" /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Other mappings = not implemented</div></div>
        </div>
      </div>

      {/* Standards selector */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
        {standards.map((s) => (
          <button key={s.id} onClick={() => setSelectedStandard(s.id)} title={s.tag} style={{ padding: "7px 14px", borderRadius: 999, border: `1px solid ${selectedStandard === s.id ? "var(--green)" : "var(--line)"}`, background: selectedStandard === s.id ? "var(--green)" : "var(--bg-2)", color: selectedStandard === s.id ? "#fff" : "var(--text)", fontWeight: selectedStandard === s.id ? 700 : 500, fontSize: 12, cursor: "pointer", opacity: s.tag === "Not mapped" ? 0.7 : 1 }}>
            {s.name} {s.tag === "Not mapped" && <span style={{ fontSize: 10, opacity: 0.8 }}>· {s.tag}</span>}
          </button>
        ))}
      </div>

      {/* Evidence table */}
      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div><h3 style={{ margin: 0, fontSize: 14, fontWeight: 800, display: "flex", alignItems: "center", gap: 8 }}><IconTarget size={14} style={{ color: "var(--green)" }} /> Deterministic Control Verifications</h3><p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Evaluated controls from live platform state · framework filters to mapped controls</p></div>
          <Badge tone={evaluated ? "green" : "slate"}>{evaluated ? `${controls.length}/${totalCount} shown` : "no evaluation"}</Badge>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead><tr><th>Control Key</th><th>Status</th><th>Observed Evidence Details</th><th>Evaluated</th></tr></thead>
            <tbody>
              {controls.map((c: any, idx: number) => (
                <tr key={idx}>
                  <td><span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: "var(--cyan)" }}>{c.control}</span></td>
                  <td><Badge variant={c.status === "pass" ? "success" : c.status === "fail" ? "danger" : "neutral"}>{String(c.status ?? "unknown").toUpperCase()}</Badge></td>
                  <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)" }}>{typeof c.evidence === "object" ? JSON.stringify(c.evidence) : String(c.evidence)}</span></td>
                  <td><span style={{ fontSize: 12, color: "var(--dim)" }}>{c.checked_at ? new Date(c.checked_at).toLocaleString() : "Live"}</span></td>
                </tr>
              ))}
              {evidence.phase === "live" && standardMapped && controls.length === 0 && <tr><td colSpan={4} style={{ textAlign: "center", padding: 28, color: "var(--dim)" }}>No policy evidence registered for this framework yet. Run a scan or configure compliance frameworks.</td></tr>}
              {evidence.phase === "live" && !standardMapped && <tr><td colSpan={4} style={{ textAlign: "center", padding: 28, color: "var(--dim)" }}><b>Not mapped</b> — the evidence engine has no control mapping for {selectedStandard}. Nothing evaluated · not a pass, not a fail.</td></tr>}
              {evidence.phase === "loading" && <tr><td colSpan={4} style={{ textAlign: "center", padding: 28, color: "var(--dim)" }}>Loading evidence…</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {/* Requirements Register */}
      <div className="panel" style={{ padding: 0, overflow: "hidden", marginTop: 18 }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div><h3 style={{ margin: 0, fontSize: 14, fontWeight: 800, display: "flex", alignItems: "center", gap: 8 }}><IconComponent size={14} style={{ color: "var(--green)" }} /> Requirements Register</h3><p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Each requirement → evidence · gap · expiry vs own freshness window · reviewer sign-off over pinned pack</p></div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="reviewer name (for sign-off)" aria-label="Reviewer name" style={{ fontSize: 12, padding: "6px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--text)" }} />
            <button onClick={() => void pinEvidence()} disabled={busy === "pin"} style={{ fontSize: 12, padding: "7px 14px", borderRadius: "var(--r)", background: "var(--green)", color: "#fff", border: "1px solid var(--green)", fontWeight: 700, cursor: busy === "pin" ? "not-allowed" : "pointer", opacity: busy === "pin" ? 0.6 : 1 }}>{busy === "pin" ? "Pinning…" : "Pin Current Evidence"}</button>
          </div>
        </div>
        <div style={{ padding: 14 }}>
          {!registerLive && <p style={{ margin: 0, fontSize: 12, color: "var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: "8px 12px" }}>Requirements register unavailable — nothing below is evaluated.</p>}
          {registerLive && register && (
            <>
              {register.pack ? <p style={{ margin: "0 0 6px", fontSize: 11, color: "var(--dim)" }}>Pinned pack <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text)" }}>{String(register.pack.pack_sha256).slice(0, 12)}…</span> · collected {register.pack.generated_at ? new Date(register.pack.generated_at).toLocaleString() : "—"} · integrity {String(register.pack.integrity)}</p>
                : <p style={{ margin: "0 0 8px", fontSize: 12, color: "var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: "8px 12px" }}>No evidence pack pinned — requirements are not evaluated. Use “Pin Current Evidence” first.</p>}
              <p style={{ margin: "0 0 12px", fontSize: 12, color: "var(--dim)" }}><strong style={{ color: "var(--text)" }}>{register.summary?.closed ?? 0} of {register.summary?.denominator ?? register.requirements?.length ?? 0} requirements closed</strong> (evidenced + fresh + signed where required)</p>
              <div style={{ overflowX: "auto" }}>
                <table className="tbl" style={{ width: "100%" }}>
                  <thead><tr><th>Requirement</th><th>Standing</th><th>Evidence</th><th>Gap</th><th>Expiry</th><th>Sign-off</th></tr></thead>
                  <tbody>
                    {(register.requirements ?? []).map((r: any) => {
                      const standingTone: Record<string, string> = { evidenced: "success", gap: "danger", expired: "warning", missing_evidence: "warning", awaiting_sign_off: "warning", no_evidence: "neutral", unevaluated: "neutral", not_evaluable: "neutral" };
                      const expiry = r.expiry?.state;
                      const expiryText = expiry === "fresh" ? `Fresh · ${r.expiry.age_days ?? 0}d old (window ${r.freshness_days}d)` : expiry === "expired" ? `EXPIRED — older than ${r.freshness_days}d window` : expiry === "unknown" ? "Unknown collection time" : expiry === "not_applicable" ? "No automated evidence" : "—";
                      const so = r.sign_off ?? {};
                      return (
                        <tr key={r.requirement}>
                          <td><div style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: "var(--cyan)" }}>{r.requirement}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{r.title}</div></td>
                          <td><Badge variant={standingTone[r.standing] ?? "neutral"}>{String(r.standing ?? "unknown").replace(/_/g, " ").toUpperCase()}</Badge></td>
                          <td>{(r.evidence_controls ?? []).length === 0 ? <span style={{ fontSize: 12, color: "var(--dim)" }}>No automated evidence mapped</span> : (r.evidence_controls ?? []).map((c: any) => (<div key={c.control} style={{ fontSize: 11, fontFamily: "var(--mono)" }}>{c.control} <Badge variant={c.status === "pass" ? "success" : c.status === "fail" ? "danger" : "neutral"}>{String(c.status ?? "unknown").toUpperCase()}</Badge></div>))}</td>
                          <td><span style={{ fontSize: 11, color: "var(--dim)", maxWidth: 260, display: "inline-block" }}>{r.gap}</span></td>
                          <td><span style={{ fontSize: 11, color: expiry === "expired" ? "var(--amber)" : "var(--dim)" }}>{expiryText}</span></td>
                          <td>{so.state === "not_required" ? <span style={{ fontSize: 12, color: "var(--dim)" }}>—</span> : so.state === "signed" ? <span style={{ fontSize: 12, color: "var(--green)" }}>✓ signed by {so.records?.find((rec: any) => rec.jws_valid)?.signed_by ?? "reviewer"}{so.records?.some((rec: any) => !rec.jws_valid) && <span style={{ color: "var(--amber)" }}> (a signature did not verify)</span>}</span> : so.state === "invalid" ? <span style={{ fontSize: 12, color: "var(--amber)" }}>Signature did not verify</span> : <button onClick={() => void signOff(r.sign_off_scope)} disabled={!register?.pack || !reviewer.trim() || busy === r.sign_off_scope} title={reviewer.trim() ? "Sign off this requirement over the pinned pack" : "Enter a reviewer name above first"} style={{ fontSize: 11, padding: "4px 10px", borderRadius: "var(--r)", background: "var(--green)", color: "#fff", border: "1px solid var(--green)", fontWeight: 700, cursor: !register?.pack || !reviewer.trim() ? "not-allowed" : "pointer", opacity: !register?.pack || !reviewer.trim() ? 0.5 : 1 }}>{busy === r.sign_off_scope ? "Signing…" : "Sign off"}</button>}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <Link to="/evidence" style={{ color: "var(--green)" }}>Evidence Lake →</Link><span>·</span><Link to="/security-center" style={{ color: "var(--cyan)" }}>Audit Log →</Link><span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>WORM · signed packs · no fabricated green</span>
        </div>
      </div>
    </div>
  );
}
