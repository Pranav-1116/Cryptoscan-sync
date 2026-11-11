import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code, Tabs, Bar, ProgressBar } from "../components/ui.jsx";
import { StackedBar, StateCell, VizEmpty } from "../components/viz.jsx";
import { IconCode, IconContainer, IconCloud, IconComponent, IconSecurity, IconNetwork, IconHardware, IconCertificate, IconTarget, IconTrendUp } from "../components/icons";
import { ApiResult } from "../lib/api.js";
import {
  apiContainerScan, apiK8sScan, apiCloudPosture, apiSbomImport,
  apiSbomScan, apiSbomArtifacts, apiSbomValidate, apiSbomDiff, apiSbomVerify,
  apiSbomGate, apiSbomRescan, apiSbomPrune, apiSbomLicense, apiSbomComponents,
  apiSbomAdvisories, downloadSbomArtifact, downloadSbomReport,
  apiBinaryScan, apiBinaryScanJob, apiBinaryCbom, apiBinaryDynamic, apiBinaryBatch,
  apiBinaryBatchStatus, apiJobStatus, apiYaraValidate, apiConnectorPreview,
  apiBinaryScans, apiBinaryScanDetail,
  DynamicScanResult, BinaryBatchResult, KnowledgeState,
  apiBinaryAtRest, apiKnowledge, apiKnowledgeInstall, apiKnowledgeUninstall,
} from "../lib/api.js";
import DomainCrossNav from "../components/DomainCrossNav";

/* DevSecOps pipeline gates — deterministic, rule-based: container CVE scan
   (Trivy-style), K8s manifest misconfig, cloud CIS posture, SBOM
   CycloneDX/SPDX import with pinning checks, and outbound connector previews
   (ServiceNow/Jira, Splunk/Elastic, Kafka/RabbitMQ, Slack/Teams). Every panel
   drives the live backend; no demo data. */

function Err({ res }: { res: ApiResult<any> | null }) {
  if (!res) return null;
  if (res.ok) return null;
  return <Badge tone="red"><span className="dot" /> {res.error || "OFFLINE / UNAUTHORIZED"}</Badge>;
}

function EvidenceBoundaryStrip() {
  const stages: Array<[string, string, string, any]> = [
    ["01", "Source / binary", "observed scope", IconCode],
    ["02", "SBOM + CBOM", "components + crypto", IconComponent],
    ["03", "HBOM + NBOM", "context / candidates", IconHardware],
    ["04", "VBOM + advisories", "provider provenance", IconCloud],
    ["05", "Policy + evidence", "gates / tasks", IconSecurity],
  ];
  return (
    <section className="pipeline-strip" aria-label="Applications evidence pipeline" style={{ background: "linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%)", border: "1px solid var(--line)", overflow: "hidden" }}>
      <div className="pipeline-strip-head" style={{ alignItems: "center" }}>
        <div>
          <span className="kicker" style={{ color: "var(--accent)" }}>Bounded evidence pipeline</span>
          <h2 style={{ display: "flex", gap: 10, alignItems: "center" }}><IconTarget size={22} style={{ color: "var(--accent)" }} /> From artifact to accountable decision</h2>
          <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 4, fontFamily: "var(--mono)" }}>Deterministic, fail-closed · every finding cites its evidence · no inferred clean</div>
        </div>
        <span style={{ fontFamily: "var(--mono)", letterSpacing: ".04em" }}><Badge tone="amber"><span className="dot" /> CLEAN ≠ COMPLETE</Badge></span>
      </div>
      <div className="pipeline-stages" style={{ gap: 10 }}>
        {stages.map(([number, title, detail, Ico], index) => (
          <React.Fragment key={number}>
            <div className="pipeline-stage" style={{ flex: 1, minWidth: 0, padding: "14px 12px", border: "1px solid var(--line)", borderRadius: 10, background: "var(--panel-2)", display: "flex", flexDirection: "column", gap: 8, position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: index === 0 ? "var(--accent)" : index === 1 ? "var(--cyan)" : index === 2 ? "var(--violet)" : index === 3 ? "var(--amber)" : "var(--green)" }} />
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className="pipeline-number" style={{ color: "var(--accent)", fontWeight: 700 }}>{number}</span>
                <Ico size={14} style={{ color: "var(--faint)" }} />
              </div>
              <strong style={{ fontSize: 11.5, lineHeight: 1.2 }}>{title}</strong>
              <small style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 9.5 }}>{detail}</small>
            </div>
            {index < stages.length - 1 && <span className="pipeline-arrow" aria-hidden="true" style={{ color: "var(--accent)", opacity: .6 }}>→</span>}
          </React.Fragment>
        ))}
      </div>
      <div className="pipeline-boundaries" style={{ background: "var(--bg-2)", margin: "14px -20px -20px", padding: "10px 20px", borderTop: "1px solid var(--line)", display: "flex", gap: 16, flexWrap: "wrap" }}>
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 11 }}><span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--accent)" }} /><b>Observed</b> is not inferred.</span>
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 11 }}><span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--cyan)" }} /><b>Signatures</b> are not trust decisions.</span>
        <span style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 11 }}><span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--amber)" }} /><b>No finding</b> means no match in scope, never an unobserved clean estate.</span>
      </div>
    </section>
  );
}

function sevTone(s: string) { return s === "CRITICAL" ? "red" : s === "HIGH" ? "red" : s === "MEDIUM" ? "amber" : "green"; }

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/* Severity counts as the gate actually returned them.
   The bar is a composition of matched findings — never a "risk score", never a
   fraction of a target, and never an arc whose sweep was invented. */
function SeverityComposition({ counts, note }: { counts: Record<string, number>; note?: string }) {
  const keys = [
    ...SEV_ORDER.filter((s) => counts[s]),
    ...Object.keys(counts).filter((s) => !SEV_ORDER.includes(s) && counts[s]),
  ];
  if (!keys.length) {
    return <VizEmpty title="No finding in this input" note={note ?? "No rule matched the submitted input. That is not an unobserved clean estate."} height={54} />;
  }
  return <StackedBar segments={keys.map((s) => ({ key: s, label: s.toLowerCase(), value: Number(counts[s] ?? 0), tone: sevTone(s) }))} note={note} />;
}

function FindingTable({ rows, codeKey, sevKey }: { rows: any[]; codeKey: (r: any) => string; sevKey: (r: any) => string }) {
  if (!rows?.length) return <VizEmpty title="No finding in the observed input" note="No rule matched here. That is a bounded result, not an unobserved clean estate." height={54} />;
  return (
    <Table
      head={["severity", "rule", "location / target", "detail"]}
      rows={rows.map((r) => [
        <Badge tone={sevTone(sevKey(r))}>{sevKey(r)}</Badge>,
        <span className="mono">{codeKey(r)}</span>,
        <span className="mono">{r.location || r.resource || r.instruction || r.package || r.name || "—"}</span>,
        <span style={{ fontSize: 12 }}>{r.detail}</span>,
      ])}
    />
  );
}

/* ---- 13. container scan ---- */
function ContainerPanel() {
  const [dockerfile, setDockerfile] = useState("FROM ubuntu:latest\nRUN apt-get update && apt-get install -y openssl\n");
  const [packages, setPackages] = useState('[{"name":"openssl","version":"3.0.9","ecosystem":"debian"}]');
  const [feed, setFeed] = useState('[{"cve_id":"CVE-2024-0001","severity":"CRITICAL","affected":[{"ecosystem":"debian","package":"openssl","ranges":[{"introduced":"0","fixed":"3.0.11"}]}]}]');
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      setRes(await apiContainerScan(JSON.parse(packages), JSON.parse(feed), dockerfile));
    } catch (e) { setRes({ source: "live", ok: false, data: null, error: "JSON parse: " + String(e) }); }
    setBusy(false);
  };
  const d = res?.data;
  const sevCounts = d ? d.cve_matches.reduce((a: any, c: any) => (a[c.severity] = (a[c.severity]||0)+1, a), {} as any) : {};
  return (
    <Panel title="Container image scan (on push)" sub="Dockerfile policy + deterministic CVE match — visual posture, not raw dumps" className="mt" style={{ overflow: "hidden", padding: 0 }}>
      <div style={{ padding: "14px 16px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <span className="brandmark" style={{ width: 32, height: 32, display: "grid", placeItems: "center" }}><IconContainer size={16} /></span>
        <div><div style={{ fontWeight: 700, fontSize: 13 }}>Container image scan</div><div style={{ fontSize: 11, color: "var(--dim)" }}>Dockerfile policy + NVD-style feed · deterministic, offline match</div></div>
        <span className="badge amber" style={{ marginLeft: "auto" }}><span className="dot" /> ON PUSH GATE</span>
      </div>
      <div style={{ padding: 16 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}><IconCode size={12} /> Dockerfile</span>
            <textarea className="inp" rows={5} value={dockerfile} onChange={(e) => setDockerfile(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--line)" }} placeholder="FROM ubuntu:latest" />
            <span style={{ fontSize: 10, color: "var(--faint)" }}>Policy: latest tag, apt-get pinning, USER non-root</span>
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}><IconComponent size={12} /> Installed packages</span>
            <textarea className="inp" rows={5} value={packages} onChange={(e) => setPackages(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--line)" }} placeholder='[{"name","version","ecosystem"}]' />
            <span style={{ fontSize: 10, color: "var(--faint)" }}>Exact versions from image layer · ecosystem-aware</span>
          </label>
        </div>
        <label style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}><IconCloud size={12} /> Advisory feed (NVD-style)</span>
          <textarea className="inp" rows={3} value={feed} onChange={(e) => setFeed(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--line)" }} placeholder='[{"cve_id":"CVE-...","severity":"CRITICAL",...}]' />
        </label>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button className="btn sm primary" onClick={() => void run()} disabled={busy} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><IconTarget size={12} /> {busy ? "Scanning…" : "Scan image"}</button>
          <span style={{ fontSize: 11, color: "var(--faint)" }}>Deterministic — same input → same CVEs, offline & no inference</span>
        </div>
        <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
        {d && (
          <>
            <div style={{ padding: "12px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 12 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8, marginBottom: 10 }}>
                <StateCell label="CVEs matched" value={d.vulnerabilities} tone={d.vulnerabilities ? "amber" : "green"} note="deterministic match against the supplied feed" />
                <StateCell label="worst severity" value={d.worst_severity} tone={sevTone(d.worst_severity)} />
                <StateCell label="fixable" value={d.fixable} tone={d.fixable ? "amber" : ""} note="advisory carries a fixed version" />
                <StateCell label="Dockerfile issues" value={d.dockerfile_findings.length} tone={d.dockerfile_findings.length ? "amber" : ""} />
              </div>
              <SeverityComposition counts={sevCounts} note="Segment width is the count of matched CVEs at that severity — an input-scoped result, not a score." />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 12 }}>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", marginBottom: 6, display: "flex", gap: 6, alignItems: "center" }}><IconSecurity size={12} /> CVE matches</div>
                <FindingTable rows={d.cve_matches.map((c: any) => ({ ...c, name: `${c.package}@${c.version}`, detail: `${c.cve_id}${c.fixed_version ? " → fix " + c.fixed_version : ""} (${c.ecosystem})` }))} codeKey={(r) => r.cve_id} sevKey={(r) => r.severity} />
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", marginBottom: 6, display: "flex", gap: 6, alignItems: "center" }}><IconCode size={12} /> Dockerfile policy</div>
                <FindingTable rows={d.dockerfile_findings} codeKey={(r) => r.code} sevKey={(r) => r.severity} />
              </div>
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

/* ---- 14. K8s ---- */
function K8sPanel() {
  const [yaml, setYaml] = useState("apiVersion: v1\nkind: Pod\nmetadata:\n  name: example\nspec:\n  hostPID: true\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const d = res?.data;
  const sevCountsK8s = d ? d.findings.reduce((a: any, f: any) => (a[f.severity]=(a[f.severity]||0)+1, a), {} as any) : {};
  return (
    <Panel title="Kubernetes manifest misconfig rules" sub="Misconfig rules — visual severity & resource findings" className="mt" style={{ overflow: "hidden", padding: 0 }}>
      <div style={{ padding: "14px 16px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", gap: 10, alignItems: "center" }}>
        <span className="brandmark" style={{ width: 32, height: 32, display: "grid", placeItems: "center" }}><IconContainer size={16} /></span>
        <div><div style={{ fontWeight: 700, fontSize: 13 }}>K8s manifest scan</div><div style={{ fontSize: 11, color: "var(--dim)" }}>privileged pods · hostPath · RBAC · limits · run-as-root</div></div>
        <Badge tone=""><span className="dot" /> K8S GATE</Badge>
      </div>
      <div style={{ padding: 16 }}>
        <label style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}><IconCode size={12} /> Manifest YAML</span>
          <textarea className="inp" rows={9} value={yaml} onChange={(e) => setYaml(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--line)" }} />
        </label>
        <button className="btn sm primary" onClick={async () => { setBusy(true); setRes(await apiK8sScan(yaml)); setBusy(false); }} disabled={busy} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><IconTarget size={12} /> {busy ? "Scanning…" : "Scan manifests"}</button>
        <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
        {d && (
          <>
            <div style={{ padding: "10px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 10 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8, marginBottom: 8 }}>
                <StateCell label="findings" value={d.total_findings} tone={d.total_findings ? "amber" : "green"} />
                <StateCell label="manifests scanned" value={d.manifests_scanned} note="files actually parsed" />
              </div>
              <SeverityComposition counts={sevCountsK8s} note="Misconfig findings by severity across the manifests supplied." />
            </div>
            <FindingTable rows={d.findings} codeKey={(r) => r.code} sevKey={(r) => r.severity} />
          </>
        )}
      </div>
    </Panel>
  );
}

/* ---- 15. cloud posture ---- */
const POSTURE_TEMPLATE = JSON.stringify([
  { provider: "aws", type: "s3_bucket", name: "open-bucket", acl: "public-read", public_access_block: {}, encryption: null, versioning: false, logging: null },
  { provider: "aws", type: "security_group", name: "ssh-open", ingress: [{ cidr: "0.0.0.0/0", from_port: 22, to_port: 22, protocol: "tcp" }] },
], null, 2);
function PosturePanel() {
  const [text, setText] = useState(POSTURE_TEMPLATE);
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const d = res?.data;
  const sevCloud = d ? d.findings.reduce((a: any, f: any) => (a[f.severity]=(a[f.severity]||0)+1,a),{} as any) : {};
  return (
    <Panel title="Cloud posture (CIS-style) — AWS / Azure / GCP" sub="CIS posture — visual resource findings" className="mt" style={{ overflow: "hidden", padding: 0 }}>
      <div style={{ padding: "14px 16px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", gap: 10, alignItems: "center" }}>
        <span className="brandmark" style={{ width: 32, height: 32, display: "grid", placeItems: "center" }}><IconCloud size={16} /></span>
        <div><div style={{ fontWeight: 700, fontSize: 13 }}>Cloud posture</div><div style={{ fontSize: 11, color: "var(--dim)" }}>AWS / Azure / GCP · public IAM · open buckets · TLS</div></div>
        <Badge tone=""><span className="dot" /> CIS GATE</Badge>
      </div>
      <div style={{ padding: 16 }}>
        <label style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 12 }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}><IconCloud size={12} /> Resources JSON</span>
          <textarea className="inp" rows={8} value={text} onChange={(e) => setText(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11, background: "var(--bg)", border: "1px solid var(--line)" }} />
        </label>
        <button className="btn sm primary" onClick={async () => {
          setBusy(true);
          try { setRes(await apiCloudPosture(JSON.parse(text))); }
          catch (e) { setRes({ source: "live", ok: false, data: null, error: "JSON: " + String(e) }); }
          setBusy(false);
        }} disabled={busy} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><IconTarget size={12} /> {busy ? "Evaluating…" : "Evaluate posture"}</button>
        <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
        {d && <>
          <div style={{ padding: "10px 14px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 10 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8, marginBottom: 8 }}>
              <StateCell label="findings" value={d.total_findings} tone={d.total_findings ? "red" : "green"} />
              <StateCell label="resources scanned" value={d.resources_scanned} note="resources in the submitted JSON" />
            </div>
            <SeverityComposition counts={sevCloud} note="CIS-style findings by severity across the submitted resources." />
          </div>
          <FindingTable rows={d.findings} codeKey={(r) => r.rule_id} sevKey={(r) => r.severity} />
        </>}
      </div>
    </Panel>
  );
}

/* ---- 16. SBOM — scan · artifacts · diff · validate · import ---- */
function ScoreBadge({ score, compliant }: { score: string; compliant: boolean }) {
  return <Badge tone={compliant ? "green" : "amber"}>NTIA {score}{compliant ? " · compliant" : " · gaps"}</Badge>;
}

function SbomScanTab() {
  const [kind, setKind] = useState("source");
  const [target, setTarget] = useState("");
  const [fmt, setFmt] = useState("cyclonedx");
  const [asImage, setAsImage] = useState(false);
  const [includeVendored, setIncludeVendored] = useState(false);
  const [useLockfiles, setUseLockfiles] = useState(true);
  const [feedText, setFeedText] = useState("");
  const [feedError, setFeedError] = useState<string | null>(null);
  const [scanRes, setScanRes] = useState<ApiResult<any> | null>(null);
  const [scanning, setScanning] = useState(false);
  const [showBom, setShowBom] = useState(false);
  const [dlBusy, setDlBusy] = useState<string | null>(null);
  const scan = async () => {
    if (!target.trim()) { setScanRes({ source: "live", ok: false, data: null, error: "target is required" }); return; }
    let feed: any[] | undefined;
    if (feedText.trim()) {
      try {
        const parsed = JSON.parse(feedText);
        feed = Array.isArray(parsed) ? parsed : (parsed?.vulnerabilities || parsed?.advisories);
        if (!Array.isArray(feed)) throw new Error("expected a JSON array of advisories");
        setFeedError(null);
      } catch (e) {
        // a malformed feed must not turn into a silent no-advisory scan
        setFeedError("advisory feed is not valid JSON: " + String(e));
        return;
      }
    } else { setFeedError(null); }
    setScanning(true); setShowBom(false);
    try {
      setScanRes(await apiSbomScan({ kind, target: target.trim(), format: fmt, as_image: asImage, include_vendored: includeVendored, use_lockfiles: useLockfiles, feed }));
    } catch (e) { setScanRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setScanning(false);
  };
  const m = scanRes?.data?.manifest;
  const compliance = scanRes?.data?.compliance;
  return (
    <Panel title="SBOM scanner — source tree / container → CycloneDX 1.5 · SPDX 2.3" sub="Source/container → CycloneDX/SPDX · signed artifacts" className="mt" style={{ overflow: "hidden", padding: 0 }}>
      <div style={{ padding: "12px 16px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", gap: 10, alignItems: "center" }}>
        <span className="brandmark" style={{ width: 32, height: 32, display: "grid", placeItems: "center" }}><IconComponent size={16} /></span>
        <div><div style={{ fontWeight: 700, fontSize: 13 }}>SBOM generator</div><div style={{ fontSize: 11, color: "var(--dim)" }}>Manifests + lockfiles · transitive graph · crypto-relevant · signed</div></div>
        <Badge tone="cyan"><span className="dot" /> SIGNED</Badge>
      </div>
      <div style={{ padding: 16 }}>
      <div className="grid" style={{ gridTemplateColumns: "130px 1fr 130px", gap: 8, marginBottom: 8 }}>
        <select className="inp" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="source">source tree</option>
          <option value="container">container</option>
        </select>
        <input className="inp" placeholder={kind === "source" ? "source tree path (e.g. /tmp/cryptoscan-sources/myapp)" : "filesystem root, docker-save .tar, or registry image (e.g. nginx:1.27)"} value={target} onChange={(e) => setTarget(e.target.value)} />
        <select className="inp" value={fmt} onChange={(e) => setFmt(e.target.value)}>
          <option value="cyclonedx">CycloneDX 1.5</option>
          <option value="spdx">SPDX 2.3</option>
        </select>
      </div>
      <div className="row" style={{ gap: 14, marginBottom: 8, fontSize: 12.5, flexWrap: "wrap" }}>
        {kind === "container" && <label><input type="checkbox" checked={asImage} onChange={(e) => setAsImage(e.target.checked)} /> treat as registry image</label>}
        {kind === "source" && <label><input type="checkbox" checked={useLockfiles} onChange={(e) => setUseLockfiles(e.target.checked)} /> resolve lockfiles (transitive deps)</label>}
        {kind === "source" && <label><input type="checkbox" checked={includeVendored} onChange={(e) => setIncludeVendored(e.target.checked)} /> include vendor/ dirs</label>}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}>
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          advisory feed (JSON array, optional) — matched offline against the discovered versions; without one the SBOM claims no advisories
        </div>
        <textarea className="inp" rows={2} style={{ width: "100%", fontFamily: "ui-monospace, monospace", fontSize: 12 }}
          placeholder='[{"cve_id":"CVE-2024-21538","severity":"CRITICAL","affected":[{"ecosystem":"npm","package":"jws","ranges":[{"introduced":"0","fixed":"3.2.3"}]}]}]'
          value={feedText} onChange={(e) => setFeedText(e.target.value)} />
        {feedError && <div style={{ color: "var(--red)", fontSize: 12.5, marginTop: 4 }}>{feedError}</div>}
      </div>
      <button className="btn sm primary" onClick={() => void scan()} disabled={scanning}>{scanning ? "Scanning…" : "Scan & generate SBOM"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={scanRes} /></div>
      {m && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
            <Badge tone=""><span className="dot" /> {m.component_count} components</Badge>
            {kind === "source" && <Badge tone="">{m.direct_count} direct · {m.transitive_count} transitive{m.lockfile_count ? ` · ${m.lockfile_count} lockfiles` : ""}</Badge>}
            <Badge tone={m.crypto_components ? "blue" : ""}>{m.crypto_components} crypto-relevant</Badge>
            <Badge tone={m.unpinned ? "amber" : "green"}>{m.pinned} pinned / {m.unpinned} unpinned</Badge>
            <Badge tone={!m.feed_supplied ? "gray" : (m.vulnerability_count ? "red" : "green")}>
              {m.feed_supplied ? `${m.vulnerability_count} advisories matched` : "no feed — advisories unchecked"}
            </Badge>
            {typeof m.dependency_edges === "number" && <Badge tone="">{m.dependency_edges} deps edges</Badge>}
            {compliance && <ScoreBadge score={compliance.score} compliant={compliance.compliant} />}
            <Badge tone={m.signature_alg ? "green" : "gray"}>{m.signature_alg ? "signed" : "unsigned"} · sha256 {String(m.sha256).slice(0, 10)}…</Badge>
          </div>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <button className="btn sm" onClick={async () => {
              setDlBusy(m.artifact_id);
              try { await downloadSbomArtifact(m.artifact_id); }
              catch (e) { setScanRes({ source: "live", ok: false, data: m, error: "download: " + String(e) }); }
              setDlBusy(null);
            }} disabled={dlBusy === m.artifact_id}>{dlBusy === m.artifact_id ? "Downloading…" : "Download artifact"}</button>
            <button className="btn sm" onClick={() => setShowBom(!showBom)}>{showBom ? "Hide BOM" : "View BOM JSON"}</button>
          </div>
          {compliance && !compliance.compliant && (
            <div className="mt" style={{ fontSize: 12.5 }}>
              <div className="muted" style={{ marginBottom: 4 }}>Minimum-elements gaps</div>
              <ul style={{ margin: 0, paddingLeft: 18 }}>{compliance.gaps.map((g: string) => <li key={g}>{g}</li>)}</ul>
            </div>
          )}
          {showBom && <pre className="code" style={{ marginTop: 8, maxHeight: 320, overflow: "auto" }}>{JSON.stringify(scanRes?.data?.bom, null, 1)}</pre>}
        </>
      )}
      </div>
    </Panel>
  );
}

function SbomArtifactsTab() {
  const [artRes, setArtRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [verdicts, setVerdicts] = useState<Record<string, any>>({});
  // filters mirror the API: kind / format / target substring
  const [fKind, setFKind] = useState("");
  const [fFmt, setFFmt] = useState("");
  const [fQuery, setFQuery] = useState("");
  const [pruneDays, setPruneDays] = useState(90);
  const [pruned, setPruned] = useState<string | null>(null);
  const refresh = async (filters?: { kind?: string; fmt?: string; q?: string }) => {
    setBusy(true);
    try { setArtRes(await apiSbomArtifacts({ kind: filters?.kind ?? fKind, fmt: filters?.fmt ?? fFmt, q: filters?.q ?? fQuery })); }
    catch (e) { setArtRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setBusy(false);
  };
  React.useEffect(() => { void refresh(); }, []);
  const arts = artRes?.data?.artifacts || [];
  const remember = (id: string, value: any) => setVerdicts((v) => ({ ...v, [id]: value }));
  const verify = async (id: string) => {
    setRowBusy(id);
    try {
      const res = await apiSbomVerify(id);
      remember(id, res.data || { verdict: res.error || "ERROR" });
    } finally { setRowBusy(null); }
  };
  const gate = async (id: string) => {
    setRowBusy(id);
    try {
      const res = await apiSbomGate(id);
      remember(id, res.data || { verdict: res.error || "ERROR" });
    } finally { setRowBusy(null); }
  };
  const rescan = async (id: string) => {
    setRowBusy(id);
    try {
      const res = await apiSbomRescan(id);
      if (!res.ok || !res.data) { remember(id, { verdict: res.error || "ERROR" }); return; }
      const d = res.data;
      remember(id, {
        verdict: d.gate?.verdict || "?", kind: "rescan", fresh: d.artifact_id,
        diff: d.diff, gate: d.gate, notes: d.notes || [],
      });
      await refresh();
    } finally { setRowBusy(null); }
  };
  const verdictCell = (a: any) => {
    const v = verdicts[a.artifact_id];
    if (!v) return <Badge tone={a.signature_alg ? "gray" : ""}>{a.signature_alg ? "signed" : "unsigned"}</Badge>;
    if (v.kind === "rescan") {
      const summary = v.diff
        ? `${v.diff.verdict} · +${v.diff.added?.length || 0} / −${v.diff.removed?.length || 0} / Δ${v.diff.changed?.length || 0}`
        : "re-scanned (no diff)";
      return <Badge tone={v.gate?.verdict === "PASS" ? "green" : "red"}>{`rescan ${v.gate?.verdict || "?"} · ${summary}`}</Badge>;
    }
    if (v.counts) {
      // gate result: show the verdict plus the first blocker
      const blocker = (v.blockers || [])[0];
      return <Badge tone={v.verdict === "PASS" ? "green" : "red"}>{`gate ${v.verdict}${blocker ? ` · ${blocker.code}` : ""}`}</Badge>;
    }
    return <Badge tone={v.verdict === "OK" ? "green" : "red"}>{v.verdict}</Badge>;
  };
  const detailCell = (a: any) => {
    const v = verdicts[a.artifact_id];
    if (!v) return "";
    if (v.kind === "rescan") {
      const moved = (v.diff?.changed || []).slice(0, 3).map((c: any) => `${c.name} ${c.from}→${c.to}`).join(", ");
      const added = (v.diff?.added || []).slice(0, 3).map((c: any) => `+${c.name}`).join(" ");
      return <span className="muted" style={{ fontSize: 12 }}>{[moved, added].filter(Boolean).join(" · ") || "no component changes"}{(v.notes || []).length ? ` — ${v.notes[0]}` : ""}</span>;
    }
    if (v.counts) {
      return <span className="muted" style={{ fontSize: 12 }}>{(v.blockers || []).map((b: any) => b.detail).join("; ") || (v.warnings || []).map((w: any) => w.detail).join("; ")}</span>;
    }
    const failed = (v.checks || []).filter((c: any) => !c.ok).map((c: any) => c.check);
    return failed.length ? <span className="muted" style={{ fontSize: 12 }}>failed: {failed.join(", ")}</span> : "";
  };
  return (
    <Panel title="SBOM artifacts — persisted, hash-signed" sub="Hash-signed · verify / gate / rescan · visual provenance" className="mt">
      <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <select className="inp" style={{ width: 120 }} value={fKind} onChange={(e) => setFKind(e.target.value)}>
          <option value="">all kinds</option>
          <option value="source">source</option>
          <option value="container">container</option>
        </select>
        <select className="inp" style={{ width: 130 }} value={fFmt} onChange={(e) => setFFmt(e.target.value)}>
          <option value="">all formats</option>
          <option value="cyclonedx">CycloneDX</option>
          <option value="spdx">SPDX</option>
        </select>
        <input className="inp" style={{ width: 190 }} placeholder="target contains…" value={fQuery} onChange={(e) => setFQuery(e.target.value)} />
        <button className="btn sm" onClick={() => void refresh()} disabled={busy}>{busy ? "Refreshing…" : "Apply / refresh"}</button>
        <span className="muted" style={{ fontSize: 12.5 }}>retention:</span>
        <input className="inp" style={{ width: 70 }} type="number" min={1} value={pruneDays} onChange={(e) => setPruneDays(Number(e.target.value))} />
        <span className="muted" style={{ fontSize: 12.5 }}>days</span>
        <button className="btn sm" onClick={async () => {
          const res = await apiSbomPrune(pruneDays);
          setPruned(res.ok ? `deleted ${res.data.deleted}, kept ${res.data.kept}` : (res.error || "failed"));
          void refresh();
        }}>Prune older</button>
        {pruned && <Badge tone="amber">{pruned}</Badge>}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={artRes} /></div>
      {arts.length > 0 ? (
        <Table
          head={["created", "format", "kind", "target", "components", "direct/trans", "NTIA", "advisories", "provenance", ""]}
          rows={arts.map((a: any) => [
            String(a.created_at || "").replace("T", " ").slice(0, 19),
            a.format,
            a.kind,
            String(a.target || "").slice(0, 40),
            a.component_count,
            `${a.direct_count ?? "-"}/${a.transitive_count ?? "-"}`,
            a.minimum_elements || "-",
            <span key={`${a.artifact_id}-v`} title={a.feed_supplied ? "matched against an advisory feed" : "no advisory feed was supplied"}>
              {a.vulnerability_count ?? "-"}{a.feed_supplied ? "" : " (unchecked)"}
            </span>,
            verdictCell(a),
            <span key={a.artifact_id} style={{ display: "grid", gap: 6 }}>
              <span className="row" style={{ gap: 6 }}>
                <button className="btn sm" onClick={() => void verify(a.artifact_id)} disabled={rowBusy === a.artifact_id}>{rowBusy === a.artifact_id ? "…" : "Verify"}</button>
                <button className="btn sm" onClick={() => void gate(a.artifact_id)} disabled={rowBusy === a.artifact_id}>Gate</button>
                <button className="btn sm" onClick={() => void rescan(a.artifact_id)} disabled={rowBusy === a.artifact_id}>Rescan</button>
                <button className="btn sm" onClick={async () => { try { await downloadSbomReport(a.artifact_id); } catch (e) { window.alert("report failed: " + String(e)); } }}>Report</button>
                <button className="btn sm" onClick={async () => { try { await downloadSbomArtifact(a.artifact_id); } catch (e) { window.alert("download failed: " + String(e)); } }}>SBOM</button>
              </span>
              {detailCell(a)}
            </span>,
          ])}
        />
      ) : <div className="muted" style={{ fontSize: 12.5 }}>No artifacts match — clear the filters or run a scan.</div>}
    </Panel>
  );
}

function SbomDiffTab() {
  const [arts, setArts] = useState<any[]>([]);
  const [fromId, setFromId] = useState("");
  const [toId, setToId] = useState("");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  React.useEffect(() => {
    void (async () => {
      const r = await apiSbomArtifacts();
      const list = r.data?.artifacts || [];
      setArts(list);
      if (list[1]) setFromId(list[1].artifact_id);
      if (list[0]) setToId(list[0].artifact_id);
    })();
  }, []);
  const d = res?.data;
  const run = async () => {
    if (!fromId || !toId) { setRes({ source: "live", ok: false, data: null, error: "pick two artifacts" }); return; }
    setBusy(true);
    try { setRes(await apiSbomDiff({ from_artifact: fromId, to_artifact: toId })); }
    catch (e) { setRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setBusy(false);
  };
  return (
    <Panel title="SBOM diff — what changed between two bills of materials" sub="Visual diff · added/removed/changed · crypto deltas" className="mt">
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr auto", gap: 8, marginBottom: 8 }}>
        <select className="inp" value={fromId} onChange={(e) => setFromId(e.target.value)}>
          <option value="">baseline artifact…</option>
          {arts.map((a) => <option key={a.artifact_id} value={a.artifact_id}>{String(a.created_at).slice(0, 16)} · {a.format} · {String(a.target).slice(0, 34)}</option>)}
        </select>
        <select className="inp" value={toId} onChange={(e) => setToId(e.target.value)}>
          <option value="">current artifact…</option>
          {arts.map((a) => <option key={a.artifact_id} value={a.artifact_id}>{String(a.created_at).slice(0, 16)} · {a.format} · {String(a.target).slice(0, 34)}</option>)}
        </select>
        <button className="btn sm primary" onClick={() => void run()} disabled={busy}>{busy ? "Diffing…" : "Diff"}</button>
      </div>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
            <Badge tone={d.verdict === "UNCHANGED" ? "green" : d.verdict === "CRYPTO_REVIEW" ? "red" : "amber"}>{d.verdict}</Badge>
            <Badge tone="">{d.summary.added} added</Badge>
            <Badge tone="">{d.summary.removed} removed</Badge>
            <Badge tone="">{d.summary.changed} changed</Badge>
            <Badge tone="">{d.summary.from.components} → {d.summary.to.components} components</Badge>
          </div>
          {(d.added.length + d.removed.length + d.changed.length) > 0 && (
            <Table
              head={["change", "component", "from", "to", "crypto"]}
              rows={[
                ...d.added.map((x: any) => ["ADDED", x.name, "-", x.version ?? "-", x.crypto ? "yes" : ""]),
                ...d.removed.map((x: any) => ["REMOVED", x.name, x.version ?? "-", "-", x.crypto ? "yes" : ""]),
                ...d.changed.map((x: any) => [x.direction.toUpperCase(), x.name, x.from ?? "-", x.to ?? "-", x.crypto ? "yes" : ""]),
              ]}
            />
          )}
        </>
      )}
    </Panel>
  );
}

function SbomValidateTab() {
  const [doc, setDoc] = useState(JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    metadata: { timestamp: "2026-09-22T00:00:00Z", authors: [{ name: "supplier-ci" }] },
    components: [{ type: "library", name: "libfoo", version: "1.0", purl: "pkg:generic/libfoo@1.0", supplier: { name: "ACME" } }],
    dependencies: [{ ref: "pkg:generic/libfoo@1.0", dependsOn: [] }],
  }, null, 2));
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const d = res?.data;
  return (
    <Panel title="SBOM validation — NTIA minimum elements" sub="NTIA minimum elements — visual compliance score" className="mt">
      <textarea className="inp" rows={10} value={doc} onChange={(e) => setDoc(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} />
      <button className="btn sm primary" onClick={async () => {
        setBusy(true);
        try { setRes(await apiSbomValidate(JSON.parse(doc))); }
        catch (e) { setRes({ source: "live", ok: false, data: null, error: "JSON: " + String(e) }); }
        setBusy(false);
      }} disabled={busy}>{busy ? "Validating…" : "Validate document"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
            <Badge tone={d.compliant ? "green" : "amber"}>{d.score} minimum elements</Badge>
            <Badge tone="">{d.format} {d.spec_version}</Badge>
            <Badge tone="">{d.component_count} components</Badge>
          </div>
          <Table head={["element", "status", "detail"]} rows={d.elements.map((e: any) => [e.label, e.status, e.detail])} />
          {d.recommended?.length > 0 && (
            <div className="mt">
              <Table head={["recommended", "status", "detail"]} rows={d.recommended.map((e: any) => [e.label, e.status, e.detail])} />
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function SbomImportTab() {
  const [doc, setDoc] = useState(JSON.stringify({
    bomFormat: "CycloneDX",
    components: [
      { type: "library", name: "requests", version: "^2.0", purl: "pkg:pypi/requests@2.0" },
      { type: "library", name: "certifi", version: "2024.2.2", purl: "pkg:pypi/certifi@2024.2.2" },
    ],
  }, null, 2));
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const d = res?.data;
  return (
    <Panel title="SBOM import — CycloneDX / SPDX + pinning" sub="Import + pinning check — visual dependency graph" className="mt">
      <textarea className="inp" rows={8} value={doc} onChange={(e) => setDoc(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} />
      <button className="btn sm primary" onClick={async () => {
        setBusy(true);
        try { setRes(await apiSbomImport(JSON.parse(doc))); }
        catch (e) { setRes({ source: "live", ok: false, data: null, error: "JSON: " + String(e) }); }
        setBusy(false);
      }} disabled={busy}>{busy ? "Importing…" : "Import SBOM"}</button>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone=""><span className="dot" /> {d.component_count} components</Badge>
            <Badge tone={d.pinning.unpinned ? "amber" : "green"}>{d.pinning.pinned} pinned / {d.pinning.unpinned} unpinned</Badge>
            <Badge tone={d.graph.has_cycle ? "red" : "green"}>{d.graph.edge_count} edges{d.graph.has_cycle ? " · CYCLE" : ""}</Badge>
          </div>
          <FindingTable rows={d.pinning.findings} codeKey={(r) => r.code} sevKey={(r) => r.severity === "HIGH" ? "HIGH" : "MEDIUM"} />
        </>
      )}
    </Panel>
  );
}

function SbomLicenseTab() {
  const [docs, setDocs] = useState<any[]>([]);
  const [artifactId, setArtifactId] = useState("");
  const [forbidden, setForbidden] = useState("");
  const [restricted, setRestricted] = useState("");
  const [requireDeclared, setRequireDeclared] = useState(false);
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  React.useEffect(() => {
    void (async () => {
      const r = await apiSbomArtifacts({ limit: 50 });
      if (r.ok) setDocs(r.data.artifacts || []);
    })();
  }, []);
  const run = async () => {
    if (!artifactId) { setRes({ source: "live", ok: false, data: null, error: "pick an artifact" }); return; }
    setBusy(true);
    try {
      setRes(await apiSbomLicense({
        artifact_id: artifactId,
        policy: {
          forbidden: forbidden.split(",").map((x) => x.trim()).filter(Boolean),
          restricted: restricted.split(",").map((x) => x.trim()).filter(Boolean),
          require_declared: requireDeclared,
        },
      }));
    } catch (e) { setRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setBusy(false);
  };
  const d = res?.data;
  return (
    <Panel title="License compliance" sub="SPDX licenses · violations & policy flags" className="mt">
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
        <select className="inp" value={artifactId} onChange={(e) => setArtifactId(e.target.value)}>
          <option value="">select an artifact…</option>
          {docs.map((a: any) => <option key={a.artifact_id} value={a.artifact_id}>{String(a.target).slice(0, 44)} · {a.format}</option>)}
        </select>
        <div className="row" style={{ gap: 8 }}>
          <input className="inp" placeholder="forbidden ids (comma separated)" value={forbidden} onChange={(e) => setForbidden(e.target.value)} />
          <input className="inp" placeholder="restricted ids" value={restricted} onChange={(e) => setRestricted(e.target.value)} />
        </div>
      </div>
      <div className="row" style={{ gap: 12, marginBottom: 8, fontSize: 12.5, alignItems: "center" }}>
        <label><input type="checkbox" checked={requireDeclared} onChange={(e) => setRequireDeclared(e.target.checked)} /> require every component to declare a license</label>
        <button className="btn sm primary" onClick={() => void run()} disabled={busy}>{busy ? "Evaluating…" : "Evaluate licenses"}</button>
      </div>
      <Err res={res} />
      {d && (
        <>
          <div className="row" style={{ gap: 8, margin: "10px 0", flexWrap: "wrap" }}>
            <Badge tone={d.verdict === "PASS" ? "green" : (d.verdict === "FAIL" ? "red" : "amber")}>license {d.verdict}</Badge>
            <Badge tone="">{d.inventory.distinct_licenses} distinct</Badge>
            <Badge tone={d.inventory.undeclared.length ? "amber" : "green"}>{d.inventory.undeclared.length} undeclared</Badge>
            {Object.entries(d.inventory.classes || {}).map(([k, v]) => <Badge key={k} tone="">{k}: {String(v)}</Badge>)}
          </div>
          {d.inventory.licenses.length > 0 && (
            <Table head={["license", "class", "components", "carried by"]}
              rows={d.inventory.licenses.map((row: any) => [
                row.spdx_id + (row.exceptions?.length ? ` (WITH ${row.exceptions.join(", ")})` : ""),
                row.class, row.count,
                (row.components || []).slice(0, 4).map((c: any) => c.component).join(", "),
              ])} />
          )}
          {d.inventory.undeclared.length > 0 && (
            <div className="mt" style={{ fontSize: 12.5 }}>
              <div className="muted">Undeclared licenses — reported as unknown, never as permitted or denied</div>
              <div>{d.inventory.undeclared.map((u: any) => u.component).join(", ")}</div>
            </div>
          )}
          {d.violations.length > 0 && (
            <div className="mt">
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>Findings</div>
              <Table head={["code", "severity", "detail"]}
                rows={d.violations.map((v: any) => [v.code, v.severity, v.detail])} />
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

function SbomInventoryTab() {
  const [q, setQ] = useState("");
  const [cryptoOnly, setCryptoOnly] = useState(false);
  const [severity, setSeverity] = useState("");
  const [comps, setComps] = useState<ApiResult<any> | null>(null);
  const [advs, setAdvs] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const load = async () => {
    setBusy(true);
    try {
      const [c, a] = await Promise.all([
        apiSbomComponents({ q: q || undefined, crypto: cryptoOnly || undefined, limit: 200 }),
        apiSbomAdvisories({ severity: severity || undefined }),
      ]);
      setComps(c); setAdvs(a);
    } finally { setBusy(false); }
  };
  React.useEffect(() => { void load(); }, []);
  const compRows = comps?.data?.components || [];
  const advRows = advs?.data?.advisories || [];
  return (
    <Panel title="Component & advisory index" sub="Cross-artifact index — components & advisories" className="mt">
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input className="inp" style={{ width: 220 }} placeholder="component name or purl…" value={q} onChange={(e) => setQ(e.target.value)} />
        <label style={{ fontSize: 12.5 }}><input type="checkbox" checked={cryptoOnly} onChange={(e) => setCryptoOnly(e.target.checked)} /> crypto-relevant only</label>
        <select className="inp" style={{ width: 140 }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">any severity</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className="btn sm" onClick={() => void load()} disabled={busy}>{busy ? "Loading…" : "Apply"}</button>
      </div>
      <Err res={comps} />
      <div className="mt" style={{ marginTop: 10 }}>
        {compRows.length > 0 ? (
          <>
            <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
              {comps?.data?.total} component row(s) from {comps?.data?.artifacts_scanned} artifact(s)
              {comps?.data?.truncated ? " — truncated, raise the limit or narrow the filter" : ""}
            </div>
            <Table head={["component", "version", "crypto", "artifact", "target"]}
              total={compRows.length} rows={compRows.slice(0, 60).map((c: any) => [
                c.name, c.version || "-",
                c.crypto ? <Badge tone="blue">crypto</Badge> : "",
                String(c.artifact_id || "").slice(0, 8), String(c.target || "").slice(0, 40),
              ])} />
          </>
        ) : <div className="muted" style={{ fontSize: 12.5 }}>No components indexed — run a scan.</div>}
      </div>
      <div className="mt">
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          Advisories: {advs?.data?.total ?? 0} across {advs?.data?.artifacts_checked ?? 0} checked artifact(s)
          {(advs?.data?.artifacts_without_feed ?? 0) > 0 ? ` · ${advs?.data?.artifacts_without_feed} artifact(s) were never checked (no feed)` : ""}
        </div>
        {advRows.length > 0 ? (
          <Table head={["CVE", "severity", "fix", "affected components"]}
            rows={advRows.map((a: any) => [
              a.cve,
              <Badge tone={a.severity === "CRITICAL" ? "red" : (a.severity === "HIGH" ? "amber" : "gray")}>{a.severity}</Badge>,
              a.recommendation || "-",
              (a.affected || []).slice(0, 3).map((x: any) => `${x.ref} (${String(x.artifact_id).slice(0, 8)})`).join(", "),
            ])} />
        ) : <div className="muted" style={{ fontSize: 12.5 }}>No advisories recorded — scan with an advisory feed to populate this view.</div>}
      </div>
    </Panel>
  );
}

function SbomPanel() {
  const [sub, setSub] = useState(0);
  const tabs = ["Scan & generate", "Artifacts", "Diff", "Validate", "Licenses", "Index", "Import"];
  return (
    <>
      <div className="mt"><Tabs tabs={tabs} active={sub} onChange={setSub} /></div>
      {sub === 0 && <SbomScanTab />}
      {sub === 1 && <SbomArtifactsTab />}
      {sub === 2 && <SbomDiffTab />}
      {sub === 3 && <SbomValidateTab />}
      {sub === 4 && <SbomLicenseTab />}
      {sub === 5 && <SbomInventoryTab />}
      {sub === 6 && <SbomImportTab />}
    </>
  );
}


/* ---- binaries & firmware ---- */
function BinaryPanel() {
  const [target, setTarget] = useState("");
  const [fmt, setFmt] = useState("cyclonedx");
  const [recursive, setRecursive] = useState(true);
  const [includeRaw, setIncludeRaw] = useState(false);
  const [feedText, setFeedText] = useState("");
  const [feedError, setFeedError] = useState<string | null>(null);
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [showBom, setShowBom] = useState(false);
  const [showCbom, setShowCbom] = useState(false);
  const [storedCbom, setStoredCbom] = useState<string | null>(null);
  const [storedBusy, setStoredBusy] = useState(false);
  // rule files / directories for the YARA subset (the built-in rules always run)
  const [rulesPath, setRulesPath] = useState("");
  const [rulesInfo, setRulesInfo] = useState<{ ok: boolean; text: string } | null>(null);
  const [rulesBusy, setRulesBusy] = useState(false);
  // a queued scan: the job id and its progress, polled until it stops moving
  const [job, setJob] = useState<{ job_id: string; artifact_id: string; status: string } | null>(null);
  const [jobProgress, setJobProgress] = useState<any | null>(null);
  const [jobError, setJobError] = useState<string | null>(null);
  const [jobBusy, setJobBusy] = useState(false);
  const rules = () => (rulesPath.trim() ? [rulesPath.trim()] : []);
  // installed detection packs: signed rule bundles that arrive on media and are
  // loaded by every scan. What the scanner will actually match is a digest, not a
  // claim — so the state (built-in + packs + the set a scan uses) is shown here.
  const [knowledge, setKnowledge] = useState<KnowledgeState | null>(null);
  const [packPath, setPackPath] = useState("");
  const [packBusy, setPackBusy] = useState(false);
  const [atRest, setAtRest] = useState<{
    tenant: string; artifacts: number; plaintext_artifacts: number;
    by_algorithm: Record<string, number>;
    at_rest: { algorithm: string; encrypted: boolean; key_id?: string; key_source: string; note?: string };
  } | null>(null);
  const [packInfo, setPackInfo] = useState<{ ok: boolean; text: string; reasons: string[] } | null>(null);
  // database-backed history/read model: the signed artifact response remains the
  // authoritative export, while this index makes prior observations searchable.
  const [history, setHistory] = useState<ApiResult<any> | null>(null);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyQuery, setHistoryQuery] = useState("");
  const [selectedHistory, setSelectedHistory] = useState<any | null>(null);
  const [selectedHistoryBusy, setSelectedHistoryBusy] = useState(false);

  // dynamic analysis (ADR-012 LD_PRELOAD tracer). The host has to allow it and the
  // sample has to pass the preflight; a refusal is shown with its reasons, never as
  // an empty result. The preflight starts nothing, so it is safe to click first.
  const [dynArgs, setDynArgs] = useState("");
  const [dynSubmit, setDynSubmit] = useState(true);
  const [dyn, setDyn] = useState<DynamicScanResult | null>(null);
  const [dynRefusals, setDynRefusals] = useState<string[]>([]);
  const [dynError, setDynError] = useState<string | null>(null);
  const [dynBusy, setDynBusy] = useState(false);
  const dynArgv = () => dynArgs.trim().split(/\s+/).filter(Boolean);

  // fleet intake: a spool directory in, jobs out — deduplicated by content
  const [spool, setSpool] = useState("");
  const [batch, setBatch] = useState<BinaryBatchResult | null>(null);
  const [batchStatus, setBatchStatus] = useState<any | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchAll, setBatchAll] = useState(false);

  /** Plan a pass (the default) or queue it — the same decision either way, shown. */
  const runPass = async (queue: boolean) => {
    if (!spool.trim()) { setBatchError("a spool directory is required"); return; }
    setBatchBusy(true); setBatchError(null); setBatchStatus(null);
    try {
      const answer = await apiBinaryBatch({
        spool: spool.trim(), dry_run: !queue, recursive, include_raw: includeRaw,
        format: fmt, yara_rules: rules(),
      });
      if (!answer.ok || !answer.data) setBatchError(answer.error || "the pass could not be planned");
      else setBatch(answer.data);
    } catch (e) { setBatchError(String(e)); }
    setBatchBusy(false);
  };

  // follow a queued pass until nothing is still moving
  React.useEffect(() => {
    if (!batch?.batch_id || batch.dry_run) return;
    let stop = false;
    const tick = async () => {
      const answer = await apiBinaryBatchStatus(batch.batch_id);
      if (stop) return;
      if (!answer.ok || !answer.data) { setBatchError(answer.error || "batch status unavailable"); return; }
      setBatchStatus(answer.data);
      const moving = (answer.data.by_status?.QUEUED || 0) + (answer.data.by_status?.RUNNING || 0);
      if (moving === 0) { stop = true; return; }
      window.setTimeout(() => void tick(), 3000);
    };
    void tick();
    return () => { stop = true; };
  }, [batch?.batch_id, batch?.dry_run]);

  // which rules and constant tables this host will load: read once, refreshed
  // after every install
  React.useEffect(() => { void loadKnowledge(); }, []);
  // how this tenant's stored artifacts are protected on disk (algorithm, key id)
  React.useEffect(() => { void loadAtRest(); }, []);

  /** Preflight only: no process is started, and the refusals are the answer. */
  const preflight = async () => {
    if (!target.trim()) { setDynError("target is required"); return; }
    setDynBusy(true); setDynError(null); setDynRefusals([]); setDyn(null);
    try {
      const answer = await apiBinaryDynamic({ target: target.trim(), args: dynArgv() });
      setDyn(answer.data); setDynRefusals(answer.refusals);
      if (!answer.ok && !answer.refusals.length) setDynError(answer.error);
    } catch (e) { setDynError(String(e)); }
    setDynBusy(false);
  };

  /** Run it under the tracer — only where the host has opted in and the sample passed. */
  const runDynamic = async () => {
    if (!target.trim()) { setDynError("target is required"); return; }
    setDynBusy(true); setDynError(null); setDynRefusals([]); setDyn(null);
    try {
      const answer = await apiBinaryDynamic({
        target: target.trim(), args: dynArgv(), execute: true, submit: dynSubmit,
      });
      setDyn(answer.data); setDynRefusals(answer.refusals);
      if (!answer.ok && !answer.refusals.length) setDynError(answer.error);
    } catch (e) { setDynError(String(e)); }
    setDynBusy(false);
  };

  const loadKnowledge = async () => {
    const answer = await apiKnowledge();
    if (answer.ok && answer.data) setKnowledge(answer.data);
  };

  const loadAtRest = async () => {
    const answer = await apiBinaryAtRest();
    if (answer.ok) setAtRest(answer.data);
  };

  const loadHistory = async () => {
    setHistoryBusy(true);
    try {
      setHistory(await apiBinaryScans({ limit: 50, q: historyQuery.trim() || undefined }));
    } catch (e) {
      setHistory({ source: "live", ok: false, data: null, error: String(e) });
    }
    setHistoryBusy(false);
  };

  const inspectHistory = async (scanId: string) => {
    setSelectedHistoryBusy(true);
    try {
      const answer = await apiBinaryScanDetail(scanId);
      setSelectedHistory(answer.ok ? answer.data : { error: answer.error });
    } catch (e) { setSelectedHistory({ error: String(e) }); }
    setSelectedHistoryBusy(false);
  };

  React.useEffect(() => { void loadHistory(); }, []);

  /** Verify (dry run) or verify-and-install a pack. Refusal reasons are the answer. */
  const installPack = async (dryRun: boolean) => {
    if (!packPath.trim()) { setPackInfo({ ok: false, text: "a pack path is required", reasons: [] }); return; }
    setPackBusy(true); setPackInfo(null);
    try {
      const answer = await apiKnowledgeInstall({ pack: packPath.trim(), dry_run: dryRun });
      if (!answer.ok) {
        setPackInfo({ ok: false, text: answer.error, reasons: answer.reasons });
      } else {
        const data = answer.data || {};
        const names = (data.loaded_rules?.names || []).join(", ");
        // `repaired` means the pack was already here but a file no longer matched
        // what was verified; say which, so "it was already installed" is never
        // mistaken for "the copy on this host is the one that was signed"
        const drifted = (data.repaired || data.drift || []) as { file: string; reason: string }[];
        const tables = (data.tables || []) as { algorithm?: string; name: string }[];
        setPackInfo({
          ok: true,
          text: `${data.action}: ${data.manifest?.name} v${data.manifest?.version}`
            + ` · ${(data.files || []).length} rule file(s)`
            + (names ? ` · rules: ${names}` : "")
            + (tables.length ? ` · tables: ${tables.map((row) => row.algorithm ?? row.name).join(", ")}` : "")
            + (data.replaced ? ` · replaced v${data.replaced.version}` : "")
            + (drifted.length ? ` · restored ${drifted.map((row) => `${row.file} (${row.reason})`).join(", ")}` : "")
            + (data.dry_run ? " (nothing was installed — this was the check)" : ""),
          reasons: [],
        });
        await loadKnowledge();
      }
    } catch (e) { setPackInfo({ ok: false, text: String(e), reasons: [] }); }
    setPackBusy(false);
  };

  const removePack = async (name: string) => {
    setPackBusy(true);
    try {
      const answer = await apiKnowledgeUninstall(name);
      setPackInfo(answer.ok
        ? { ok: true, text: answer.data?.removed ? `${name} removed — its rules no longer load` : `${name} was not installed`, reasons: [] }
        : { ok: false, text: answer.error || "uninstall failed", reasons: [] });
      await loadKnowledge();
    } catch (e) { setPackInfo({ ok: false, text: String(e), reasons: [] }); }
    setPackBusy(false);
  };

  /** What the ruleset will do — before trusting a scan to it. */
  const validateRules = async () => {
    setRulesBusy(true); setRulesInfo(null);
    try {
      const answer = await apiYaraValidate({ rules: rules() });
      const summary = answer.data?.summary;
      if (!answer.ok || !summary) {
        setRulesInfo({ ok: false, text: answer.error || "ruleset could not be loaded" });
      } else {
        const errors = (summary.errors || []).map((e: any) => `${e.source}: ${e.error}`);
        setRulesInfo({
          ok: (summary.error_count || 0) === 0,
          text: `${summary.rules} rules (${summary.private_rules} private) · digest ${String(summary.digest).slice(0, 16)}`
            + (errors.length ? ` · ${summary.error_count} refused: ${errors.slice(0, 3).join("; ")}` : ""),
        });
      }
    } catch (e) { setRulesInfo({ ok: false, text: String(e) }); }
    setRulesBusy(false);
  };

  /** Queue the scan; the artifact id is known now, so the report URL is pollable. */
  const queue = async () => {
    if (!target.trim()) { setJobError("target is required"); return; }
    setJobBusy(true); setJobError(null); setJobProgress(null);
    try {
      const answer = await apiBinaryScanJob({
        target: target.trim(), recursive, include_raw: includeRaw, format: fmt,
        yara_rules: rules(),
      });
      if (!answer.ok || !answer.data?.job_id) {
        setJobError(answer.error || "the scan could not be queued");
      } else {
        setJob({ job_id: answer.data.job_id, artifact_id: answer.data.artifact_id, status: answer.data.status });
      }
    } catch (e) { setJobError(String(e)); }
    setJobBusy(false);
  };

  // poll the queued job: progress while it runs, the artifact when it is done
  React.useEffect(() => {
    if (!job?.job_id) return;
    let stop = false;
    const tick = async () => {
      const answer = await apiJobStatus(job.job_id);
      if (stop) return;
      const data = answer.data;
      if (!answer.ok || !data) { setJobError(answer.error || "job status unavailable"); return; }
      setJobProgress(data.progress || null);
      setJob((prev) => (prev ? { ...prev, status: data.status } : prev));
      if (data.status === "COMPLETED" || data.status === "FAILED") { stop = true; return; }
      window.setTimeout(() => void tick(), 2000);
    };
    void tick();
    return () => { stop = true; };
  }, [job?.job_id]);

  /** Prove the CBOM was persisted: read it back from the artifact store. */
  const fetchStoredCbom = async () => {
    if (!res?.data?.artifact_id) return;
    setStoredBusy(true);
    try {
      const answered = await apiBinaryCbom(res.data.artifact_id);
      const stored = answered.data;
      setStoredCbom(stored
        ? `stored CBOM: ${stored.components?.length ?? 0} assets, serial ${stored.serialNumber}`
        : `stored CBOM unavailable: ${answered.error ?? "empty response"}`);
    } catch (e) { setStoredCbom("stored CBOM unavailable: " + String(e)); }
    setStoredBusy(false);
  };

  const scan = async () => {
    if (!target.trim()) { setRes({ source: "live", ok: false, data: null, error: "target is required" }); return; }
    let feed: any[] | undefined;
    if (feedText.trim()) {
      try {
        const parsed = JSON.parse(feedText);
        feed = Array.isArray(parsed) ? parsed : (parsed?.vulnerabilities || parsed?.advisories);
        if (!Array.isArray(feed)) throw new Error("expected a JSON array of advisories");
        setFeedError(null);
      } catch (e) {
        // a malformed feed must not read as "no advisories found"
        setFeedError("advisory feed is not valid JSON: " + String(e));
        return;
      }
    } else { setFeedError(null); }
    setBusy(true); setShowBom(false); setShowCbom(false); setStoredCbom(null);
    try {
      setRes(await apiBinaryScan({
        target: target.trim(), recursive, include_raw: includeRaw, format: fmt, feed,
        yara_rules: rules(),
      }));
    } catch (e) { setRes({ source: "live", ok: false, data: null, error: String(e) }); }
    setBusy(false);
  };

  const d = res?.data;
  const summary = d?.summary;
  const libraries: any[] = d?.crypto_libraries || [];
  const findings: any[] = d?.findings || [];
  const binaries: any[] = d?.binaries || [];
  const containers: any[] = binaries.flatMap((b: any) =>
    (b.containers_followed || []).map((c: any) => ({ ...c, binary: b.path })));
  const derived = binaries.filter((b: any) => b.derived_from);
  const formats = Object.entries(summary?.by_format || {});
  // one renderer for every format's mitigation vocabulary: ELF (pie/nx/relro/
  // canary/fortified), PE (aslr/dep/cfg/gs/seh) and Mach-O (pie/hardened-runtime)
  const hardeningOf = (b: any) => {
    const h = b.hardening || {};
    const keys = ["pie", "nx", "aslr", "dep", "relro", "canary", "gs", "cfg", "fortified"]
      .filter((k) => k in h);
    if (!keys.length) return "—";
    return keys.map((k) => `${h[k] ? "+" : "−"}${k}`).join(" ")
      + (h.full_relro ? " +full-relro" : "")
      + (h.cfg_instrumented ? " +cfg-instrumented" : "")
      + (h.hardened_runtime ? " +hardened-runtime" : "");
  };
  // linkage, code signature and OS floor: what the file links against and who
  // signed it, read from the load commands / symbol tables rather than guessed
  // a uImage states what it is in its own header (OS/arch/type/compression)
  const formatOf = (b: any) => {
    const base = b.format + (b.type?.endsWith(":efi") ? " · EFI" : "");
    const image = b.uimage;
    if (!image) return base;
    const detail = [image.os, image.arch, image.image_type, image.compression]
      .filter((v: any) => v && v !== "none").join(" / ");
    return detail ? `${base} · ${detail}` : base;
  };
  const linkageOf = (b: any) => {
    const bits: string[] = [];
    const dylibs = Object.keys(b.dylib_versions || {});
    if (dylibs.length) bits.push(`${dylibs.length} dylibs`);
    else if (b.import_count) bits.push(`${b.import_count} imports`);
    if (b.minimum_os) bits.push(`min ${b.minimum_os}`);
    const sig = b.signature;
    if (sig && b.format === "macho") {
      bits.push(sig.present ? `signed${sig.team_id ? ` ${sig.team_id}` : ""}` : "unsigned");
    } else if (sig && b.format === "pe") {
      bits.push(sig.present ? "signed" : "unsigned");
    }
    if (b.encrypted) bits.push("ENCRYPTED");
    return bits.join(" · ") || "—";
  };
  const parserStateOf = (b: any) => {
    if (b.parsed === true) return "observed";
    const note = String(b.parse_error || b.parse_note || b.reason || "").toLowerCase();
    if (b.unsupported || b.refused || ["unrecognised", "unsupported", "refused"].some((token) => note.includes(token))) return "unsupported";
    if (note) return "partial";
    return "unknown";
  };
  const staticEvidenceOf = (b: any) => {
    const bits: string[] = [];
    if ((b.import_symbols || []).length) bits.push(`${b.import_symbols.length} named imports`);
    if ((b.delay_import_symbols || []).length) bits.push(`${b.delay_import_symbols.length} delay imports`);
    if ((b.exports || []).length) bits.push(`${b.exports.length} exports`);
    const signing = b.android?.apk_signing_block;
    if (signing?.present) bits.push(`APK ${((signing.schemes || []).join("/") || "block")}`);
    if (signing && !signing.present && signing.state === "partial") bits.push("APK block partial");
    return bits.join(" · ") || "—";
  };
  const severityTone = (s: string) => (s === "CRITICAL" || s === "HIGH" ? "red" : (s === "MEDIUM" ? "amber" : "gray"));
  return (
    <Panel title="Binaries, archives & firmware — parse, not guess"
      sub="Parse, not guess — visual crypto evidence & hardening" className="mt" style={{ overflow: "hidden", padding: 0 }}>
      <div style={{ padding: "14px 16px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <span className="brandmark" style={{ width: 32, height: 32, display: "grid", placeItems: "center" }}><IconHardware size={16} /></span>
        <div><div style={{ fontWeight: 700, fontSize: 13 }}>Binaries & firmware</div><div style={{ fontSize: 11, color: "var(--dim)" }}>ELF · PE · Mach-O · ar/zip/cpio/deb · WASM · firmware · crypto evidence</div></div>
        <span className="badge violet" style={{ marginLeft: "auto" }}><span className="dot" /> PARSE, NOT GUESS</span>
      </div>
      <div style={{ padding: 16 }}>
      <div className="mt" style={{ marginBottom: 12 }}>
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 5 }}>
          <strong style={{ fontSize: 13 }}>Persisted binary history</strong>
          <span className="muted" style={{ fontSize: 12 }}>
            database read model · bounded observations · signed artifact remains authoritative
          </span>
          <input className="inp" style={{ width: 220, marginLeft: "auto" }} placeholder="filter target…"
            value={historyQuery} onChange={(e) => setHistoryQuery(e.target.value)} />
          <button className="btn sm" onClick={() => void loadHistory()} disabled={historyBusy}>
            {historyBusy ? "loading…" : "Refresh"}
          </button>
        </div>
        <Err res={history} />
        {history?.data?.records?.length ? (
          <Table head={["created", "target", "format", "coverage", "findings", "inspect"]}
            rows={history.data.records.map((row: any) => [
              <span className="muted" style={{ fontSize: 11.5 }}>{row.created_at ? new Date(row.created_at).toLocaleString() : "—"}</span>,
              <span className="mono" style={{ fontSize: 11.5 }}>{row.target}</span>,
              row.format,
              `${row.binaries_scanned} binaries · ${row.observations_count}${row.observations_truncated ? "+" : ""} observations`,
              <Badge tone={row.findings_count ? "amber" : "green"}>{row.findings_count}</Badge>,
              <button className="btn sm" onClick={() => void inspectHistory(row.id)} disabled={selectedHistoryBusy}>Inspect</button>,
            ])} />
        ) : (
          <div className="muted" style={{ fontSize: 12 }}>No indexed scans yet. Run a scan after migration 0063, or refresh if the index is still being populated.</div>
        )}
        {selectedHistory?.error && (
          <div className="muted" style={{ color: "var(--red)", fontSize: 12, marginTop: 6 }}>{selectedHistory.error}</div>
        )}
        {selectedHistory?.record && (
          <div className="mt" style={{ borderTop: "1px solid var(--line)", paddingTop: 8 }}>
            <div className="row" style={{ gap: 8, alignItems: "center", marginBottom: 5 }}>
              <strong style={{ fontSize: 12.5 }}>Observation detail</strong>
              <span className="mono muted" style={{ fontSize: 11 }}>{selectedHistory.record.artifact_id}</span>
              <button className="btn sm" onClick={() => setSelectedHistory(null)}>close</button>
            </div>
            <div className="muted" style={{ fontSize: 12, marginBottom: 5 }}>
              {selectedHistory.record.files_walked} files · {selectedHistory.record.binaries_scanned} binaries · {selectedHistory.observations?.length ?? 0} loaded
              {selectedHistory.record.observations_truncated ? " · database observation cap reached" : ""}
            </div>
            <Table head={["path", "format", "state", "arch", "crypto", "hardening / findings", "metadata / provenance", "signature / package evidence"]}
              rows={(selectedHistory.observations || []).slice(0, 80).map((row: any) => [
                <span className="mono" style={{ fontSize: 11.5 }}>{row.path}</span>, row.format,
                <Badge tone={row.evidence_state === "observed" ? "green" : row.evidence_state === "partial" ? "amber" : "gray"}>{row.evidence_state}</Badge>,
                row.arch || "—",
                `${row.crypto?.algorithms?.length || 0} algorithms${row.crypto?.libraries?.length ? ` · ${row.crypto.libraries.length} libraries` : ""}`,
                `${Object.entries(row.hardening || {}).filter(([, value]) => value === true).map(([key]) => key).slice(0, 3).join(", ") || "no flags"} · ${row.findings?.length || 0} findings`,
                `${row.metadata?.type || row.metadata?.android?.package_kind || row.metadata?.ios?.package_kind || "binary"}${row.derived_from ? ` · from ${String(row.derived_from).slice(0, 20)}` : ""}`,
                row.signature?.present ? "signature present (not trust-validated)" : (
                  row.metadata?.android?.apk_signing_block?.present
                    ? `APK ${((row.metadata.android.apk_signing_block.schemes || []).join("/") || "signing block")} (not verified)`
                    : row.metadata?.android?.apk_signing_block?.state === "partial" ? "APK signing block partial"
                    : row.metadata?.type === "android-package" ? "APK package metadata" : "—"
                ),
              ])} />
          </div>
        )}
      </div>
      <div className="grid" style={{ gridTemplateColumns: "1fr 130px", gap: 8, marginBottom: 8 }}>
        <input className="inp" placeholder="file or directory (e.g. /opt/app, /tmp/firmware.img, /lib/x86_64-linux-gnu/libcrypto.so.3)"
          value={target} onChange={(e) => setTarget(e.target.value)} />
        <select className="inp" value={fmt} onChange={(e) => setFmt(e.target.value)}>
          <option value="cyclonedx">CycloneDX 1.5</option>
          <option value="spdx">SPDX 2.3</option>
        </select>
      </div>
      <div className="row" style={{ gap: 14, marginBottom: 8, fontSize: 12.5, flexWrap: "wrap" }}>
        <label><input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> descend into subdirectories</label>
        <label><input type="checkbox" checked={includeRaw} onChange={(e) => setIncludeRaw(e.target.checked)} /> include unrecognised blobs that carry crypto evidence</label>
      </div>
      {job && (
        <div className="mt" style={{ marginBottom: 8, fontSize: 12.5 }}>
          <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <Badge tone={job.status === "COMPLETED" ? "green" : job.status === "FAILED" ? "red" : "amber"}>
              job {job.status.toLowerCase()}
            </Badge>
            <span className="mono">{job.job_id}</span>
            <span className="muted">
              {jobProgress?.current_stage ? `stage ${jobProgress.current_stage}` : "waiting for the worker"}
              {typeof jobProgress?.percent === "number" ? ` · ${jobProgress.percent}%` : ""}
            </span>
            <button className="btn sm" onClick={() => setJob(null)}>dismiss</button>
          </div>
          {jobProgress?.binary && (
            <div className="muted" style={{ marginTop: 4 }}>
              {jobProgress.binary.binaries_scanned} binaries from {jobProgress.binary.files_walked} files ·{" "}
              {jobProgress.binary.findings} findings
              {jobProgress.binary.yara_matches ? ` · ${jobProgress.binary.yara_matches} rule matches` : ""}
              {" · artifact "}<span className="mono">{jobProgress.binary.artifact_id}</span>
              {jobProgress.binary.report_url ? (
                <>
                  {" · "}
                  <a href={jobProgress.binary.report_url} target="_blank" rel="noreferrer">report</a>
                </>
              ) : null}
            </div>
          )}
          {jobError && <div style={{ color: "var(--red)", marginTop: 4 }}>{jobError}</div>}
        </div>
      )}
      <div className="mt" style={{ marginBottom: 8 }}>
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          dynamic analysis (ADR-012 LD_PRELOAD tracer) — off unless the host sets BINARY_EXECUTION_ENABLED.
          The sample would run with this process&#39;s privileges and network reach, so the preflight and the
          result both state their limits; nothing is executed until you ask for it.
        </div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input className="inp" style={{ flex: 1, minWidth: 220 }}
            placeholder="arguments for the sample (space separated, optional)"
            value={dynArgs} onChange={(e) => setDynArgs(e.target.value)} />
          <label style={{ fontSize: 12.5 }}>
            <input type="checkbox" checked={dynSubmit} onChange={(e) => setDynSubmit(e.target.checked)} />
            {" "}record as runtime findings
          </label>
          <button className="btn sm" onClick={() => void preflight()} disabled={dynBusy}>Preflight</button>
          <button className="btn sm" onClick={() => void runDynamic()} disabled={dynBusy}>
            {dynBusy ? "working…" : "Run under tracer"}
          </button>
          {dynError && <Badge tone="red"><span className="dot" /> {dynError}</Badge>}
        </div>
        {dynRefusals.length > 0 && (
          <div style={{ color: "var(--red)", fontSize: 12.5, marginTop: 4 }}>
            not executed: {dynRefusals.join("; ")}
          </div>
        )}
        {dyn && (
          <div style={{ fontSize: 12.5, marginTop: 4 }}>
            <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <Badge tone={dyn.executed ? "green" : "gray"}>{dyn.executed ? "executed" : "not executed"}</Badge>
              <Badge tone="gray">{dyn.tracer || "no tracer"}</Badge>
              <span className="muted">
                {dyn.observations.length} crypto observations · {dyn.duration_ms} ms
                {dyn.timed_out ? " · killed at the timeout" : ""}
                {dyn.returncode !== null && dyn.returncode !== undefined ? ` · exit ${dyn.returncode}` : ""}
                {dyn.changed ? " · the sample's bytes changed while it ran" : ""}
              </span>
              {dyn.runtime_ingest?.accepted ? (
                <Badge tone="green">{dyn.runtime_ingest.accepted} runtime findings recorded</Badge>
              ) : null}
            </div>
            {dyn.findings.slice(0, 8).map((f: any, i: number) => (
              <div key={i} className="muted" style={{ marginTop: 2 }}>
                <Badge tone={f.severity === "HIGH" ? "red" : f.severity === "MEDIUM" ? "amber" : "gray"}>{f.severity}</Badge>{" "}
                <span className="mono">{f.code}</span> {f.title}
              </div>
            ))}
            {dyn.executed && dyn.limits.length > 0 && (
              <details style={{ marginTop: 4 }}>
                <summary className="muted">what did not isolate this run ({dyn.limits.length})</summary>
                <ul className="muted" style={{ margin: "4px 0 0 18px" }}>
                  {dyn.limits.map((l, i) => <li key={i}>{l}</li>)}
                </ul>
              </details>
            )}
          </div>
        )}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}>
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          fleet intake — point at a directory of dropped binaries and queue what needs scanning:
          the same bytes at two paths are one scan, changed content is a new scan, and every file
          that is <em>not</em> queued says why. The memory of what was scanned lives in
          &lt;spool&gt;/.cryptoscan-intake.json
        </div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input className="inp" style={{ flex: 1, minWidth: 260 }}
            placeholder="/srv/release-drop or /var/spool/cryptoscan/binaries"
            value={spool} onChange={(e) => setSpool(e.target.value)} />
          <button className="btn sm" onClick={() => void runPass(false)} disabled={batchBusy}>
            {batchBusy ? "working…" : "Plan pass"}
          </button>
          <button className="btn sm" onClick={() => void runPass(true)} disabled={batchBusy}>Queue pass</button>
          {batchError && <Badge tone="red"><span className="dot" /> {batchError}</Badge>}
        </div>
        {batch && (
          <div style={{ fontSize: 12.5, marginTop: 4 }}>
            <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <Badge tone={batch.queued > 0 ? "amber" : "gray"}>
                {batch.dry_run ? `${batch.planned} would be queued` : `${batch.queued} queued`}
              </Badge>
              <Badge tone="gray">{batch.considered} considered</Badge>
              <Badge tone="gray">{batch.skipped} skipped</Badge>
              {!batch.dry_run && (
                <Badge tone={batch.state_saved ? "green" : "red"}>
                  {batch.state_saved ? "intake memory written" : "intake memory NOT written"}
                </Badge>
              )}
              <span className="muted mono">batch {batch.batch_id.slice(0, 8)}</span>
              {batch.dry_run && (
                <button className="btn sm" onClick={() => void runPass(true)}>queue these</button>
              )}
            </div>
            {batch.state_note && (
              <div style={{ color: "var(--red)", marginTop: 2 }}>{batch.state_note}</div>
            )}
            <Table
              head={["file", "decision", "why", "covers"]}
              rows={(batchAll ? batch.files : batch.files.slice(0, 12)).map((f) => [
                <span className="mono">{f.path.split("/").slice(-1)[0]}</span>,
                <Badge tone={f.action === "queue" ? "amber" : "gray"}>{f.action}</Badge>,
                <span title={f.path}>{f.reason}</span>,
                <span className="mono" style={{ fontSize: 11.5 }}>
                  {f.artifact_id ? String(f.artifact_id).slice(0, 8) : "—"}
                </span>,
              ])}
            />
            {batch.files.length > 12 && (
              <button className="btn sm" onClick={() => setBatchAll((v) => !v)}>
                {batchAll ? "show fewer" : `show all ${batch.files.length}`}
              </button>
            )}
            {batchStatus && (
              <div style={{ marginTop: 4 }}>
                {Object.entries(batchStatus.by_status || {}).map(([status, count]) => (
                  <Badge key={status} tone={status === "COMPLETED" ? "green" : status === "FAILED" ? "red" : "amber"}>
                    {String(count)} {status.toLowerCase()}
                  </Badge>
                ))}
                <span className="muted" style={{ marginLeft: 6 }}>
                  {batchStatus.totals.binaries_scanned} binaries · {batchStatus.totals.findings} findings ·{" "}
                  {batchStatus.totals.yara_matches} rule matches
                </span>
                {batchStatus.files.map((row: any, i: number) => (
                  <div key={i} className="muted" style={{ marginTop: 2 }}>
                    {String(row.target || "").split("/").slice(-1)[0]} — {row.status}
                    {row.stage ? ` @ ${row.stage}` : ""}
                    {typeof row.percent === "number" ? ` ${row.percent}%` : ""}
                    {row.error ? ` · ${row.error}` : ""}
                    {row.report_url ? (
                      <>
                        {" · "}
                        <a href={row.report_url} target="_blank" rel="noreferrer">report</a>
                      </>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}>
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          rule files or directories (YARA subset, optional) — the platform&#39;s own rules always run; a rule that cannot
          be parsed is refused and reported, never silently skipped
        </div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <input className="inp" style={{ flex: 1, minWidth: 260 }}
            placeholder="/etc/cryptoscan/rules/vendor.yar or a directory of .yar files"
            value={rulesPath} onChange={(e) => setRulesPath(e.target.value)} />
          <button className="btn sm" onClick={() => void validateRules()} disabled={rulesBusy}>
            {rulesBusy ? "loading…" : "Check rules"}
          </button>
        </div>
        {rulesInfo && (
          <div style={{ fontSize: 12.5, marginTop: 4, color: rulesInfo.ok ? "var(--green)" : "var(--red)" }}>
            {rulesInfo.text}
          </div>
        )}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}>
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          detection packs — signed rule bundles for an install that never sees the internet. A pack is verified
          (signature, per-file digests, and that its rules load here) before anything is written, so it is refused
          or installed, never half-applied.
        </div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <input className="inp" style={{ flex: 1, minWidth: 260 }}
            placeholder="/media/acme-fips-2026.09.tar.gz or a pack directory on this host"
            value={packPath} onChange={(e) => setPackPath(e.target.value)} />
          <button className="btn sm" onClick={() => void installPack(true)} disabled={packBusy}>
            {packBusy ? "working…" : "Verify only"}
          </button>
          <button className="btn sm" onClick={() => void installPack(false)} disabled={packBusy}>Install pack</button>
        </div>
        {packInfo && (
          <div style={{ fontSize: 12.5, marginTop: 4, color: packInfo.ok ? "var(--green)" : "var(--red)" }}>
            {packInfo.text}
            {packInfo.reasons.map((reason, i) => (
              <div key={i} className="muted">refused: {reason}</div>
            ))}
          </div>
        )}
        {knowledge && (
          <div style={{ fontSize: 12.5, marginTop: 6 }}>
            <div className="muted">
              a scan loads <b>{knowledge.ruleset.rules}</b> rules · digest{" "}
              <span className="mono">{String(knowledge.ruleset.digest).slice(0, 16)}</span> · built-in{" "}
              {knowledge.builtin.rules} · {Object.keys(knowledge.installed).length} pack(s) installed
            </div>
            {atRest && (
              <div className="muted">
                stored artifacts <b>{atRest.artifacts}</b> ·{" "}
                {atRest.at_rest.encrypted ? (
                  <>
                    sealed <b>{atRest.at_rest.algorithm}</b> · key{" "}
                    <span className="mono">{atRest.at_rest.key_id}</span>
                  </>
                ) : (
                  <span style={{ color: "var(--red)" }}>
                    plaintext — {atRest.at_rest.note || "no artifact key configured"}
                  </span>
                )}
                {atRest.plaintext_artifacts > 0 && atRest.at_rest.encrypted
                  ? ` · ${atRest.plaintext_artifacts} plaintext from before` : ""}
              </div>
            )}
            {knowledge.tables && (
              <div className="muted">
                constant tables <b>{knowledge.tables.total}</b> · digest{" "}
                <span className="mono">{String(knowledge.tables.digest).slice(0, 16)}</span> ·{" "}
                {knowledge.tables.builtin} built-in
                {knowledge.tables.installed > 0 ? ` · ${knowledge.tables.installed} from pack(s)` : ""}
              </div>
            )}
            {Object.entries(knowledge.installed).map(([name, entry]) => (
              <div key={name} className="row" style={{ gap: 8, alignItems: "center", marginTop: 3 }}>
                <Badge tone="green">{name} v{entry.version}</Badge>
                <span className="muted mono">digest {String(entry.digest).slice(0, 12)}</span>
                <span className="muted">{entry.signed_by ? `signed by ${entry.signed_by}` : "unsigned"}</span>
                <span className="muted">{(entry.rule_names || []).length} rule(s)</span>
                {(entry.tables || []).length > 0 && (
                  <span className="muted">{(entry.tables || []).length} table(s)</span>
                )}
                <button className="btn sm" onClick={() => void removePack(name)} disabled={packBusy}>Remove</button>
              </div>
            ))}
            {knowledge.tables?.errors?.map((problem, i) => (
              <div key={i} className="muted" style={{ color: "var(--red)" }}>
                table not searched: {problem.file} ({problem.source}) — {problem.error}
              </div>
            ))}
            {knowledge.registry_note && <div className="muted">{knowledge.registry_note}</div>}
          </div>
        )}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}>
        <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
          advisory feed (JSON array, optional) — binary-detected crypto implementations match against ecosystem &#34;generic&#34; rows
        </div>
        <textarea className="inp" rows={2} style={{ width: "100%", fontFamily: "ui-monospace, monospace", fontSize: 12 }}
          placeholder='[{"cve_id":"CVE-2026-0001","severity":"HIGH","affected":[{"ecosystem":"generic","package":"OpenSSL","ranges":[{"introduced":"3.0.0","fixed":"3.0.21"}]}]}]'
          value={feedText} onChange={(e) => setFeedText(e.target.value)} />
        {feedError && <div style={{ color: "var(--red)", fontSize: 12.5, marginTop: 4 }}>{feedError}</div>}
      </div>
      <div className="row" style={{ gap: 8 }}>
        <button className="btn sm primary" onClick={() => void scan()} disabled={busy}>{busy ? "scanning…" : "Scan binaries"}</button>
        <button className="btn sm" onClick={() => void queue()} disabled={jobBusy}>
          {jobBusy ? "queueing…" : "Queue as job"}
        </button>
        {jobError && <Badge tone="red"><span className="dot" /> {jobError}</Badge>}
        {d?.artifact_id && (
          <>
            <Badge tone={d.manifest?.signature ? "green" : "gray"}>{d.manifest?.signature ? "signed artifact" : "unsigned artifact"}</Badge>
            <span className="muted" style={{ fontSize: 12 }}>artifact {String(d.artifact_id).slice(0, 8)}</span>
            <Badge tone={d.database_indexed ? "green" : "amber"}>{d.database_indexed ? "history indexed" : "history unavailable"}</Badge>
          </>
        )}
      </div>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
            <Badge tone="">{summary?.binaries_scanned ?? 0} binaries</Badge>
            <Badge tone="">{summary?.files_walked ?? 0} files walked</Badge>
            <Badge tone={(summary?.crypto_libraries || 0) > 0 ? "amber" : "gray"}>{summary?.crypto_libraries ?? 0} crypto implementations</Badge>
            <Badge tone={(summary?.findings || 0) > 0 ? "amber" : "green"}>{summary?.findings ?? 0} findings</Badge>
            <Badge tone="">CBOM {summary?.cbom_components ?? 0} assets</Badge>
            <Badge tone={(summary?.embedded_binaries || 0) > 0 ? "amber" : "gray"}>
              {summary?.embedded_binaries ?? 0} embedded
            </Badge>
            <Badge tone={(summary?.containers_followed || 0) > 0 ? "amber" : "gray"}>
              {summary?.containers_followed ?? 0} containers followed
            </Badge>
            {(summary?.containers_refused || 0) > 0 && (
              <Badge tone="gray">{summary?.containers_refused} containers refused</Badge>
            )}
            {(summary?.signature_posture?.signed || 0) > 0 && (
              <Badge tone="green">{summary?.signature_posture?.signed} signed</Badge>
            )}
            {(summary?.signature_posture?.unsigned || 0) > 0 && (
              <Badge tone="amber">{summary?.signature_posture?.unsigned} unsigned</Badge>
            )}
            {(summary?.encrypted_binaries || 0) > 0 && (
              <Badge tone="red">{summary?.encrypted_binaries} encrypted</Badge>
            )}
            {(summary?.packed_binaries || 0) > 0 && (
              <Badge tone="amber">{summary?.packed_binaries} packed</Badge>
            )}
            {(summary?.fingerprints?.exact_duplicate_groups || 0) > 0 && (
              <Badge tone="gray">{summary.fingerprints.exact_duplicate_groups} duplicated build{summary.fingerprints.exact_duplicate_groups === 1 ? "" : "s"}</Badge>
            )}
            {(summary?.fingerprints?.near_duplicate_pairs || 0) > 0 && (
              <Badge tone="amber">{summary.fingerprints.near_duplicate_pairs} near-duplicate pair{summary.fingerprints.near_duplicate_pairs === 1 ? "" : "s"}</Badge>
            )}
            {summary?.truncated && <Badge tone="red">TRUNCATED — walk cap hit</Badge>}
            {d.manifest?.feed_supplied ? <Badge tone="amber">FEED SUPPLIED</Badge> : <Badge tone="">no feed</Badge>}
          </div>
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
            <div>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>formats</div>
              <Table head={["format", "count"]} rows={formats.map(([k, v]) => [k, String(v)])} />
            </div>
            <div>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>architectures</div>
              <Table head={["arch", "count"]} rows={Object.entries(summary?.by_arch || {}).map(([k, v]) => [k, String(v)])} />
            </div>
          </div>
          {(summary?.pqc_markers?.length > 0 || summary?.ecc_markers?.length > 0) && (
            <div className="row" style={{ gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
              {(summary.pqc_markers || []).map((m: string) => <Badge key={m} tone="green">PQC · {m}</Badge>)}
              {(summary.ecc_markers || []).length > 0 && (
                <Badge tone="amber">classical ECC present{summary.pqc_markers?.length ? " alongside PQC" : ""}</Badge>
              )}
            </div>
          )}
          {binaries.length > 0 && (
            <div className="mt" style={{ marginBottom: 10 }}>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
                binaries parsed ({binaries.length}) — embedded files are listed under the container they came from
              </div>
              <Table head={["path", "format", "state", "provenance", "arch", "publisher / product", "linkage / signature", "static evidence", "hardening", "packer", "crypto", "build fingerprint", "packages inside"]}
                rows={binaries.map((b: any) => [
                  <span style={{ fontSize: 12 }}>
                    {b.derived_from ? "└ " : ""}{b.path}
                  </span>,
                  formatOf(b),
                  <Badge tone={parserStateOf(b) === "observed" ? "green" : parserStateOf(b) === "partial" ? "amber" : "gray"}>{parserStateOf(b)}</Badge>,
                  <span className="mono muted" style={{ fontSize: 11 }}>{b.derived_from ? `${String(b.derived_from).slice(0, 26)} · depth ${b.depth ?? 1}` : "root target"}</span>,
                  b.arch || "—",
                  [b.publisher, b.product].filter(Boolean).join(" / ") || "—",
                  <span style={{ fontSize: 12 }}>{linkageOf(b)}</span>,
                  <span style={{ fontSize: 12 }}>{staticEvidenceOf(b)}</span>,
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11.5 }}>{hardeningOf(b)}</span>,
                  b.packer ? <Badge tone="amber">{b.packer}</Badge> : "—",
                  (b.crypto_constants || []).length > 0
                    ? `${(b.algorithms || []).length} algos · tables: ${(b.crypto_constants || []).join(", ")}`
                    : `${(b.algorithms || []).length} algos`,
                  <span style={{ fontFamily: "var(--mono)", fontSize: 11 }} title={b.fingerprints?.build_fingerprint || ""}>
                    {b.fingerprints?.build_fingerprint
                      ? b.fingerprints.build_fingerprint.slice(0, 12)
                      : "—"}
                    {b.fingerprints?.code_bytes
                      ? <span className="muted"> · {b.fingerprints.code_bytes} B code</span>
                      : <span className="muted"> · whole file</span>}
                  </span>,
                  (b.packages_inside || []).length > 0
                    ? (b.packages_inside || []).map((p: any) => `${p.name}${p.version ? "@" + p.version : ""} (${p.manager})`).join(", ")
                    : "—",
                ])} />
            </div>
          )}
          {containers.length > 0 && (
            <div className="mt" style={{ marginBottom: 10 }}>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>
                containers opened ({containers.length}) — what was inside, and what could not be opened
              </div>
              <Table head={["container", "inside", "members", "parsed", "opened / refused"]}
                rows={containers.map((c: any) => [
                  c.format + (c.offset ? ` @0x${c.offset.toString(16)}` : ""),
                  c.inner_format || "—",
                  String(c.members_listed ?? 0),
                  String(c.parsed ?? 0),
                  <span style={{ fontSize: 12 }}>
                    {(c.opened || []).join("; ") || "—"}
                    {(c.refused || []).map((r: any) => (
                      <div key={String(r.member || r.format)} style={{ color: "var(--amber)" }}>
                        refused {r.member || r.format}: {r.reason}
                      </div>
                    ))}
                  </span>,
                ])} />
            </div>
          )}
          {libraries.length > 0 && (
            <div className="mt" style={{ marginBottom: 10 }}>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>crypto implementations found in the images</div>
              <Table head={["library", "version", "evidence", "found in", "state"]}
                rows={libraries.map((l: any) => [
                  l.name,
                  l.version || "not embedded",
                  (l.evidence || []).join(", ") || "-",
                  (l.found_in || []).join(", "),
                  l.deprecated ? <Badge tone="red">END OF LIFE</Badge> : <Badge tone="green">current line</Badge>,
                ])} />
            </div>
          )}
          {findings.length > 0 && (
            <div className="mt" style={{ marginBottom: 10 }}>
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 4 }}>findings (each cites its evidence)</div>
              <Table head={["code", "severity", "path", "detail"]}
                rows={findings.map((f: any) => [
                  f.code,
                  <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>,
                  f.path,
                  <span style={{ fontSize: 12 }}>{f.detail}</span>,
                ])} />
            </div>
          )}
          <div className="row" style={{ gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
            <button className="btn sm" onClick={() => setShowBom(!showBom)}>{showBom ? "Hide" : "Show"} SBOM</button>
            <button className="btn sm" onClick={() => setShowCbom(!showCbom)}>{showCbom ? "Hide" : "Show"} CBOM</button>
            {d.artifact_id && (
              <button className="btn sm" onClick={() => void fetchStoredCbom()} disabled={storedBusy}>
                {storedBusy ? "…" : "Fetch stored CBOM"}
              </button>
            )}
            {d.artifact_id && (
              <span className="muted" style={{ fontSize: 12 }}>
                gate, license, VEX, diff and rescan are on the SBOM tab — this artifact has kind=binary
              </span>
            )}
          </div>
          {summary?.extraction_limits && (
            <div style={{ display: "inline-flex", gap: 6, alignItems: "center", padding: "6px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}>
              <IconHardware size={12} /> Budget {Math.round((summary.extraction_limits.max_payload_bytes || 0) / (1024 * 1024))} MiB · depth {summary.extraction_limits.max_depth} · {summary.extraction_limits.max_members} members
            </div>
          )}
          {storedCbom && <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>{storedCbom}</div>}
          {showBom && <Code>{JSON.stringify(d.bom, null, 2)}</Code>}
          {showCbom && <Code>{JSON.stringify(d.cbom, null, 2)}</Code>}
        </>
      )}
      </div>
    </Panel>
  );
}

/* ---- 17-20. connectors ---- */
const CONNECTORS = [
  { id: "servicenow", label: "ServiceNow (incident)" },
  { id: "jira", label: "Jira (issue)" },
  { id: "splunk", label: "Splunk HEC" },
  { id: "elastic", label: "Elastic / OpenSearch" },
  { id: "kafka", label: "Kafka topic" },
  { id: "rabbitmq", label: "RabbitMQ exchange" },
  { id: "slack", label: "Slack card" },
  { id: "teams", label: "MS Teams card" },
];
function ConnectorPanel() {
  const [provider, setProvider] = useState("slack");
  const [finding, setFinding] = useState(JSON.stringify({ finding_id: "F-1001", title: "Public S3 bucket", severity: "critical", asset: "open-bucket", detail: "acl=public-read" }, null, 2));
  const [target, setTarget] = useState("{}");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (live: boolean) => {
    setBusy(true);
    try { setRes(await apiConnectorPreview(provider, JSON.parse(finding), JSON.parse(target || "{}"), live)); }
    catch (e) { setRes({ source: "live", ok: false, data: null, error: "JSON: " + String(e) }); }
    setBusy(false);
  };
  const d = res?.data;
  return (
    <Panel title="Ticketing · SIEM · bus · chat connectors" sub="ITSM/SIEM/bus/chat — visual payload previews" className="mt">
      <div className="grid" style={{ gridTemplateColumns: "1fr 2fr", gap: 8, marginBottom: 8 }}>
        <select className="inp" value={provider} onChange={(e) => setProvider(e.target.value)}>
          {CONNECTORS.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
        </select>
        <input className="inp" placeholder='target (e.g. {"webhook_url":"https://...","instance":"x.service-now.com"})' value={target} onChange={(e) => setTarget(e.target.value)} />
      </div>
      <textarea className="inp" rows={5} value={finding} onChange={(e) => setFinding(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} />
      <div className="row" style={{ gap: 8 }}>
        <button className="btn sm" onClick={() => void run(false)} disabled={busy}>Build payload (preview)</button>
        <button className="btn sm primary" onClick={() => void run(true)} disabled={busy}>{busy ? "…" : "Deliver live"}</button>
      </div>
      <div className="mt" style={{ marginBottom: 8 }}><Err res={res} /></div>
      {d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone={d.result?.ok ? "green" : "red"}>{d.provider} · {d.result?.ok ? "OK" : "FAILED"}</Badge>
            <Badge tone="">dedup {d.result?.dedup_key?.slice(0, 18)}</Badge>
            {d.delivered_live ? <Badge tone="amber">LIVE DELIVERY</Badge> : <Badge tone="">PREVIEW</Badge>}
          </div>
          <Code>{JSON.stringify(d.preview, null, 2)}</Code>
        </>
      )}
    </Panel>
  );
}

export default function DevSecOps() {
  const [tab, setTab] = useState(0);
  const tabs = ["Container scan", "K8s manifests", "Cloud posture", "SBOM", "Binaries", "Connectors"];
  return (
    <>
      <PageHead
        crumb="operate / devsecops pipeline"
        title="DevSecOps pipeline"
        sub="6 shift-left gates · visual, deterministic, fail-closed"
        right={<Badge tone=""><span className="dot" /> SHIFT-LEFT GATES</Badge>}
      />
      <DomainCrossNav current="applications" />
      <EvidenceBoundaryStrip />
      <div className="mt"><Tabs tabs={tabs} active={tab} onChange={setTab} /></div>
      {tab === 0 && <ContainerPanel />}
      {tab === 1 && <K8sPanel />}
      {tab === 2 && <PosturePanel />}
      {tab === 3 && <SbomPanel />}
      {tab === 4 && <BinaryPanel />}
      {tab === 5 && <ConnectorPanel />}
    </>
  );
}
